// SPDX-License-Identifier: Apache-2.0
//! Persistent per-workload consultation quota owned by PostgreSQL.
//!
//! The bucket key can only be derived from a coupled authenticated workload
//! and a compiled profile identity. PostgreSQL owns both time and mutation.
//! Relay receives only a closed allow/exhausted result and never exposes the
//! runtime database client.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use thiserror::Error;
use tokio::sync::Mutex;
use tokio_postgres::{Client, Row};

use crate::consultation::{AuthenticatedConsultationWorkload, ProfileIdentity};

use super::migration::{
    validate_runtime_capability_v1, AuditChainKeyEpochId, RuntimeCapabilityError,
    RUNTIME_SESSION_LIMITS_SQL,
};

const QUOTA_RESERVE_SQL: &str =
    "SELECT * FROM relay_state_api.quota_reserve_v1($1, $2, $3, $4, $5)";
const DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const V1_MAX_RATE_PER_MINUTE: u16 = 60;
const V1_MAX_BURST_TOKENS: u8 = 10;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Exact durable bucket identity. No request field can construct this key.
pub(crate) struct QuotaKey {
    workload_id: String,
    profile_id: String,
    profile_version: i64,
}

impl QuotaKey {
    pub(crate) fn from_authenticated(
        workload: &AuthenticatedConsultationWorkload,
        profile: &ProfileIdentity,
    ) -> Self {
        Self {
            workload_id: workload.workload_id().as_str().to_owned(),
            profile_id: profile.id().as_str().to_owned(),
            profile_version: i64::try_from(profile.version().get())
                .expect("validated profile versions fit PostgreSQL bigint"),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(workload_id: &str, profile_id: &str, profile_version: u64) -> Self {
        use crate::consultation::{ProfileId, ProfileVersion, WorkloadId};

        let workload = WorkloadId::try_from(workload_id).expect("valid test workload id");
        let profile = ProfileId::try_from(profile_id).expect("valid test profile id");
        let version = ProfileVersion::try_from(profile_version.to_string().as_str())
            .expect("valid test profile version");
        Self {
            workload_id: workload.as_str().to_owned(),
            profile_id: profile.as_str().to_owned(),
            profile_version: i64::try_from(version.get())
                .expect("validated profile versions fit PostgreSQL bigint"),
        }
    }
}

impl std::fmt::Debug for QuotaKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QuotaKey(<authenticated workload/profile>)")
    }
}

/// Hash-covered public maxima from the compiled consultation profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicQuotaLimits {
    rate_per_minute: u16,
    burst_tokens: u8,
}

impl PublicQuotaLimits {
    pub(crate) fn new(rate_per_minute: u16, burst_tokens: u8) -> Result<Self, QuotaError> {
        if !(1..=V1_MAX_RATE_PER_MINUTE).contains(&rate_per_minute)
            || !(1..=V1_MAX_BURST_TOKENS).contains(&burst_tokens)
        {
            return Err(QuotaError::InvalidPublicLimits);
        }
        Ok(Self {
            rate_per_minute,
            burst_tokens,
        })
    }

    pub(crate) const fn v1_default() -> Self {
        Self {
            rate_per_minute: V1_MAX_RATE_PER_MINUTE,
            burst_tokens: V1_MAX_BURST_TOKENS,
        }
    }
}

/// Deployment-effective limits proven not to exceed the public maxima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveQuotaLimits {
    rate_per_minute: u16,
    burst_tokens: u8,
}

impl EffectiveQuotaLimits {
    pub(crate) fn lowered_from(
        public: PublicQuotaLimits,
        rate_per_minute: u16,
        burst_tokens: u8,
    ) -> Result<Self, QuotaError> {
        if rate_per_minute == 0
            || burst_tokens == 0
            || rate_per_minute > public.rate_per_minute
            || burst_tokens > public.burst_tokens
        {
            return Err(QuotaError::InvalidEffectiveLimits);
        }
        Ok(Self {
            rate_per_minute,
            burst_tokens,
        })
    }

    fn rate_for_postgres(self) -> i32 {
        i32::from(self.rate_per_minute)
    }

    fn burst_for_postgres(self) -> i32 {
        i32::from(self.burst_tokens)
    }
}

/// Consuming closed result of one confirmed PostgreSQL reservation.
pub(crate) enum QuotaReservation {
    Allowed(QuotaGrant),
    Exhausted(QuotaExhaustion),
}

/// One non-cloneable authority grant bound to the exact reserved key/limits.
///
/// The future consultation dispatch kernel must take this value by value. It
/// must never accept a boolean derived from it or a borrowed reference to it.
#[must_use = "a quota grant must be consumed by the fenced dispatch kernel"]
pub(crate) struct QuotaGrant {
    key: QuotaKey,
    limits: EffectiveQuotaLimits,
}

impl std::fmt::Debug for QuotaGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = (&self.key, self.limits);
        formatter.write_str("QuotaGrant(<reserved workload/profile authority>)")
    }
}

/// Confirmed exhaustion carrying the only public retry instruction.
pub(crate) struct QuotaExhaustion {
    retry_after: Duration,
}

impl QuotaExhaustion {
    pub(crate) fn into_retry_after(self) -> Duration {
        self.retry_after
    }
}

impl std::fmt::Debug for QuotaExhaustion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuotaExhaustion")
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

impl std::fmt::Debug for QuotaReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed(grant) => formatter.debug_tuple("Allowed").field(grant).finish(),
            Self::Exhausted(exhaustion) => formatter
                .debug_tuple("Exhausted")
                .field(exhaustion)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaReadiness {
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum QuotaError {
    #[error("Relay consultation public quota limits are invalid")]
    InvalidPublicLimits,
    #[error("Relay consultation effective quota limits are invalid")]
    InvalidEffectiveLimits,
    #[error("Relay consultation quota runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay consultation quota capability has drifted")]
    CapabilityDrift,
    #[error("Relay consultation quota limits require a governed maintenance transition")]
    LimitMismatch,
    #[error("Relay consultation quota observed an unsafe PostgreSQL clock rollback")]
    ClockAnomaly,
    #[error("Relay consultation quota database protocol has drifted")]
    ProtocolDrift,
    #[error("Relay consultation quota is unavailable")]
    Unavailable,
}

/// Execute-only persistent limiter. Any uncertain operation seals this value.
pub(crate) struct PostgresQuotaStatePlane {
    client: Mutex<Client>,
    chain_key_epoch_id: AuditChainKeyEpochId,
    available: AtomicBool,
}

impl PostgresQuotaStatePlane {
    pub(crate) async fn connect(
        client: Client,
        chain_key_epoch_id: AuditChainKeyEpochId,
    ) -> Result<Self, QuotaError> {
        client
            .batch_execute("ROLLBACK")
            .await
            .map_err(|_| QuotaError::Unavailable)?;
        client
            .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
            .await
            .map_err(|_| QuotaError::Unavailable)?;
        validate_runtime_capability_v1(&client, &chain_key_epoch_id)
            .await
            .map_err(map_runtime_capability_error)?;
        Ok(Self {
            client: Mutex::new(client),
            chain_key_epoch_id,
            available: AtomicBool::new(true),
        })
    }

    pub(crate) async fn readiness(&self) -> QuotaReadiness {
        if !self.available.load(Ordering::Acquire) {
            return QuotaReadiness::Unavailable;
        }
        let Ok(client) = self.client.try_lock() else {
            return QuotaReadiness::Unavailable;
        };
        match tokio::time::timeout(
            DATABASE_OPERATION_TIMEOUT,
            validate_runtime_capability_v1(&client, &self.chain_key_epoch_id),
        )
        .await
        {
            Ok(Ok(())) => QuotaReadiness::Ready,
            _ => {
                self.available.store(false, Ordering::Release);
                QuotaReadiness::Unavailable
            }
        }
    }

    pub(crate) async fn reserve(
        &self,
        key: QuotaKey,
        limits: EffectiveQuotaLimits,
    ) -> Result<QuotaReservation, QuotaError> {
        if !self.available.load(Ordering::Acquire) {
            return Err(QuotaError::Unavailable);
        }

        // Waiting for another local caller does not send SQL and therefore
        // creates no database uncertainty. Timeout or cancellation while
        // queued affects only that caller.
        let client = tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| QuotaError::Unavailable)?;
        if !self.available.load(Ordering::Acquire) {
            return Err(QuotaError::Unavailable);
        }

        // Declared after the client guard so an uncertain query seals the
        // plane before the mutex unlocks and another waiter can observe it.
        let mut uncertainty = QuotaUncertaintyGuard::new(&self.available);
        let row = tokio::time::timeout(
            DATABASE_OPERATION_TIMEOUT,
            client.query_one(
                QUOTA_RESERVE_SQL,
                &[
                    &key.workload_id,
                    &key.profile_id,
                    &key.profile_version,
                    &limits.rate_for_postgres(),
                    &limits.burst_for_postgres(),
                ],
            ),
        )
        .await
        .map_err(|_| QuotaError::Unavailable)?
        .map_err(map_postgres_error)?;

        let reservation = reservation_from_row(&row, key, limits)?;
        uncertainty.confirm();
        Ok(reservation)
    }
}

struct QuotaUncertaintyGuard<'a> {
    available: &'a AtomicBool,
    confirmed: bool,
}

impl<'a> QuotaUncertaintyGuard<'a> {
    fn new(available: &'a AtomicBool) -> Self {
        Self {
            available,
            confirmed: false,
        }
    }

    fn confirm(&mut self) {
        self.confirmed = true;
    }
}

impl Drop for QuotaUncertaintyGuard<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.available.store(false, Ordering::Release);
        }
    }
}

fn reservation_from_row(
    row: &Row,
    key: QuotaKey,
    expected_limits: EffectiveQuotaLimits,
) -> Result<QuotaReservation, QuotaError> {
    let outcome = row
        .try_get::<_, &str>("outcome")
        .map_err(|_| QuotaError::ProtocolDrift)?;
    if outcome == "limit_mismatch" {
        return Err(QuotaError::LimitMismatch);
    }
    if outcome == "clock_anomaly" {
        return Err(QuotaError::ClockAnomaly);
    }

    let returned_rate = row
        .try_get::<_, i32>("rate_per_minute")
        .map_err(|_| QuotaError::ProtocolDrift)?;
    let returned_burst = row
        .try_get::<_, i32>("burst_tokens")
        .map_err(|_| QuotaError::ProtocolDrift)?;
    let retry_after_ms = row
        .try_get::<_, i64>("retry_after_ms")
        .map_err(|_| QuotaError::ProtocolDrift)?;
    if returned_rate != expected_limits.rate_for_postgres()
        || returned_burst != expected_limits.burst_for_postgres()
    {
        return Err(QuotaError::ProtocolDrift);
    }

    match outcome {
        "allowed" if retry_after_ms == 0 => Ok(QuotaReservation::Allowed(QuotaGrant {
            key,
            limits: expected_limits,
        })),
        "exhausted"
            if retry_after_ms > 0
                && retry_after_ms
                    <= i64::try_from(MAX_RETRY_AFTER.as_millis())
                        .expect("bounded retry duration fits i64") =>
        {
            Ok(QuotaReservation::Exhausted(QuotaExhaustion {
                retry_after: Duration::from_millis(
                    u64::try_from(retry_after_ms).expect("positive retry duration fits u64"),
                ),
            }))
        }
        _ => Err(QuotaError::ProtocolDrift),
    }
}

fn map_runtime_capability_error(error: RuntimeCapabilityError) -> QuotaError {
    match error {
        RuntimeCapabilityError::WrongRuntimeIdentity => QuotaError::WrongRuntimeIdentity,
        RuntimeCapabilityError::Drift => QuotaError::CapabilityDrift,
        RuntimeCapabilityError::Unavailable => QuotaError::Unavailable,
    }
}

fn map_postgres_error(error: tokio_postgres::Error) -> QuotaError {
    match error
        .as_db_error()
        .map(|database_error| database_error.code().code())
    {
        Some("42501") => QuotaError::WrongRuntimeIdentity,
        Some("55000") => QuotaError::CapabilityDrift,
        _ => QuotaError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_and_effective_limits_are_bounded() {
        assert_eq!(
            PublicQuotaLimits::new(60, 10),
            Ok(PublicQuotaLimits::v1_default())
        );
        assert_eq!(
            PublicQuotaLimits::new(61, 10),
            Err(QuotaError::InvalidPublicLimits)
        );
        assert_eq!(
            PublicQuotaLimits::new(60, 0),
            Err(QuotaError::InvalidPublicLimits)
        );

        let public = PublicQuotaLimits::new(45, 7).unwrap();
        assert_eq!(
            EffectiveQuotaLimits::lowered_from(public, 30, 5),
            Ok(EffectiveQuotaLimits {
                rate_per_minute: 30,
                burst_tokens: 5,
            })
        );
        assert_eq!(
            EffectiveQuotaLimits::lowered_from(public, 46, 5),
            Err(QuotaError::InvalidEffectiveLimits)
        );
        assert_eq!(
            EffectiveQuotaLimits::lowered_from(public, 30, 8),
            Err(QuotaError::InvalidEffectiveLimits)
        );
    }

    #[test]
    fn quota_key_uses_only_validated_exact_identifiers() {
        let key = QuotaKey::for_test("opencrvs", "person.status", 9_999_999_999);
        assert_eq!(key.workload_id, "opencrvs");
        assert_eq!(key.profile_id, "person.status");
        assert_eq!(key.profile_version, 9_999_999_999);
        assert!(!format!("{key:?}").contains("opencrvs"));
    }

    #[test]
    fn reservation_protocol_is_closed_and_retry_is_bounded() {
        let limits =
            EffectiveQuotaLimits::lowered_from(PublicQuotaLimits::v1_default(), 60, 10).unwrap();
        let allowed = QuotaReservation::Allowed(QuotaGrant {
            key: QuotaKey::for_test("opencrvs", "person.status", 1),
            limits,
        });
        match allowed {
            QuotaReservation::Allowed(grant) => {
                assert!(!format!("{grant:?}").contains("opencrvs"));
            }
            QuotaReservation::Exhausted(_) => panic!("expected allowed grant"),
        }

        let exhausted = QuotaReservation::Exhausted(QuotaExhaustion {
            retry_after: MAX_RETRY_AFTER,
        });
        match exhausted {
            QuotaReservation::Exhausted(exhaustion) => {
                assert_eq!(exhaustion.into_retry_after(), MAX_RETRY_AFTER);
            }
            QuotaReservation::Allowed(_) => panic!("expected exhaustion"),
        }
        assert_eq!(limits.rate_for_postgres(), 60);
    }
}
