// SPDX-License-Identifier: Apache-2.0
//! In-process rate limiting for citizen self-attestation paths.

use std::collections::HashMap;
use std::sync::Mutex;

use registry_platform_audit::AuditKeyHasher;
use registry_witness_core::{
    Bounded, EvidenceError, Hashed, HolderIdentifier, PrincipalIdentifier,
    SelfAttestationDenialCode, SelfAttestationRateLimitsConfig, SubjectBinding,
};
use time::{Duration, OffsetDateTime};

const MAX_RATE_LIMIT_KEY_LEN: usize = 128;

type RateLimitKey = Bounded<MAX_RATE_LIMIT_KEY_LEN>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfAttestationRateLimitBucket {
    InvalidTokenPerClientAddress,
    PerPrincipal,
    SubjectMismatchPerPrincipal,
    PerHolderIssuance,
    CredentialIssuancePerPrincipal,
}

impl SelfAttestationRateLimitBucket {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTokenPerClientAddress => "invalid_token_per_client_address",
            Self::PerPrincipal => "per_principal",
            Self::SubjectMismatchPerPrincipal => "subject_mismatch_per_principal",
            Self::PerHolderIssuance => "per_holder_issuance",
            Self::CredentialIssuancePerPrincipal => "credential_issuance_per_principal",
        }
    }

    const fn key_prefix(self) -> &'static str {
        match self {
            Self::InvalidTokenPerClientAddress => "it",
            Self::PerPrincipal => "pp",
            Self::SubjectMismatchPerPrincipal => "sm",
            Self::PerHolderIssuance => "hi",
            Self::CredentialIssuancePerPrincipal => "ci",
        }
    }

    const fn window(self) -> Duration {
        match self {
            Self::InvalidTokenPerClientAddress | Self::PerPrincipal => Duration::minutes(1),
            Self::SubjectMismatchPerPrincipal
            | Self::PerHolderIssuance
            | Self::CredentialIssuancePerPrincipal => Duration::hours(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAddressIdentifier {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAttestationRateLimitError {
    Limited {
        bucket: SelfAttestationRateLimitBucket,
    },
    Unavailable {
        reason: String,
    },
}

impl SelfAttestationRateLimitError {
    #[must_use]
    pub fn evidence_error(&self) -> EvidenceError {
        match self {
            Self::Limited { .. } => EvidenceError::SelfAttestationRateLimited,
            Self::Unavailable { .. } => EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::RateLimited,
            },
        }
    }

    #[must_use]
    pub const fn bucket(&self) -> Option<SelfAttestationRateLimitBucket> {
        match self {
            Self::Limited { bucket } => Some(*bucket),
            Self::Unavailable { .. } => None,
        }
    }
}

impl std::fmt::Display for SelfAttestationRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limited { bucket } => {
                write!(
                    f,
                    "self-attestation rate limit exceeded: {}",
                    bucket.as_str()
                )
            }
            Self::Unavailable { reason } => {
                write!(f, "self-attestation rate limiter unavailable: {reason}")
            }
        }
    }
}

impl std::error::Error for SelfAttestationRateLimitError {}

pub type SelfAttestationRateLimitResult<T> = Result<T, SelfAttestationRateLimitError>;

#[derive(Debug, Clone)]
pub struct SelfAttestationRateLimitKeys {
    hasher: AuditKeyHasher,
}

impl SelfAttestationRateLimitKeys {
    #[must_use]
    pub fn new(hasher: AuditKeyHasher) -> Self {
        Self { hasher }
    }

    pub fn principal(
        &self,
        principal_id: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<PrincipalIdentifier>> {
        self.hash_identifier("principal", principal_id)
    }

    pub fn client_address(
        &self,
        client_address: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<ClientAddressIdentifier>> {
        self.hash_identifier("client_address", client_address)
    }

    pub fn holder(
        &self,
        holder_id: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<HolderIdentifier>> {
        self.hash_identifier("holder", holder_id)
    }

    pub fn subject_binding(
        &self,
        subject_binding: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<SubjectBinding>> {
        self.hash_identifier("subject_binding", subject_binding)
    }

    pub fn subject_ref(
        &self,
        id_type: &str,
        subject_ref: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<SubjectBinding>> {
        if subject_ref.is_empty() {
            return Err(SelfAttestationRateLimitError::Unavailable {
                reason: "subject_ref identifier is empty".to_string(),
            });
        }
        let hashed = self.hasher.hash(&format!(
            "registry-witness:subject-ref:{}:{id_type}:{}:{subject_ref}",
            id_type.len(),
            subject_ref.len()
        ));
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }

    pub fn oid4vci_nonce(
        &self,
        issuer: &str,
        credential_configuration_id: &str,
        nonce: &str,
    ) -> SelfAttestationRateLimitResult<String> {
        if issuer.is_empty() || credential_configuration_id.is_empty() || nonce.is_empty() {
            return Err(SelfAttestationRateLimitError::Unavailable {
                reason: "oid4vci nonce identifier is empty".to_string(),
            });
        }
        let hashed = self.hasher.hash(&format!(
            "registry-witness:oid4vci:nonce:{issuer}:{credential_configuration_id}:{nonce}"
        ));
        ensure_bounded(&hashed)?;
        Ok(hashed)
    }

    fn hash_identifier<T>(
        &self,
        kind: &str,
        raw: &str,
    ) -> SelfAttestationRateLimitResult<Hashed<T>> {
        if raw.is_empty() {
            return Err(SelfAttestationRateLimitError::Unavailable {
                reason: format!("{kind} rate-limit identifier is empty"),
            });
        }
        let hashed = self
            .hasher
            .hash(&format!("registry-witness:self-attestation:{kind}:{raw}"));
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }
}

#[derive(Debug)]
pub struct SelfAttestationRateLimiter {
    config: SelfAttestationRateLimitsConfig,
    counters: Mutex<HashMap<RateLimitKey, Counter>>,
}

impl SelfAttestationRateLimiter {
    #[must_use]
    pub fn new(config: SelfAttestationRateLimitsConfig) -> Self {
        Self {
            config,
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_invalid_token_for_client_address(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.check_invalid_token_for_client_address_at(client_address, OffsetDateTime::now_utc())
    }

    pub fn check_invalid_token_for_client_address_available(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.check_invalid_token_for_client_address_available_at(
            client_address,
            OffsetDateTime::now_utc(),
        )
    }

    pub fn check_authenticated_request(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.check_authenticated_request_at(principal, OffsetDateTime::now_utc())
    }

    pub fn consume_subject_mismatch_denial(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.consume_subject_mismatch_denial_at(principal, OffsetDateTime::now_utc())
    }

    pub fn consume_subject_mismatch_denial_only(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.consume_subject_mismatch_denial_only_at(principal, OffsetDateTime::now_utc())
    }

    pub fn check_credential_issuance(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        holder: Option<&Hashed<HolderIdentifier>>,
    ) -> SelfAttestationRateLimitResult<()> {
        self.check_credential_issuance_at(principal, holder, OffsetDateTime::now_utc())
    }

    fn check_invalid_token_for_client_address_at(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let denial = BucketCheck::new(
            SelfAttestationRateLimitBucket::InvalidTokenPerClientAddress,
            client_address.as_str(),
        )?;
        self.check_and_consume(Vec::new(), Some(denial), now)
    }

    fn check_invalid_token_for_client_address_available_at(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let check = BucketCheck::new(
            SelfAttestationRateLimitBucket::InvalidTokenPerClientAddress,
            client_address.as_str(),
        )?;
        self.check_only(&[check], now)
    }

    fn check_authenticated_request_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SelfAttestationRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        self.check_and_consume(checks, None, now)
    }

    fn consume_subject_mismatch_denial_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SelfAttestationRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        let denial = BucketCheck::new(
            SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal,
            principal.as_str(),
        )?;
        self.check_and_consume(checks, Some(denial), now)
    }

    fn consume_subject_mismatch_denial_only_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let denial = BucketCheck::new(
            SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal,
            principal.as_str(),
        )?;
        self.check_and_consume(Vec::new(), Some(denial), now)
    }

    fn check_credential_issuance_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        holder: Option<&Hashed<HolderIdentifier>>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let mut checks = vec![
            BucketCheck::new(
                SelfAttestationRateLimitBucket::PerPrincipal,
                principal.as_str(),
            )?,
            BucketCheck::new(
                SelfAttestationRateLimitBucket::CredentialIssuancePerPrincipal,
                principal.as_str(),
            )?,
        ];
        if let Some(holder) = holder {
            checks.push(BucketCheck::new(
                SelfAttestationRateLimitBucket::PerHolderIssuance,
                holder.as_str(),
            )?);
        }
        self.check_and_consume(checks, None, now)
    }

    fn check_and_consume(
        &self,
        checks: Vec<BucketCheck>,
        denial: Option<BucketCheck>,
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let mut counters =
            self.counters
                .lock()
                .map_err(|_| SelfAttestationRateLimitError::Unavailable {
                    reason: "counter mutex is poisoned".to_string(),
                })?;
        prune_expired(&mut counters, now);

        if let Some(denial) = &denial {
            let mut applicable = vec![denial.clone()];
            applicable.extend(checks.clone());
            if let Some(over_limit) = applicable
                .iter()
                .find(|check| !self.bucket_allows(&counters, check, now))
                .cloned()
            {
                return Err(SelfAttestationRateLimitError::Limited {
                    bucket: over_limit.bucket,
                });
            }
        } else if let Some(over_limit) = checks
            .iter()
            .find(|check| !self.bucket_allows(&counters, check, now))
            .cloned()
        {
            return Err(SelfAttestationRateLimitError::Limited {
                bucket: over_limit.bucket,
            });
        }

        if let Some(denial) = denial {
            for check in &checks {
                consume_bucket(&mut counters, check, now);
            }
            consume_bucket(&mut counters, &denial, now);
        } else {
            for check in &checks {
                consume_bucket(&mut counters, check, now);
            }
        }
        Ok(())
    }

    fn check_only(
        &self,
        checks: &[BucketCheck],
        now: OffsetDateTime,
    ) -> SelfAttestationRateLimitResult<()> {
        let mut counters =
            self.counters
                .lock()
                .map_err(|_| SelfAttestationRateLimitError::Unavailable {
                    reason: "counter mutex is poisoned".to_string(),
                })?;
        prune_expired(&mut counters, now);
        if let Some(over_limit) = checks
            .iter()
            .find(|check| !self.bucket_allows(&counters, check, now))
        {
            return Err(SelfAttestationRateLimitError::Limited {
                bucket: over_limit.bucket,
            });
        }
        Ok(())
    }

    fn bucket_allows(
        &self,
        counters: &HashMap<RateLimitKey, Counter>,
        check: &BucketCheck,
        now: OffsetDateTime,
    ) -> bool {
        let limit = self.limit_for(check.bucket);
        if limit == 0 {
            return false;
        }
        match counters.get(&check.key) {
            Some(counter) if counter.in_window(now) => counter.used < limit,
            _ => true,
        }
    }

    const fn limit_for(&self, bucket: SelfAttestationRateLimitBucket) -> u32 {
        match bucket {
            SelfAttestationRateLimitBucket::InvalidTokenPerClientAddress => {
                self.config.invalid_token_per_client_address_per_minute
            }
            SelfAttestationRateLimitBucket::PerPrincipal => self.config.per_principal_per_minute,
            SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal => {
                self.config.subject_mismatch_per_principal_per_hour
            }
            SelfAttestationRateLimitBucket::PerHolderIssuance => self.config.per_holder_per_hour,
            SelfAttestationRateLimitBucket::CredentialIssuancePerPrincipal => {
                self.config.credential_issuance_per_principal_per_hour
            }
        }
    }

    #[cfg(test)]
    fn count_for(
        &self,
        bucket: SelfAttestationRateLimitBucket,
        hashed_id: &str,
    ) -> SelfAttestationRateLimitResult<u32> {
        let key = bucket_key(bucket, hashed_id)?;
        Ok(self
            .counters
            .lock()
            .expect("counter mutex is not poisoned")
            .get(&key)
            .map(|counter| counter.used)
            .unwrap_or(0))
    }

    #[cfg(test)]
    fn stored_keys(&self) -> Vec<String> {
        self.counters
            .lock()
            .expect("counter mutex is not poisoned")
            .keys()
            .map(|key| key.as_str().to_string())
            .collect()
    }
}

#[derive(Debug, Clone)]
struct BucketCheck {
    bucket: SelfAttestationRateLimitBucket,
    key: RateLimitKey,
}

impl BucketCheck {
    fn new(
        bucket: SelfAttestationRateLimitBucket,
        hashed_id: &str,
    ) -> SelfAttestationRateLimitResult<Self> {
        Ok(Self {
            bucket,
            key: bucket_key(bucket, hashed_id)?,
        })
    }
}

#[derive(Debug, Clone)]
struct Counter {
    bucket: SelfAttestationRateLimitBucket,
    window_start: OffsetDateTime,
    used: u32,
}

impl Counter {
    fn in_window(&self, now: OffsetDateTime) -> bool {
        now < self.window_start + self.bucket.window()
    }
}

fn bucket_key(
    bucket: SelfAttestationRateLimitBucket,
    hashed_id: &str,
) -> SelfAttestationRateLimitResult<RateLimitKey> {
    ensure_bounded(hashed_id)?;
    RateLimitKey::new(format!("{}:{hashed_id}", bucket.key_prefix())).map_err(|error| {
        SelfAttestationRateLimitError::Unavailable {
            reason: error.to_string(),
        }
    })
}

fn consume_bucket(
    counters: &mut HashMap<RateLimitKey, Counter>,
    check: &BucketCheck,
    now: OffsetDateTime,
) {
    let counter = counters.entry(check.key.clone()).or_insert(Counter {
        bucket: check.bucket,
        window_start: now,
        used: 0,
    });
    if !counter.in_window(now) {
        counter.window_start = now;
        counter.used = 0;
    }
    counter.used = counter.used.saturating_add(1);
}

fn prune_expired(counters: &mut HashMap<RateLimitKey, Counter>, now: OffsetDateTime) {
    counters.retain(|_, counter| counter.in_window(now));
}

fn ensure_bounded(value: &str) -> SelfAttestationRateLimitResult<()> {
    RateLimitKey::new(value).map(|_| ()).map_err(|error| {
        SelfAttestationRateLimitError::Unavailable {
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SelfAttestationRateLimitsConfig {
        SelfAttestationRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 2,
            per_principal_per_minute: 2,
            subject_mismatch_per_principal_per_hour: 2,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 2,
            ..SelfAttestationRateLimitsConfig::default()
        }
    }

    fn keys() -> SelfAttestationRateLimitKeys {
        SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only())
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp")
    }

    #[test]
    fn invalid_token_bucket_is_keyed_by_hashed_client_address() {
        let limiter = SelfAttestationRateLimiter::new(config());
        let client = keys()
            .client_address("203.0.113.10")
            .expect("client address hashes");

        limiter
            .check_invalid_token_for_client_address_at(&client, now())
            .expect("first invalid-token attempt is recorded");
        limiter
            .check_invalid_token_for_client_address_at(&client, now())
            .expect("second invalid-token attempt is recorded");
        let error = limiter
            .check_invalid_token_for_client_address_at(&client, now())
            .expect_err("third invalid-token attempt is limited");

        assert_eq!(
            error,
            SelfAttestationRateLimitError::Limited {
                bucket: SelfAttestationRateLimitBucket::InvalidTokenPerClientAddress,
            }
        );
        assert!(
            limiter
                .stored_keys()
                .iter()
                .all(|key| !key.contains("203.0.113.10")),
            "raw client address must not be stored in limiter keys"
        );
    }

    #[test]
    fn subject_ref_hash_is_delimiter_collision_resistant() {
        let key_builder = keys();
        let first = key_builder
            .subject_ref("national_id", "123:456")
            .expect("first subject ref hashes");
        let second = key_builder
            .subject_ref("national_id:123", "456")
            .expect("second subject ref hashes");

        assert_ne!(
            first, second,
            "id_type and subject_ref must be encoded unambiguously before hashing"
        );
    }

    #[test]
    fn authenticated_request_consumes_per_principal_bucket() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        let limiter = SelfAttestationRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("first authenticated request is allowed");
        let error = limiter
            .check_authenticated_request_at(&principal, now())
            .expect_err("second authenticated request is limited");

        assert_eq!(
            error.bucket(),
            Some(SelfAttestationRateLimitBucket::PerPrincipal)
        );
    }

    #[test]
    fn subject_mismatch_denial_consumes_principal_and_denial_buckets() {
        let mut config = config();
        config.per_principal_per_minute = 2;
        config.subject_mismatch_per_principal_per_hour = 1;
        let limiter = SelfAttestationRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .consume_subject_mismatch_denial_at(&principal, now())
            .expect("subject mismatch is recorded");
        assert_eq!(
            limiter
                .count_for(
                    SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            1
        );
        assert_eq!(
            limiter
                .count_for(
                    SelfAttestationRateLimitBucket::PerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            1
        );

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("principal bucket has one remaining request");
        let error = limiter
            .consume_subject_mismatch_denial_at(&principal, now())
            .expect_err("second subject mismatch is limited");
        assert_eq!(
            error.bucket(),
            Some(SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal)
        );
    }

    #[test]
    fn subject_mismatch_denial_is_atomic_when_principal_bucket_is_over_limit() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        config.subject_mismatch_per_principal_per_hour = 2;
        let limiter = SelfAttestationRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("principal bucket is consumed");
        let error = limiter
            .consume_subject_mismatch_denial_at(&principal, now())
            .expect_err("principal bucket is over limit");

        assert_eq!(
            error.bucket(),
            Some(SelfAttestationRateLimitBucket::PerPrincipal)
        );
        assert_eq!(
            limiter
                .count_for(
                    SelfAttestationRateLimitBucket::SubjectMismatchPerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            0
        );
    }

    #[test]
    fn credential_issuance_is_atomic_across_holder_and_principal_buckets() {
        let limiter = SelfAttestationRateLimiter::new(config());
        let key_builder = keys();
        let principal = key_builder
            .principal("citizen-123")
            .expect("principal hashes");
        let holder_one = key_builder
            .holder("did:jwk:holder-one")
            .expect("holder hashes");
        let holder_two = key_builder
            .holder("did:jwk:holder-two")
            .expect("holder hashes");

        limiter
            .check_credential_issuance_at(&principal, Some(&holder_one), now())
            .expect("first issuance is allowed");
        let error = limiter
            .check_credential_issuance_at(&principal, Some(&holder_one), now())
            .expect_err("same holder is limited");
        assert_eq!(
            error.bucket(),
            Some(SelfAttestationRateLimitBucket::PerHolderIssuance)
        );

        limiter
            .check_credential_issuance_at(&principal, Some(&holder_two), now())
            .expect("failed holder attempt did not consume principal issuance bucket");
        assert_eq!(
            limiter
                .count_for(
                    SelfAttestationRateLimitBucket::CredentialIssuancePerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            2
        );
    }

    #[test]
    fn windows_expire_and_reset() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        let limiter = SelfAttestationRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("first request is allowed");
        limiter
            .check_authenticated_request_at(&principal, now() + Duration::minutes(1))
            .expect("next minute resets the bucket");
    }
}
