// SPDX-License-Identifier: Apache-2.0
//! Rate limiting for citizen subject-access paths. Local/test runtimes keep
//! the existing in-process counters; PostgreSQL runtimes use typed Notary
//! state-plane operations over already-keyed pseudonyms.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use registry_notary_core::{
    Bounded, EvidenceEntityReference, EvidenceError, Hashed, HolderIdentifier,
    PreAuthorizedCodeIdentifier, PrincipalIdentifier, SubjectAccessDenialCode,
    SubjectAccessRateLimitsConfig, SubjectBinding,
};
use registry_platform_audit::AuditKeyHasher;
use time::{Duration, OffsetDateTime};

use crate::state_plane::NotaryStatePlaneHandle;

const MAX_RATE_LIMIT_KEY_LEN: usize = 128;

type RateLimitKey = Bounded<MAX_RATE_LIMIT_KEY_LEN>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectAccessRateLimitBucket {
    InvalidTokenPerClientAddress,
    PerPrincipal,
    SubjectMismatchPerPrincipal,
    PerHolderIssuance,
    CredentialIssuancePerPrincipal,
    TxCodeAttemptPerCode,
}

impl SubjectAccessRateLimitBucket {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTokenPerClientAddress => "invalid_token_per_client_address",
            Self::PerPrincipal => "per_principal",
            Self::SubjectMismatchPerPrincipal => "subject_mismatch_per_principal",
            Self::PerHolderIssuance => "per_holder_issuance",
            Self::CredentialIssuancePerPrincipal => "credential_issuance_per_principal",
            Self::TxCodeAttemptPerCode => "tx_code_attempt_per_code",
        }
    }

    const fn key_prefix(self) -> &'static str {
        match self {
            Self::InvalidTokenPerClientAddress => "it",
            Self::PerPrincipal => "pp",
            Self::SubjectMismatchPerPrincipal => "sm",
            Self::PerHolderIssuance => "hi",
            Self::CredentialIssuancePerPrincipal => "ci",
            Self::TxCodeAttemptPerCode => "tx",
        }
    }

    const fn window(self) -> Duration {
        match self {
            Self::InvalidTokenPerClientAddress
            | Self::PerPrincipal
            | Self::TxCodeAttemptPerCode => Duration::minutes(1),
            Self::SubjectMismatchPerPrincipal
            | Self::PerHolderIssuance
            | Self::CredentialIssuancePerPrincipal => Duration::hours(1),
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "invalid_token_per_client_address" => Some(Self::InvalidTokenPerClientAddress),
            "per_principal" => Some(Self::PerPrincipal),
            "subject_mismatch_per_principal" => Some(Self::SubjectMismatchPerPrincipal),
            "per_holder_issuance" => Some(Self::PerHolderIssuance),
            "credential_issuance_per_principal" => Some(Self::CredentialIssuancePerPrincipal),
            "tx_code_attempt_per_code" => Some(Self::TxCodeAttemptPerCode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAddressIdentifier {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAccessRateLimitError {
    Limited {
        bucket: SubjectAccessRateLimitBucket,
    },
    Unavailable {
        reason: String,
    },
}

impl SubjectAccessRateLimitError {
    #[must_use]
    pub fn evidence_error(&self) -> EvidenceError {
        match self {
            Self::Limited { .. } => EvidenceError::SubjectAccessRateLimited,
            Self::Unavailable { .. } => EvidenceError::SubjectAccessDenied {
                reason: SubjectAccessDenialCode::RateLimited,
            },
        }
    }

    #[must_use]
    pub const fn bucket(&self) -> Option<SubjectAccessRateLimitBucket> {
        match self {
            Self::Limited { bucket } => Some(*bucket),
            Self::Unavailable { .. } => None,
        }
    }
}

impl std::fmt::Display for SubjectAccessRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limited { bucket } => {
                write!(f, "subject-access rate limit exceeded: {}", bucket.as_str())
            }
            Self::Unavailable { reason } => {
                write!(f, "subject-access rate limiter unavailable: {reason}")
            }
        }
    }
}

impl std::error::Error for SubjectAccessRateLimitError {}

pub type SubjectAccessRateLimitResult<T> = Result<T, SubjectAccessRateLimitError>;

#[derive(Debug, Clone)]
pub struct SubjectAccessRateLimitKeys {
    hasher: AuditKeyHasher,
}

impl SubjectAccessRateLimitKeys {
    #[must_use]
    pub fn new(hasher: AuditKeyHasher) -> Self {
        Self { hasher }
    }

    pub fn principal(
        &self,
        principal_id: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<PrincipalIdentifier>> {
        self.hash_identifier("principal", principal_id)
    }

    pub fn client_address(
        &self,
        client_address: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<ClientAddressIdentifier>> {
        self.hash_identifier("client_address", client_address)
    }

    pub fn holder(
        &self,
        holder_id: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<HolderIdentifier>> {
        self.hash_identifier("holder", holder_id)
    }

    pub fn subject_binding(
        &self,
        subject_binding: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<SubjectBinding>> {
        self.hash_identifier("subject_binding", subject_binding)
    }

    /// Hash a delegated subject binding over the `(id_type, id)` pair rather than
    /// the bare value. Used only for the delegated requester and dependent target
    /// bindings so the hash distinguishes subjects that share an id value across
    /// different id-type schemes. Keyed under a dedicated domain class so it never
    /// collides with the value-only [`Self::subject_binding`] keyspace, and the
    /// non-delegated subject-access hashing stays byte-for-byte unchanged.
    pub fn delegated_subject_binding(
        &self,
        id_type: &str,
        id: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<SubjectBinding>> {
        if id_type.is_empty() || id.is_empty() {
            return Err(SubjectAccessRateLimitError::Unavailable {
                reason: "delegated subject binding identifier is empty".to_string(),
            });
        }
        let canonical_input = format!(
            "id_type\0{}\0{id_type}\0id\0{}\0{id}",
            id_type.len(),
            id.len()
        );
        let hashed = self.audit_reference_hash("delegated-subject-binding-v1", &canonical_input)?;
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }

    /// Hash a raw `pre-authorized_code` for use as a rate-limit key. The raw
    /// code is brute-forceable via its `tx_code` PIN, so the limiter must key
    /// by this hash and never by the raw code.
    pub fn pre_authorized_code(
        &self,
        pre_authorized_code: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<PreAuthorizedCodeIdentifier>> {
        self.hash_identifier("pre_authorized_code", pre_authorized_code)
    }

    pub fn subject_ref(
        &self,
        id_type: &str,
        subject_ref: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<SubjectBinding>> {
        if subject_ref.is_empty() {
            return Err(SubjectAccessRateLimitError::Unavailable {
                reason: "subject_ref identifier is empty".to_string(),
            });
        }
        let canonical_input = format!(
            "id_type\0{}\0{id_type}\0subject_ref\0{}\0{subject_ref}",
            id_type.len(),
            subject_ref.len()
        );
        let hashed =
            self.audit_reference_hash("subject-access-subject-ref-v1", &canonical_input)?;
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }

    pub fn audit_pseudonym_ref(
        &self,
        class: &str,
        canonical_input: &str,
    ) -> SubjectAccessRateLimitResult<Hashed<EvidenceEntityReference>> {
        if class.is_empty() || canonical_input.is_empty() {
            return Err(SubjectAccessRateLimitError::Unavailable {
                reason: "audit pseudonym input is empty".to_string(),
            });
        }
        let hashed = self.audit_reference_hash(class, canonical_input)?;
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }

    pub fn oid4vci_nonce(
        &self,
        issuer: &str,
        credential_configuration_id: &str,
        nonce: &str,
    ) -> SubjectAccessRateLimitResult<String> {
        if issuer.is_empty() || credential_configuration_id.is_empty() || nonce.is_empty() {
            return Err(SubjectAccessRateLimitError::Unavailable {
                reason: "oid4vci nonce identifier is empty".to_string(),
            });
        }
        let hashed = self.hasher.hash(&format!(
            "registry-notary:oid4vci:nonce:{issuer}:{credential_configuration_id}:{nonce}"
        ));
        ensure_bounded(&hashed)?;
        Ok(hashed)
    }

    fn hash_identifier<T>(&self, kind: &str, raw: &str) -> SubjectAccessRateLimitResult<Hashed<T>> {
        if raw.is_empty() {
            return Err(SubjectAccessRateLimitError::Unavailable {
                reason: format!("{kind} rate-limit identifier is empty"),
            });
        }
        let canonical_input = format!("value\0{}\0{raw}", raw.len());
        let class = format!("subject-access-{kind}-v1");
        let hashed = self.audit_reference_hash(&class, &canonical_input)?;
        ensure_bounded(&hashed)?;
        Ok(Hashed::from_hash(hashed))
    }

    fn audit_reference_hash(
        &self,
        class: &str,
        canonical_input: &str,
    ) -> SubjectAccessRateLimitResult<String> {
        self.hasher
            .audit_reference_hash(class, "", canonical_input)
            .map_err(|error| SubjectAccessRateLimitError::Unavailable {
                reason: error.to_string(),
            })
    }
}

#[derive(Debug)]
pub struct SubjectAccessRateLimiter {
    config: SubjectAccessRateLimitsConfig,
    state_plane: Option<Arc<NotaryStatePlaneHandle>>,
    counters: Mutex<HashMap<RateLimitKey, Counter>>,
}

impl SubjectAccessRateLimiter {
    #[must_use]
    pub fn new(config: SubjectAccessRateLimitsConfig) -> Self {
        Self {
            config,
            state_plane: None,
            counters: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub(crate) fn with_state_plane(
        config: SubjectAccessRateLimitsConfig,
        state_plane: Arc<NotaryStatePlaneHandle>,
    ) -> Self {
        Self {
            config,
            state_plane: Some(state_plane),
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_invalid_token_for_client_address(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let denial = BucketCheck::new(
            SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress,
            client_address.as_str(),
        )?;
        self.check_and_consume_current(Vec::new(), Some(denial))
            .await
    }

    pub async fn check_invalid_token_for_client_address_available(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let check = BucketCheck::new(
            SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress,
            client_address.as_str(),
        )?;
        self.check_only_current(&[check]).await
    }

    pub async fn check_authenticated_request(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        self.check_and_consume_current(checks, None).await
    }

    pub async fn consume_subject_mismatch_denial(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        let denial = BucketCheck::new(
            SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal,
            principal.as_str(),
        )?;
        self.check_and_consume_current(checks, Some(denial)).await
    }

    pub async fn consume_subject_mismatch_denial_only(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let denial = BucketCheck::new(
            SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal,
            principal.as_str(),
        )?;
        self.check_and_consume_current(Vec::new(), Some(denial))
            .await
    }

    pub async fn check_credential_issuance(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        holder: Option<&Hashed<HolderIdentifier>>,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = self.credential_issuance_checks(principal, holder)?;
        self.check_and_consume_current(checks, None).await
    }

    /// Record one `tx_code` attempt against a single (hashed)
    /// `pre-authorized_code`. After `tx_code_attempts_per_code_per_minute`
    /// attempts in the window the code is locked.
    pub async fn check_tx_code_attempt(
        &self,
        pre_authorized_code: &Hashed<PreAuthorizedCodeIdentifier>,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::TxCodeAttemptPerCode,
            pre_authorized_code.as_str(),
        )?];
        self.check_and_consume_current(checks, None).await
    }

    async fn check_and_consume_current(
        &self,
        checks: Vec<BucketCheck>,
        denial: Option<BucketCheck>,
    ) -> SubjectAccessRateLimitResult<()> {
        let Some(state_plane) = self
            .state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
        else {
            return self.check_and_consume(checks, denial, OffsetDateTime::now_utc());
        };
        let applicable = if let Some(denial) = denial {
            let mut applicable = Vec::with_capacity(checks.len() + 1);
            applicable.push(denial);
            applicable.extend(checks);
            applicable
        } else {
            checks
        };
        self.run_postgres_quota_operation(state_plane, &applicable, true)
            .await
    }

    async fn check_only_current(&self, checks: &[BucketCheck]) -> SubjectAccessRateLimitResult<()> {
        let Some(state_plane) = self
            .state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
        else {
            return self.check_only(checks, OffsetDateTime::now_utc());
        };
        self.run_postgres_quota_operation(state_plane, checks, false)
            .await
    }

    async fn run_postgres_quota_operation(
        &self,
        state_plane: &NotaryStatePlaneHandle,
        checks: &[BucketCheck],
        consume: bool,
    ) -> SubjectAccessRateLimitResult<()> {
        let bucket_kinds = checks
            .iter()
            .map(|check| check.bucket.as_str())
            .collect::<Vec<_>>();
        let key_hashes = checks
            .iter()
            .map(|check| decode_keyed_pseudonym_hash(&check.pseudonym))
            .collect::<Result<Vec<_>, _>>()?;
        let limits = checks
            .iter()
            .map(|check| {
                i32::try_from(self.limit_for(check.bucket)).map_err(|_| postgres_unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let window_seconds = checks
            .iter()
            .map(|check| {
                i32::try_from(check.bucket.window().whole_seconds())
                    .map_err(|_| postgres_unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let runtime = state_plane.runtime().map_err(|_| postgres_unavailable())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| postgres_unavailable())?;
        let statement = if consume {
            "SELECT allowed, denied_bucket, retry_after_seconds \
               FROM registry_notary_api.subject_access_quota_debit_v1($1, $2, $3, $4)"
        } else {
            "SELECT allowed, denied_bucket, retry_after_seconds \
               FROM registry_notary_api.subject_access_quota_check_v1($1, $2, $3, $4)"
        };
        let row = session
            .run_operation(session.client().query_one(
                statement,
                &[&bucket_kinds, &key_hashes, &limits, &window_seconds],
            ))
            .await
            .map_err(|_| postgres_unavailable())?;
        let allowed: bool = row.try_get("allowed").map_err(|_| postgres_unavailable())?;
        if allowed {
            return Ok(());
        }
        let denied_bucket: Option<String> = row
            .try_get("denied_bucket")
            .map_err(|_| postgres_unavailable())?;
        let bucket = denied_bucket
            .as_deref()
            .and_then(SubjectAccessRateLimitBucket::parse)
            .ok_or_else(postgres_unavailable)?;
        Err(SubjectAccessRateLimitError::Limited { bucket })
    }

    #[cfg(test)]
    fn check_invalid_token_for_client_address_at(
        &self,
        client_address: &Hashed<ClientAddressIdentifier>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let denial = BucketCheck::new(
            SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress,
            client_address.as_str(),
        )?;
        self.check_and_consume(Vec::new(), Some(denial), now)
    }

    #[cfg(test)]
    fn check_authenticated_request_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        self.check_and_consume(checks, None, now)
    }

    #[cfg(test)]
    fn consume_subject_mismatch_denial_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::PerPrincipal,
            principal.as_str(),
        )?];
        let denial = BucketCheck::new(
            SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal,
            principal.as_str(),
        )?;
        self.check_and_consume(checks, Some(denial), now)
    }

    #[cfg(test)]
    fn check_credential_issuance_at(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        holder: Option<&Hashed<HolderIdentifier>>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = self.credential_issuance_checks(principal, holder)?;
        self.check_and_consume(checks, None, now)
    }

    fn credential_issuance_checks(
        &self,
        principal: &Hashed<PrincipalIdentifier>,
        holder: Option<&Hashed<HolderIdentifier>>,
    ) -> SubjectAccessRateLimitResult<Vec<BucketCheck>> {
        let mut checks = vec![
            BucketCheck::new(
                SubjectAccessRateLimitBucket::PerPrincipal,
                principal.as_str(),
            )?,
            BucketCheck::new(
                SubjectAccessRateLimitBucket::CredentialIssuancePerPrincipal,
                principal.as_str(),
            )?,
        ];
        if let Some(holder) = holder {
            checks.push(BucketCheck::new(
                SubjectAccessRateLimitBucket::PerHolderIssuance,
                holder.as_str(),
            )?);
        }
        Ok(checks)
    }

    #[cfg(test)]
    fn check_tx_code_attempt_at(
        &self,
        pre_authorized_code: &Hashed<PreAuthorizedCodeIdentifier>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let checks = vec![BucketCheck::new(
            SubjectAccessRateLimitBucket::TxCodeAttemptPerCode,
            pre_authorized_code.as_str(),
        )?];
        self.check_and_consume(checks, None, now)
    }

    fn check_and_consume(
        &self,
        checks: Vec<BucketCheck>,
        denial: Option<BucketCheck>,
        now: OffsetDateTime,
    ) -> SubjectAccessRateLimitResult<()> {
        let mut counters =
            self.counters
                .lock()
                .map_err(|_| SubjectAccessRateLimitError::Unavailable {
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
                return Err(SubjectAccessRateLimitError::Limited {
                    bucket: over_limit.bucket,
                });
            }
        } else if let Some(over_limit) = checks
            .iter()
            .find(|check| !self.bucket_allows(&counters, check, now))
            .cloned()
        {
            return Err(SubjectAccessRateLimitError::Limited {
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
    ) -> SubjectAccessRateLimitResult<()> {
        let mut counters =
            self.counters
                .lock()
                .map_err(|_| SubjectAccessRateLimitError::Unavailable {
                    reason: "counter mutex is poisoned".to_string(),
                })?;
        prune_expired(&mut counters, now);
        if let Some(over_limit) = checks
            .iter()
            .find(|check| !self.bucket_allows(&counters, check, now))
        {
            return Err(SubjectAccessRateLimitError::Limited {
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

    const fn limit_for(&self, bucket: SubjectAccessRateLimitBucket) -> u32 {
        match bucket {
            SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress => {
                self.config.invalid_token_per_client_address_per_minute
            }
            SubjectAccessRateLimitBucket::PerPrincipal => self.config.per_principal_per_minute,
            SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal => {
                self.config.subject_mismatch_per_principal_per_hour
            }
            SubjectAccessRateLimitBucket::PerHolderIssuance => self.config.per_holder_per_hour,
            SubjectAccessRateLimitBucket::CredentialIssuancePerPrincipal => {
                self.config.credential_issuance_per_principal_per_hour
            }
            SubjectAccessRateLimitBucket::TxCodeAttemptPerCode => {
                self.config.tx_code_attempts_per_code_per_minute
            }
        }
    }

    #[cfg(test)]
    fn count_for(
        &self,
        bucket: SubjectAccessRateLimitBucket,
        hashed_id: &str,
    ) -> SubjectAccessRateLimitResult<u32> {
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
    bucket: SubjectAccessRateLimitBucket,
    key: RateLimitKey,
    pseudonym: String,
}

impl BucketCheck {
    fn new(
        bucket: SubjectAccessRateLimitBucket,
        hashed_id: &str,
    ) -> SubjectAccessRateLimitResult<Self> {
        Ok(Self {
            bucket,
            key: bucket_key(bucket, hashed_id)?,
            pseudonym: hashed_id.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
struct Counter {
    bucket: SubjectAccessRateLimitBucket,
    window_start: OffsetDateTime,
    used: u32,
}

impl Counter {
    fn in_window(&self, now: OffsetDateTime) -> bool {
        now < self.window_start + self.bucket.window()
    }
}

fn bucket_key(
    bucket: SubjectAccessRateLimitBucket,
    hashed_id: &str,
) -> SubjectAccessRateLimitResult<RateLimitKey> {
    ensure_bounded(hashed_id)?;
    RateLimitKey::new(format!("{}:{hashed_id}", bucket.key_prefix())).map_err(|error| {
        SubjectAccessRateLimitError::Unavailable {
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

fn ensure_bounded(value: &str) -> SubjectAccessRateLimitResult<()> {
    RateLimitKey::new(value)
        .map(|_| ())
        .map_err(|error| SubjectAccessRateLimitError::Unavailable {
            reason: error.to_string(),
        })
}

fn decode_keyed_pseudonym_hash(value: &str) -> SubjectAccessRateLimitResult<Vec<u8>> {
    let encoded = value
        .strip_prefix("hmac-sha256:")
        .ok_or_else(postgres_unavailable)?;
    if encoded.len() != 64 {
        return Err(postgres_unavailable());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(postgres_unavailable)?;
            let low = hex_nibble(pair[1]).ok_or_else(postgres_unavailable)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn postgres_unavailable() -> SubjectAccessRateLimitError {
    SubjectAccessRateLimitError::Unavailable {
        reason: "PostgreSQL subject-access quota operation failed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SubjectAccessRateLimitsConfig {
        SubjectAccessRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 2,
            per_principal_per_minute: 2,
            subject_mismatch_per_principal_per_hour: 2,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 2,
            tx_code_attempts_per_code_per_minute: 2,
        }
    }

    fn keys() -> SubjectAccessRateLimitKeys {
        SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only())
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp")
    }

    #[test]
    fn invalid_token_bucket_is_keyed_by_hashed_client_address() {
        let limiter = SubjectAccessRateLimiter::new(config());
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
            SubjectAccessRateLimitError::Limited {
                bucket: SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress,
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

    #[tokio::test]
    async fn invalid_token_availability_precheck_does_not_consume_quota() {
        let limiter = SubjectAccessRateLimiter::new(config());
        let client = keys()
            .client_address("203.0.113.10")
            .expect("client address hashes");

        for _ in 0..3 {
            limiter
                .check_invalid_token_for_client_address_available(&client)
                .await
                .expect("availability precheck does not debit quota");
        }
        limiter
            .check_invalid_token_for_client_address(&client)
            .await
            .expect("first rejected token is recorded");
        limiter
            .check_invalid_token_for_client_address(&client)
            .await
            .expect("second rejected token is recorded");
        let error = limiter
            .check_invalid_token_for_client_address_available(&client)
            .await
            .expect_err("precheck observes the exhausted bucket");

        assert_eq!(
            error.bucket(),
            Some(SubjectAccessRateLimitBucket::InvalidTokenPerClientAddress)
        );
    }

    #[test]
    fn postgres_key_decoder_accepts_only_keyed_32_byte_pseudonym_encodings() {
        let keyed = format!("hmac-sha256:{}", "cd".repeat(32));

        assert_eq!(decode_keyed_pseudonym_hash(&keyed), Ok(vec![0xcd; 32]));
        assert!(decode_keyed_pseudonym_hash(&format!("hmac-sha256:{}", "ab".repeat(31))).is_err());
        assert!(decode_keyed_pseudonym_hash(&format!("hmac-sha256:{}", "ag".repeat(32))).is_err());
        assert!(decode_keyed_pseudonym_hash(&format!("hmac-sha256:{}", "CD".repeat(32))).is_err());
        assert!(decode_keyed_pseudonym_hash(&format!("sha256:{}", "ab".repeat(32))).is_err());
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
    fn delegated_subject_binding_distinguishes_id_type_for_same_value() {
        let key_builder = keys();
        let national = key_builder
            .delegated_subject_binding("national_id", "CHILD-123")
            .expect("national_id binding hashes");
        let civil = key_builder
            .delegated_subject_binding("civil_registration_id", "CHILD-123")
            .expect("civil_registration_id binding hashes");

        assert_ne!(
            national, civil,
            "delegated binding must distinguish the same id value across id-type schemes"
        );
        // The composition must be delimiter-collision resistant.
        let split_value = key_builder
            .delegated_subject_binding("national_id", "x:CHILD-123")
            .expect("hashes");
        let split_type = key_builder
            .delegated_subject_binding("national_id:x", "CHILD-123")
            .expect("hashes");
        assert_ne!(
            split_value, split_type,
            "id_type and id must be encoded unambiguously before hashing"
        );
    }

    #[test]
    fn delegated_subject_binding_uses_separate_keyspace_from_subject_binding() {
        let key_builder = keys();
        let value_only = key_builder
            .subject_binding("CHILD-123")
            .expect("value-only binding hashes");
        let composed = key_builder
            .delegated_subject_binding("civil_registration_id", "CHILD-123")
            .expect("composed binding hashes");

        assert_ne!(
            value_only, composed,
            "delegated composition must not collide with the value-only subject_binding keyspace"
        );
    }

    #[test]
    fn delegated_subject_binding_rejects_empty_inputs() {
        let key_builder = keys();
        assert!(key_builder
            .delegated_subject_binding("", "CHILD-123")
            .is_err());
        assert!(key_builder
            .delegated_subject_binding("civil_registration_id", "")
            .is_err());
    }

    #[test]
    fn identity_keys_use_platform_audit_reference_domain() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let key_builder = SubjectAccessRateLimitKeys::new(hasher.clone());
        let principal = key_builder
            .principal("citizen-123")
            .expect("principal hashes");
        let expected = hasher
            .audit_reference_hash(
                "subject-access-principal-v1",
                "",
                &format!("value\0{}\0citizen-123", "citizen-123".len()),
            )
            .expect("reference hash");
        let legacy = hasher.hash("registry-notary:subject-access:principal:citizen-123");

        assert_eq!(principal.as_str(), expected);
        assert_ne!(principal.as_str(), legacy);
    }

    #[test]
    fn audit_pseudonym_ref_uses_separate_domain_from_subject_ref() {
        let key_builder = keys();
        let subject_ref = key_builder
            .subject_ref("national_id", "rnref:v1:target")
            .expect("subject ref hashes");
        let audit_ref = key_builder
            .audit_pseudonym_ref(
                "matched-reference-v1",
                r#"{"class":"matched-reference-v1","handle":"rnref:v1:target"}"#,
            )
            .expect("audit pseudonym hashes");

        assert_ne!(
            subject_ref.as_str(),
            audit_ref.as_str(),
            "audit pseudonyms must not be interchangeable with legacy subject refs"
        );
    }

    #[test]
    fn authenticated_request_consumes_per_principal_bucket() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        let limiter = SubjectAccessRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("first authenticated request is allowed");
        let error = limiter
            .check_authenticated_request_at(&principal, now())
            .expect_err("second authenticated request is limited");

        assert_eq!(
            error.bucket(),
            Some(SubjectAccessRateLimitBucket::PerPrincipal)
        );
    }

    #[test]
    fn subject_mismatch_denial_consumes_principal_and_denial_buckets() {
        let mut config = config();
        config.per_principal_per_minute = 2;
        config.subject_mismatch_per_principal_per_hour = 1;
        let limiter = SubjectAccessRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .consume_subject_mismatch_denial_at(&principal, now())
            .expect("subject mismatch is recorded");
        assert_eq!(
            limiter
                .count_for(
                    SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            1
        );
        assert_eq!(
            limiter
                .count_for(
                    SubjectAccessRateLimitBucket::PerPrincipal,
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
            Some(SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal)
        );
    }

    #[test]
    fn subject_mismatch_denial_is_atomic_when_principal_bucket_is_over_limit() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        config.subject_mismatch_per_principal_per_hour = 2;
        let limiter = SubjectAccessRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("principal bucket is consumed");
        let error = limiter
            .consume_subject_mismatch_denial_at(&principal, now())
            .expect_err("principal bucket is over limit");

        assert_eq!(
            error.bucket(),
            Some(SubjectAccessRateLimitBucket::PerPrincipal)
        );
        assert_eq!(
            limiter
                .count_for(
                    SubjectAccessRateLimitBucket::SubjectMismatchPerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            0
        );
    }

    #[test]
    fn credential_issuance_is_atomic_across_holder_and_principal_buckets() {
        let limiter = SubjectAccessRateLimiter::new(config());
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
            Some(SubjectAccessRateLimitBucket::PerHolderIssuance)
        );

        limiter
            .check_credential_issuance_at(&principal, Some(&holder_two), now())
            .expect("failed holder attempt did not consume principal issuance bucket");
        assert_eq!(
            limiter
                .count_for(
                    SubjectAccessRateLimitBucket::CredentialIssuancePerPrincipal,
                    principal.as_str()
                )
                .expect("counter can be read"),
            2
        );
    }

    #[test]
    fn tx_code_attempts_lock_a_single_pre_authorized_code() {
        let mut config = config();
        config.tx_code_attempts_per_code_per_minute = 2;
        let limiter = SubjectAccessRateLimiter::new(config);
        let code = keys()
            .pre_authorized_code("pre-auth-code-secret")
            .expect("pre-authorized code hashes");

        limiter
            .check_tx_code_attempt_at(&code, now())
            .expect("first tx_code attempt is recorded");
        limiter
            .check_tx_code_attempt_at(&code, now())
            .expect("second tx_code attempt is recorded");
        let error = limiter
            .check_tx_code_attempt_at(&code, now())
            .expect_err("third tx_code attempt is limited");

        assert_eq!(
            error.bucket(),
            Some(SubjectAccessRateLimitBucket::TxCodeAttemptPerCode)
        );
    }

    #[test]
    fn tx_code_bucket_is_keyed_by_hashed_code_not_the_raw_code() {
        let limiter = SubjectAccessRateLimiter::new(config());
        let raw_code = "pre-auth-code-secret";
        let code = keys()
            .pre_authorized_code(raw_code)
            .expect("pre-authorized code hashes");

        limiter
            .check_tx_code_attempt_at(&code, now())
            .expect("tx_code attempt is recorded");

        assert!(
            limiter
                .stored_keys()
                .iter()
                .all(|key| !key.contains(raw_code)),
            "raw pre-authorized_code must not be stored in limiter keys"
        );
    }

    #[test]
    fn tx_code_attempts_are_isolated_per_code() {
        let mut config = config();
        config.tx_code_attempts_per_code_per_minute = 1;
        let limiter = SubjectAccessRateLimiter::new(config);
        let key_builder = keys();
        let code_one = key_builder
            .pre_authorized_code("code-one")
            .expect("first code hashes");
        let code_two = key_builder
            .pre_authorized_code("code-two")
            .expect("second code hashes");

        limiter
            .check_tx_code_attempt_at(&code_one, now())
            .expect("first attempt on code-one is allowed");
        let error = limiter
            .check_tx_code_attempt_at(&code_one, now())
            .expect_err("second attempt on code-one is limited");
        assert_eq!(
            error.bucket(),
            Some(SubjectAccessRateLimitBucket::TxCodeAttemptPerCode)
        );
        limiter
            .check_tx_code_attempt_at(&code_two, now())
            .expect("a different code is tracked independently");
    }

    #[test]
    fn windows_expire_and_reset() {
        let mut config = config();
        config.per_principal_per_minute = 1;
        let limiter = SubjectAccessRateLimiter::new(config);
        let principal = keys().principal("citizen-123").expect("principal hashes");

        limiter
            .check_authenticated_request_at(&principal, now())
            .expect("first request is allowed");
        limiter
            .check_authenticated_request_at(&principal, now() + Duration::minutes(1))
            .expect("next minute resets the bucket");
    }
}
