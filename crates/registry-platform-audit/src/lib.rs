// SPDX-License-Identifier: Apache-2.0
//! Tamper-evident audit envelopes, async sinks, and redaction helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_FILES: u32 = 50;
const MIN_AUDIT_SECRET_BYTES: usize = 32;
const KEYED_HASH_PREFIX: &str = "hmac-sha256:";
const UNKEYED_HASH_PREFIX: &str = "sha256:";
const CHAIN_HMAC_CONTEXT: &[u8] = b"registry-platform-audit-chain-v1";
const AUDIT_REFERENCE_HASH_CONTEXT: &str = "registry-platform:audit-reference:v1";

/// Stable schema identifier for sink-built durable phase records.
pub const DURABLE_AUDIT_RECORD_SCHEMA_V1: &str = "registry.durable-audit/v1";

/// HKDF-Expand `info` label deriving the chain-integrity sub-key (AUDIT-03).
const CHAIN_KEY_DERIVATION_INFO: &[u8] = b"registry-platform-audit/chain-key/v1";
/// HKDF-Expand `info` label deriving the identifier-hashing sub-key (AUDIT-03).
const IDENTIFIER_KEY_DERIVATION_INFO: &[u8] = b"registry-platform-audit/identifier-key/v1";

/// One chained audit record.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEnvelope {
    /// ULID assigned by the chain when the record is appended.
    pub envelope_id: String,
    /// UTC Unix timestamp in milliseconds.
    pub timestamp_unix_ms: i64,
    /// Previous envelope hash, or `None` for the genesis record.
    #[serde(with = "option_hash_hex")]
    pub prev_hash: Option<[u8; 32]>,
    /// Consumer-owned audit event body.
    pub record: Value,
    /// Hash of `{ envelope_id, timestamp_unix_ms, prev_hash, record }`,
    /// serialized as lowercase hex in JSONL.
    #[serde(with = "hash_hex")]
    pub record_hash: [u8; 32],
}

impl fmt::Debug for AuditEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEnvelope")
            .field("envelope_id", &self.envelope_id)
            .field("timestamp_unix_ms", &self.timestamp_unix_ms)
            .field("prev_hash", &self.prev_hash)
            .field("record", &"<redacted>")
            .field("record_hash", &self.record_hash)
            .finish()
    }
}

impl AuditEnvelope {
    #[cfg(test)]
    fn new(record: Value, prev_hash: Option<[u8; 32]>) -> Result<Self, AuditError> {
        Self::new_with_hasher(record, prev_hash, &AuditChainHasher::unkeyed_dev_only())
    }

    fn new_with_hasher(
        record: Value,
        prev_hash: Option<[u8; 32]>,
        hasher: &AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let envelope_id = Ulid::new().to_string();
        let timestamp_unix_ms = now_unix_ms();
        let record_hash = record_hash(
            &envelope_id,
            timestamp_unix_ms,
            prev_hash.as_ref(),
            &record,
            hasher,
        )?;
        Ok(Self {
            envelope_id,
            timestamp_unix_ms,
            prev_hash,
            record,
            record_hash,
        })
    }

    /// Serialize as one JSON line terminated by `\n`.
    pub fn to_jsonl(&self) -> Result<String, AuditError> {
        let mut line = serde_json::to_string(self).map_err(AuditError::Json)?;
        line.push('\n');
        Ok(line)
    }
}

/// Mutable audit chain state.
#[derive(Debug)]
pub struct ChainState {
    hasher: AuditChainHasher,
    last_hash: tokio::sync::Mutex<Option<[u8; 32]>>,
}

impl ChainState {
    /// Start a fresh production chain using a keyed audit-chain hasher.
    #[must_use]
    pub fn new(hasher: AuditChainHasher) -> Self {
        Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(None),
        }
    }

    /// Start a fresh unkeyed chain for tests and local development.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::new(AuditChainHasher::unkeyed_dev_only())
    }

    /// Bootstrap a production chain from a tailable sink's current tail hash.
    pub async fn bootstrap(
        sink: &dyn AuditSink,
        hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let Some(tail_hash) = sink.tail_hash_with_hasher(&hasher).await? else {
            return Err(AuditError::NonTailableSink);
        };
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(Some(tail_hash)),
        })
    }

    /// Bootstrap from a sink that may be empty, using an explicit keyed hasher.
    pub async fn bootstrap_or_start_empty(
        sink: &dyn AuditSink,
        hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
        let last_hash = sink.tail_hash_with_hasher(&hasher).await?;
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(last_hash),
        })
    }

    /// Bootstrap or restart from genesis for tests and local development.
    pub async fn bootstrap_unkeyed_dev_only(sink: &dyn AuditSink) -> Result<Self, AuditError> {
        let hasher = AuditChainHasher::unkeyed_dev_only();
        let last_hash = sink.tail_hash_with_hasher(&hasher).await?;
        Ok(Self {
            hasher,
            last_hash: tokio::sync::Mutex::new(last_hash),
        })
    }

    /// Return the current in-memory tail hash.
    pub async fn last_hash(&self) -> Option<[u8; 32]> {
        *self.last_hash.lock().await
    }

    /// Return the current in-memory tail hash without waiting behind an append.
    ///
    /// `None` means an append currently owns the chain state. Readiness callers
    /// must fail closed instead of waiting on a potentially stalled audit sink.
    pub fn try_last_hash(&self) -> Option<Option<[u8; 32]>> {
        self.last_hash.try_lock().ok().map(|last_hash| *last_hash)
    }

    /// Append a serializable record, persist it through `sink`, and advance the chain.
    ///
    /// The state advances only after the sink write succeeds. Concurrent appends are
    /// serialized so every record observes the previous successful write.
    pub async fn append<T: Serialize + Send>(
        &self,
        sink: &dyn AuditSink,
        record: T,
    ) -> Result<AuditEnvelope, AuditError> {
        let record = serde_json::to_value(record).map_err(AuditError::Json)?;
        let mut last_hash = self.last_hash.lock().await;
        let envelope = AuditEnvelope::new_with_hasher(record, *last_hash, &self.hasher)?;
        sink.write(&envelope).await?;
        *last_hash = Some(envelope.record_hash);
        Ok(envelope)
    }
}

/// Named audit-chain profile for applications that need to bootstrap a chain
/// without owning the low-level hash mode selection.
#[derive(Clone, Debug)]
pub struct AuditChainProfile {
    hasher: AuditChainHasher,
}

impl AuditChainProfile {
    /// Production profile backed by the HMAC secret in `env_var_name`.
    ///
    /// The chain key is an HKDF-derived sub-key of the master env secret so it is
    /// domain-separated from the identifier key derived by [`AuditProfile`]
    /// (AUDIT-03). Both profiles derive the same chain sub-key from the same env
    /// secret, so a chain bootstrapped via either profile stays consistent.
    pub fn production_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self {
            hasher: AuditChainHasher::from_env_derived(env_var_name)?,
        })
    }

    /// Registry Relay production audit-chain profile.
    pub fn registry_relay_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Registry Notary production audit-chain profile.
    pub fn registry_notary_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Explicit test and local-development profile.
    #[must_use]
    pub fn dev_unkeyed() -> Self {
        Self {
            hasher: AuditChainHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn hasher(&self) -> AuditChainHasher {
        self.hasher.clone()
    }

    pub async fn bootstrap_or_start_empty(
        &self,
        sink: &dyn AuditSink,
    ) -> Result<ChainState, AuditError> {
        ChainState::bootstrap_or_start_empty(sink, self.hasher()).await
    }
}

/// Shared application audit profile for keyed chain integrity and identifier
/// hashing.
#[derive(Clone, Debug)]
pub struct AuditProfile {
    chain_hasher: AuditChainHasher,
    key_hasher: AuditKeyHasher,
}

impl AuditProfile {
    /// Production profile backed by the HMAC secret in `env_var_name`.
    ///
    /// The chain key and identifier key are independent HKDF-derived sub-keys of
    /// the master env secret, each bound to a distinct per-purpose `info` label
    /// (AUDIT-03). A leak of one derived sub-key reveals neither the master nor
    /// the sibling. The chain sub-key matches the one derived by
    /// [`AuditChainProfile::production_from_env`] for the same env secret.
    pub fn production_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self {
            chain_hasher: AuditChainHasher::from_env_derived(env_var_name)?,
            key_hasher: AuditKeyHasher::from_env_derived(env_var_name)?,
        })
    }

    /// Registry Relay production audit profile.
    pub fn registry_relay_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Registry Notary production audit profile.
    pub fn registry_notary_from_env(env_var_name: &str) -> Result<Self, AuditError> {
        Self::production_from_env(env_var_name)
    }

    /// Explicit test and local-development profile.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self {
            chain_hasher: AuditChainHasher::unkeyed_dev_only(),
            key_hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }

    #[must_use]
    pub fn chain_hasher(&self) -> AuditChainHasher {
        self.chain_hasher.clone()
    }

    #[must_use]
    pub fn key_hasher(&self) -> AuditKeyHasher {
        self.key_hasher.clone()
    }

    pub async fn bootstrap_or_start_empty(
        &self,
        sink: &dyn AuditSink,
    ) -> Result<ChainState, AuditError> {
        ChainState::bootstrap_or_start_empty(sink, self.chain_hasher()).await
    }
}

/// Closed durable audit stream classes that require atomic phase idempotency.
///
/// Adding a stream is a contract change that requires a matching durable-store
/// migration. Request-supplied labels cannot enter the idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableAuditStreamKind {
    /// A governed Relay consultation.
    Consultation,
    /// A governed source materialization acquisition.
    Materialization,
    /// A fail-closed access denial decision.
    Denial,
    /// An operator-controlled startup credential probe.
    StartupCredentialProbe,
    /// An operator-controlled readiness credential probe.
    ReadinessCredentialProbe,
}

impl DurableAuditStreamKind {
    /// Stable storage label for this stream kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consultation => "consultation",
            Self::Materialization => "materialization",
            Self::Denial => "denial",
            Self::StartupCredentialProbe => "startup_credential_probe",
            Self::ReadinessCredentialProbe => "readiness_credential_probe",
        }
    }

    const fn accepts_phase(self, phase: DurableAuditPhase) -> bool {
        match self {
            Self::Denial => matches!(phase, DurableAuditPhase::DenialDecision),
            Self::Consultation
            | Self::Materialization
            | Self::StartupCredentialProbe
            | Self::ReadinessCredentialProbe => {
                matches!(
                    phase,
                    DurableAuditPhase::Attempt | DurableAuditPhase::Completion
                )
            }
        }
    }
}

impl TryFrom<&str> for DurableAuditStreamKind {
    type Error = DurableAuditValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "consultation" => Ok(Self::Consultation),
            "materialization" => Ok(Self::Materialization),
            "denial" => Ok(Self::Denial),
            "startup_credential_probe" => Ok(Self::StartupCredentialProbe),
            "readiness_credential_probe" => Ok(Self::ReadinessCredentialProbe),
            _ => Err(DurableAuditValidationError::InvalidStreamKind),
        }
    }
}

/// Closed phases of a durable governed audit operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableAuditPhase {
    /// Written durably before any governed source or credential access.
    Attempt,
    /// Written durably before an operation result is published.
    Completion,
    /// One fail-closed denial decision that cannot masquerade as source access.
    DenialDecision,
}

impl DurableAuditPhase {
    /// Stable storage label for this phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Completion => "completion",
            Self::DenialDecision => "denial_decision",
        }
    }
}

impl TryFrom<&str> for DurableAuditPhase {
    type Error = DurableAuditValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "attempt" => Ok(Self::Attempt),
            "completion" => Ok(Self::Completion),
            "denial_decision" => Ok(Self::DenialDecision),
            _ => Err(DurableAuditValidationError::InvalidPhase),
        }
    }
}

/// Canonical ULID syntax identifying one durable audit operation.
///
/// This type validates only syntax and canonical encoding. The consumer must
/// enforce that it was server-minted and was not derived from a selector,
/// credential, source identifier, or other sensitive input.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableAuditOperationId(String);

impl DurableAuditOperationId {
    /// Construct an operation id from a ULID the consumer has server-minted.
    ///
    /// This constructor can preserve only syntax, so the consumer remains
    /// responsible for the minting provenance documented on this type.
    #[must_use]
    pub fn from_ulid(value: Ulid) -> Self {
        Self(value.to_string())
    }

    /// Parse an exact canonical ULID string.
    pub fn parse(value: &str) -> Result<Self, DurableAuditValidationError> {
        let parsed = Ulid::from_string(value)
            .map_err(|_| DurableAuditValidationError::InvalidOperationId)?;
        if parsed.to_string() != value {
            return Err(DurableAuditValidationError::InvalidOperationId);
        }
        Ok(Self(value.to_string()))
    }

    /// Return the canonical ULID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DurableAuditOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DurableAuditOperationId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for DurableAuditOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for DurableAuditOperationId {
    type Error = DurableAuditValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// SHA-256 of consumer-owned canonical, audit-safe JSON bytes.
///
/// Only [`DurableAuditWrite`] constructs this value, so a caller cannot supply
/// payload bytes and a mismatched digest. The digest remains redacted from
/// `Debug` and errors.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalSafeAuditPayloadDigest([u8; 32]);

impl CanonicalSafeAuditPayloadDigest {
    fn from_canonical_bytes(canonical_safe_payload: &[u8]) -> Self {
        Self(sha256_bytes(canonical_safe_payload))
    }

    /// Return the digest bytes for atomic durable-store comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the stable lowercase SHA-256 representation.
    #[must_use]
    pub fn to_lower_hex(self) -> String {
        hex_lower(&self.0)
    }
}

impl fmt::Debug for CanonicalSafeAuditPayloadDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalSafeAuditPayloadDigest(sha256:<redacted>)")
    }
}

/// Validated idempotency key for one durable audit phase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableAuditOperationKey {
    stream_kind: DurableAuditStreamKind,
    operation_id: DurableAuditOperationId,
    phase: DurableAuditPhase,
}

impl DurableAuditOperationKey {
    /// Construct a key and enforce the closed stream/phase matrix.
    pub fn new(
        stream_kind: DurableAuditStreamKind,
        operation_id: DurableAuditOperationId,
        phase: DurableAuditPhase,
    ) -> Result<Self, DurableAuditValidationError> {
        if !stream_kind.accepts_phase(phase) {
            return Err(DurableAuditValidationError::InvalidStreamPhaseCombination);
        }
        Ok(Self {
            stream_kind,
            operation_id,
            phase,
        })
    }

    #[must_use]
    pub const fn stream_kind(&self) -> DurableAuditStreamKind {
        self.stream_kind
    }

    #[must_use]
    pub fn operation_id(&self) -> &DurableAuditOperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn phase(&self) -> DurableAuditPhase {
        self.phase
    }
}

/// Stable identity of the envelope actually stored for a durable phase.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableAuditStoredIdentity {
    envelope_id: String,
    record_hash: [u8; 32],
}

impl DurableAuditStoredIdentity {
    /// Validate and capture the identity of a sink-built envelope.
    pub fn from_envelope(envelope: &AuditEnvelope) -> Result<Self, DurableAuditValidationError> {
        let parsed = Ulid::from_string(&envelope.envelope_id)
            .map_err(|_| DurableAuditValidationError::InvalidEnvelopeId)?;
        if parsed.to_string() != envelope.envelope_id {
            return Err(DurableAuditValidationError::InvalidEnvelopeId);
        }
        Ok(Self {
            envelope_id: envelope.envelope_id.clone(),
            record_hash: envelope.record_hash,
        })
    }

    /// Canonical ULID assigned to the stored envelope.
    #[must_use]
    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }

    /// Chained record hash of the stored envelope.
    #[must_use]
    pub const fn record_hash(&self) -> &[u8; 32] {
        &self.record_hash
    }
}

impl fmt::Debug for DurableAuditStoredIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableAuditStoredIdentity")
            .field("envelope_id", &self.envelope_id)
            .field("record_hash", &"sha256:<redacted>")
            .finish()
    }
}

/// One validated operation-phase write for an atomic durable audit sink.
///
/// The write owns the safe JSON object and derives its digest from the shared
/// RFC 8785 canonical representation. It carries no envelope, predecessor hash,
/// or event identity. Those are assigned by the sink under the same serialized
/// durable-chain operation that inserts the idempotency key.
#[derive(Clone)]
pub struct DurableAuditWrite {
    key: DurableAuditOperationKey,
    payload_digest: CanonicalSafeAuditPayloadDigest,
    safe_payload: Value,
}

impl DurableAuditWrite {
    /// Validate one non-empty top-level JSON object containing only audit-safe
    /// fields, canonicalize it with RFC 8785, and derive its SHA-256 digest.
    /// Payload data is never included in diagnostics.
    pub fn new(
        stream_kind: DurableAuditStreamKind,
        operation_id: DurableAuditOperationId,
        phase: DurableAuditPhase,
        safe_payload: Value,
    ) -> Result<Self, DurableAuditValidationError> {
        let Value::Object(fields) = &safe_payload else {
            return Err(DurableAuditValidationError::SafePayloadMustBeObject);
        };
        if fields.is_empty() {
            return Err(DurableAuditValidationError::SafePayloadMustBeNonEmpty);
        }
        let canonical_safe_payload =
            registry_platform_canonical_json::canonicalize_json(&safe_payload)
                .map_err(|_| DurableAuditValidationError::SafePayloadCanonicalizationFailed)?;

        Ok(Self {
            key: DurableAuditOperationKey::new(stream_kind, operation_id, phase)?,
            payload_digest: CanonicalSafeAuditPayloadDigest::from_canonical_bytes(
                &canonical_safe_payload,
            ),
            safe_payload,
        })
    }

    #[must_use]
    pub fn key(&self) -> &DurableAuditOperationKey {
        &self.key
    }

    #[must_use]
    pub const fn payload_digest(&self) -> CanonicalSafeAuditPayloadDigest {
        self.payload_digest
    }

    /// Build the envelope after a durable sink has serialized access to its
    /// current chain head.
    ///
    /// The sink-built record wraps the consumer payload with the stable schema,
    /// operation key, phase, and canonical payload digest. The chain hash
    /// therefore detects reassociation of an envelope with a different durable
    /// row key.
    ///
    /// Sink implementations call this only after resolving duplicates and
    /// while holding the database transaction or equivalent critical section
    /// that owns `predecessor`. Callers cannot place a precomputed predecessor
    /// or envelope into [`DurableAuditWrite`].
    pub fn build_envelope_at_chain_head(
        &self,
        predecessor: Option<[u8; 32]>,
        hasher: &AuditChainHasher,
    ) -> Result<AuditEnvelope, AuditError> {
        let record = json!({
            "schema": DURABLE_AUDIT_RECORD_SCHEMA_V1,
            "stream_kind": self.key.stream_kind().as_str(),
            "operation_id": self.key.operation_id().as_str(),
            "phase": self.key.phase().as_str(),
            "payload_digest": format!("sha256:{}", self.payload_digest.to_lower_hex()),
            "payload": self.safe_payload.clone(),
        });
        AuditEnvelope::new_with_hasher(record, predecessor, hasher)
    }
}

impl fmt::Debug for DurableAuditWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableAuditWrite")
            .field("key", &self.key)
            .field("payload_digest", &self.payload_digest)
            .field("safe_payload", &"<redacted>")
            .finish()
    }
}

/// Validation failures for the closed durable audit write contract.
///
/// Variants deliberately do not retain rejected input values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DurableAuditValidationError {
    #[error("durable audit stream kind is not supported")]
    InvalidStreamKind,
    #[error("durable audit phase is not supported")]
    InvalidPhase,
    #[error("durable audit stream and phase combination is not supported")]
    InvalidStreamPhaseCombination,
    #[error("durable audit operation id is not a canonical ULID")]
    InvalidOperationId,
    #[error("safe audit payload must be a top-level JSON object")]
    SafePayloadMustBeObject,
    #[error("safe audit payload object must not be empty")]
    SafePayloadMustBeNonEmpty,
    #[error("safe audit payload canonicalization failed")]
    SafePayloadCanonicalizationFailed,
    #[error("durable audit envelope id is not a canonical ULID")]
    InvalidEnvelopeId,
}

/// Atomic result of a durable phase write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableAuditWriteOutcome {
    /// This call inserted a newly sink-built envelope.
    Inserted(DurableAuditStoredIdentity),
    /// The key already held the same payload digest.
    IdenticalDuplicate(DurableAuditStoredIdentity),
    /// The key already held a different payload digest.
    ConflictingDuplicate(DurableAuditStoredIdentity),
}

impl DurableAuditWriteOutcome {
    /// Identity of the envelope originally stored for this phase.
    #[must_use]
    pub fn stored_identity(&self) -> &DurableAuditStoredIdentity {
        match self {
            Self::Inserted(identity)
            | Self::IdenticalDuplicate(identity)
            | Self::ConflictingDuplicate(identity) => identity,
        }
    }
}

/// Availability or internal failures from an atomic durable phase write.
///
/// Storage implementations map database details to these safe classes and log
/// only separately sanitized diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DurableAuditWriteError {
    #[error("durable audit store is unavailable")]
    StoreUnavailable,
    #[error("durable audit store failed")]
    StoreFailure,
}

/// Atomic, durable, idempotent audit-phase persistence.
///
/// A sink resolves the key, compares the digest, and inserts a sink-built
/// envelope while it owns the serialized durable chain head. Identical and
/// conflicting duplicates return the original stored identity. This trait is
/// intentionally independent of [`AuditSink`]; append-only sinks have no
/// fallback or blanket implementation and cannot satisfy this contract.
#[async_trait]
pub trait DurableAuditSink: Send + Sync {
    async fn write_phase(
        &self,
        write: &DurableAuditWrite,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError>;
}

#[cfg(test)]
struct InMemoryDurableAuditEntry {
    payload_digest: CanonicalSafeAuditPayloadDigest,
    envelope: AuditEnvelope,
    stored_identity: DurableAuditStoredIdentity,
}

#[cfg(test)]
#[derive(Default)]
struct InMemoryDurableAuditState {
    entries: BTreeMap<DurableAuditOperationKey, InMemoryDurableAuditEntry>,
    last_hash: Option<[u8; 32]>,
}

/// Unit-test-only atomic conformance sink. It is absent from production builds.
#[cfg(test)]
struct InMemoryDurableAuditTestSink {
    hasher: AuditChainHasher,
    state: tokio::sync::Mutex<InMemoryDurableAuditState>,
}

#[cfg(test)]
impl Default for InMemoryDurableAuditTestSink {
    fn default() -> Self {
        Self {
            hasher: AuditChainHasher::unkeyed_dev_only(),
            state: tokio::sync::Mutex::new(InMemoryDurableAuditState::default()),
        }
    }
}

#[cfg(test)]
impl fmt::Debug for InMemoryDurableAuditTestSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryDurableAuditTestSink")
            .field("state", &"<opaque>")
            .finish()
    }
}

#[cfg(test)]
impl InMemoryDurableAuditTestSink {
    async fn len(&self) -> usize {
        self.state.lock().await.entries.len()
    }

    async fn stored_envelope(&self, key: &DurableAuditOperationKey) -> Option<AuditEnvelope> {
        self.state
            .lock()
            .await
            .entries
            .get(key)
            .map(|entry| entry.envelope.clone())
    }
}

#[cfg(test)]
#[async_trait]
impl DurableAuditSink for InMemoryDurableAuditTestSink {
    async fn write_phase(
        &self,
        write: &DurableAuditWrite,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError> {
        let mut state = self.state.lock().await;
        if let Some(stored) = state.entries.get(write.key()) {
            let stored_identity = stored.stored_identity.clone();
            return if stored.payload_digest == write.payload_digest() {
                Ok(DurableAuditWriteOutcome::IdenticalDuplicate(
                    stored_identity,
                ))
            } else {
                Ok(DurableAuditWriteOutcome::ConflictingDuplicate(
                    stored_identity,
                ))
            };
        }

        let envelope = write
            .build_envelope_at_chain_head(state.last_hash, &self.hasher)
            .map_err(|_| DurableAuditWriteError::StoreFailure)?;
        let stored_identity = DurableAuditStoredIdentity::from_envelope(&envelope)
            .map_err(|_| DurableAuditWriteError::StoreFailure)?;
        state.last_hash = Some(envelope.record_hash);
        state.entries.insert(
            write.key().clone(),
            InMemoryDurableAuditEntry {
                payload_digest: write.payload_digest(),
                envelope,
                stored_identity: stored_identity.clone(),
            },
        );
        Ok(DurableAuditWriteOutcome::Inserted(stored_identity))
    }
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError>;

    /// Return the chain tail hash using the sink's own default hash mode.
    ///
    /// WARNING (AUDIT-06): for tailable sinks that recompute hashes while reading
    /// (such as [`JsonlFileSink`]) this path is **UNKEYED / dev-only**. It cannot
    /// authenticate a retained chain against the deployment HMAC secret, so an
    /// attacker who rewrites the log can forge a self-consistent tail. Production
    /// code MUST use [`Self::tail_hash_with_hasher`] with a keyed
    /// [`AuditChainHasher`] (e.g. via [`ChainState::bootstrap_or_start_empty`]).
    ///
    /// Implementors must still provide this method (it is the read primitive);
    /// the `#[deprecated]` marker is a guardrail against *calling* the bare,
    /// unkeyed convenience from production code.
    #[deprecated(
        note = "tail_hash() recomputes UNKEYED for tailable sinks (dev/test only); use tail_hash_with_hasher with a keyed AuditChainHasher in production"
    )]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError>;

    /// Return the chain tail hash recomputed under the caller-selected `hasher`.
    ///
    /// This is the keyed, production-safe entry point. Tailable sinks that
    /// recompute the chain while reading (such as [`JsonlFileSink`]) MUST honor
    /// the supplied hasher. Sinks that cannot provide a tail (stdout, syslog)
    /// should return `Ok(None)`. Sinks that retain already-computed envelope
    /// hashes without recomputing them may ignore `hasher`.
    ///
    /// The default fails closed instead of falling back to [`Self::tail_hash`],
    /// so legacy custom sinks do not silently recompute an unkeyed production
    /// tail.
    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _ = hasher;
        Err(AuditError::NonTailableSink)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    #[error("audit JSON serialization or parsing failed: {0}")]
    Json(#[source] serde_json::Error),
    #[error("audit sink I/O failure: {0}")]
    Io(#[source] std::io::Error),
    #[error("audit hash secret environment variable name is empty")]
    EmptyEnvVarName,
    #[error("audit hash secret environment variable {name} is not set: {source}")]
    EnvVar {
        name: String,
        #[source]
        source: env::VarError,
    },
    #[error("audit hash secret environment variable {name} is empty")]
    EmptySecret { name: String },
    #[error("audit hash secret from {name} must be at least {min_bytes} bytes")]
    WeakSecret { name: String, min_bytes: usize },
    #[error("audit hash field {field} is not a valid lowercase sha256 hex string")]
    InvalidHashHex { field: &'static str },
    #[error("audit sink cannot provide a tail hash; use bootstrap_or_start_empty or explicit dev-only restart mode")]
    NonTailableSink,
    #[error("audit chain hash mismatch")]
    HashMismatch,
    #[error("audit chain verification failed: {0}")]
    ChainVerification(#[source] ChainVerificationError),
    /// The single-writer advisory lock on the audit sink is already held by
    /// another writer (typically a second process sharing the audit volume, or
    /// an overlapping container during a restart/recreate). Failing loudly here
    /// is what prevents a silently forked chain (#211).
    #[error("audit sink single-writer lock is already held by another writer: {path}")]
    SinkLocked { path: String },
    /// A write-time tail self-check found the on-disk chain tail advanced past
    /// the writer's in-memory predecessor: a foreign writer has appended to the
    /// same file since this writer's last append (a chain fork in progress).
    /// The append is refused so the fork window is seconds, not until the next
    /// restart (#211).
    #[error("audit chain fork detected at write time: on-disk tail {found} does not match expected predecessor {expected}")]
    ChainForkDetected {
        expected: OptionalHashHex,
        found: OptionalHashHex,
    },
}

/// Display helper for an optional 32-byte hash rendered as lowercase hex (or
/// `none`), used in [`AuditError::ChainForkDetected`] so operators see the
/// diverging tail hashes without a `Debug` array dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHashHex(pub Option<[u8; 32]>);

impl fmt::Display for OptionalHashHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(hash) => f.write_str(&hex_lower(&hash)),
            None => f.write_str("none"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuditReferenceHashError {
    #[error("audit reference class is empty")]
    EmptyClass,
    #[error("audit reference canonical input is empty")]
    EmptyCanonicalInput,
}

/// JSONL sink with in-process size rotation.
#[derive(Debug, Clone)]
pub struct JsonlFileSink {
    inner: Arc<JsonlFileSinkInner>,
}

#[derive(Debug)]
struct JsonlFileSinkInner {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
    lock: tokio::sync::Mutex<()>,
    /// Process-lifetime advisory lock on the sentinel `<path>.lock` file, held
    /// for single-writer sinks (`with_rotation_single_writer`) and `None` for
    /// the unlocked dev/test constructors. Dropping the sink releases the OS
    /// lock. Never read after construction: its sole job is to keep the
    /// `flock` held (#211).
    _writer_lock: Option<File>,
}

impl JsonlFileSink {
    /// Construct an unlocked file sink with a 10 MiB active file and 50 retained
    /// files. Dev/test convenience; production uses
    /// [`Self::with_rotation_single_writer`].
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_rotation(path, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_FILES)
    }

    /// Construct an unlocked file sink with byte-based rotation.
    ///
    /// `max_size_bytes = 0` disables rotation. `max_files` counts the active file;
    /// values below 1 are treated as 1.
    ///
    /// This does NOT take the single-writer advisory lock; two of these on the
    /// same path can fork the chain. Production callers use
    /// [`Self::with_rotation_single_writer`].
    #[must_use]
    pub fn with_rotation(path: impl Into<PathBuf>, max_size_bytes: u64, max_files: u32) -> Self {
        Self {
            inner: Arc::new(JsonlFileSinkInner {
                path: path.into(),
                max_size_bytes,
                max_files: max_files.max(1),
                lock: tokio::sync::Mutex::new(()),
                _writer_lock: None,
            }),
        }
    }

    /// Construct a single-writer file sink: acquire a process-lifetime advisory
    /// lock (`flock`) on a stable sentinel file `<path>.lock` next to the JSONL,
    /// so a second writer sharing the same volume fails loudly at construction
    /// instead of silently forking the chain (#211).
    ///
    /// The sentinel is a fixed, never-rotated path; the active JSONL rotates
    /// (`audit.jsonl` -> `audit.jsonl.1`), and an `flock` follows the inode, so
    /// locking the sentinel rather than the active file keeps the lock stable
    /// across rotations.
    ///
    /// Returns [`AuditError::SinkLocked`] when another writer already holds the
    /// lock. On network filesystems `flock` semantics can be unreliable; the
    /// write-time tail self-check (see [`AuditSink::write`]) is the backstop for
    /// that case.
    pub fn with_rotation_single_writer(
        path: impl Into<PathBuf>,
        max_size_bytes: u64,
        max_files: u32,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        let writer_lock = acquire_writer_lock(&path)?;
        Ok(Self {
            inner: Arc::new(JsonlFileSinkInner {
                path,
                max_size_bytes,
                max_files: max_files.max(1),
                lock: tokio::sync::Mutex::new(()),
                _writer_lock: Some(writer_lock),
            }),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

/// Path of the never-rotated sentinel lock file for `path`.
fn sentinel_lock_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(".lock");
    PathBuf::from(raw)
}

/// Acquire the process-lifetime advisory lock on `path`'s sentinel file.
fn acquire_writer_lock(path: &Path) -> Result<File, AuditError> {
    let lock_path = sentinel_lock_path(path);
    ensure_parent_dir(&lock_path)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .audit_file_mode()
        .open(&lock_path)
        .map_err(AuditError::Io)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(AuditError::SinkLocked {
            path: lock_path.display().to_string(),
        }),
        Err(TryLockError::Error(error)) => Err(AuditError::Io(error)),
    }
}

#[async_trait]
impl AuditSink for JsonlFileSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        // The envelope's `prev_hash` is the writer's in-memory chain tail. The
        // blocking write self-checks it against the on-disk tail before
        // appending, so a foreign append (a second writer that got past or
        // around the advisory lock) is caught at write time (#211).
        let expected_prev = envelope.prev_hash;
        let _guard = self.inner.lock.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.write_line_blocking(&line, expected_prev))
            .await
            .map_err(join_error_to_io)?
    }

    /// WARNING (AUDIT-06): this recomputes the retained chain with an **UNKEYED**
    /// hasher and is dev/test only. It cannot detect a rewrite by a writer that
    /// lacks the deployment HMAC secret. Production callers MUST use
    /// [`Self::tail_hash_with_hasher`] with a keyed [`AuditChainHasher`].
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_blocking(AuditChainHasher::unkeyed_dev_only())
            .await
    }

    /// Recompute the retained chain tail under the caller-selected `hasher`.
    ///
    /// This is the keyed, production-safe path: pass a keyed [`AuditChainHasher`]
    /// to authenticate the retained JSONL set against the deployment secret.
    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        self.tail_hash_blocking(hasher.clone()).await
    }
}

impl JsonlFileSink {
    async fn tail_hash_blocking(
        &self,
        hasher: AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _guard = self.inner.lock.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            tail_hash_from_files(&inner.path, inner.max_files, &hasher)
        })
        .await
        .map_err(join_error_to_io)?
    }
}

impl JsonlFileSinkInner {
    fn write_line_blocking(
        &self,
        line: &str,
        expected_prev: Option<[u8; 32]>,
    ) -> Result<(), AuditError> {
        ensure_parent_dir(&self.path)?;
        // Self-check the on-disk tail against our in-memory predecessor BEFORE
        // rotation, so the comparison sees the retained set as it stood when the
        // envelope was chained. Rotation (which we perform below, under the same
        // async `lock`) then moves the checked tail into `.1` and we append to a
        // fresh active file.
        self.verify_tail_matches(expected_prev)?;
        self.rotate_if_needed(line.len() as u64)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .audit_file_mode()
            .open(&self.path)
            .map_err(AuditError::Io)?;
        file.write_all(line.as_bytes()).map_err(AuditError::Io)?;
        file.flush().map_err(AuditError::Io)
    }

    /// Refuse the append if the on-disk chain tail no longer matches the
    /// writer's in-memory predecessor. A match (including the genesis case where
    /// both are `None`) proceeds; any divergence means a foreign writer appended
    /// since this writer's last append (#211).
    fn verify_tail_matches(&self, expected_prev: Option<[u8; 32]>) -> Result<(), AuditError> {
        let found = self.current_tail_record_hash()?;
        if found != expected_prev {
            return Err(AuditError::ChainForkDetected {
                expected: OptionalHashHex(expected_prev),
                found: OptionalHashHex(found),
            });
        }
        Ok(())
    }

    /// `record_hash` of the newest retained on-disk record, or `None` when the
    /// retained set is empty (genesis). Reads only the tail of the newest
    /// non-empty file, so the cost is independent of file size. A last line that
    /// fails to parse surfaces as a verification error (fail closed).
    fn current_tail_record_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        // Active file first; only when it is empty (e.g. immediately after a
        // process that rotated but had no subsequent write) fall back to the
        // newest rotated file, so the check stays correct without a false
        // positive on a legitimately just-rotated set.
        let mut candidates = vec![self.path.clone()];
        for index in 1..self.max_files {
            candidates.push(rotated_path(&self.path, index));
        }
        for candidate in candidates {
            let Some(last_line) = read_last_line(&candidate)? else {
                continue;
            };
            let envelope = serde_json::from_str::<AuditEnvelope>(&last_line).map_err(|source| {
                AuditError::ChainVerification(ChainVerificationError::InvalidJson {
                    line: 0,
                    message: source.to_string(),
                })
            })?;
            return Ok(Some(envelope.record_hash));
        }
        Ok(None)
    }

    fn rotate_if_needed(&self, incoming_bytes: u64) -> Result<(), AuditError> {
        if self.max_size_bytes == 0 {
            return Ok(());
        }

        let current_size = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(AuditError::Io(error)),
        };

        if current_size.saturating_add(incoming_bytes) <= self.max_size_bytes {
            return Ok(());
        }

        self.rotate()
    }

    fn rotate(&self) -> Result<(), AuditError> {
        if self.max_files <= 1 {
            return match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(AuditError::Io(error)),
            };
        }

        let last_index = self.max_files - 1;
        remove_file_if_exists(&rotated_path(&self.path, last_index))?;

        for index in (1..last_index).rev() {
            let from = rotated_path(&self.path, index);
            let to = rotated_path(&self.path, index + 1);
            rename_if_exists(&from, &to)?;
        }

        rename_if_exists(&self.path, &rotated_path(&self.path, 1))
    }
}

/// JSONL sink that writes one envelope per line to process stdout.
#[derive(Debug, Default, Clone)]
pub struct JsonlStdoutSink;

impl JsonlStdoutSink {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuditSink for JsonlStdoutSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        tokio::task::spawn_blocking(move || {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(line.as_bytes()).map_err(AuditError::Io)?;
            handle.flush().map_err(AuditError::Io)
        })
        .await
        .map_err(join_error_to_io)?
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _ = hasher;
        Ok(None)
    }
}

/// Syslog sink over a local Unix datagram socket.
#[derive(Debug, Clone)]
pub struct SyslogSink {
    socket_path: PathBuf,
}

impl SyslogSink {
    #[must_use]
    pub fn new() -> Self {
        Self::with_socket_path(default_syslog_socket_path())
    }

    #[must_use]
    pub fn with_socket_path(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }
}

impl Default for SyslogSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSink for SyslogSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let line = envelope.to_jsonl()?;
        let frame = rfc5424_frame(line.trim_end());
        send_syslog_datagram(&self.socket_path, frame.as_bytes()).await
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _ = hasher;
        Ok(None)
    }
}

/// Inner key bytes for [`AuditHashSecret`].
///
/// The raw HMAC key is zeroized when the last shared reference is dropped, so a
/// leaked process image is far less likely to retain the deployment secret after
/// the audit profile is torn down.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBytes(Vec<u8>);

/// Shared per-deployment HMAC secret for audit identifiers.
///
/// The key material is held behind an `Arc<SecretBytes>` whose inner bytes are
/// zeroized on drop of the last clone (AUDIT-02).
#[derive(Clone)]
pub struct AuditHashSecret(Arc<SecretBytes>);

impl AuditHashSecret {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuditError> {
        // Own the bytes directly: on the success path they move into the
        // `ZeroizeOnDrop` `SecretBytes` with no intermediate copy; on the error
        // path the rejected (too-short) secret is scrubbed explicitly.
        let mut secret = secret.into();
        if secret.len() < MIN_AUDIT_SECRET_BYTES {
            secret.zeroize();
            return Err(AuditError::WeakSecret {
                name: "explicit secret".to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(secret))))
    }

    fn from_env_value(name: &str, value: String) -> Result<Self, AuditError> {
        // Keep ownership of the env value so it can move into `SecretBytes`
        // (`String::into_bytes` is allocation-free) instead of being copied;
        // rejected values are scrubbed before returning.
        let mut value = value;
        if value.is_empty() {
            return Err(AuditError::EmptySecret {
                name: name.to_string(),
            });
        }
        if value.len() < MIN_AUDIT_SECRET_BYTES {
            value.zeroize();
            return Err(AuditError::WeakSecret {
                name: name.to_string(),
                min_bytes: MIN_AUDIT_SECRET_BYTES,
            });
        }
        Ok(Self(Arc::new(SecretBytes(value.into_bytes()))))
    }

    fn from_bytes(secret: Vec<u8>) -> Self {
        Self(Arc::new(SecretBytes(secret)))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0 .0
    }
}

impl fmt::Debug for AuditHashSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHashSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Audit-chain record hasher.
///
/// Keyed mode protects the retained JSONL chain from a file writer that cannot
/// read the deployment HMAC secret. Unkeyed mode is retained only for tests,
/// fixtures, and migration checks of legacy pre-beta logs.
#[derive(Clone, Debug)]
pub enum AuditChainHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}

impl AuditChainHasher {
    #[must_use]
    pub fn keyed(secret: AuditHashSecret) -> Self {
        Self::Keyed(secret)
    }

    /// Load an HMAC chain secret from the named environment variable.
    ///
    /// The raw env value is used directly as the chain key. Prefer
    /// [`Self::from_env_derived`] at the profile boundary so the chain key and
    /// sibling identifier key are cryptographically separated sub-keys of the
    /// master env secret (AUDIT-03).
    pub fn from_env(env_var_name: &str) -> Result<Self, AuditError> {
        if env_var_name.trim().is_empty() {
            return Err(AuditError::EmptyEnvVarName);
        }
        let value = env::var(env_var_name).map_err(|source| AuditError::EnvVar {
            name: env_var_name.to_string(),
            source,
        })?;
        Ok(Self::Keyed(AuditHashSecret::from_env_value(
            env_var_name,
            value,
        )?))
    }

    /// Load a chain hasher whose key is an HKDF-derived sub-key of the master
    /// env secret, domain-separated from the identifier key (AUDIT-03).
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self::Keyed(derive_subkey_from_env(
            env_var_name,
            CHAIN_KEY_DERIVATION_INFO,
        )?))
    }

    /// Explicit unkeyed mode for tests, fixtures, and legacy pre-beta logs.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::UnkeyedDevOnly
    }

    fn hash_record(&self, bytes: &[u8]) -> [u8; 32] {
        match self {
            Self::Keyed(secret) => hmac_sha256_bytes(secret.as_bytes(), CHAIN_HMAC_CONTEXT, bytes),
            Self::UnkeyedDevOnly => sha256_bytes(bytes),
        }
    }
}

/// Deterministic audit identifier hasher.
#[derive(Clone, Debug)]
pub enum AuditKeyHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}

impl AuditKeyHasher {
    /// Load an HMAC secret from the named environment variable.
    ///
    /// This fails closed when the env var name is empty, unset, empty, or shorter
    /// than 32 bytes. Unkeyed hashing requires [`Self::unkeyed_dev_only`].
    pub fn from_env(env_var_name: &str) -> Result<Self, AuditError> {
        if env_var_name.trim().is_empty() {
            return Err(AuditError::EmptyEnvVarName);
        }
        let value = env::var(env_var_name).map_err(|source| AuditError::EnvVar {
            name: env_var_name.to_string(),
            source,
        })?;
        Ok(Self::Keyed(AuditHashSecret::from_env_value(
            env_var_name,
            value,
        )?))
    }

    /// Load an identifier hasher whose key is an HKDF-derived sub-key of the
    /// master env secret, domain-separated from the chain key (AUDIT-03).
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditError> {
        Ok(Self::Keyed(derive_subkey_from_env(
            env_var_name,
            IDENTIFIER_KEY_DERIVATION_INFO,
        )?))
    }

    /// Explicit unkeyed mode for tests and local development.
    #[must_use]
    pub fn unkeyed_dev_only() -> Self {
        Self::UnkeyedDevOnly
    }

    /// Hash a raw audit identifier.
    #[must_use]
    pub fn hash(&self, raw: &str) -> String {
        match self {
            Self::Keyed(secret) => hmac_sha256_hex(secret.as_bytes(), raw.as_bytes()),
            Self::UnkeyedDevOnly => sha256_hex(raw.as_bytes()),
        }
    }

    /// Hash a service-owned canonical audit reference under a versioned class
    /// and scope.
    ///
    /// `class` separates reference families such as matched subjects, table ids,
    /// or primary keys. `scope` may be empty when the service has no narrower
    /// purpose or tenant boundary. `canonical_input` is owned by the caller and
    /// must already be stable and privacy-reviewed for that product surface.
    pub fn audit_reference_hash(
        &self,
        class: &str,
        scope: &str,
        canonical_input: &str,
    ) -> Result<String, AuditReferenceHashError> {
        if class.is_empty() {
            return Err(AuditReferenceHashError::EmptyClass);
        }
        if canonical_input.is_empty() {
            return Err(AuditReferenceHashError::EmptyCanonicalInput);
        }
        let input = audit_reference_hash_input(class, scope, canonical_input);
        Ok(self.hash(&input))
    }

    /// Hash a sensitive audit lookup value under a field-bound platform class.
    ///
    /// This is appropriate for generic redaction surfaces such as URL query
    /// parameters. Services that need product-specific pseudonym classes should
    /// call [`Self::audit_reference_hash`] with their own canonical input.
    #[must_use]
    pub fn sensitive_value_hash(&self, field: &str, value: &str) -> String {
        let canonical_input = format!("value\0{}\0{value}", value.len());
        self.audit_reference_hash("sensitive-value-v1", field, &canonical_input)
            .expect("platform sensitive-value class and canonical input are non-empty")
    }
}

fn audit_reference_hash_input(class: &str, scope: &str, canonical_input: &str) -> String {
    format!(
        "{AUDIT_REFERENCE_HASH_CONTEXT}\0{}\0{class}\0{}\0{scope}\0{}\0{canonical_input}",
        class.len(),
        scope.len(),
        canonical_input.len()
    )
}

pub mod redact {
    use super::*;

    const SECRET_PARAM_NAMES: &[&str] = &[
        "token",
        "key",
        "api_key",
        "apikey",
        "password",
        "secret",
        "authorization",
        "auth",
        // AUDIT-05: OAuth / OIDC / generic credential parameter names.
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "client_assertion",
        "assertion",
        "bearer",
        "code",
        "private_key",
        "credential",
        "credentials",
        "passwd",
        "pwd",
        "session_token",
    ];

    /// Fully redact an email address without preserving local-part or domain.
    #[must_use]
    pub fn email(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Fully redact a phone number without preserving digits.
    #[must_use]
    pub fn phone(s: &str) -> String {
        if s.is_empty() {
            String::new()
        } else {
            "redacted".to_string()
        }
    }

    /// Redacts URL query parameters into a stable JSON object.
    #[derive(Debug, Clone, Default)]
    pub struct QueryRedactor {
        sensitive_fields: BTreeSet<String>,
        hasher: Option<AuditKeyHasher>,
    }

    impl QueryRedactor {
        /// Construct a redactor that redacts sensitive values without lookup hashes.
        #[must_use]
        pub fn new<I, S>(sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                sensitive_fields: sensitive_fields
                    .into_iter()
                    .map(|field| field.into().to_ascii_lowercase())
                    .collect(),
                hasher: None,
            }
        }

        /// Construct a redactor that hashes sensitive lookup values.
        #[must_use]
        pub fn with_hasher<I, S>(hasher: AuditKeyHasher, sensitive_fields: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                hasher: Some(hasher),
                ..Self::new(sensitive_fields)
            }
        }

        #[must_use]
        pub fn redact_query(&self, query: &str) -> Value {
            self.try_redact_query(query).unwrap_or_else(|error| {
                json!({
                    "_error": {
                        "code": "invalid_query_encoding",
                        "detail": error.to_string(),
                    }
                })
            })
        }

        pub fn try_redact_query(&self, query: &str) -> Result<Value, QueryRedactionError> {
            if query.is_empty() {
                return Ok(json!({}));
            }

            let mut out = BTreeMap::new();
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
                let name = decode_query_component(raw_name)?;
                let value = decode_query_component(raw_value)?;
                let (field, op) = split_field_operator(&name);
                let field_key = field.to_ascii_lowercase();

                let entry = if is_secret_param_name(field) {
                    json!({ "op": "redacted" })
                } else if self.sensitive_fields.contains(&field_key) {
                    match &self.hasher {
                        Some(hasher) => json!({
                            "op": op,
                            "value_hash": hasher.sensitive_value_hash(field, &value),
                        }),
                        None => json!({ "op": "redacted" }),
                    }
                } else {
                    json!({ "op": op })
                };

                out.insert(name, entry);
            }

            Ok(serde_json::to_value(out).unwrap_or_else(|_| json!({})))
        }
    }

    #[derive(Debug, Error, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum QueryRedactionError {
        #[error("query component is not valid UTF-8")]
        InvalidUtf8,
    }

    fn is_secret_param_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        SECRET_PARAM_NAMES.iter().any(|secret| *secret == lower)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerification {
    pub records: usize,
    pub start_prev_hash: Option<[u8; 32]>,
    pub last_hash: Option<[u8; 32]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainVerificationError {
    #[error("audit chain line {line} is not valid JSON: {message}")]
    InvalidJson { line: usize, message: String },
    #[error("audit chain line {line} expected prev_hash {expected:?}, got {actual:?}")]
    PrevHashMismatch {
        line: usize,
        expected: Option<[u8; 32]>,
        actual: Option<[u8; 32]>,
    },
    #[error("audit chain line {line} has an invalid record_hash")]
    RecordHashMismatch { line: usize },
}

/// Verify retained audit records with the caller-selected hash mode.
///
/// The first retained record's `prev_hash` is the retained-set boundary. This
/// checks tamper-evidence for records still present in the verified set; it does
/// not prove that earlier records were never deleted. Use off-host audit
/// shipping when completeness matters.
pub fn verify_chain(
    envelopes: &[AuditEnvelope],
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError> {
    verify_retained_set(envelopes, hasher)
}

fn verify_retained_set(
    envelopes: &[AuditEnvelope],
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError> {
    let mut records = 0usize;
    let mut previous_hash = envelopes.first().and_then(|envelope| envelope.prev_hash);
    let mut start_prev_hash = None;
    let mut last_hash = None;

    for (index, envelope) in envelopes.iter().enumerate() {
        let line = index + 1;
        if records == 0 {
            start_prev_hash = envelope.prev_hash;
        }

        if envelope.prev_hash != previous_hash {
            return Err(ChainVerificationError::PrevHashMismatch {
                line,
                expected: previous_hash,
                actual: envelope.prev_hash,
            });
        }

        let expected_hash = record_hash(
            &envelope.envelope_id,
            envelope.timestamp_unix_ms,
            envelope.prev_hash.as_ref(),
            &envelope.record,
            hasher,
        )
        .map_err(|_| ChainVerificationError::InvalidJson {
            line,
            message: "hash input serialization failed".to_string(),
        })?;
        if !hashes_equal(&expected_hash, &envelope.record_hash) {
            return Err(ChainVerificationError::RecordHashMismatch { line });
        }

        previous_hash = Some(envelope.record_hash);
        last_hash = Some(envelope.record_hash);
        records += 1;
    }

    Ok(ChainVerification {
        records,
        start_prev_hash,
        last_hash,
    })
}

/// Verify a retained audit chain from JSONL lines using **UNKEYED** hashing.
///
/// This helper hardcodes [`AuditChainHasher::unkeyed_dev_only`], so it provides
/// NO protection against an attacker who can rewrite the JSONL set: an adversary
/// without the deployment HMAC secret can still forge a fully self-consistent
/// chain. It is intended only for tests, fixtures, and migration checks of
/// legacy pre-beta logs.
///
/// Production verification MUST use [`verify_jsonl_lines_with_hasher`] with an
/// explicit keyed [`AuditChainHasher`].
#[deprecated(
    note = "performs UNKEYED verification (dev/test only); use verify_jsonl_lines_with_hasher with an explicit AuditChainHasher in production"
)]
pub fn verify_jsonl_lines<I, S>(lines: I) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain(&envelopes, &AuditChainHasher::unkeyed_dev_only())
}

pub fn verify_jsonl_lines_with_hasher<I, S>(
    lines: I,
    hasher: &AuditChainHasher,
) -> Result<ChainVerification, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let envelopes = parse_jsonl_lines(lines)?;
    verify_chain(&envelopes, hasher)
}

fn parse_jsonl_lines<I, S>(lines: I) -> Result<Vec<AuditEnvelope>, ChainVerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut envelopes = Vec::new();
    for (index, line) in lines.into_iter().enumerate() {
        let line_no = index + 1;
        let line = line.as_ref().trim();
        if line.is_empty() {
            continue;
        }
        envelopes.push(
            serde_json::from_str::<AuditEnvelope>(line).map_err(|source| {
                ChainVerificationError::InvalidJson {
                    line: line_no,
                    message: source.to_string(),
                }
            })?,
        );
    }
    Ok(envelopes)
}

/// Parse JSONL content one non-empty line at a time, stopping at (rather than
/// erroring on) the first line that fails to parse as an [`AuditEnvelope`].
/// Used only by [`quarantine_and_recover_chain`], which treats an unparseable
/// tail line as evidence of a break rather than a reason to abort recovery.
/// Returns the successfully parsed prefix and whether every line parsed.
fn parse_jsonl_lines_lenient(contents: &str) -> (Vec<AuditEnvelope>, bool) {
    let mut envelopes = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEnvelope>(line) {
            Ok(envelope) => envelopes.push(envelope),
            Err(_) => return (envelopes, false),
        }
    }
    (envelopes, true)
}

/// Outcome of [`quarantine_and_recover_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecoveryOutcome {
    /// The retained chain already verified; nothing was changed.
    pub already_consistent: bool,
    /// 1-indexed line (retained-set order) of the first inconsistent record.
    pub first_bad_line: Option<usize>,
    /// Last verified record hash before the break (the predecessor the recovered
    /// segment chains onto), or `None` when the first record was already bad.
    pub last_good_hash: Option<[u8; 32]>,
    /// Record hash of the emitted `audit.chain.break` event.
    pub break_event_hash: Option<[u8; 32]>,
    /// Count of good records preserved in the quarantine archive before the break.
    pub records_before_break: usize,
    /// Filename suffix applied to the quarantined files (`corrupt-<ts>`).
    pub quarantine_suffix: Option<String>,
}

/// `event` discriminator of the tamper-evident chain-break record.
pub const CHAIN_BREAK_EVENT: &str = "audit.chain.break";

/// Record body of the tamper-evident chain-break event that opens a recovered
/// segment. It is the `record` of the first envelope of the fresh chain, so it
/// is itself hashed and chained onto `last_good_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainBreakRecord {
    /// Always [`CHAIN_BREAK_EVENT`].
    pub event: String,
    /// Operator-supplied reason for the recovery.
    pub reason: String,
    /// When the recovery ran (UTC Unix ms).
    pub recovered_at_unix_ms: i64,
    /// 1-indexed line of the first inconsistent record in the quarantined set.
    pub first_bad_line: usize,
    /// Last verified record hash before the break (hex), or `None`.
    pub last_good_hash: Option<String>,
    /// Count of good records preserved before the break.
    pub records_before_break: usize,
    /// Filename suffix applied to the quarantined files.
    pub quarantine_suffix: String,
    /// Optional operator identity recorded for accountability.
    pub operator: Option<String>,
}

/// Quarantine a retained audit chain that no longer verifies and start a fresh
/// break segment (#196). This is the offline operator recovery path: it takes
/// the single-writer lock, so it refuses to run while the server holds it
/// (returns [`AuditError::SinkLocked`]).
///
/// Retained-set verification starts at the first retained record's `prev_hash`,
/// so a legitimately aged-out genesis is not treated as corruption. Any
/// first-failing-line divergence is handled uniformly: a mid-file fork
/// (`PrevHashMismatch`), a rewrite or wrong-key tail (`RecordHashMismatch`), or a
/// torn line (`InvalidJson`): every retained data file is moved aside to
/// `<name>.corrupt-<ts>` (retained, never deleted), and a fresh active file is
/// started whose first record is a hash-linked `audit.chain.break` event chained
/// onto the last good tail.
///
/// `now_unix_ms` is supplied by the caller so the archive suffix is
/// deterministic and testable.
///
/// Security note (audit integrity, per CONTRIBUTING): the break event is itself
/// chained and hashed, and the corrupt segment is retained, so the discontinuity
/// is tamper-evident and an operator cannot silently erase records after the
/// break. Off-host shipping remains the structural completeness guarantee.
pub fn quarantine_and_recover_chain(
    path: &Path,
    max_files: u32,
    hasher: &AuditChainHasher,
    reason: &str,
    operator: Option<&str>,
    now_unix_ms: i64,
) -> Result<ChainRecoveryOutcome, AuditError> {
    let _lock = acquire_writer_lock(path)?;
    let max_files = max_files.max(1);

    let paths = existing_audit_paths(path, max_files);
    let mut contents = String::new();
    for source in &paths {
        contents.push_str(&read_audit_file(source)?);
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }
    // Parse leniently rather than with `parse_jsonl_lines`: a torn trailing
    // line (#196, where an unclean container stop truncates the last write) must
    // recover the same as any other break, not abort with `InvalidJson`
    // before the scan even runs. Stop at the first unparseable line and treat
    // the successfully parsed prefix as the retained set; `first_bad` then
    // takes whichever comes first, an inconsistency already inside that
    // prefix or the torn line itself.
    let (envelopes, fully_parsed) = parse_jsonl_lines_lenient(&contents);

    let (first_bad, last_good, good_count) = scan_first_inconsistency(&envelopes, hasher);
    let first_bad = if first_bad == 0 && !fully_parsed {
        envelopes.len() + 1
    } else {
        first_bad
    };
    if first_bad == 0 {
        return Ok(ChainRecoveryOutcome {
            already_consistent: true,
            first_bad_line: None,
            last_good_hash: last_good,
            break_event_hash: None,
            records_before_break: good_count,
            quarantine_suffix: None,
        });
    }

    let suffix = format!("corrupt-{now_unix_ms}");
    for source in &paths {
        let dest = PathBuf::from(format!("{}.{suffix}", source.display()));
        fs::rename(source, &dest).map_err(AuditError::Io)?;
    }

    // An upgrade from a release that wrote the local completeness anchor can
    // leave `<path>.anchor.json` behind. It describes the chain now being
    // quarantined, so move it aside under the same suffix rather than leaving
    // it where it looks current. A clean install has no sidecar; that is not an
    // error.
    let legacy_anchor = PathBuf::from(format!("{}.anchor.json", path.display()));
    if legacy_anchor.exists() {
        let dest = PathBuf::from(format!("{}.{suffix}", legacy_anchor.display()));
        fs::rename(&legacy_anchor, &dest).map_err(AuditError::Io)?;
    }

    let break_record = ChainBreakRecord {
        event: CHAIN_BREAK_EVENT.to_string(),
        reason: reason.to_string(),
        recovered_at_unix_ms: now_unix_ms,
        first_bad_line: first_bad,
        last_good_hash: last_good.map(|hash| hex_lower(&hash)),
        records_before_break: good_count,
        quarantine_suffix: suffix.clone(),
        operator: operator.map(str::to_string),
    };
    let break_value = serde_json::to_value(&break_record).map_err(AuditError::Json)?;
    let break_envelope = AuditEnvelope::new_with_hasher(break_value, last_good, hasher)?;

    // Write the break event directly as line 1 of the fresh active file. The
    // sink's tail self-check is bypassed on purpose: the break event's prev_hash
    // points at a record now in the archive, not in the (empty) active set.
    ensure_parent_dir(path)?;
    let line = break_envelope.to_jsonl()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .audit_file_mode()
        .open(path)
        .map_err(AuditError::Io)?;
    file.write_all(line.as_bytes()).map_err(AuditError::Io)?;
    file.flush().map_err(AuditError::Io)?;

    Ok(ChainRecoveryOutcome {
        already_consistent: false,
        first_bad_line: Some(first_bad),
        last_good_hash: last_good,
        break_event_hash: Some(break_envelope.record_hash),
        records_before_break: good_count,
        quarantine_suffix: Some(suffix),
    })
}

/// Scan for the first record that breaks chain continuity, starting from the
/// first retained record's `prev_hash`. Returns `(first_bad_line_1indexed,
/// last_good_hash, good_count)`; `first_bad_line == 0` means fully consistent.
fn scan_first_inconsistency(
    envelopes: &[AuditEnvelope],
    hasher: &AuditChainHasher,
) -> (usize, Option<[u8; 32]>, usize) {
    let mut previous = envelopes.first().and_then(|env| env.prev_hash);
    let mut last_good = None;
    for (index, env) in envelopes.iter().enumerate() {
        if env.prev_hash != previous {
            return (index + 1, last_good, index);
        }
        let expected = record_hash(
            &env.envelope_id,
            env.timestamp_unix_ms,
            env.prev_hash.as_ref(),
            &env.record,
            hasher,
        )
        .ok();
        if expected != Some(env.record_hash) {
            return (index + 1, last_good, index);
        }
        previous = Some(env.record_hash);
        last_good = Some(env.record_hash);
    }
    (0, last_good, envelopes.len())
}

fn tail_hash_from_files(
    path: &Path,
    max_files: u32,
    hasher: &AuditChainHasher,
) -> Result<Option<[u8; 32]>, AuditError> {
    let paths = existing_audit_paths(path, max_files);
    if paths.is_empty() {
        return Ok(None);
    }

    let mut contents = String::new();
    for source in &paths {
        let file_contents = read_audit_file(source)?;
        contents.push_str(&file_contents);
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }

    let envelopes = parse_jsonl_lines(contents.lines()).map_err(AuditError::ChainVerification)?;
    if envelopes.is_empty() {
        return Ok(None);
    }
    let verification = verify_chain(&envelopes, hasher).map_err(AuditError::ChainVerification)?;
    Ok(verification.last_hash)
}

fn read_audit_file(path: &Path) -> Result<String, AuditError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(AuditError::Io(error)),
    };
    Ok(contents)
}

/// Initial tail window for [`read_last_line`]; audit envelopes are well under
/// this, so a single read almost always captures the final line.
const TAIL_READ_WINDOW_BYTES: u64 = 8192;

/// Read the last non-empty line of `path` by seeking from the end, without
/// loading the whole file. Returns `None` for a missing or empty file. Grows
/// the read window until a complete final line is captured (or the whole file
/// has been read, for a single line larger than the window).
fn read_last_line(path: &Path) -> Result<Option<String>, AuditError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AuditError::Io(error)),
    };
    let len = file.metadata().map_err(AuditError::Io)?.len();
    if len == 0 {
        return Ok(None);
    }

    let mut window = TAIL_READ_WINDOW_BYTES;
    loop {
        let start = len.saturating_sub(window);
        file.seek(SeekFrom::Start(start)).map_err(AuditError::Io)?;
        let mut buf = Vec::with_capacity((len - start) as usize);
        Read::by_ref(&mut file)
            .take(len - start)
            .read_to_end(&mut buf)
            .map_err(AuditError::Io)?;

        let text = String::from_utf8(buf).map_err(|_| {
            AuditError::ChainVerification(ChainVerificationError::InvalidJson {
                line: 0,
                message: "audit tail is not valid UTF-8".to_string(),
            })
        })?;
        let trimmed = text.trim_end_matches(['\n', '\r']);
        match trimmed.rfind('\n') {
            Some(idx) => {
                let last = trimmed[idx + 1..].trim();
                return Ok((!last.is_empty()).then(|| last.to_string()));
            }
            None if start == 0 => {
                let last = trimmed.trim();
                return Ok((!last.is_empty()).then(|| last.to_string()));
            }
            None => {
                // The window did not reach a line boundary; widen and retry.
                window = window.saturating_mul(2);
            }
        }
    }
}

fn existing_audit_paths(path: &Path, max_files: u32) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for index in (1..max_files).rev() {
        let rotated = rotated_path(path, index);
        if rotated.exists() {
            paths.push(rotated);
        }
    }
    if path.exists() {
        paths.push(path.to_path_buf());
    }
    paths
}

fn record_hash(
    envelope_id: &str,
    timestamp_unix_ms: i64,
    prev_hash: Option<&[u8; 32]>,
    record: &Value,
    hasher: &AuditChainHasher,
) -> Result<[u8; 32], AuditError> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        envelope_id: &'a str,
        timestamp_unix_ms: i64,
        prev_hash: Option<String>,
        record: &'a Value,
    }

    let input = HashInput {
        envelope_id,
        timestamp_unix_ms,
        prev_hash: prev_hash.map(|hash| hex_lower(hash)),
        record,
    };
    let bytes = serde_json::to_vec(&input).map_err(AuditError::Json)?;
    Ok(hasher.hash_record(&bytes))
}

fn hashes_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn now_unix_ms() -> i64 {
    let millis = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    match i64::try_from(millis) {
        Ok(millis) => millis,
        Err(_) if millis.is_negative() => i64::MIN,
        Err(_) => i64::MAX,
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_audit_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
trait AuditFileMode {
    fn audit_file_mode(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl AuditFileMode for OpenOptions {
    fn audit_file_mode(&mut self) -> &mut Self {
        self.mode(0o600)
    }
}

#[cfg(not(unix))]
trait AuditFileMode {
    fn audit_file_mode(&mut self) -> &mut Self;
}

#[cfg(not(unix))]
impl AuditFileMode for OpenOptions {
    fn audit_file_mode(&mut self) -> &mut Self {
        self
    }
}

#[cfg(unix)]
fn create_audit_dir_all(path: &Path) -> Result<(), AuditError> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(AuditError::Io)
}

#[cfg(not(unix))]
fn create_audit_dir_all(path: &Path) -> Result<(), AuditError> {
    fs::create_dir_all(path).map_err(AuditError::Io)
}

fn remove_file_if_exists(path: &Path) -> Result<(), AuditError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> Result<(), AuditError> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

fn join_error_to_io(error: tokio::task::JoinError) -> AuditError {
    AuditError::Io(std::io::Error::other(error))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{UNKEYED_HASH_PREFIX}{}", hex_lower(&sha256_bytes(bytes)))
}

fn hmac_sha256_hex(secret: &[u8], bytes: &[u8]) -> String {
    format!(
        "{KEYED_HASH_PREFIX}{}",
        hex_lower(&hmac_sha256_bytes(secret, b"", bytes))
    )
}

fn hmac_sha256_bytes(secret: &[u8], context: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    if !context.is_empty() {
        mac.update(context);
        mac.update(&[0]);
    }
    mac.update(bytes);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// HKDF-Expand (RFC 5869) over SHA-256, producing one 32-byte output block.
///
/// The master env secret is already operator-supplied high-entropy material of
/// at least 32 bytes, so it is used directly as the HKDF pseudorandom key (PRK)
/// without a separate Extract step (Expand-only); a distinct per-purpose `info`
/// label domain-separates each derived sub-key. Because the SHA-256 output is a
/// single block, the counter byte is always `0x01` and no `T(0)` carry is
/// needed. The caller moves the returned bytes straight into the
/// `ZeroizeOnDrop` [`SecretBytes`] backing an [`AuditHashSecret`], so the
/// derived sub-key is scrubbed on drop without an intermediate copy.
fn hkdf_expand_sha256(prk: &[u8], info: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(prk).expect("HMAC-SHA256 accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    mac.finalize().into_bytes().to_vec()
}

/// Derive a domain-separated [`AuditHashSecret`] sub-key from a master env
/// secret using [`hkdf_expand_sha256`] (AUDIT-03).
///
/// A leak of one derived sub-key reveals neither the master secret nor the
/// sibling sub-key, because each is a one-way HMAC over an independent `info`
/// label.
fn derive_subkey_from_env(env_var_name: &str, info: &[u8]) -> Result<AuditHashSecret, AuditError> {
    if env_var_name.trim().is_empty() {
        return Err(AuditError::EmptyEnvVarName);
    }
    let value = Zeroizing::new(env::var(env_var_name).map_err(|source| AuditError::EnvVar {
        name: env_var_name.to_string(),
        source,
    })?);
    if value.is_empty() {
        return Err(AuditError::EmptySecret {
            name: env_var_name.to_string(),
        });
    }
    // `value` (a `Zeroizing<String>`) owns and scrubs the master secret across
    // every return path; borrow its bytes for the length check and HKDF rather
    // than allocating a separate copy of the secret.
    if value.len() < MIN_AUDIT_SECRET_BYTES {
        return Err(AuditError::WeakSecret {
            name: env_var_name.to_string(),
            min_bytes: MIN_AUDIT_SECRET_BYTES,
        });
    }
    let derived = hkdf_expand_sha256(value.as_bytes(), info);
    Ok(AuditHashSecret::from_bytes(derived))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hash_hex(value: &str, field: &'static str) -> Result<[u8; 32], AuditError> {
    if value.len() != 64 {
        return Err(AuditError::InvalidHashHex { field });
    }

    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or(AuditError::InvalidHashHex { field })?;
        let lo = hex_value(chunk[1]).ok_or(AuditError::InvalidHashHex { field })?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn split_field_operator(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((field, op)) if !field.is_empty() && !op.is_empty() => (field, op),
        _ => (name, "eq"),
    }
}

fn decode_query_component(raw: &str) -> Result<String, redact::QueryRedactionError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_value_any(bytes[i + 1]), hex_value_any(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| redact::QueryRedactionError::InvalidUtf8)
}

fn hex_value_any(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn rfc5424_frame(message: &str) -> String {
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "-".to_string());
    format!("<134>1 {timestamp} - registry-platform-audit - - - {message}")
}

#[cfg(unix)]
async fn send_syslog_datagram(socket_path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    let socket = tokio::net::UnixDatagram::unbound().map_err(AuditError::Io)?;
    socket
        .send_to(bytes, socket_path)
        .await
        .map_err(AuditError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
async fn send_syslog_datagram(_socket_path: &Path, _bytes: &[u8]) -> Result<(), AuditError> {
    Err(AuditError::Io(std::io::Error::new(
        ErrorKind::Unsupported,
        "syslog audit sink requires Unix datagram sockets",
    )))
}

#[cfg(target_os = "macos")]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::from("/var/run/syslog")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::from("/dev/log")
}

#[cfg(not(unix))]
fn default_syslog_socket_path() -> PathBuf {
    PathBuf::new()
}

mod hash_hex {
    use super::*;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_lower(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_hash_hex(&value, "record_hash").map_err(serde::de::Error::custom)
    }
}

mod option_hash_hex {
    use super::*;

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex_lower(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .as_deref()
            .map(|hash| parse_hash_hex(hash, "prev_hash"))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{redact::QueryRedactor, *};

    struct StalledSink {
        started: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl Default for StalledSink {
        fn default() -> Self {
            Self {
                started: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    #[async_trait]
    impl AuditSink for StalledSink {
        async fn write(&self, _envelope: &AuditEnvelope) -> Result<(), AuditError> {
            self.started.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("test release semaphore stays open")
                .forget();
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    fn durable_operation_id() -> DurableAuditOperationId {
        DurableAuditOperationId::parse("01J5K8M0000000000000000000")
            .expect("test operation id is canonical")
    }

    fn durable_write(
        stream_kind: DurableAuditStreamKind,
        phase: DurableAuditPhase,
        payload: Value,
    ) -> DurableAuditWrite {
        DurableAuditWrite::new(stream_kind, durable_operation_id(), phase, payload)
            .expect("test durable write is valid")
    }

    #[test]
    fn durable_audit_closed_labels_parse_exactly() {
        for (label, expected) in [
            ("consultation", DurableAuditStreamKind::Consultation),
            ("materialization", DurableAuditStreamKind::Materialization),
            ("denial", DurableAuditStreamKind::Denial),
            (
                "startup_credential_probe",
                DurableAuditStreamKind::StartupCredentialProbe,
            ),
            (
                "readiness_credential_probe",
                DurableAuditStreamKind::ReadinessCredentialProbe,
            ),
        ] {
            assert_eq!(DurableAuditStreamKind::try_from(label), Ok(expected));
            assert_eq!(expected.as_str(), label);
        }
        assert_eq!(
            DurableAuditStreamKind::try_from("caller-supplied"),
            Err(DurableAuditValidationError::InvalidStreamKind)
        );

        for (label, expected) in [
            ("attempt", DurableAuditPhase::Attempt),
            ("completion", DurableAuditPhase::Completion),
            ("denial_decision", DurableAuditPhase::DenialDecision),
        ] {
            assert_eq!(DurableAuditPhase::try_from(label), Ok(expected));
            assert_eq!(expected.as_str(), label);
        }
        assert_eq!(
            DurableAuditPhase::try_from("dispatch"),
            Err(DurableAuditValidationError::InvalidPhase)
        );
    }

    #[test]
    fn durable_audit_stream_phase_matrix_is_closed() {
        let operation_id = durable_operation_id();
        let valid = [
            (
                DurableAuditStreamKind::Consultation,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::Consultation,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::Denial,
                DurableAuditPhase::DenialDecision,
            ),
            (
                DurableAuditStreamKind::StartupCredentialProbe,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::StartupCredentialProbe,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::ReadinessCredentialProbe,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::ReadinessCredentialProbe,
                DurableAuditPhase::Completion,
            ),
        ];
        for (stream, phase) in valid {
            DurableAuditOperationKey::new(stream, operation_id.clone(), phase)
                .expect("accepted stream/phase pair");
        }

        let invalid = [
            (DurableAuditStreamKind::Denial, DurableAuditPhase::Attempt),
            (
                DurableAuditStreamKind::Denial,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::Consultation,
                DurableAuditPhase::DenialDecision,
            ),
            (
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::DenialDecision,
            ),
            (
                DurableAuditStreamKind::StartupCredentialProbe,
                DurableAuditPhase::DenialDecision,
            ),
            (
                DurableAuditStreamKind::ReadinessCredentialProbe,
                DurableAuditPhase::DenialDecision,
            ),
        ];
        for (stream, phase) in invalid {
            assert_eq!(
                DurableAuditOperationKey::new(stream, operation_id.clone(), phase),
                Err(DurableAuditValidationError::InvalidStreamPhaseCombination)
            );
        }
    }

    #[test]
    fn durable_audit_operation_id_validates_canonical_syntax() {
        let canonical = "01J5K8M0000000000000000000";
        assert_eq!(
            DurableAuditOperationId::parse(canonical)
                .expect("canonical operation id")
                .as_str(),
            canonical
        );
        assert_eq!(
            DurableAuditOperationId::parse("not-an-operation-id"),
            Err(DurableAuditValidationError::InvalidOperationId)
        );
        assert_eq!(
            DurableAuditOperationId::parse(&canonical.to_ascii_lowercase()),
            Err(DurableAuditValidationError::InvalidOperationId)
        );
    }

    #[test]
    fn durable_audit_write_canonicalizes_object_and_derives_fixed_digest() {
        let write = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            json!({"event": "consultation.attempt"}),
        );
        assert_eq!(
            write.payload_digest().to_lower_hex(),
            "be830668de05435f7be931b49de534d7a009c1003385ec757e85dfef117e6fb6"
        );

        let envelope = write
            .build_envelope_at_chain_head(None, &AuditChainHasher::unkeyed_dev_only())
            .expect("sink can build envelope");
        let expected_payload_digest = format!("sha256:{}", write.payload_digest().to_lower_hex());
        assert_eq!(
            envelope.record,
            json!({
                "schema": DURABLE_AUDIT_RECORD_SCHEMA_V1,
                "stream_kind": "consultation",
                "operation_id": "01J5K8M0000000000000000000",
                "phase": "attempt",
                "payload_digest": expected_payload_digest,
                "payload": { "event": "consultation.attempt" },
            })
        );
        assert!(envelope.prev_hash.is_none());
    }

    #[test]
    fn durable_audit_write_rejects_invalid_payload_shapes_without_echoing_input() {
        let make = |payload: Value| {
            DurableAuditWrite::new(
                DurableAuditStreamKind::Consultation,
                durable_operation_id(),
                DurableAuditPhase::Attempt,
                payload,
            )
        };
        assert_eq!(
            make(Value::Null).expect_err("null fails"),
            DurableAuditValidationError::SafePayloadMustBeObject
        );
        assert_eq!(
            make(json!([])).expect_err("array fails"),
            DurableAuditValidationError::SafePayloadMustBeObject
        );
        assert_eq!(
            make(json!({})).expect_err("empty object fails"),
            DurableAuditValidationError::SafePayloadMustBeNonEmpty
        );
    }

    #[test]
    fn durable_audit_write_maps_jcs_integer_rounding_rejection_to_a_safe_error() {
        let result = DurableAuditWrite::new(
            DurableAuditStreamKind::Consultation,
            durable_operation_id(),
            DurableAuditPhase::Attempt,
            json!({
                "nested": {
                    "rounded_by_binary64": 9_007_199_254_740_993_u64,
                }
            }),
        );

        assert_eq!(
            result.expect_err("out-of-range integer must not enter the digest"),
            DurableAuditValidationError::SafePayloadCanonicalizationFailed
        );
    }

    #[tokio::test]
    async fn durable_audit_sink_builds_envelopes_at_its_serialized_chain_head() {
        let sink = InMemoryDurableAuditTestSink::default();
        let attempt = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            json!({"event": "consultation.attempt"}),
        );
        let completion = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Completion,
            json!({"event": "consultation.completion"}),
        );

        let attempt_outcome = sink.write_phase(&attempt).await.expect("attempt insert");
        let completion_outcome = sink
            .write_phase(&completion)
            .await
            .expect("completion insert");
        assert!(matches!(
            attempt_outcome,
            DurableAuditWriteOutcome::Inserted(_)
        ));
        assert!(matches!(
            completion_outcome,
            DurableAuditWriteOutcome::Inserted(_)
        ));
        let attempt_envelope = sink
            .stored_envelope(attempt.key())
            .await
            .expect("attempt envelope");
        let completion_envelope = sink
            .stored_envelope(completion.key())
            .await
            .expect("completion envelope");
        assert!(attempt_envelope.prev_hash.is_none());
        assert_eq!(
            completion_envelope.prev_hash,
            Some(attempt_envelope.record_hash)
        );
        assert_eq!(sink.len().await, 2);
    }

    #[tokio::test]
    async fn durable_audit_identical_replay_returns_original_stored_identity() {
        let sink = InMemoryDurableAuditTestSink::default();
        let payload = json!({"event": "consultation.attempt"});
        let original = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            payload.clone(),
        );
        let replay = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            payload,
        );

        let inserted = sink.write_phase(&original).await.expect("initial insert");
        let outcome = sink.write_phase(&replay).await.expect("replay succeeds");

        assert_eq!(
            outcome,
            DurableAuditWriteOutcome::IdenticalDuplicate(inserted.stored_identity().clone())
        );
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn durable_audit_conflicting_replay_is_outcome_with_original_identity() {
        let sink = InMemoryDurableAuditTestSink::default();
        let original = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Completion,
            json!({"outcome": "known_complete"}),
        );
        let conflicting = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Completion,
            json!({"outcome": "outcome_unknown"}),
        );

        let inserted = sink.write_phase(&original).await.expect("initial insert");
        let outcome = sink
            .write_phase(&conflicting)
            .await
            .expect("conflict is a deterministic outcome");
        assert_eq!(
            outcome,
            DurableAuditWriteOutcome::ConflictingDuplicate(inserted.stored_identity().clone())
        );
        assert_eq!(sink.len().await, 1);
        assert_eq!(
            sink.stored_envelope(original.key())
                .await
                .expect("original remains")
                .envelope_id,
            inserted.stored_identity().envelope_id()
        );
    }

    #[tokio::test]
    async fn durable_audit_key_separates_streams_and_phases() {
        let sink = InMemoryDurableAuditTestSink::default();
        let valid = [
            (
                DurableAuditStreamKind::Consultation,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::Consultation,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::Denial,
                DurableAuditPhase::DenialDecision,
            ),
            (
                DurableAuditStreamKind::StartupCredentialProbe,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::StartupCredentialProbe,
                DurableAuditPhase::Completion,
            ),
            (
                DurableAuditStreamKind::ReadinessCredentialProbe,
                DurableAuditPhase::Attempt,
            ),
            (
                DurableAuditStreamKind::ReadinessCredentialProbe,
                DurableAuditPhase::Completion,
            ),
        ];
        for (stream_kind, phase) in valid {
            let payload = json!({
                "phase": phase.as_str(),
                "stream": stream_kind.as_str(),
            });
            let write = durable_write(stream_kind, phase, payload);
            assert!(matches!(
                sink.write_phase(&write)
                    .await
                    .expect("distinct key inserts"),
                DurableAuditWriteOutcome::Inserted(_)
            ));
        }

        assert_eq!(sink.len().await, 9);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_audit_concurrent_identical_writes_insert_exactly_once() {
        const WRITERS: usize = 64;
        let sink = Arc::new(InMemoryDurableAuditTestSink::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(WRITERS));
        let mut writes = tokio::task::JoinSet::new();

        for _ in 0..WRITERS {
            let sink = Arc::clone(&sink);
            let barrier = Arc::clone(&barrier);
            let write = durable_write(
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Attempt,
                json!({"event": "materialization.attempt"}),
            );
            writes.spawn(async move {
                barrier.wait().await;
                sink.write_phase(&write).await
            });
        }

        let mut inserted = 0;
        let mut duplicates = 0;
        let mut stored_ids = BTreeSet::new();
        while let Some(joined) = writes.join_next().await {
            let outcome = joined
                .expect("writer task completes")
                .expect("write succeeds");
            match &outcome {
                DurableAuditWriteOutcome::Inserted(_) => inserted += 1,
                DurableAuditWriteOutcome::IdenticalDuplicate(_) => duplicates += 1,
                DurableAuditWriteOutcome::ConflictingDuplicate(_) => {
                    panic!("identical digest must not conflict")
                }
            }
            stored_ids.insert(outcome.stored_identity().envelope_id().to_string());
        }

        assert_eq!(inserted, 1);
        assert_eq!(duplicates, WRITERS - 1);
        assert_eq!(stored_ids.len(), 1);
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_audit_concurrent_conflicting_writers_choose_one_payload() {
        const WRITERS_PER_PAYLOAD: usize = 32;
        const WRITERS: usize = WRITERS_PER_PAYLOAD * 2;
        let sink = Arc::new(InMemoryDurableAuditTestSink::default());
        let barrier = Arc::new(tokio::sync::Barrier::new(WRITERS));
        let mut writes = tokio::task::JoinSet::new();

        for index in 0..WRITERS {
            let sink = Arc::clone(&sink);
            let barrier = Arc::clone(&barrier);
            let payload = if index < WRITERS_PER_PAYLOAD {
                json!({"outcome": "known_complete"})
            } else {
                json!({"outcome": "outcome_unknown"})
            };
            let write = durable_write(
                DurableAuditStreamKind::Materialization,
                DurableAuditPhase::Completion,
                payload,
            );
            writes.spawn(async move {
                barrier.wait().await;
                sink.write_phase(&write).await
            });
        }

        let mut inserted = 0;
        let mut duplicates = 0;
        let mut conflicts = 0;
        let mut stored_ids = BTreeSet::new();
        while let Some(joined) = writes.join_next().await {
            let outcome = joined
                .expect("writer task completes")
                .expect("write returns deterministic outcome");
            match &outcome {
                DurableAuditWriteOutcome::Inserted(_) => inserted += 1,
                DurableAuditWriteOutcome::IdenticalDuplicate(_) => duplicates += 1,
                DurableAuditWriteOutcome::ConflictingDuplicate(_) => conflicts += 1,
            }
            stored_ids.insert(outcome.stored_identity().envelope_id().to_string());
        }

        assert_eq!(inserted, 1);
        assert_eq!(duplicates, WRITERS_PER_PAYLOAD - 1);
        assert_eq!(conflicts, WRITERS_PER_PAYLOAD);
        assert_eq!(stored_ids.len(), 1);
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn durable_audit_debug_and_errors_redact_payloads_and_digests() {
        const RAW_SELECTOR: &str = "NID-raw-selector-must-not-leak";
        const RAW_SECRET: &str = "source-token-must-not-leak";
        let sink = InMemoryDurableAuditTestSink::default();
        let safe_payload = json!({
            "selector": RAW_SELECTOR,
            "token": RAW_SECRET,
        });
        let write = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            safe_payload,
        );

        let write_debug = format!("{write:?}");
        assert!(!write_debug.contains(RAW_SELECTOR));
        assert!(!write_debug.contains(RAW_SECRET));
        assert!(!write_debug.contains(&write.payload_digest().to_lower_hex()));
        sink.write_phase(&write).await.expect("insert");
        let sink_debug = format!("{sink:?}");
        assert!(!sink_debug.contains(RAW_SELECTOR));
        assert!(!sink_debug.contains(RAW_SECRET));

        let conflict = durable_write(
            DurableAuditStreamKind::Consultation,
            DurableAuditPhase::Attempt,
            json!({"event": "different"}),
        );
        let outcome = sink
            .write_phase(&conflict)
            .await
            .expect("conflict is an outcome");
        let stored_record_hash = hex_lower(outcome.stored_identity().record_hash());
        for diagnostic in [
            format!("{outcome:?}"),
            format!("{:?}", DurableAuditWriteError::StoreUnavailable),
            DurableAuditWriteError::StoreFailure.to_string(),
        ] {
            assert!(!diagnostic.contains(RAW_SELECTOR));
            assert!(!diagnostic.contains(RAW_SECRET));
            assert!(!diagnostic.contains(&write.payload_digest().to_lower_hex()));
            assert!(!diagnostic.contains(&stored_record_hash));
        }

        let rejected = format!("{RAW_SECRET}-not-a-ulid");
        let validation = DurableAuditOperationId::parse(&rejected)
            .expect_err("invalid operation id is rejected");
        assert!(!format!("{validation:?}").contains(RAW_SECRET));
        assert!(!validation.to_string().contains(RAW_SECRET));
    }

    #[test]
    fn default_rotation_retains_fifty_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);

        // The default retention cap is ~500 MiB (50 files x 10 MiB) so audit
        // history is not silently discarded after ~50 MiB.
        assert_eq!(sink.inner.max_size_bytes, 10 * 1024 * 1024);
        assert_eq!(sink.inner.max_files, 50);
    }

    #[tokio::test]
    async fn audit_chain_bootstraps_from_sink_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap empty");

        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert!(first.prev_hash.is_none());
        assert_eq!(second.prev_hash, Some(first.record_hash));
        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("tail"),
            Some(second.record_hash)
        );

        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap tail");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");
        assert_eq!(third.prev_hash, Some(second.record_hash));

        let contents = fs::read_to_string(path).expect("audit file");
        let verification =
            verify_jsonl_lines_with_hasher(contents.lines(), &AuditChainHasher::unkeyed_dev_only())
                .expect("valid chain");
        assert_eq!(verification.records, 3);
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[tokio::test]
    async fn audit_chain_tail_read_fails_fast_while_append_is_stalled() {
        let chain = Arc::new(ChainState::unkeyed_dev_only());
        let sink = Arc::new(StalledSink::default());
        let append = tokio::spawn({
            let chain = Arc::clone(&chain);
            let sink = Arc::clone(&sink);
            async move {
                chain
                    .append(sink.as_ref(), json!({ "event": "stalled" }))
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), sink.started.acquire())
            .await
            .expect("audit write stalls within the test deadline")
            .expect("test started semaphore stays open")
            .forget();

        assert_eq!(chain.try_last_hash(), None);

        sink.release.add_permits(1);
        let envelope = tokio::time::timeout(Duration::from_secs(1), append)
            .await
            .expect("append completes within the test deadline")
            .expect("append task joins")
            .expect("append writes");
        assert_eq!(chain.try_last_hash(), Some(Some(envelope.record_hash)));
    }

    #[tokio::test]
    async fn keyed_chain_rejects_full_rewrite_without_secret() {
        let sink = MemorySink::default();
        let secret =
            AuditHashSecret::new(b"this-is-a-32-byte-chain-secret-ok".to_vec()).expect("secret");
        let hasher = AuditChainHasher::keyed(secret);
        let chain = ChainState::new(hasher.clone());
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        verify_chain(&[first.clone(), second.clone()], &hasher).expect("keyed chain verifies");

        let fake_first = AuditEnvelope::new(json!({ "event": "fake-first" }), None)
            .expect("attacker can build legacy first");
        let fake_second = AuditEnvelope::new(
            json!({ "event": "fake-second" }),
            Some(fake_first.record_hash),
        )
        .expect("attacker can build legacy second");

        assert!(matches!(
            verify_chain(&[fake_first, fake_second], &hasher),
            Err(ChainVerificationError::RecordHashMismatch { line: 1 })
        ));
    }

    #[tokio::test]
    async fn production_bootstrap_rejects_non_tailable_sink() {
        let hasher = AuditChainHasher::keyed(
            AuditHashSecret::new(b"this-is-a-32-byte-chain-secret-ok".to_vec()).expect("secret"),
        );

        assert!(matches!(
            ChainState::bootstrap(&JsonlStdoutSink::new(), hasher).await,
            Err(AuditError::NonTailableSink)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_sink_creates_private_file_and_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let audit_dir = dir.path().join("private-audit");
        let path = audit_dir.join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();

        chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("append");

        let file_mode = fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(&audit_dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[tokio::test]
    async fn audit_chain_detects_inserted_envelope() {
        let sink = MemorySink::default();
        let chain = ChainState::unkeyed_dev_only();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let _second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");
        let third = chain
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");

        let err = verify_chain(&[first, third], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("gap detected");
        assert!(matches!(
            err,
            ChainVerificationError::PrevHashMismatch { line: 2, .. }
        ));
    }

    #[test]
    fn audit_hash_secret_debug_never_exposes_raw_bytes() {
        let raw_bytes = b"this-is-a-32-byte-secret-1234567";
        let secret = AuditHashSecret::new(raw_bytes.to_vec()).expect("secret builds");

        let debug = format!("{secret:?}");

        assert!(
            debug.contains("<redacted>"),
            "debug must contain <redacted>"
        );
        assert!(
            !debug.contains("this-is-a-32-byte-secret-1234567"),
            "debug must not expose the raw secret bytes"
        );
    }

    #[test]
    fn audit_envelope_debug_redacts_record() {
        let envelope = AuditEnvelope::new(
            json!({
                "event": "credential.issued",
                "token": "secret-token",
                "email": "jeremi@example.test",
            }),
            None,
        )
        .expect("envelope");

        let debug = format!("{envelope:?}");

        assert!(debug.contains("AuditEnvelope"));
        assert!(debug.contains("record: \"<redacted>\""));
        assert!(debug.contains(&envelope.envelope_id));
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("jeremi@example.test"));
        assert!(!debug.contains("credential.issued"));
    }

    #[test]
    fn audit_chain_detects_tampered_record() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let mut second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        second.record["event"] = json!("changed");

        let err = verify_chain(&[first, second], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 2 });
    }

    #[test]
    fn audit_chain_detects_tampered_timestamp() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.timestamp_unix_ms += 1;

        let err = verify_chain(&[envelope], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[test]
    fn audit_chain_detects_tampered_envelope_id() {
        let mut envelope = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        envelope.envelope_id = Ulid::new().to_string();

        let err = verify_chain(&[envelope], &AuditChainHasher::unkeyed_dev_only())
            .expect_err("tamper detected");
        assert_eq!(err, ChainVerificationError::RecordHashMismatch { line: 1 });
    }

    #[tokio::test]
    async fn file_sink_tail_hash_accepts_retained_set_after_missing_first_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();
        let _first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        let contents = fs::read_to_string(&path).expect("audit file");
        let rewritten = contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, rewritten).expect("rewrite without first line");

        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("retained set tail"),
            Some(second.record_hash)
        );
    }

    #[tokio::test]
    async fn file_sink_bootstrap_accepts_retained_set_after_missing_first_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();
        chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        let contents = fs::read_to_string(&path).expect("audit file");
        let rewritten = contents.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, rewritten).expect("rewrite without first line");

        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap retained set");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("append after retained set");
        assert_eq!(third.prev_hash, Some(second.record_hash));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_continues_from_retained_rotated_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 2);
        let chain = ChainState::unkeyed_dev_only();
        let mut third_hash = None;
        for event in ["first", "second", "third"] {
            let envelope = chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
            third_hash = Some(envelope.record_hash);
        }

        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("tail"),
            third_hash
        );
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap");
        let fourth = bootstrapped
            .append(&sink, json!({ "event": "fourth" }))
            .await
            .expect("fourth append");
        assert_eq!(fourth.prev_hash, third_hash);
    }

    #[tokio::test]
    async fn file_sink_retained_suffix_bootstraps_as_retained_set() {
        // max_size 1 rotates every append and max_files 2 retains only the
        // active file plus one rotated file. After three appends the genesis
        // record has aged out, so the oldest retained record carries a non-None
        // prev_hash. Local verification treats that as the retained-set
        // boundary; off-host shipping is the completeness guarantee.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 2);
        let chain = ChainState::unkeyed_dev_only();
        let mut third_hash = None;
        for event in ["first", "second", "third"] {
            let envelope = chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
            third_hash = Some(envelope.record_hash);
        }

        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("retained suffix bootstraps"),
            third_hash
        );
    }

    #[tokio::test]
    async fn file_sink_bootstrap_accepts_legacy_smaller_retained_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let legacy_sink = JsonlFileSink::with_rotation(&path, 1, 5);
        let chain = ChainState::unkeyed_dev_only();
        let mut last_hash = None;
        for index in 0..8 {
            let envelope = chain
                .append(&legacy_sink, json!({ "event": index }))
                .await
                .expect("append");
            last_hash = Some(envelope.record_hash);
        }

        let upgraded_sink = JsonlFileSink::with_rotation(&path, 1, 50);
        assert_eq!(
            upgraded_sink
                .tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("tail"),
            last_hash
        );
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&upgraded_sink)
            .await
            .expect("bootstrap");
        let next = bootstrapped
            .append(&upgraded_sink, json!({ "event": "after-upgrade" }))
            .await
            .expect("append after upgrade");
        assert_eq!(next.prev_hash, last_hash);
    }

    #[tokio::test]
    async fn file_sink_retained_suffix_detects_tampered_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 2);
        let chain = ChainState::unkeyed_dev_only();
        for event in ["first", "second", "third"] {
            chain
                .append(&sink, json!({ "event": event }))
                .await
                .expect("append");
        }

        let contents = fs::read_to_string(&path).expect("active audit file");
        fs::write(&path, contents.replace("\"third\"", "\"tampered\""))
            .expect("tamper active file");

        assert!(matches!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::RecordHashMismatch { line: 2 }
            ))
        ));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_accepts_truncated_oldest_rotated_file_as_retained_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // max_size 1 rotates on every append and max_files 50 retains
        // everything, so two appends leave the genesis record in
        // `audit.jsonl.1` and the second record live: a set complete from
        // genesis.
        let sink = JsonlFileSink::with_rotation(&path, 1, 50);
        let chain = ChainState::unkeyed_dev_only();
        let _genesis = chain
            .append(&sink, json!({ "event": "genesis" }))
            .await
            .expect("append genesis");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("append second");

        // Healthy set bootstraps cleanly.
        sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
            .await
            .expect("healthy tail");

        // Truncate the oldest rotated file, dropping the genesis record. The
        // first retained record now has a non-None prev_hash pointing at the
        // lost record; local verification treats that value as the retained-set
        // boundary instead of claiming completeness.
        let rotated = rotated_path(&path, 1);
        fs::write(&rotated, "").expect("truncate rotated file");

        assert_eq!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await
                .expect("retained tail"),
            Some(second.record_hash)
        );
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap retained set");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("append after retained set");
        assert_eq!(third.prev_hash, Some(second.record_hash));
    }

    #[test]
    fn verify_jsonl_lines_accepts_retained_suffix() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");
        let suffix = [second.to_jsonl().unwrap(), third.to_jsonl().unwrap()];

        let verification =
            verify_jsonl_lines_with_hasher(suffix.iter(), &AuditChainHasher::unkeyed_dev_only())
                .expect("suffix verifies as retained set");
        assert_eq!(verification.records, 2);
        assert_eq!(verification.start_prev_hash, Some(first.record_hash));
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[test]
    fn verify_chain_accepts_retained_suffix() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");

        let verification = verify_chain(
            &[second.clone(), third.clone()],
            &AuditChainHasher::unkeyed_dev_only(),
        )
        .expect("retained suffix verifies");

        assert_eq!(verification.records, 2);
        assert_eq!(verification.start_prev_hash, Some(first.record_hash));
        assert_eq!(verification.last_hash, Some(third.record_hash));
    }

    #[test]
    fn verify_chain_accepts_self_consistent_full_rewrite_without_offhost_evidence() {
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let rewritten_first =
            AuditEnvelope::new(json!({ "event": "fake-first" }), None).expect("fake first");
        let rewritten_second = AuditEnvelope::new(
            json!({ "event": "fake-second" }),
            Some(rewritten_first.record_hash),
        )
        .expect("fake second");

        let rewritten = [rewritten_first, rewritten_second];
        let verification = verify_chain(&rewritten, &AuditChainHasher::unkeyed_dev_only())
            .expect("self-consistent rewrite verifies locally");
        assert_eq!(verification.records, 2);
        assert_ne!(verification.last_hash, Some(second.record_hash));
    }

    #[test]
    fn verify_chain_accepts_trailing_truncation_without_offhost_evidence() {
        // Dropping the tail of a valid chain leaves a self-consistent prefix
        // with nothing to mark the removed records: truncating the newest
        // envelopes is not locally detectable. Off-host shipping is the
        // completeness guarantee.
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let _third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");

        let truncated = [first, second.clone()];
        let verification = verify_chain(&truncated, &AuditChainHasher::unkeyed_dev_only())
            .expect("truncated prefix verifies");
        assert_eq!(verification.records, 2);
        assert_eq!(verification.last_hash, Some(second.record_hash));
    }

    #[test]
    fn verify_chain_detects_interior_deletion() {
        // Removing an envelope from inside the retained set breaks the hash
        // link: the survivor after the gap still points at the deleted record's
        // hash, which no longer matches its predecessor.
        let first = AuditEnvelope::new(json!({ "event": "first" }), None).expect("first");
        let second = AuditEnvelope::new(json!({ "event": "second" }), Some(first.record_hash))
            .expect("second");
        let third = AuditEnvelope::new(json!({ "event": "third" }), Some(second.record_hash))
            .expect("third");

        let with_gap = [first, third];
        let err = verify_chain(&with_gap, &AuditChainHasher::unkeyed_dev_only())
            .expect_err("interior deletion is detected");
        assert!(matches!(
            err,
            ChainVerificationError::PrevHashMismatch { line: 2, .. }
        ));
    }

    #[tokio::test]
    async fn file_sink_bootstrap_accepts_max_files_one_retained_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation(&path, 1, 1);
        let chain = ChainState::unkeyed_dev_only();
        let first = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("first append");
        let second = chain
            .append(&sink, json!({ "event": "second" }))
            .await
            .expect("second append");

        assert_eq!(second.prev_hash, Some(first.record_hash));
        let bootstrapped = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("bootstrap");
        let third = bootstrapped
            .append(&sink, json!({ "event": "third" }))
            .await
            .expect("third append");
        assert_eq!(third.prev_hash, Some(second.record_hash));
    }

    #[test]
    fn audit_hasher_from_env_returns_err_when_unset() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_UNSET";
        env::remove_var(name);
        assert!(matches!(
            AuditKeyHasher::from_env(name),
            Err(AuditError::EnvVar { .. })
        ));
    }

    #[test]
    fn audit_hasher_requires_explicit_unkeyed_dev_mode() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hasher_from_env_uses_hmac_secret() {
        let name = "REGISTRY_PLATFORM_AUDIT_TEST_SECRET";
        env::set_var(name, "0123456789abcdef0123456789abcdef");
        let hasher = AuditKeyHasher::from_env(name).expect("hasher");
        env::remove_var(name);

        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
        assert_ne!(
            hashed,
            AuditKeyHasher::unkeyed_dev_only().hash("subject-123")
        );
    }

    #[tokio::test]
    async fn audit_profile_uses_one_secret_for_chain_and_identifier_hashing() {
        let name = "REGISTRY_PLATFORM_AUDIT_PROFILE_TEST_SECRET";
        env::set_var(name, "0123456789abcdef0123456789abcdef");
        let profile = AuditProfile::registry_notary_from_env(name).expect("profile");
        env::remove_var(name);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);

        let chain = profile
            .bootstrap_or_start_empty(&sink)
            .await
            .expect("chain bootstraps");
        chain
            .append(&sink, json!({ "event": "profiled" }))
            .await
            .expect("append");
        let contents = fs::read_to_string(&path).expect("audit file");

        assert!(verify_jsonl_lines_with_hasher(
            contents.lines(),
            &AuditChainHasher::unkeyed_dev_only()
        )
        .is_err());
        verify_jsonl_lines_with_hasher(contents.lines(), &profile.chain_hasher())
            .expect("profile chain verifies");
        assert!(profile
            .key_hasher()
            .hash("subject-123")
            .starts_with(KEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_profile_dev_mode_is_explicitly_unkeyed() {
        let profile = AuditProfile::unkeyed_dev_only();

        assert!(profile
            .key_hasher()
            .hash("subject-123")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_reference_hash_is_domain_class_and_scope_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let base = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_class = hasher
            .audit_reference_hash(
                "matching-attempt-v1",
                "purpose-a",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");
        let other_scope = hasher
            .audit_reference_hash(
                "matched-reference-v1",
                "purpose-b",
                r#"{"role":"target","handle":"abc"}"#,
            )
            .expect("reference hash");

        assert!(base.starts_with(UNKEYED_HASH_PREFIX));
        assert_ne!(base, hasher.hash(r#"{"role":"target","handle":"abc"}"#));
        assert_ne!(base, other_class);
        assert_ne!(base, other_scope);
    }

    #[test]
    fn audit_reference_hash_rejects_empty_class_or_input_but_allows_empty_scope() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        assert!(matches!(
            hasher.audit_reference_hash("", "scope", "canonical"),
            Err(AuditReferenceHashError::EmptyClass)
        ));
        assert!(matches!(
            hasher.audit_reference_hash("class", "scope", ""),
            Err(AuditReferenceHashError::EmptyCanonicalInput)
        ));
        assert!(hasher
            .audit_reference_hash("class", "", "canonical")
            .expect("empty scope is explicit")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn sensitive_value_hash_is_field_bound_and_reference_domain_separated() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let first = hasher.sensitive_value_hash("person_id", "IND-001");
        let second = hasher.sensitive_value_hash("person_id", "IND-001");
        let other_field = hasher.sensitive_value_hash("household_id", "IND-001");

        assert_eq!(first, second);
        assert_ne!(first, other_field);
        assert_ne!(first, hasher.hash("person_id\0IND-001"));
        assert!(hasher
            .sensitive_value_hash("empty", "")
            .starts_with(UNKEYED_HASH_PREFIX));
    }

    #[test]
    fn query_redactor_redacts_secrets_and_hashes_sensitive_fields() {
        let redactor =
            QueryRedactor::with_hasher(AuditKeyHasher::unkeyed_dev_only(), ["email", "person_id"]);
        let redacted = redactor
            .redact_query("email=jeremi%40example.test&token=secret&limit=10&person_id.gte=abc");

        assert_eq!(redacted["token"]["op"], "redacted");
        assert_eq!(redacted["limit"]["op"], "eq");
        assert_eq!(redacted["email"]["op"], "eq");
        assert!(redacted["email"]["value_hash"]
            .as_str()
            .expect("hash")
            .starts_with(UNKEYED_HASH_PREFIX));
        assert_eq!(redacted["person_id.gte"]["op"], "gte");
        assert!(!redacted.to_string().contains("jeremi"));
        assert!(!redacted.to_string().contains("secret"));
        assert!(!redacted.to_string().contains("abc"));
    }

    #[test]
    fn query_redactor_surfaces_invalid_utf8() {
        let redactor = QueryRedactor::new(["email"]);

        let err = redactor
            .try_redact_query("email=%FF")
            .expect_err("invalid UTF-8 is not silently lossy-decoded");
        assert_eq!(err, redact::QueryRedactionError::InvalidUtf8);

        let redacted = redactor.redact_query("email=%FF");
        assert_eq!(redacted["_error"]["code"], "invalid_query_encoding");
    }

    #[tokio::test]
    async fn file_sink_rejects_tampered_tail_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();
        let mut envelope = chain
            .append(&sink, json!({ "event": "first" }))
            .await
            .expect("append");
        envelope.record["event"] = json!("changed");
        fs::write(&path, envelope.to_jsonl().expect("jsonl")).expect("rewrite");

        assert!(matches!(
            sink.tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
                .await,
            Err(AuditError::ChainVerification(
                ChainVerificationError::RecordHashMismatch { line: 1 }
            ))
        ));
    }

    #[test]
    fn audit_hash_secret_round_trips_and_clones_share_bytes() {
        // AUDIT-02: zeroize-on-drop newtype must not change observable behavior.
        let raw = b"this-is-a-32-byte-chain-secret-ok".to_vec();
        let secret = AuditHashSecret::new(raw.clone()).expect("secret builds");
        assert_eq!(secret.as_bytes(), raw.as_slice());

        let cloned = secret.clone();
        // Clones share the same underlying Arc<SecretBytes> and observe equal bytes.
        assert_eq!(cloned.as_bytes(), secret.as_bytes());

        // Dropping one clone must not disturb the surviving clone's key material.
        drop(secret);
        assert_eq!(cloned.as_bytes(), raw.as_slice());

        // The hasher built from the secret still produces stable keyed output.
        let hasher = AuditKeyHasher::Keyed(cloned);
        let hashed = hasher.hash("subject-123");
        assert!(hashed.starts_with(KEYED_HASH_PREFIX));
    }

    #[test]
    fn audit_hash_secret_rejects_weak_secret() {
        // AUDIT-02: short keys still fail closed after the newtype change.
        assert!(matches!(
            AuditHashSecret::new(b"too-short".to_vec()),
            Err(AuditError::WeakSecret { .. })
        ));
    }

    #[test]
    fn production_profile_derives_separated_chain_and_identifier_keys() {
        // AUDIT-03: the chain key and identifier key must be independent derived
        // sub-keys of the master env secret, and neither may equal the master.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_TEST_SECRET";
        let master = "0123456789abcdef0123456789abcdef-master";
        env::set_var(name, master);

        let chain_key = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain key");
        let ident_key =
            derive_subkey_from_env(name, IDENTIFIER_KEY_DERIVATION_INFO).expect("identifier key");
        env::remove_var(name);

        // Sub-keys differ from each other.
        assert_ne!(chain_key.as_bytes(), ident_key.as_bytes());
        // Sub-keys differ from the raw master env material.
        assert_ne!(chain_key.as_bytes(), master.as_bytes());
        assert_ne!(ident_key.as_bytes(), master.as_bytes());
        // HKDF-Expand over SHA-256 yields a single 32-byte block.
        assert_eq!(chain_key.as_bytes().len(), 32);
        assert_eq!(ident_key.as_bytes().len(), 32);
    }

    #[test]
    fn production_profile_key_derivation_is_deterministic_and_stable() {
        // AUDIT-03: the same env secret must yield the same derived sub-keys, so
        // a chain stays verifiable across process restarts.
        let name = "REGISTRY_PLATFORM_AUDIT_KDF_STABLE_SECRET";
        let master = "stable-master-secret-0123456789abcdef";
        env::set_var(name, master);

        let chain_a = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain a");
        let chain_b = derive_subkey_from_env(name, CHAIN_KEY_DERIVATION_INFO).expect("chain b");
        env::remove_var(name);

        assert_eq!(chain_a.as_bytes(), chain_b.as_bytes());

        // Known-answer vector pins the HKDF-Expand-only construction.
        let expected = hkdf_expand_sha256(master.as_bytes(), CHAIN_KEY_DERIVATION_INFO);
        assert_eq!(chain_a.as_bytes(), expected.as_slice());
    }

    #[tokio::test]
    async fn audit_profile_chain_and_identifier_keys_are_domain_separated() {
        // AUDIT-03: the two profiles must agree on the derived chain key while
        // the identifier key stays distinct.
        let name = "REGISTRY_PLATFORM_AUDIT_PROFILE_KDF_SECRET";
        env::set_var(name, "profile-master-secret-0123456789abcdef");
        let profile = AuditProfile::production_from_env(name).expect("profile");
        let chain_profile = AuditChainProfile::production_from_env(name).expect("chain profile");
        env::remove_var(name);

        // Both profiles derive the same chain key, so a chain bootstrapped via
        // either verifies under the other's chain hasher.
        let first = AuditEnvelope::new_with_hasher(
            json!({ "event": "first" }),
            None,
            &profile.chain_hasher(),
        )
        .expect("first");
        verify_chain(std::slice::from_ref(&first), &chain_profile.hasher())
            .expect("cross-profile chain agrees");

        // The identifier key is keyed but domain-separated from the chain key.
        let identifier_hash = profile.key_hasher().hash("subject-123");
        assert!(identifier_hash.starts_with(KEYED_HASH_PREFIX));
        let unkeyed = AuditKeyHasher::unkeyed_dev_only().hash("subject-123");
        assert_ne!(identifier_hash, unkeyed);
    }

    #[test]
    fn query_redactor_redacts_oauth_and_credential_param_names() {
        // AUDIT-05: extended denylist covers OAuth/OIDC and credential params.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted =
            redactor.redact_query("access_token=x&refresh_token=y&client_secret=z&bearer=b");

        assert_eq!(redacted["access_token"]["op"], "redacted");
        assert_eq!(redacted["refresh_token"]["op"], "redacted");
        assert_eq!(redacted["client_secret"]["op"], "redacted");
        assert_eq!(redacted["bearer"]["op"], "redacted");

        let serialized = redacted.to_string();
        assert!(!serialized.contains("\"x\""));
        assert!(!serialized.contains("\"y\""));
        assert!(!serialized.contains("\"z\""));
        assert!(!serialized.contains("\"b\""));
    }

    #[test]
    fn query_redactor_redacts_remaining_new_credential_param_names() {
        // AUDIT-05: exercise the rest of the added names for coverage.
        let redactor = QueryRedactor::new(Vec::<String>::new());
        let redacted = redactor.redact_query(
            "id_token=a&client_assertion=b&assertion=c&code=d&private_key=e&credential=f&credentials=g&passwd=h&pwd=i&session_token=j",
        );

        for name in [
            "id_token",
            "client_assertion",
            "assertion",
            "code",
            "private_key",
            "credential",
            "credentials",
            "passwd",
            "pwd",
            "session_token",
        ] {
            assert_eq!(redacted[name]["op"], "redacted", "{name} must be redacted");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn single_writer_concurrent_hammer_then_full_chain_verifies() {
        // #211 regression: one single-writer sink driven by many concurrent
        // audited appends must produce a chain that verifies end to end (no
        // fork), because `ChainState::append` serializes tail advancement.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::with_rotation_single_writer(&path, 0, 1)
            .expect("single-writer sink acquires the lock");
        let secret =
            AuditHashSecret::new(b"this-is-a-32-byte-chain-secret-ok".to_vec()).expect("secret");
        let hasher = AuditChainHasher::keyed(secret);
        let chain = Arc::new(ChainState::new(hasher.clone()));

        let mut set = tokio::task::JoinSet::new();
        for index in 0..200 {
            let chain = Arc::clone(&chain);
            let sink = sink.clone();
            set.spawn(async move {
                chain
                    .append(&sink, json!({ "event": "rows", "i": index }))
                    .await
                    .expect("concurrent append succeeds");
            });
        }
        while let Some(joined) = set.join_next().await {
            joined.expect("append task joins");
        }

        let contents = fs::read_to_string(&path).expect("audit file");
        let verification =
            verify_jsonl_lines_with_hasher(contents.lines(), &hasher).expect("chain verifies");
        assert_eq!(verification.records, 200);
    }

    #[tokio::test]
    async fn second_writer_is_rejected_by_flock() {
        // #211: a second single-writer sink on the same path must fail loudly at
        // construction instead of silently forking the chain. `flock` is scoped
        // to the open file description on Unix, so two opens contend even within
        // one process, making this a faithful stand-in for two containers.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let _first = JsonlFileSink::with_rotation_single_writer(&path, 0, 1)
            .expect("first writer takes the lock");
        let second = JsonlFileSink::with_rotation_single_writer(&path, 0, 1);
        assert!(
            matches!(second, Err(AuditError::SinkLocked { .. })),
            "second writer must be rejected, got {second:?}"
        );
    }

    #[tokio::test]
    async fn sentinel_lock_is_released_when_sink_dropped() {
        // The lock is process-lifetime, not permanent: once the holder drops
        // (clean shutdown), a fresh writer can acquire it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let first = JsonlFileSink::with_rotation_single_writer(&path, 0, 1).expect("first locks");
        drop(first);
        JsonlFileSink::with_rotation_single_writer(&path, 0, 1)
            .expect("lock is re-acquirable after the holder drops");
    }

    #[tokio::test]
    async fn tail_self_check_detects_foreign_append() {
        // #211 write-time detection: two `ChainState`s over one file reproduce
        // the exact fork mechanism (both chain from the same tail). The second
        // writer's append advances the on-disk tail; the first writer's next
        // append then diverges and must be refused at write time rather than
        // producing the fork that bricks the relay on the next restart.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);

        let writer_a = ChainState::unkeyed_dev_only();
        writer_a
            .append(&sink, json!({ "event": "a1" }))
            .await
            .expect("a1 append");

        let writer_b = ChainState::bootstrap_unkeyed_dev_only(&sink)
            .await
            .expect("foreign writer bootstraps from the same tail");
        writer_b
            .append(&sink, json!({ "event": "b1" }))
            .await
            .expect("b1 append advances the on-disk tail");

        let err = writer_a
            .append(&sink, json!({ "event": "a2" }))
            .await
            .expect_err("A's stale predecessor must be caught");
        assert!(
            matches!(err, AuditError::ChainForkDetected { .. }),
            "expected ChainForkDetected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn recovery_is_a_no_op_on_a_consistent_chain() {
        // #196: a healthy chain must not be quarantined or rewritten.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        let chain = ChainState::unkeyed_dev_only();
        chain
            .append(&sink, json!({ "event": "one" }))
            .await
            .expect("append one");
        chain
            .append(&sink, json!({ "event": "two" }))
            .await
            .expect("append two");
        let before = fs::read_to_string(&path).expect("audit file");

        let outcome = quarantine_and_recover_chain(
            &path,
            50,
            &AuditChainHasher::unkeyed_dev_only(),
            "unit no-op",
            None,
            999,
        )
        .expect("recovery runs");

        assert!(outcome.already_consistent);
        assert_eq!(outcome.first_bad_line, None);
        assert_eq!(outcome.quarantine_suffix, None);
        assert_eq!(fs::read_to_string(&path).expect("audit file"), before);
        assert!(
            !dir.path().join("audit.jsonl.corrupt-999").exists(),
            "a consistent chain must not be quarantined"
        );
    }

    #[tokio::test]
    async fn recovery_quarantines_a_fork_and_starts_a_break_segment() {
        // #196: build a forked file by hand (the write-time self-check now
        // refuses to create one), then recover it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let genesis = AuditEnvelope::new(json!({ "event": "genesis" }), None).expect("genesis");
        let good = AuditEnvelope::new(json!({ "event": "good" }), Some(genesis.record_hash))
            .expect("good");
        // Fork: `forked` shares `good`'s predecessor instead of chaining onto it.
        let forked = AuditEnvelope::new(json!({ "event": "forked" }), Some(genesis.record_hash))
            .expect("forked");
        let original = format!(
            "{}{}{}",
            genesis.to_jsonl().expect("genesis jsonl"),
            good.to_jsonl().expect("good jsonl"),
            forked.to_jsonl().expect("forked jsonl"),
        );
        fs::write(&path, &original).expect("write forked chain");

        let outcome = quarantine_and_recover_chain(
            &path,
            1,
            &AuditChainHasher::unkeyed_dev_only(),
            "fork recovery",
            Some("operator-1"),
            1234,
        )
        .expect("recovery runs");

        assert!(!outcome.already_consistent);
        assert_eq!(outcome.first_bad_line, Some(3));
        assert_eq!(outcome.last_good_hash, Some(good.record_hash));
        assert_eq!(outcome.records_before_break, 2);
        assert_eq!(outcome.quarantine_suffix.as_deref(), Some("corrupt-1234"));

        // The corrupt set is retained verbatim.
        let archived = fs::read_to_string(dir.path().join("audit.jsonl.corrupt-1234"))
            .expect("archive exists");
        assert_eq!(archived, original);

        // The fresh active file holds exactly the break event, chained onto the
        // last good tail.
        let active = fs::read_to_string(&path).expect("active file");
        let lines: Vec<&str> = active.lines().collect();
        assert_eq!(lines.len(), 1);
        let break_envelope: AuditEnvelope =
            serde_json::from_str(lines[0]).expect("break envelope parses");
        assert_eq!(break_envelope.prev_hash, Some(good.record_hash));
        assert_eq!(
            break_envelope.record_hash,
            outcome.break_event_hash.unwrap()
        );
        let break_record: ChainBreakRecord =
            serde_json::from_value(break_envelope.record.clone()).expect("break record parses");
        assert_eq!(break_record.event, CHAIN_BREAK_EVENT);
        assert_eq!(break_record.first_bad_line, 3);
        assert_eq!(break_record.operator.as_deref(), Some("operator-1"));

        // The recovered segment verifies as a retained set whose first
        // predecessor is the last good hash. No local completeness anchor is
        // written; off-host shipping is the completeness guarantee.
        let verification = verify_chain(&[break_envelope], &AuditChainHasher::unkeyed_dev_only())
            .expect("recovered segment verifies as retained set");
        assert_eq!(verification.start_prev_hash, Some(good.record_hash));
        assert!(!dir.path().join("audit.jsonl.anchor.json").exists());
    }

    #[tokio::test]
    async fn recovery_quarantines_a_legacy_completeness_anchor_sidecar() {
        // Upgrade path: a release from before the anchor sidecar was removed
        // can leave `<path>.anchor.json` on disk. Recovery must move it aside
        // with the data files so it cannot keep describing the now-quarantined
        // chain as current.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let genesis = AuditEnvelope::new(json!({ "event": "genesis" }), None).expect("genesis");
        let good = AuditEnvelope::new(json!({ "event": "good" }), Some(genesis.record_hash))
            .expect("good");
        let forked = AuditEnvelope::new(json!({ "event": "forked" }), Some(genesis.record_hash))
            .expect("forked");
        let original = format!(
            "{}{}{}",
            genesis.to_jsonl().expect("genesis jsonl"),
            good.to_jsonl().expect("good jsonl"),
            forked.to_jsonl().expect("forked jsonl"),
        );
        fs::write(&path, &original).expect("write forked chain");

        let sidecar = dir.path().join("audit.jsonl.anchor.json");
        let sidecar_contents = r#"{"schema":"registry.audit.anchor.v1"}"#;
        fs::write(&sidecar, sidecar_contents).expect("write legacy sidecar");

        let outcome = quarantine_and_recover_chain(
            &path,
            1,
            &AuditChainHasher::unkeyed_dev_only(),
            "fork recovery",
            Some("operator-1"),
            1234,
        )
        .expect("recovery runs");

        assert!(!outcome.already_consistent);

        // The legacy sidecar is moved aside under the same suffix as the data
        // files and no longer sits where the active chain's anchor would be.
        assert!(
            !sidecar.exists(),
            "the legacy anchor sidecar must not remain active after quarantine"
        );
        let quarantined_sidecar = dir.path().join("audit.jsonl.anchor.json.corrupt-1234");
        assert_eq!(
            fs::read_to_string(&quarantined_sidecar).expect("quarantined sidecar exists"),
            sidecar_contents
        );
    }

    #[tokio::test]
    async fn recovery_quarantines_a_torn_trailing_line() {
        // #196: an unclean container stop can truncate the final write
        // mid-line. Recovery must treat the torn line as the start of the
        // break instead of aborting with `InvalidJson` before it ever gets to
        // scan the chain.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let genesis = AuditEnvelope::new(json!({ "event": "genesis" }), None).expect("genesis");
        let good = AuditEnvelope::new(json!({ "event": "good" }), Some(genesis.record_hash))
            .expect("good");
        let torn_line = r#"{"envelope_id":"zz"#;
        let original = format!(
            "{}{}{}",
            genesis.to_jsonl().expect("genesis jsonl"),
            good.to_jsonl().expect("good jsonl"),
            torn_line,
        );
        fs::write(&path, &original).expect("write torn chain");

        let outcome = quarantine_and_recover_chain(
            &path,
            1,
            &AuditChainHasher::unkeyed_dev_only(),
            "torn line recovery",
            Some("operator-1"),
            5678,
        )
        .expect("recovery runs despite the torn trailing line");

        assert!(!outcome.already_consistent);
        assert_eq!(outcome.first_bad_line, Some(3));
        assert_eq!(outcome.last_good_hash, Some(good.record_hash));
        assert_eq!(outcome.records_before_break, 2);
        assert_eq!(outcome.quarantine_suffix.as_deref(), Some("corrupt-5678"));

        // The corrupt set, torn line included verbatim, is retained.
        let archived = fs::read_to_string(dir.path().join("audit.jsonl.corrupt-5678"))
            .expect("archive exists");
        assert_eq!(archived, original);

        // The fresh active file holds exactly the break event, chained onto
        // the last good tail.
        let active = fs::read_to_string(&path).expect("active file");
        let lines: Vec<&str> = active.lines().collect();
        assert_eq!(lines.len(), 1);
        let break_envelope: AuditEnvelope =
            serde_json::from_str(lines[0]).expect("break envelope parses");
        assert_eq!(break_envelope.prev_hash, Some(good.record_hash));
        assert_eq!(
            break_envelope.record_hash,
            outcome.break_event_hash.unwrap()
        );
    }

    #[tokio::test]
    async fn recovery_refuses_while_the_single_writer_lock_is_held() {
        // #196: recovery is offline-only; a running server holding the lock must
        // block it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let _server =
            JsonlFileSink::with_rotation_single_writer(&path, 0, 1).expect("server holds the lock");
        let result = quarantine_and_recover_chain(
            &path,
            1,
            &AuditChainHasher::unkeyed_dev_only(),
            "should refuse",
            None,
            1,
        );
        assert!(
            matches!(result, Err(AuditError::SinkLocked { .. })),
            "recovery must refuse while the server holds the lock, got {result:?}"
        );
    }

    #[derive(Default)]
    struct MemorySink {
        envelopes: tokio::sync::Mutex<Vec<AuditEnvelope>>,
    }

    #[async_trait]
    impl AuditSink for MemorySink {
        async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
            self.envelopes.lock().await.push(envelope.clone());
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(self
                .envelopes
                .lock()
                .await
                .last()
                .map(|envelope| envelope.record_hash))
        }

        async fn tail_hash_with_hasher(
            &self,
            hasher: &AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            let _ = hasher;
            Ok(self
                .envelopes
                .lock()
                .await
                .last()
                .map(|envelope| envelope.record_hash))
        }
    }
}
