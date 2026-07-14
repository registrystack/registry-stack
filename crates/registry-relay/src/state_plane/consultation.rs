// SPDX-License-Identifier: Apache-2.0
//! Atomic consultation attempt, dispatch, completion, and takeover recovery.

use std::time::Duration;

#[cfg(test)]
use registry_platform_audit::pseudonym_keyring::{AuditPseudonymCommitment, AuditPseudonymKeyId};
use registry_platform_audit::{
    AuditEnvelope, DurableAuditOperationId, DurableAuditPhase, DurableAuditStoredIdentity,
    DurableAuditStreamKind, DurableAuditWrite,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::Instant;
use tokio_postgres::{Error as PostgresError, Row};
use zeroize::Zeroizing;

use crate::consultation::audit::{
    PreparedAtomicConsultationStateView, TerminalConsultationStateView,
};
#[cfg(test)]
use crate::consultation::audit::{TerminalCompletionTestHook, TerminalCompletionTestPoint};
use crate::consultation::commitments::BatchChildReplayBinding;
use crate::consultation::ConsultationId;

use super::audit::PostgresDurableAuditStatePlane;
use super::fence::{
    AuditedConsultationDispatch, ConsultationDispatchPermit, DispatchOperationId,
    DispatchPermitState, FencedConsultationAttemptAuthority, TakeoverCompletionRecoveryAuthority,
};
use super::migration::validate_runtime_pseudonym_capability_v1;
use super::pseudonym_keyring::ActiveAuditPseudonymWriteEpoch;

const ATTEMPT_SNAPSHOT_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_attempt_intent_snapshot_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18
)
"#;
const ATTEMPT_CAS_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_attempt_intent_cas_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
)
"#;
const NORMAL_COMPLETION_SNAPSHOT_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_snapshot_normal_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
"#;
const RECOVERY_COMPLETION_SNAPSHOT_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_snapshot_recovery_v1(
    $1, $2, $3, $4, $5, $6
)
"#;
const NORMAL_COMPLETION_CAS_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_cas_normal_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20
)
"#;
const BATCH_NORMAL_COMPLETION_CAS_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_cas_normal_batch_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22, $23
)
"#;
const UNFINISHED_COMPLETION_CAS_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_cas_unfinished_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20
)
"#;
const RECOVERY_COMPLETION_CAS_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_completion_cas_recovery_v1(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
)
"#;
const BATCH_CHILD_RESERVE_SQL: &str = r#"
SELECT * FROM relay_state_api.consultation_batch_child_reserve_v1($1, $2, $3)
"#;
const BATCH_CHILD_RELEASE_SQL: &str = r#"
SELECT relay_state_api.consultation_batch_child_release_v1($1, $2, $3) AS released
"#;

const MAX_CAS_ATTEMPTS: usize = 8;
const MAX_ELAPSED: Duration = Duration::from_secs(5);
#[cfg(test)]
const MAX_COMPLETION_SEED_CANONICAL_BYTES_V1: usize = 256 * 1024;
#[cfg(test)]
const MAX_COMMITMENT_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConsultationPersistenceError {
    #[error("consultation persistence input is invalid")]
    InvalidInput,
    #[error("consultation persistence conflicts with durable state")]
    Conflict,
    #[error("consultation serving-fence ownership is unavailable")]
    OwnershipLost,
    #[error("consultation completion state no longer permits this operation")]
    StateConflict,
    #[error("consultation persistence protocol has drifted")]
    ProtocolDrift,
    #[error("consultation persistence is unavailable")]
    Unavailable,
}

pub(crate) struct BatchChildReplayContext {
    child_key: [u8; 32],
    binding_digest: [u8; 32],
    operation_id: Box<str>,
}

impl std::fmt::Debug for BatchChildReplayContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BatchChildReplayContext([REDACTED])")
    }
}

pub(crate) struct BatchTerminalReplay {
    operation_id: Box<str>,
    value: Zeroizing<String>,
}

impl std::fmt::Debug for BatchTerminalReplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BatchTerminalReplay([REDACTED])")
    }
}

pub(crate) enum BatchChildReplayReservation {
    Reserved(BatchChildReplayContext),
    Replay(BatchTerminalReplay),
    InProgress,
    Conflict,
}

impl BatchChildReplayContext {
    pub(crate) fn from_binding(
        binding: BatchChildReplayBinding,
        operation_id: DurableAuditOperationId,
    ) -> Self {
        Self {
            child_key: *binding.child_key(),
            binding_digest: *binding.binding_digest(),
            operation_id: operation_id.as_str().into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        child_key: [u8; 32],
        binding_digest: [u8; 32],
        operation_id: &DurableAuditOperationId,
    ) -> Self {
        Self {
            child_key,
            binding_digest,
            operation_id: operation_id.as_str().into(),
        }
    }
}

impl BatchTerminalReplay {
    pub(crate) fn into_parts(self) -> (Box<str>, Zeroizing<String>) {
        (self.operation_id, self.value)
    }
}

/// Immutable, canonical, non-pseudonym context shared by every completion.
#[cfg(test)]
pub(crate) struct ConsultationCompletionSeed {
    canonical: String,
    digest: [u8; 32],
    timeout_ms: u32,
}

#[cfg(test)]
impl ConsultationCompletionSeed {
    /// Canonicalize the compiler-owned, secret-free completion seed before it
    /// crosses into the atomic state-plane protocol. PostgreSQL performs the
    /// authoritative exact-shape validation in the attempt CAS.
    fn from_safe_value(value: Value) -> Result<Self, ConsultationPersistenceError> {
        let timeout_ms = value
            .get("bounds")
            .and_then(Value::as_object)
            .and_then(|bounds| bounds.get("timeout_ms"))
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=60_000).contains(value))
            .ok_or(ConsultationPersistenceError::InvalidInput)?;
        let (canonical, digest) = canonical_binding(value)?;
        if canonical.len() > MAX_COMPLETION_SEED_CANONICAL_BYTES_V1 {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        Ok(Self {
            canonical,
            digest,
            timeout_ms,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_value_for_test(value: Value) -> Result<Self, ConsultationPersistenceError> {
        Self::from_safe_value(value)
    }
}

/// Exact pseudonym values already committed by the attempt audit.
#[cfg(test)]
pub(crate) struct AttemptPseudonymBundle {
    key_id: String,
    canonical: String,
    digest: [u8; 32],
}

#[cfg(test)]
impl AttemptPseudonymBundle {
    /// Bind the exact four typed consultation commitments to the authoritative
    /// key epoch used for the attempt audit. The platform types have already
    /// enforced the closed key-id and `hmac-sha256:<lowercase hex>` grammars.
    fn from_commitments(
        key_id: &AuditPseudonymKeyId,
        subject_handle: &AuditPseudonymCommitment,
        input_commitment: &AuditPseudonymCommitment,
        predicate_commitment: &AuditPseudonymCommitment,
        consent_evidence_commitment: Option<&AuditPseudonymCommitment>,
    ) -> Result<Self, ConsultationPersistenceError> {
        let (canonical, digest) = canonical_binding(json!({
            "commitment_key_id": key_id.as_str(),
            "subject_handle": subject_handle.as_str(),
            "input_commitment": input_commitment.as_str(),
            "predicate_commitment": predicate_commitment.as_str(),
            "consent_evidence_commitment": consent_evidence_commitment
                .map(AuditPseudonymCommitment::as_str),
        }))?;
        Ok(Self {
            key_id: key_id.as_str().to_owned(),
            canonical,
            digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        key_id: &str,
        subject_handle: &str,
        input_commitment: &str,
        predicate_commitment: &str,
        consent_evidence_commitment: Option<&str>,
    ) -> Result<Self, ConsultationPersistenceError> {
        if !valid_key_id(key_id)
            || !valid_commitment(subject_handle)
            || !valid_commitment(input_commitment)
            || !valid_commitment(predicate_commitment)
            || consent_evidence_commitment.is_some_and(|value| !valid_commitment(value))
        {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        let (canonical, digest) = canonical_binding(json!({
            "commitment_key_id": key_id,
            "subject_handle": subject_handle,
            "input_commitment": input_commitment,
            "predicate_commitment": predicate_commitment,
            "consent_evidence_commitment": consent_evidence_commitment,
        }))?;
        Ok(Self {
            key_id: key_id.to_owned(),
            canonical,
            digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsultationCompletionOutcome {
    KnownComplete,
    NotStarted,
    OutcomeUnknown,
}

impl ConsultationCompletionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::KnownComplete => "known_complete",
            Self::NotStarted => "not_started",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicConsultationOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

impl PublicConsultationOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no_match",
            Self::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownFailureClass {
    CredentialUnavailable,
    SourceUnavailable,
    ResponseContractViolation,
    SubjectMismatch,
    CardinalityViolation,
}

impl KnownFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "credential_unavailable",
            Self::SourceUnavailable => "source_unavailable",
            Self::ResponseContractViolation => "response_contract_violation",
            Self::SubjectMismatch => "subject_mismatch",
            Self::CardinalityViolation => "cardinality_violation",
        }
    }
}

enum ValidatedAcquisitionProvenance {
    Live,
    MaterializedSnapshot {
        generation: String,
        published_at_unix_ms: i64,
    },
}

struct ValidatedPublicProvenance {
    relay_acquired_at_unix_ms: i64,
    source_observed_at_unix_ms: Option<i64>,
    source_revision: Option<String>,
    acquisition: ValidatedAcquisitionProvenance,
}

enum KnownExecutionResult {
    Public {
        outcome: PublicConsultationOutcome,
        provenance: ValidatedPublicProvenance,
    },
    Failure(KnownFailureClass),
}

/// Executor-issued facts accepted by normal known completion. Production has
/// no raw constructor: only the validated backend integration may mint it.
pub(crate) struct KnownConsultationCompletionFacts {
    result: KnownExecutionResult,
}

impl KnownConsultationCompletionFacts {
    /// Mint the only public-success provenance supported by the live v1
    /// executor. Source-observed and revision facts are deliberately absent.
    pub(crate) fn public_for_live(
        outcome: PublicConsultationOutcome,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationPersistenceError> {
        if !valid_public_unix_ms(relay_acquired_at_unix_ms) {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        Ok(Self {
            result: KnownExecutionResult::Public {
                outcome,
                provenance: ValidatedPublicProvenance {
                    relay_acquired_at_unix_ms,
                    source_observed_at_unix_ms: None,
                    source_revision: None,
                    acquisition: ValidatedAcquisitionProvenance::Live,
                },
            },
        })
    }

    /// Mint a value-free known execution failure for atomic completion.
    pub(crate) const fn failure(failure: KnownFailureClass) -> Self {
        Self {
            result: KnownExecutionResult::Failure(failure),
        }
    }

    /// Mint public-success provenance for one exact immutable materialized
    /// snapshot. The restricted content digest remains private to publication
    /// state and is deliberately absent from consultation completion facts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn public_for_snapshot(
        outcome: PublicConsultationOutcome,
        relay_acquired_at_unix_ms: i64,
        source_observed_at_unix_ms: Option<i64>,
        source_revision: Option<&str>,
        snapshot_generation: crate::consultation::SnapshotGenerationId,
        snapshot_published_at_unix_ms: i64,
    ) -> Result<Self, ConsultationPersistenceError> {
        if !valid_public_unix_ms(relay_acquired_at_unix_ms)
            || !valid_public_unix_ms(snapshot_published_at_unix_ms)
            || snapshot_published_at_unix_ms > relay_acquired_at_unix_ms
            || source_observed_at_unix_ms.is_some_and(|value| {
                !valid_public_unix_ms(value) || value > snapshot_published_at_unix_ms
            })
            || source_revision.is_some_and(|value| value.is_empty() || value.len() > 512)
        {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        Ok(Self {
            result: KnownExecutionResult::Public {
                outcome,
                provenance: ValidatedPublicProvenance {
                    relay_acquired_at_unix_ms,
                    source_observed_at_unix_ms,
                    source_revision: source_revision.map(ToOwned::to_owned),
                    acquisition: ValidatedAcquisitionProvenance::MaterializedSnapshot {
                        generation: snapshot_generation.to_canonical_string(),
                        published_at_unix_ms: snapshot_published_at_unix_ms,
                    },
                },
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn public_for_live_test(
        outcome: PublicConsultationOutcome,
        relay_acquired_at_unix_ms: i64,
        source_observed_at_unix_ms: Option<i64>,
        source_revision: Option<&str>,
    ) -> Result<Self, ConsultationPersistenceError> {
        if source_observed_at_unix_ms.is_none() && source_revision.is_none() {
            return Self::public_for_live(outcome, relay_acquired_at_unix_ms);
        }
        Self::public_for_test(
            outcome,
            relay_acquired_at_unix_ms,
            source_observed_at_unix_ms,
            source_revision,
            ValidatedAcquisitionProvenance::Live,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn public_for_snapshot_test(
        outcome: PublicConsultationOutcome,
        relay_acquired_at_unix_ms: i64,
        source_observed_at_unix_ms: Option<i64>,
        source_revision: Option<&str>,
        snapshot_generation: &str,
        snapshot_published_at_unix_ms: i64,
    ) -> Result<Self, ConsultationPersistenceError> {
        Self::public_for_snapshot(
            outcome,
            relay_acquired_at_unix_ms,
            source_observed_at_unix_ms,
            source_revision,
            crate::consultation::SnapshotGenerationId::try_from(snapshot_generation)
                .map_err(|_| ConsultationPersistenceError::InvalidInput)?,
            snapshot_published_at_unix_ms,
        )
    }

    #[cfg(test)]
    fn public_for_test(
        outcome: PublicConsultationOutcome,
        relay_acquired_at_unix_ms: i64,
        source_observed_at_unix_ms: Option<i64>,
        source_revision: Option<&str>,
        acquisition: ValidatedAcquisitionProvenance,
    ) -> Result<Self, ConsultationPersistenceError> {
        if !valid_public_unix_ms(relay_acquired_at_unix_ms)
            || source_observed_at_unix_ms.is_some()
            || source_revision.is_some()
        {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        Ok(Self {
            result: KnownExecutionResult::Public {
                outcome,
                provenance: ValidatedPublicProvenance {
                    relay_acquired_at_unix_ms,
                    source_observed_at_unix_ms,
                    source_revision: source_revision.map(ToOwned::to_owned),
                    acquisition,
                },
            },
        })
    }

    #[cfg(test)]
    pub(crate) const fn failure_for_test(failure: KnownFailureClass) -> Self {
        Self::failure(failure)
    }

    fn payload_values(&self) -> (Value, Value) {
        match &self.result {
            KnownExecutionResult::Public {
                outcome,
                provenance,
            } => {
                let (snapshot_generation, snapshot_published_at_unix_ms) =
                    match &provenance.acquisition {
                        ValidatedAcquisitionProvenance::Live => (None, None),
                        ValidatedAcquisitionProvenance::MaterializedSnapshot {
                            generation,
                            published_at_unix_ms,
                        } => (Some(generation.as_str()), Some(*published_at_unix_ms)),
                    };
                (
                    json!({"class": "public_success", "outcome": outcome.as_str()}),
                    json!({
                        "relay_acquired_at_unix_ms": provenance.relay_acquired_at_unix_ms,
                        "source_observed_at_unix_ms": provenance.source_observed_at_unix_ms,
                        "source_revision": provenance.source_revision,
                        "snapshot_generation": snapshot_generation,
                        "snapshot_published_at_unix_ms": snapshot_published_at_unix_ms,
                    }),
                )
            }
            KnownExecutionResult::Failure(failure) => (
                json!({"class": "known_failure", "failure_class": failure.as_str()}),
                Value::Null,
            ),
        }
    }

    pub(crate) const fn is_public_success(&self) -> bool {
        matches!(&self.result, KnownExecutionResult::Public { .. })
    }
}

fn valid_public_unix_ms(value: i64) -> bool {
    (0..=9_007_199_254_740_991).contains(&value)
}

/// Response-publication authority exists only after acknowledged or proven
/// identical normal completion.
#[must_use = "a response may be published only while this grant is owned"]
pub(crate) struct ConsultationPublicationGrant {
    stored_identity: DurableAuditStoredIdentity,
}

pub(crate) struct ConsultationCompletionReceipt {
    stored_identity: DurableAuditStoredIdentity,
    outcome: ConsultationCompletionOutcome,
}

impl ConsultationCompletionReceipt {
    pub(crate) fn stored_identity(&self) -> &DurableAuditStoredIdentity {
        &self.stored_identity
    }

    pub(crate) const fn outcome(&self) -> ConsultationCompletionOutcome {
        self.outcome
    }
}

pub(crate) enum KnownCompletionDisposition {
    Published(ConsultationPublicationGrant),
    FinalizedFailure(ConsultationCompletionReceipt),
}

impl ConsultationPublicationGrant {
    pub(crate) fn stored_identity(&self) -> &DurableAuditStoredIdentity {
        &self.stored_identity
    }
}

pub(crate) struct RecoveredConsultationCompletion {
    stored_identity: DurableAuditStoredIdentity,
    outcome: ConsultationCompletionOutcome,
}

impl RecoveredConsultationCompletion {
    pub(crate) fn outcome(&self) -> ConsultationCompletionOutcome {
        self.outcome
    }

    pub(crate) fn stored_identity(&self) -> &DurableAuditStoredIdentity {
        &self.stored_identity
    }
}

struct CompletionSnapshot {
    outcome: String,
    attempt_envelope_id: String,
    attempt_record_hash: [u8; 32],
    seed: Value,
    bundle: Value,
    permit_kinds: Vec<String>,
    permit_ordinals: Vec<i16>,
    permit_request_commitments: Vec<Option<String>>,
    permit_dispatched_at_unix_us: Vec<Option<i64>>,
    dispatched_credentials: i64,
    dispatched_data: i64,
    predecessor: Option<[u8; 32]>,
    generation: Option<i64>,
    stored_envelope_id: Option<String>,
    stored_chain_hash: Option<[u8; 32]>,
    stored_payload_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
enum ActiveCompletionMode {
    Known,
    Unfinished,
}

/// One normal-completion attempt while the sealed dispatch remains borrowed.
/// A stale pseudonym authority proves zero mutation and lets the production
/// orchestrator reacquire the then-current epoch without dropping the armed
/// lifecycle seal.
#[must_use = "a terminal attempt must either complete or trigger a fresh-authority retry"]
pub(crate) enum TerminalCompletionAttempt<T> {
    Completed(T),
    PseudonymAuthorityStale,
}

enum ActiveConsultationFinalization {
    Completed {
        stored_identity: DurableAuditStoredIdentity,
        outcome: ConsultationCompletionOutcome,
    },
    PseudonymAuthorityStale,
}

impl PostgresDurableAuditStatePlane {
    pub(crate) async fn reserve_batch_child_replay(
        &self,
        binding: BatchChildReplayBinding,
        consultation_id: ConsultationId,
    ) -> Result<BatchChildReplayReservation, ConsultationPersistenceError> {
        let operation_id = DurableAuditOperationId::parse(&consultation_id.to_canonical_string())
            .map_err(|_| ConsultationPersistenceError::InvalidInput)?;
        let context = BatchChildReplayContext::from_binding(binding, operation_id.clone());
        let deadline = Instant::now() + MAX_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        let row = consultation_query(
            deadline,
            client.query_one(
                BATCH_CHILD_RESERVE_SQL,
                &[
                    &context.child_key.as_slice(),
                    &context.binding_digest.as_slice(),
                    &context.operation_id.as_ref(),
                ],
            ),
        )
        .await?;
        let outcome = required_str(&row, "outcome")?;
        let stored_operation_id = row
            .try_get::<_, Option<String>>("stored_operation_id")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
        let terminal_payload = row
            .try_get::<_, Option<String>>("terminal_payload")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
        match outcome {
            "reserved"
                if stored_operation_id.as_deref() == Some(context.operation_id.as_ref())
                    && terminal_payload.is_none() =>
            {
                Ok(BatchChildReplayReservation::Reserved(context))
            }
            "replay" if stored_operation_id.is_some() => terminal_payload
                .zip(stored_operation_id)
                .map(|(value, operation_id)| {
                    BatchChildReplayReservation::Replay(BatchTerminalReplay {
                        operation_id: operation_id.into_boxed_str(),
                        value: Zeroizing::new(value),
                    })
                })
                .ok_or(ConsultationPersistenceError::ProtocolDrift),
            "in_progress" if stored_operation_id.is_some() && terminal_payload.is_none() => {
                Ok(BatchChildReplayReservation::InProgress)
            }
            "conflict" if stored_operation_id.is_none() && terminal_payload.is_none() => {
                Ok(BatchChildReplayReservation::Conflict)
            }
            _ => Err(ConsultationPersistenceError::ProtocolDrift),
        }
    }

    pub(crate) async fn release_batch_child_replay(
        &self,
        context: &BatchChildReplayContext,
    ) -> Result<(), ConsultationPersistenceError> {
        let deadline = Instant::now() + MAX_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        let row = consultation_query(
            deadline,
            client.query_one(
                BATCH_CHILD_RELEASE_SQL,
                &[
                    &context.child_key.as_slice(),
                    &context.binding_digest.as_slice(),
                    &context.operation_id.as_ref(),
                ],
            ),
        )
        .await?;
        row.try_get::<_, bool>("released")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?
            .then_some(())
            .ok_or(ConsultationPersistenceError::StateConflict)
    }

    pub(crate) async fn write_attempt_with_state_view(
        &self,
        mut attempt: PreparedAtomicConsultationStateView<'_, '_>,
    ) -> Result<AuditedConsultationDispatch, ConsultationPersistenceError> {
        let write = attempt.audit_write().clone();
        let seed_canonical = attempt.completion_seed_canonical().to_owned();
        let seed_digest = *attempt.completion_seed_digest();
        let bundle_canonical = attempt.pseudonym_bundle_canonical().to_owned();
        let bundle_digest = *attempt.pseudonym_bundle_digest();
        let bundle_key_id = attempt.pseudonym_key_id().to_owned();
        let compiled_timeout_ms = attempt.compiled_timeout_ms();
        let decision_expires_at_unix_ms = attempt.decision_expires_at_unix_ms();
        let (
            fence_lock_key,
            fence_holder_id,
            fence_generation,
            fence_budget_ms,
            permit_kinds,
            permit_ordinals,
        ) = {
            let fence = attempt
                .fence_mut()
                .ok_or(ConsultationPersistenceError::InvalidInput)?;
            let (permit_kinds, permit_ordinals) = fence.permit_set.postgres_arrays();
            (
                fence.lock_key,
                fence.holder_id.clone(),
                fence.fence_generation,
                fence.budget.as_milliseconds(),
                permit_kinds,
                permit_ordinals,
            )
        };
        if write.key().stream_kind() != DurableAuditStreamKind::Consultation
            || write.key().phase() != DurableAuditPhase::Attempt
            || i32::try_from(compiled_timeout_ms).ok() != Some(fence_budget_ms)
        {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        let operation_id = DispatchOperationId::parse(write.key().operation_id().as_str())
            .map_err(|_| ConsultationPersistenceError::InvalidInput)?;
        let started = Instant::now();
        let local_not_after = started
            .checked_add(Duration::from_millis(fence_budget_ms as u64))
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
        let (authority_key_id, authority_generation, authority_digest, chain_epoch, lock_key) =
            attempt.active_epoch().postgres_binding();
        let authority_key_id = authority_key_id.to_owned();
        let authority_digest = *authority_digest;
        let chain_epoch = chain_epoch.clone();
        if authority_key_id != bundle_key_id
            || chain_epoch != self.chain_key_epoch_id
            || lock_key != self.keyring_lock_key.as_i64()
        {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        let deadline = Instant::now() + MAX_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        validate_runtime_pseudonym_capability_v1(
            &client,
            &self.chain_key_epoch_id,
            self.keyring_lock_key,
        )
        .await
        .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let snapshot = consultation_query(
                deadline,
                client.query_one(
                    ATTEMPT_SNAPSHOT_SQL,
                    &[
                        &operation_id.as_str(),
                        &write.payload_digest().as_bytes().as_slice(),
                        &seed_canonical,
                        &seed_digest.as_slice(),
                        &bundle_canonical,
                        &bundle_digest.as_slice(),
                        &bundle_key_id,
                        &authority_generation,
                        &authority_digest.as_slice(),
                        &fence_lock_key.as_i64(),
                        &fence_holder_id,
                        &fence_generation,
                        &fence_budget_ms,
                        &decision_expires_at_unix_ms,
                        &permit_kinds,
                        &permit_ordinals,
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            match required_str(&snapshot, "outcome")? {
                "identical_duplicate" => {
                    let fence = attempt
                        .take_fence()
                        .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
                    return dispatch_from_attempt_row(
                        &snapshot,
                        operation_id,
                        fence,
                        self.chain_hasher.clone(),
                        local_not_after,
                    );
                }
                "conflicting_duplicate" => return Err(ConsultationPersistenceError::Conflict),
                "decision_expired" => return Err(ConsultationPersistenceError::StateConflict),
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                "candidate" => {}
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
            let predecessor = optional_hash(&snapshot, "candidate_predecessor_hash")?;
            let generation = required_i64(&snapshot, "candidate_generation")?;
            let envelope = write
                .build_envelope_at_chain_head(predecessor, &self.chain_hasher)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let record_json = serde_json::to_string(&envelope.record)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let envelope_json = serde_json::to_string(&envelope)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            attempt
                .check_persistence_freshness()
                .map_err(|_| ConsultationPersistenceError::StateConflict)?;
            // From this point PostgreSQL can commit the intent even if this
            // task never observes the acknowledgement. The seal remains armed
            // across retries and transfers into the returned dispatch.
            attempt
                .fence_mut()
                .ok_or(ConsultationPersistenceError::ProtocolDrift)?
                .arm_lifecycle_seal();
            let cas = consultation_query(
                deadline,
                client.query_one(
                    ATTEMPT_CAS_SQL,
                    &[
                        &operation_id.as_str(),
                        &write.payload_digest().as_bytes().as_slice(),
                        &generation,
                        &predecessor.as_ref().map(<[u8; 32]>::as_slice),
                        &envelope.envelope_id,
                        &envelope.timestamp_unix_ms,
                        &record_json,
                        &envelope_json,
                        &envelope.record_hash.as_slice(),
                        &seed_canonical,
                        &seed_digest.as_slice(),
                        &bundle_canonical,
                        &bundle_digest.as_slice(),
                        &bundle_key_id,
                        &authority_generation,
                        &authority_digest.as_slice(),
                        &fence_lock_key.as_i64(),
                        &fence_holder_id,
                        &fence_generation,
                        &fence_budget_ms,
                        &decision_expires_at_unix_ms,
                        &permit_kinds,
                        &permit_ordinals,
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            match required_str(&cas, "outcome")? {
                "inserted" | "identical_duplicate" => {
                    let fence = attempt
                        .take_fence()
                        .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
                    return dispatch_from_attempt_row(
                        &cas,
                        operation_id,
                        fence,
                        self.chain_hasher.clone(),
                        local_not_after,
                    );
                }
                "head_changed" => {
                    // PostgreSQL proved that this CAS advanced no audit head
                    // and inserted no intent or permit. Return the authority
                    // to its harmless pre-intent state before the read-only
                    // retry; the next mutating CAS re-arms it immediately.
                    attempt
                        .fence_mut()
                        .ok_or(ConsultationPersistenceError::ProtocolDrift)?
                        .disarm_after_non_mutating_attempt_cas();
                    continue;
                }
                "conflicting_duplicate" => return Err(ConsultationPersistenceError::Conflict),
                "decision_expired" => {
                    // PostgreSQL proves that expiry won before this CAS wrote
                    // an audit row, completion intent, or permit. Restore the
                    // harmless pre-intent seal before returning the conflict so
                    // an ordinary authorization race cannot abort a healthy
                    // fence session.
                    attempt
                        .fence_mut()
                        .ok_or(ConsultationPersistenceError::ProtocolDrift)?
                        .disarm_after_non_mutating_attempt_cas();
                    return Err(ConsultationPersistenceError::StateConflict);
                }
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
        }
        Err(ConsultationPersistenceError::Unavailable)
    }

    pub(crate) async fn finalize_validated_consultation_view(
        &self,
        mut terminal: TerminalConsultationStateView<'_>,
        facts: &KnownConsultationCompletionFacts,
        batch: Option<(&BatchChildReplayContext, &str)>,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
        #[cfg(test)] test_hook: Option<&mut TerminalCompletionTestHook>,
    ) -> Result<TerminalCompletionAttempt<KnownCompletionDisposition>, ConsultationPersistenceError>
    {
        let completion = self
            .finalize_active_consultation(
                terminal
                    .dispatch_mut()
                    .ok_or(ConsultationPersistenceError::InvalidInput)?,
                Some(facts),
                ActiveCompletionMode::Known,
                batch,
                pseudonym_authority,
                #[cfg(test)]
                test_hook,
            )
            .await?;
        let ActiveConsultationFinalization::Completed {
            stored_identity,
            outcome,
        } = completion
        else {
            return Ok(TerminalCompletionAttempt::PseudonymAuthorityStale);
        };
        if outcome != ConsultationCompletionOutcome::KnownComplete {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        drop(
            terminal
                .take_dispatch()
                .ok_or(ConsultationPersistenceError::ProtocolDrift)?,
        );
        Ok(TerminalCompletionAttempt::Completed(known_disposition(
            facts,
            stored_identity,
        )))
    }

    pub(crate) async fn close_unfinished_consultation_view(
        &self,
        mut terminal: TerminalConsultationStateView<'_>,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
        #[cfg(test)] test_hook: Option<&mut TerminalCompletionTestHook>,
    ) -> Result<
        TerminalCompletionAttempt<ConsultationCompletionReceipt>,
        ConsultationPersistenceError,
    > {
        let completion = self
            .finalize_active_consultation(
                terminal
                    .dispatch_mut()
                    .ok_or(ConsultationPersistenceError::InvalidInput)?,
                None,
                ActiveCompletionMode::Unfinished,
                None,
                pseudonym_authority,
                #[cfg(test)]
                test_hook,
            )
            .await?;
        let ActiveConsultationFinalization::Completed {
            stored_identity,
            outcome,
        } = completion
        else {
            return Ok(TerminalCompletionAttempt::PseudonymAuthorityStale);
        };
        if outcome == ConsultationCompletionOutcome::KnownComplete {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        drop(
            terminal
                .take_dispatch()
                .ok_or(ConsultationPersistenceError::ProtocolDrift)?,
        );
        Ok(TerminalCompletionAttempt::Completed(
            ConsultationCompletionReceipt {
                stored_identity,
                outcome,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) async fn finalize_validated_consultation_for_test(
        &self,
        dispatch: AuditedConsultationDispatch,
        facts: KnownConsultationCompletionFacts,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
    ) -> Result<KnownCompletionDisposition, ConsultationPersistenceError> {
        let mut dispatch = dispatch;
        let completion = self
            .finalize_active_consultation(
                &mut dispatch,
                Some(&facts),
                ActiveCompletionMode::Known,
                None,
                pseudonym_authority,
                #[cfg(test)]
                None,
            )
            .await?;
        let ActiveConsultationFinalization::Completed {
            stored_identity,
            outcome,
        } = completion
        else {
            return Err(ConsultationPersistenceError::StateConflict);
        };
        if outcome != ConsultationCompletionOutcome::KnownComplete {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        Ok(known_disposition(&facts, stored_identity))
    }

    #[cfg(test)]
    pub(crate) async fn finalize_validated_batch_consultation_for_test(
        &self,
        dispatch: &mut AuditedConsultationDispatch,
        facts: &KnownConsultationCompletionFacts,
        batch: &BatchChildReplayContext,
        terminal_payload: &str,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
    ) -> Result<KnownCompletionDisposition, ConsultationPersistenceError> {
        let completion = self
            .finalize_active_consultation(
                dispatch,
                Some(facts),
                ActiveCompletionMode::Known,
                Some((batch, terminal_payload)),
                pseudonym_authority,
                None,
            )
            .await?;
        let ActiveConsultationFinalization::Completed {
            stored_identity,
            outcome,
        } = completion
        else {
            return Err(ConsultationPersistenceError::StateConflict);
        };
        if outcome != ConsultationCompletionOutcome::KnownComplete {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        Ok(known_disposition(facts, stored_identity))
    }

    #[cfg(test)]
    pub(crate) async fn close_unfinished_consultation_for_test(
        &self,
        dispatch: AuditedConsultationDispatch,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
    ) -> Result<ConsultationCompletionReceipt, ConsultationPersistenceError> {
        let mut dispatch = dispatch;
        let completion = self
            .finalize_active_consultation(
                &mut dispatch,
                None,
                ActiveCompletionMode::Unfinished,
                None,
                pseudonym_authority,
                #[cfg(test)]
                None,
            )
            .await?;
        let ActiveConsultationFinalization::Completed {
            stored_identity,
            outcome,
        } = completion
        else {
            return Err(ConsultationPersistenceError::StateConflict);
        };
        if outcome == ConsultationCompletionOutcome::KnownComplete {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        Ok(ConsultationCompletionReceipt {
            stored_identity,
            outcome,
        })
    }

    async fn finalize_active_consultation(
        &self,
        dispatch: &mut AuditedConsultationDispatch,
        facts: Option<&KnownConsultationCompletionFacts>,
        mode: ActiveCompletionMode,
        batch: Option<(&BatchChildReplayContext, &str)>,
        pseudonym_authority: ActiveAuditPseudonymWriteEpoch,
        #[cfg(test)] mut test_hook: Option<&mut TerminalCompletionTestHook>,
    ) -> Result<ActiveConsultationFinalization, ConsultationPersistenceError> {
        if matches!(mode, ActiveCompletionMode::Known) != facts.is_some() {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        let (permit_kinds, permit_ordinals) = dispatch.postgres_permit_arrays();
        let (current_key_id, current_generation, current_digest, chain_epoch, lock_key) =
            pseudonym_authority.postgres_binding();
        if chain_epoch != &self.chain_key_epoch_id || lock_key != self.keyring_lock_key.as_i64() {
            return Err(ConsultationPersistenceError::InvalidInput);
        }
        let deadline = Instant::now() + MAX_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let row = consultation_query(
                deadline,
                client.query_one(
                    NORMAL_COMPLETION_SNAPSHOT_SQL,
                    &[
                        &dispatch.operation_id.as_str(),
                        &dispatch.lock_key.as_i64(),
                        &dispatch.holder_id,
                        &dispatch.fence_generation,
                        &dispatch.deadline_unix_ms,
                        &permit_kinds,
                        &permit_ordinals,
                        &current_key_id,
                        &current_generation,
                        &current_digest.as_slice(),
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            if required_str(&row, "outcome")? == "pseudonym_authority_stale" {
                // This typed outcome carries null payload columns and proves
                // the snapshot wrote nothing. Detect it before parsing and
                // return while the exact armed dispatch remains borrowed.
                return Ok(ActiveConsultationFinalization::PseudonymAuthorityStale);
            }
            let snapshot = parse_completion_snapshot(&row)?;
            let completion_outcome = match mode {
                ActiveCompletionMode::Known => ConsultationCompletionOutcome::KnownComplete,
                ActiveCompletionMode::Unfinished
                    if snapshot.dispatched_credentials + snapshot.dispatched_data == 0 =>
                {
                    ConsultationCompletionOutcome::NotStarted
                }
                ActiveCompletionMode::Unfinished => ConsultationCompletionOutcome::OutcomeUnknown,
            };
            let completion =
                completion_write(&dispatch.operation_id, &snapshot, completion_outcome, facts)?;
            if snapshot.outcome == "completed" {
                let stored_identity = identical_completion(&snapshot, &completion)?;
                dispatch.disarm_after_terminal_completion();
                return Ok(ActiveConsultationFinalization::Completed {
                    stored_identity,
                    outcome: completion_outcome,
                });
            }
            match snapshot.outcome.as_str() {
                "candidate" => {}
                "permit_mismatch" => return Err(ConsultationPersistenceError::ProtocolDrift),
                "state_conflict" => return Err(ConsultationPersistenceError::StateConflict),
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
            #[cfg(test)]
            if let Some(hook) = test_hook.as_mut() {
                hook.pause_if(TerminalCompletionTestPoint::AfterCandidateSnapshot)
                    .await?;
            }
            let generation = snapshot
                .generation
                .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
            let envelope = completion
                .build_envelope_at_chain_head(snapshot.predecessor, &self.chain_hasher)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let record_json = serde_json::to_string(&envelope.record)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let envelope_json = serde_json::to_string(&envelope)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let completion_payload_digest = completion.payload_digest();
            let completion_payload_digest_bytes = completion_payload_digest.as_bytes();
            let ordinary_parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
                &dispatch.operation_id.as_str(),
                &dispatch.lock_key.as_i64(),
                &dispatch.holder_id,
                &dispatch.fence_generation,
                &dispatch.deadline_unix_ms,
                &permit_kinds,
                &permit_ordinals,
                &current_key_id,
                &current_generation,
                &current_digest.as_slice(),
                &completion_payload_digest_bytes.as_slice(),
                &generation,
                &snapshot.predecessor.as_ref().map(<[u8; 32]>::as_slice),
                &envelope.envelope_id,
                &envelope.timestamp_unix_ms,
                &record_json,
                &envelope_json,
                &envelope.record_hash.as_slice(),
                &self.chain_key_epoch_id.as_str(),
                &self.keyring_lock_key.as_i64(),
            ];
            let cas = if let Some((batch, terminal_payload)) = batch {
                if !matches!(mode, ActiveCompletionMode::Known) {
                    return Err(ConsultationPersistenceError::InvalidInput);
                }
                let child_key = batch.child_key.as_slice();
                let binding_digest = batch.binding_digest.as_slice();
                let mut parameters = ordinary_parameters.to_vec();
                parameters.push(&child_key);
                parameters.push(&binding_digest);
                parameters.push(&terminal_payload);
                consultation_query(
                    deadline,
                    client.query_one(BATCH_NORMAL_COMPLETION_CAS_SQL, &parameters),
                )
                .await?
            } else {
                consultation_query(
                    deadline,
                    client.query_one(
                        match mode {
                            ActiveCompletionMode::Known => NORMAL_COMPLETION_CAS_SQL,
                            ActiveCompletionMode::Unfinished => UNFINISHED_COMPLETION_CAS_SQL,
                        },
                        ordinary_parameters,
                    ),
                )
                .await?
            };
            match required_str(&cas, "outcome")? {
                "inserted" | "identical_duplicate" => {
                    if required_str(&cas, "completion_outcome")? != completion_outcome.as_str() {
                        return Err(ConsultationPersistenceError::ProtocolDrift);
                    }
                    let stored_identity = stored_identity(&cas)?;
                    dispatch.disarm_after_terminal_completion();
                    return Ok(ActiveConsultationFinalization::Completed {
                        stored_identity,
                        outcome: completion_outcome,
                    });
                }
                "head_changed" => continue,
                "pseudonym_authority_stale" => {
                    // The CAS revalidated authority under its mutation lock and
                    // proved zero writes. Keep the dispatch armed and borrowed
                    // so production can reacquire the current epoch and retry.
                    return Ok(ActiveConsultationFinalization::PseudonymAuthorityStale);
                }
                "conflicting_duplicate" => return Err(ConsultationPersistenceError::Conflict),
                "state_conflict" => return Err(ConsultationPersistenceError::StateConflict),
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
        }
        Err(ConsultationPersistenceError::Unavailable)
    }

    pub(crate) async fn recover_orphaned_consultation(
        &self,
        authority: &mut TakeoverCompletionRecoveryAuthority,
    ) -> Result<RecoveredConsultationCompletion, ConsultationPersistenceError> {
        let operation_id = authority
            .current_operation()
            .ok_or(ConsultationPersistenceError::StateConflict)?;
        let deadline = Instant::now() + MAX_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let row = consultation_query(
                deadline,
                client.query_one(
                    RECOVERY_COMPLETION_SNAPSHOT_SQL,
                    &[
                        &operation_id.as_str(),
                        &authority.lock_key.as_i64(),
                        &authority.holder_id,
                        &authority.fence_generation,
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            let snapshot = parse_completion_snapshot(&row)?;
            let outcome = if snapshot.dispatched_credentials + snapshot.dispatched_data == 0 {
                ConsultationCompletionOutcome::NotStarted
            } else {
                ConsultationCompletionOutcome::OutcomeUnknown
            };
            let completion = completion_write(operation_id, &snapshot, outcome, None)?;
            if snapshot.outcome == "completed" {
                let stored = identical_recovery(&snapshot, &completion, outcome)?;
                authority.mark_current_recovered();
                return Ok(stored);
            }
            match snapshot.outcome.as_str() {
                "candidate" => {}
                "state_conflict" => return Err(ConsultationPersistenceError::StateConflict),
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
            let generation = snapshot
                .generation
                .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
            let envelope = completion
                .build_envelope_at_chain_head(snapshot.predecessor, &self.chain_hasher)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let record_json = serde_json::to_string(&envelope.record)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let envelope_json = serde_json::to_string(&envelope)
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
            let cas = consultation_query(
                deadline,
                client.query_one(
                    RECOVERY_COMPLETION_CAS_SQL,
                    &[
                        &operation_id.as_str(),
                        &authority.lock_key.as_i64(),
                        &authority.holder_id,
                        &authority.fence_generation,
                        &completion.payload_digest().as_bytes().as_slice(),
                        &generation,
                        &snapshot.predecessor.as_ref().map(<[u8; 32]>::as_slice),
                        &envelope.envelope_id,
                        &envelope.timestamp_unix_ms,
                        &record_json,
                        &envelope_json,
                        &envelope.record_hash.as_slice(),
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            match required_str(&cas, "outcome")? {
                "inserted" | "identical_duplicate" => {
                    let stored = RecoveredConsultationCompletion {
                        stored_identity: stored_identity(&cas)?,
                        outcome,
                    };
                    authority.mark_current_recovered();
                    return Ok(stored);
                }
                "head_changed" => continue,
                "conflicting_duplicate" => return Err(ConsultationPersistenceError::Conflict),
                "state_conflict" => return Err(ConsultationPersistenceError::StateConflict),
                "ownership_lost" => return Err(ConsultationPersistenceError::OwnershipLost),
                _ => return Err(ConsultationPersistenceError::ProtocolDrift),
            }
        }
        Err(ConsultationPersistenceError::Unavailable)
    }
}

fn dispatch_from_attempt_row(
    row: &Row,
    operation_id: DispatchOperationId,
    mut fence: FencedConsultationAttemptAuthority,
    request_effect_hasher: registry_platform_audit::AuditChainHasher,
    local_not_after: Instant,
) -> Result<AuditedConsultationDispatch, ConsultationPersistenceError> {
    // An identical snapshot proves that a durable intent already exists, while
    // a CAS caller arrives here with the seal already armed.
    // Arm idempotently before parsing so protocol drift cannot strand it under
    // an admission-ready fence.
    fence.arm_lifecycle_seal();
    let deadline_unix_ms = required_i64(row, "deadline_unix_ms")?;
    let kinds = required_text_array(row, "stored_permit_kinds")?;
    let ordinals = required_i16_array(row, "stored_permit_ordinals")?;
    let expected = fence.permit_set.postgres_arrays();
    if kinds != expected.0 || ordinals != expected.1 {
        return Err(ConsultationPersistenceError::ProtocolDrift);
    }
    let attempt_envelope_id = required_str(row, "stored_envelope_id")?.to_owned();
    let attempt_record_hash = required_hash(row, "stored_chain_hash")?;
    let permits = fence
        .permit_set
        .permits()
        .iter()
        .map(|(kind, ordinal)| ConsultationDispatchPermit {
            operation_id: operation_id.clone(),
            kind: *kind,
            ordinal: *ordinal,
            fence_generation: fence.fence_generation,
            holder_id: fence.holder_id.clone(),
            budget: fence.budget,
            deadline_unix_ms,
            local_not_after,
            state: DispatchPermitState::Ready,
        })
        .collect();
    Ok(AuditedConsultationDispatch {
        operation_id,
        attempt_envelope_id,
        attempt_record_hash,
        lock_key: fence.lock_key,
        fence_generation: fence.fence_generation,
        holder_id: fence.holder_id,
        deadline_unix_ms,
        local_not_after,
        permits,
        request_effect_hasher,
        lifecycle_seal: fence.lifecycle_seal,
    })
}

fn completion_write(
    operation_id: &DispatchOperationId,
    snapshot: &CompletionSnapshot,
    outcome: ConsultationCompletionOutcome,
    facts: Option<&KnownConsultationCompletionFacts>,
) -> Result<DurableAuditWrite, ConsultationPersistenceError> {
    let bundle = snapshot
        .bundle
        .as_object()
        .ok_or(ConsultationPersistenceError::ProtocolDrift)?;
    if snapshot.permit_kinds.len() != snapshot.permit_ordinals.len()
        || snapshot.permit_kinds.len() != snapshot.permit_request_commitments.len()
        || snapshot.permit_kinds.len() != snapshot.permit_dispatched_at_unix_us.len()
    {
        return Err(ConsultationPersistenceError::ProtocolDrift);
    }
    let permit_evidence = snapshot
        .permit_kinds
        .iter()
        .zip(&snapshot.permit_ordinals)
        .zip(&snapshot.permit_request_commitments)
        .zip(&snapshot.permit_dispatched_at_unix_us)
        .map(|(((kind, ordinal), request_commitment), dispatched_at)| {
            if request_commitment.is_some() != dispatched_at.is_some() {
                return Err(ConsultationPersistenceError::ProtocolDrift);
            }
            Ok(json!({
                "kind": kind,
                "ordinal": ordinal,
                "request_commitment": request_commitment,
                "dispatched_at_unix_us": dispatched_at,
            }))
        })
        .collect::<Result<Vec<_>, ConsultationPersistenceError>>()?;
    let actual_path = snapshot
        .permit_kinds
        .iter()
        .zip(&snapshot.permit_ordinals)
        .zip(&snapshot.permit_request_commitments)
        .zip(&snapshot.permit_dispatched_at_unix_us)
        .filter_map(|(((kind, ordinal), request_commitment), dispatched_at)| {
            dispatched_at
                .is_some()
                .then_some((kind, ordinal, request_commitment.as_deref()))
        })
        .map(|(kind, ordinal, request_commitment)| {
            let request_commitment =
                request_commitment.ok_or(ConsultationPersistenceError::ProtocolDrift)?;
            Ok(json!({
                "kind": kind,
                "ordinal": ordinal,
                "request_commitment": request_commitment,
            }))
        })
        .collect::<Result<Vec<_>, ConsultationPersistenceError>>()?;
    let completion_facts = match (outcome, facts) {
        (ConsultationCompletionOutcome::KnownComplete, Some(facts)) => {
            let (execution_result, provenance) = facts.payload_values();
            Some(json!({
                "schema": "registry.relay.consultation-completion-facts/v1",
                "execution_result": execution_result,
                "provenance": provenance,
                "actual_credential_exchanges": snapshot.dispatched_credentials,
                "actual_data_exchanges": snapshot.dispatched_data,
                "actual_path": actual_path,
            }))
        }
        (ConsultationCompletionOutcome::NotStarted, None)
        | (ConsultationCompletionOutcome::OutcomeUnknown, None) => None,
        _ => return Err(ConsultationPersistenceError::InvalidInput),
    };
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        DurableAuditOperationId::parse(operation_id.as_str())
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": {
                "envelope_id": snapshot.attempt_envelope_id,
                "chain_hash": format!(
                    "registry-audit-chain-v1:{}",
                    encode_hex(&snapshot.attempt_record_hash)
                ),
            },
            "completion_seed": snapshot.seed,
            "commitment_key_id": bundle.get("commitment_key_id"),
            "subject_handle": bundle.get("subject_handle"),
            "input_commitment": bundle.get("input_commitment"),
            "predicate_commitment": bundle.get("predicate_commitment"),
            "consent_evidence_commitment": bundle.get("consent_evidence_commitment"),
            "outcome": outcome.as_str(),
            "permit_evidence": permit_evidence,
            "completion_facts": completion_facts,
        }),
    )
    .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn parse_completion_snapshot(
    row: &Row,
) -> Result<CompletionSnapshot, ConsultationPersistenceError> {
    let seed_canonical = required_str(row, "completion_seed_canonical")?;
    let bundle_canonical = required_str(row, "pseudonym_bundle_canonical")?;
    verify_canonical_digest(
        seed_canonical,
        required_hash(row, "completion_seed_digest")?,
    )?;
    verify_canonical_digest(
        bundle_canonical,
        required_hash(row, "pseudonym_bundle_digest")?,
    )?;
    Ok(CompletionSnapshot {
        outcome: required_str(row, "outcome")?.to_owned(),
        attempt_envelope_id: required_str(row, "attempt_envelope_id")?.to_owned(),
        attempt_record_hash: required_hash(row, "attempt_record_hash")?,
        seed: serde_json::from_str(seed_canonical)
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        bundle: serde_json::from_str(bundle_canonical)
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        permit_kinds: required_text_array(row, "permit_kinds")?,
        permit_ordinals: required_i16_array(row, "permit_ordinals")?,
        permit_request_commitments: row
            .try_get("permit_request_commitments")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        permit_dispatched_at_unix_us: row
            .try_get("permit_dispatched_at_unix_us")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        dispatched_credentials: required_i64(row, "dispatched_credential_count")?,
        dispatched_data: required_i64(row, "dispatched_data_count")?,
        predecessor: optional_hash(row, "candidate_predecessor_hash")?,
        generation: row
            .try_get("candidate_generation")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        stored_envelope_id: row
            .try_get("stored_completion_envelope_id")
            .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?,
        stored_chain_hash: optional_hash(row, "stored_completion_chain_hash")?,
        stored_payload_digest: optional_hash(row, "stored_completion_payload_digest")?,
    })
}

fn identical_completion(
    snapshot: &CompletionSnapshot,
    write: &DurableAuditWrite,
) -> Result<DurableAuditStoredIdentity, ConsultationPersistenceError> {
    if snapshot.stored_payload_digest != Some(*write.payload_digest().as_bytes()) {
        return Err(ConsultationPersistenceError::Conflict);
    }
    snapshot_identity(snapshot)
}

fn known_disposition(
    facts: &KnownConsultationCompletionFacts,
    stored_identity: DurableAuditStoredIdentity,
) -> KnownCompletionDisposition {
    if facts.is_public_success() {
        KnownCompletionDisposition::Published(ConsultationPublicationGrant { stored_identity })
    } else {
        KnownCompletionDisposition::FinalizedFailure(ConsultationCompletionReceipt {
            stored_identity,
            outcome: ConsultationCompletionOutcome::KnownComplete,
        })
    }
}

fn identical_recovery(
    snapshot: &CompletionSnapshot,
    write: &DurableAuditWrite,
    outcome: ConsultationCompletionOutcome,
) -> Result<RecoveredConsultationCompletion, ConsultationPersistenceError> {
    if snapshot.stored_payload_digest != Some(*write.payload_digest().as_bytes()) {
        return Err(ConsultationPersistenceError::Conflict);
    }
    Ok(RecoveredConsultationCompletion {
        stored_identity: snapshot_identity(snapshot)?,
        outcome,
    })
}

fn snapshot_identity(
    snapshot: &CompletionSnapshot,
) -> Result<DurableAuditStoredIdentity, ConsultationPersistenceError> {
    identity_from_parts(
        snapshot
            .stored_envelope_id
            .as_deref()
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?,
        snapshot
            .stored_chain_hash
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?,
    )
}

fn stored_identity(row: &Row) -> Result<DurableAuditStoredIdentity, ConsultationPersistenceError> {
    identity_from_parts(
        required_str(row, "stored_envelope_id")?,
        required_hash(row, "stored_chain_hash")?,
    )
}

fn identity_from_parts(
    envelope_id: &str,
    record_hash: [u8; 32],
) -> Result<DurableAuditStoredIdentity, ConsultationPersistenceError> {
    DurableAuditStoredIdentity::from_envelope(&AuditEnvelope {
        envelope_id: envelope_id.to_owned(),
        timestamp_unix_ms: 0,
        prev_hash: None,
        record: Value::Null,
        record_hash,
    })
    .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn canonical_binding(value: Value) -> Result<(String, [u8; 32]), ConsultationPersistenceError> {
    let bytes =
        canonicalize_json(&value).map_err(|_| ConsultationPersistenceError::InvalidInput)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let canonical =
        String::from_utf8(bytes).map_err(|_| ConsultationPersistenceError::InvalidInput)?;
    Ok((canonical, digest))
}

fn verify_canonical_digest(
    canonical: &str,
    expected: [u8; 32],
) -> Result<(), ConsultationPersistenceError> {
    let value: Value =
        serde_json::from_str(canonical).map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
    let recanonicalized =
        canonicalize_json(&value).map_err(|_| ConsultationPersistenceError::ProtocolDrift)?;
    if recanonicalized != canonical.as_bytes()
        || <[u8; 32]>::from(Sha256::digest(canonical.as_bytes())) != expected
    {
        return Err(ConsultationPersistenceError::ProtocolDrift);
    }
    Ok(())
}

async fn consultation_query<F>(
    deadline: Instant,
    future: F,
) -> Result<Row, ConsultationPersistenceError>
where
    F: std::future::Future<Output = Result<Row, PostgresError>>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ConsultationPersistenceError::Unavailable)?
        .map_err(map_postgres_error)
}

fn map_postgres_error(error: PostgresError) -> ConsultationPersistenceError {
    match error.as_db_error().map(|error| error.code().code()) {
        Some("22023" | "23514" | "23503" | "23505") => ConsultationPersistenceError::InvalidInput,
        Some("42501") => ConsultationPersistenceError::OwnershipLost,
        _ => ConsultationPersistenceError::Unavailable,
    }
}

fn required_str<'a>(row: &'a Row, column: &str) -> Result<&'a str, ConsultationPersistenceError> {
    row.try_get(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn required_i64(row: &Row, column: &str) -> Result<i64, ConsultationPersistenceError> {
    row.try_get(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn required_hash(row: &Row, column: &str) -> Result<[u8; 32], ConsultationPersistenceError> {
    row.try_get::<_, &[u8]>(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?
        .try_into()
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn optional_hash(
    row: &Row,
    column: &str,
) -> Result<Option<[u8; 32]>, ConsultationPersistenceError> {
    row.try_get::<_, Option<&[u8]>>(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)?
        .map(|value| {
            value
                .try_into()
                .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
        })
        .transpose()
}

fn required_text_array(
    row: &Row,
    column: &str,
) -> Result<Vec<String>, ConsultationPersistenceError> {
    row.try_get(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

fn required_i16_array(row: &Row, column: &str) -> Result<Vec<i16>, ConsultationPersistenceError> {
    row.try_get(column)
        .map_err(|_| ConsultationPersistenceError::ProtocolDrift)
}

#[cfg(test)]
#[cfg(test)]
fn valid_key_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && value.len() <= 64
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
#[cfg(test)]
fn valid_commitment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMMITMENT_BYTES
        && value.chars().all(|character| !character.is_control())
}

fn encode_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{KnownConsultationCompletionFacts, KnownFailureClass};

    #[test]
    fn subject_mismatch_is_a_distinct_durable_failure_class() {
        let facts = KnownConsultationCompletionFacts::failure(KnownFailureClass::SubjectMismatch);
        let (execution_result, provenance) = facts.payload_values();

        assert_eq!(
            execution_result,
            json!({"class": "known_failure", "failure_class": "subject_mismatch"})
        );
        assert_eq!(provenance, serde_json::Value::Null);
    }
}
