// SPDX-License-Identifier: Apache-2.0
//! Production consultation completion-seed and attempt-audit construction.
//!
//! Completion audit writes intentionally remain owned by the atomic PostgreSQL
//! state plane. Only that boundary has the durable attempt identity and actual
//! monotonic permit markers, so constructing a second completion path here
//! would weaken the sealed lifecycle contract.

use std::future::Future;
use std::pin::Pin;
#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
use tokio::sync::oneshot;

#[cfg(test)]
use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyId;
use registry_platform_audit::{
    DurableAuditOperationId, DurableAuditPhase, DurableAuditStreamKind, DurableAuditWrite,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::source_plan::runtime_profile::{
    CompiledRuntimeProfile, CompiledSourceObservedAtContract, CompiledSourceRevisionContract,
    MAX_COMPLETION_SEED_CANONICAL_BYTES_V1,
};
use crate::state_plane::{
    ActiveAuditPseudonymWriteEpoch, AuditedConsultationDispatch, ConsultationCompletionReceipt,
    ConsultationPersistenceError, ConsultationPublicationGrant, FencedConsultationAttemptAuthority,
    KnownCompletionDisposition, KnownConsultationCompletionFacts,
    PostgresAuditPseudonymKeyringRuntime, PostgresDurableAuditStatePlane,
    TerminalCompletionAttempt,
};

use super::commitments::{
    acquisition_schema_value, authorized_operation_union_value, consent_seed_value,
    empty_obligations_digest, permit_bindings_value, public_outcome_str,
    AuthorizedConsultationAttempt, ConsultationCommitmentError, ConsultationDigests,
    PendingConsultationDispatchFreshness, PendingConsultationPersistenceFreshness,
    VerifiedConsentDecision,
};
use super::pseudonym::PreparedConsultationPseudonyms;
use super::{AcquisitionClass, ConsultationId, NotaryEvaluationId};

const MAX_TERMINAL_PSEUDONYM_AUTHORITY_ATTEMPTS: usize = 4;

/// Deterministic one-shot pause points for live PostgreSQL race coverage.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalCompletionTestPoint {
    AfterAuthorityMinted,
    AfterCandidateSnapshot,
}

/// Test-only half retained by production-shaped terminal orchestration.
#[cfg(test)]
pub(crate) struct TerminalCompletionTestHook {
    point: TerminalCompletionTestPoint,
    reached: Option<oneshot::Sender<()>>,
    resume: Option<oneshot::Receiver<()>>,
    fired: bool,
}

/// Test-only half used by the live PostgreSQL driver to rotate state exactly
/// while terminal orchestration is paused.
#[cfg(test)]
pub(crate) struct TerminalCompletionTestControl {
    reached: Option<oneshot::Receiver<()>>,
    resume: Option<oneshot::Sender<()>>,
}

#[cfg(test)]
pub(crate) fn terminal_completion_test_hook(
    point: TerminalCompletionTestPoint,
) -> (TerminalCompletionTestHook, TerminalCompletionTestControl) {
    let (reached_sender, reached_receiver) = oneshot::channel();
    let (resume_sender, resume_receiver) = oneshot::channel();
    (
        TerminalCompletionTestHook {
            point,
            reached: Some(reached_sender),
            resume: Some(resume_receiver),
            fired: false,
        },
        TerminalCompletionTestControl {
            reached: Some(reached_receiver),
            resume: Some(resume_sender),
        },
    )
}

#[cfg(test)]
impl TerminalCompletionTestHook {
    pub(crate) async fn pause_if(
        &mut self,
        point: TerminalCompletionTestPoint,
    ) -> Result<(), ConsultationPersistenceError> {
        if self.fired || self.point != point {
            return Ok(());
        }
        self.fired = true;
        self.reached
            .take()
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?
            .send(())
            .map_err(|_| ConsultationPersistenceError::Unavailable)?;
        self.resume
            .take()
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)
    }
}

#[cfg(test)]
impl TerminalCompletionTestControl {
    pub(crate) async fn wait_until_paused(&mut self) -> Result<(), ConsultationPersistenceError> {
        self.reached
            .take()
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?
            .await
            .map_err(|_| ConsultationPersistenceError::Unavailable)
    }

    pub(crate) fn resume(&mut self) -> Result<(), ConsultationPersistenceError> {
        self.resume
            .take()
            .ok_or(ConsultationPersistenceError::ProtocolDrift)?
            .send(())
            .map_err(|_| ConsultationPersistenceError::Unavailable)
    }
}

/// Value-free failure taxonomy for seed and durable-write construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConsultationAuditBuildError {
    #[error("consultation completion seed facts do not match the compiled profile")]
    ProfileMismatch,
    #[error("consultation completion seed exceeds its compiled persistence bound")]
    SeedOutOfBounds,
    #[error("consultation completion seed could not be canonicalized")]
    Canonicalization,
    #[error("consultation attempt audit write is invalid")]
    InvalidAuditWrite,
    #[error("consultation attempt state-plane binding is invalid")]
    StateBinding,
}

impl From<ConsultationCommitmentError> for ConsultationAuditBuildError {
    fn from(_: ConsultationCommitmentError) -> Self {
        Self::ProfileMismatch
    }
}

/// Exact safe completion seed handed to both the attempt payload and atomic
/// state-plane intent. It is private, neither serializable nor debuggable, and
/// remains coupled to the one authorized aggregate that produced it.
struct RuntimeConsultationCompletionSeed {
    value: Value,
}

impl RuntimeConsultationCompletionSeed {
    fn build(
        attempt: &AuthorizedConsultationAttempt<'_>,
        notary_evaluation_id: Option<NotaryEvaluationId>,
    ) -> Result<Self, ConsultationAuditBuildError> {
        Self::build_from_parts(
            attempt.profile(),
            notary_evaluation_id,
            attempt.canonical_purpose(),
            attempt.consent(),
            attempt.digests(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_from_parts(
        profile: &CompiledRuntimeProfile,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        canonical_purpose: &str,
        consent: VerifiedConsentDecision,
        digests: &ConsultationDigests,
    ) -> Result<Self, ConsultationAuditBuildError> {
        if !profile
            .purposes()
            .any(|purpose| purpose == canonical_purpose)
        {
            return Err(ConsultationAuditBuildError::ProfileMismatch);
        }
        let provenance_contract = match (
            profile.acquisition_provenance().source_observed_at(),
            profile.acquisition_provenance().source_revision(),
        ) {
            (CompiledSourceObservedAtContract::Absent, CompiledSourceRevisionContract::Absent) => {
                json!({
                    "source_observed_at": null,
                    "source_revision": null,
                    "snapshot_generation": if profile
                        .acquisition_provenance()
                        .snapshot_generation_required()
                    {
                        "required"
                    } else {
                        "absent"
                    },
                    "snapshot_published_at": if profile
                        .acquisition_provenance()
                        .snapshot_published_at_required()
                    {
                        "required"
                    } else {
                        "absent"
                    },
                })
            }
            _ => return Err(ConsultationAuditBuildError::ProfileMismatch),
        };
        let bounds = profile.effective_limits();
        let operation_bounds = bounds.operation();
        if operation_bounds.timeout_ms == 0 || operation_bounds.timeout_ms > 10_000 {
            return Err(ConsultationAuditBuildError::ProfileMismatch);
        }
        let value = json!({
            "schema": "registry.relay.consultation-completion-seed/v1",
            "correlation": {
                "notary_evaluation_id": notary_evaluation_id
                    .map(NotaryEvaluationId::to_canonical_string),
            },
            "profile": {
                "id": profile.profile().id().as_str(),
                "version": profile.profile().version().to_string(),
                "contract_hash": profile.profile().contract_hash().as_str(),
            },
            "integration_pack": {
                "id": profile.integration_pack().id().as_str(),
                "version": profile.integration_pack().version().to_string(),
                "hash": profile.integration_pack().hash().as_str(),
            },
            "private_binding_hash": profile.private_binding_hash(),
            "workload": {
                "id": profile.workload_id().as_str(),
                "tenant_id": profile.tenant().as_str(),
                "registry_id": profile.registry_instance().as_str(),
            },
            "purpose": canonical_purpose,
            "policy": {
                "id": profile.authorization().policy().id().as_str(),
                "hash": profile.authorization().policy().hash().as_str(),
                "legal_basis_id": profile.legal_basis(),
                "consent": consent_seed_value(
                    profile.authorization().consent(),
                    consent,
                )?,
                "obligations_digest": empty_obligations_digest()?.as_str(),
            },
            "acquisition": {
                "class": acquisition_class_str(profile.footprint().acquisition_class()),
                "schema": acquisition_schema_value(profile),
                "disclosure_fields": profile.output().map(|field| field.name()).collect::<Vec<_>>(),
                "public_outcomes": profile.outcomes().map(public_outcome_str).collect::<Vec<_>>(),
                "provenance_contract": provenance_contract,
            },
            "destinations": {
                "credential_destination_id": profile.credential_destination_id(),
                "data_destination_id": profile.data_destination_id(),
            },
            "credential": {
                "reference": profile.credential_reference(),
                "generation": profile.credential_generation(),
            },
            "authorized_operation_union": authorized_operation_union_value(profile),
            "dispatch": {
                "plan_kind": source_plan_kind_str(profile.kind()),
                "permit_bindings": permit_bindings_value(profile),
            },
            "bounds": {
                "source_matches": operation_bounds.max_source_matches,
                "disclosed_records": operation_bounds.max_disclosed_records,
                "data_exchanges": operation_bounds.max_data_exchanges,
                "credential_exchanges": operation_bounds.max_credential_exchanges,
                "data_destinations": operation_bounds.max_data_destinations,
                "source_bytes": operation_bounds.max_source_bytes,
                "timeout_ms": operation_bounds.timeout_ms,
                "max_in_flight": bounds.max_in_flight(),
                "quota_rate_per_minute": bounds.quota_per_minute(),
                "quota_burst": bounds.quota_burst(),
                "public_response_bytes": bounds.max_public_response_bytes(),
                "credential_token_lifetime_ms": profile.credential_token_lifetime_ms(),
            },
            "request_digest": digests.request().as_str(),
            "authorization_context_digest": digests.authorization_context().as_str(),
            "execution_plan_digest": digests.execution_plan().as_str(),
        });
        let canonical =
            canonicalize_json(&value).map_err(|_| ConsultationAuditBuildError::Canonicalization)?;
        let canonical_bytes = canonical.len();
        if canonical_bytes > MAX_COMPLETION_SEED_CANONICAL_BYTES_V1
            || canonical_bytes > profile.completion_seed_canonical_bytes_max()
        {
            return Err(ConsultationAuditBuildError::SeedOutOfBounds);
        }
        Ok(Self { value })
    }

    fn safe_value(&self) -> &Value {
        &self.value
    }

    fn into_safe_value(self) -> Value {
        self.value
    }
}

/// Build the only production attempt write accepted by the atomic
/// consultation state-plane operation.
fn build_attempt_audit_write(
    consultation_id: ConsultationId,
    seed: &RuntimeConsultationCompletionSeed,
    pseudonyms: &PreparedConsultationPseudonyms,
) -> Result<DurableAuditWrite, ConsultationAuditBuildError> {
    let operation_id = DurableAuditOperationId::parse(&consultation_id.to_canonical_string())
        .map_err(|_| ConsultationAuditBuildError::InvalidAuditWrite)?;
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id,
        DurableAuditPhase::Attempt,
        attempt_audit_payload(
            seed.safe_value(),
            pseudonyms.key_id.as_str(),
            pseudonyms.subject_handle.as_str(),
            pseudonyms.input_commitment.as_str(),
            pseudonyms.predicate_commitment.as_str(),
            pseudonyms
                .consent_evidence_commitment
                .as_ref()
                .map(|commitment| commitment.as_str()),
        ),
    )
    .map_err(|_| ConsultationAuditBuildError::InvalidAuditWrite)
}

fn attempt_audit_payload(
    completion_seed: &Value,
    commitment_key_id: &str,
    subject_handle: &str,
    input_commitment: &str,
    predicate_commitment: &str,
    consent_evidence_commitment: Option<&str>,
) -> Value {
    json!({
        "schema": "registry.relay.consultation-attempt/v1",
        "authorization": "accepted",
        "completion_seed": completion_seed,
        "commitment_key_id": commitment_key_id,
        "subject_handle": subject_handle,
        "input_commitment": input_commitment,
        "predicate_commitment": predicate_commitment,
        "consent_evidence_commitment": consent_evidence_commitment,
    })
}

/// One fully bound, one-shot input to the atomic attempt-audit and completion
/// intent CAS. The fields cannot be independently replaced after construction.
#[must_use = "an authorized attempt must be consumed by the atomic state-plane CAS"]
pub(crate) struct PreparedAtomicConsultationAttempt {
    audit_write: DurableAuditWrite,
    completion_seed: CanonicalStateBinding,
    pseudonym_bundle: CanonicalPseudonymBundle,
    active_epoch: ActiveAuditPseudonymWriteEpoch,
    dispatch_freshness: PendingConsultationDispatchFreshness,
    persistence_freshness: PendingConsultationPersistenceFreshness,
    compiled_timeout_ms: u32,
    fence: Option<FencedConsultationAttemptAuthority>,
}

impl PreparedAtomicConsultationAttempt {
    /// Return the exact compiled timeout used to derive the fence budget.
    pub(crate) const fn compiled_timeout_ms(&self) -> u32 {
        self.compiled_timeout_ms
    }

    fn state_view(&mut self) -> PreparedAtomicConsultationStateView<'_> {
        PreparedAtomicConsultationStateView { prepared: self }
    }

    fn into_persisted_dispatch(
        self,
        dispatch: AuditedConsultationDispatch,
    ) -> Result<PreparedAuditedConsultationDispatch, ConsultationPersistenceError> {
        if self.fence.is_some() {
            return Err(ConsultationPersistenceError::ProtocolDrift);
        }
        Ok(PreparedAuditedConsultationDispatch {
            dispatch,
            dispatch_freshness: self.dispatch_freshness,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_state_test(
        audit_write: DurableAuditWrite,
        completion_seed: Value,
        key_id: &AuditPseudonymKeyId,
        fence: FencedConsultationAttemptAuthority,
        active_epoch: ActiveAuditPseudonymWriteEpoch,
        decision_expires_at_unix_ms: i64,
    ) -> Result<Self, ConsultationAuditBuildError> {
        let compiled_timeout_ms = completion_seed
            .get("bounds")
            .and_then(Value::as_object)
            .and_then(|bounds| bounds.get("timeout_ms"))
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=10_000).contains(value))
            .ok_or(ConsultationAuditBuildError::StateBinding)?;
        let pseudonym_bundle = CanonicalPseudonymBundle {
            key_id: key_id.as_str().to_owned(),
            binding: canonical_state_binding(json!({
                "commitment_key_id": key_id.as_str(),
                "subject_handle": "hmac-sha256:test-only-redacted-handle",
                "input_commitment": "hmac-sha256:test-only-input-commitment",
                "predicate_commitment": "hmac-sha256:test-only-predicate-commitment",
                "consent_evidence_commitment": null,
            }))?,
        };
        let local_not_after = Instant::now()
            .checked_add(Duration::from_secs(300))
            .ok_or(ConsultationAuditBuildError::StateBinding)?;
        Ok(Self {
            audit_write,
            completion_seed: canonical_state_binding(completion_seed)?,
            pseudonym_bundle,
            active_epoch,
            dispatch_freshness: PendingConsultationDispatchFreshness::for_state_test(
                decision_expires_at_unix_ms,
                local_not_after,
            ),
            persistence_freshness: PendingConsultationPersistenceFreshness::for_state_test(
                decision_expires_at_unix_ms,
                local_not_after,
            ),
            compiled_timeout_ms,
            fence: Some(fence),
        })
    }
}

struct CanonicalStateBinding {
    canonical: String,
    digest: [u8; 32],
}

struct CanonicalPseudonymBundle {
    key_id: String,
    binding: CanonicalStateBinding,
}

/// The only borrowed state-plane view over one fully sealed attempt.
///
/// Its fields are private and callers cannot construct it. The durable writer
/// retains this view across retries and can only move the fence out while the
/// original aggregate remains borrowed by the sealing orchestration method.
pub(crate) struct PreparedAtomicConsultationStateView<'attempt> {
    prepared: &'attempt mut PreparedAtomicConsultationAttempt,
}

impl PreparedAtomicConsultationStateView<'_> {
    pub(crate) fn audit_write(&self) -> &DurableAuditWrite {
        &self.prepared.audit_write
    }

    pub(crate) fn completion_seed_canonical(&self) -> &str {
        &self.prepared.completion_seed.canonical
    }

    pub(crate) const fn completion_seed_digest(&self) -> &[u8; 32] {
        &self.prepared.completion_seed.digest
    }

    pub(crate) const fn compiled_timeout_ms(&self) -> u32 {
        self.prepared.compiled_timeout_ms
    }

    pub(crate) fn pseudonym_bundle_canonical(&self) -> &str {
        &self.prepared.pseudonym_bundle.binding.canonical
    }

    pub(crate) const fn pseudonym_bundle_digest(&self) -> &[u8; 32] {
        &self.prepared.pseudonym_bundle.binding.digest
    }

    pub(crate) fn pseudonym_key_id(&self) -> &str {
        &self.prepared.pseudonym_bundle.key_id
    }

    pub(crate) const fn active_epoch(&self) -> &ActiveAuditPseudonymWriteEpoch {
        &self.prepared.active_epoch
    }

    pub(crate) const fn decision_expires_at_unix_ms(&self) -> i64 {
        self.prepared.persistence_freshness.expires_at_unix_ms()
    }

    pub(crate) fn check_persistence_freshness(&self) -> Result<(), ConsultationCommitmentError> {
        self.prepared.persistence_freshness.check_fresh_now()
    }

    pub(crate) fn fence_mut(&mut self) -> Option<&mut FencedConsultationAttemptAuthority> {
        self.prepared.fence.as_mut()
    }

    pub(crate) fn take_fence(&mut self) -> Option<FencedConsultationAttemptAuthority> {
        self.prepared.fence.take()
    }
}

/// Exact durable dispatch paired with the original decision guard. An exact
/// replay returns this sealed dispatch even after that guard expires, because
/// the durable attempt already exists and must reach terminal `not_started`
/// rather than becoming unreachable after a lost acknowledgement. The attempt
/// key epoch is consumed by the attempt CAS and deliberately does not survive
/// into completion. Terminal orchestration reacquires the then-current write
/// epoch across bounded, proven-nonmutating stale-authority retries so key
/// rotation cannot strand an open consultation.
#[must_use = "the audited dispatch must reach one terminal completion"]
pub(crate) struct PreparedAuditedConsultationDispatch {
    dispatch: AuditedConsultationDispatch,
    dispatch_freshness: PendingConsultationDispatchFreshness,
}

/// One decoder-validated backend result that binds its potentially publishable
/// output to the exact completion facts derived from the same source response.
///
/// Production construction is deliberately unavailable until the concrete
/// strict decoder integration can own the only minting boundary. In
/// particular, the service cannot independently pair output with completion
/// facts after backend execution.
#[must_use = "a validated backend result must remain sealed through terminal completion"]
pub(crate) struct ValidatedConsultationBackendResult<T> {
    publishable_output: T,
    completion_facts: KnownConsultationCompletionFacts,
}

impl<T> ValidatedConsultationBackendResult<T> {
    /// Explicit test-only minting boundary for production-shaped state-plane
    /// orchestration tests. Production must instead mint this value at the
    /// concrete strict decoder boundary.
    #[cfg(test)]
    pub(crate) const fn for_test(
        publishable_output: T,
        completion_facts: KnownConsultationCompletionFacts,
    ) -> Self {
        Self {
            publishable_output,
            completion_facts,
        }
    }

    fn into_parts(self) -> (T, KnownConsultationCompletionFacts) {
        (self.publishable_output, self.completion_facts)
    }
}

/// A backend result that retains the exact structurally sealed audited
/// dispatch and decoder-issued result for terminal completion. Completion
/// reacquires the then-current pseudonym write authority without moving this
/// dispatch across a stale check.
#[must_use = "backend output must be consumed by terminal completion"]
pub(crate) struct ExecutedAuditedConsultationDispatch<T> {
    dispatch: Option<AuditedConsultationDispatch>,
    validated: ValidatedConsultationBackendResult<T>,
}

/// Terminal result of one decoder-validated backend execution. Publishable
/// output exists only in the variant that owns durable publication authority;
/// a known failure can return only its terminal receipt.
#[must_use = "a published output requires the paired durable publication grant"]
pub(crate) enum FinalizedValidatedConsultation<T> {
    Published {
        grant: ConsultationPublicationGrant,
        output: T,
    },
    FinalizedFailure(ConsultationCompletionReceipt),
}

/// An expired decision that still owns the exact structurally sealed durable
/// dispatch so the service can record `not_started` without source access.
/// Completion reacquires the then-current pseudonym write authority without
/// moving this dispatch across a stale check.
#[must_use = "a denied backend start must be recorded as terminal not_started"]
pub(crate) struct ConsultationBackendStartDenied {
    dispatch: Option<AuditedConsultationDispatch>,
}

impl PreparedAuditedConsultationDispatch {
    /// Check decision freshness once at the last possible point, then enter
    /// the whole bounded backend executor. No timeless authorization marker or
    /// independently replaceable dispatch escapes this method.
    pub(crate) async fn run_backend<T, F>(
        self,
        backend: F,
    ) -> Result<ExecutedAuditedConsultationDispatch<T>, ConsultationBackendStartDenied>
    where
        F: for<'dispatch> FnOnce(
            &'dispatch mut AuditedConsultationDispatch,
        ) -> Pin<
            Box<dyn Future<Output = ValidatedConsultationBackendResult<T>> + Send + 'dispatch>,
        >,
    {
        let Self {
            mut dispatch,
            dispatch_freshness,
        } = self;
        if dispatch_freshness.check_fresh_now().is_err() {
            return Err(ConsultationBackendStartDenied {
                dispatch: Some(dispatch),
            });
        }
        let validated = backend(&mut dispatch).await;
        Ok(ExecutedAuditedConsultationDispatch {
            dispatch: Some(dispatch),
            validated,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_dispatch_for_state_test(self) -> AuditedConsultationDispatch {
        self.dispatch
    }
}

/// Nonconstructible move view used only by terminal state-plane methods.
pub(crate) struct TerminalConsultationStateView<'dispatch> {
    dispatch: &'dispatch mut Option<AuditedConsultationDispatch>,
}

impl TerminalConsultationStateView<'_> {
    pub(crate) fn dispatch_mut(&mut self) -> Option<&mut AuditedConsultationDispatch> {
        self.dispatch.as_mut()
    }

    pub(crate) fn take_dispatch(&mut self) -> Option<AuditedConsultationDispatch> {
        self.dispatch.take()
    }
}

impl<T> ExecutedAuditedConsultationDispatch<T> {
    fn into_parts(
        self,
    ) -> (
        Option<AuditedConsultationDispatch>,
        ValidatedConsultationBackendResult<T>,
    ) {
        (self.dispatch, self.validated)
    }
}

impl ConsultationBackendStartDenied {
    fn state_view(&mut self) -> TerminalConsultationStateView<'_> {
        TerminalConsultationStateView {
            dispatch: &mut self.dispatch,
        }
    }
}

impl PostgresDurableAuditStatePlane {
    /// Consume the sealed attempt through the only production persistence path.
    pub(crate) async fn write_attempt_with_completion_intent(
        &self,
        mut prepared: PreparedAtomicConsultationAttempt,
    ) -> Result<PreparedAuditedConsultationDispatch, ConsultationPersistenceError> {
        let dispatch = self
            .write_attempt_with_state_view(prepared.state_view())
            .await?;
        prepared.into_persisted_dispatch(dispatch)
    }

    /// Terminally complete one validated backend result without separating its
    /// structurally sealed dispatch from its output. The keyring runtime mints
    /// a fresh then-current pseudonym authority for each bounded stale retry.
    pub(crate) async fn finalize_validated_consultation<T>(
        &self,
        executed: ExecutedAuditedConsultationDispatch<T>,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
    ) -> Result<FinalizedValidatedConsultation<T>, ConsultationPersistenceError> {
        self.finalize_validated_consultation_inner(
            executed,
            keyring,
            #[cfg(test)]
            None,
        )
        .await
    }

    /// Exercise the exact production known-completion retry loop with one
    /// deterministic pause. No hook exists outside test builds.
    #[cfg(test)]
    pub(crate) async fn finalize_validated_consultation_with_test_hook<T>(
        &self,
        executed: ExecutedAuditedConsultationDispatch<T>,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
        hook: TerminalCompletionTestHook,
    ) -> Result<FinalizedValidatedConsultation<T>, ConsultationPersistenceError> {
        self.finalize_validated_consultation_inner(executed, keyring, Some(hook))
            .await
    }

    async fn finalize_validated_consultation_inner<T>(
        &self,
        executed: ExecutedAuditedConsultationDispatch<T>,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
        #[cfg(test)] mut test_hook: Option<TerminalCompletionTestHook>,
    ) -> Result<FinalizedValidatedConsultation<T>, ConsultationPersistenceError> {
        let (mut dispatch, validated) = executed.into_parts();
        let (publishable_output, completion_facts) = validated.into_parts();
        for _ in 0..MAX_TERMINAL_PSEUDONYM_AUTHORITY_ATTEMPTS {
            let completion_epoch = current_completion_epoch(keyring).await?;
            #[cfg(test)]
            if let Some(hook) = test_hook.as_mut() {
                hook.pause_if(TerminalCompletionTestPoint::AfterAuthorityMinted)
                    .await?;
            }
            match self
                .finalize_validated_consultation_view(
                    TerminalConsultationStateView {
                        dispatch: &mut dispatch,
                    },
                    &completion_facts,
                    completion_epoch,
                    #[cfg(test)]
                    test_hook.as_mut(),
                )
                .await?
            {
                TerminalCompletionAttempt::Completed(disposition) => {
                    return Ok(match disposition {
                        KnownCompletionDisposition::Published(grant) => {
                            FinalizedValidatedConsultation::Published {
                                grant,
                                output: publishable_output,
                            }
                        }
                        KnownCompletionDisposition::FinalizedFailure(receipt) => {
                            FinalizedValidatedConsultation::FinalizedFailure(receipt)
                        }
                    });
                }
                TerminalCompletionAttempt::PseudonymAuthorityStale => {}
            }
        }
        Err(ConsultationPersistenceError::Unavailable)
    }

    /// Record an expired pre-backend decision as `not_started` while retaining
    /// the exact structurally sealed dispatch that the attempt CAS returned.
    /// The keyring runtime mints a fresh then-current pseudonym authority for
    /// each bounded stale retry.
    pub(crate) async fn close_unfinished_consultation(
        &self,
        denied: ConsultationBackendStartDenied,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
    ) -> Result<ConsultationCompletionReceipt, ConsultationPersistenceError> {
        self.close_unfinished_consultation_inner(
            denied,
            keyring,
            #[cfg(test)]
            None,
        )
        .await
    }

    /// Exercise the exact production retry loop with one deterministic pause.
    /// No hook type or alternate terminal path exists outside test builds.
    #[cfg(test)]
    pub(crate) async fn close_unfinished_consultation_with_test_hook(
        &self,
        denied: ConsultationBackendStartDenied,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
        hook: TerminalCompletionTestHook,
    ) -> Result<ConsultationCompletionReceipt, ConsultationPersistenceError> {
        self.close_unfinished_consultation_inner(denied, keyring, Some(hook))
            .await
    }

    async fn close_unfinished_consultation_inner(
        &self,
        mut denied: ConsultationBackendStartDenied,
        keyring: &PostgresAuditPseudonymKeyringRuntime,
        #[cfg(test)] mut test_hook: Option<TerminalCompletionTestHook>,
    ) -> Result<ConsultationCompletionReceipt, ConsultationPersistenceError> {
        for _ in 0..MAX_TERMINAL_PSEUDONYM_AUTHORITY_ATTEMPTS {
            let completion_epoch = current_completion_epoch(keyring).await?;
            #[cfg(test)]
            if let Some(hook) = test_hook.as_mut() {
                hook.pause_if(TerminalCompletionTestPoint::AfterAuthorityMinted)
                    .await?;
            }
            match self
                .close_unfinished_consultation_view(
                    denied.state_view(),
                    completion_epoch,
                    #[cfg(test)]
                    test_hook.as_mut(),
                )
                .await?
            {
                TerminalCompletionAttempt::Completed(receipt) => return Ok(receipt),
                TerminalCompletionAttempt::PseudonymAuthorityStale => {}
            }
        }
        Err(ConsultationPersistenceError::Unavailable)
    }
}

async fn current_completion_epoch(
    keyring: &PostgresAuditPseudonymKeyringRuntime,
) -> Result<ActiveAuditPseudonymWriteEpoch, ConsultationPersistenceError> {
    keyring
        .current_write_authority()
        .await
        .map_err(|_| ConsultationPersistenceError::Unavailable)?
        .authorize_use()
        .map_err(|_| ConsultationPersistenceError::Unavailable)
}

/// Seal the exact audit write, completion seed, commitment bundle, and current
/// PostgreSQL pseudonym authority into one atomic-CAS input.
pub(crate) fn prepare_atomic_consultation_attempt(
    consultation_id: ConsultationId,
    notary_evaluation_id: Option<NotaryEvaluationId>,
    attempt: AuthorizedConsultationAttempt<'_>,
    fence: FencedConsultationAttemptAuthority,
) -> Result<PreparedAtomicConsultationAttempt, ConsultationAuditBuildError> {
    attempt.ensure_preparation_fresh()?;
    let seed = RuntimeConsultationCompletionSeed::build(&attempt, notary_evaluation_id)?;
    let compiled_timeout_ms = attempt.profile().effective_limits().operation().timeout_ms;
    let audit_write = build_attempt_audit_write(consultation_id, &seed, attempt.pseudonyms())?;
    let pseudonym_bundle_value = json!({
        "commitment_key_id": attempt.pseudonyms().key_id.as_str(),
        "subject_handle": attempt.pseudonyms().subject_handle.as_str(),
        "input_commitment": attempt.pseudonyms().input_commitment.as_str(),
        "predicate_commitment": attempt.pseudonyms().predicate_commitment.as_str(),
        "consent_evidence_commitment": attempt
            .pseudonyms()
            .consent_evidence_commitment
            .as_ref()
            .map(|commitment| commitment.as_str()),
    });
    let pseudonym_bundle = CanonicalPseudonymBundle {
        key_id: attempt.pseudonyms().key_id.as_str().to_owned(),
        binding: canonical_state_binding(pseudonym_bundle_value)?,
    };
    let completion_seed = canonical_state_binding(seed.into_safe_value())?;
    let (pseudonyms, persistence_freshness, dispatch_freshness) =
        attempt.into_pseudonyms_and_freshness_guards();
    let PreparedConsultationPseudonyms { active_epoch, .. } = pseudonyms;
    Ok(PreparedAtomicConsultationAttempt {
        audit_write,
        completion_seed,
        pseudonym_bundle,
        active_epoch,
        persistence_freshness,
        dispatch_freshness,
        compiled_timeout_ms,
        fence: Some(fence),
    })
}

fn canonical_state_binding(
    value: Value,
) -> Result<CanonicalStateBinding, ConsultationAuditBuildError> {
    let canonical =
        canonicalize_json(&value).map_err(|_| ConsultationAuditBuildError::Canonicalization)?;
    let digest = Sha256::digest(&canonical).into();
    let canonical =
        String::from_utf8(canonical).map_err(|_| ConsultationAuditBuildError::Canonicalization)?;
    Ok(CanonicalStateBinding { canonical, digest })
}

const fn source_plan_kind_str(kind: crate::source_plan::SourcePlanKind) -> &'static str {
    match kind {
        crate::source_plan::SourcePlanKind::SnapshotExact => "snapshot_exact",
        crate::source_plan::SourcePlanKind::BoundedHttp => "bounded_http",
        crate::source_plan::SourcePlanKind::SandboxedRhai => "sandboxed_rhai",
    }
}

const fn acquisition_class_str(class: AcquisitionClass) -> &'static str {
    match class {
        AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use registry_platform_audit::pseudonym_keyring::{
        AuditPseudonymKeyId, AuditPseudonymKeyMaterial,
    };
    use registry_platform_crypto::parse_json_strict;
    use zeroize::Zeroizing;

    use super::*;
    use crate::consultation::commitments::{
        build_pseudonym_inputs, runtime_digest_chain_for_test, CanonicalConsultationInputs,
        RuntimeDigestChainForTest, RuntimePseudonymPreimagesForTest, VerifiedConsentAuthority,
    };
    use crate::consultation::{
        AuthenticatedConsultationWorkload, ParsedPurpose, ParsedSingleStringInput,
        PreAuthorizationConsultationCore,
    };
    use crate::source_plan::runtime_profile::CompiledConsentProfile;
    use crate::source_plan::{
        bounded_runtime_vector_plan_fixture, consent_runtime_vector_plan_fixture,
        maximum_runtime_profile_fixture, rhai_runtime_vector_plan_fixture, CompiledSourcePlan,
    };

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RUNTIME_VECTOR: &[u8] =
        include_bytes!("../../tests/fixtures/source-plan-v1/runtime-chain-vectors.json");
    const SYNTHETIC_SUBJECT: &str = "SYNTHETIC-SUBJECT-0001";
    const SYNTHETIC_CONSENT_REFERENCE: &str = "SYNTHETIC-CONSENT-0001";
    const COMMITMENT_KEY_ID: &str = "synthetic-epoch-1";
    const MASTER_KEY_BYTE: u8 = 0x42;
    const CONSENT_CHECKED_AT_UNIX_MS: i64 = 1_700_000_000_000;
    const CONSENT_EXPIRES_AT_UNIX_MS: i64 = 1_700_000_060_000;
    const DECISION_EXPIRES_AT_UNIX_MS: i64 = 1_700_000_001_500;
    const AUTHENTICATION_EXPIRES_AT_UNIX_MS: i64 = 1_700_000_002_000;

    #[test]
    fn production_seed_uses_the_exact_seventeen_member_state_shape() {
        let profile = maximum_runtime_profile_fixture();
        let purpose = profile.purposes().next().expect("fixture purpose");
        let digests = ConsultationDigests::from_labels_for_test(DIGEST);
        let seed = RuntimeConsultationCompletionSeed::build_from_parts(
            &profile,
            None,
            purpose,
            VerifiedConsentDecision::not_required_for_test(),
            &digests,
        )
        .expect("typed production seed");
        let object = seed.safe_value().as_object().expect("seed object");
        assert_eq!(object.len(), 17);
        assert_eq!(
            object.get("schema").and_then(Value::as_str),
            Some("registry.relay.consultation-completion-seed/v1")
        );
        assert_eq!(
            object["bounds"]["timeout_ms"].as_u64(),
            Some(u64::from(profile.effective_limits().operation().timeout_ms)),
            "the state seed carries the exact effective timeout"
        );
        assert!(
            canonicalize_json(seed.safe_value()).unwrap().len()
                <= profile.completion_seed_canonical_bytes_max()
        );
    }

    #[test]
    fn production_seed_rejects_an_uncompiled_purpose_without_value_diagnostics() {
        let profile = maximum_runtime_profile_fixture();
        let digests = ConsultationDigests::from_labels_for_test(DIGEST);
        assert!(matches!(
            RuntimeConsultationCompletionSeed::build_from_parts(
                &profile,
                None,
                "unreviewed-purpose",
                VerifiedConsentDecision::not_required_for_test(),
                &digests,
            ),
            Err(ConsultationAuditBuildError::ProfileMismatch)
        ));
    }

    #[test]
    fn atomic_preparation_accepts_only_the_move_only_authorized_aggregate() {
        fn assert_signature(
            _: for<'profile> fn(
                ConsultationId,
                Option<NotaryEvaluationId>,
                AuthorizedConsultationAttempt<'profile>,
                FencedConsultationAttemptAuthority,
            ) -> Result<
                PreparedAtomicConsultationAttempt,
                ConsultationAuditBuildError,
            >,
        ) {
        }

        assert_signature(prepare_atomic_consultation_attempt);
    }

    #[test]
    fn attempt_payload_contains_only_seed_and_keyed_commitment_facts() {
        let payload = attempt_audit_payload(
            &json!({"schema": "registry.relay.consultation-completion-seed/v1"}),
            "epoch-1",
            "hmac-sha256:subject",
            "hmac-sha256:input",
            "hmac-sha256:predicate",
            Some("hmac-sha256:consent"),
        );
        let object = payload.as_object().expect("attempt object");
        assert_eq!(object.len(), 8);
        assert_eq!(
            object.get("schema").and_then(Value::as_str),
            Some("registry.relay.consultation-attempt/v1")
        );
        let canonical = canonicalize_json(&payload).expect("safe canonical attempt");
        let diagnostic = String::from_utf8(canonical).expect("canonical UTF-8");
        for forbidden in [
            "selector",
            "raw_consent_reference",
            "credential_value",
            "origin_url",
            "script_source",
        ] {
            assert!(!diagnostic.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn terminal_completion_test_hook_pauses_at_only_one_selected_boundary() {
        let (mut hook, mut control) =
            terminal_completion_test_hook(TerminalCompletionTestPoint::AfterCandidateSnapshot);
        let hook_driver = async {
            hook.pause_if(TerminalCompletionTestPoint::AfterAuthorityMinted)
                .await?;
            hook.pause_if(TerminalCompletionTestPoint::AfterCandidateSnapshot)
                .await?;
            hook.pause_if(TerminalCompletionTestPoint::AfterCandidateSnapshot)
                .await
        };
        let test_driver = async {
            control.wait_until_paused().await?;
            control.resume()
        };
        let (hook_result, test_result) = tokio::join!(hook_driver, test_driver);
        hook_result.expect("selected test hook resumes and fires only once");
        test_result.expect("test control observes and resumes the selected hook");
    }

    #[test]
    fn portable_runtime_chain_vector_matches_production_preimages_and_digests() {
        let expected = parse_json_strict(RUNTIME_VECTOR).expect("strict runtime vector JSON");
        assert_eq!(runtime_chain_vector_value(), expected);
    }

    #[test]
    #[ignore = "prints the reviewed portable fixture for an intentional vector update"]
    fn print_portable_runtime_chain_vector_for_review() {
        println!("RUNTIME_VECTOR_BEGIN");
        println!(
            "{}",
            serde_json::to_string(&runtime_chain_vector_value())
                .expect("runtime vector serializes")
        );
        println!("RUNTIME_VECTOR_END");
    }

    fn runtime_chain_vector_value() -> Value {
        let key_id = AuditPseudonymKeyId::parse(COMMITMENT_KEY_ID).expect("synthetic key id");
        let material =
            AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![MASTER_KEY_BYTE; 32]))
                .expect("synthetic master key");
        let notary_evaluation_id =
            NotaryEvaluationId::try_parse("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("synthetic ULID");
        let cases = [
            (
                "bounded_http_no_consent",
                bounded_runtime_vector_plan_fixture(),
                None,
            ),
            (
                "sandboxed_rhai_no_consent",
                rhai_runtime_vector_plan_fixture(),
                None,
            ),
            (
                "bounded_http_required_consent",
                consent_runtime_vector_plan_fixture(),
                Some(SYNTHETIC_CONSENT_REFERENCE),
            ),
        ]
        .into_iter()
        .map(|(name, plan, raw_consent_reference)| {
            runtime_chain_case(
                name,
                &plan,
                raw_consent_reference,
                &key_id,
                &material,
                notary_evaluation_id,
            )
        })
        .collect::<Vec<_>>();
        json!({
            "schema": "registry.relay.consultation-runtime-chain-v1",
            "canonicalization": "RFC8785",
            "numeric_domain": "finite-safe-integers-only",
            "synthetic_fixture": true,
            "commitment_key": {
                "id": COMMITMENT_KEY_ID,
                "master_key": {
                    "encoding": "hex",
                    "value": "4242424242424242424242424242424242424242424242424242424242424242",
                },
                "derivation": {
                    "algorithm": "HKDF-Expand-only-HMAC-SHA256",
                    "info_utf8": "registry-platform-audit/audit-pseudonym-key/v1",
                    "output_bytes": 32,
                },
            },
            "framing": {
                "encoding": "UTF-8",
                "separator_hex": "00",
                "shape": "domain_label || 0x00 || RFC8785(value)",
            },
            "cases": cases,
        })
    }

    fn runtime_chain_case(
        name: &str,
        plan: &CompiledSourcePlan,
        raw_consent_reference: Option<&str>,
        key_id: &AuditPseudonymKeyId,
        material: &AuditPseudonymKeyMaterial,
        notary_evaluation_id: NotaryEvaluationId,
    ) -> Value {
        let profile = plan.runtime_profile();
        let core = PreAuthorizationConsultationCore::new_for_test(
            plan.profile().clone(),
            profile.subject().selector_provenance().clone(),
            ParsedPurpose::try_parse("benefit-verification").expect("synthetic purpose"),
            ParsedSingleStringInput::try_parse("subject_id", SYNTHETIC_SUBJECT)
                .expect("synthetic subject"),
            plan.footprint().clone(),
        );
        let inputs = CanonicalConsultationInputs::try_from_resolved_core(plan, core)
            .expect("synthetic core binds to exact plan");
        let preimages = inputs
            .runtime_pseudonym_preimages_for_test(raw_consent_reference)
            .expect("exact pseudonym preimages");
        let authority = match (profile.authorization().consent(), raw_consent_reference) {
            (CompiledConsentProfile::NotRequired, None) => {
                VerifiedConsentAuthority::consent_not_required(inputs)
                    .expect("consent not required")
            }
            (CompiledConsentProfile::Required { .. }, Some(reference)) => {
                VerifiedConsentAuthority::verified_for_test(
                    inputs,
                    Zeroizing::new(reference.to_owned()),
                    CONSENT_CHECKED_AT_UNIX_MS,
                    CONSENT_EXPIRES_AT_UNIX_MS,
                )
                .expect("synthetic consent verified")
            }
            _ => panic!("runtime vector consent shape must match its compiled plan"),
        };
        let pseudonym_inputs =
            build_pseudonym_inputs(authority).expect("production pseudonym input builder");
        let subject_handle = material.consultation_subject_commitment(&pseudonym_inputs.subject);
        let input_commitment = material.consultation_input_commitment(&pseudonym_inputs.input);
        let predicate_commitment =
            material.consultation_predicate_commitment(&pseudonym_inputs.predicate);
        let consent_evidence_commitment = pseudonym_inputs
            .consent_evidence
            .as_ref()
            .map(|input| material.consultation_consent_commitment(input));
        let workload = AuthenticatedConsultationWorkload::for_runtime_vector_test(
            AUTHENTICATION_EXPIRES_AT_UNIX_MS,
        );
        let digest_chain = runtime_digest_chain_for_test(
            profile,
            &workload,
            &pseudonym_inputs.canonical_purpose,
            pseudonym_inputs.consent,
            consent_evidence_commitment.as_ref(),
            DECISION_EXPIRES_AT_UNIX_MS,
            key_id,
            &input_commitment,
            &subject_handle,
            &predicate_commitment,
        )
        .expect("production ordinary digest builders");
        let seed = RuntimeConsultationCompletionSeed::build_from_parts(
            profile,
            Some(notary_evaluation_id),
            &pseudonym_inputs.canonical_purpose,
            pseudonym_inputs.consent,
            &digest_chain.digests,
        )
        .expect("production completion seed builder");
        render_runtime_chain_case(
            name,
            preimages,
            &subject_handle,
            &input_commitment,
            &predicate_commitment,
            consent_evidence_commitment.as_ref(),
            digest_chain,
            seed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn render_runtime_chain_case(
        name: &str,
        preimages: RuntimePseudonymPreimagesForTest,
        subject_handle: &registry_platform_audit::pseudonym_keyring::AuditPseudonymCommitment,
        input_commitment: &registry_platform_audit::pseudonym_keyring::AuditPseudonymCommitment,
        predicate_commitment: &registry_platform_audit::pseudonym_keyring::AuditPseudonymCommitment,
        consent_evidence_commitment: Option<
            &registry_platform_audit::pseudonym_keyring::AuditPseudonymCommitment,
        >,
        digest_chain: RuntimeDigestChainForTest,
        seed: RuntimeConsultationCompletionSeed,
    ) -> Value {
        let RuntimePseudonymPreimagesForTest {
            subject,
            input,
            predicate,
            consent_evidence,
        } = preimages;
        let RuntimeDigestChainForTest {
            authorization_context_preimage,
            execution_plan_preimage,
            request_preimage,
            digests,
        } = digest_chain;
        let consent = match (consent_evidence, consent_evidence_commitment) {
            (Some(preimage), Some(commitment)) => Some(framed_chain_member(
                "registry.relay.consultation-consent.v1",
                preimage,
                commitment.as_str(),
            )),
            (None, None) => None,
            _ => panic!("consent commitment must match its exact preimage"),
        };
        json!({
            "name": name,
            "hmac_commitments": {
                "subject": framed_chain_member(
                    "registry.relay.consultation-subject.v1",
                    subject,
                    subject_handle.as_str(),
                ),
                "input": framed_chain_member(
                    "registry.relay.consultation-input.v1",
                    input,
                    input_commitment.as_str(),
                ),
                "predicate": framed_chain_member(
                    "registry.relay.consultation-predicate.v1",
                    predicate,
                    predicate_commitment.as_str(),
                ),
                "consent": consent,
            },
            "ordinary_digests": {
                "authorization_context": framed_chain_member(
                    "registry.relay.consultation-authorization.v1",
                    authorization_context_preimage,
                    digests.authorization_context().as_str(),
                ),
                "execution_plan": framed_chain_member(
                    "registry.relay.consultation-execution-plan.v1",
                    execution_plan_preimage,
                    digests.execution_plan().as_str(),
                ),
                "authorized_request": framed_chain_member(
                    "registry.relay.authorized-consultation.v1",
                    request_preimage,
                    digests.request().as_str(),
                ),
            },
            "completion_seed": plain_seed_member(seed.safe_value()),
        })
    }

    fn framed_chain_member(domain_label: &str, value: Value, expected: &str) -> Value {
        let canonical_json = String::from_utf8(
            canonicalize_json(&value).expect("runtime vector member canonicalizes"),
        )
        .expect("canonical JSON is UTF-8");
        json!({
            "domain_label": domain_label,
            "value": value,
            "canonical_json": canonical_json,
            "expected": expected,
        })
    }

    fn plain_seed_member(value: &Value) -> Value {
        let canonical = canonicalize_json(value).expect("completion seed canonicalizes");
        json!({
            "value": value,
            "canonical_json": String::from_utf8(canonical.clone())
                .expect("canonical seed JSON is UTF-8"),
            "canonical_bytes": canonical.len(),
            "expected_digest": sha256_label(&canonical),
        })
    }

    fn sha256_label(bytes: &[u8]) -> String {
        let mut label = String::from("sha256:");
        for byte in Sha256::digest(bytes) {
            write!(&mut label, "{byte:02x}").expect("writing to String is infallible");
        }
        label
    }
}
