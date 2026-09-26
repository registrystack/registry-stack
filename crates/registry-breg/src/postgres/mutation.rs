// SPDX-License-Identifier: Apache-2.0

//! Concrete PostgreSQL mutation runtime for the compiled HTTP surface.

use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::{
    ActionTargetConditionsInput, AuthorizedActionContext, AuthorizedRequestContext,
    BatchMutationInput, ConditionalMutationInput, CreateMutationInput, HeldReadResponse,
    ImmediateActionInput, RowBoundaryOperator as ApiRowBoundaryOperator, VerifiedRowBoundary,
};
use crate::audit::{record_http_refusal_audit, HttpRefusalAudit, RegistryAudit};
use crate::correlation::RequestCorrelation;
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::ingestion_store::{self, IngestionAttemptOutcome, IngestionRunStatus};
use crate::model::CompiledRegistry;
#[cfg(feature = "postgres-test")]
use crate::mutation::MutationFaultPoint;
use crate::mutation::{
    valid_strong_etag, BatchMutationItem, BatchMutationRequest, IngestionChunkBinding,
    MutationBody, MutationCoordinator, MutationError, MutationOutcome, MutationPlan,
    MutationRequest, PatchOperation,
};

use super::{
    begin_record_transaction, ActionClaimContext, ClaimContext, ExpectedRegistryIdentity,
    RegistryLockKey, RowBoundaryContext, RuntimePool,
};

const REQUEST_ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_ACTION_CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct PostgresRecordMutationService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    coordinator: MutationCoordinator,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    field_encryption: Option<Arc<crate::field_encryption::FieldEncryptionService>>,
    action_timeout: Duration,
    evidence_timeout: Duration,
    evidence_evaluator: Option<Arc<crate::action_evidence::ActionEvidenceEvaluator>>,
    review_result_source: Option<Arc<dyn crate::review_store::ReviewResultSource>>,
    fault: MutationFaultControl,
}

/// One durable ingestion-run creation as the authenticated surface admits it.
/// The caller keeps the source file and the derived counts; the run keeps the
/// binding and refuses every divergence from it.
pub struct IngestionRunCreateInput {
    pub entity_id: String,
    pub operation: String,
    pub profile_id: String,
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub input_digest: String,
    pub input_length: i64,
    pub item_count: i64,
    pub chunk_count: i64,
    pub chunk_algorithm_version: String,
}

/// One chunk submission against the next expected chunk of a run.
pub struct IngestionChunkSubmitInput {
    pub run_id: Uuid,
    pub entity_id: String,
    pub chunk_index: i64,
    pub items: Vec<Value>,
    pub digest: String,
    pub prefix_digest: String,
}

/// The bounded, creator-scoped listing one caller can see.
pub struct IngestionRunListQuery {
    pub entity_id: String,
    pub status: Option<String>,
    pub input_digest: Option<String>,
    pub after_run_id: Option<Uuid>,
    pub limit: i64,
}

/// A refused ingestion-run call. `answered` is true when the call's refusal
/// is already on record as the `response` of the ingestion `request` entry it
/// wrote, so the caller must not record it again in another schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestionRefusal {
    pub error: IngestionServiceError,
    pub answered: bool,
}

/// What one ingestion-run call has recorded so far: the ingestion `request`
/// entry it wrote, or whether it handed the chunk to the batch mutation,
/// which records its own attempt and refusal.
#[derive(Default)]
struct IngestionAudit {
    run: Option<ingestion_store::RunAttempt>,
    batch: bool,
}

/// The closed refusal vocabulary of the ingestion-run service. It is bounded
/// and value-free: no chunk bytes, row values, or bearer material appear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestionServiceError {
    RequestInvalid,
    PreconditionFailed,
    NotFound,
    ProfileMismatch,
    RunNotOpen,
    RunBlocked,
    ChunkMismatch,
    ReceiptErased,
    Unavailable,
}

impl PostgresRecordMutationService {
    #[must_use]
    pub fn with_task_status(
        mut self,
        checker: Arc<dyn crate::task_grant::TaskGrantStatusChecker>,
    ) -> Self {
        self.coordinator = self.coordinator.with_task_status(checker);
        self
    }

    #[must_use]
    pub fn with_attachment_storage(
        mut self,
        storage: crate::attachment_storage::AttachmentStorage,
    ) -> Self {
        self.coordinator = self.coordinator.with_attachment_storage(storage);
        self
    }
    #[must_use]
    pub fn with_attachment_verification(
        mut self,
        verification: crate::attachment_verification::AttachmentVerification,
    ) -> Self {
        self.coordinator = self.coordinator.with_attachment_verification(verification);
        self
    }

    /// Bind the field-encryption key state record writes seal and open under.
    #[must_use]
    pub fn with_field_encryption(
        mut self,
        service: Arc<crate::field_encryption::FieldEncryptionService>,
    ) -> Self {
        self.field_encryption = Some(Arc::clone(&service));
        self.coordinator = self.coordinator.with_field_encryption(service);
        self
    }

    /// Bind operator-approved Evidence clients for v2 immediate action handlers.
    #[must_use]
    pub fn with_evidence_evaluator(
        mut self,
        evaluator: Arc<crate::action_evidence::ActionEvidenceEvaluator>,
    ) -> Self {
        self.evidence_evaluator = Some(evaluator);
        self
    }

    #[must_use]
    pub fn with_review_result_source(
        mut self,
        source: Arc<crate::review_store::ReviewAuthorityRegistry>,
    ) -> Self {
        self.coordinator = self
            .coordinator
            .with_review_authorities(Arc::clone(&source));
        self.review_result_source = Some(source);
        self
    }

    /// Keep the evidence lifecycle within the outer HTTP request budget.
    #[must_use]
    pub(crate) fn with_evidence_timeout(mut self, timeout: Duration) -> Self {
        self.evidence_timeout = timeout.min(self.action_timeout);
        self
    }

    pub async fn invoke_action(
        &self,
        input: ImmediateActionInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        // One deadline includes admission, every queue/pool wait, external
        // processing and all SQL attempts. No phase can renew the budget.
        let started = tokio::time::Instant::now();
        let claims = strict_action_context(input.context, input.action_id)?;
        let target_authority = strict_action_target_authority(input.context)?;
        let fault = match self.fault {
            #[cfg(feature = "postgres-test")]
            MutationFaultControl::At(point) => crate::mutation::FaultControl::At(point),
            _ => crate::mutation::FaultControl::Disabled,
        };
        let is_evidence = self
            .registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == input.action_id)
            .and_then(|action| action.handler.as_ref())
            .is_some_and(|handler| handler.abi == "registry.action-handler/v2");
        let deadline = started
            + if is_evidence {
                self.evidence_timeout.min(self.action_timeout)
            } else {
                self.action_timeout
            };
        if is_evidence {
            return tokio::time::timeout_at(
                deadline,
                self.invoke_evidence_action(input, &claims, &target_authority, fault, deadline),
            )
            .await
            .unwrap_or(Err(MutationError::Unavailable));
        }
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| MutationError::Unavailable)?
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        match tokio::time::timeout_at(
            deadline,
            self.coordinator.execute_immediate_action(
                guard.client(),
                &self.registry,
                input,
                &claims,
                &target_authority,
                fault,
                deadline,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        }
    }

    async fn invoke_evidence_action(
        &self,
        input: ImmediateActionInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &std::collections::BTreeMap<String, Vec<RowBoundaryContext>>,
        fault: crate::mutation::FaultControl,
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        let evaluator = self
            .evidence_evaluator
            .as_ref()
            .ok_or(MutationError::Unavailable)?;
        let route_id = input.route_id;
        let correlation = input.correlation;
        let prepared = {
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
            let result = self
                .coordinator
                .preflight_evidence_action(
                    guard.client(),
                    &self.registry,
                    input,
                    claims,
                    target_authority,
                    deadline,
                )
                .await;
            if result.is_err() && tokio::time::Instant::now() < deadline {
                self.coordinator
                    .record_action_boundary_audit(
                        claims,
                        route_id,
                        correlation,
                        crate::audit::PreIoAuditKind::Refusal,
                    )
                    .await?;
            }
            guard.disarm();
            match result? {
                Ok(prepared) => prepared,
                Err(receipt) => return Ok(receipt),
            }
        }; // Drop the entire pooled connection before evaluation or acquisition.
        let frozen = evaluator
            .evaluate(
                prepared.action.clone(),
                prepared.inputs.clone(),
                deadline.into_std(),
            )
            .await;
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        // Receipt recovery is deliberately also performed for refusals and
        // dependency failures. A concurrent committed application takes priority.
        let result = self
            .coordinator
            .finalize_evidence_action(
                guard.client(),
                &self.registry,
                &prepared,
                &frozen,
                claims,
                target_authority,
                route_id,
                correlation,
                fault,
                deadline,
            )
            .await;
        guard.disarm();
        result
    }

    pub async fn action_target_conditions(
        &self,
        input: ActionTargetConditionsInput<'_>,
    ) -> Result<HeldReadResponse, MutationError> {
        let claims = strict_action_context(input.context, input.action_id)?;
        let target_authority = strict_action_target_authority(input.context)?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        match tokio::time::timeout(
            self.action_timeout,
            self.coordinator.action_target_conditions(
                guard.client(),
                &self.registry,
                input,
                &claims,
                &target_authority,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        }
    }

    pub async fn request_action(
        &self,
        input: crate::api::RequestActionInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let is_evidence_apply = matches!(input.action, crate::api::RequestActionBody::Apply { .. })
            && self
                .registry
                .entities()
                .get(input.entity_id)
                .and_then(|entity| entity.change_request.as_ref())
                .is_some_and(|plan| !plan.application.preconditions.evidence.is_empty());
        let is_reviewed_apply = matches!(input.action, crate::api::RequestActionBody::Apply { .. })
            && self
                .registry
                .entities()
                .get(input.entity_id)
                .and_then(|entity| entity.change_request.as_ref())
                .is_some_and(|plan| {
                    matches!(
                        plan.review,
                        crate::model::CompiledChangeRequestReview::Required(_)
                    )
                });
        if is_reviewed_apply {
            return self
                .request_reviewed_apply(input, &claims, is_evidence_apply)
                .await;
        }
        if is_evidence_apply {
            return self
                .request_evidence_apply(input, &claims, None, None)
                .await;
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let fault = match self.fault {
            #[cfg(feature = "postgres-test")]
            MutationFaultControl::At(point) => crate::mutation::FaultControl::At(point),
            _ => crate::mutation::FaultControl::Disabled,
        };
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        match tokio::time::timeout(
            REQUEST_ACTION_TIMEOUT,
            self.coordinator.execute_request_action(
                guard.client(),
                &self.registry,
                input,
                &claims,
                fault,
                None,
                None,
                false,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        }
    }

    async fn request_evidence_apply(
        &self,
        input: crate::api::RequestActionInput<'_>,
        claims: &ClaimContext,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        attempt: Option<registry_platform_audit::AuditRequest>,
    ) -> Result<MutationOutcome, MutationError> {
        // The request's attempt, held until the action answers it: the
        // reviewed apply that routes here has already recorded it, and the
        // preflight records it otherwise.
        let mut attempt = attempt;
        let evaluator = self
            .evidence_evaluator
            .as_ref()
            .ok_or(MutationError::Unavailable)?;
        let deadline =
            tokio::time::Instant::now() + self.evidence_timeout.min(REQUEST_ACTION_TIMEOUT);
        let fault = match self.fault {
            #[cfg(feature = "postgres-test")]
            MutationFaultControl::At(point) => crate::mutation::FaultControl::At(point),
            _ => crate::mutation::FaultControl::Disabled,
        };
        let preflight = {
            let client = tokio::time::timeout_at(deadline, self.pool.get())
                .await
                .map_err(|_| MutationError::Unavailable)?
                .map_err(|_| MutationError::Unavailable)?;
            let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
            let result = tokio::time::timeout_at(deadline, async {
                let result = self
                    .coordinator
                    .preflight_request_evidence_apply(
                        guard.client(),
                        &self.registry,
                        &input,
                        claims,
                        deadline,
                        &mut attempt,
                    )
                    .await;
                if result.is_err() && tokio::time::Instant::now() < deadline {
                    self.coordinator
                        .record_request_boundary_refusal(&self.registry, &input, claims)
                        .await?;
                }
                result
            })
            .await;
            match result {
                Ok(result) => {
                    guard.disarm();
                    result?
                }
                Err(_) => {
                    guard.cancel_and_discard().await;
                    return Err(MutationError::Unavailable);
                }
            }
        }; // The complete pool checkout is dropped before remote Evidence I/O.
        let acquisitions = match preflight {
            crate::mutation::RequestEvidencePreflight::Receipt => None,
            crate::mutation::RequestEvidencePreflight::Acquire(requests) => Some(
                evaluator
                    .acquire_preconditions(requests, deadline.into_std())
                    .await,
            ),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        let client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| MutationError::Unavailable)?
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        // A concurrent committed receipt takes priority over a failed helper.
        let frozen = acquisitions
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let result = match tokio::time::timeout_at(
            deadline,
            self.coordinator.execute_request_action(
                guard.client(),
                &self.registry,
                input,
                claims,
                fault,
                review_evidence,
                frozen.map(Vec::as_slice),
                true,
            ),
        )
        .await
        {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                return Err(MutationError::Unavailable);
            }
        };
        match (result, acquisitions) {
            (Ok(outcome), _) => Ok(outcome),
            (
                Err(MutationError::PreconditionFailed | MutationError::Conflict),
                Some(Err(acquisition_error)),
            ) => Err(acquisition_error),
            (Err(error), _) => Err(error),
        }
    }

    async fn request_reviewed_apply(
        &self,
        input: crate::api::RequestActionInput<'_>,
        claims: &ClaimContext,
        needs_action_evidence: bool,
    ) -> Result<MutationOutcome, MutationError> {
        let deadline = tokio::time::Instant::now() + REQUEST_ACTION_TIMEOUT;
        let fault = match self.fault {
            #[cfg(feature = "postgres-test")]
            MutationFaultControl::At(point) => crate::mutation::FaultControl::At(point),
            _ => crate::mutation::FaultControl::Disabled,
        };
        // The attempt precedes the receipt preflight's reads, the review
        // authority, and the action transaction, and is held across them.
        let attempt = tokio::time::timeout_at(
            deadline,
            self.coordinator
                .begin_request_action_audit(&self.registry, &input, claims),
        )
        .await
        .map_err(|_| MutationError::Unavailable)??;
        let receipt_preflight = {
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
            let result = tokio::time::timeout_at(
                deadline,
                self.coordinator.preflight_request_action_receipt(
                    guard.client(),
                    &self.registry,
                    &input,
                    claims,
                ),
            )
            .await;
            match result {
                Ok(Ok(preflight)) => {
                    guard.disarm();
                    preflight
                }
                Ok(Err(error)) => {
                    guard.disarm();
                    tokio::time::timeout_at(
                        deadline,
                        self.coordinator.record_request_boundary_refusal(
                            &self.registry,
                            &input,
                            claims,
                        ),
                    )
                    .await
                    .map_err(|_| MutationError::Unavailable)??;
                    return Err(error);
                }
                Err(_) => {
                    guard.cancel_and_discard().await;
                    return Err(MutationError::Unavailable);
                }
            }
        };
        let proposal_authority = match receipt_preflight {
            crate::mutation::RequestReceiptPreflight::Continue { proposal_authority } => {
                proposal_authority
            }
            crate::mutation::RequestReceiptPreflight::Receipt => {
                let client = self
                    .pool
                    .get()
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
                let result = tokio::time::timeout_at(
                    deadline,
                    self.coordinator.execute_request_action(
                        guard.client(),
                        &self.registry,
                        input,
                        claims,
                        fault,
                        None,
                        None,
                        true,
                    ),
                )
                .await;
                return match result {
                    Ok(result) => {
                        guard.disarm();
                        result
                    }
                    Err(_) => {
                        guard.cancel_and_discard().await;
                        Err(MutationError::Unavailable)
                    }
                };
            }
        };
        let crate::api::RequestActionBody::Apply {
            proposal_version,
            ref effect_digest,
            ..
        } = input.action
        else {
            return Err(MutationError::InvalidRequest);
        };
        let request_id =
            uuid::Uuid::parse_str(input.record_id).map_err(|_| MutationError::InvalidRequest)?;
        let (authority, accepted) = {
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let (authority, accepted) = crate::review_store::load_accepted_binding(
                &**client,
                input.entity_id,
                request_id,
                i64::from(proposal_version),
                effect_digest,
            )
            .await?;
            (authority, accepted)
        };
        // A guard acquisition is a protected disclosure too. Check both the
        // current actor and the authority frozen at submission before the
        // review authority is contacted.
        let task_authority = async {
            if let Some(grant) = claims.task_grant() {
                self.coordinator.check_task_authority(grant).await?;
            }
            if let Some(grant) = proposal_authority.as_deref() {
                self.coordinator.check_task_authority(grant).await?;
            }
            Ok::<(), MutationError>(())
        }
        .await;
        if let Err(error) = task_authority {
            // The refusal answers the held attempt, the same as a refused
            // evidence-apply preflight.
            tokio::time::timeout_at(
                deadline,
                self.coordinator
                    .record_request_boundary_refusal(&self.registry, &input, claims),
            )
            .await
            .map_err(|_| MutationError::Unavailable)??;
            return Err(error);
        }
        let source = self
            .review_result_source
            .as_ref()
            .ok_or(MutationError::Unavailable)?;
        let review_evidence = source.approved_evidence(&authority, &accepted).await?;
        if needs_action_evidence {
            return self
                .request_evidence_apply(input, claims, Some(&review_evidence), Some(attempt))
                .await;
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let mut guard = RequestActionCancellationGuard::new(self.pool.clone(), client);
        let result = tokio::time::timeout_at(
            deadline,
            self.coordinator.execute_request_action(
                guard.client(),
                &self.registry,
                input,
                claims,
                fault,
                Some(&review_evidence),
                None,
                true,
            ),
        )
        .await;
        match result {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => {
                guard.cancel_and_discard().await;
                Err(MutationError::Unavailable)
            }
        }
    }
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
    ) -> Self {
        Self::new_with_event_destinations(
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit,
            None,
        )
    }

    #[must_use]
    pub fn new_with_event_destinations(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
        event_destinations: Option<Arc<ActivatedEventDestinationRegistry>>,
    ) -> Self {
        let coordinator = MutationCoordinator::new_with_event_destinations(
            lock_key,
            lock_timeout,
            expected.clone(),
            audit.clone(),
            event_destinations,
        );
        Self {
            pool,
            registry,
            coordinator,
            expected,
            lock_key,
            lock_timeout,
            audit,
            field_encryption: None,
            action_timeout: REQUEST_ACTION_TIMEOUT,
            evidence_timeout: REQUEST_ACTION_TIMEOUT,
            evidence_evaluator: None,
            review_result_source: None,
            fault: MutationFaultControl::Disabled,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_action_timeout_for_test(mut self, timeout: Duration) -> Self {
        self.action_timeout = timeout;
        self
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: MutationFaultPoint) -> Self {
        self.fault = MutationFaultControl::At(fault);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_refusal_audit_fault_for_test(mut self) -> Self {
        self.fault = MutationFaultControl::RefusalAudit;
        self
    }

    pub(crate) async fn record_refusal(
        &self,
        event: HttpRefusalAudit<'_>,
    ) -> Result<(), MutationError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self.fault, MutationFaultControl::RefusalAudit) {
            return Err(MutationError::Unavailable);
        }
        record_http_refusal_audit(&self.audit, &self.expected, event)
            .await
            .map_err(MutationError::from)
    }

    pub(crate) async fn record_attachment_refusal(
        &self,
        event: HttpRefusalAudit<'_>,
        slot_id: &str,
    ) -> Result<(), MutationError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self.fault, MutationFaultControl::RefusalAudit) {
            return Err(MutationError::Unavailable);
        }
        crate::audit::record_attachment_http_refusal_audit(
            &self.audit,
            &self.expected,
            event,
            slot_id,
        )
        .await
        .map_err(MutationError::from)
    }

    pub(crate) async fn record_action_refusal<'a>(
        &self,
        action_id: &'a str,
        mut event: HttpRefusalAudit<'a>,
    ) -> Result<(), MutationError> {
        event.action_id = Some(action_id);
        event.target_record = None;
        self.record_refusal(event).await
    }

    pub async fn create(
        &self,
        input: CreateMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, input.route_id)?;
        self.execute_request(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key: input.idempotency_key,
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(input.data),
                response_fields: input.response_fields,
                representation: input.representation,
                correlation: input.correlation.clone(),
            },
        )
        .await
    }

    pub async fn patch(
        &self,
        input: ConditionalMutationInput<'_>,
        patch: Vec<PatchOperation>,
    ) -> Result<MutationOutcome, MutationError> {
        self.conditional_mutation(input, MutationBody::Patch(patch))
            .await
    }

    pub async fn attachment(
        &self,
        input: ConditionalMutationInput<'_>,
        attachment: crate::attachment::AttachmentMutation,
    ) -> Result<MutationOutcome, MutationError> {
        self.conditional_mutation(input, MutationBody::Attachment(attachment))
            .await
    }

    pub async fn batch(
        &self,
        input: BatchMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, input.route_id)?;
        let request = BatchMutationRequest {
            plan: &plan,
            idempotency_key: input.idempotency_key,
            claims: &claims,
            change_context: input.change_context,
            items: input.items,
            response_fields: input.response_fields,
            body_bytes: input.body_bytes,
            correlation: input.correlation.clone(),
            ingestion: None,
        };
        #[cfg(feature = "postgres-test")]
        if let MutationFaultControl::At(fault) = self.fault {
            return self
                .coordinator
                .execute_batch_with_fault(&mut client, request, fault)
                .await;
        }
        self.coordinator.execute_batch(&mut client, request).await
    }

    /// Parse one chunk item exactly as the compiled batch route parses its
    /// own item members, so a run chunk and a direct batch submission of the
    /// same bytes execute the same mutation.
    fn parse_ingestion_item(item: &Value) -> Option<BatchMutationItem> {
        let object = item.as_object()?;
        match object.get("operation").and_then(Value::as_str) {
            Some("create")
                if object.len() == 2 && object.get("data").is_some_and(Value::is_object) =>
            {
                Some(BatchMutationItem::Create(
                    object.get("data")?.as_object()?.clone(),
                ))
            }
            Some("patch")
                if object.len() == 4
                    && object.contains_key("recordId")
                    && object.contains_key("ifMatch")
                    && object.contains_key("patch") =>
            {
                let record_id = object.get("recordId")?.as_str()?;
                let expected_etag = object.get("ifMatch")?.as_str()?;
                if !Uuid::parse_str(record_id).is_ok_and(|id| id.to_string() == record_id)
                    || !valid_strong_etag(expected_etag)
                {
                    return None;
                }
                let patch =
                    crate::mutation::parse_json_patch_document(object.get("patch")?.clone())
                        .ok()?;
                Some(BatchMutationItem::Patch {
                    record_id: record_id.to_owned(),
                    expected_etag: expected_etag.to_owned(),
                    patch,
                })
            }
            _ => None,
        }
    }

    /// The creator-scoped principal reference of one ingestion caller. The
    /// scope is the database, stable across package revisions, so a run stays
    /// visible to its creator across a package change instead of silently
    /// disappearing, and the same principal in another database yields an
    /// unrelated reference.
    fn ingestion_principal_reference(
        &self,
        principal: &str,
    ) -> Result<String, IngestionServiceError> {
        self.audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-ingestion-principal-v1",
                &self.expected.database_id,
                principal,
            )
            .map_err(|_| IngestionServiceError::Unavailable)
    }

    /// The keyed reference of the claim context one run is bound to. It
    /// covers the same members an ordinary mutation's idempotency binding
    /// covers, with the database rather than the package revision as its
    /// scope, so a committed chunk's replay still answers across a package
    /// change while a drifted context cannot replay or continue the run.
    fn ingestion_context_reference(
        &self,
        claims: &ClaimContext,
    ) -> Result<String, IngestionServiceError> {
        ingestion_context_reference(self.audit.profile(), &self.expected.database_id, claims)
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, IngestionServiceError> {
        self.pool
            .get()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)
    }

    /// Load one run its creator asks about. Anything else, including a run id
    /// belonging to another caller or entity, answers not found: possession
    /// of a run id grants nothing.
    async fn visible_run(
        &self,
        client: &impl tokio_postgres::GenericClient,
        context: &AuthorizedRequestContext,
        entity_id: &str,
        run_id: Uuid,
    ) -> Result<ingestion_store::IngestionRunRecord, IngestionServiceError> {
        let claims = strict_claim_context(&self.registry, context, entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        let principal_reference = self.ingestion_principal_reference(principal)?;
        let run = ingestion_store::load_run(client, run_id)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?
            .ok_or(IngestionServiceError::NotFound)?;
        if run.entity_id != entity_id || run.created_principal_reference != principal_reference {
            return Err(IngestionServiceError::NotFound);
        }
        Ok(run)
    }

    /// Record the bounded outcome of one refused attempt. The operational hint
    /// is best-effort: a failure to persist it is dropped rather than masking
    /// the original answer. Service-level refusals carry no refusal audit of
    /// their own, matching the ordinary mutation surface.
    async fn record_ingestion_attempt(
        &self,
        client: &impl tokio_postgres::GenericClient,
        run_id: Uuid,
        outcome: IngestionAttemptOutcome,
        chunk_index: i64,
    ) {
        let _ = ingestion_store::record_attempt(client, run_id, outcome, chunk_index).await;
    }

    /// Render one run against the binding that decides it. Callers pass the
    /// package identity the database holds active, never the process's own:
    /// a stale instance must report runs the way the durable state sees
    /// them, not the way its retired identity wishes it did.
    fn run_response(run: &ingestion_store::IngestionRunRecord, active: (&str, &str)) -> Value {
        run.response_json(active.0, active.1)
    }

    /// Open one ingestion run.
    pub async fn create_ingestion_run(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionRunCreateInput,
    ) -> Result<Value, IngestionRefusal> {
        let mut attempt = IngestionAudit::default();
        let result = self
            .create_ingestion_run_in(context, correlation, input, &mut attempt)
            .await;
        Self::settle_ingestion(result, attempt).await
    }

    /// Cancel one open ingestion run.
    pub async fn cancel_ingestion_run(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity_id: &str,
        run_id: Uuid,
    ) -> Result<Value, IngestionRefusal> {
        let mut attempt = IngestionAudit::default();
        let result = self
            .cancel_ingestion_run_in(context, correlation, entity_id, run_id, &mut attempt)
            .await;
        Self::settle_ingestion(result, attempt).await
    }

    /// Submit one chunk of an open ingestion run.
    pub async fn submit_ingestion_chunk(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionChunkSubmitInput,
    ) -> Result<Value, IngestionRefusal> {
        let mut attempt = IngestionAudit::default();
        let result = self
            .submit_ingestion_chunk_in(context, correlation, input, &mut attempt)
            .await;
        Self::settle_ingestion(result, attempt).await
    }

    /// Recover the retained receipt of one committed chunk.
    pub async fn ingestion_chunk_receipt(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity_id: &str,
        run_id: Uuid,
        chunk_index: i64,
    ) -> Result<Value, IngestionRefusal> {
        let mut attempt = IngestionAudit::default();
        let result = self
            .ingestion_chunk_receipt_in(
                context,
                correlation,
                entity_id,
                run_id,
                chunk_index,
                &mut attempt,
            )
            .await;
        Self::settle_ingestion(result, attempt).await
    }

    /// Answer the ingestion `request` entry a refused call wrote, in the
    /// ingestion schema, so the refusal is never recorded only in another
    /// schema. A call refused before it wrote one leaves the refusal to its
    /// caller.
    async fn settle_ingestion(
        result: Result<Value, IngestionServiceError>,
        audit: IngestionAudit,
    ) -> Result<Value, IngestionRefusal> {
        let error = match result {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let answered = match audit.run {
            Some(attempt) if attempt.is_answered() => true,
            Some(attempt) => attempt.refuse().await,
            None => audit.batch,
        };
        Err(IngestionRefusal { error, answered })
    }

    /// Create a durable ingestion run bound to the active package revision,
    /// schema fingerprint, entity, profile, operation, input digest, chunking
    /// algorithm, and announced counts.
    async fn create_ingestion_run_in(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionRunCreateInput,
        attempt: &mut IngestionAudit,
    ) -> Result<Value, IngestionServiceError> {
        if !crate::audit::profile_is_keyed(self.audit.profile()) {
            return Err(IngestionServiceError::Unavailable);
        }
        let claims = strict_claim_context(&self.registry, context, &input.entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        if input.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if input.package_revision != self.expected.package_revision
            || input.schema_fingerprint != self.expected.schema_fingerprint
        {
            // The caller planned against a different active package; the run
            // is refused before it exists rather than blocked after.
            return Err(IngestionServiceError::PreconditionFailed);
        }
        if input.chunk_algorithm_version != crate::data::RUN_CHUNK_ALGORITHM_VERSION {
            return Err(IngestionServiceError::RequestInvalid);
        }
        if crate::data::ingestion_batch_route(&self.registry, &input.entity_id, &input.profile_id)
            .is_none()
        {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let entity = self
            .registry
            .entities()
            .get(&input.entity_id)
            .ok_or(IngestionServiceError::RequestInvalid)?;
        let batch = entity
            .batch
            .as_ref()
            .ok_or(IngestionServiceError::RequestInvalid)?;
        // The announced operation must be one the selected profile can
        // execute to the end of every chunk, decided exactly as an import
        // binding is; otherwise the run would linger open while every chunk
        // deterministically fails item authorization.
        let announced = match input.operation.as_str() {
            "create" => crate::data::DataImportOperation::Create,
            "patch" => crate::data::DataImportOperation::Patch,
            _ => return Err(IngestionServiceError::RequestInvalid),
        };
        if !crate::data::ingestion_item_operation_admitted(
            &self.registry,
            entity,
            &input.profile_id,
            announced,
        ) {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let run = ingestion_store::NewIngestionRun {
            created_principal_reference: self.ingestion_principal_reference(principal)?,
            package_revision: input.package_revision,
            schema_fingerprint: input.schema_fingerprint,
            entity_id: input.entity_id,
            operation: input.operation,
            profile_id: input.profile_id,
            bound_context_reference: self.ingestion_context_reference(&claims)?,
            input_digest: input.input_digest,
            input_length: input.input_length,
            item_count: input.item_count,
            chunk_count: input.chunk_count,
            chunk_algorithm_version: input.chunk_algorithm_version,
            maximum_items: i64::from(batch.maximum_items),
            maximum_bytes: i64::from(batch.maximum_bytes),
        };
        ingestion_store::validate_new_run(&run)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let request_correlation = correlation.request_id().to_string();
        // The request entry is accepted before the run is opened: an audit
        // outage refuses the creation instead of opening a run nobody
        // recorded asking for.
        attempt.run = Some(
            ingestion_store::begin_run_request(
                &self.audit,
                ingestion_store::RunRequest {
                    transition: "create",
                    run_id: None,
                    chunk_index: None,
                    package_revision: &self.expected.package_revision,
                    entity_id: &run.entity_id,
                    profile_id: &run.profile_id,
                    principal_reference: &run.created_principal_reference,
                    correlation: &request_correlation,
                },
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?,
        );
        let mut client = self.client().await?;
        // The run binding must name the package the database still holds
        // active, so creation takes the same guarded transaction ordinary
        // mutations take: a stale process cannot open runs under a retired
        // revision while activation is racing it.
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = transaction.transaction();
        let record = ingestion_store::insert_run(tx, &run)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let audit_record = ingestion_store::run_audit_record(
            "created",
            &record,
            &self.expected.package_revision,
            &record.created_principal_reference,
            Some(&request_correlation),
        );
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        // The run exists once the transaction commits; its answer leaves only
        // after the audit entry is accepted.
        ingestion_store::append_run_audit(&self.audit, audit_record)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        // The guarded transaction just proved the durable binding equals
        // this process's identity, so the created run renders under it.
        Ok(Self::run_response(
            &record,
            (
                &self.expected.package_revision,
                &self.expected.schema_fingerprint,
            ),
        ))
    }

    /// List the bounded page of runs one caller created for one entity.
    pub async fn list_ingestion_runs(
        &self,
        context: &AuthorizedRequestContext,
        query: IngestionRunListQuery,
    ) -> Result<Value, IngestionServiceError> {
        let claims = strict_claim_context(&self.registry, context, &query.entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        let principal_reference = self.ingestion_principal_reference(principal)?;
        let context_reference = self.ingestion_context_reference(&claims)?;
        let limit = if query.limit == 0 {
            ingestion_store::DEFAULT_RUN_PAGE_SIZE
        } else {
            query.limit
        };
        if !(0..=ingestion_store::MAX_RUN_PAGE_SIZE).contains(&limit) {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let status = match query.status.as_deref() {
            None | Some("") => None,
            Some(value) => Some(
                IngestionRunStatus::parse(value).ok_or(IngestionServiceError::RequestInvalid)?,
            ),
        };
        let client = self.client().await?;
        let after = match query.after_run_id {
            None => None,
            Some(run_id) => {
                let cursor = ingestion_store::load_run(&**client, run_id)
                    .await
                    .map_err(|_| IngestionServiceError::Unavailable)?
                    .filter(|run| {
                        run.created_principal_reference == principal_reference
                            && run.bound_context_reference == context_reference
                            && run.entity_id == query.entity_id
                    })
                    .ok_or(IngestionServiceError::RequestInvalid)?;
                Some((cursor.created_at, cursor.run_id))
            }
        };
        let page = ingestion_store::list_runs(
            &**client,
            &ingestion_store::IngestionRunListFilter {
                principal_reference: &principal_reference,
                bound_context_reference: &context_reference,
                entity_id: Some(&query.entity_id),
                profile_id: None,
                status,
                input_digest: query.input_digest.as_deref(),
                after,
                limit,
            },
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        // The page carries the binding its effective-status filter ran
        // against, so the rendered runs answer to that same snapshot; a
        // separately fetched binding could already disagree with the rows it
        // would have rendered. That snapshot is also the durable identity
        // check: a page read under a binding this process does not serve
        // answers an outage instead of run metadata a successor's activation
        // already retired. An empty page carries no binding and discloses
        // nothing, so it serves.
        if let Some((revision, fingerprint)) = &page.active_binding {
            if revision != &self.expected.package_revision
                || fingerprint != &self.expected.schema_fingerprint
            {
                return Err(IngestionServiceError::Unavailable);
            }
        }
        let runs = match &page.active_binding {
            Some((revision, fingerprint)) => page
                .runs
                .iter()
                .map(|run| Self::run_response(run, (revision, fingerprint)))
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        let next_after = if page.has_more {
            page.runs
                .last()
                .map(|run| json!(run.run_id.to_string()))
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        Ok(json!({
            "runs": runs,
            "hasMore": page.has_more,
            "nextAfter": next_after,
        }))
    }

    /// Read one run and its next expected chunk index.
    pub async fn read_ingestion_run(
        &self,
        context: &AuthorizedRequestContext,
        entity_id: &str,
        run_id: Uuid,
    ) -> Result<Value, IngestionServiceError> {
        // The read owes the run the same admission chunk submission and
        // receipt recovery owe it: a drifted profile or claim context cannot
        // read a run's binding, digest, counts, and progress it could not
        // continue. The load and the rendering take the same guarded
        // transaction run cancellation takes, so an instance whose package a
        // successor retired refuses the read with an outage instead of
        // answering run metadata under an identity the successor already
        // retired.
        let claims = strict_claim_context(&self.registry, context, entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let mut client = self.client().await?;
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = transaction.transaction();
        let run = self.visible_run(tx, context, entity_id, run_id).await?;
        if run.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if run.bound_context_reference != self.ingestion_context_reference(&claims)? {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        // The guarded transaction just proved the durable binding equals
        // this process's identity, so the run renders under it.
        let response = Self::run_response(
            &run,
            (
                &self.expected.package_revision,
                &self.expected.schema_fingerprint,
            ),
        );
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        Ok(response)
    }

    /// Cancel an open or blocked run, preserving the committed prefix, the
    /// counts, and the audit trail.
    async fn cancel_ingestion_run_in(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity_id: &str,
        run_id: Uuid,
        attempt: &mut IngestionAudit,
    ) -> Result<Value, IngestionServiceError> {
        if !crate::audit::profile_is_keyed(self.audit.profile()) {
            return Err(IngestionServiceError::Unavailable);
        }
        let claims = strict_claim_context(&self.registry, context, entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        let request_correlation = correlation.request_id().to_string();
        // The request entry is accepted before the run is read or closed: an
        // audit outage leaves the run open and resumable.
        attempt.run = Some(
            ingestion_store::begin_run_request(
                &self.audit,
                ingestion_store::RunRequest {
                    transition: "cancel",
                    run_id: Some(run_id),
                    chunk_index: None,
                    package_revision: &self.expected.package_revision,
                    entity_id,
                    profile_id: claims.access_profile(),
                    principal_reference: &self.ingestion_principal_reference(principal)?,
                    correlation: &request_correlation,
                },
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?,
        );
        let mut client = self.client().await?;
        let run = self
            .visible_run(&**client, context, entity_id, run_id)
            .await?;
        // Cancellation owes the run the same admission chunk submission and
        // receipt recovery owe it: a drifted profile or claim context cannot
        // terminate a run it could not continue.
        if run.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if run.bound_context_reference != self.ingestion_context_reference(&claims)? {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        // Cancellation permanently closes an otherwise resumable run, so the
        // write takes the same guarded transaction run creation takes: the
        // registry lock plus the durable identity check inside it leave a
        // stale instance no window to cancel under an identity its successor
        // already retired.
        let transaction = begin_record_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = transaction.transaction();
        let cancelled =
            ingestion_store::cancel_run(tx, run.run_id, IngestionAttemptOutcome::Refused)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::RunNotOpen)?;
        let audit_record = ingestion_store::run_audit_record(
            "cancelled",
            &cancelled,
            &self.expected.package_revision,
            &cancelled.created_principal_reference,
            Some(&request_correlation),
        );
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        ingestion_store::append_run_audit(&self.audit, audit_record)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        // A cancelled run is terminal, so it renders identically under any
        // active binding; the durable pair the open paths fetch is not
        // needed here.
        Ok(Self::run_response(
            &cancelled,
            (
                &self.expected.package_revision,
                &self.expected.schema_fingerprint,
            ),
        ))
    }

    /// Submit the next exact chunk of one run. The server derives the
    /// idempotency key from the run binding, so an interrupted submission
    /// replays the original receipt without a duplicate mutation.
    async fn submit_ingestion_chunk_in(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionChunkSubmitInput,
        attempt: &mut IngestionAudit,
    ) -> Result<Value, IngestionServiceError> {
        let claims = strict_claim_context(&self.registry, context, &input.entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        if input.chunk_index < 0
            || !valid_digest(&input.digest)
            || !valid_digest(&input.prefix_digest)
        {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let principal_reference = self.ingestion_principal_reference(principal)?;
        let client = self.client().await?;
        let run = ingestion_store::load_run(&**client, input.run_id)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?
            .filter(|run| {
                run.entity_id == input.entity_id
                    && run.created_principal_reference == principal_reference
            })
            .ok_or(IngestionServiceError::NotFound)?;
        if run.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if run.bound_context_reference != self.ingestion_context_reference(&claims)? {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        // Every binding decision below answers to the package identity the
        // database holds active, not the one this process started under: a
        // stale instance must report and block runs a successor retired.
        let active = ingestion_store::active_binding(&**client)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        // The submitted items are parsed and canonicalized once, before any
        // branch decides replay or fresh execution, so the announced digest
        // binds the body the caller actually sent in both.
        let items = input
            .items
            .iter()
            .map(Self::parse_ingestion_item)
            .collect::<Option<Vec<_>>>()
            .ok_or(IngestionServiceError::RequestInvalid)?;
        if items.is_empty() {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let (canonical_body, canonical_digest) = crate::data::canonical_chunk_body(&input.items)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let announced_body =
            canonical_digest == input.digest && canonical_body.len() <= run.maximum_bytes as usize;
        if input.chunk_index < run.next_chunk_index {
            // The checkpoint already covers this chunk, so the caller is
            // recovering a lost response: return the stored receipt, never a
            // second mutation. This holds for every terminal status and for
            // a changed active package, because the committed prefix and its
            // receipts survive completion, cancellation, and blocking.
            // A body that does not hash to the digest it announces cannot
            // borrow the retained receipt, whatever digest strings it carries.
            if !announced_body {
                self.record_ingestion_attempt(
                    &**client,
                    run.run_id,
                    IngestionAttemptOutcome::ChunkMismatch,
                    input.chunk_index,
                )
                .await;
                return Err(IngestionServiceError::ChunkMismatch);
            }
            // The replay releases the retained batch answer a second time, so
            // the release takes the same guarded transaction ordinary
            // mutations take: the registry lock plus the durable identity
            // check inside it leave an instance whose package a successor
            // retired no window to serve the receipt under permissions the
            // successor already revoked, while a current instance serves the
            // receipt the committed prefix retains. The stored receipt is
            // read inside that same transaction, after the lock is held: a
            // record-history erasure takes the lock exclusively while it
            // scrubs the receipt, so a release that parks through an erasure
            // re-reads the row after the erasure committed and answers
            // receipt_erased instead of serving the erased values. The
            // replayed attempt marker commits atomically with that check, so
            // a refused release moves no marker and writes no record. The
            // disclosure entry is appended after that commit and before the
            // receipt leaves: an audit outage gates the release instead of
            // passing silently.
            let request_correlation = correlation.request_id().to_string();
            // The request entry is accepted before the release transaction
            // opens: an audit outage moves no attempt marker and releases
            // nothing.
            attempt.run = Some(
                ingestion_store::begin_run_request(
                    &self.audit,
                    ingestion_store::RunRequest {
                        transition: "submitChunk",
                        run_id: Some(run.run_id),
                        chunk_index: Some(input.chunk_index),
                        package_revision: &self.expected.package_revision,
                        entity_id: &run.entity_id,
                        profile_id: &run.profile_id,
                        principal_reference: &principal_reference,
                        correlation: &request_correlation,
                    },
                )
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?,
            );
            let mut disclosure_writer = self.client().await?;
            let disclosure_transaction = begin_record_transaction(
                &mut disclosure_writer,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                &claims,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            let tx: &tokio_postgres::Transaction<'_> = disclosure_transaction.transaction();
            let stored = ingestion_store::load_chunk(tx, run.run_id, input.chunk_index)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::Unavailable)?;
            let replayed =
                stored.chunk_digest == input.digest && stored.prefix_digest == input.prefix_digest;
            if !replayed {
                ingestion_store::record_attempt(
                    tx,
                    run.run_id,
                    IngestionAttemptOutcome::ChunkMismatch,
                    input.chunk_index,
                )
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
                disclosure_transaction
                    .commit()
                    .await
                    .map_err(|_| IngestionServiceError::Unavailable)?;
                return Err(IngestionServiceError::ChunkMismatch);
            }
            if stored.erased && stored.receipt.is_some() {
                // Erasure and the receipt bytes must agree; a row holding
                // both is corruption, and erased material never replays.
                return Err(IngestionServiceError::Unavailable);
            }
            if !stored.committed_shape_is_valid() {
                return Err(IngestionServiceError::Unavailable);
            }
            let Some(receipt) = stored.receipt else {
                return Err(IngestionServiceError::ReceiptErased);
            };
            // A committed receipt always carries the member identities it
            // was produced under; a live row without that map is stored
            // corruption, answered as an outage rather than released.
            let Some(field_bindings) = stored.field_bindings else {
                return Err(IngestionServiceError::Unavailable);
            };
            let mut batch: Value =
                serde_json::from_slice(&receipt).map_err(|_| IngestionServiceError::Unavailable)?;
            // The stored answer answers to the projection the current
            // registry grants the run's profile before the disclosure record
            // commits: each member is retained only when the field identity
            // it was committed under is still a readable field of the
            // current package under the same api name.
            self.project_receipt_readability(
                &input.entity_id,
                &run.profile_id,
                &field_bindings,
                &mut batch,
            )?;
            // The stored answer opens its sealed members before the
            // disclosure record commits, so a process without key state
            // refuses here instead of writing a disclosure record for an
            // answer it cannot serve. The guarded transaction above proved
            // the database holds this process's identity active, so the
            // receipt can carry ciphertext a successor retired only when the
            // run's own binding no longer matches it.
            self.open_receipt_members(
                &input.entity_id,
                !run.active_binding_matches(
                    &self.expected.package_revision,
                    &self.expected.schema_fingerprint,
                ),
                &mut batch,
            )?;
            ingestion_store::record_attempt(
                tx,
                run.run_id,
                IngestionAttemptOutcome::Replayed,
                input.chunk_index,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            let disclosure_record = ingestion_store::receipt_disclosure_record(
                &run,
                input.chunk_index,
                &principal_reference,
                Some(&request_correlation),
            );
            // The attempt row above moved the run's last-attempt marker, so
            // the answer describes the run as it now stands, not as this
            // request found it. It is read inside the release transaction,
            // which sees that row, and the answer is built before the
            // disclosure entry: once that entry is accepted, nothing fallible
            // stands between it and the caller. The guarded transaction
            // proved the durable binding equals this process's identity, so
            // the replayed run renders under it.
            let current = ingestion_store::load_run(tx, run.run_id)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::Unavailable)?;
            let answer = json!({
                "run": Self::run_response(
                    &current,
                    (&self.expected.package_revision, &self.expected.schema_fingerprint),
                ),
                "receipt": receipt_json(input.chunk_index, &input.digest, true, false, batch),
            });
            disclosure_transaction
                .commit()
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            ingestion_store::append_run_audit(&self.audit, disclosure_record)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            return Ok(answer);
        }
        // A terminal run stays terminal when the active package later
        // changes: the blocking transition belongs to open runs alone, so a
        // stale next-chunk submission answers run_not_open and never writes
        // a blocked audit record for a run whose stored status never moved.
        match run.status {
            IngestionRunStatus::Blocked => return Err(IngestionServiceError::RunBlocked),
            IngestionRunStatus::Complete | IngestionRunStatus::Cancelled => {
                return Err(IngestionServiceError::RunNotOpen);
            }
            IngestionRunStatus::Open => {}
        }
        if !run.active_binding_matches(&active.0, &active.1) {
            let request_correlation = correlation.request_id().to_string();
            // The request entry is accepted before the blocking transition
            // opens: an audit outage leaves the run open.
            attempt.run = Some(
                ingestion_store::begin_run_request(
                    &self.audit,
                    ingestion_store::RunRequest {
                        transition: "submitChunk",
                        run_id: Some(run.run_id),
                        chunk_index: Some(input.chunk_index),
                        package_revision: &active.0,
                        entity_id: &run.entity_id,
                        profile_id: &run.profile_id,
                        principal_reference: &principal_reference,
                        correlation: &request_correlation,
                    },
                )
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?,
            );
            let mut writer = self.client().await?;
            let transaction = writer
                .transaction()
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            let tx: &tokio_postgres::Transaction<'_> = &transaction;
            // The blocking transition verifies it changed the row: a
            // cancellation or completion that commits between the plain run
            // read above and this update closes the run first, and the
            // guarded update then changes nothing. Answer the stored status
            // instead of writing a blocked audit record and an attempt
            // marker that would misdescribe a run this request never
            // transitioned.
            let changed = ingestion_store::mark_blocked(
                tx,
                run.run_id,
                ingestion_store::IngestionBlockedReason::ActivePackageChanged,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            if changed == 0 {
                let stored = ingestion_store::load_run(tx, run.run_id)
                    .await
                    .map_err(|_| IngestionServiceError::Unavailable)?
                    .ok_or(IngestionServiceError::Unavailable)?;
                return match stored.status {
                    IngestionRunStatus::Blocked => Err(IngestionServiceError::RunBlocked),
                    IngestionRunStatus::Complete | IngestionRunStatus::Cancelled => {
                        Err(IngestionServiceError::RunNotOpen)
                    }
                    // The guarded update can only miss an open row through a
                    // state the plain read above cannot explain, so the
                    // refusal stays conservative.
                    IngestionRunStatus::Open => Err(IngestionServiceError::Unavailable),
                };
            }
            ingestion_store::record_attempt(
                tx,
                run.run_id,
                IngestionAttemptOutcome::BindingChanged,
                input.chunk_index,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            let mut audited_run = run.clone();
            audited_run.status = IngestionRunStatus::Blocked;
            audited_run.blocked_reason =
                Some(ingestion_store::IngestionBlockedReason::ActivePackageChanged);
            let blocked_record = ingestion_store::run_audit_record(
                "blocked",
                &audited_run,
                &active.0,
                &run.created_principal_reference,
                Some(&request_correlation),
            );
            transaction
                .commit()
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            ingestion_store::append_run_audit(&self.audit, blocked_record)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            return Err(IngestionServiceError::RunBlocked);
        }

        if input.chunk_index > run.next_chunk_index || input.chunk_index >= run.chunk_count {
            self.record_ingestion_attempt(
                &**client,
                run.run_id,
                IngestionAttemptOutcome::ChunkMismatch,
                input.chunk_index,
            )
            .await;
            return Err(IngestionServiceError::ChunkMismatch);
        }
        // The fresh chunk owes the run's own stored bounds, not just the
        // current package's: the API layer parses under the stable protocol
        // ceilings so committed chunks replay, so the run's per-chunk item
        // ceiling is enforced here.
        if !announced_body || items.len() > run.maximum_items as usize {
            self.record_ingestion_attempt(
                &**client,
                run.run_id,
                IngestionAttemptOutcome::ChunkMismatch,
                input.chunk_index,
            )
            .await;
            return Err(IngestionServiceError::ChunkMismatch);
        }
        let idempotency_key = crate::data::ingestion_chunk_idempotency_key(
            &run.run_id.to_string(),
            &run.input_digest,
            u64::try_from(input.chunk_index).map_err(|_| IngestionServiceError::RequestInvalid)?,
            &input.digest,
        )
        .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let route =
            crate::data::ingestion_batch_route(&self.registry, &run.entity_id, &run.profile_id)
                .ok_or(IngestionServiceError::Unavailable)?;
        let plan = MutationPlan::from_compiled(&self.registry, &route.id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let response_fields = plan_readable_fields(&self.registry, &run.entity_id, &run.profile_id)
            .ok_or(IngestionServiceError::RequestInvalid)?;
        let chunk_binding = IngestionChunkBinding {
            run_id: run.run_id,
            chunk_index: input.chunk_index,
            chunk_digest: input.digest.clone(),
            prefix_digest: input.prefix_digest.clone(),
            item_count: i64::try_from(items.len())
                .map_err(|_| IngestionServiceError::RequestInvalid)?,
            created_principal_reference: run.created_principal_reference.clone(),
        };
        let request = BatchMutationRequest {
            plan: &plan,
            idempotency_key: &idempotency_key,
            claims: &claims,
            change_context: None,
            items,
            response_fields,
            body_bytes: canonical_body.len(),
            correlation: correlation.clone(),
            ingestion: Some(&chunk_binding),
        };
        let mut writer = self.client().await?;
        // From here the batch mutation records the chunk's attempt and its
        // refusal under this request's correlation.
        attempt.batch = true;
        #[cfg(feature = "postgres-test")]
        if let MutationFaultControl::At(fault) = self.fault {
            return self
                .finish_ingestion_submission(
                    context,
                    &input,
                    self.coordinator
                        .execute_batch_with_fault(&mut writer, request, fault)
                        .await,
                )
                .await;
        }
        self.finish_ingestion_submission(
            context,
            &input,
            self.coordinator.execute_batch(&mut writer, request).await,
        )
        .await
    }

    /// Render the submission answer from the mutation outcome, mapping every
    /// refusal to the closed run vocabulary and recording the attempt.
    /// Open the sealed members a receipt's batch answer carries before it
    /// leaves the service. Receipts store sealed envelopes exactly as the
    /// ordinary batch route's idempotency cache does and open them at this
    /// same serve edge: an entity without encrypted fields serves unchanged
    /// without touching key state, and absent key state or any open failure
    /// refuses the release instead of handing a caller sealed envelopes.
    /// `retirement_possible` marks a receipt stored under a package the
    /// database no longer holds active, the only situation where a member
    /// that still parses as a sealed envelope can be retired ciphertext
    /// rather than plaintext the caller wrote.
    /// Project a released answer's data members through what the current
    /// registry grants the run's profile, decided on the field identity each
    /// member was committed under: the stored bindings map every member to
    /// the logical field id that produced it, and a member is retained only
    /// when that field id is still one the current profile reads and still
    /// names the same member in the current entity. A successor that revokes
    /// a readable field therefore drops the member, and a successor that
    /// retires a field while reusing its api name for a different logical
    /// field cannot have the stored answer serve the old value under the
    /// new field's name.
    fn project_receipt_readability(
        &self,
        entity_id: &str,
        profile_id: &str,
        bindings: &std::collections::BTreeMap<String, String>,
        batch: &mut Value,
    ) -> Result<(), IngestionServiceError> {
        let Some(entity) = self.registry.entities().get(entity_id) else {
            return Err(IngestionServiceError::Unavailable);
        };
        // A profile the current registry no longer grants reads nothing, so
        // the release cannot answer any projection at all.
        let Some(readable) = plan_readable_fields(&self.registry, entity_id, profile_id) else {
            return Err(IngestionServiceError::Unavailable);
        };
        let api_names: std::collections::BTreeMap<&str, &str> = entity
            .stored_fields
            .iter()
            .map(|field| (field.logical.id.as_str(), field.logical.api_name.as_str()))
            .collect();
        let Some(results) = batch.get_mut("results").and_then(Value::as_array_mut) else {
            // A stored answer with no results array carries no domain data to
            // project, so it serves exactly as stored.
            return Ok(());
        };
        for result in results {
            if let Some(data) = result.get_mut("data").and_then(Value::as_object_mut) {
                data.retain(|member, _| {
                    bindings.get(member).is_some_and(|field_id| {
                        readable.contains(field_id)
                            && api_names.get(field_id.as_str()) == Some(&member.as_str())
                    })
                });
            }
        }
        Ok(())
    }

    fn open_receipt_members(
        &self,
        entity_id: &str,
        retirement_possible: bool,
        batch: &mut Value,
    ) -> Result<(), IngestionServiceError> {
        let Some(results) = batch.get_mut("results").and_then(Value::as_array_mut) else {
            // A stored answer with no results array carries no domain data to
            // open, so it serves exactly as stored.
            return Ok(());
        };
        let Some(entity) = self.registry.entities().get(entity_id) else {
            return Err(IngestionServiceError::Unavailable);
        };
        crate::field_encryption::open_batch_result_members(
            entity,
            results,
            self.field_encryption.as_deref(),
            retirement_possible,
        )
        .map_err(|_| IngestionServiceError::Unavailable)?;
        Ok(())
    }

    async fn finish_ingestion_submission(
        &self,
        context: &AuthorizedRequestContext,
        input: &IngestionChunkSubmitInput,
        outcome: Result<MutationOutcome, MutationError>,
    ) -> Result<Value, IngestionServiceError> {
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let client = self.client().await?;
                let (outcome_hint, refusal) = match error {
                    MutationError::IngestionRefusal(refusal) => match refusal {
                        crate::mutation::IngestionRefusal::RunNotOpen => (
                            IngestionAttemptOutcome::RunNotOpen,
                            Some(IngestionServiceError::RunNotOpen),
                        ),
                        crate::mutation::IngestionRefusal::ChunkMismatch => (
                            IngestionAttemptOutcome::ChunkMismatch,
                            Some(IngestionServiceError::ChunkMismatch),
                        ),
                        crate::mutation::IngestionRefusal::BindingChanged => (
                            IngestionAttemptOutcome::BindingChanged,
                            Some(IngestionServiceError::RunBlocked),
                        ),
                        crate::mutation::IngestionRefusal::ReceiptErased => (
                            IngestionAttemptOutcome::Replayed,
                            Some(IngestionServiceError::ReceiptErased),
                        ),
                    },
                    MutationError::InvalidRequest => (
                        IngestionAttemptOutcome::InvalidItem,
                        Some(IngestionServiceError::RequestInvalid),
                    ),
                    MutationError::PreconditionFailed
                    | MutationError::Conflict
                    | MutationError::FieldPatternViolation { .. } => (
                        IngestionAttemptOutcome::Refused,
                        Some(IngestionServiceError::PreconditionFailed),
                    ),
                    MutationError::IdempotencyConflict
                    | MutationError::Unavailable
                    | MutationError::RetryableConflict
                    | MutationError::LegacyReviewDataPresent
                    | MutationError::RetiredAuditRowsPresent
                    | MutationError::FieldEncryptionUnavailable
                    | MutationError::PlannerFailure(_)
                    | MutationError::ActionHandlerFailure(_)
                    | MutationError::ActionEvidenceFailure { .. }
                    | MutationError::ActionRefusal(_) => {
                        (IngestionAttemptOutcome::Unavailable, None)
                    }
                };
                self.record_ingestion_attempt(
                    &**client,
                    input.run_id,
                    outcome_hint,
                    input.chunk_index,
                )
                .await;
                return Err(refusal.unwrap_or(IngestionServiceError::Unavailable));
            }
        };
        let mut batch: Value = serde_json::from_slice(outcome.response().body())
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let entity = self
            .registry
            .entities()
            .get(&input.entity_id)
            .ok_or(IngestionServiceError::Unavailable)?;
        // The member identities are bound where the receipt is finalized,
        // from the same answer the chunk commit stores, so every later
        // release of the stored answer can re-check each member against the
        // package that then reads it.
        let field_bindings = ingestion_store::parse_field_bindings(
            &ingestion_store::receipt_field_bindings(entity, outcome.response().body())
                .ok_or(IngestionServiceError::Unavailable)?,
        )
        .ok_or(IngestionServiceError::Unavailable)?;
        let client = self.client().await?;
        let run = self
            .visible_run(&**client, context, &input.entity_id, input.run_id)
            .await?;
        let active = ingestion_store::active_binding(&**client)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        // The fresh answer and the coordinator's replayed receipt both reach
        // this arm with sealed members still inside; they answer to the
        // projection the current registry grants the run's profile and open
        // here, at the same serve edge the ordinary batch route opens its
        // answers. The admission gate above already refused a run the active
        // package no longer matches, so the receipt cannot carry retired
        // ciphertext.
        self.project_receipt_readability(
            &input.entity_id,
            &run.profile_id,
            &field_bindings,
            &mut batch,
        )?;
        self.open_receipt_members(
            &input.entity_id,
            !run.active_binding_matches(&active.0, &active.1),
            &mut batch,
        )?;
        Ok(json!({
            "run": Self::run_response(&run, (&active.0, &active.1)),
            "receipt": receipt_json(
                input.chunk_index,
                &input.digest,
                outcome.replayed(),
                false,
                batch,
            ),
        }))
    }

    /// Recover the stored receipt of one committed chunk after a lost
    /// response. The receipt is erased with the record history it describes.
    async fn ingestion_chunk_receipt_in(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity_id: &str,
        run_id: Uuid,
        chunk_index: i64,
        attempt: &mut IngestionAudit,
    ) -> Result<Value, IngestionServiceError> {
        if chunk_index < 0 {
            return Err(IngestionServiceError::RequestInvalid);
        }
        if !crate::audit::profile_is_keyed(self.audit.profile()) {
            return Err(IngestionServiceError::Unavailable);
        }
        let claims = strict_claim_context(&self.registry, context, entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        let Some(principal) = claims.principal() else {
            return Err(IngestionServiceError::RequestInvalid);
        };
        let principal_reference = self.ingestion_principal_reference(principal)?;
        let request_correlation = correlation.request_id().to_string();
        // The request entry is accepted before the run or the stored chunk is
        // read: an audit outage refuses the recovery instead of releasing a
        // receipt nobody recorded asking for.
        attempt.run = Some(
            ingestion_store::begin_run_request(
                &self.audit,
                ingestion_store::RunRequest {
                    transition: "chunkReceipt",
                    run_id: Some(run_id),
                    chunk_index: Some(chunk_index),
                    package_revision: &self.expected.package_revision,
                    entity_id,
                    profile_id: claims.access_profile(),
                    principal_reference: &principal_reference,
                    correlation: &request_correlation,
                },
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?,
        );
        let client = self.client().await?;
        let run = self
            .visible_run(&**client, context, entity_id, run_id)
            .await?;
        if run.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if run.bound_context_reference != self.ingestion_context_reference(&claims)? {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        // Recovery releases the same retained batch answer a replay does, so
        // the release takes the same guarded transaction the replay release
        // takes: the registry lock plus the durable identity check inside it
        // leave an instance whose package a successor retired no window to
        // serve the receipt under permissions the successor already revoked,
        // while a current instance owes the audit log the disclosure record,
        // accepted before the answer leaves, so an audit outage gates the
        // release. The stored receipt is read inside that same transaction,
        // after the lock is held: a record-history erasure takes the lock
        // exclusively while it scrubs the receipt, so a release that parks
        // through an erasure re-reads the row after the erasure committed and
        // answers receipt_erased instead of serving the erased values, and
        // writes no disclosure record for them.
        let mut writer = self.client().await?;
        let transaction = begin_record_transaction(
            &mut writer,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = transaction.transaction();
        let stored = ingestion_store::load_chunk(tx, run.run_id, chunk_index)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?
            .ok_or(IngestionServiceError::NotFound)?;
        if stored.erased {
            return Err(IngestionServiceError::ReceiptErased);
        }
        if !stored.committed_shape_is_valid() {
            return Err(IngestionServiceError::Unavailable);
        }
        let Some(receipt) = stored.receipt else {
            return Err(IngestionServiceError::ReceiptErased);
        };
        // A committed receipt always carries the member identities it was
        // produced under; a live row without that map is stored corruption,
        // answered as an outage rather than released.
        let Some(field_bindings) = stored.field_bindings else {
            return Err(IngestionServiceError::Unavailable);
        };
        let mut batch: Value =
            serde_json::from_slice(&receipt).map_err(|_| IngestionServiceError::Unavailable)?;
        // The stored answer answers to the projection the current registry
        // grants the run's profile before the disclosure record commits: each
        // member is retained only when the field identity it was committed
        // under is still a readable field of the current package under the
        // same api name.
        self.project_receipt_readability(entity_id, &run.profile_id, &field_bindings, &mut batch)?;
        // The stored answer opens its sealed members before the disclosure
        // record commits, so a process without key state refuses here instead
        // of writing a disclosure record for an answer it cannot serve. The
        // guarded transaction above proved the database holds this process's
        // identity active, so the receipt can carry ciphertext a successor
        // retired only when the run's own binding no longer matches it.
        self.open_receipt_members(
            entity_id,
            !run.active_binding_matches(
                &self.expected.package_revision,
                &self.expected.schema_fingerprint,
            ),
            &mut batch,
        )?;
        let disclosure_record = ingestion_store::receipt_disclosure_record(
            &run,
            stored.chunk_index,
            &principal_reference,
            Some(&request_correlation),
        );
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        ingestion_store::append_run_audit(&self.audit, disclosure_record)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        Ok(receipt_json(
            stored.chunk_index,
            &stored.chunk_digest,
            true,
            false,
            batch,
        ))
    }

    pub async fn tombstone(
        &self,
        input: ConditionalMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        self.conditional_mutation(input, MutationBody::Tombstone)
            .await
    }

    async fn conditional_mutation(
        &self,
        input: ConditionalMutationInput<'_>,
        body: MutationBody,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, input.route_id)?;
        let plan = match &body {
            MutationBody::Attachment(attachment) => {
                plan.attachment(&attachment.slot_id, attachment.bytes.is_none())?
            }
            _ => plan,
        };
        self.execute_request(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key: input.idempotency_key,
                claims: &claims,
                record_id: Some(input.record_id),
                expected_etag: Some(input.if_match),
                body,
                response_fields: input.response_fields,
                representation: input.representation,
                correlation: input.correlation.clone(),
            },
        )
        .await
    }

    async fn execute_request(
        &self,
        client: &mut deadpool_postgres::Client,
        request: MutationRequest<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        #[cfg(feature = "postgres-test")]
        if let MutationFaultControl::At(fault) = self.fault {
            return self
                .coordinator
                .execute_with_fault(client, request, fault)
                .await;
        }
        let _ = self.fault;
        self.coordinator.execute(client, request).await
    }
}

struct RequestActionCancellationGuard {
    pool: RuntimePool,
    client: Option<deadpool_postgres::Client>,
    cancel_token: tokio_postgres::CancelToken,
    armed: bool,
}

impl RequestActionCancellationGuard {
    fn new(pool: RuntimePool, client: deadpool_postgres::Client) -> Self {
        let cancel_token = client.cancel_token();
        Self {
            pool,
            client: Some(client),
            cancel_token,
            armed: true,
        }
    }

    fn client(&mut self) -> &mut deadpool_postgres::Client {
        self.client
            .as_mut()
            .expect("request action client is present while guarded")
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    async fn cancel_and_discard(&mut self) {
        self.discard();
        let _ = tokio::time::timeout(
            REQUEST_ACTION_CANCEL_TIMEOUT,
            self.pool.cancel_query(self.cancel_token.clone()),
        )
        .await;
        self.armed = false;
    }

    fn discard(&mut self) {
        if let Some(client) = self.client.take() {
            self.pool.discard(client);
        }
    }
}

impl Drop for RequestActionCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.discard();
            let pool = self.pool.clone();
            let token = self.cancel_token.clone();
            tokio::spawn(async move {
                let _ =
                    tokio::time::timeout(REQUEST_ACTION_CANCEL_TIMEOUT, pool.cancel_query(token))
                        .await;
            });
        }
    }
}

#[derive(Clone, Copy)]
enum MutationFaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(MutationFaultPoint),
    #[cfg(feature = "postgres-test")]
    RefusalAudit,
}

/// The keyed reference of the claim context one run is bound to. It
/// covers the same members an ordinary mutation's idempotency binding
/// covers, including the task grant when the claims carry one, with the
/// database rather than the package revision as its scope, so a committed
/// chunk's replay still answers across a package change while a drifted
/// context cannot replay or continue the run.
fn ingestion_context_reference(
    audit_profile: &AuditProfile,
    database_id: &str,
    claims: &ClaimContext,
) -> Result<String, IngestionServiceError> {
    let mut context = crate::idempotency::canonical_claim_context(audit_profile, claims, "")
        .map_err(|_| IngestionServiceError::Unavailable)?;
    if let Some(grant) = claims.task_grant() {
        context["taskGrant"] =
            serde_json::to_value(grant).map_err(|_| IngestionServiceError::Unavailable)?;
    }
    let canonical = registry_platform_canonical_json::canonicalize_json(&context)
        .map_err(|_| IngestionServiceError::Unavailable)?;
    let canonical =
        std::str::from_utf8(&canonical).map_err(|_| IngestionServiceError::Unavailable)?;
    audit_profile
        .key_hasher()
        .audit_reference_hash("breg-ingestion-context-v1", database_id, canonical)
        .map_err(|_| IngestionServiceError::Unavailable)
}

fn strict_claim_context(
    registry: &CompiledRegistry,
    context: &AuthorizedRequestContext,
    entity_id: &str,
) -> Result<ClaimContext, MutationError> {
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(api_boundary)
        .collect::<Result<Vec<_>, _>>()?;
    ClaimContext::for_compiled(
        registry,
        entity_id,
        context.principal().map(str::to_owned),
        context.selected_profile(),
        context.purpose().map(str::to_owned),
        row_boundaries,
    )
    .map(|claims| claims.with_grant_audit(context.grant_audit().cloned()))
    .and_then(|claims| claims.with_human_identity(context.human_identity().cloned()))
    .and_then(|claims| claims.with_api_submitter_targets(registry, context))
    .and_then(|claims| claims.with_recipients(context.recipients().clone()))
    .and_then(|claims| match context.task_grant() {
        Some(grant) => claims.with_task_grant(grant.clone()),
        None => Ok(claims),
    })
    .map_err(|_| MutationError::InvalidRequest)
}

fn strict_action_context(
    context: &AuthorizedActionContext,
    action_id: &str,
) -> Result<ActionClaimContext, MutationError> {
    if context.action_id() != action_id {
        return Err(MutationError::InvalidRequest);
    }
    ActionClaimContext::new(
        context.action_id().to_owned(),
        context.principal().to_owned(),
        context.selected_profile().to_owned(),
        context.purpose().map(str::to_owned),
        context.result_effects().clone(),
    )
    .map_err(|_| MutationError::InvalidRequest)
}

fn strict_action_target_authority(
    context: &AuthorizedActionContext,
) -> Result<std::collections::BTreeMap<String, Vec<RowBoundaryContext>>, MutationError> {
    context
        .target_authority()
        .iter()
        .map(|(entity_id, boundaries)| {
            Ok((
                entity_id.clone(),
                boundaries
                    .iter()
                    .map(api_boundary)
                    .collect::<Result<Vec<_>, _>>()?,
            ))
        })
        .collect()
}

fn api_boundary(boundary: &VerifiedRowBoundary) -> Result<RowBoundaryContext, MutationError> {
    match boundary.operator() {
        ApiRowBoundaryOperator::Equals => {
            let value = boundary
                .values()
                .iter()
                .next()
                .ok_or(MutationError::InvalidRequest)?;
            if boundary.values().len() != 1 {
                return Err(MutationError::InvalidRequest);
            }
            Ok(RowBoundaryContext::Equals {
                field: boundary.field().to_owned(),
                value: value.clone(),
            })
        }
        ApiRowBoundaryOperator::In => Ok(RowBoundaryContext::In {
            field: boundary.field().to_owned(),
            values: boundary.values().clone(),
        }),
    }
}

/// The readable projection bound to the run profile, so the receipt carries
/// exactly the fields the profile may read and nothing wider.
fn plan_readable_fields(
    registry: &CompiledRegistry,
    entity_id: &str,
    profile_id: &str,
) -> Option<std::collections::BTreeSet<String>> {
    Some(
        registry
            .entities()
            .get(entity_id)?
            .access_profiles
            .get(profile_id)?
            .readable_fields
            .clone(),
    )
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn receipt_json(
    chunk_index: i64,
    digest: &str,
    replayed: bool,
    erased: bool,
    batch: Value,
) -> Value {
    json!({
        "chunkIndex": chunk_index,
        "digest": digest,
        "replayed": replayed,
        "erased": erased,
        "batch": batch,
    })
}

#[cfg(test)]
mod ingestion_context_tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use crate::task_grant::TaskGrantBinding;

    const CONTEXT_FIXTURE: &str = r#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"run-context-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}]
      }],
      "accessProfiles":[{
        "id":"operator","default":true,"principalClaim":"registry_principal",
        "requiredPurposes":["review"],
        "permissions":[{
          "entity":"entry","operations":["get"],
          "readableFields":["tenant"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
        }]
      }]
    }"#;

    fn fixture_claims() -> ClaimContext {
        let project =
            parse_project_json(CONTEXT_FIXTURE.as_bytes()).expect("the fixture project parses");
        let registry = compile_project(&project, &[], CompileProfile::Authoring)
            .expect("the fixture project compiles");
        ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("agent".to_owned()),
            "operator",
            Some("review".to_owned()),
            vec![RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "tenant-a".to_owned(),
            }],
        )
        .expect("the fixture context is exact")
    }

    fn grant(id: &str) -> TaskGrantBinding {
        serde_json::from_value(json!({
            "grantId": id,
            "sourceIssuer": "https://casework.example",
            "principal": "agent",
            "client": "task-agent",
            "resource": "urn:breg:test",
            "purpose": "review",
            "bounds": {"type": "breg", "permissions": [
                {"collection": "entries", "operations": ["get"]}
            ]},
            "subjects": {"tenant_claim": "tenant-a"},
            "expiresAt": chrono::Utc::now().timestamp() + 900,
        }))
        .expect("the fixture grant binds")
    }

    /// The run context reference is total over the verified authorization
    /// inputs: two scope-identical sibling task grants differ only in grant
    /// id, and the reference must separate them exactly the way the ordinary
    /// mutation idempotency binding's taskGrant member does, while a
    /// grant-free context keeps the reference shape it has always had.
    #[test]
    fn a_sibling_task_grant_changes_the_run_context_reference() {
        let profile = AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("the test owns a keyed audit profile");
        let claims = fixture_claims();
        let plain = ingestion_context_reference(&profile, "run-database", &claims)
            .expect("the grant-free reference derives");
        let first = ingestion_context_reference(
            &profile,
            "run-database",
            &claims
                .clone()
                .with_task_grant(grant("11111111-1111-4111-8111-111111111111"))
                .expect("the first grant binds to the claims"),
        )
        .expect("the first granted reference derives");
        let second = ingestion_context_reference(
            &profile,
            "run-database",
            &claims
                .clone()
                .with_task_grant(grant("22222222-2222-4222-8222-222222222222"))
                .expect("the second grant binds to the claims"),
        )
        .expect("the second granted reference derives");

        assert_ne!(
            first, second,
            "scope-identical sibling grants must not share one run context reference"
        );
        assert_ne!(
            first, plain,
            "a granted context must not answer the grant-free reference"
        );

        // The grant-free shape is stable: a context without a task grant
        // hashes exactly the member set the reference has always covered, so
        // references stored before grants could reach a run still answer.
        let context = crate::idempotency::canonical_claim_context(&profile, &claims, "")
            .expect("the grant-free canonical context derives");
        let canonical = registry_platform_canonical_json::canonicalize_json(&context)
            .expect("the canonical context encodes");
        let legacy = profile
            .key_hasher()
            .audit_reference_hash(
                "breg-ingestion-context-v1",
                "run-database",
                std::str::from_utf8(&canonical).expect("canonical JSON is UTF-8"),
            )
            .expect("the legacy reference derives");
        assert_eq!(plain, legacy);
    }
}
