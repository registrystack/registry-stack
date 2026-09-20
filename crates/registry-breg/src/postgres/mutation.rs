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
use crate::audit::{record_http_refusal_audit, HttpRefusalAudit};
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
    ActionClaimContext, ClaimContext, ExpectedRegistryIdentity, RegistryLockKey,
    RowBoundaryContext, RuntimePool,
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
    audit_profile: AuditProfile,
    action_timeout: Duration,
    evidence_timeout: Duration,
    evidence_evaluator: Option<Arc<crate::action_evidence::ActionEvidenceEvaluator>>,
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

    /// Bind operator-approved Evidence clients for v2 immediate action handlers.
    #[must_use]
    pub fn with_evidence_evaluator(
        mut self,
        evaluator: Arc<crate::action_evidence::ActionEvidenceEvaluator>,
    ) -> Self {
        self.evidence_evaluator = Some(evaluator);
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
                        guard.client(),
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
        if is_evidence_apply {
            return self.request_evidence_apply(input, &claims).await;
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
    ) -> Result<MutationOutcome, MutationError> {
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
                    )
                    .await;
                if result.is_err() && tokio::time::Instant::now() < deadline {
                    self.coordinator
                        .record_request_boundary_refusal(
                            guard.client(),
                            &self.registry,
                            &input,
                            claims,
                        )
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
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
    ) -> Self {
        Self::new_with_event_destinations(
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
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
        audit_profile: AuditProfile,
        event_destinations: Option<Arc<ActivatedEventDestinationRegistry>>,
    ) -> Self {
        let coordinator = MutationCoordinator::new_with_event_destinations(
            lock_key,
            lock_timeout,
            expected.clone(),
            audit_profile.clone(),
            event_destinations,
        );
        Self {
            pool,
            registry,
            coordinator,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
            action_timeout: REQUEST_ACTION_TIMEOUT,
            evidence_timeout: REQUEST_ACTION_TIMEOUT,
            evidence_evaluator: None,
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
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        record_http_refusal_audit(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &self.audit_profile,
            event,
        )
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
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        crate::audit::record_attachment_http_refusal_audit(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &self.audit_profile,
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
        self.audit_profile
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
        let context = crate::idempotency::canonical_claim_context(&self.audit_profile, claims, "")
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let canonical = registry_platform_canonical_json::canonicalize_json(&context)
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let canonical =
            std::str::from_utf8(&canonical).map_err(|_| IngestionServiceError::Unavailable)?;
        self.audit_profile
            .key_hasher()
            .audit_reference_hash(
                "breg-ingestion-context-v1",
                &self.expected.database_id,
                canonical,
            )
            .map_err(|_| IngestionServiceError::Unavailable)
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

    fn run_response(&self, run: &ingestion_store::IngestionRunRecord) -> Value {
        run.response_json(
            &self.expected.package_revision,
            &self.expected.schema_fingerprint,
        )
    }

    /// Create a durable ingestion run bound to the active package revision,
    /// schema fingerprint, entity, profile, operation, input digest, chunking
    /// algorithm, and announced counts.
    pub async fn create_ingestion_run(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionRunCreateInput,
    ) -> Result<Value, IngestionServiceError> {
        if !crate::audit::profile_is_keyed(&self.audit_profile) {
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
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = &transaction;
        let record = ingestion_store::insert_run(tx, &run)
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        ingestion_store::append_run_audit(
            tx,
            &self.audit_profile,
            ingestion_store::run_audit_record(
                "created",
                &record,
                &self.expected.package_revision,
                &record.created_principal_reference,
                Some(&correlation.request_id().to_string()),
            ),
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        Ok(self.run_response(&record))
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
                            && run.entity_id == query.entity_id
                    })
                    .ok_or(IngestionServiceError::RequestInvalid)?;
                Some((cursor.created_at, cursor.run_id))
            }
        };
        let (runs, has_more) = ingestion_store::list_runs(
            &**client,
            &ingestion_store::IngestionRunListFilter {
                principal_reference: &principal_reference,
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
        let next_after = if has_more {
            runs.last()
                .map(|run| json!(run.run_id.to_string()))
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        Ok(json!({
            "runs": runs
                .iter()
                .map(|run| self.run_response(run))
                .collect::<Vec<_>>(),
            "hasMore": has_more,
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
        let client = self.client().await?;
        let run = self
            .visible_run(&**client, context, entity_id, run_id)
            .await?;
        Ok(self.run_response(&run))
    }

    /// Cancel an open or blocked run, preserving the committed prefix, the
    /// counts, and the audit trail.
    pub async fn cancel_ingestion_run(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity_id: &str,
        run_id: Uuid,
    ) -> Result<Value, IngestionServiceError> {
        if !crate::audit::profile_is_keyed(&self.audit_profile) {
            return Err(IngestionServiceError::Unavailable);
        }
        let mut client = self.client().await?;
        let run = self
            .visible_run(&**client, context, entity_id, run_id)
            .await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let tx: &tokio_postgres::Transaction<'_> = &transaction;
        let cancelled =
            ingestion_store::cancel_run(tx, run.run_id, IngestionAttemptOutcome::Refused)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::RunNotOpen)?;
        ingestion_store::append_run_audit(
            tx,
            &self.audit_profile,
            ingestion_store::run_audit_record(
                "cancelled",
                &cancelled,
                &self.expected.package_revision,
                &cancelled.created_principal_reference,
                Some(&correlation.request_id().to_string()),
            ),
        )
        .await
        .map_err(|_| IngestionServiceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
        Ok(self.run_response(&cancelled))
    }

    /// Submit the next exact chunk of one run. The server derives the
    /// idempotency key from the run binding, so an interrupted submission
    /// replays the original receipt without a duplicate mutation.
    pub async fn submit_ingestion_chunk(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        input: IngestionChunkSubmitInput,
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
        if input.chunk_index < run.next_chunk_index {
            // The checkpoint already covers this chunk, so the caller is
            // recovering a lost response: return the stored receipt, never a
            // second mutation. This holds for every terminal status and for
            // a changed active package, because the committed prefix and its
            // receipts survive completion, cancellation, and blocking.
            let stored = ingestion_store::load_chunk(&**client, run.run_id, input.chunk_index)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::Unavailable)?;
            let replayed =
                stored.chunk_digest == input.digest && stored.prefix_digest == input.prefix_digest;
            self.record_ingestion_attempt(
                &**client,
                run.run_id,
                if replayed {
                    IngestionAttemptOutcome::Replayed
                } else {
                    IngestionAttemptOutcome::ChunkMismatch
                },
                input.chunk_index,
            )
            .await;
            if !replayed {
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
            let batch: Value =
                serde_json::from_slice(&receipt).map_err(|_| IngestionServiceError::Unavailable)?;
            // The attempt row above moved the run's last-attempt marker, so
            // the answer describes the run as it now stands, not as this
            // request found it.
            let run = ingestion_store::load_run(&**client, run.run_id)
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?
                .ok_or(IngestionServiceError::Unavailable)?;
            return Ok(json!({
                "run": self.run_response(&run),
                "receipt": receipt_json(input.chunk_index, &input.digest, true, false, batch),
            }));
        }
        if !run.active_binding_matches(
            &self.expected.package_revision,
            &self.expected.schema_fingerprint,
        ) {
            let mut writer = self.client().await?;
            let transaction = writer
                .transaction()
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            let tx: &tokio_postgres::Transaction<'_> = &transaction;
            ingestion_store::mark_blocked(
                tx,
                run.run_id,
                ingestion_store::IngestionBlockedReason::ActivePackageChanged,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            ingestion_store::record_attempt(
                tx,
                run.run_id,
                IngestionAttemptOutcome::BindingChanged,
                input.chunk_index,
            )
            .await
            .map_err(|_| IngestionServiceError::Unavailable)?;
            if crate::audit::profile_is_keyed(&self.audit_profile) {
                let mut audited_run = run.clone();
                audited_run.status = IngestionRunStatus::Blocked;
                audited_run.blocked_reason =
                    Some(ingestion_store::IngestionBlockedReason::ActivePackageChanged);
                ingestion_store::append_run_audit(
                    tx,
                    &self.audit_profile,
                    ingestion_store::run_audit_record(
                        "blocked",
                        &audited_run,
                        &self.expected.package_revision,
                        &run.created_principal_reference,
                        Some(&correlation.request_id().to_string()),
                    ),
                )
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            }
            transaction
                .commit()
                .await
                .map_err(|_| IngestionServiceError::Unavailable)?;
            return Err(IngestionServiceError::RunBlocked);
        }

        match run.status {
            IngestionRunStatus::Blocked => return Err(IngestionServiceError::RunBlocked),
            IngestionRunStatus::Complete | IngestionRunStatus::Cancelled => {
                return Err(IngestionServiceError::RunNotOpen);
            }
            IngestionRunStatus::Open => {}
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
        if canonical_digest != input.digest || canonical_body.len() > run.maximum_bytes as usize {
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
                    MutationError::PreconditionFailed | MutationError::Conflict => (
                        IngestionAttemptOutcome::Refused,
                        Some(IngestionServiceError::PreconditionFailed),
                    ),
                    MutationError::IdempotencyConflict
                    | MutationError::Unavailable
                    | MutationError::RetryableConflict
                    | MutationError::PlannerFailure(_)
                    | MutationError::ActionHandlerFailure(_)
                    | MutationError::ActionEvidenceFailure { .. }
                    | MutationError::ActionRefusal(_)
                    | MutationError::FieldPatternViolation { .. } => {
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
        let batch: Value = serde_json::from_slice(outcome.response().body())
            .map_err(|_| IngestionServiceError::Unavailable)?;
        let client = self.client().await?;
        let run = self
            .visible_run(&**client, context, &input.entity_id, input.run_id)
            .await?;
        Ok(json!({
            "run": self.run_response(&run),
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
    pub async fn ingestion_chunk_receipt(
        &self,
        context: &AuthorizedRequestContext,
        entity_id: &str,
        run_id: Uuid,
        chunk_index: i64,
    ) -> Result<Value, IngestionServiceError> {
        if chunk_index < 0 {
            return Err(IngestionServiceError::RequestInvalid);
        }
        let client = self.client().await?;
        let run = self
            .visible_run(&**client, context, entity_id, run_id)
            .await?;
        let claims = strict_claim_context(&self.registry, context, entity_id)
            .map_err(|_| IngestionServiceError::RequestInvalid)?;
        if run.profile_id != claims.access_profile() {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        if run.bound_context_reference != self.ingestion_context_reference(&claims)? {
            return Err(IngestionServiceError::ProfileMismatch);
        }
        let stored = ingestion_store::load_chunk(&**client, run.run_id, chunk_index)
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
        let batch: Value =
            serde_json::from_slice(&receipt).map_err(|_| IngestionServiceError::Unavailable)?;
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
    .and_then(|claims| claims.with_api_submitter_targets(registry, context))
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
