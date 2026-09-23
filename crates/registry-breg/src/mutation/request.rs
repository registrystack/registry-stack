// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::api::{
    RequestActionBody, RequestActionInput, RowBoundaryOperator as ApiBoundaryOperator,
};
use crate::postgres::{
    ChangeRequestActionContext, ChangeRequestTargetBinding, ChangeRequestTargetContext,
    RowBoundaryContext,
};
use crate::request_prepare::{self, RequestTargetSnapshot};
use crate::request_workflow::{
    ApplicationId, ApplicationResultLink, ContractFingerprint, EntityId, ObservedTarget,
    PreparedApplication, ProposalDigest, ProposalVersion, RecordId, RecordRevision, RequestState,
    RequestWorkflow, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
};
use crate::rhai_planner::{CandidateChangeRequestEffect, CandidateChangeRequestMutation};

pub(crate) const REQUEST_ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_ACTION_STATEMENT_TIMEOUT_HEADROOM: Duration = Duration::from_millis(500);

struct SubmissionCandidate {
    request_record_revision: i64,
    workflow_revision: u64,
    intake: Map<String, Value>,
    resolved: crate::request_prepare::ResolvedRequestTargets,
}

struct AppliedRequest {
    workflow: RequestWorkflow,
    result_count: u16,
    result_revisions: Vec<(String, Uuid, i64)>,
}

pub(crate) enum RequestEvidencePreflight {
    Receipt,
    Acquire(
        Vec<(
            crate::action_evidence_contracts::CompiledEvidenceCapability,
            crate::action_evidence_client::EvidenceSubjects,
        )>,
    ),
}

pub(crate) enum RequestReceiptPreflight {
    Receipt,
    Continue {
        proposal_authority: Option<Box<crate::task_grant::TaskGrantBinding>>,
    },
}

/// A bounded, external status observation for the exact apply authorities.
///
/// The remote source cannot participate in BReg's PostgreSQL transaction. Each
/// guarded apply attempt therefore checks status immediately before opening its
/// effect transaction, then re-loads and compares the source-owned proposal
/// binding under that transaction. Revocation after the status response is
/// bounded by both grants' expirations; BReg does not claim cross-service
/// atomicity for that unavoidable interval.
struct CheckedApplyTaskAuthority {
    current: Option<crate::task_grant::TaskGrantBinding>,
    proposal: Option<crate::task_grant::TaskGrantBinding>,
}

impl CheckedApplyTaskAuthority {
    fn verify_current(&self, claims: &ClaimContext) -> Result<(), MutationError> {
        if self.current.as_ref() != claims.task_grant()
            || self
                .current
                .as_ref()
                .is_some_and(|grant| !grant.is_current())
            || self
                .proposal
                .as_ref()
                .is_some_and(|grant| !grant.is_current())
        {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(())
    }
}

/// A conditional action is bound to its exact selected operation and authority,
/// not to the ETag of a record page or a work-queue/list response.
#[allow(clippy::too_many_arguments)]
pub(crate) fn request_action_etag(
    profile: &AuditProfile,
    claims: &ClaimContext,
    package_revision: &str,
    route: &CompiledRoute,
    record_id: &str,
    record_revision: i64,
    workflow: &RequestWorkflow,
    response_fields: &BTreeSet<String>,
    target_authority: &[crate::api::RequestActionTargetAuthority],
) -> Result<String, MutationError> {
    request_action_etag_for_revisions(
        profile,
        claims,
        package_revision,
        route,
        record_id,
        record_revision,
        workflow.workflow_revision().get(),
        workflow,
        response_fields,
        target_authority,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_action_etag_for_revisions(
    profile: &AuditProfile,
    claims: &ClaimContext,
    package_revision: &str,
    route: &CompiledRoute,
    record_id: &str,
    record_revision: i64,
    workflow_revision: u64,
    workflow: &RequestWorkflow,
    response_fields: &BTreeSet<String>,
    target_authority: &[crate::api::RequestActionTargetAuthority],
) -> Result<String, MutationError> {
    if record_revision <= 0 || workflow_revision == 0 {
        return Err(MutationError::PreconditionFailed);
    }
    let binding = json!({
        "authority": crate::idempotency::canonical_claim_context(profile, claims, package_revision)?,
        "operationId": route.id,
        "recordId": record_id, "recordRevision": record_revision,
        "workflowRevision": workflow_revision,
        "proposalVersion": workflow.current_version().get(),
        "effectDigest": workflow.current_proposal().map(|proposal| proposal.effect_digest().as_str()),
        "responseFields": response_fields,
        "targetAuthority": target_authority_binding(target_authority),
    });
    let canonical = canonicalize_json(&binding).map_err(|_| MutationError::Unavailable)?;
    let digest = profile
        .key_hasher()
        .audit_reference_hash(
            "breg-request-action-etag-v1",
            package_revision,
            std::str::from_utf8(&canonical).map_err(|_| MutationError::Unavailable)?,
        )
        .map_err(|_| MutationError::Unavailable)?;
    Ok(format!("\"breg-action-{digest}\""))
}

impl MutationCoordinator {
    /// Determine whether this exact action binding already has a durable
    /// source-owned receipt. This check deliberately performs no remote I/O
    /// and returns no receipt content. The normal action transaction still
    /// re-authorizes the caller before returning the stored response.
    pub(crate) async fn preflight_request_action_receipt(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
    ) -> Result<RequestReceiptPreflight, MutationError> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == input.route_id)
            .ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(input.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let profile = entity
            .access_profiles
            .get(claims.access_profile())
            .ok_or(MutationError::InvalidRequest)?;
        if !profile_is_keyed(&self.audit_profile)
            || entity.change_request.is_none()
            || route.entity_id != entity.id
            || claims.entity_id() != entity.id
            || claims.principal().is_none()
            || route.method != HttpMethod::Post
            || !route
                .access_profiles
                .iter()
                .any(|id| id == claims.access_profile())
            || !profile.operations.contains(&route.operation)
            || action_operation(&input.action) != route.operation
            || !input.response_fields.is_subset(&profile.readable_fields)
            || !valid_uuid(input.record_id)
        {
            return Err(MutationError::InvalidRequest);
        }
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: route.method,
                route: &route.path,
                target_record: Some(input.record_id),
                package_revision: &self.expected.package_revision,
                response_fields: &input.response_fields,
                canonical_request_digest: Sha256::digest(
                    canonicalize_json(&action_binding_json(input)?)
                        .map_err(|_| MutationError::InvalidRequest)?,
                )
                .into(),
                key_domain: IdempotencyKeyDomain::Caller,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let request_id =
            Uuid::parse_str(input.record_id).map_err(|_| MutationError::InvalidRequest)?;
        let actor =
            request_actor_reference(&self.audit_profile, &self.expected.database_id, claims)?;
        let header = transaction
            .transaction()
            .query_opt(
                "SELECT proposal_version,state FROM registry_internal.registry_request_state
                 WHERE request_entity_id = $1 AND request_id = $2",
                &[&entity.id, &request_id],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .ok_or(MutationError::PreconditionFailed)?;
        let action_context = ChangeRequestActionContext::for_route(
            registry,
            claims,
            &route.id,
            request_id,
            header.get::<_, i64>(0),
            &actor,
            &self.expected.package_revision,
        )
        .map_err(|_| MutationError::PreconditionFailed)?;
        transaction
            .install_change_request_action_context(&action_context)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let receipt = transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_idempotency WHERE key_reference = $1",
                &[&binding.key_reference],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some();
        let applied = header.get::<_, String>(1) == "applied";
        let proposal_authority = if !receipt && !applied {
            if let RequestActionBody::Apply {
                proposal_version, ..
            } = &input.action
            {
                crate::request_store::load_task_authority(
                    transaction.transaction(),
                    &entity.id,
                    request_id,
                    i64::from(*proposal_version),
                )
                .await?
            } else {
                None
            }
        } else {
            None
        };
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(if receipt || applied {
            RequestReceiptPreflight::Receipt
        } else {
            RequestReceiptPreflight::Continue {
                proposal_authority: proposal_authority.map(Box::new),
            }
        })
    }

    pub(crate) async fn record_request_boundary_refusal(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
    ) -> Result<(), MutationError> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == input.route_id)
            .ok_or(MutationError::InvalidRequest)?;
        record_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
            &self.audit_profile,
            PreIoAudit {
                kind: PreIoAuditKind::Refusal,
                method: route.method,
                operation_id: &route.id,
                target_record: Some(input.record_id),
                refusal_reason: None,
                correlation: input.correlation,
            },
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn preflight_request_evidence_apply(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        deadline: tokio::time::Instant,
    ) -> Result<RequestEvidencePreflight, MutationError> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == input.route_id)
            .ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(input.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let profile = entity
            .access_profiles
            .get(claims.access_profile())
            .ok_or(MutationError::InvalidRequest)?;
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let RequestActionBody::Apply {
            proposal_version,
            effect_digest,
            ..
        } = &input.action
        else {
            return Err(MutationError::InvalidRequest);
        };
        if plan.application.preconditions.evidence.is_empty()
            || plan.on_approved.mode != crate::model::CompiledChangeRequestOnApprovedMode::Manual
            || !profile_is_keyed(&self.audit_profile)
            || route.entity_id != entity.id
            || claims.entity_id() != entity.id
            || claims.principal().is_none()
            || route.method != HttpMethod::Post
            || !route
                .access_profiles
                .iter()
                .any(|id| id == claims.access_profile())
            || !profile.operations.contains(&Operation::ApplyRequest)
            || !input.response_fields.is_subset(&profile.readable_fields)
            || !valid_uuid(input.record_id)
        {
            return Err(MutationError::InvalidRequest);
        }
        record_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
            &self.audit_profile,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: route.method,
                operation_id: &route.id,
                target_record: Some(input.record_id),
                refusal_reason: None,
                correlation: input.correlation,
            },
        )
        .await?;
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: route.method,
                route: &route.path,
                target_record: Some(input.record_id),
                package_revision: &self.expected.package_revision,
                response_fields: &input.response_fields,
                canonical_request_digest: Sha256::digest(
                    canonicalize_json(&action_binding_json(input)?)
                        .map_err(|_| MutationError::InvalidRequest)?,
                )
                .into(),
                key_domain: IdempotencyKeyDomain::Caller,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        set_transaction_statement_timeout(
            transaction.transaction(),
            request_action_statement_timeout(deadline),
        )
        .await?;
        let request_id =
            Uuid::parse_str(input.record_id).map_err(|_| MutationError::InvalidRequest)?;
        let actor =
            request_actor_reference(&self.audit_profile, &self.expected.database_id, claims)?;
        let header = transaction
            .transaction()
            .query_opt(
                "SELECT proposal_version FROM registry_internal.registry_request_state
                 WHERE request_entity_id = $1 AND request_id = $2",
                &[&entity.id, &request_id],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .ok_or(MutationError::PreconditionFailed)?;
        let action_context = ChangeRequestActionContext::for_route(
            registry,
            claims,
            &route.id,
            request_id,
            header.get::<_, i64>(0),
            &actor,
            &self.expected.package_revision,
        )
        .map_err(|_| MutationError::PreconditionFailed)?;
        transaction
            .install_change_request_action_context(&action_context)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_idempotency WHERE key_reference = $1",
                &[&binding.key_reference],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some()
        {
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(RequestEvidencePreflight::Receipt);
        }
        let current = load_row(transaction.transaction(), entity, input.record_id, false).await?;
        let workflow =
            crate::request_store::load(transaction.transaction(), &entity.id, request_id, false)
                .await?;
        if workflow.state() == RequestState::Applied {
            // A new key may recover the committed application without fresh
            // Evidence. The action transaction rechecks the original approved
            // precondition, proposal identity, and current target authority.
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(RequestEvidencePreflight::Receipt);
        }
        let etag = request_action_etag(
            &self.audit_profile,
            claims,
            &self.expected.package_revision,
            route,
            input.record_id,
            current.record_revision,
            &workflow,
            &input.response_fields,
            &input.target_authority,
        )?;
        if workflow.state() != RequestState::Submitted
            || etag.as_bytes().ct_eq(input.if_match.as_bytes()).unwrap_u8() != 1
        {
            return Err(MutationError::PreconditionFailed);
        }
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        if proposal.version().get() != *proposal_version
            || proposal.effect_digest().as_str() != effect_digest
            || proposal.contract_fingerprint().as_str() != plan.contract_fingerprint
        {
            return Err(MutationError::PreconditionFailed);
        }
        let frozen = proposal
            .application_preconditions()
            .filter(|frozen| frozen.contract == plan.application.preconditions)
            .ok_or(MutationError::PreconditionFailed)?;
        verify_frozen_request_values(frozen, &current.data)?;
        let current_date = time::OffsetDateTime::now_utc().date().to_string();
        verify_compiled_predicates(
            &frozen.contract.request,
            &frozen.request_values,
            &frozen.request_values,
            &current_date,
            |field| {
                entity
                    .fields
                    .get(field)
                    .is_some_and(|field| matches!(field.field_type, FieldTypeSource::Timestamp))
            },
        )?;
        let targets = crate::request_store::load_targets(
            transaction.transaction(),
            &entity.id,
            request_id,
            i64::from(*proposal_version),
        )
        .await?;
        self.authorize_targets(registry, input, claims, entity, &workflow, &targets, &actor)?;
        for guard in &frozen.targets {
            let compiled = frozen
                .contract
                .targets
                .iter()
                .find(|candidate| candidate.id == guard.id)
                .ok_or(MutationError::PreconditionFailed)?;
            let record_id = Uuid::parse_str(guard.record_id.as_str())
                .map_err(|_| MutationError::PreconditionFailed)?;
            let authority = input
                .target_authority
                .iter()
                .find(|authority| authority.target_entity_id == guard.entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let context = ChangeRequestTargetContext::for_application(
                registry,
                claims,
                request_authority_boundaries(authority)?,
                guard_target_binding(
                    entity,
                    &workflow,
                    plan,
                    compiled,
                    record_id,
                    Some(guard.expected_revision),
                    &self.expected.package_revision,
                    &actor,
                )?,
            )
            .map_err(|_| MutationError::PreconditionFailed)?;
            transaction
                .install_change_request_target_context(&context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let row = load_row(
                transaction.transaction(),
                &registry.entities()[&guard.entity_id],
                &record_id.to_string(),
                false,
            )
            .await?;
            if row.record_revision != guard.expected_revision
                || guard
                    .values
                    .iter()
                    .any(|(field, value)| row.data.get(field) != Some(value))
            {
                return Err(MutationError::PreconditionFailed);
            }
            context
                .authorize_rows(
                    &registry.entities()[&guard.entity_id],
                    Some(&row.data),
                    &row.data,
                    record_id,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
            let values = row
                .data
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            verify_compiled_predicates(
                &compiled.requires,
                &values,
                &frozen.request_values,
                &current_date,
                |field| {
                    registry.entities()[&guard.entity_id]
                        .fields
                        .get(field)
                        .is_some_and(|field| matches!(field.field_type, FieldTypeSource::Timestamp))
                },
            )?;
        }
        let requests = request_evidence_subjects(frozen)?;
        let proposal_authority = crate::request_store::load_task_authority(
            transaction.transaction(),
            &entity.id,
            request_id,
            i64::from(*proposal_version),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        // A guard acquisition is a protected disclosure too. Check both the
        // current actor and the authority frozen at submission before Evidence
        // I/O, then recheck at the final SQL attempt before applying effects.
        if let Some(grant) = claims.task_grant() {
            self.check_task_authority(grant).await?;
        }
        if let Some(grant) = proposal_authority {
            self.check_task_authority(&grant).await?;
        }
        Ok(RequestEvidencePreflight::Acquire(requests))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_request_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: RequestActionInput<'_>,
        claims: &ClaimContext,
        fault: FaultControl,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        frozen_evidence: Option<&[crate::action_evidence_client::VerifiedAcquisition]>,
        attempt_recorded: bool,
    ) -> Result<MutationOutcome, MutationError> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == input.route_id)
            .ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(input.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let profile = entity
            .access_profiles
            .get(claims.access_profile())
            .ok_or(MutationError::InvalidRequest)?;
        if !profile_is_keyed(&self.audit_profile)
            || entity.change_request.is_none()
            || route.entity_id != entity.id
            || claims.entity_id() != entity.id
            || claims.principal().is_none()
            || route.method != HttpMethod::Post
            || !route
                .access_profiles
                .iter()
                .any(|id| id == claims.access_profile())
            || !profile.operations.contains(&route.operation)
            || action_operation(&input.action) != route.operation
            || !input.response_fields.is_subset(&profile.readable_fields)
            || !valid_uuid(input.record_id)
        {
            return Err(MutationError::InvalidRequest);
        }
        let audit = |kind, refusal_reason| PreIoAudit {
            kind,
            method: route.method,
            operation_id: &route.id,
            target_record: Some(input.record_id),
            refusal_reason,
            correlation: input.correlation,
        };
        if !attempt_recorded {
            record_pre_io_audit(
                client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                claims,
                &self.audit_profile,
                audit(PreIoAuditKind::Attempt, None),
            )
            .await?;
        }
        let deadline = tokio::time::Instant::now() + REQUEST_ACTION_TIMEOUT;
        // Capture the exact intake under request RLS, close that transaction,
        // then run the bounded planner exactly once outside retry and target
        // locks. The resulting candidate and reserved identities are reused by
        // every positively identified transaction retry.
        let submission = if matches!(input.action, RequestActionBody::Submit) {
            match self
                .plan_submission_candidate(
                    client, registry, &input, claims, route, entity, deadline,
                )
                .await
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    // A planner failure is journaled by its closed vocabulary,
                    // so the refusal is reviewable without the script text or
                    // the values the submission carried.
                    let refusal_reason = match error {
                        MutationError::PlannerFailure(planner) => Some(planner.code()),
                        _ => None,
                    };
                    if !fault.is_enabled() {
                        record_pre_io_audit(
                            client,
                            self.lock_key,
                            self.lock_timeout,
                            &self.expected,
                            claims,
                            &self.audit_profile,
                            audit(PreIoAuditKind::Refusal, refusal_reason),
                        )
                        .await?;
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        let mut result = Err(MutationError::Unavailable);
        for attempt in 0..3 {
            let checked_apply_authority = if matches!(input.action, RequestActionBody::Apply { .. })
            {
                match self
                    .preflight_request_action_receipt(client, registry, &input, claims)
                    .await?
                {
                    RequestReceiptPreflight::Receipt => None,
                    RequestReceiptPreflight::Continue { proposal_authority } => {
                        if let Some(grant) = claims.task_grant() {
                            self.check_task_authority(grant).await?;
                        }
                        if let Some(grant) = proposal_authority.as_deref() {
                            self.check_task_authority(grant).await?;
                        }
                        Some(CheckedApplyTaskAuthority {
                            current: claims.task_grant().cloned(),
                            proposal: proposal_authority.map(|grant| *grant),
                        })
                    }
                }
            } else {
                None
            };
            result = self
                .execute_request_action_transaction(
                    client,
                    registry,
                    &input,
                    claims,
                    route,
                    entity,
                    submission.as_ref(),
                    request_action_statement_timeout(deadline),
                    fault,
                    review_evidence,
                    frozen_evidence,
                    checked_apply_authority.as_ref(),
                )
                .await;
            if tokio::time::Instant::now() >= deadline
                && result == Err(MutationError::RetryableConflict)
            {
                result = Err(MutationError::Unavailable);
            }
            // Only a positively identified transaction abort is retried.
            // Connection failures and uncertain commit outcomes require normal
            // idempotency recovery, never speculative re-execution here.
            if result != Err(MutationError::RetryableConflict)
                || attempt == 2
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        if result.is_err() && !fault.is_enabled() {
            record_pre_io_audit(
                client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                claims,
                &self.audit_profile,
                audit(PreIoAuditKind::Refusal, None),
            )
            .await?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn plan_submission_candidate(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        route: &CompiledRoute,
        entity: &CompiledEntity,
        deadline: tokio::time::Instant,
    ) -> Result<Option<SubmissionCandidate>, MutationError> {
        let body = action_binding_json(input)?;
        let digest: [u8; 32] =
            Sha256::digest(canonicalize_json(&body).map_err(|_| MutationError::InvalidRequest)?)
                .into();
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: route.method,
                route: &route.path,
                target_record: Some(input.record_id),
                package_revision: &self.expected.package_revision,
                response_fields: &input.response_fields,
                canonical_request_digest: digest,
                key_domain: IdempotencyKeyDomain::Caller,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        set_transaction_statement_timeout(
            transaction.transaction(),
            request_action_statement_timeout(deadline),
        )
        .await?;
        let request_id =
            Uuid::parse_str(input.record_id).map_err(|_| MutationError::InvalidRequest)?;
        let actor_reference =
            request_actor_reference(&self.audit_profile, &self.expected.database_id, claims)?;
        let header = transaction
            .transaction()
            .query_opt(
                "SELECT proposal_version FROM registry_internal.registry_request_state
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&entity.id, &request_id],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .ok_or(MutationError::PreconditionFailed)?;
        let action_context = ChangeRequestActionContext::for_route(
            registry,
            claims,
            &route.id,
            request_id,
            header.get::<_, i64>(0),
            &actor_reference,
            &self.expected.package_revision,
        )
        .map_err(|_| MutationError::PreconditionFailed)?;
        transaction
            .install_change_request_action_context(&action_context)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let receipt_exists = transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_idempotency WHERE key_reference = $1",
                &[&binding.key_reference],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some();
        if receipt_exists {
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(None);
        }
        let current = load_row(transaction.transaction(), entity, input.record_id, false).await?;
        let workflow =
            crate::request_store::load(transaction.transaction(), &entity.id, request_id, false)
                .await?;
        let etag = request_action_etag(
            &self.audit_profile,
            claims,
            &self.expected.package_revision,
            route,
            input.record_id,
            current.record_revision,
            &workflow,
            &input.response_fields,
            &input.target_authority,
        )?;
        if etag.as_bytes().ct_eq(input.if_match.as_bytes()).unwrap_u8() != 1
            || workflow.owner().as_str() != actor_reference
            || workflow.state() != RequestState::Draft
        {
            return Err(MutationError::PreconditionFailed);
        }
        let intake = crate::request_store::load_authored_intake(
            transaction.transaction(),
            &entity.id,
            request_id,
            &current.data,
        )
        .await?;
        let workflow_revision = workflow.workflow_revision().get();
        let request_record_revision = current.record_revision;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;

        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let candidate =
            crate::rhai_planner::plan_change_request_effects(plan, &intake, deadline.into_std())
                .map_err(|error| {
                    // The operator learns which entity refused, which planner
                    // ran, and the closed failure kind. Script text, request
                    // values, and target data stay out of the log.
                    tracing::warn!(
                        entity_id = %entity.id,
                        planner_digest = plan
                            .planner
                            .as_ref()
                            .map_or("none", |planner| planner.script_sha256.as_str()),
                        planner_failure = %error.code(),
                        "change-request planner produced no plan"
                    );
                    MutationError::PlannerFailure(error)
                })?;
        let reserved_create_ids = candidate
            .effects
            .iter()
            .filter(|effect| effect.operation == Operation::Create)
            .map(|effect| (effect.id.clone(), Uuid::new_v4()))
            .collect::<BTreeMap<_, _>>();
        let resolved = request_prepare::resolve_targets(
            registry,
            entity,
            &intake,
            candidate,
            &reserved_create_ids,
        )?;
        Ok(Some(SubmissionCandidate {
            request_record_revision,
            workflow_revision,
            intake,
            resolved,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_request_action_transaction(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        route: &CompiledRoute,
        entity: &CompiledEntity,
        submission: Option<&SubmissionCandidate>,
        statement_timeout: Duration,
        fault: FaultControl,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        frozen_evidence: Option<&[crate::action_evidence_client::VerifiedAcquisition]>,
        checked_apply_authority: Option<&CheckedApplyTaskAuthority>,
    ) -> Result<MutationOutcome, MutationError> {
        let body = action_binding_json(input)?;
        let digest: [u8; 32] =
            Sha256::digest(canonicalize_json(&body).map_err(|_| MutationError::InvalidRequest)?)
                .into();
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: route.method,
                route: &route.path,
                target_record: Some(input.record_id),
                package_revision: &self.expected.package_revision,
                response_fields: &input.response_fields,
                canonical_request_digest: digest,
                key_domain: IdempotencyKeyDomain::Caller,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        set_transaction_statement_timeout(transaction.transaction(), statement_timeout).await?;
        let request_id =
            Uuid::parse_str(input.record_id).map_err(|_| MutationError::InvalidRequest)?;
        let actor_reference =
            request_actor_reference(&self.audit_profile, &self.expected.database_id, claims)?;
        // Only the version is read before target-row authorization. No intake,
        // decisions, snapshots, or held response can cross this boundary.
        let header = transaction
            .transaction()
            .query_opt(
                "SELECT proposal_version FROM registry_internal.registry_request_state
             WHERE request_entity_id = $1 AND request_id = $2",
                &[&entity.id, &request_id],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .ok_or(MutationError::PreconditionFailed)?;
        let action_context = ChangeRequestActionContext::for_route(
            registry,
            claims,
            &route.id,
            request_id,
            header.get::<_, i64>(0),
            &actor_reference,
            &self.expected.package_revision,
        )
        .map_err(|_| MutationError::PreconditionFailed)?;
        transaction
            .install_change_request_action_context(&action_context)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        // Materialize and bound a submission before acquiring mutation locks.
        // A retained receipt skips preparation; replay is authorized again below.
        let receipt_exists = transaction
            .transaction()
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_idempotency WHERE key_reference = $1",
                &[&binding.key_reference],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .is_some();
        let mut prepared_submission =
            if matches!(input.action, RequestActionBody::Submit) && !receipt_exists {
                let preview =
                    load_row(transaction.transaction(), entity, input.record_id, false).await?;
                let preview_workflow = crate::request_store::load(
                    transaction.transaction(),
                    &entity.id,
                    request_id,
                    false,
                )
                .await?;
                let preview_etag = request_action_etag(
                    &self.audit_profile,
                    claims,
                    &self.expected.package_revision,
                    route,
                    input.record_id,
                    preview.record_revision,
                    &preview_workflow,
                    &input.response_fields,
                    &input.target_authority,
                )?;
                if preview_etag
                    .as_bytes()
                    .ct_eq(input.if_match.as_bytes())
                    .unwrap_u8()
                    != 1
                {
                    return Err(MutationError::PreconditionFailed);
                }
                if preview_workflow.owner().as_str() != actor_reference {
                    return Err(MutationError::PreconditionFailed);
                }
                let prepared = self
                    .prepare_submission(
                        &transaction,
                        registry,
                        entity,
                        &preview,
                        &preview_workflow,
                        claims,
                        &actor_reference,
                        submission.ok_or(MutationError::Unavailable)?,
                    )
                    .await?;
                Some((
                    preview.record_revision,
                    preview_workflow.workflow_revision().get(),
                    prepared,
                ))
            } else {
                None
            };
        let stored = lock_and_load(transaction.transaction(), &binding).await?;
        if stored.as_ref().is_some_and(|stored| {
            matches!(&stored.metadata, StoredResultMetadata::Application { .. })
                && !matches!(input.action, RequestActionBody::Apply { .. })
        }) {
            return Err(MutationError::PreconditionFailed);
        }
        // Request state serializes every lifecycle operation and draft edit.
        // Read the request row after that lock without demanding UPDATE rights:
        // an applied request remains readable for authorized receipt recovery.
        crate::request_store::load_header(transaction.transaction(), &entity.id, request_id, true)
            .await?;
        let mut current =
            load_row(transaction.transaction(), entity, input.record_id, false).await?;
        // Consult frozen payloads only after the typed request row passes its
        // exact action RLS policy. Erased or out-of-scope rows are concealed
        // without attempting to deserialize retained-away detail.
        let workflow =
            crate::request_store::load(transaction.transaction(), &entity.id, request_id, false)
                .await?;
        let record_uuid = current.record_uuid;
        if matches!(
            input.action,
            RequestActionBody::Submit | RequestActionBody::Revise { .. }
        ) {
            admit_submitter_targets(
                transaction.transaction(),
                entity,
                registry.entities(),
                claims,
                &current.data,
            )
            .await?;
        }
        if let Some(stored) = stored {
            if workflow.current_proposal().is_some() {
                let targets = crate::request_store::load_targets(
                    transaction.transaction(),
                    &entity.id,
                    record_uuid,
                    i64::from(workflow.current_version().get()),
                )
                .await?;
                self.authorize_targets(
                    registry,
                    input,
                    claims,
                    entity,
                    &workflow,
                    &targets,
                    &actor_reference,
                )?;
            }
            append_terminal_audit(
                transaction.transaction(),
                &self.audit_profile,
                self.request_terminal(
                    input,
                    claims,
                    route,
                    &binding,
                    current.record_revision,
                    TerminalAuditOutcome::Replayed,
                ),
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(MutationOutcome {
                response: stored.response,
                replayed: true,
            });
        }
        if let RequestActionBody::Apply {
            proposal_version,
            effect_digest,
            ..
        } = &input.action
        {
            if workflow.state() == RequestState::Applied {
                let application = workflow.application().ok_or(MutationError::Unavailable)?;
                if application.version().get() != *proposal_version
                    || application.effect_digest().as_str() != effect_digest
                {
                    return Err(MutationError::PreconditionFailed);
                }
                // Applied requests are immutable. Application advances both
                // counters once, so recover the exact approved-state action
                // precondition under this caller's current authority. A
                // different idempotency key must not accept a page, another
                // profile's action, or an arbitrary syntactically valid ETag.
                let precondition = request_action_etag_for_revisions(
                    &self.audit_profile,
                    claims,
                    &self.expected.package_revision,
                    route,
                    input.record_id,
                    current
                        .record_revision
                        .checked_sub(1)
                        .ok_or(MutationError::Unavailable)?,
                    workflow
                        .workflow_revision()
                        .get()
                        .checked_sub(1)
                        .ok_or(MutationError::Unavailable)?,
                    &workflow,
                    &input.response_fields,
                    &input.target_authority,
                )?;
                if input
                    .if_match
                    .as_bytes()
                    .ct_eq(precondition.as_bytes())
                    .unwrap_u8()
                    != 1
                {
                    return Err(MutationError::PreconditionFailed);
                }
                let targets = crate::request_store::load_targets(
                    transaction.transaction(),
                    &entity.id,
                    record_uuid,
                    i64::from(*proposal_version),
                )
                .await?;
                self.authorize_targets(
                    registry,
                    input,
                    claims,
                    entity,
                    &workflow,
                    &targets,
                    &actor_reference,
                )?;
                // A new idempotency key has no retained authority binding.
                // Check read-only guards against the current apply grant too.
                self.authorize_applied_guard_targets(
                    transaction.transaction(),
                    registry,
                    input,
                    claims,
                    entity,
                    &workflow,
                    &actor_reference,
                )
                .await?;
                let snapshot_reference = request_revision_snapshot_reference(
                    transaction.transaction(),
                    &entity.id,
                    record_uuid,
                    current.record_revision,
                )
                .await?;
                let held = request_action_response(
                    input.record_id,
                    current.record_revision,
                    snapshot_reference,
                    &workflow,
                    &actor_reference,
                )?;
                let metadata = StoredResultMetadata::Application {
                    record_reference: record_reference(
                        &self.audit_profile,
                        &self.expected.package_revision,
                        input.record_id,
                    )?,
                    record_revision: current.record_revision,
                    proposal_version: i64::from(*proposal_version),
                    result_count: u16::try_from(application.result_links().len())
                        .map_err(|_| MutationError::Unavailable)?,
                };
                append_terminal_audit(
                    transaction.transaction(),
                    &self.audit_profile,
                    self.request_terminal(
                        input,
                        claims,
                        route,
                        &binding,
                        current.record_revision,
                        TerminalAuditOutcome::Replayed,
                    ),
                )
                .await?;
                insert_result(transaction.transaction(), &binding, &metadata, &held).await?;
                crate::request_store::link_idempotency_result(
                    transaction.transaction(),
                    &binding.key_reference,
                    &entity.id,
                    record_uuid,
                    i64::from(*proposal_version),
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                return Ok(MutationOutcome {
                    response: held,
                    replayed: true,
                });
            }
        }
        let etag = request_action_etag(
            &self.audit_profile,
            claims,
            &self.expected.package_revision,
            route,
            input.record_id,
            current.record_revision,
            &workflow,
            &input.response_fields,
            &input.target_authority,
        )?;
        if etag.as_bytes().ct_eq(input.if_match.as_bytes()).unwrap_u8() != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        if action_requires_request_owner(&input.action)
            && workflow.owner().as_str() != actor_reference
        {
            return Err(MutationError::PreconditionFailed);
        }
        if matches!(input.action, RequestActionBody::Apply { .. }) {
            checked_apply_authority
                .ok_or(MutationError::Unavailable)?
                .verify_current(claims)?;
        } else if let Some(grant) = claims.task_grant() {
            self.check_task_authority(grant).await?;
        }
        if let RequestActionBody::Revise { rebase } = &input.action {
            // The read advertises revise from the same settled outcome: a
            // rejection leaves only cancellation, and a send-back or an
            // expired approval is answered by a revision, never a rebase.
            match crate::review_store::settled_outcome(
                transaction.transaction(),
                &entity.id,
                record_uuid,
                workflow.current_version().get(),
            )
            .await?
            {
                Some(crate::review_store::SettledReviewOutcome::Rejected) => {
                    return Err(MutationError::Conflict)
                }
                Some(
                    crate::review_store::SettledReviewOutcome::ChangesRequested
                    | crate::review_store::SettledReviewOutcome::Approved { expired: true },
                ) if *rebase => return Err(MutationError::Conflict),
                _ => {}
            }
        }
        let previous_revision = i64::try_from(workflow.workflow_revision().get())
            .map_err(|_| MutationError::Unavailable)?;
        let save_previous_revision = previous_revision;
        let previous_state = workflow.state();
        let previous_version = workflow.current_version().get();
        let trusted = TrustedTransitionContext::from_verified_context(
            TrustedActorRef::from_verified_context(&actor_reference)
                .map_err(|_| MutationError::Unavailable)?,
            request_timestamp(time::OffsetDateTime::now_utc())?,
        );
        let mut prepared_targets = None;
        let mut application_count = None;
        let mut application_result_revisions = Vec::new();
        let next = match &input.action {
            RequestActionBody::Submit => {
                let (record_revision, workflow_revision, prepared) = prepared_submission
                    .take()
                    .ok_or(MutationError::Unavailable)?;
                if record_revision != current.record_revision
                    || workflow_revision != workflow.workflow_revision().get()
                {
                    return Err(MutationError::PreconditionFailed);
                }
                let attachments = crate::attachment_store::manifest(
                    transaction.transaction(),
                    &entity.id,
                    current.record_uuid,
                    i64::from(workflow.current_version().get()),
                )
                .await?;
                validate_submission_attachments(&entity.attachments, &attachments)?;
                let proposal = prepared
                    .proposal
                    .with_attachments(attachments)
                    .map_err(workflow_error)?;
                prepared_targets = Some(prepared.targets);
                workflow
                    .submit(trusted.clone(), proposal)
                    .map_err(workflow_error)?
                    .into_workflow()
            }
            RequestActionBody::Revise { rebase } => if *rebase {
                workflow.rebase(trusted.clone())
            } else {
                workflow.revise(trusted.clone())
            }
            .map_err(workflow_error)?
            .into_workflow(),
            RequestActionBody::Cancel => workflow
                .cancel(trusted.clone())
                .map_err(workflow_error)?
                .into_workflow(),
            RequestActionBody::Apply {
                proposal_version,
                effect_digest,
                ..
            } => {
                let applied = self
                    .apply_approved_request(
                        &transaction,
                        registry,
                        input,
                        claims,
                        route,
                        entity,
                        workflow,
                        &current.data,
                        &actor_reference,
                        trusted.clone(),
                        *proposal_version,
                        effect_digest,
                        None,
                        review_evidence,
                        &binding,
                        fault,
                        frozen_evidence,
                        checked_apply_authority.ok_or(MutationError::Unavailable)?,
                    )
                    .await?;
                application_count = Some(applied.result_count);
                application_result_revisions = applied.result_revisions;
                applied.workflow
            }
        };
        if matches!(input.action, RequestActionBody::Revise { .. }) {
            crate::attachment_store::carry_forward(
                transaction.transaction(),
                &entity.id,
                current.record_uuid,
                i64::from(previous_version),
                i64::from(next.current_version().get()),
            )
            .await?;
        }
        // Restore the ordinary request context before advancing its revision.
        transaction
            .transaction()
            .execute(
                "SELECT set_config('registry.change_request_target_context', '', true)",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        current = advance_request_revision(transaction.transaction(), entity, &current).await?;
        let request_reference = record_reference(
            &self.audit_profile,
            &self.expected.package_revision,
            input.record_id,
        )?;
        fault.fail_at(MutationFaultPoint::BeforeRevision)?;
        self.insert_request_revision(
            transaction.transaction(),
            input,
            route,
            &current,
            &request_reference,
            &binding,
        )
        .await?;
        crate::request_store::save(
            transaction.transaction(),
            &entity.id,
            record_uuid,
            save_previous_revision,
            &next,
        )
        .await?;
        if matches!(
            input.action,
            RequestActionBody::Revise { .. } | RequestActionBody::Cancel
        ) {
            crate::review_store::schedule_cancellation(
                transaction.transaction(),
                &entity.id,
                record_uuid,
                i64::from(previous_version),
            )
            .await?;
        }
        if matches!(input.action, RequestActionBody::Submit) {
            let proposal = next.current_proposal().ok_or(MutationError::Unavailable)?;
            if matches!(
                proposal.review_requirement(),
                crate::model::CompiledChangeRequestReview::Required(_)
            ) {
                crate::review_store::enqueue_submission(
                    transaction.transaction(),
                    registry,
                    &entity.id,
                    record_uuid,
                    proposal,
                    &actor_reference,
                    claims.human_identity(),
                    self.review_authorities
                        .as_deref()
                        .ok_or(MutationError::Unavailable)?,
                )
                .await?;
            }
            if let Some(grant) = claims.task_grant() {
                crate::request_store::save_task_authority(
                    transaction.transaction(),
                    &entity.id,
                    record_uuid,
                    i64::from(next.current_version().get()),
                    grant,
                )
                .await?;
            }
        }
        if let Some(acquisitions) = frozen_evidence {
            let application = next.application().ok_or(MutationError::Unavailable)?;
            insert_request_evidence_uses(
                transaction.transaction(),
                Uuid::parse_str(application.application_id().as_str())
                    .map_err(|_| MutationError::Unavailable)?,
                acquisitions,
            )
            .await?;
        }
        if matches!(input.action, RequestActionBody::Apply { .. }) {
            let application = next.application().ok_or(MutationError::Unavailable)?;
            let application_id = Uuid::parse_str(application.application_id().as_str())
                .map_err(|_| MutationError::Unavailable)?;
            transaction
                .transaction()
                .execute(
                    "UPDATE registry_internal.registry_request_application_jobs
                        SET state='applied',application_id=$4,claim_token=NULL,
                            last_error_code=NULL,updated_at=transaction_timestamp()
                      WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3
                        AND state <> 'applied'",
                    &[
                        &entity.id,
                        &record_uuid,
                        &i64::from(next.current_version().get()),
                        &application_id,
                    ],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
        }
        crate::request_store::link_request_revision(
            transaction.transaction(),
            &entity.id,
            record_uuid,
            current.record_revision,
            &entity.id,
            record_uuid,
            i64::from(next.current_version().get()),
            "request_lifecycle",
        )
        .await?;
        if let Some(targets) = prepared_targets {
            crate::request_store::save_targets(
                transaction.transaction(),
                &entity.id,
                record_uuid,
                i64::from(next.current_version().get()),
                &targets,
            )
            .await?;
        }
        fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
        let deliveries = exact_entity_event_deliveries(registry, entity)?;
        let data_schemas = event_data_schemas(
            registry.registry_id(),
            entity,
            EventTrigger::RequestLifecycle,
            &deliveries,
        )?;
        let event_source = self.event_source();
        crate::request_events::insert_request_lifecycle_events(
            transaction.transaction(),
            &entity.hooks,
            &deliveries,
            self.event_destinations.as_deref(),
            crate::request_events::RequestLifecycleEvent {
                request_entity_id: &entity.id,
                request_id: record_uuid,
                request_record_reference: &request_reference,
                request_record_revision: current.record_revision,
                proposal_version: next.current_version().get(),
                workflow_revision: next.workflow_revision().get(),
                from_state: request_state_name(previous_state),
                to_state: request_state_name(next.state()),
                transition: match input.action {
                    RequestActionBody::Submit => "submit",
                    RequestActionBody::Revise { rebase: true } => "rebase",
                    RequestActionBody::Revise { rebase: false } => "revise",
                    RequestActionBody::Cancel => "cancel",
                    RequestActionBody::Apply { .. } => "apply",
                },
                reason: input.action.reason(),
                effect_digest: next
                    .current_proposal()
                    .map(|proposal| proposal.effect_digest().as_str()),
                package_revision: &self.expected.package_revision,
                schema_fingerprint: &self.expected.schema_fingerprint,
                request_values: &current.data,
                payload_retention: self
                    .event_destinations
                    .as_ref()
                    .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                        destinations.payload_retention()
                    }),
                envelope: EnvelopeBinding {
                    source: &event_source,
                    data_schemas: &data_schemas,
                    causation: None,
                },
            },
        )
        .await?;
        let mut commit_member_records = Vec::with_capacity(application_result_revisions.len() + 1);
        commit_member_records.push((entity.id.clone(), record_uuid, current.record_revision));
        commit_member_records.extend(application_result_revisions);
        let commit_members = commit_member_records
            .iter()
            .map(
                |(entity_id, record_id, record_revision)| RevisionCommitMember {
                    entity_id: entity_id.as_str(),
                    record_id: *record_id,
                    record_revision: *record_revision,
                },
            )
            .collect::<Vec<_>>();
        let committed = allocate_revision_commit(
            transaction.transaction(),
            CommitAllocation {
                package_revision: &self.expected.package_revision,
                origin: CommitOrigin::Mutation {
                    actor_reference: &binding.principal_reference,
                    request_reference: &binding.binding_reference,
                },
                change_context: None,
                members: &commit_members,
            },
        )
        .await?;
        let held = request_action_response(
            input.record_id,
            current.record_revision,
            committed.reference.to_string(),
            &next,
            &actor_reference,
        )?;
        fault.fail_at(MutationFaultPoint::BeforeTerminalAudit)?;
        append_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            self.request_terminal(
                input,
                claims,
                route,
                &binding,
                current.record_revision,
                TerminalAuditOutcome::Committed,
            ),
        )
        .await?;
        let result_metadata = match application_count {
            Some(result_count) => StoredResultMetadata::Application {
                record_reference: request_reference,
                record_revision: current.record_revision,
                proposal_version: i64::from(next.current_version().get()),
                result_count,
            },
            None => StoredResultMetadata::Record {
                record_reference: request_reference,
                record_revision: current.record_revision,
            },
        };
        fault.fail_at(MutationFaultPoint::BeforeIdempotency)?;
        insert_result(transaction.transaction(), &binding, &result_metadata, &held).await?;
        crate::request_store::link_idempotency_result(
            transaction.transaction(),
            &binding.key_reference,
            &entity.id,
            record_uuid,
            i64::from(next.current_version().get()),
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeCommit)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::AfterCommitBeforeResponseRelease)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_submission(
        &self,
        transaction: &crate::postgres::GuardedTransaction<'_>,
        registry: &CompiledRegistry,
        entity: &CompiledEntity,
        current: &CurrentRow,
        workflow: &RequestWorkflow,
        claims: &ClaimContext,
        actor_reference: &str,
        submission: &SubmissionCandidate,
    ) -> Result<crate::request_prepare::PreparedRequest, MutationError> {
        if workflow.state() != RequestState::Draft
            || current.record_revision != submission.request_record_revision
            || workflow.workflow_revision().get() != submission.workflow_revision
        {
            return Err(MutationError::PreconditionFailed);
        }
        if !entity.access_profiles[claims.access_profile()]
            .submitter_targets
            .is_empty()
        {
            crate::request_store::load_header(
                transaction.transaction(),
                &entity.id,
                current.record_uuid,
                true,
            )
            .await?;
            admit_submitter_targets(
                transaction.transaction(),
                entity,
                registry.entities(),
                claims,
                &current.data,
            )
            .await?;
        }
        let authored = crate::request_store::load_authored_intake(
            transaction.transaction(),
            &entity.id,
            current.record_uuid,
            &current.data,
        )
        .await?;
        if authored != submission.intake {
            return Err(MutationError::PreconditionFailed);
        }
        let resolved = &submission.resolved;
        let mut bases = BTreeMap::new();
        for ((target_entity_id, target_record_id), operation) in &resolved.records {
            if *operation != Operation::Patch {
                continue;
            }
            let effect = resolved
                .candidate
                .effects
                .iter()
                .find(|effect| {
                    effect.target.entity_id == *target_entity_id
                        && resolved.effect_records.get(&effect.id) == Some(target_record_id)
                })
                .ok_or(MutationError::InvalidRequest)?;
            let target_binding = target_binding(
                entity,
                workflow,
                effect,
                *target_record_id,
                None,
                &self.expected.package_revision,
                actor_reference,
            )?;
            let context =
                ChangeRequestTargetContext::for_preparation(registry, claims, target_binding)
                    .map_err(|_| MutationError::PreconditionFailed)?;
            transaction
                .install_change_request_target_context(&context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let target_entity = &registry.entities()[target_entity_id];
            let base = load_row(
                transaction.transaction(),
                target_entity,
                &target_record_id.to_string(),
                false,
            )
            .await?;
            bases.insert(
                (target_entity_id.clone(), *target_record_id),
                (base.record_revision, base.data),
            );
        }
        let mut guard_bases = BTreeMap::new();
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        for guard in &plan.application.preconditions.targets {
            let record_id = submission
                .intake
                .get(&guard.from_field)
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(MutationError::InvalidRequest)?;
            let binding = guard_target_binding(
                entity,
                workflow,
                plan,
                guard,
                record_id,
                None,
                &self.expected.package_revision,
                actor_reference,
            )?;
            let context = ChangeRequestTargetContext::for_preparation(registry, claims, binding)
                .map_err(|_| MutationError::PreconditionFailed)?;
            transaction
                .install_change_request_target_context(&context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let target_entity = registry
                .entities()
                .get(&guard.entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let base = load_row(
                transaction.transaction(),
                target_entity,
                &record_id.to_string(),
                false,
            )
            .await?;
            guard_bases.insert(
                guard.id.clone(),
                (record_id, base.record_revision, base.data),
            );
        }
        let prepared = request_prepare::prepare(
            registry,
            entity,
            &submission.intake,
            current.record_uuid,
            current.record_revision,
            &self.expected.package_revision,
            resolved,
            bases,
            guard_bases,
        )?;
        Ok(prepared)
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_approved_request(
        &self,
        transaction: &crate::postgres::GuardedTransaction<'_>,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        route: &CompiledRoute,
        entity: &CompiledEntity,
        workflow: RequestWorkflow,
        request_data: &Map<String, Value>,
        actor_reference: &str,
        trusted: TrustedTransitionContext,
        proposal_version: u32,
        effect_digest: &str,
        targets_override: Option<&[RequestTargetSnapshot]>,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        fault: FaultControl,
        frozen_evidence: Option<&[crate::action_evidence_client::VerifiedAcquisition]>,
        checked_task_authority: &CheckedApplyTaskAuthority,
    ) -> Result<AppliedRequest, MutationError> {
        if workflow.state() != RequestState::Submitted {
            return Err(MutationError::Conflict);
        }
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        if !plan.application.preconditions.evidence.is_empty() && frozen_evidence.is_none() {
            return Err(MutationError::PreconditionFailed);
        }
        if proposal.contract_fingerprint().as_str() != plan.contract_fingerprint
            || proposal.version().get() != proposal_version
            || proposal.effect_digest().as_str() != effect_digest
        {
            return Err(MutationError::PreconditionFailed);
        }
        let proposal_authority = crate::request_store::load_task_authority(
            transaction.transaction(),
            &entity.id,
            Uuid::parse_str(workflow.request().record_id().as_str())
                .map_err(|_| MutationError::InvalidRequest)?,
            i64::from(proposal_version),
        )
        .await?;
        if proposal_authority != checked_task_authority.proposal
            || proposal_authority
                .as_ref()
                .is_some_and(|grant| !grant.is_current())
        {
            return Err(MutationError::PreconditionFailed);
        }
        let loaded_targets;
        let targets = if let Some(targets) = targets_override {
            targets
        } else {
            loaded_targets = crate::request_store::load_targets(
                transaction.transaction(),
                &entity.id,
                Uuid::parse_str(workflow.request().record_id().as_str())
                    .map_err(|_| MutationError::InvalidRequest)?,
                i64::from(proposal_version),
            )
            .await?;
            &loaded_targets
        };
        let contexts = self.authorize_targets(
            registry,
            input,
            claims,
            entity,
            &workflow,
            targets,
            actor_reference,
        )?;
        let observed = self
            .lock_and_verify_application_preconditions(
                transaction,
                registry,
                input,
                claims,
                entity,
                &workflow,
                request_data,
                targets,
                &contexts,
                actor_reference,
                frozen_evidence,
            )
            .await?;
        let mut written = BTreeSet::new();
        let mut links = Vec::new();
        let mut result_revisions = Vec::new();
        for effect in proposal.effects() {
            let target_id = effect
                .target()
                .existing_record_id()
                .or_else(|| effect.target().reserved_record_id())
                .ok_or(MutationError::InvalidRequest)?;
            let target_uuid =
                Uuid::parse_str(target_id.as_str()).map_err(|_| MutationError::InvalidRequest)?;
            let key = (effect.target().entity_id().as_str().to_owned(), target_uuid);
            if !written.insert(key.clone()) {
                continue;
            }
            let target = targets
                .iter()
                .find(|target| target.entity_id == key.0 && target.record_id == key.1)
                .ok_or(MutationError::InvalidRequest)?;
            transaction
                .install_change_request_target_context(&contexts[&key])
                .await
                .map_err(|_| MutationError::Unavailable)?;
            fault.fail_at(MutationFaultPoint::BeforeCurrentRow)?;
            let approved_fields = proposal
                .effects()
                .iter()
                .filter(|candidate| {
                    candidate.target().entity_id().as_str() == target.entity_id
                        && candidate
                            .target()
                            .existing_record_id()
                            .or_else(|| candidate.target().reserved_record_id())
                            .is_some_and(|id| id.as_str() == target.record_id.to_string())
                })
                .flat_map(|candidate| {
                    candidate
                        .field_changes()
                        .iter()
                        .map(|change| change.field().as_str().to_owned())
                })
                .collect::<BTreeSet<_>>();
            let result = self
                .apply_request_target(
                    transaction.transaction(),
                    registry,
                    input,
                    claims,
                    route,
                    target,
                    &approved_fields,
                    binding,
                    fault,
                )
                .await?;
            result_revisions.push((
                target.entity_id.clone(),
                result.record_uuid,
                result.record_revision,
            ));
            links.push(ApplicationResultLink::new(
                EntityId::new(&target.entity_id).map_err(workflow_error)?,
                RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,
                RecordRevision::new(result.record_revision).map_err(workflow_error)?,
            ));
            if written.len() == 1 {
                fault.fail_at(MutationFaultPoint::AfterFirstBatchItem)?;
            }
        }
        let result_count = u16::try_from(links.len()).map_err(|_| MutationError::Unavailable)?;
        let workflow = workflow
            .apply(
                trusted,
                ProposalVersion::new(proposal_version).map_err(workflow_error)?,
                &ProposalDigest::new(effect_digest).map_err(workflow_error)?,
                &ContractFingerprint::new(&plan.contract_fingerprint).map_err(workflow_error)?,
                review_evidence,
                observed,
                PreparedApplication::new(
                    ApplicationId::new(Uuid::new_v4().to_string()).map_err(workflow_error)?,
                    links,
                )
                .map_err(workflow_error)?,
                input.action.reason().map(str::to_owned),
            )
            .map_err(workflow_error)?
            .into_workflow();
        Ok(AppliedRequest {
            workflow,
            result_count,
            result_revisions,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_targets(
        &self,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        entity: &CompiledEntity,
        workflow: &RequestWorkflow,
        targets: &[RequestTargetSnapshot],
        actor: &str,
    ) -> Result<BTreeMap<(String, Uuid), ChangeRequestTargetContext>, MutationError> {
        let mut contexts = BTreeMap::new();
        if !matches!(input.action, RequestActionBody::Apply { .. }) {
            return Ok(contexts);
        }
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        request_prepare::validate_frozen_targets(proposal, targets)?;
        if proposal.contract_fingerprint().as_str() != plan.contract_fingerprint {
            return Err(MutationError::PreconditionFailed);
        }
        for effect in proposal.effects() {
            let record = effect
                .target()
                .existing_record_id()
                .or_else(|| effect.target().reserved_record_id())
                .ok_or(MutationError::InvalidRequest)?;
            let uuid =
                Uuid::parse_str(record.as_str()).map_err(|_| MutationError::InvalidRequest)?;
            let target = targets
                .iter()
                .find(|target| {
                    target.entity_id == effect.target().entity_id().as_str()
                        && target.record_id == uuid
                })
                .ok_or(MutationError::PreconditionFailed)?;
            let authority = input
                .target_authority
                .iter()
                .find(|authority| authority.target_entity_id == target.entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let boundaries = authority
                .row_boundaries
                .iter()
                .map(|boundary| match boundary.operator() {
                    ApiBoundaryOperator::Equals if boundary.values().len() == 1 => {
                        Ok(RowBoundaryContext::Equals {
                            field: boundary.field().to_owned(),
                            value: boundary
                                .values()
                                .iter()
                                .next()
                                .ok_or(MutationError::InvalidRequest)?
                                .clone(),
                        })
                    }
                    ApiBoundaryOperator::In => Ok(RowBoundaryContext::In {
                        field: boundary.field().to_owned(),
                        values: boundary.values().clone(),
                    }),
                    _ => Err(MutationError::InvalidRequest),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let binding = frozen_target_binding(
                entity,
                workflow,
                effect,
                uuid,
                target.expected_revision,
                &self.expected.package_revision,
                actor,
            )?;
            let context =
                ChangeRequestTargetContext::for_application(registry, claims, boundaries, binding)
                    .map_err(|_| MutationError::PreconditionFailed)?;
            context
                .authorize_rows(
                    &registry.entities()[&target.entity_id],
                    target.before.as_ref(),
                    &target.after,
                    target.record_id,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
            contexts.insert((target.entity_id.clone(), target.record_id), context);
        }
        if contexts.len() != targets.len() {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(contexts)
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_applied_guard_targets(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        entity: &CompiledEntity,
        workflow: &RequestWorkflow,
        actor: &str,
    ) -> Result<(), MutationError> {
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        let Some(frozen) = proposal.application_preconditions() else {
            return if plan.application.preconditions.is_empty() {
                Ok(())
            } else {
                Err(MutationError::PreconditionFailed)
            };
        };
        frozen
            .validate()
            .map_err(|_| MutationError::PreconditionFailed)?;
        if frozen.contract != plan.application.preconditions {
            return Err(MutationError::PreconditionFailed);
        }
        for guard in &frozen.targets {
            let compiled = frozen
                .contract
                .targets
                .iter()
                .find(|candidate| candidate.id == guard.id)
                .ok_or(MutationError::PreconditionFailed)?;
            let record_id = Uuid::parse_str(guard.record_id.as_str())
                .map_err(|_| MutationError::PreconditionFailed)?;
            let authority = input
                .target_authority
                .iter()
                .find(|authority| authority.target_entity_id == guard.entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let row = transaction
                .query_opt(
                    "SELECT snapshot FROM registry_internal.registry_revisions WHERE entity_id=$1 AND record_id=$2 AND record_revision=$3 AND erased_at IS NULL",
                    &[&guard.entity_id, &record_id, &guard.expected_revision],
                )
                .await
                .map_err(|_| MutationError::Unavailable)?
                .ok_or(MutationError::PreconditionFailed)?;
            let bytes: Vec<u8> = row
                .try_get::<_, Option<Vec<u8>>>(0)
                .map_err(|_| MutationError::Unavailable)?
                .ok_or(MutationError::PreconditionFailed)?;
            let snapshot = registry_platform_canonical_json::parse_json_strict(&bytes)
                .map_err(|_| MutationError::Unavailable)?;
            if registry_platform_canonical_json::canonicalize_json(&snapshot)
                .map_err(|_| MutationError::Unavailable)?
                != bytes
            {
                return Err(MutationError::Unavailable);
            }
            let snapshot = snapshot.as_object().ok_or(MutationError::Unavailable)?;
            if guard
                .values
                .iter()
                .any(|(field, value)| snapshot.get(field) != Some(value))
            {
                return Err(MutationError::PreconditionFailed);
            }
            let binding = guard_target_binding(
                entity,
                workflow,
                plan,
                compiled,
                record_id,
                Some(guard.expected_revision),
                &self.expected.package_revision,
                actor,
            )?;
            ChangeRequestTargetContext::for_application(
                registry,
                claims,
                request_authority_boundaries(authority)?,
                binding,
            )
            .map_err(|_| MutationError::PreconditionFailed)?
            .authorize_rows(
                registry
                    .entities()
                    .get(&guard.entity_id)
                    .ok_or(MutationError::InvalidRequest)?,
                Some(snapshot),
                snapshot,
                record_id,
            )
            .map_err(|_| MutationError::PreconditionFailed)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_and_verify_application_preconditions(
        &self,
        transaction: &crate::postgres::GuardedTransaction<'_>,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        entity: &CompiledEntity,
        workflow: &RequestWorkflow,
        request_data: &Map<String, Value>,
        targets: &[RequestTargetSnapshot],
        effect_contexts: &BTreeMap<(String, Uuid), ChangeRequestTargetContext>,
        actor: &str,
        frozen_evidence: Option<&[crate::action_evidence_client::VerifiedAcquisition]>,
    ) -> Result<Vec<ObservedTarget>, MutationError> {
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        let frozen = proposal.application_preconditions();
        if plan.application.preconditions.is_empty() {
            if frozen.is_some() || frozen_evidence.is_some_and(|items| !items.is_empty()) {
                return Err(MutationError::PreconditionFailed);
            }
        } else if frozen.is_none_or(|frozen| frozen.contract != plan.application.preconditions) {
            return Err(MutationError::PreconditionFailed);
        }

        let mut guard_contexts = BTreeMap::new();
        if let Some(frozen) = frozen {
            for guard in &frozen.targets {
                let compiled = plan
                    .application
                    .preconditions
                    .targets
                    .iter()
                    .find(|candidate| candidate.id == guard.id)
                    .ok_or(MutationError::PreconditionFailed)?;
                let authority = input
                    .target_authority
                    .iter()
                    .find(|authority| authority.target_entity_id == guard.entity_id)
                    .ok_or(MutationError::PreconditionFailed)?;
                let boundaries = request_authority_boundaries(authority)?;
                let record_id = Uuid::parse_str(guard.record_id.as_str())
                    .map_err(|_| MutationError::PreconditionFailed)?;
                let binding = guard_target_binding(
                    entity,
                    workflow,
                    plan,
                    compiled,
                    record_id,
                    Some(guard.expected_revision),
                    &self.expected.package_revision,
                    actor,
                )?;
                let context = ChangeRequestTargetContext::for_application(
                    registry, claims, boundaries, binding,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
                guard_contexts.insert((guard.entity_id.clone(), record_id), context);
            }
        }

        // Existing effect targets and read-only guard targets share one total
        // lock order so concurrent applications cannot invert their waits.
        let lock_keys = targets
            .iter()
            .filter_map(|target| {
                target
                    .expected_revision
                    .map(|_| (target.entity_id.clone(), target.record_id))
            })
            .chain(guard_contexts.keys().cloned())
            .collect::<BTreeSet<_>>();
        let mut locked = BTreeMap::new();
        for key in lock_keys {
            let context = guard_contexts
                .get(&key)
                .or_else(|| effect_contexts.get(&key))
                .ok_or(MutationError::PreconditionFailed)?;
            transaction
                .install_change_request_target_context(context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let row = load_row(
                transaction.transaction(),
                registry
                    .entities()
                    .get(&key.0)
                    .ok_or(MutationError::InvalidRequest)?,
                &key.1.to_string(),
                true,
            )
            .await?;
            locked.insert(key, row);
        }

        let mut observed = Vec::new();
        for target in targets {
            if let Some(expected) = target.expected_revision {
                if locked
                    .get(&(target.entity_id.clone(), target.record_id))
                    .is_none_or(|row| row.record_revision != expected)
                {
                    return Err(MutationError::PreconditionFailed);
                }
                observed.push(ObservedTarget::existing(
                    EntityId::new(&target.entity_id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,
                    RecordRevision::new(expected).map_err(workflow_error)?,
                ));
            } else {
                observed.push(ObservedTarget::reserved_create(
                    EntityId::new(&target.entity_id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,
                ));
            }
        }

        if let Some(frozen) = frozen {
            verify_frozen_request_values(frozen, request_data)?;
            let current_date = time::OffsetDateTime::now_utc().date().to_string();
            verify_compiled_predicates(
                &frozen.contract.request,
                &frozen.request_values,
                &frozen.request_values,
                &current_date,
                |field| {
                    entity
                        .fields
                        .get(field)
                        .is_some_and(|field| matches!(field.field_type, FieldTypeSource::Timestamp))
                },
            )?;
            for guard in &frozen.targets {
                let record_id = Uuid::parse_str(guard.record_id.as_str())
                    .map_err(|_| MutationError::PreconditionFailed)?;
                let key = (guard.entity_id.clone(), record_id);
                let row = locked.get(&key).ok_or(MutationError::PreconditionFailed)?;
                if row.record_revision != guard.expected_revision
                    || guard
                        .values
                        .iter()
                        .any(|(field, value)| row.data.get(field) != Some(value))
                {
                    return Err(MutationError::PreconditionFailed);
                }
                guard_contexts[&key]
                    .authorize_rows(
                        &registry.entities()[&guard.entity_id],
                        Some(&row.data),
                        &row.data,
                        record_id,
                    )
                    .map_err(|_| MutationError::PreconditionFailed)?;
                let compiled = frozen
                    .contract
                    .targets
                    .iter()
                    .find(|candidate| candidate.id == guard.id)
                    .ok_or(MutationError::PreconditionFailed)?;
                verify_compiled_predicates(
                    &compiled.requires,
                    &row.data
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    &frozen.request_values,
                    &current_date,
                    |field| {
                        registry.entities()[&guard.entity_id]
                            .fields
                            .get(field)
                            .is_some_and(|field| {
                                matches!(field.field_type, FieldTypeSource::Timestamp)
                            })
                    },
                )?;
            }
            verify_request_evidence(frozen, frozen_evidence.unwrap_or_default(), |field| {
                entity
                    .fields
                    .get(field)
                    .is_some_and(|field| matches!(field.field_type, FieldTypeSource::Timestamp))
            })?;
        }
        Ok(observed)
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_request_target(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        route: &CompiledRoute,
        target: &RequestTargetSnapshot,
        approved_fields: &BTreeSet<String>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        fault: FaultControl,
    ) -> Result<CurrentRow, MutationError> {
        let entity = registry
            .entities()
            .get(&target.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let mut target_route = route.clone();
        target_route.entity_id = entity.id.clone();
        target_route.operation = target.operation;
        let inventory = registry
            .physical_names()
            .entities
            .get(&entity.id)
            .ok_or(MutationError::InvalidRequest)?;
        let plan = MutationPlan {
            registry_id: registry.registry_id().to_owned(),
            route: target_route,
            entity: entity.clone(),
            submitter_target_entities: BTreeMap::new(),
            event_deliveries: exact_entity_event_deliveries(registry, entity)?,
            temporal_exclusion_constraints: temporal_exclusion_constraints(
                registry, entity, inventory,
            )?,
        };
        let id = target.record_id.to_string();
        let request = MutationRequest {
            plan: &plan,
            idempotency_key: input.idempotency_key,
            claims,
            record_id: Some(&id),
            expected_etag: None,
            body: MutationBody::Create(target.after.clone()),
            response_fields: BTreeSet::new(),
            representation: crate::record_profile::RecordRepresentation::Json,
            correlation: input.correlation.clone(),
        };
        let mut current = match target.expected_revision {
            None => {
                apply_create_row(transaction, &request, &id, self.field_encryption.as_deref()).await
            }
            Some(revision) => {
                // Even no-op effects write only the approved field ceiling.
                let changed = approved_fields
                    .iter()
                    .map(|field| {
                        Ok((
                            field.clone(),
                            target
                                .after
                                .get(field)
                                .ok_or(MutationError::InvalidRequest)?
                                .clone(),
                        ))
                    })
                    .collect::<Result<Map<_, _>, MutationError>>()?;
                apply_patch_row(
                    transaction,
                    &request,
                    revision,
                    changed,
                    self.field_encryption.as_deref(),
                )
                .await
            }
        }
        .map_err(|error| match error {
            // Apply authority does not grant target field disclosure. Keep
            // the same public conflict for every frozen target pattern failure.
            MutationError::FieldPatternViolation { .. } => MutationError::Conflict,
            other => other,
        })?;
        current.predecessor_revision = target.expected_revision;
        current.before_data = target.before.clone();
        let reference =
            record_reference(&self.audit_profile, &self.expected.package_revision, &id)?;
        // The target journal describes the canonical entity operation. The
        // protected request-results relation records its request provenance.
        let target_operation_id =
            format!("records.{}.{}", entity.id, mutation_kind(target.operation));
        fault.fail_at(MutationFaultPoint::BeforeRevision)?;
        insert_revision(
            transaction,
            RevisionInsert {
                entity_id: &entity.id,
                record_id: target.record_id,
                record_reference: &reference,
                record_revision: current.record_revision,
                predecessor_revision: target.expected_revision,
                lifecycle: "active",
                package_revision: &self.expected.package_revision,
                operation_id: &target_operation_id,
                mutation_kind: mutation_kind(target.operation),
                principal_reference: &binding.principal_reference,
                request_reference: &binding.binding_reference,
                snapshot: &canonical_snapshot(&current.data)?,
            },
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
        let trigger = mutation_trigger(target.operation);
        let data_schemas =
            event_data_schemas(&plan.registry_id, entity, trigger, &plan.event_deliveries)?;
        let event_source = self.event_source();
        insert_configured_events(
            transaction,
            entity,
            &plan.event_deliveries,
            self.event_destinations.as_deref(),
            OutboxMutation {
                trigger,
                application_reference: None,
                entity_id: &entity.id,
                record_id: &id,
                record_reference: &reference,
                record_revision: current.record_revision,
                package_revision: &self.expected.package_revision,
                schema_fingerprint: &self.expected.schema_fingerprint,
                before: target.before.as_ref(),
                after: Some(&current.data),
                payload_retention: self
                    .event_destinations
                    .as_deref()
                    .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                        destinations.payload_retention()
                    }),
                envelope: EnvelopeBinding {
                    source: &event_source,
                    data_schemas: &data_schemas,
                    causation: None,
                },
            },
        )
        .await?;
        Ok(current)
    }

    async fn insert_request_revision(
        &self,
        transaction: &Transaction<'_>,
        input: &RequestActionInput<'_>,
        route: &CompiledRoute,
        current: &CurrentRow,
        reference: &str,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
    ) -> Result<(), MutationError> {
        insert_revision(
            transaction,
            RevisionInsert {
                entity_id: input.entity_id,
                record_id: current.record_uuid,
                record_reference: reference,
                record_revision: current.record_revision,
                predecessor_revision: current.predecessor_revision,
                lifecycle: "active",
                package_revision: &self.expected.package_revision,
                operation_id: &route.id,
                mutation_kind: "patch",
                principal_reference: &binding.principal_reference,
                request_reference: &binding.binding_reference,
                snapshot: &canonical_snapshot(&current.data)?,
            },
        )
        .await
        .map_err(MutationError::from)
    }

    fn request_terminal(
        &self,
        input: &RequestActionInput<'_>,
        claims: &ClaimContext,
        route: &CompiledRoute,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        revision: i64,
        outcome: TerminalAuditOutcome,
    ) -> TerminalAudit {
        TerminalAudit {
            grant: claims.grant_audit().cloned(),
            outcome,
            method: route.method,
            operation_id: route.id.clone(),
            entity_id: Some(input.entity_id.to_owned()),
            action_id: None,
            package_revision: self.expected.package_revision.clone(),
            selected_access_profile: claims.access_profile().to_owned(),
            purpose_present: claims.purpose().is_some(),
            principal_reference: Some(binding.principal_reference.clone()),
            record_reference: Some(binding.record_reference.clone()),
            record_revision: Some(revision),
            result_count: None,
            field_set_reference: None,
            correlation: input.correlation.clone(),
        }
    }
}

fn request_timestamp(now: time::OffsetDateTime) -> Result<TrustedTimestamp, MutationError> {
    // PostgreSQL persists microseconds. Canonical fixed precision keeps the
    // initial held receipt identical to recovery after a database round trip.
    let value = now
        .to_offset(time::UtcOffset::UTC)
        .format(time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
        ))
        .map_err(|_| MutationError::Unavailable)?;
    TrustedTimestamp::from_server_clock(value).map_err(|_| MutationError::Unavailable)
}

fn request_action_statement_timeout(deadline: tokio::time::Instant) -> Duration {
    deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .saturating_sub(REQUEST_ACTION_STATEMENT_TIMEOUT_HEADROOM)
        .max(Duration::from_millis(1))
}

async fn set_transaction_statement_timeout(
    transaction: &Transaction<'_>,
    timeout: Duration,
) -> Result<(), MutationError> {
    let timeout_millis =
        i32::try_from(timeout.as_millis()).map_err(|_| MutationError::Unavailable)?;
    transaction
        .execute(
            "SELECT set_config('statement_timeout', $1::text, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

fn target_binding(
    entity: &CompiledEntity,
    workflow: &RequestWorkflow,
    effect: &CandidateChangeRequestEffect,
    target_record_id: Uuid,
    expected_revision: Option<i64>,
    package_revision: &str,
    actor: &str,
) -> Result<ChangeRequestTargetBinding, MutationError> {
    Ok(ChangeRequestTargetBinding {
        request_entity_id: entity.id.clone(),
        request_id: Uuid::parse_str(workflow.request().record_id().as_str())
            .map_err(|_| MutationError::InvalidRequest)?,
        proposal_version: i64::from(workflow.current_version().get()),
        contract_fingerprint: entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?
            .contract_fingerprint
            .clone(),
        effect_digest: workflow
            .current_proposal()
            .map_or(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                |proposal| proposal.effect_digest().as_str(),
            )
            .to_owned(),
        active_package_revision: package_revision.to_owned(),
        actor_reference: actor.to_owned(),
        effect_id: effect.id.clone(),
        target_entity_id: effect.target.entity_id.clone(),
        target_record_id,
        operation: effect.operation,
        expected_revision,
        fields: effect
            .mutations
            .iter()
            .map(|mutation| match mutation {
                CandidateChangeRequestMutation::Set { field, .. }
                | CandidateChangeRequestMutation::Clear { field } => field.clone(),
            })
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn guard_target_binding(
    entity: &CompiledEntity,
    workflow: &RequestWorkflow,
    plan: &crate::model::CompiledChangeRequest,
    guard: &crate::model::CompiledChangeRequestGuardTarget,
    target_record_id: Uuid,
    expected_revision: Option<i64>,
    package_revision: &str,
    actor: &str,
) -> Result<ChangeRequestTargetBinding, MutationError> {
    let fields = guard
        .requires
        .iter()
        .map(|predicate| predicate.field.clone())
        .chain(
            plan.application
                .preconditions
                .evidence
                .iter()
                .flat_map(|evidence| evidence.subjects.values())
                .flat_map(|subject| subject.selectors.values())
                .filter_map(|selector| match selector {
                    crate::model::CompiledChangeRequestSelector::TargetField { target, field }
                        if target == &guard.id =>
                    {
                        Some(field.clone())
                    }
                    _ => None,
                }),
        )
        .collect();
    Ok(ChangeRequestTargetBinding {
        request_entity_id: entity.id.clone(),
        request_id: Uuid::parse_str(workflow.request().record_id().as_str())
            .map_err(|_| MutationError::InvalidRequest)?,
        proposal_version: i64::from(workflow.current_version().get()),
        contract_fingerprint: plan.contract_fingerprint.clone(),
        effect_digest: workflow
            .current_proposal()
            .map_or(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                |proposal| proposal.effect_digest().as_str(),
            )
            .to_owned(),
        active_package_revision: package_revision.to_owned(),
        actor_reference: actor.to_owned(),
        effect_id: guard.id.clone(),
        target_entity_id: guard.entity_id.clone(),
        target_record_id,
        operation: Operation::Patch,
        expected_revision,
        fields,
    })
}

fn frozen_target_binding(
    entity: &CompiledEntity,
    workflow: &RequestWorkflow,
    effect: &crate::request_workflow::PreparedEffect,
    target_record_id: Uuid,
    expected_revision: Option<i64>,
    package_revision: &str,
    actor: &str,
) -> Result<ChangeRequestTargetBinding, MutationError> {
    Ok(ChangeRequestTargetBinding {
        request_entity_id: entity.id.clone(),
        request_id: Uuid::parse_str(workflow.request().record_id().as_str())
            .map_err(|_| MutationError::InvalidRequest)?,
        proposal_version: i64::from(workflow.current_version().get()),
        contract_fingerprint: workflow
            .current_proposal()
            .ok_or(MutationError::Conflict)?
            .contract_fingerprint()
            .as_str()
            .to_owned(),
        effect_digest: workflow
            .current_proposal()
            .ok_or(MutationError::Conflict)?
            .effect_digest()
            .as_str()
            .to_owned(),
        active_package_revision: package_revision.to_owned(),
        actor_reference: actor.to_owned(),
        effect_id: effect.id().as_str().to_owned(),
        target_entity_id: effect.target().entity_id().as_str().to_owned(),
        target_record_id,
        operation: effect.operation(),
        expected_revision,
        fields: effect
            .field_changes()
            .iter()
            .map(|change| change.field().as_str().to_owned())
            .collect(),
    })
}

async fn load_row(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    id: &str,
    lock: bool,
) -> Result<CurrentRow, MutationError> {
    let sql = format!(
        "SELECT {} FROM registry_data.{} WHERE record_id = $1::text::uuid
        AND record_lifecycle = 'active'{}",
        returning_projection(entity),
        quote_identifier(&entity.physical_table),
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&id])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity, &row)
}

async fn advance_request_revision(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    current: &CurrentRow,
) -> Result<CurrentRow, MutationError> {
    let sql = format!(
        "UPDATE registry_data.{} SET record_revision = record_revision + 1,
        active_package_revision = DEFAULT, updated_at = transaction_timestamp()
        WHERE record_id = $1 AND record_revision = $2 RETURNING {}",
        quote_identifier(&entity.physical_table),
        returning_projection(entity)
    );
    let row = transaction
        .query_opt(&sql, &[&current.record_uuid, &current.record_revision])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    let mut next = row_to_current(entity, &row)?;
    next.predecessor_revision = Some(current.record_revision);
    Ok(next)
}

fn action_binding_json(input: &RequestActionInput<'_>) -> Result<Value, MutationError> {
    let mut action = match &input.action {
        RequestActionBody::Submit => json!({"operation": "submit"}),
        RequestActionBody::Cancel => json!({"operation": "cancel"}),
        RequestActionBody::Revise { rebase } => json!({"operation": "revise", "rebase": rebase}),
        RequestActionBody::Apply {
            proposal_version,
            effect_digest,
            ..
        } => json!({
            "operation": action_operation(&input.action), "proposalVersion": proposal_version, "effectDigest": effect_digest,
        }),
    };
    if let Some(reason) = input.action.reason() {
        action["reason"] = json!(reason);
    }
    Ok(json!({
        "action": action,
        "ifMatch": input.if_match,
        "targetAuthority": target_authority_binding(&input.target_authority),
    }))
}

fn target_authority_binding(authority: &[crate::api::RequestActionTargetAuthority]) -> Value {
    let authority = authority.iter().map(|authority| json!({
        "targetEntityId": authority.target_entity_id, "readableFields": authority.readable_fields,
        "rowBoundaries": authority.row_boundaries.iter().map(|boundary| json!({
            "field": boundary.field(), "operator": match boundary.operator() { ApiBoundaryOperator::Equals => "equals", ApiBoundaryOperator::In => "in" },
            "values": boundary.values(),
        })).collect::<Vec<_>>(),
    })).collect::<Vec<_>>();
    Value::Array(authority)
}

fn action_operation(action: &RequestActionBody) -> Operation {
    match action {
        RequestActionBody::Submit => Operation::SubmitRequest,
        RequestActionBody::Revise { .. } => Operation::ReviseRequest,
        RequestActionBody::Cancel => Operation::CancelRequest,
        RequestActionBody::Apply { .. } => Operation::ApplyRequest,
    }
}

fn request_action_response(
    record_id: &str,
    record_revision: i64,
    snapshot_reference: String,
    workflow: &RequestWorkflow,
    actor_reference: &str,
) -> Result<HeldResponse, MutationError> {
    let mut request = json!({
        "bregState": workflow.state(),
        "proposalVersion": workflow.current_version().get(),
        "effectDigest": workflow.current_proposal().map(|proposal| proposal.effect_digest().as_str()),
        "application": workflow.application().map(|receipt| json!({
            "applicationId": receipt.application_id().as_str(),
            "proposalVersion": receipt.version().get(),
            "effectDigest": receipt.effect_digest().as_str(),
            "appliedAt": receipt.applied_at().as_str(),
        })),
    });
    if let Some(proposal) = workflow.current_proposal() {
        request["proposal"] = json!({
            "review": proposal.review_requirement(),
        });
    }
    HeldResponse::from_json(
        200,
        &json!({
            "id": record_id,
            "revision": record_revision,
            "snapshot": snapshot_reference,
            "actorReference": actor_reference,
            "request": request,
        }),
        BTreeMap::from([(
            PermittedResponseHeader::ContentType,
            b"application/json".to_vec(),
        )]),
    )
    .map_err(MutationError::from)
}

async fn request_revision_snapshot_reference(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    record_revision: i64,
) -> Result<String, MutationError> {
    let row = transaction
        .query_opt(
            "SELECT revision_commit.snapshot_reference
               FROM registry_internal.registry_revision_commit_members AS member
               JOIN registry_internal.registry_revision_commits AS revision_commit
                 ON revision_commit.commit_position = member.commit_position
              WHERE member.entity_id = $1
                AND member.record_id = $2
                AND member.record_revision = $3",
            &[&entity_id, &record_id, &record_revision],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Unavailable)?;
    Ok(crate::history_reference::SnapshotReference::for_uuid(row.get::<_, Uuid>(0)).to_string())
}

fn workflow_error(_: crate::request_workflow::WorkflowError) -> MutationError {
    MutationError::Conflict
}

fn request_authority_boundaries(
    authority: &crate::api::RequestActionTargetAuthority,
) -> Result<Vec<RowBoundaryContext>, MutationError> {
    authority
        .row_boundaries
        .iter()
        .map(|boundary| match boundary.operator() {
            ApiBoundaryOperator::Equals if boundary.values().len() == 1 => {
                Ok(RowBoundaryContext::Equals {
                    field: boundary.field().to_owned(),
                    value: boundary
                        .values()
                        .iter()
                        .next()
                        .ok_or(MutationError::InvalidRequest)?
                        .clone(),
                })
            }
            ApiBoundaryOperator::In => Ok(RowBoundaryContext::In {
                field: boundary.field().to_owned(),
                values: boundary.values().clone(),
            }),
            _ => Err(MutationError::InvalidRequest),
        })
        .collect()
}

fn verify_frozen_request_values(
    frozen: &crate::request_workflow::FrozenApplicationPreconditions,
    request_data: &Map<String, Value>,
) -> Result<(), MutationError> {
    if frozen
        .request_values
        .iter()
        .any(|(field, value)| request_data.get(field) != Some(value))
    {
        Err(MutationError::PreconditionFailed)
    } else {
        Ok(())
    }
}

fn verify_compiled_predicates(
    predicates: &[crate::model::CompiledChangeRequestPredicate],
    actual: &BTreeMap<String, Value>,
    request_values: &BTreeMap<String, Value>,
    current_date: &str,
    is_timestamp: impl Fn(&str) -> bool,
) -> Result<(), MutationError> {
    for predicate in predicates {
        let value = actual
            .get(&predicate.field)
            .ok_or(MutationError::PreconditionFailed)?;
        let accepted = match &predicate.expected {
            crate::model::CompiledChangeRequestPredicateExpected::Literal { value: expected } => {
                predicate_values_equal(value, expected, is_timestamp(&predicate.field))
            }
            crate::model::CompiledChangeRequestPredicateExpected::RequestField { field } => {
                request_values.get(field).is_some_and(|expected| {
                    predicate_values_equal(value, expected, is_timestamp(&predicate.field))
                })
            }
            crate::model::CompiledChangeRequestPredicateExpected::CurrentDate { relation } => {
                value.as_str().is_some_and(|date| match relation {
                    crate::model::CompiledCurrentDateRelation::OnOrAfter => date >= current_date,
                    crate::model::CompiledCurrentDateRelation::OnOrBefore => date <= current_date,
                })
            }
            crate::model::CompiledChangeRequestPredicateExpected::AtLeast { value: minimum } => {
                value.as_i64().is_some_and(|value| value >= *minimum)
            }
            crate::model::CompiledChangeRequestPredicateExpected::AtMost { value: maximum } => {
                value.as_i64().is_some_and(|value| value <= *maximum)
            }
        };
        if !accepted {
            return Err(MutationError::PreconditionFailed);
        }
    }
    Ok(())
}

fn predicate_values_equal(actual: &Value, expected: &Value, timestamp: bool) -> bool {
    if !timestamp || (actual.is_null() && expected.is_null()) {
        return actual == expected;
    }
    let parse = |value: &Value| {
        value.as_str().and_then(|value| {
            let (normalized, day_offset) = if let Some(bc) = value.strip_suffix(" BC") {
                // Valid year-0001 inputs can cross into BC when PostgreSQL
                // normalizes their offset. RFC3339 year 0000 is that instant.
                let rest = bc.strip_prefix("0001-")?;
                (format!("0000-{rest}"), 0)
            } else if let Some(rest) = value.strip_prefix("10000-01-01T") {
                // A year-9999 input can similarly normalize into PostgreSQL's
                // five-digit UTC year. Parse the prior day, then add one day.
                (format!("9999-12-31T{rest}"), 1)
            } else {
                (value.to_owned(), 0)
            };
            time::OffsetDateTime::parse(&normalized, &time::format_description::well_known::Rfc3339)
                .ok()
                .map(|parsed| parsed.unix_timestamp_nanos() + day_offset * 86_400_000_000_000)
        })
    };
    parse(actual)
        .zip(parse(expected))
        .is_some_and(|(actual, expected)| actual == expected)
}

fn verify_request_evidence(
    frozen: &crate::request_workflow::FrozenApplicationPreconditions,
    acquisitions: &[crate::action_evidence_client::VerifiedAcquisition],
    is_timestamp: impl Fn(&str) -> bool,
) -> Result<(), MutationError> {
    if acquisitions.len() != frozen.contract.evidence.len() {
        return Err(MutationError::PreconditionFailed);
    }
    for (evidence, acquisition) in frozen.contract.evidence.iter().zip(acquisitions) {
        if acquisition.capability_id() != evidence.capability.id
            || acquisition.contract_fingerprint() != evidence.capability.contract_fingerprint
        {
            return Err(MutationError::PreconditionFailed);
        }
        acquisition.validate_acceptance(chrono::Utc::now())?;
        verify_request_evidence_requirements(
            &evidence.requires,
            &frozen.request_values,
            acquisition.outputs(),
            &is_timestamp,
        )?;
    }
    Ok(())
}

fn verify_request_evidence_requirements(
    requirements: &[crate::model::CompiledChangeRequestEvidenceRequirement],
    request_values: &BTreeMap<String, Value>,
    outputs: &BTreeMap<String, Value>,
    is_timestamp: impl Fn(&str) -> bool,
) -> Result<(), MutationError> {
    for requirement in requirements {
        let actual = outputs.get(&requirement.output);
        let accepted = match &requirement.expected {
            crate::model::CompiledChangeRequestEvidenceExpected::Literal { value } => {
                actual == Some(value)
            }
            crate::model::CompiledChangeRequestEvidenceExpected::RequestField { field } => actual
                .zip(request_values.get(field))
                .is_some_and(|(actual, expected)| {
                    predicate_values_equal(actual, expected, is_timestamp(field))
                }),
            crate::model::CompiledChangeRequestEvidenceExpected::AtLeast { value } => actual
                .and_then(Value::as_i64)
                .is_some_and(|actual| actual >= *value),
            crate::model::CompiledChangeRequestEvidenceExpected::AtMost { value } => actual
                .and_then(Value::as_i64)
                .is_some_and(|actual| actual <= *value),
        };
        if !accepted {
            return Err(MutationError::PreconditionFailed);
        }
    }
    Ok(())
}

fn request_evidence_subjects(
    frozen: &crate::request_workflow::FrozenApplicationPreconditions,
) -> Result<
    Vec<(
        crate::action_evidence_contracts::CompiledEvidenceCapability,
        crate::action_evidence_client::EvidenceSubjects,
    )>,
    MutationError,
> {
    let targets = frozen
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    frozen
        .contract
        .evidence
        .iter()
        .map(|evidence| {
            let subjects = evidence
                .subjects
                .iter()
                .map(|(role, subject)| {
                    let values = subject
                        .selectors
                        .iter()
                        .map(|(selector_field, selector)| {
                            let value = match selector {
                                crate::model::CompiledChangeRequestSelector::RequestField {
                                    field,
                                } => frozen.request_values.get(field),
                                crate::model::CompiledChangeRequestSelector::TargetField {
                                    target,
                                    field,
                                } => targets
                                    .get(target.as_str())
                                    .and_then(|target| target.values.get(field)),
                            }
                            .cloned()
                            .ok_or(MutationError::PreconditionFailed)?;
                            Ok((selector_field.clone(), value))
                        })
                        .collect::<Result<BTreeMap<_, _>, MutationError>>()?;
                    Ok((role.clone(), values))
                })
                .collect::<Result<BTreeMap<_, _>, MutationError>>()?;
            Ok((evidence.capability.clone(), subjects))
        })
        .collect()
}

async fn insert_request_evidence_uses(
    transaction: &Transaction<'_>,
    application_id: Uuid,
    acquisitions: &[crate::action_evidence_client::VerifiedAcquisition],
) -> Result<(), MutationError> {
    for (ordinal, acquisition) in acquisitions.iter().enumerate() {
        let ordinal = i16::try_from(ordinal).map_err(|_| MutationError::Unavailable)?;
        let retained = acquisition
            .retained_serialization_for("registry.breg.request-application-evidence-use/v1")?;
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_evidence_uses
                    (application_id, ordinal, retained, expires_at)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &application_id,
                    &ordinal,
                    &retained,
                    &acquisition.retention_expires_at(),
                ],
            )
            .await
            .map_err(map_database_error)?;
    }
    Ok(())
}

/// Actions only the request owner may take. Submit and revise move the
/// owner's own draft; cancel is the owner's withdrawal. Reviewers reject a
/// request, they do not cancel it.
fn action_requires_request_owner(action: &RequestActionBody) -> bool {
    match action {
        RequestActionBody::Submit
        | RequestActionBody::Revise { .. }
        | RequestActionBody::Cancel => true,
        RequestActionBody::Apply { .. } => false,
    }
}

fn request_state_name(state: RequestState) -> &'static str {
    match state {
        RequestState::Draft => "draft",
        RequestState::Submitted => "submitted",
        RequestState::Cancelled => "cancelled",
        RequestState::Applied => "applied",
    }
}

// Drafts can survive a package upgrade. Recheck their stored attachment policy
// against the active contract before freezing the manifest into a proposal.
fn validate_submission_attachments(
    slots: &BTreeMap<String, crate::model::CompiledAttachmentSlot>,
    attachments: &BTreeMap<String, crate::request_workflow::AttachmentManifestEntry>,
) -> Result<(), MutationError> {
    if slots
        .iter()
        .any(|(id, slot)| slot.required && !attachments.contains_key(id))
        || attachments.iter().any(|(id, attachment)| {
            slots.get(id).is_none_or(|slot| {
                attachment.byte_size > u64::from(slot.maximum_bytes)
                    || !slot.content_types.contains(&attachment.content_type)
            })
        })
    {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

#[cfg(test)]
mod attachment_submission_tests {
    use super::validate_submission_attachments;
    use crate::contract::Classification;
    use crate::model::CompiledAttachmentSlot;
    use crate::request_workflow::AttachmentManifestEntry;
    use std::collections::BTreeMap;

    #[test]
    fn stored_draft_attachments_must_satisfy_active_slot_policy() {
        let mut slots = BTreeMap::from([(
            "evidence".to_owned(),
            CompiledAttachmentSlot {
                id: "evidence".to_owned(),
                required: true,
                maximum_bytes: 100,
                content_types: vec!["application/pdf".to_owned()],
                classification: Classification::Restricted,
            },
        )]);
        let attachments = BTreeMap::from([(
            "evidence".to_owned(),
            AttachmentManifestEntry {
                verification_policy: None,
                sha256: "a".repeat(64),
                content_type: "application/pdf".to_owned(),
                byte_size: 100,
            },
        )]);
        assert!(validate_submission_attachments(&slots, &attachments).is_ok());
        assert!(validate_submission_attachments(&slots, &BTreeMap::new()).is_err());
        slots.get_mut("evidence").unwrap().maximum_bytes = 99;
        assert!(validate_submission_attachments(&slots, &attachments).is_err());
        slots.get_mut("evidence").unwrap().maximum_bytes = 100;
        slots.get_mut("evidence").unwrap().content_types = vec!["image/png".to_owned()];
        assert!(validate_submission_attachments(&slots, &attachments).is_err());
        slots.clear();
        assert!(validate_submission_attachments(&slots, &attachments).is_err());
        assert!(validate_submission_attachments(&slots, &BTreeMap::new()).is_ok());
    }
}

#[cfg(test)]
mod application_precondition_tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::model::{
        CompiledChangeRequestEvidenceExpected, CompiledChangeRequestEvidenceRequirement,
        CompiledChangeRequestPredicate, CompiledChangeRequestPredicateExpected,
        CompiledCurrentDateRelation,
    };
    use crate::mutation::MutationError;

    #[test]
    fn runtime_owned_date_window_is_inclusive_and_closed() {
        let predicates = vec![
            CompiledChangeRequestPredicate {
                field: "valid-from".into(),
                expected: CompiledChangeRequestPredicateExpected::CurrentDate {
                    relation: CompiledCurrentDateRelation::OnOrBefore,
                },
            },
            CompiledChangeRequestPredicate {
                field: "valid-through".into(),
                expected: CompiledChangeRequestPredicateExpected::CurrentDate {
                    relation: CompiledCurrentDateRelation::OnOrAfter,
                },
            },
        ];
        let request = BTreeMap::from([
            ("valid-from".into(), json!("2026-09-12")),
            ("valid-through".into(), json!("2026-09-12")),
        ]);
        assert!(super::verify_compiled_predicates(
            &predicates,
            &request,
            &request,
            "2026-09-12",
            |_| false
        )
        .is_ok());
        for date in ["2026-09-11", "2026-09-13"] {
            assert_eq!(
                super::verify_compiled_predicates(&predicates, &request, &request, date, |_| false),
                Err(MutationError::PreconditionFailed)
            );
        }
    }

    #[test]
    fn timestamp_equality_compares_instants_without_widening_string_equality() {
        let actual = json!("2026-09-12T09:30:00+07:00");
        let same_instant = json!("2026-09-12T02:30:00Z");
        let different_instant = json!("2026-09-12T02:30:01Z");
        let predicates = [CompiledChangeRequestPredicate {
            field: "observed-at".into(),
            expected: CompiledChangeRequestPredicateExpected::RequestField {
                field: "requested-at".into(),
            },
        }];
        let observed = BTreeMap::from([("observed-at".into(), actual.clone())]);
        let requested = BTreeMap::from([("requested-at".into(), same_instant.clone())]);
        assert!(super::verify_compiled_predicates(
            &predicates,
            &observed,
            &requested,
            "2026-09-12",
            |_| true
        )
        .is_ok());
        let literal = [CompiledChangeRequestPredicate {
            field: "observed-at".into(),
            expected: CompiledChangeRequestPredicateExpected::Literal {
                value: same_instant.clone(),
            },
        }];
        assert!(super::verify_compiled_predicates(
            &literal,
            &observed,
            &requested,
            "2026-09-12",
            |_| true
        )
        .is_ok());
        assert_eq!(
            super::verify_compiled_predicates(
                &predicates,
                &observed,
                &requested,
                "2026-09-12",
                |_| false,
            ),
            Err(MutationError::PreconditionFailed)
        );
        assert!(super::predicate_values_equal(&actual, &same_instant, true));
        assert!(!super::predicate_values_equal(
            &actual,
            &different_instant,
            true
        ));
        assert!(!super::predicate_values_equal(
            &actual,
            &same_instant,
            false
        ));
        assert!(super::predicate_values_equal(
            &json!(null),
            &json!(null),
            true
        ));
        assert!(!super::predicate_values_equal(&actual, &json!(null), true));
        let stored_bc = json!("0001-12-31T23:00:00.123456+00:00 BC");
        let submitted = json!("0001-01-01T00:00:00.123456+01:00");
        assert!(super::predicate_values_equal(&stored_bc, &submitted, true));
        assert!(!super::predicate_values_equal(
            &stored_bc, &submitted, false
        ));
        let stored_next_year = json!("10000-01-01T00:00:00.12+00:00");
        let submitted_previous_year = json!("9999-12-31T23:00:00.12-01:00");
        assert!(time::OffsetDateTime::parse(
            submitted_previous_year.as_str().unwrap(),
            &time::format_description::well_known::Rfc3339
        )
        .is_ok());
        assert!(super::predicate_values_equal(
            &stored_next_year,
            &submitted_previous_year,
            true
        ));
        assert!(!super::predicate_values_equal(
            &stored_next_year,
            &json!("9999-12-31T23:00:00.13-01:00"),
            true
        ));
        assert!(!super::predicate_values_equal(
            &stored_next_year,
            &submitted_previous_year,
            false
        ));
    }

    #[test]
    fn evidence_outputs_require_frozen_identity_and_inclusive_thresholds() {
        let requirements = vec![
            CompiledChangeRequestEvidenceRequirement {
                output: "report-reference".into(),
                expected: CompiledChangeRequestEvidenceExpected::RequestField {
                    field: "report-reference".into(),
                },
            },
            CompiledChangeRequestEvidenceRequirement {
                output: "germination".into(),
                expected: CompiledChangeRequestEvidenceExpected::AtLeast { value: 9000 },
            },
            CompiledChangeRequestEvidenceRequirement {
                output: "purity".into(),
                expected: CompiledChangeRequestEvidenceExpected::AtLeast { value: 9800 },
            },
        ];
        let frozen = BTreeMap::from([("report-reference".into(), json!("report-v7"))]);
        let passing = BTreeMap::from([
            ("report-reference".into(), json!("report-v7")),
            ("germination".into(), json!(9000)),
            ("purity".into(), json!(9920)),
        ]);
        assert!(super::verify_request_evidence_requirements(
            &requirements,
            &frozen,
            &passing,
            |_| false
        )
        .is_ok());
        for (field, wrong) in [
            ("report-reference", json!("other-report")),
            ("germination", json!(8999)),
            ("purity", json!(9799)),
        ] {
            let mut outputs = passing.clone();
            outputs.insert(field.into(), wrong);
            assert_eq!(
                super::verify_request_evidence_requirements(
                    &requirements,
                    &frozen,
                    &outputs,
                    |_| false
                ),
                Err(MutationError::PreconditionFailed)
            );
        }
    }

    #[test]
    fn evidence_timestamp_request_binding_compares_instants_only_for_timestamp_fields() {
        let requirements = [CompiledChangeRequestEvidenceRequirement {
            output: "observed-at".into(),
            expected: CompiledChangeRequestEvidenceExpected::RequestField {
                field: "requested-at".into(),
            },
        }];
        let requested = BTreeMap::from([("requested-at".into(), json!("2026-09-13T10:00:00Z"))]);
        let observed = BTreeMap::from([("observed-at".into(), json!("2026-09-13T12:00:00+02:00"))]);
        assert!(super::verify_request_evidence_requirements(
            &requirements,
            &requested,
            &observed,
            |field| field == "requested-at",
        )
        .is_ok());
        assert_eq!(
            super::verify_request_evidence_requirements(
                &requirements,
                &requested,
                &observed,
                |_| false
            ),
            Err(MutationError::PreconditionFailed)
        );
        let different =
            BTreeMap::from([("observed-at".into(), json!("2026-09-13T12:00:01+02:00"))]);
        assert_eq!(
            super::verify_request_evidence_requirements(
                &requirements,
                &requested,
                &different,
                |_| true,
            ),
            Err(MutationError::PreconditionFailed)
        );
    }
}

#[cfg(test)]
mod owner_gate_tests {
    use super::{action_requires_request_owner, RequestActionBody};

    #[test]
    fn only_the_owner_submits_revises_or_cancels() {
        for action in [
            RequestActionBody::Submit,
            RequestActionBody::Revise { rebase: false },
            RequestActionBody::Revise { rebase: true },
            RequestActionBody::Cancel,
        ] {
            assert!(
                action_requires_request_owner(&action),
                "{action:?} is an owner-only action"
            );
        }

        let apply = RequestActionBody::Apply {
            proposal_version: 1,
            effect_digest: String::new(),
            reason: None,
        };
        assert!(!action_requires_request_owner(&apply));
    }
}

#[cfg(test)]
mod timestamp_tests {
    #[test]
    fn receipts_use_canonical_postgres_microseconds_including_trailing_zeroes() {
        for (clock, stored) in [
            (
                "2026-08-31T01:02:03.700350123Z",
                "2026-08-31T01:02:03.700350Z",
            ),
            ("2026-08-31T01:02:03Z", "2026-08-31T01:02:03.000000Z"),
            (
                "2026-08-31T08:02:03.123456789+07:00",
                "2026-08-31T01:02:03.123456Z",
            ),
        ] {
            let now =
                time::OffsetDateTime::parse(clock, &time::format_description::well_known::Rfc3339)
                    .unwrap();
            assert_eq!(super::request_timestamp(now).unwrap().as_str(), stored);
        }
    }
}

/// Current native-reference admission runs under target table locks, held until the
/// request mutation commits. A target change therefore cannot pass between the
/// authority check and its protected request write.
pub(super) async fn admit_submitter_targets(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    targets: &BTreeMap<String, CompiledEntity>,
    claims: &ClaimContext,
    intake: &Map<String, Value>,
) -> Result<(), MutationError> {
    let profile = entity
        .access_profiles
        .get(claims.access_profile())
        .ok_or(MutationError::InvalidRequest)?;
    if profile.submitter_targets.is_empty() {
        return Ok(());
    }
    if profile
        .submitter_targets
        .iter()
        .any(|id| !claims.submitter_targets().contains_key(id))
    {
        return Err(MutationError::PreconditionFailed);
    }
    let plan = entity
        .change_request
        .as_ref()
        .ok_or(MutationError::InvalidRequest)?;
    let records = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.target.binding {
            crate::model::CompiledChangeRequestTargetBinding::Existing { from_field } => {
                Some((effect.target.entity_id.as_str(), from_field.as_str()))
            }
            crate::model::CompiledChangeRequestTargetBinding::ReservedCreate { .. } => None,
        })
        .chain(
            plan.application
                .preconditions
                .targets
                .iter()
                .map(|target| (target.entity_id.as_str(), target.from_field.as_str())),
        )
        .map(|(entity_id, from_field)| {
            let id = intake
                .get(from_field)
                .and_then(Value::as_str)
                .ok_or(MutationError::InvalidRequest)?;
            let id = Uuid::parse_str(id).map_err(|_| MutationError::InvalidRequest)?;
            Ok((entity_id.to_owned(), id))
        })
        .collect::<Result<BTreeSet<_>, MutationError>>()?;
    transaction
        .execute(
            "SELECT set_config('registry.change_request_target_context', '', true)",
            &[],
        )
        .await
        .map_err(map_database_error)?;
    for (entity_id, id) in records {
        let target = targets
            .get(&entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let target_claims = claims
            .submitter_targets()
            .get(&entity_id)
            .ok_or(MutationError::PreconditionFailed)?;
        target_claims
            .install_row_boundaries(transaction)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        // PostgreSQL row-locking SELECT also requires an UPDATE RLS policy.
        // A table SHARE lock preserves ordinary GET-only target authority while
        // serializing target writes through the short request transaction.
        // Fixed target ordering and manual application avoid lock upgrades.
        transaction
            .batch_execute(&format!(
                "LOCK TABLE registry_data.{} IN SHARE MODE",
                quote_identifier(&target.physical_table)
            ))
            .await
            .map_err(map_database_error)?;
        let sql = format!("SELECT record_id FROM registry_data.{} WHERE record_id = $1 AND record_lifecycle = 'active'", quote_identifier(&target.physical_table));
        let admitted = transaction
            .query_opt(&sql, &[&id])
            .await
            .map_err(map_database_error)?;
        claims
            .install_row_boundaries(transaction)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if admitted.is_none() {
            return Err(MutationError::PreconditionFailed);
        }
    }
    Ok(())
}
