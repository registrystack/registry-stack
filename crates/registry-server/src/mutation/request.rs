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
    RequestWorkflow, ReviewDecisionKind, TrustedActorRef, TrustedTimestamp,
    TrustedTransitionContext,
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
    automatic_apply_authority: Option<&[crate::api::RequestActionTargetAuthority]>,
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
        automatic_apply_authority,
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
    automatic_apply_authority: Option<&[crate::api::RequestActionTargetAuthority]>,
) -> Result<String, MutationError> {
    if record_revision <= 0 || workflow_revision == 0 {
        return Err(MutationError::PreconditionFailed);
    }
    let binding = json!({
        "authority": crate::idempotency::canonical_claim_context(profile, claims, package_revision)?,
        "operationId": route.id, "stage": route.request_stage,
        "recordId": record_id, "recordRevision": record_revision,
        "workflowRevision": workflow_revision,
        "proposalVersion": workflow.current_version().get(),
        "effectDigest": workflow.current_proposal().map(|proposal| proposal.effect_digest().as_str()),
        "responseFields": response_fields,
        "targetAuthority": target_authority_binding(target_authority),
        "automaticApplyAuthority": automatic_apply_authority.map(target_authority_binding),
    });
    let canonical = canonicalize_json(&binding).map_err(|_| MutationError::Unavailable)?;
    let digest = profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-request-action-etag-v1",
            package_revision,
            std::str::from_utf8(&canonical).map_err(|_| MutationError::Unavailable)?,
        )
        .map_err(|_| MutationError::Unavailable)?;
    Ok(format!("\"rs-action-{digest}\""))
}

impl MutationCoordinator {
    pub(crate) async fn execute_request_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: RequestActionInput<'_>,
        claims: &ClaimContext,
        fault: FaultControl,
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
        let audit = |kind| PreIoAudit {
            kind,
            method: route.method,
            operation_id: &route.id,
            target_record: Some(input.record_id),
            correlation: input.correlation,
        };
        record_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
            &self.audit_profile,
            audit(PreIoAuditKind::Attempt),
        )
        .await?;
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
                    if !fault.is_enabled() {
                        record_pre_io_audit(
                            client,
                            self.lock_key,
                            self.lock_timeout,
                            &self.expected,
                            claims,
                            &self.audit_profile,
                            audit(PreIoAuditKind::Refusal),
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
                audit(PreIoAuditKind::Refusal),
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
            input.automatic_apply_authority.as_deref(),
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
                .map_err(|error| match error {
                    crate::rhai_planner::ChangeRequestPlannerError::Deadline => {
                        MutationError::Unavailable
                    }
                    _ => MutationError::InvalidRequest,
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
                    input.automatic_apply_authority.as_deref(),
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
            // An automatically applied submit/approval is recovered under the
            // same selected profile's real ApplyRequest route. This changes
            // only the transaction-local request-row RLS phase; the stored
            // idempotency binding and terminal audit remain bound to the
            // caller's original action.
            input
                .automatic_apply_authority
                .as_ref()
                .ok_or(MutationError::PreconditionFailed)?;
            let apply_route = registry
                .routes()
                .routes
                .iter()
                .find(|candidate| {
                    candidate.entity_id == entity.id
                        && candidate.operation == Operation::ApplyRequest
                })
                .ok_or(MutationError::PreconditionFailed)?;
            let recovery_context = ChangeRequestActionContext::for_route(
                registry,
                claims,
                &apply_route.id,
                request_id,
                header.get::<_, i64>(0),
                &actor_reference,
                &self.expected.package_revision,
            )
            .map_err(|_| MutationError::PreconditionFailed)?;
            transaction
                .install_change_request_action_context(&recovery_context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
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
                // A replay of an automatically applied submit or approval
                // must re-prove the independent ApplyRequest grant. The
                // ordinary action authority above remains the review/submit
                // proof and is never substituted with this apply proof.
                if workflow.state() == RequestState::Applied
                    && !matches!(input.action, RequestActionBody::Apply { .. })
                    && workflow
                        .current_proposal()
                        .and_then(|proposal| proposal.planning_binding())
                        .is_some_and(|planning| {
                            planning.disposition()
                                == crate::request_workflow::FrozenPlannerDisposition::Apply
                        })
                {
                    let proposal = workflow
                        .current_proposal()
                        .ok_or(MutationError::Unavailable)?;
                    let apply_authority = input
                        .automatic_apply_authority
                        .clone()
                        .ok_or(MutationError::PreconditionFailed)?;
                    let automatic_input = RequestActionInput {
                        route_id: input.route_id,
                        idempotency_key: input.idempotency_key,
                        if_match: input.if_match,
                        context: input.context,
                        entity_id: input.entity_id,
                        record_id: input.record_id,
                        action: RequestActionBody::Apply {
                            proposal_version: proposal.version().get(),
                            effect_digest: proposal.effect_digest().as_str().to_owned(),
                        },
                        response_fields: input.response_fields.clone(),
                        target_authority: apply_authority,
                        automatic_apply_authority: None,
                        correlation: input.correlation,
                    };
                    self.authorize_targets(
                        registry,
                        &automatic_input,
                        claims,
                        entity,
                        &workflow,
                        &targets,
                        &actor_reference,
                    )?;
                }
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
                    input.automatic_apply_authority.as_deref(),
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
            input.automatic_apply_authority.as_deref(),
        )?;
        if etag.as_bytes().ct_eq(input.if_match.as_bytes()).unwrap_u8() != 1 {
            return Err(MutationError::PreconditionFailed);
        }
        if matches!(
            input.action,
            RequestActionBody::Submit | RequestActionBody::Revise { .. }
        ) && workflow.owner().as_str() != actor_reference
        {
            return Err(MutationError::PreconditionFailed);
        }
        let previous_revision = i64::try_from(workflow.workflow_revision().get())
            .map_err(|_| MutationError::Unavailable)?;
        let mut save_previous_revision = previous_revision;
        let previous_state = workflow.state();
        let trusted = TrustedTransitionContext::from_verified_context(
            TrustedActorRef::from_verified_context(&actor_reference)
                .map_err(|_| MutationError::Unavailable)?,
            request_timestamp(time::OffsetDateTime::now_utc())?,
        );
        let mut prepared_targets = None;
        let mut prepared_targets_saved = false;
        let mut request_revision_advanced = false;
        let mut application_count = None;
        let mut application_result_revisions = Vec::new();
        let mut next = match &input.action {
            RequestActionBody::Submit => {
                let (record_revision, workflow_revision, prepared) = prepared_submission
                    .take()
                    .ok_or(MutationError::Unavailable)?;
                if record_revision != current.record_revision
                    || workflow_revision != workflow.workflow_revision().get()
                {
                    return Err(MutationError::PreconditionFailed);
                }
                prepared_targets = Some(prepared.targets);
                workflow
                    .submit(trusted.clone(), prepared.proposal)
                    .map_err(workflow_error)?
                    .into_workflow()
            }
            RequestActionBody::Approve {
                proposal_version,
                effect_digest,
            }
            | RequestActionBody::Reject {
                proposal_version,
                effect_digest,
            }
            | RequestActionBody::RequestRevision {
                proposal_version,
                effect_digest,
            } => {
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
                let decision = match input.action {
                    RequestActionBody::Approve { .. } => ReviewDecisionKind::Approve,
                    RequestActionBody::Reject { .. } => ReviewDecisionKind::Reject,
                    _ => ReviewDecisionKind::RequestRevision,
                };
                workflow
                    .decide(
                        trusted.clone(),
                        route
                            .request_stage
                            .as_deref()
                            .ok_or(MutationError::InvalidRequest)?,
                        ProposalVersion::new(*proposal_version).map_err(workflow_error)?,
                        &ProposalDigest::new(effect_digest).map_err(workflow_error)?,
                        decision,
                    )
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
                        &actor_reference,
                        trusted.clone(),
                        *proposal_version,
                        effect_digest,
                        None,
                        &binding,
                        fault,
                    )
                    .await?;
                application_count = Some(applied.result_count);
                application_result_revisions = applied.result_revisions;
                applied.workflow
            }
        };
        if !matches!(input.action, RequestActionBody::Apply { .. })
            && next.state() == RequestState::Approved
            && next
                .current_proposal()
                .and_then(|proposal| proposal.planning_binding())
                .is_some_and(|binding| {
                    binding.disposition()
                        == crate::request_workflow::FrozenPlannerDisposition::Apply
                })
        {
            let proposal = next.current_proposal().ok_or(MutationError::Conflict)?;
            let proposal_version = proposal.version().get();
            let effect_digest = proposal.effect_digest().as_str().to_owned();
            let apply_authority = input
                .automatic_apply_authority
                .clone()
                .ok_or(MutationError::PreconditionFailed)?;
            // The submit/approve action policy authorizes the request-row
            // revision while the durable workflow still has its source state.
            // Advance that row before transaction-local materialization of the
            // approved state; target application still follows afterward and
            // the whole composition rolls back together on any failure.
            current = advance_request_revision(transaction.transaction(), entity, &current).await?;
            request_revision_advanced = true;
            // Materialize the approved proposal, final decision (if any), and
            // frozen targets inside this transaction before entering the
            // existing application RLS path. No intermediate state is
            // externally visible, and any application failure rolls all of it
            // back with the target writes.
            crate::request_store::save(
                transaction.transaction(),
                &entity.id,
                record_uuid,
                save_previous_revision,
                &next,
            )
            .await?;
            save_previous_revision = i64::try_from(next.workflow_revision().get())
                .map_err(|_| MutationError::Unavailable)?;
            if let Some(targets) = prepared_targets.as_deref() {
                crate::request_store::save_targets(
                    transaction.transaction(),
                    &entity.id,
                    record_uuid,
                    i64::from(next.current_version().get()),
                    targets,
                )
                .await?;
                prepared_targets_saved = true;
            }
            let automatic_input = RequestActionInput {
                route_id: input.route_id,
                idempotency_key: input.idempotency_key,
                if_match: input.if_match,
                context: input.context,
                entity_id: input.entity_id,
                record_id: input.record_id,
                action: RequestActionBody::Apply {
                    proposal_version,
                    effect_digest: effect_digest.clone(),
                },
                response_fields: input.response_fields.clone(),
                target_authority: apply_authority,
                automatic_apply_authority: None,
                correlation: input.correlation,
            };
            let applied = self
                .apply_approved_request(
                    &transaction,
                    registry,
                    &automatic_input,
                    claims,
                    route,
                    entity,
                    next,
                    &actor_reference,
                    trusted.clone(),
                    proposal_version,
                    &effect_digest,
                    prepared_targets.as_deref(),
                    &binding,
                    fault,
                )
                .await?;
            application_count = Some(applied.result_count);
            application_result_revisions = applied.result_revisions;
            next = applied.workflow;
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
        if !request_revision_advanced {
            current = advance_request_revision(transaction.transaction(), entity, &current).await?;
        }
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
        if let Some(targets) = prepared_targets.filter(|_| !prepared_targets_saved) {
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
        crate::request_events::insert_request_lifecycle_events(
            transaction.transaction(),
            &entity.events,
            &exact_entity_event_deliveries(registry, entity)?,
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
                    RequestActionBody::Approve { .. } => "approve",
                    RequestActionBody::Reject { .. } => "reject",
                    RequestActionBody::RequestRevision { .. } => "request_revision",
                    RequestActionBody::Revise { rebase: true } => "rebase",
                    RequestActionBody::Revise { rebase: false } => "revise",
                    RequestActionBody::Cancel => "cancel",
                    RequestActionBody::Apply { .. } => "apply",
                },
                stage_id: route.request_stage.as_deref(),
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
        let prepared = request_prepare::prepare(
            registry,
            entity,
            &submission.intake,
            current.record_revision,
            &self.expected.package_revision,
            resolved,
            bases,
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
        actor_reference: &str,
        trusted: TrustedTransitionContext,
        proposal_version: u32,
        effect_digest: &str,
        targets_override: Option<&[RequestTargetSnapshot]>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        fault: FaultControl,
    ) -> Result<AppliedRequest, MutationError> {
        if workflow.state() != RequestState::Approved {
            return Err(MutationError::Conflict);
        }
        let proposal = workflow.current_proposal().ok_or(MutationError::Conflict)?;
        let plan = entity
            .change_request
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        if proposal.contract_fingerprint().as_str() != plan.contract_fingerprint
            || proposal.version().get() != proposal_version
            || proposal.effect_digest().as_str() != effect_digest
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
        let mut observed = Vec::new();
        for target in targets {
            let context = contexts
                .get(&(target.entity_id.clone(), target.record_id))
                .ok_or(MutationError::InvalidRequest)?;
            transaction
                .install_change_request_target_context(context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            if let Some(expected) = target.expected_revision {
                let actual = load_row(
                    transaction.transaction(),
                    &registry.entities()[&target.entity_id],
                    &target.record_id.to_string(),
                    true,
                )
                .await?;
                if actual.record_revision != expected {
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
                observed,
                PreparedApplication::new(
                    ApplicationId::new(Uuid::new_v4().to_string()).map_err(workflow_error)?,
                    links,
                )
                .map_err(workflow_error)?,
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
        if !matches!(
            input.action,
            RequestActionBody::Approve { .. }
                | RequestActionBody::Reject { .. }
                | RequestActionBody::RequestRevision { .. }
                | RequestActionBody::Apply { .. }
        ) {
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
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == input.route_id)
            .ok_or(MutationError::InvalidRequest)?;
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
            let context = if matches!(input.action, RequestActionBody::Apply { .. }) {
                ChangeRequestTargetContext::for_application(registry, claims, boundaries, binding)
            } else {
                ChangeRequestTargetContext::for_review(
                    registry,
                    claims,
                    route
                        .request_stage
                        .as_deref()
                        .ok_or(MutationError::InvalidRequest)?,
                    boundaries,
                    binding,
                )
            }
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
            None => apply_create_row(transaction, &request, &id).await?,
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
                apply_patch_row(transaction, &request, revision, changed).await?
            }
        };
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
        insert_configured_events(
            transaction,
            &entity.events,
            &plan.event_deliveries,
            self.event_destinations.as_deref(),
            OutboxMutation {
                trigger: mutation_trigger(target.operation),
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
    let action = match &input.action {
        RequestActionBody::Submit => json!({"operation": "submit"}),
        RequestActionBody::Cancel => json!({"operation": "cancel"}),
        RequestActionBody::Revise { rebase } => json!({"operation": "revise", "rebase": rebase}),
        RequestActionBody::Approve {
            proposal_version,
            effect_digest,
        }
        | RequestActionBody::Reject {
            proposal_version,
            effect_digest,
        }
        | RequestActionBody::RequestRevision {
            proposal_version,
            effect_digest,
        }
        | RequestActionBody::Apply {
            proposal_version,
            effect_digest,
        } => json!({
            "operation": action_operation(&input.action), "proposalVersion": proposal_version, "effectDigest": effect_digest,
        }),
    };
    Ok(json!({"action": action, "ifMatch": input.if_match,
            "targetAuthority": target_authority_binding(&input.target_authority),
            "automaticApplyAuthority": input.automatic_apply_authority.as_deref().map(target_authority_binding)}))
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
        RequestActionBody::Approve { .. } => Operation::ApproveRequest,
        RequestActionBody::Reject { .. } => Operation::RejectRequest,
        RequestActionBody::RequestRevision { .. } => Operation::RequestRevision,
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
) -> Result<HeldResponse, MutationError> {
    let mut request = json!({
        "serverState": workflow.state(),
        "proposalVersion": workflow.current_version().get(),
        "effectDigest": workflow.current_proposal().map(|proposal| proposal.effect_digest().as_str()),
        "application": workflow.application().map(|receipt| json!({
            "applicationId": receipt.application_id().as_str(),
            "proposalVersion": receipt.version().get(),
            "effectDigest": receipt.effect_digest().as_str(),
            "appliedAt": receipt.applied_at().as_str(),
        })),
    });
    if let Some(public) = workflow.current_proposal().and_then(|proposal| {
        let planning = proposal.planning_binding()?;
        let mut public = json!({
            "reviewMode": match proposal.review_policy() {
                crate::request_workflow::FrozenReviewPolicy::None => "none",
                crate::request_workflow::FrozenReviewPolicy::Stages => "staged",
            },
            "applicationDisposition": match planning.disposition() {
                crate::request_workflow::FrozenPlannerDisposition::Apply => "apply",
                crate::request_workflow::FrozenPlannerDisposition::Queue => "queue",
            },
        });
        if let Some(reason) = planning.queue_reason() {
            public["queueReason"] = json!({
                "code": reason.code(), "label": reason.label(),
            });
        }
        Some(public)
    }) {
        request["proposal"] = public;
    }
    HeldResponse::from_json(
        200,
        &json!({
            "id": record_id,
            "revision": record_revision,
            "snapshot": snapshot_reference,
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

fn request_state_name(state: RequestState) -> &'static str {
    match state {
        RequestState::Draft => "draft",
        RequestState::Submitted => "submitted",
        RequestState::Approved => "approved",
        RequestState::NeedsChanges => "needs_changes",
        RequestState::Rejected => "rejected",
        RequestState::Canceled => "canceled",
        RequestState::Applied => "applied",
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
