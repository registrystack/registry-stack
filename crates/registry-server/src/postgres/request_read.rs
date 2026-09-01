// SPDX-License-Identifier: Apache-2.0

//! Permission-aware change-request annotations for normal record reads.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_audit::AuditProfile;
use serde_json::{json, Map, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{compiled_api_name, RecordEnvelope};
use crate::api::{
    ReadServiceError, RecordReadRequest, RequestActionTargetAuthority,
    RowBoundaryOperator as ApiRowBoundaryOperator, VerifiedRequestAction, VerifiedRequestPresence,
    VerifiedRequestTargetAuthority, VerifiedRowBoundary,
};
use crate::contract::Operation;
use crate::model::{CompiledEntity, CompiledRegistry, CompiledRoute, HttpMethod};
use crate::mutation::request_action_etag;
use crate::postgres::context::ChangeRequestPresenceContext;
use crate::postgres::{
    ChangeRequestTargetBinding, ChangeRequestTargetContext, ClaimContext, ExpectedRegistryIdentity,
    RowBoundaryContext,
};
use crate::request_prepare::{validate_frozen_targets, RequestTargetSnapshot};
use crate::request_retention::{
    RetainedHistoryQuery, RetainedRequestProposal, RetainedRequestResultLink,
};
use crate::request_workflow::{RequestState, RequestWorkflow, ReviewDecisionKind};

#[allow(clippy::too_many_arguments)]
pub(super) async fn annotate_records(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    audit_profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    records: &mut [RecordEnvelope],
) -> Result<(), ReadServiceError> {
    if records.is_empty() {
        return Ok(());
    }
    if entity.change_request.is_some() {
        annotate_request_records(
            transaction,
            registry,
            audit_profile,
            expected,
            request,
            claims,
            entity,
            records,
        )
        .await?;
    }
    if !request.context.request_presence().is_empty() {
        annotate_target_presence(
            transaction,
            registry,
            expected,
            request,
            claims,
            entity,
            records,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(super) async fn erased_terminal_request_record(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    record_id: &str,
    record_revision: i64,
) -> Result<Option<RecordEnvelope>, ReadServiceError> {
    if entity.change_request.is_none() || request.method != HttpMethod::Get {
        return Ok(None);
    }
    if record_revision <= 0 {
        return Err(ReadServiceError::Unavailable);
    }
    let record_uuid = parse_uuid(record_id)?;
    let header = crate::request_store::load_header(transaction, &entity.id, record_uuid, false)
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    if !header.current_proposal_erased || !header.is_terminal() {
        return Ok(None);
    }
    let revision = u64::try_from(record_revision).map_err(|_| ReadServiceError::Unavailable)?;
    let history =
        retained_history(transaction, registry, request, claims, entity, record_uuid).await?;
    let mut record = RecordEnvelope {
        id: record_id.to_owned(),
        revision,
        data: Map::new(),
        request: Some(erased_terminal_request_metadata(
            &header,
            history,
            may_disclose_effect_digests(entity, request),
        )),
        request_presence: None,
    };
    if !request.context.request_presence().is_empty() {
        annotate_target_presence(
            transaction,
            registry,
            expected,
            request,
            claims,
            entity,
            std::slice::from_mut(&mut record),
        )
        .await?;
    }
    Ok(Some(record))
}

#[allow(clippy::too_many_arguments)]
async fn annotate_request_records(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    audit_profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    records: &mut [RecordEnvelope],
) -> Result<(), ReadServiceError> {
    let actor_reference = claims
        .principal()
        .map(|principal| {
            audit_profile.key_hasher().audit_reference_hash(
                "registry-server-request-actor-v1",
                &expected.database_id,
                principal,
            )
        })
        .transpose()
        .map_err(|_| ReadServiceError::Unavailable)?;
    for record in records {
        let record_uuid = parse_uuid(&record.id)?;
        let header = crate::request_store::load_header(transaction, &entity.id, record_uuid, false)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        if header.current_proposal_erased && header.is_terminal() {
            let history =
                retained_history(transaction, registry, request, claims, entity, record_uuid)
                    .await?;
            record.request = Some(erased_terminal_request_metadata(
                &header,
                history,
                may_disclose_effect_digests(entity, request),
            ));
            continue;
        }
        let workflow = crate::request_store::load(transaction, &entity.id, record_uuid, false)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let targets = if workflow.current_proposal().is_some()
            && request.context.request_actions().iter().any(|action| {
                matches!(
                    action.operation(),
                    Operation::ApproveRequest
                        | Operation::RejectRequest
                        | Operation::RequestRevision
                        | Operation::ApplyRequest
                )
            }) {
            crate::request_store::load_targets(
                transaction,
                &entity.id,
                record_uuid,
                i64::from(workflow.current_version().get()),
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?
        } else {
            Vec::new()
        };
        let editable = actor_reference.as_deref().is_some_and(|actor| {
            workflow.state() == RequestState::Draft
                && workflow.owner().as_str() == actor
                && selected_profile_allows_draft_patch(entity, request)
        });
        let actions = action_links(
            registry,
            audit_profile,
            expected,
            request,
            claims,
            entity,
            record,
            &workflow,
            &targets,
            actor_reference.as_deref(),
        )?;
        let history =
            retained_history(transaction, registry, request, claims, entity, record_uuid).await?;
        let mut metadata = Map::new();
        metadata.insert(
            "serverState".to_owned(),
            json!(request_state_name(workflow.state())),
        );
        metadata.insert(
            "proposalVersion".to_owned(),
            json!(workflow.current_version().get()),
        );
        if may_disclose_effect_digests(entity, request) {
            metadata.insert(
                "effectDigest".to_owned(),
                workflow
                    .current_proposal()
                    .map(|proposal| json!(proposal.effect_digest().as_str()))
                    .unwrap_or(Value::Null),
            );
        }
        metadata.insert("editable".to_owned(), json!(editable));
        if !actions.is_empty() {
            metadata.insert("actions".to_owned(), Value::Array(actions));
        }
        if let Some(history) = history {
            metadata.insert("history".to_owned(), history.value);
        }
        if let Some(application) = workflow.application() {
            let mut application_metadata = json!({
                "applicationId": application.application_id().as_str(),
                "proposalVersion": application.version().get(),
                "appliedAt": application.applied_at().as_str(),
            });
            if may_disclose_effect_digests(entity, request) {
                application_metadata["effectDigest"] = json!(application.effect_digest().as_str());
            }
            metadata.insert("application".to_owned(), application_metadata);
        }
        record.request = Some(Value::Object(metadata));
    }
    Ok(())
}

fn erased_terminal_request_metadata(
    header: &crate::request_store::RequestWorkflowHeader,
    history: Option<RetainedHistoryMetadata>,
    disclose_effect_digests: bool,
) -> Value {
    let mut metadata = Map::new();
    metadata.insert("serverState".to_owned(), json!(header.state));
    metadata.insert("proposalVersion".to_owned(), json!(header.proposal_version));
    metadata.insert("detailErased".to_owned(), json!(true));
    metadata.insert("editable".to_owned(), json!(false));
    if let Some(history) = history {
        if disclose_effect_digests {
            if let Some(effect_digest) = history.current_effect_digest {
                metadata.insert("effectDigest".to_owned(), json!(effect_digest));
            }
        }
        if let Some(application_id) = history.current_application_id {
            metadata.insert(
                "application".to_owned(),
                json!({
                    "applicationId": application_id,
                    "proposalVersion": header.proposal_version,
                }),
            );
        }
        metadata.insert("history".to_owned(), history.value);
    }
    Value::Object(metadata)
}

#[allow(clippy::too_many_arguments)]
fn action_links(
    registry: &CompiledRegistry,
    audit_profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    record: &RecordEnvelope,
    workflow: &RequestWorkflow,
    targets: &[RequestTargetSnapshot],
    actor_reference: Option<&str>,
) -> Result<Vec<Value>, ReadServiceError> {
    let record_revision =
        i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
    let mut values = Vec::new();
    for action in request.context.request_actions() {
        if !action_is_available(action, workflow, actor_reference) {
            continue;
        }
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == action.route_id())
            .ok_or(ReadServiceError::Unavailable)?;
        let target_authority = action
            .target_authority()
            .iter()
            .map(RequestActionTargetAuthority::from)
            .collect::<Vec<_>>();
        let precondition = request_action_etag(
            audit_profile,
            claims,
            &expected.package_revision,
            route,
            &record.id,
            record_revision,
            workflow,
            action.response_fields(),
            &target_authority,
        )
        .map_err(|_| ReadServiceError::Unavailable)?;
        let mut value = json!({
            "operation": operation_name(action.operation()),
            "method": method_name(action.method()),
            "href": action_href(action, request, &record.id),
            "ifMatch": precondition,
        });
        if let Some(stage) = action.review_stage() {
            value["stage"] = json!(stage);
        }
        if let Some(rebase) = revise_rebase_available(action, workflow) {
            value["rebase"] = json!(rebase);
        }
        if let Some(proposal) = workflow.current_proposal() {
            value["proposalVersion"] = json!(proposal.version().get());
            value["effectDigest"] = json!(proposal.effect_digest().as_str());
        }
        if matches!(
            action.operation(),
            Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision
        ) {
            let Some(actor_reference) = actor_reference else {
                continue;
            };
            if let Some(review) = review_snapshot(
                registry,
                expected,
                claims,
                entity,
                route,
                action,
                workflow,
                targets,
                actor_reference,
            )? {
                value["review"] = review;
            } else {
                continue;
            }
        }
        values.push(value);
    }
    Ok(values)
}

fn action_href(
    action: &VerifiedRequestAction,
    request: &RecordReadRequest,
    record_id: &str,
) -> String {
    let path = action.path().replace("{record_id}", record_id);
    let separator = if path.contains('?') { '&' } else { '?' };
    format!(
        "{path}{separator}accessProfile={}",
        percent_encode_query_value(request.context.selected_profile())
    )
}

fn percent_encode_query_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(HEX[usize::from(byte >> 4)]);
            output.push(HEX[usize::from(byte & 0x0f)]);
        }
    }
    output
}

const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

fn action_is_available(
    action: &VerifiedRequestAction,
    workflow: &RequestWorkflow,
    actor_reference: Option<&str>,
) -> bool {
    match action.operation() {
        Operation::SubmitRequest => {
            workflow.state() == RequestState::Draft
                && actor_reference.is_some_and(|actor| workflow.owner().as_str() == actor)
        }
        Operation::ReviseRequest => {
            revise_rebase_available(action, workflow).is_some()
                && actor_reference.is_some_and(|actor| workflow.owner().as_str() == actor)
        }
        Operation::CancelRequest => !matches!(
            workflow.state(),
            RequestState::Canceled | RequestState::Applied
        ),
        Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision => {
            review_decision_available(action, workflow, actor_reference)
        }
        Operation::ApplyRequest => workflow.state() == RequestState::Approved,
        _ => false,
    }
}

fn revise_rebase_available(
    action: &VerifiedRequestAction,
    workflow: &RequestWorkflow,
) -> Option<bool> {
    if action.operation() != Operation::ReviseRequest {
        return None;
    }
    match workflow.state() {
        RequestState::NeedsChanges | RequestState::Rejected => Some(false),
        RequestState::Submitted | RequestState::Approved => Some(true),
        _ => None,
    }
}

fn review_decision_available(
    action: &VerifiedRequestAction,
    workflow: &RequestWorkflow,
    actor_reference: Option<&str>,
) -> bool {
    if workflow.state() != RequestState::Submitted
        || pending_stage(workflow) != action.review_stage()
    {
        return false;
    }
    let (Some(proposal), Some(stage), Some(actor)) = (
        workflow.current_proposal(),
        action.review_stage(),
        actor_reference,
    ) else {
        return false;
    };
    let Some(pending_stage) = proposal.stages().iter().find(|pending| pending.id == stage) else {
        return false;
    };
    if pending_stage.exclude_submitter && proposal.submitted_by().as_str() == actor {
        return false;
    }
    !workflow.decisions().iter().any(|decision| {
        decision.version() == proposal.version()
            && decision.stage_id() == stage
            && decision.actor().as_str() == actor
    })
}

fn pending_stage(workflow: &RequestWorkflow) -> Option<&str> {
    let proposal = workflow.current_proposal()?;
    proposal
        .stages()
        .iter()
        .find(|stage| {
            let approvals = workflow
                .decisions()
                .iter()
                .filter(|decision| {
                    decision.version() == proposal.version()
                        && decision.stage_id() == stage.id
                        && decision.kind() == ReviewDecisionKind::Approve
                })
                .map(|decision| decision.actor().as_str())
                .collect::<BTreeSet<_>>()
                .len();
            approvals < usize::from(stage.approvals)
        })
        .map(|stage| stage.id.as_str())
}

#[allow(clippy::too_many_arguments)]
fn review_snapshot(
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    route: &CompiledRoute,
    action: &VerifiedRequestAction,
    workflow: &RequestWorkflow,
    targets: &[RequestTargetSnapshot],
    actor_reference: &str,
) -> Result<Option<Value>, ReadServiceError> {
    let Some(proposal) = workflow.current_proposal() else {
        return Ok(None);
    };
    validate_frozen_targets(proposal, targets).map_err(|_| ReadServiceError::Unavailable)?;
    let mut by_target = BTreeMap::new();
    for target in targets {
        by_target.insert((target.entity_id.as_str(), target.record_id), target);
    }
    let mut target_values = Vec::new();
    for effect in proposal.effects() {
        let target_entity_id = effect.target().entity_id().as_str();
        let record_id = effect
            .target()
            .existing_record_id()
            .or_else(|| effect.target().reserved_record_id())
            .ok_or(ReadServiceError::Unavailable)?;
        let record_uuid = parse_uuid(record_id.as_str())?;
        let Some(snapshot) = by_target.get(&(target_entity_id, record_uuid)).copied() else {
            return Err(ReadServiceError::Unavailable);
        };
        let Some(authority) = action
            .target_authority()
            .iter()
            .find(|authority| authority.target_entity_id() == target_entity_id)
        else {
            return Err(ReadServiceError::Unavailable);
        };
        let target_entity = registry
            .entities()
            .get(target_entity_id)
            .ok_or(ReadServiceError::Unavailable)?;
        let fields = effect
            .field_changes()
            .iter()
            .map(|change| change.field().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let binding = ChangeRequestTargetBinding {
            request_entity_id: entity.id.clone(),
            request_id: parse_uuid(workflow.request().record_id().as_str())?,
            proposal_version: i64::from(proposal.version().get()),
            actor_reference: actor_reference.to_owned(),
            contract_fingerprint: proposal.contract_fingerprint().as_str().to_owned(),
            effect_digest: proposal.effect_digest().as_str().to_owned(),
            active_package_revision: expected.package_revision.clone(),
            effect_id: effect.id().as_str().to_owned(),
            target_entity_id: target_entity_id.to_owned(),
            target_record_id: record_uuid,
            operation: effect.operation(),
            fields,
            expected_revision: snapshot.expected_revision,
        };
        let context = ChangeRequestTargetContext::for_review(
            registry,
            claims,
            route
                .request_stage
                .as_deref()
                .ok_or(ReadServiceError::Unavailable)?,
            row_boundaries(authority)?,
            binding,
        )
        .map_err(|_| ReadServiceError::Unavailable)?;
        context
            .authorize_rows(
                target_entity,
                snapshot.before.as_ref(),
                &snapshot.after,
                record_uuid,
            )
            .map_err(|_| ReadServiceError::Unavailable)?;
        target_values.push(json!({
            "entityId": target_entity_id,
            "recordId": record_id.as_str(),
            "operation": operation_name(effect.operation()),
            "baseRevision": snapshot.expected_revision,
            "before": snapshot.before.as_ref().map(|before| api_object(target_entity, before, authority.readable_fields())).transpose()?,
            "after": api_object(target_entity, &snapshot.after, authority.readable_fields())?,
        }));
    }
    Ok(Some(json!({ "targets": target_values })))
}

async fn annotate_target_presence(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    records: &mut [RecordEnvelope],
) -> Result<(), ReadServiceError> {
    for record in records {
        let target_uuid = parse_uuid(&record.id)?;
        let mut values = Vec::new();
        for grant in request.context.request_presence() {
            if pending_for_grant(
                transaction,
                registry,
                expected,
                claims,
                entity,
                target_uuid,
                grant,
            )
            .await?
            {
                values.push(json!({
                    "requestType": grant.request_entity_id(),
                    "pending": true,
                }));
            } else {
                values.push(json!({
                    "requestType": grant.request_entity_id(),
                    "pending": false,
                }));
            }
        }
        if !values.is_empty() {
            record.request_presence = Some(json!({ "requests": values }));
        }
    }
    Ok(())
}

async fn pending_for_grant(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    target_entity: &CompiledEntity,
    target_record_id: Uuid,
    grant: &VerifiedRequestPresence,
) -> Result<bool, ReadServiceError> {
    let request_entity = registry
        .entities()
        .get(grant.request_entity_id())
        .ok_or(ReadServiceError::Unavailable)?;
    let request_table =
        SqlIdent::new(&request_entity.physical_table).ok_or(ReadServiceError::Unavailable)?;
    let presence_context = ChangeRequestPresenceContext::for_presence(
        registry,
        claims,
        grant.request_entity_id(),
        &target_entity.id,
        target_record_id,
        row_boundary_contexts(grant.request_row_boundaries())?,
        &expected.package_revision,
    )
    .map_err(|_| ReadServiceError::Unavailable)?;
    let filters = presence_filters(request_entity, grant, 3)?;
    let sql = format!(
        "SELECT EXISTS (
            SELECT 1
            FROM registry_internal.registry_request_targets target
            JOIN registry_internal.registry_request_state state
              ON state.request_entity_id = target.request_entity_id
             AND state.request_id = target.request_id
            JOIN registry_data.{request_table} request_row
              ON request_row.record_id = target.request_id
            WHERE target.request_entity_id = $1
              AND target.target_entity_id = $2
              AND target.target_record_id = $3
              AND state.proposal_version = target.proposal_version
              AND state.state IN ('submitted', 'approved')
              {filters}
        )",
    );
    let request_entity_id = grant.request_entity_id().to_owned();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        vec![&request_entity_id, &target_entity.id, &target_record_id];
    let boundary_values = grant
        .request_row_boundaries()
        .iter()
        .flat_map(|boundary| boundary.values().iter())
        .collect::<Vec<_>>();
    for value in &boundary_values {
        params.push(*value);
    }
    transaction
        .execute(
            "SELECT set_config('registry.change_request_presence_context', $1, true)",
            &[&presence_context.canonical_context()],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    transaction
        .query_one(&sql, &params)
        .await
        .map(|row| row.get::<_, bool>(0))
        .map_err(|_| ReadServiceError::Unavailable)
}

fn presence_filters(
    request_entity: &CompiledEntity,
    grant: &VerifiedRequestPresence,
    first_param: usize,
) -> Result<String, ReadServiceError> {
    let mut filters = String::new();
    let mut parameter = first_param;
    for boundary in grant.request_row_boundaries() {
        let field = request_entity
            .fields
            .get(boundary.field())
            .map(|field| field.physical_name.as_str())
            .or_else(|| {
                (boundary.field() == request_entity.canonical_id.id)
                    .then_some(request_entity.canonical_id.sql_name.as_str())
            })
            .and_then(SqlIdent::new)
            .ok_or(ReadServiceError::Unavailable)?;
        match boundary.operator() {
            ApiRowBoundaryOperator::Equals => {
                parameter += 1;
                filters.push_str(&format!(
                    " AND request_row.{field}::text = ${parameter}::text"
                ));
            }
            ApiRowBoundaryOperator::In => {
                let mut placeholders = Vec::new();
                for _ in boundary.values() {
                    parameter += 1;
                    placeholders.push(format!("${parameter}::text"));
                }
                filters.push_str(&format!(
                    " AND request_row.{field}::text IN ({})",
                    placeholders.join(", ")
                ));
            }
        }
    }
    Ok(filters)
}

async fn retained_history(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    request_id: Uuid,
) -> Result<Option<RetainedHistoryMetadata>, ReadServiceError> {
    let authorized_target_entities = BTreeSet::new();
    let mut page = crate::request_retention::load_retained_history(
        transaction,
        RetainedHistoryQuery {
            request_entity_id: &entity.id,
            request_id,
            after_proposal_version: request.request_history_after_proposal_version,
            limit: 50,
            authorized_target_entities: &authorized_target_entities,
        },
    )
    .await
    .map_err(|_| ReadServiceError::Unavailable)?;
    if page.proposals.is_empty() {
        return Ok(None);
    }
    for proposal in &mut page.proposals {
        let links =
            authorized_result_links(transaction, registry, request, claims, proposal).await?;
        proposal.result_link_count =
            u16::try_from(links.len()).map_err(|_| ReadServiceError::Unavailable)?;
        proposal.result_links = links;
    }
    let current = page.proposals.iter().find(|proposal| proposal.current);
    let current_effect_digest = current.map(|proposal| proposal.effect_digest.clone());
    let current_application_id = current.and_then(|proposal| proposal.application_id.clone());
    let value = json!({
        "proposals": page
            .proposals
            .into_iter()
            .map(|proposal| retained_history_value(proposal, may_disclose_effect_digests(entity, request)))
            .collect::<Vec<_>>(),
        "nextAfterProposalVersion": page.next_after_proposal_version,
    });
    Ok(Some(RetainedHistoryMetadata {
        value,
        current_effect_digest,
        current_application_id,
    }))
}

struct RetainedHistoryMetadata {
    value: Value,
    current_effect_digest: Option<String>,
    current_application_id: Option<String>,
}

async fn authorized_result_links(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    proposal: &RetainedRequestProposal,
) -> Result<Vec<RetainedRequestResultLink>, ReadServiceError> {
    if proposal.application_id.is_none() {
        return Ok(Vec::new());
    }
    let request_id = parse_uuid(&proposal.request_id)?;
    let rows = transaction
        .query(
            "SELECT target_entity_id, target_record_id, target_revision
               FROM registry_internal.registry_request_results
              WHERE request_entity_id = $1
                AND request_id = $2
                AND proposal_version = $3
              ORDER BY target_entity_id, target_record_id",
            &[
                &proposal.request_entity_id,
                &request_id,
                &proposal.proposal_version,
            ],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    let mut links = Vec::new();
    for row in rows {
        let target_entity_id = row.get::<_, String>(0);
        let target_record_id = row.get::<_, Uuid>(1);
        let target_revision = row.get::<_, i64>(2);
        if target_revision <= 0 {
            return Err(ReadServiceError::Unavailable);
        }
        if target_get_is_authorized(
            transaction,
            registry,
            request,
            claims,
            &target_entity_id,
            target_record_id,
        )
        .await?
        {
            links.push(RetainedRequestResultLink {
                target_entity_id,
                target_record_id: target_record_id.to_string(),
                target_revision,
            });
        }
    }
    Ok(links)
}

async fn target_get_is_authorized(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    target_entity_id: &str,
    target_record_id: Uuid,
) -> Result<bool, ReadServiceError> {
    let target_entity = registry
        .entities()
        .get(target_entity_id)
        .ok_or(ReadServiceError::Unavailable)?;
    let Some(profile) = target_entity
        .access_profiles
        .get(request.context.selected_profile())
    else {
        return Ok(false);
    };
    if !profile.operations.contains(&Operation::Get)
        || !registry.routes().routes.iter().any(|route| {
            route.entity_id == target_entity_id
                && route.operation == Operation::Get
                && route.method == HttpMethod::Get
                && route
                    .access_profiles
                    .iter()
                    .any(|profile| profile == request.context.selected_profile())
        })
        || ClaimContext::for_compiled(
            registry,
            target_entity_id,
            claims.principal().map(str::to_owned),
            request.context.selected_profile(),
            claims.purpose().map(str::to_owned),
            claims.row_boundaries().to_vec(),
        )
        .is_err()
    {
        return Ok(false);
    }
    let table =
        SqlIdent::new(&target_entity.physical_table).ok_or(ReadServiceError::Unavailable)?;
    let sql = format!(
        "SELECT record_revision
           FROM registry_data.{table}
          WHERE record_id = $1
            AND record_lifecycle = 'active'
          LIMIT 1",
    );
    transaction
        .query_opt(&sql, &[&target_record_id])
        .await
        .map(|row| row.is_some())
        .map_err(|_| ReadServiceError::Unavailable)
}

fn retained_history_value(
    proposal: RetainedRequestProposal,
    disclose_effect_digests: bool,
) -> Value {
    let mut value = json!({
        "requestEntityId": proposal.request_entity_id,
        "requestId": proposal.request_id,
        "proposalVersion": proposal.proposal_version,
        "serverState": proposal.request_state,
        "current": proposal.current,
        "contractFingerprint": proposal.contract_fingerprint,
        "detailErased": proposal.detail_erased,
        "applicationId": proposal.application_id,
        "resultLinkCount": proposal.result_link_count,
        "resultLinks": proposal.result_links.into_iter().map(|link| {
            json!({
                "targetEntityId": link.target_entity_id,
                "targetRecordId": link.target_record_id,
                "targetRevision": link.target_revision,
            })
        })
        .collect::<Vec<_>>(),
    });
    if disclose_effect_digests {
        value["effectDigest"] = json!(proposal.effect_digest);
    }
    value
}

fn may_disclose_effect_digests(entity: &CompiledEntity, request: &RecordReadRequest) -> bool {
    entity
        .access_profiles
        .get(request.context.selected_profile())
        .is_some_and(|profile| !profile.anonymous)
}

fn selected_profile_allows_draft_patch(
    entity: &CompiledEntity,
    request: &RecordReadRequest,
) -> bool {
    entity
        .access_profiles
        .get(request.context.selected_profile())
        .is_some_and(|profile| {
            profile.operations.contains(&Operation::Patch) && !profile.writable_fields.is_empty()
        })
}

fn api_object(
    entity: &CompiledEntity,
    snapshot: &Map<String, Value>,
    readable_fields: &BTreeSet<String>,
) -> Result<Value, ReadServiceError> {
    let mut object = Map::new();
    for field in readable_fields {
        let api_name = compiled_api_name(entity, field).ok_or(ReadServiceError::Unavailable)?;
        if let Some(value) = snapshot.get(field) {
            object.insert(api_name.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(object))
}

fn row_boundaries(
    authority: &VerifiedRequestTargetAuthority,
) -> Result<Vec<RowBoundaryContext>, ReadServiceError> {
    row_boundary_contexts(authority.row_boundaries())
}

fn row_boundary_contexts(
    boundaries: &[VerifiedRowBoundary],
) -> Result<Vec<RowBoundaryContext>, ReadServiceError> {
    boundaries
        .iter()
        .map(|boundary| match boundary.operator() {
            ApiRowBoundaryOperator::Equals => {
                if boundary.values().len() != 1 {
                    return Err(ReadServiceError::Unavailable);
                }
                Ok(RowBoundaryContext::Equals {
                    field: boundary.field().to_owned(),
                    value: boundary
                        .values()
                        .iter()
                        .next()
                        .ok_or(ReadServiceError::Unavailable)?
                        .clone(),
                })
            }
            ApiRowBoundaryOperator::In => Ok(RowBoundaryContext::In {
                field: boundary.field().to_owned(),
                values: boundary.values().clone(),
            }),
        })
        .collect()
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Get => "get",
        Operation::Lookup => "lookup",
        Operation::List => "list",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        Operation::Invoke => "invoke",
        Operation::Snapshot => "snapshot",
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
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

fn parse_uuid(value: &str) -> Result<Uuid, ReadServiceError> {
    let uuid = Uuid::parse_str(value).map_err(|_| ReadServiceError::Unavailable)?;
    if uuid.to_string() == value {
        Ok(uuid)
    } else {
        Err(ReadServiceError::Unavailable)
    }
}

struct SqlIdent(String);

impl SqlIdent {
    fn new(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.bytes().any(|byte| {
                !(byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'_'
                    || byte == b'.')
            })
        {
            return None;
        }
        Some(Self(value.to_owned()))
    }
}

impl std::fmt::Display for SqlIdent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{json, Map, Value};

    use super::{
        action_href, action_is_available, api_object, erased_terminal_request_metadata,
        retained_history_value, revise_rebase_available, selected_profile_allows_draft_patch,
        RetainedHistoryMetadata,
    };
    use crate::api::{
        AuthorizedRequestContext, RecordReadKind, RecordReadRequest, VerifiedRequestAction,
    };
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{parse_project_json, Operation};
    use crate::correlation::RequestCorrelation;
    use crate::model::{CompiledChangeRequestStage, HttpMethod};
    use crate::request_retention::{RetainedRequestProposal, RetainedRequestResultLink};
    use crate::request_workflow::{
        ContractFingerprint, EffectId, EntityId, FieldId, FieldValue, PackageFingerprint,
        PreparedEffect, PreparedFieldChange, PreparedProposal, PreparedTarget, ProposalVersion,
        RecordId, RecordRevision, RequestKey, RequestWorkflow, ReviewDecisionKind, StateRevision,
        TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
    };

    #[test]
    fn revise_action_marks_rebase_required_on_submitted_and_approved_requests() {
        let revise = action(Operation::ReviseRequest, None);
        let submitted = submitted_workflow(1, false);
        assert_eq!(revise_rebase_available(&revise, &submitted), Some(true));
        assert!(action_is_available(&revise, &submitted, Some("owner-ref")));
        assert!(!action_is_available(
            &revise,
            &submitted,
            Some("reviewer-ref")
        ));

        let approved = decide(submitted, "reviewer-ref", ReviewDecisionKind::Approve);
        assert_eq!(revise_rebase_available(&revise, &approved), Some(true));
        assert!(action_is_available(&revise, &approved, Some("owner-ref")));
    }

    #[test]
    fn revise_action_marks_rebase_false_for_revision_drafts() {
        let revise = action(Operation::ReviseRequest, None);
        let submitted = submitted_workflow(1, false);
        let needs_changes = decide(
            submitted,
            "reviewer-ref",
            ReviewDecisionKind::RequestRevision,
        );
        assert_eq!(
            revise_rebase_available(&revise, &needs_changes),
            Some(false)
        );
        assert!(action_is_available(
            &revise,
            &needs_changes,
            Some("owner-ref")
        ));
    }

    #[test]
    fn review_actions_omit_self_and_duplicate_decisions() {
        let approve = action(Operation::ApproveRequest, Some("review"));
        let submitted = submitted_workflow(2, true);
        assert!(!action_is_available(
            &approve,
            &submitted,
            Some("owner-ref")
        ));
        assert!(action_is_available(
            &approve,
            &submitted,
            Some("reviewer-ref")
        ));

        let after_reviewer = decide(submitted, "reviewer-ref", ReviewDecisionKind::Approve);
        assert!(!action_is_available(
            &approve,
            &after_reviewer,
            Some("reviewer-ref")
        ));
        assert!(action_is_available(
            &approve,
            &after_reviewer,
            Some("second-reviewer-ref")
        ));
    }

    #[test]
    fn editable_requires_selected_profile_patch_authority() {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"editable-profile","version":"1","defaultLanguage":"en"},
              "entities":[{
                "id":"request","route":"requests","mutationMode":"mutable",
                "fields":[{"id":"label","type":"string","maxLength":64,"classification":"internal"}]
              }],
              "accessProfiles":[{
                "id":"reader","principalClaim":"principal","grants":[{
                  "entity":"request","operations":["get"],"readableFields":["label"]
                }]
              },{
                "id":"empty-editor","principalClaim":"principal","grants":[{
                  "entity":"request","operations":["get","patch"],"readableFields":["label"]
                }]
              },{
                "id":"editor","default":true,"principalClaim":"principal","grants":[{
                  "entity":"request","operations":["get","patch"],"readableFields":["label"],"writableFields":["label"]
                }]
              }]
            }"#,
        )
        .expect("fixture parses");
        let compiled =
            compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles");
        let entity = compiled.entities().get("request").expect("request entity");
        assert!(!selected_profile_allows_draft_patch(
            entity,
            &request_for_profile("reader")
        ));
        assert!(!selected_profile_allows_draft_patch(
            entity,
            &request_for_profile("empty-editor")
        ));
        assert!(selected_profile_allows_draft_patch(
            entity,
            &request_for_profile("editor")
        ));
    }

    #[test]
    fn retained_history_exposes_erased_detail_without_payload() {
        let proposal = RetainedRequestProposal {
            request_entity_id: "request".to_owned(),
            request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            proposal_version: 2,
            request_state: "approved".to_owned(),
            current: true,
            contract_fingerprint: "sha256:contract".to_owned(),
            effect_digest: "sha256:effect".to_owned(),
            detail_erased: true,
            application_id: Some("00000000-0000-4000-8000-0000000000aa".to_owned()),
            result_link_count: 1,
            result_links: vec![RetainedRequestResultLink {
                target_entity_id: "target".to_owned(),
                target_record_id: "00000000-0000-4000-8000-000000000010".to_owned(),
                target_revision: 7,
            }],
        };
        let value = retained_history_value(proposal, true);
        assert_eq!(value["detailErased"], json!(true));
        assert_eq!(value["effectDigest"], json!("sha256:effect"));
        assert_eq!(value["resultLinkCount"], json!(1));
        assert_eq!(value["resultLinks"][0]["targetRevision"], json!(7));
        assert!(value.get("snapshot").is_none());
        assert!(value.get("before").is_none());
        assert!(value.get("after").is_none());
    }

    #[test]
    fn retained_history_withholds_effect_digest_for_anonymous_claims() {
        let value = retained_history_value(
            RetainedRequestProposal {
                request_entity_id: "request".to_owned(),
                request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                proposal_version: 2,
                request_state: "approved".to_owned(),
                current: true,
                contract_fingerprint: "sha256:contract".to_owned(),
                effect_digest: "sha256:effect".to_owned(),
                detail_erased: true,
                application_id: Some("00000000-0000-4000-8000-0000000000aa".to_owned()),
                result_link_count: 0,
                result_links: Vec::new(),
            },
            false,
        );
        assert_eq!(value["detailErased"], json!(true));
        assert!(value.get("effectDigest").is_none());
        assert!(value.get("snapshot").is_none());
        assert!(value.get("before").is_none());
        assert!(value.get("after").is_none());
    }

    #[test]
    fn erased_terminal_metadata_uses_retained_stub_without_workflow_payload() {
        let value = erased_terminal_request_metadata(
            &crate::request_store::RequestWorkflowHeader {
                owner_reference: "owner-ref".to_owned(),
                state: "applied".to_owned(),
                proposal_version: 2,
                workflow_revision: 9,
                current_proposal_erased: true,
            },
            Some(RetainedHistoryMetadata {
                value: json!({
                    "proposals": [{
                        "proposalVersion": 2,
                        "detailErased": true,
                        "resultLinkCount": 0,
                        "resultLinks": []
                    }],
                    "nextAfterProposalVersion": Value::Null,
                }),
                current_effect_digest: Some("sha256:effect".to_owned()),
                current_application_id: Some("00000000-0000-4000-8000-0000000000aa".to_owned()),
            }),
            true,
        );
        assert_eq!(value["serverState"], json!("applied"));
        assert_eq!(value["proposalVersion"], json!(2));
        assert_eq!(value["detailErased"], json!(true));
        assert_eq!(value["editable"], json!(false));
        assert_eq!(value["effectDigest"], json!("sha256:effect"));
        assert!(value.get("actions").is_none());
        assert!(value.get("snapshot").is_none());
        assert!(value.get("before").is_none());
        assert!(value.get("after").is_none());
    }

    #[test]
    fn erased_terminal_metadata_withholds_effect_digest_for_anonymous_claims() {
        let value = erased_terminal_request_metadata(
            &crate::request_store::RequestWorkflowHeader {
                owner_reference: "owner-ref".to_owned(),
                state: "applied".to_owned(),
                proposal_version: 2,
                workflow_revision: 9,
                current_proposal_erased: true,
            },
            Some(RetainedHistoryMetadata {
                value: json!({
                    "proposals": [{
                        "proposalVersion": 2,
                        "detailErased": true,
                        "resultLinkCount": 0,
                        "resultLinks": []
                    }],
                    "nextAfterProposalVersion": Value::Null,
                }),
                current_effect_digest: Some("sha256:effect".to_owned()),
                current_application_id: Some("00000000-0000-4000-8000-0000000000aa".to_owned()),
            }),
            false,
        );
        assert_eq!(value["serverState"], json!("applied"));
        assert!(value.get("effectDigest").is_none());
        assert!(value.get("actions").is_none());
        assert!(value.get("snapshot").is_none());
    }

    #[test]
    fn action_href_preserves_selected_access_profile() {
        let request = request_for_profile("editor-profile");
        let action = action(Operation::ReviseRequest, None);
        assert_eq!(
            action_href(&action, &request, "00000000-0000-4000-8000-000000000001"),
            "/requests/00000000-0000-4000-8000-000000000001/action?accessProfile=editor-profile"
        );
    }

    #[test]
    fn review_snapshot_uses_configured_api_names() {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"snapshot-api-name","version":"1","defaultLanguage":"en"},
              "entities":[{
                "id":"target","route":"targets","mutationMode":"mutable",
                "fields":[
                  {"id":"proposed-site","apiName":"proposedSite","type":"string","maxLength":64,"classification":"internal"},
                  {"id":"hidden-field","apiName":"hiddenField","type":"string","maxLength":64,"classification":"internal"}
                ]
              }],
              "accessProfiles":[{
                "id":"operator","default":true,"principalClaim":"principal","grants":[{
                  "entity":"target","operations":["get"],"readableFields":["proposed-site"]
                }]
              }]
            }"#,
        )
        .expect("fixture parses");
        let compiled =
            compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles");
        let target = compiled.entities().get("target").expect("target exists");
        let snapshot = Map::from_iter([
            ("proposed-site".to_owned(), json!("site-a")),
            ("hidden-field".to_owned(), json!("do-not-include")),
        ]);
        let value = api_object(
            target,
            &snapshot,
            &BTreeSet::from(["proposed-site".to_owned()]),
        )
        .expect("snapshot serializes");
        assert_eq!(value, json!({"proposedSite": "site-a"}));
        assert!(value.get("proposed-site").is_none());
        assert!(value.get("hiddenField").is_none());
    }
    fn action(operation: Operation, stage: Option<&str>) -> VerifiedRequestAction {
        VerifiedRequestAction::new(
            "records.request.action".to_owned(),
            HttpMethod::Post,
            "/requests/{record_id}/action".to_owned(),
            operation,
            stage.map(str::to_owned),
            BTreeSet::new(),
            Vec::new(),
        )
    }

    fn submitted_workflow(approvals: u16, exclude_submitter: bool) -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(
                EntityId::new("request").expect("entity id"),
                RecordId::new("00000000-0000-4000-8000-000000000001").expect("record id"),
            ),
            actor("owner-ref"),
            StateRevision::new(1).expect("state revision"),
        )
        .submit(
            context("owner-ref", 1),
            proposal(approvals, exclude_submitter),
        )
        .expect("submit succeeds")
        .into_workflow()
    }

    fn proposal(approvals: u16, exclude_submitter: bool) -> PreparedProposal {
        PreparedProposal::new(
            RecordRevision::new(1).expect("record revision"),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            vec![CompiledChangeRequestStage {
                id: "review".to_owned(),
                approvals,
                exclude_submitter,
            }],
            vec![PreparedEffect::new(
                EffectId::new("effect").expect("effect id"),
                Operation::Patch,
                PreparedTarget::existing(
                    EntityId::new("target").expect("target entity"),
                    RecordId::new("00000000-0000-4000-8000-000000000010").expect("target record"),
                    RecordRevision::new(3).expect("target revision"),
                ),
                vec![PreparedFieldChange::set(
                    FieldId::new("field").expect("field id"),
                    FieldValue::present(json!("before")),
                    json!("after"),
                )
                .expect("field change")],
            )
            .expect("effect")],
            1024,
        )
        .expect("proposal")
    }

    fn decide(
        workflow: RequestWorkflow,
        actor_reference: &str,
        decision: ReviewDecisionKind,
    ) -> RequestWorkflow {
        let digest = workflow
            .current_proposal()
            .expect("current proposal")
            .effect_digest()
            .clone();
        workflow
            .decide(
                context(actor_reference, 2),
                "review",
                ProposalVersion::first(),
                &digest,
                decision,
            )
            .expect("decision succeeds")
            .into_workflow()
    }

    fn actor(value: &str) -> TrustedActorRef {
        TrustedActorRef::from_verified_context(value).expect("actor")
    }

    fn context(actor_reference: &str, second: u8) -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(
            actor(actor_reference),
            TrustedTimestamp::from_server_clock(format!("2026-08-31T00:00:{second:02}Z"))
                .expect("timestamp"),
        )
    }

    fn request_for_profile(profile: &str) -> RecordReadRequest {
        RecordReadRequest {
            entity_id: "request".to_owned(),
            operation_id: "records.request.get".to_owned(),
            method: HttpMethod::Get,
            context: AuthorizedRequestContext::new(None, None, profile.to_owned(), Vec::new()),
            selected_fields: BTreeSet::new(),
            kind: RecordReadKind::Get {
                id: "00000000-0000-4000-8000-000000000001".to_owned(),
            },
            maximum_records: 1,
            request_history_after_proposal_version: None,
            correlation: RequestCorrelation::server_created(),
        }
    }
}
