// SPDX-License-Identifier: Apache-2.0

//! Permission-aware change-request annotations for normal record reads.

use std::collections::BTreeSet;

use registry_platform_audit::AuditProfile;
use serde_json::{json, Map, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{compiled_api_name, open_snapshot_members, RecordEnvelope};
use crate::api::{
    ReadServiceError, RecordReadRequest, RequestActionTargetAuthority,
    RowBoundaryOperator as ApiRowBoundaryOperator, VerifiedRequestAction, VerifiedRequestPresence,
    VerifiedRequestTargetAuthority, VerifiedRowBoundary,
};
use crate::contract::{Operation, RequestMetadataFieldSource};
use crate::field_encryption::FieldEncryptionService;
use crate::model::{CompiledEntity, CompiledRegistry, HttpMethod};
use crate::mutation::request_action_etag;
use crate::postgres::context::ChangeRequestPresenceContext;
use crate::postgres::{
    ChangeRequestTargetBinding, ChangeRequestTargetContext, ClaimContext, ExpectedRegistryIdentity,
    RowBoundaryContext,
};
use crate::request_prepare::{validate_frozen_targets, RequestTargetSnapshot};
use crate::request_retention::{
    RetainedHistoryQuery, RetainedRequestHistoryPage, RetainedRequestProposal,
    RetainedRequestResultLink,
};
use crate::request_workflow::{ProposalSnapshot, RequestState, RequestWorkflow};

#[allow(clippy::too_many_arguments)]
pub(super) async fn annotate_records(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    audit_profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    field_encryption: Option<&FieldEncryptionService>,
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
            field_encryption,
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
    let history = retained_history(
        transaction,
        registry,
        request,
        claims,
        entity,
        record_uuid,
        None,
    )
    .await?;
    let metadata = erased_terminal_request_metadata(
        &header,
        history,
        may_disclose_effect_digests(entity, request),
        may_disclose_actor_references(entity, request),
    );
    let mut record = RecordEnvelope {
        id: record_id.to_owned(),
        revision,
        data: Map::new(),
        request: Some(bound_request_metadata(metadata)?),
        request_presence: None,
    };
    annotate_attachment_metadata(
        transaction,
        entity,
        request,
        record_uuid,
        header.proposal_version,
        &mut record.data,
    )
    .await?;
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
    field_encryption: Option<&FieldEncryptionService>,
    records: &mut [RecordEnvelope],
) -> Result<(), ReadServiceError> {
    let actor_reference = claims
        .principal()
        .map(|principal| {
            audit_profile.key_hasher().audit_reference_hash(
                "breg-request-actor-v1",
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
        annotate_attachment_metadata(
            transaction,
            entity,
            request,
            record_uuid,
            header.proposal_version,
            &mut record.data,
        )
        .await?;
        if header.current_proposal_erased && header.is_terminal() {
            let history = retained_history(
                transaction,
                registry,
                request,
                claims,
                entity,
                record_uuid,
                None,
            )
            .await?;
            let metadata = erased_terminal_request_metadata(
                &header,
                history,
                may_disclose_effect_digests(entity, request),
                may_disclose_actor_references(entity, request),
            );
            record.request = Some(bound_request_metadata(metadata)?);
            continue;
        }
        let workflow = crate::request_store::load(transaction, &entity.id, record_uuid, false)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let targets = if workflow.current_proposal().is_some()
            && request
                .context
                .request_actions()
                .iter()
                .any(|action| action.operation() == Operation::ApplyRequest)
        {
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
            transaction,
            registry,
            audit_profile,
            expected,
            request,
            claims,
            entity,
            field_encryption,
            record,
            &workflow,
            &targets,
            actor_reference.as_deref(),
        )
        .await?;
        let history = retained_history(
            transaction,
            registry,
            request,
            claims,
            entity,
            record_uuid,
            Some(&workflow),
        )
        .await?;
        let mut metadata = Map::new();
        metadata.insert(
            "bregState".to_owned(),
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
            if let Some(proposal) = workflow
                .current_proposal()
                .and_then(request_proposal_metadata)
            {
                metadata.insert("proposal".to_owned(), proposal);
            }
        }
        if may_disclose_actor_references(entity, request) {
            metadata.insert(
                "submitterReference".to_owned(),
                json!(workflow.owner().as_str()),
            );
            if let Some(application) = workflow.application() {
                metadata.insert(
                    "applierReference".to_owned(),
                    json!(application.applied_by().as_str()),
                );
            }
        }
        if may_disclose_review_state(entity, request) {
            if let Some(proposal) = workflow.current_proposal() {
                if let Some(review) = crate::review_store::read_projection(
                    transaction,
                    &entity.id,
                    record_uuid,
                    proposal,
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?
                {
                    metadata.insert("review".to_owned(), review);
                }
            }
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
                "reasonPresent": application.reason_present(),
            });
            if may_disclose_effect_digests(entity, request) {
                application_metadata["effectDigest"] = json!(application.effect_digest().as_str());
            }
            if may_disclose_application_reason(entity, request) {
                if let Some(reason) = application.reason() {
                    application_metadata["reason"] = json!(reason);
                }
            }
            metadata.insert("application".to_owned(), application_metadata);
        }
        record.request = Some(bound_request_metadata(Value::Object(metadata))?);
    }
    Ok(())
}

/// Exact request GET authorization is established before this helper. An owner
/// retains access to retained versions; a reviewer or applier must additionally
/// satisfy one complete current grant against the requested frozen targets.
#[allow(clippy::too_many_arguments)]
pub(super) async fn attachment_version_is_authorized(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    audit_profile: &AuditProfile,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    field_encryption: Option<&FieldEncryptionService>,
    record_id: Uuid,
    proposal_version: i64,
    slot_id: &str,
) -> Result<bool, ReadServiceError> {
    let header = crate::request_store::load_header(transaction, &entity.id, record_id, false)
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    let proposal = transaction.query_opt(
        "SELECT snapshot FROM registry_internal.registry_request_proposals WHERE request_entity_id=$1 AND request_id=$2 AND proposal_version=$3 AND erased_at IS NULL",
        &[&entity.id, &record_id, &proposal_version],
    ).await.map_err(|_| ReadServiceError::Unavailable)?;
    let unsubmitted = proposal.is_none()
        && proposal_version == header.proposal_version
        && !header.current_proposal_erased
        && matches!(header.state.as_str(), "draft" | "cancelled");
    if proposal.is_none() && !unsubmitted {
        return Ok(false);
    }
    let principal = claims.principal().ok_or(ReadServiceError::Unavailable)?;
    let actor = audit_profile
        .key_hasher()
        .audit_reference_hash("breg-request-actor-v1", &expected.database_id, principal)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if actor == header.owner_reference {
        return Ok(true);
    }
    let profile = entity
        .access_profiles
        .get(request.context.selected_profile())
        .ok_or(ReadServiceError::Unavailable)?;
    let target_role = profile
        .operations
        .iter()
        .any(|operation| *operation == Operation::ApplyRequest);
    if !target_role {
        // A separately authored direct GET grant has already passed its own
        // typed row boundary. It does not acquire any review/apply powers.
        return Ok(true);
    }
    let Some(row) = proposal else {
        return Ok(false);
    };
    let snapshot: Value = row.try_get(0).map_err(|_| ReadServiceError::Unavailable)?;
    let proposal: ProposalSnapshot =
        serde_json::from_value(snapshot).map_err(|_| ReadServiceError::Unavailable)?;
    if i64::from(proposal.version().get()) != proposal_version {
        return Err(ReadServiceError::Unavailable);
    }
    let targets =
        crate::request_store::load_targets(transaction, &entity.id, record_id, proposal_version)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
    validate_frozen_targets(&proposal, &targets).map_err(|_| ReadServiceError::Unavailable)?;
    for action in request
        .context
        .request_actions()
        .iter()
        .filter(|action| action.operation() == Operation::ApplyRequest)
    {
        let self_authority = action.attachment_request_authority();
        if action.operation() != Operation::ApplyRequest && self_authority.is_none() {
            continue;
        }
        if let Some(authority) = self_authority {
            if authority.target_entity_id() != entity.id
                || (action.operation() != Operation::ApplyRequest
                    && !authority.readable_fields().contains(slot_id))
            {
                continue;
            }
            let Some(row) = transaction.query_opt(
                "SELECT snapshot FROM registry_internal.registry_revisions WHERE entity_id=$1 AND record_id=$2 AND record_revision=$3 AND erased_at IS NULL",
                &[&entity.id, &record_id, &proposal.request_record_revision().get()],
            ).await.map_err(|_| ReadServiceError::Unavailable)? else { continue; };
            let Some(bytes): Option<Vec<u8>> =
                row.try_get(0).map_err(|_| ReadServiceError::Unavailable)?
            else {
                continue;
            };
            let intake = registry_platform_canonical_json::parse_json_strict(&bytes)
                .map_err(|_| ReadServiceError::Unavailable)?;
            if registry_platform_canonical_json::canonicalize_json(&intake)
                .map_err(|_| ReadServiceError::Unavailable)?
                != bytes
            {
                return Err(ReadServiceError::Unavailable);
            }
            let intake = intake.as_object().ok_or(ReadServiceError::Unavailable)?;
            // The retained intake keeps its sealed members until this
            // authorization edge: the boundary comparison reads the opened
            // row, and a stored envelope that does not open refuses the
            // disclosure instead of authorizing it.
            let mut intake = intake.clone();
            open_snapshot_members(
                entity,
                &record_id.to_string(),
                &mut intake,
                field_encryption,
            )?;
            if ChangeRequestTargetContext::authorize_retained_attachment_request(
                registry,
                claims,
                slot_id,
                &row_boundaries(authority)?,
                &intake,
                record_id,
            )
            .is_err()
            {
                continue;
            }
        } else if entity.change_request.as_ref().is_some_and(|plan| {
            plan.apply_permissions.iter().any(|grant| {
                grant.profile_id == claims.access_profile() && grant.target_entity_id == entity.id
            })
        }) {
            // Authored self boundaries must not disappear from verified input.
            continue;
        }
        if attachment_targets_are_authorized(
            transaction,
            registry,
            expected,
            claims,
            entity,
            field_encryption,
            record_id,
            &actor,
            &proposal,
            &targets,
            action,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
async fn attachment_targets_are_authorized(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    field_encryption: Option<&FieldEncryptionService>,
    record_id: Uuid,
    actor: &str,
    proposal: &ProposalSnapshot,
    targets: &[RequestTargetSnapshot],
    action: &VerifiedRequestAction,
) -> Result<bool, ReadServiceError> {
    for effect in proposal.effects() {
        let target_entity_id = effect.target().entity_id().as_str();
        let target_record = effect
            .target()
            .existing_record_id()
            .or_else(|| effect.target().reserved_record_id())
            .ok_or(ReadServiceError::Unavailable)?;
        let target_id = parse_uuid(target_record.as_str())?;
        let target = targets
            .iter()
            .find(|target| target.entity_id == target_entity_id && target.record_id == target_id)
            .ok_or(ReadServiceError::Unavailable)?;
        let Some(authority) = action
            .target_authority()
            .iter()
            .find(|authority| authority.target_entity_id() == target_entity_id)
        else {
            return Ok(false);
        };
        let binding = ChangeRequestTargetBinding {
            request_entity_id: entity.id.clone(),
            request_id: record_id,
            proposal_version: i64::from(proposal.version().get()),
            actor_reference: actor.to_owned(),
            contract_fingerprint: proposal.contract_fingerprint().as_str().to_owned(),
            effect_digest: proposal.effect_digest().as_str().to_owned(),
            active_package_revision: expected.package_revision.clone(),
            effect_id: effect.id().as_str().to_owned(),
            target_entity_id: target_entity_id.to_owned(),
            target_record_id: target_id,
            operation: effect.operation(),
            fields: effect
                .field_changes()
                .iter()
                .map(|change| change.field().as_str().to_owned())
                .collect(),
            expected_revision: target.expected_revision,
        };
        let target_entity = registry
            .entities()
            .get(target_entity_id)
            .ok_or(ReadServiceError::Unavailable)?;
        // The captured target rows keep their sealed members until this
        // authorization edge. Row boundaries never name an encrypted field,
        // so opening them preserves the authorized and unauthorized
        // outcomes, and a stored envelope that does not open refuses the
        // disclosure closed instead of authorizing it.
        let mut before = target.before.clone();
        if let Some(before) = before.as_mut() {
            open_snapshot_members(
                target_entity,
                &target_id.to_string(),
                before,
                field_encryption,
            )?;
        }
        if ChangeRequestTargetContext::authorize_retained_attachment_rows(
            registry,
            claims,
            row_boundaries(authority)?,
            binding,
            target_entity,
            before.as_ref(),
            &target.after,
            target_id,
        )
        .is_err()
        {
            return Ok(false);
        }
    }
    if action.operation() == Operation::ApplyRequest {
        if let Some(frozen) = proposal.application_preconditions() {
            frozen
                .validate()
                .map_err(|_| ReadServiceError::Unavailable)?;
            for guard in &frozen.targets {
                let guard_id = parse_uuid(guard.record_id.as_str())?;
                let Some(authority) = action
                    .target_authority()
                    .iter()
                    .find(|authority| authority.target_entity_id() == guard.entity_id)
                else {
                    return Ok(false);
                };
                let Some(row) = transaction
                    .query_opt(
                        "SELECT snapshot FROM registry_internal.registry_revisions WHERE entity_id=$1 AND record_id=$2 AND record_revision=$3 AND erased_at IS NULL",
                        &[&guard.entity_id, &guard_id, &guard.expected_revision],
                    )
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
                else {
                    return Ok(false);
                };
                let Some(bytes): Option<Vec<u8>> =
                    row.try_get(0).map_err(|_| ReadServiceError::Unavailable)?
                else {
                    return Ok(false);
                };
                let snapshot = registry_platform_canonical_json::parse_json_strict(&bytes)
                    .map_err(|_| ReadServiceError::Unavailable)?;
                if registry_platform_canonical_json::canonicalize_json(&snapshot)
                    .map_err(|_| ReadServiceError::Unavailable)?
                    != bytes
                {
                    return Err(ReadServiceError::Unavailable);
                }
                let guard_entity = registry
                    .entities()
                    .get(&guard.entity_id)
                    .ok_or(ReadServiceError::Unavailable)?;
                // The frozen guard compares the stored row against the value
                // the request captured, so an encrypted member opens before
                // the comparison: envelope bytes never stand in for the
                // submitted value, and a stored member that does not open
                // refuses the disclosure instead of failing it silently.
                let mut snapshot = snapshot
                    .as_object()
                    .ok_or(ReadServiceError::Unavailable)?
                    .clone();
                open_snapshot_members(
                    guard_entity,
                    &guard_id.to_string(),
                    &mut snapshot,
                    field_encryption,
                )?;
                if guard
                    .values
                    .iter()
                    .any(|(field, value)| snapshot.get(field) != Some(value))
                {
                    return Ok(false);
                }
                let binding = ChangeRequestTargetBinding {
                    request_entity_id: entity.id.clone(),
                    request_id: record_id,
                    proposal_version: i64::from(proposal.version().get()),
                    actor_reference: actor.to_owned(),
                    contract_fingerprint: proposal.contract_fingerprint().as_str().to_owned(),
                    effect_digest: proposal.effect_digest().as_str().to_owned(),
                    active_package_revision: expected.package_revision.clone(),
                    effect_id: guard.id.clone(),
                    target_entity_id: guard.entity_id.clone(),
                    target_record_id: guard_id,
                    operation: Operation::Patch,
                    fields: guard.values.keys().cloned().collect(),
                    expected_revision: Some(guard.expected_revision),
                };
                if ChangeRequestTargetContext::authorize_retained_attachment_rows(
                    registry,
                    claims,
                    row_boundaries(authority)?,
                    binding,
                    guard_entity,
                    Some(&snapshot),
                    &snapshot,
                    guard_id,
                )
                .is_err()
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

async fn annotate_attachment_metadata(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    request: &RecordReadRequest,
    record_id: Uuid,
    proposal_version: i64,
    data: &mut Map<String, Value>,
) -> Result<(), ReadServiceError> {
    let selected = request
        .selected_fields
        .iter()
        .filter(|field| entity.attachments.contains_key(*field))
        .cloned()
        .collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return Ok(());
    }
    let metadata = crate::attachment_store::metadata_for_read(
        transaction,
        &entity.id,
        record_id,
        proposal_version,
        &selected,
    )
    .await
    .map_err(|_| ReadServiceError::Unavailable)?;
    for slot in selected {
        data.insert(
            slot.clone(),
            metadata.get(&slot).cloned().unwrap_or(Value::Null),
        );
    }
    Ok(())
}

// This is the maintained client decoder's maximum request-extension size.
const MAX_REQUEST_EXTENSION_BYTES: usize = 2_097_152;

fn bound_request_metadata(mut metadata: Value) -> Result<Value, ReadServiceError> {
    while serde_json::to_vec(&metadata)
        .map_err(|_| ReadServiceError::Unavailable)?
        .len()
        > MAX_REQUEST_EXTENSION_BYTES
    {
        let history = metadata
            .get_mut("history")
            .and_then(Value::as_object_mut)
            .ok_or(ReadServiceError::Unavailable)?;
        let proposals = history
            .get_mut("proposals")
            .and_then(Value::as_array_mut)
            .ok_or(ReadServiceError::Unavailable)?;
        if proposals.len() <= 1 {
            return Err(ReadServiceError::Unavailable);
        }
        proposals.pop();
        let cursor = proposals
            .last()
            .and_then(|proposal| proposal.get("proposalVersion"))
            .cloned()
            .ok_or(ReadServiceError::Unavailable)?;
        history.insert("nextAfterProposalVersion".to_owned(), cursor);
    }
    Ok(metadata)
}

/// Caller-filtered public projection of the frozen planning binding. The
/// source digest, ABI provenance, script identity and evaluated effects remain
/// inside the proposal snapshot and review/action-specific projections.
fn request_proposal_metadata(proposal: &ProposalSnapshot) -> Option<Value> {
    Some(json!({"review": proposal.review_requirement()}))
}

fn erased_terminal_request_metadata(
    header: &crate::request_store::RequestWorkflowHeader,
    history: Option<RetainedHistoryMetadata>,
    disclose_effect_digests: bool,
    disclose_actor_references: bool,
) -> Value {
    let mut metadata = Map::new();
    metadata.insert("bregState".to_owned(), json!(header.state));
    metadata.insert("proposalVersion".to_owned(), json!(header.proposal_version));
    metadata.insert("detailErased".to_owned(), json!(true));
    metadata.insert("editable".to_owned(), json!(false));
    if disclose_actor_references {
        metadata.insert(
            "submitterReference".to_owned(),
            json!(header.owner_reference),
        );
        if let Some(applier_reference) = &header.applier_reference {
            metadata.insert("applierReference".to_owned(), json!(applier_reference));
        }
    }
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
                    // Erasure removes the applier's explanation and keeps its
                    // presence, as it does for a decision.
                    "reasonPresent": header.application_reason_present,
                }),
            );
        }
        metadata.insert("history".to_owned(), history.value);
    }
    Value::Object(metadata)
}

#[allow(clippy::too_many_arguments)]
async fn action_links(
    _transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    audit_profile: &AuditProfile,
    expected: &ExpectedRegistryIdentity,
    request: &RecordReadRequest,
    claims: &ClaimContext,
    _entity: &CompiledEntity,
    _field_encryption: Option<&FieldEncryptionService>,
    record: &RecordEnvelope,
    workflow: &RequestWorkflow,
    _targets: &[RequestTargetSnapshot],
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
        if let Some(rebase) = revise_rebase_available(action, workflow) {
            value["rebase"] = json!(rebase);
        }
        if let Some(proposal) = workflow.current_proposal() {
            value["proposalVersion"] = json!(proposal.version().get());
            value["effectDigest"] = json!(proposal.effect_digest().as_str());
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
        Operation::CancelRequest => {
            !matches!(
                workflow.state(),
                RequestState::Cancelled | RequestState::Applied
            ) && actor_reference.is_some_and(|actor| workflow.owner().as_str() == actor)
        }
        Operation::ApplyRequest => workflow.state() == RequestState::Submitted,
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
        RequestState::Submitted => Some(true),
        _ => None,
    }
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
              AND state.state = 'submitted'
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
    loaded_workflow: Option<&RequestWorkflow>,
) -> Result<Option<RetainedHistoryMetadata>, ReadServiceError> {
    if let Some(workflow) = loaded_workflow {
        let last_visible_version = i64::from(workflow.current_version().get())
            - i64::from(workflow.current_proposal().is_none());
        if request.request_history_after_proposal_version.unwrap_or(0) >= last_visible_version {
            return Ok(None);
        }
    }
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
    if let Some(workflow) = loaded_workflow {
        bind_history_to_workflow(&mut page, workflow);
    }
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
            .map(|proposal| retained_history_value(
                proposal,
                may_disclose_effect_digests(entity, request),
            ))
            .collect::<Vec<_>>(),
        "nextAfterProposalVersion": page.next_after_proposal_version,
    });
    Ok(Some(RetainedHistoryMetadata {
        value,
        current_effect_digest,
        current_application_id,
    }))
}

// Historical rows may be read after the workflow under READ COMMITTED. Bind
// lifecycle facts to the workflow already used for top-level metadata; newer
// versions or a newly submitted current draft belong to a subsequent read.
fn bind_history_to_workflow(page: &mut RetainedRequestHistoryPage, workflow: &RequestWorkflow) {
    let current_version = i64::from(workflow.current_version().get());
    let current_proposal = workflow.current_proposal();
    let last_visible_version = current_version - i64::from(current_proposal.is_none());
    let had_newer_versions = page
        .proposals
        .iter()
        .any(|proposal| proposal.proposal_version > last_visible_version);
    page.proposals
        .retain(|proposal| proposal.proposal_version <= last_visible_version);
    if had_newer_versions
        || page
            .proposals
            .last()
            .is_none_or(|proposal| proposal.proposal_version == last_visible_version)
    {
        page.next_after_proposal_version = None;
    }
    for proposal in &mut page.proposals {
        proposal.request_state = request_state_name(workflow.state()).to_owned();
        proposal.current = proposal.proposal_version == current_version;
        if !proposal.current {
            continue;
        }
        if let Some(snapshot) = current_proposal {
            proposal.contract_fingerprint = snapshot.contract_fingerprint().as_str().to_owned();
            proposal.effect_digest = snapshot.effect_digest().as_str().to_owned();
        }
        // A workflow only restores while its current proposal detail exists.
        proposal.detail_erased = false;
        proposal.application_id = workflow
            .application()
            .map(|application| application.application_id().as_str().to_owned());
        proposal.result_link_count = 0;
        proposal.result_links.clear();
    }
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

/// Verified authority over one result-link target under the reader's profile.
///
/// A grant that admits submitter targets must present the target's own verified
/// claims: the request entity's boundaries answer a different question and never
/// stand in for them, so an absent entry conceals the link.
fn authorized_target_claims<'a>(
    registry: &CompiledRegistry,
    claims: &'a ClaimContext,
    target_entity_id: &str,
) -> Option<&'a ClaimContext> {
    if let Some(target_claims) = claims.submitter_targets().get(target_entity_id) {
        return Some(target_claims);
    }
    let admits_target = registry
        .entities()
        .get(claims.entity_id())
        .and_then(|entity| entity.access_profiles.get(claims.access_profile()))
        .is_some_and(|profile| profile.submitter_targets.contains(target_entity_id));
    (!admits_target).then_some(claims)
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
    let Some(target_claims) = authorized_target_claims(registry, claims, target_entity_id) else {
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
            target_claims.row_boundaries().to_vec(),
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
    target_claims
        .install_row_boundaries(transaction)
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    let result = transaction
        .query_opt(&sql, &[&target_record_id])
        .await
        .map(|row| row.is_some())
        .map_err(|_| ReadServiceError::Unavailable);
    claims
        .install_row_boundaries(transaction)
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    result
}

fn retained_history_value(
    proposal: RetainedRequestProposal,
    disclose_effect_digests: bool,
) -> Value {
    let mut value = json!({
        "requestEntityId": proposal.request_entity_id,
        "requestId": proposal.request_id,
        "proposalVersion": proposal.proposal_version,
        "bregState": proposal.request_state,
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

fn may_disclose_application_reason(entity: &CompiledEntity, request: &RecordReadRequest) -> bool {
    entity
        .access_profiles
        .get(request.context.selected_profile())
        .is_some_and(|profile| {
            !profile.anonymous
                && profile
                    .readable_request_fields
                    .contains(&RequestMetadataFieldSource::Reason)
        })
}

fn may_disclose_review_state(entity: &CompiledEntity, request: &RecordReadRequest) -> bool {
    entity
        .access_profiles
        .get(request.context.selected_profile())
        .is_some_and(|profile| {
            !profile.anonymous
                && profile
                    .readable_request_fields
                    .contains(&RequestMetadataFieldSource::ReviewState)
        })
}

fn may_disclose_actor_references(entity: &CompiledEntity, request: &RecordReadRequest) -> bool {
    entity
        .access_profiles
        .get(request.context.selected_profile())
        .is_some_and(|profile| {
            !profile.anonymous
                && profile
                    .readable_request_fields
                    .contains(&RequestMetadataFieldSource::ActorReference)
        })
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

#[allow(dead_code)]
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
        RequestState::Cancelled => "cancelled",
        RequestState::Applied => "applied",
        RequestState::Superseded => "superseded",
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
    #[test]
    fn final_request_size_cap_keeps_whole_proposals_and_exclusive_cursor() {
        let result_links = (0..768)
            .map(|index| {
                serde_json::json!({
                    "targetEntityId": "bounded-target",
                    "targetRecordId": format!("00000000-0000-4000-8000-{index:012}"),
                    "targetRevision": 1,
                })
            })
            .collect::<Vec<_>>();
        let metadata = serde_json::json!({
            "bregState": "draft", "proposalVersion": 26, "editable": false,
            "history": {
                "proposals": (1..=25).map(|version| serde_json::json!({
                    "requestEntityId": "case-request",
                    "requestId": "00000000-0000-4000-8000-000000000001",
                    "proposalVersion": version,
                    "bregState": "draft",
                    "current": false,
                    "contractFingerprint": "contract-fingerprint",
                    "detailErased": false,
                    "applicationId": null,
                    "resultLinkCount": result_links.len(),
                    "resultLinks": result_links,
                })).collect::<Vec<_>>(),
                "nextAfterProposalVersion": null,
            },
        });
        assert!(serde_json::to_vec(&metadata).unwrap().len() > super::MAX_REQUEST_EXTENSION_BYTES);
        let bounded = super::bound_request_metadata(metadata).expect("whole proposals fit");
        // This synthetic payload intentionally exceeds the governed per-proposal
        // result-link maximum to exercise only the final serialization guard.
        // Reachable proposal shapes are covered by the client-decoder tests.
        let proposals = bounded["history"]["proposals"].as_array().unwrap();
        assert!(proposals.len() < 25);
        assert_eq!(
            bounded["history"]["nextAfterProposalVersion"],
            proposals.last().unwrap()["proposalVersion"]
        );
        assert!(proposals
            .iter()
            .all(|proposal| proposal["resultLinks"].as_array().unwrap().len() == 768));
    }

    #[test]
    fn oversized_single_history_proposal_refuses_without_an_empty_cursor_loop() {
        let metadata = serde_json::json!({
            "history": {"proposals": [{"proposalVersion": 1, "resultLinks": [],
                "oversized": "x".repeat(super::MAX_REQUEST_EXTENSION_BYTES)}],
                "nextAfterProposalVersion": 1},
        });
        assert!(super::bound_request_metadata(metadata).is_err());
    }

    use std::collections::{BTreeMap, BTreeSet};

    use registry_platform_audit::AuditProfile;
    use serde_json::{json, Value};

    use super::{
        action_href, action_is_available, authorized_target_claims,
        erased_terminal_request_metadata, may_disclose_actor_references,
        may_disclose_application_reason, may_disclose_review_state, retained_history_value,
        revise_rebase_available, selected_profile_allows_draft_patch, ClaimContext,
        RetainedHistoryMetadata, RowBoundaryContext,
    };
    use crate::api::{
        AuthorizedRequestContext, RecordReadKind, RecordReadRequest, VerifiedRequestAction,
    };
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{parse_project_json, parse_project_yaml, Operation};
    use crate::correlation::RequestCorrelation;
    use crate::model::{
        CompiledChangeRequestNoReview, CompiledChangeRequestNoReviewMode,
        CompiledChangeRequestReview, HttpMethod,
    };
    use crate::mutation::request_actor_reference;
    use crate::request_retention::{RetainedRequestProposal, RetainedRequestResultLink};
    use crate::request_workflow::{
        ContractFingerprint, EffectId, EntityId, FieldId, FieldValue, FrozenPlannerKind,
        FrozenPlanningBinding, PackageFingerprint, PreparedEffect, PreparedFieldChange,
        PreparedProposal, PreparedTarget, RecordId, RecordRevision, RequestKey, RequestWorkflow,
        StateRevision, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
    };

    #[test]
    fn revise_action_marks_rebase_required_on_submitted_requests() {
        let revise = action(Operation::ReviseRequest);
        let submitted = submitted_workflow();
        assert_eq!(revise_rebase_available(&revise, &submitted), Some(true));
        assert!(action_is_available(&revise, &submitted, Some("owner-ref")));
        assert!(!action_is_available(
            &revise,
            &submitted,
            Some("reviewer-ref")
        ));
    }

    #[test]
    fn cancel_action_is_offered_to_the_request_owner_only() {
        let cancel = action(Operation::CancelRequest);
        let draft = RequestWorkflow::new_draft(
            RequestKey::new(
                EntityId::new("request").expect("entity id"),
                RecordId::new("00000000-0000-4000-8000-000000000001").expect("record id"),
            ),
            actor("owner-ref"),
            StateRevision::new(1).expect("state revision"),
        );
        assert!(action_is_available(&cancel, &draft, Some("owner-ref")));
        assert!(!action_is_available(&cancel, &draft, Some("reviewer-ref")));
        assert!(!action_is_available(&cancel, &draft, None));

        let submitted = submitted_workflow();
        assert!(action_is_available(&cancel, &submitted, Some("owner-ref")));
        assert!(!action_is_available(
            &cancel,
            &submitted,
            Some("reviewer-ref")
        ));

        let canceled = submitted
            .clone()
            .cancel(context("owner-ref", 3))
            .expect("owner cancels")
            .into_workflow();
        assert!(!action_is_available(&cancel, &canceled, Some("owner-ref")));
    }

    #[test]
    fn submit_availability_does_not_borrow_application_authority() {
        let draft = RequestWorkflow::new_draft(
            RequestKey::new(
                EntityId::new("request").expect("entity id"),
                RecordId::new("00000000-0000-4000-8000-000000000001").expect("record id"),
            ),
            actor("owner-ref"),
            StateRevision::new(1).expect("state revision"),
        );
        let ordinary = action(Operation::SubmitRequest);
        assert!(action_is_available(&ordinary, &draft, Some("owner-ref")));
        assert!(!action_is_available(&ordinary, &draft, Some("other-ref")));
    }

    #[test]
    fn editable_requires_selected_profile_patch_authority() {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"editable-profile","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[{
                "id":"request","primaryDataset":"test-dataset","route":"requests","mutationMode":"mutable",
                "fields":[{"id":"label","type":"string","maxLength":64,"classification":"internal"}]
              }],
              "accessProfiles":[{
                "id":"reader","principalClaim":"principal","permissions":[{
                  "entity":"request","operations":["get"],"readableFields":["label"],
                  "rowBoundaries": []
                }]
              },{
                "id":"empty-editor","principalClaim":"principal","permissions":[{
                  "entity":"request","operations":["get","patch"],"readableFields":["label"],
                  "rowBoundaries": []
                }]
              },{
                "id":"editor","default":true,"principalClaim":"principal","permissions":[{
                  "entity":"request","operations":["get","patch"],"readableFields":["label"],"writableFields":["label"],
                  "rowBoundaries": []
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
    fn result_link_target_authority_never_falls_back_to_request_boundaries() {
        let compiled = compiled_product_fixture(include_bytes!(
            "../../../../products/breg/starters/professional-licences/core/registry.yaml"
        ));
        let holder = ClaimContext::for_compiled(
            &compiled,
            "scope-correction",
            Some("holder-principal".to_owned()),
            "holder",
            Some("starter-learning".to_owned()),
            Vec::new(),
        )
        .expect("the holder request grant carries no row boundaries");
        assert!(
            authorized_target_claims(&compiled, &holder, "professional-license").is_none(),
            "a grant admitting submitter targets must conceal a link it holds no target claims for"
        );

        let admitted = holder
            .clone()
            .with_submitter_targets(
                &compiled,
                BTreeMap::from([(
                    "professional-license".to_owned(),
                    vec![RowBoundaryContext::Equals {
                        field: "person-reference".to_owned(),
                        value: "holder-person".to_owned(),
                    }],
                )]),
            )
            .expect("the target grant carries one person reference boundary");
        let target_claims = authorized_target_claims(&compiled, &admitted, "professional-license")
            .expect("verified target claims answer the link");
        assert_eq!(target_claims.entity_id(), "professional-license");
        assert_eq!(target_claims.row_boundaries().len(), 1);

        let editor = ClaimContext::for_compiled(
            &compiled,
            "scope-correction",
            Some("editor-principal".to_owned()),
            "editor",
            Some("starter-learning".to_owned()),
            Vec::new(),
        )
        .expect("the editor request grant carries no row boundaries");
        assert!(
            authorized_target_claims(&compiled, &editor, "professional-license")
                .is_some_and(|claims| claims.entity_id() == "scope-correction"),
            "a grant admitting no submitter target reads the link under its own claims"
        );
    }

    #[test]
    fn request_actor_reference_is_a_keyed_hash_scoped_to_the_source_database() {
        let compiled = compiled_product_fixture(include_bytes!(
            "../../../../products/breg/acceptance/asset-site-placement-change-requests/registry.yaml"
        ));
        let claims = |principal: &str| {
            ClaimContext::for_compiled(
                &compiled,
                "placement-correction-request",
                Some(principal.to_owned()),
                "correction-submitter",
                Some("asset-correction".to_owned()),
                Vec::new(),
            )
            .expect("submitter context is valid")
        };
        let keyed = AuditProfile::production_from_secret_bytes(vec![0x4d; 32].into())
            .expect("test profile is strongly keyed");
        let rekeyed = AuditProfile::production_from_secret_bytes(vec![0x5e; 32].into())
            .expect("test profile is strongly keyed");
        let reference = |profile: &AuditProfile, database_id: &str, claims: &ClaimContext| {
            request_actor_reference(profile, database_id, claims).expect("actor reference derives")
        };
        let submitter = claims("submitter-principal");

        let baseline = reference(&keyed, "database-a", &submitter);
        assert_eq!(
            baseline,
            reference(&keyed, "database-a", &claims("submitter-principal")),
            "one principal keeps one reference within a source database"
        );
        assert!(
            !baseline.contains("submitter-principal"),
            "a reference never carries the principal it stands for"
        );
        assert_ne!(
            baseline,
            reference(&keyed, "database-b", &submitter),
            "a reference does not link one principal across source databases"
        );
        assert_ne!(
            baseline,
            reference(&rekeyed, "database-a", &submitter),
            "a reference cannot be recomputed without the audit key"
        );
        assert_ne!(
            baseline,
            reference(&keyed, "database-a", &claims("other-principal"))
        );
    }

    #[test]
    fn application_reason_bounds_and_disclosure_require_current_authority() {
        assert!(crate::request_workflow::valid_application_reason(
            &"文".repeat(crate::request_workflow::MAX_APPLICATION_REASON_CHARS)
        ));
        assert!(!crate::request_workflow::valid_application_reason(
            &"文".repeat(crate::request_workflow::MAX_APPLICATION_REASON_CHARS + 1)
        ));
        assert!(!crate::request_workflow::valid_application_reason(
            "unsafe\0reason"
        ));

        let compiled = compiled_product_fixture(include_bytes!(
            "../../../../products/breg/acceptance/asset-site-placement-change-requests/registry.yaml"
        ));
        let mut entity = compiled.entities()["placement-correction-request"].clone();
        let request = request_for_profile("correction-submitter");
        assert!(may_disclose_application_reason(&entity, &request));
        assert!(!may_disclose_actor_references(&entity, &request));
        assert!(may_disclose_review_state(&entity, &request));
        entity
            .access_profiles
            .get_mut("correction-submitter")
            .expect("profile")
            .readable_request_fields
            .extend([crate::contract::RequestMetadataFieldSource::ActorReference]);
        assert!(may_disclose_actor_references(&entity, &request));
        assert!(may_disclose_review_state(&entity, &request));
        entity
            .access_profiles
            .get_mut("correction-submitter")
            .expect("profile")
            .readable_request_fields
            .clear();
        assert!(!may_disclose_application_reason(&entity, &request));
        assert!(!may_disclose_actor_references(&entity, &request));
        assert!(!may_disclose_review_state(&entity, &request));
        entity
            .access_profiles
            .get_mut("correction-submitter")
            .expect("profile")
            .readable_request_fields
            .extend([
                crate::contract::RequestMetadataFieldSource::Reason,
                crate::contract::RequestMetadataFieldSource::ActorReference,
                crate::contract::RequestMetadataFieldSource::ReviewState,
            ]);
        entity
            .access_profiles
            .get_mut("correction-submitter")
            .expect("profile")
            .anonymous = true;
        assert!(!may_disclose_application_reason(&entity, &request));
        assert!(!may_disclose_actor_references(&entity, &request));
        assert!(!may_disclose_review_state(&entity, &request));
        assert!(!may_disclose_application_reason(
            &entity,
            &request_for_profile("missing")
        ));
    }
    fn compiled_product_fixture(bytes: &[u8]) -> crate::model::CompiledRegistry {
        let project = parse_project_yaml(bytes).expect("product fixture parses");
        compile_project(&project, &[], CompileProfile::Authoring).expect("product fixture compiles")
    }

    #[test]
    fn retained_history_exposes_erased_detail_without_payload() {
        let proposal = RetainedRequestProposal {
            request_entity_id: "request".to_owned(),
            request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            proposal_version: 2,
            request_state: "applied".to_owned(),
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
                request_state: "applied".to_owned(),
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
                applier_reference: Some("applier-ref".to_owned()),
                application_reason_present: false,
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
            true,
        );
        assert_eq!(value["bregState"], json!("applied"));
        assert_eq!(value["proposalVersion"], json!(2));
        assert_eq!(value["detailErased"], json!(true));
        assert_eq!(value["editable"], json!(false));
        assert_eq!(value["effectDigest"], json!("sha256:effect"));
        assert_eq!(value["submitterReference"], json!("owner-ref"));
        assert_eq!(value["applierReference"], json!("applier-ref"));
        assert!(value.get("actions").is_none());
        assert!(value.get("snapshot").is_none());
        assert!(value.get("before").is_none());
        assert!(value.get("after").is_none());
    }

    #[test]
    fn erased_terminal_metadata_keeps_application_reason_presence_without_text() {
        let value = erased_terminal_request_metadata(
            &crate::request_store::RequestWorkflowHeader {
                owner_reference: "owner-ref".to_owned(),
                state: "applied".to_owned(),
                proposal_version: 2,
                workflow_revision: 9,
                current_proposal_erased: true,
                applier_reference: Some("applier-ref".to_owned()),
                application_reason_present: true,
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
            true,
        );
        assert_eq!(
            value["application"],
            json!({
                "applicationId": "00000000-0000-4000-8000-0000000000aa",
                "proposalVersion": 2,
                "reasonPresent": true,
            })
        );
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
                applier_reference: Some("applier-ref".to_owned()),
                application_reason_present: false,
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
            false,
        );
        assert_eq!(value["bregState"], json!("applied"));
        assert!(value.get("effectDigest").is_none());
        assert!(value.get("actions").is_none());
        assert!(value.get("snapshot").is_none());
    }

    #[test]
    fn action_href_preserves_selected_access_profile() {
        let request = request_for_profile("editor-profile");
        let action = action(Operation::ReviseRequest);
        assert_eq!(
            action_href(&action, &request, "00000000-0000-4000-8000-000000000001"),
            "/requests/00000000-0000-4000-8000-000000000001/action?accessProfile=editor-profile"
        );
    }

    fn action(operation: Operation) -> VerifiedRequestAction {
        VerifiedRequestAction::new(
            "records.request.action".to_owned(),
            HttpMethod::Post,
            "/requests/{record_id}/action".to_owned(),
            operation,
            BTreeSet::new(),
            crate::api::VerifiedRequestActionAuthority::new(Vec::new()),
        )
    }

    fn submitted_workflow() -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(
                EntityId::new("request").expect("entity id"),
                RecordId::new("00000000-0000-4000-8000-000000000001").expect("record id"),
            ),
            actor("owner-ref"),
            StateRevision::new(1).expect("state revision"),
        )
        .submit(context("owner-ref", 1), proposal())
        .expect("submit succeeds")
        .into_workflow()
    }

    fn proposal() -> PreparedProposal {
        PreparedProposal::new_with_binding(
            RecordRevision::new(1).expect("record revision"),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            CompiledChangeRequestReview::None(CompiledChangeRequestNoReview {
                mode: CompiledChangeRequestNoReviewMode::None,
            }),
            FrozenPlanningBinding::new(
                FrozenPlannerKind::Declarative,
                "registry.change-request-plan/v1",
                None,
            )
            .expect("planning binding"),
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
            representation: crate::cursor::CursorRepresentation::Json,
            adapter: crate::cursor::CursorAdapter::Native,
            adapter_origin: None,
            geojson_next_link_prefix: None,
            kind: RecordReadKind::Get {
                id: "00000000-0000-4000-8000-000000000001".to_owned(),
            },
            maximum_records: 1,
            request_history_after_proposal_version: None,
            correlation: RequestCorrelation::breg_created(),
        }
    }
}
