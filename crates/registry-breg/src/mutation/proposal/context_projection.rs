// SPDX-License-Identifier: Apache-2.0
//! Governed Review display over frozen inputs/changes and current disclosure.
use super::*;
use crate::api::proposals::ProposalRecordReadAuthority;
use crate::contract::ProposalContextValueSource;
use crate::proposal_workflow::ProposalSnapshot;

pub(super) async fn fields(
    tx: &Transaction<'_>,
    registry: &CompiledRegistry,
    document: &ProposalDocument,
    authority: &ProposalAuthority,
    records: &BTreeMap<String, ProposalRecordReadAuthority>,
    frozen: &ProposalSnapshot,
    selected_fields: Option<&BTreeSet<String>>,
) -> Result<Map<String, Value>, MutationError> {
    let action = proposal_action(registry, &document.action_id)?;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(MutationError::PreconditionFailed);
    };
    let mapping = proposal
        .review_context
        .as_ref()
        .ok_or(MutationError::PreconditionFailed)?;
    let permission = proposal
        .permissions
        .iter()
        .find(|permission| {
            permission.profile_id == authority.common.access_profile()
                && permission.operations.contains(&match authority.operation {
                    ProposalAuthorityOperation::Lifecycle(operation) => operation,
                    ProposalAuthorityOperation::Start => return false,
                })
        })
        .ok_or(MutationError::PreconditionFailed)?;
    let document_contract = if mapping
        .fields
        .iter()
        .filter(|(field, _)| selected_fields.is_none_or(|selected| selected.contains(*field)))
        .map(|(_, source)| source)
        .any(|source| matches!(source, ProposalContextValueSource::Document { .. }))
    {
        Some(
            crate::compiler::review_context::compile_schema(registry, action)
                .map_err(|_| MutationError::Unavailable)?
                .ok_or(MutationError::PreconditionFailed)?,
        )
    } else {
        None
    };
    frozen
        .verify_digest(&crate::proposal_workflow::ProposalKey::new(
            EntityId::new(&document.action_id).map_err(workflow_error)?,
            RecordId::new(document.proposal_id.to_string()).map_err(workflow_error)?,
        ))
        .map_err(workflow_error)?;
    if frozen.version().get() as i64 != document.header.submission_version
        || frozen.contract_fingerprint().as_str() != document.action_revision
    {
        return Err(MutationError::PreconditionFailed);
    }
    let targets = if mapping
        .fields
        .iter()
        .filter(|(field, _)| selected_fields.is_none_or(|selected| selected.contains(*field)))
        .map(|(_, source)| source)
        .any(|source| matches!(source, ProposalContextValueSource::Changes { .. }))
    {
        frozen
            .verify_digest(&crate::proposal_workflow::ProposalKey::new(
                EntityId::new(&document.action_id).map_err(workflow_error)?,
                RecordId::new(document.proposal_id.to_string()).map_err(workflow_error)?,
            ))
            .map_err(workflow_error)?;
        let targets = proposal_store::load_targets(
            tx,
            &document.action_id,
            document.proposal_id,
            i64::from(frozen.version().get()),
        )
        .await?;
        proposal_prepare::validate_frozen_targets(frozen, &targets)?;
        targets
    } else {
        Vec::new()
    };
    let mut projected = Map::new();
    for (field, source) in &mapping.fields {
        if selected_fields.is_some_and(|selected| !selected.contains(field)) {
            continue;
        }
        if !permission.readable_context_fields.contains(field) {
            return Err(MutationError::PreconditionFailed);
        }
        let resolved = match source {
            ProposalContextValueSource::Document { slot } => {
                let definition = proposal
                    .attachments
                    .get(slot)
                    .ok_or(MutationError::PreconditionFailed)?;
                if let Some(manifest) = frozen.attachments().get(slot) {
                    crate::attachment_store::require_frozen_reference(
                        tx,
                        &document.action_id,
                        document.proposal_id,
                        document.header.submission_version,
                        slot,
                        manifest,
                    )
                    .await?;
                    let schema = document_contract
                        .as_ref()
                        .ok_or(MutationError::PreconditionFailed)?;
                    let path = format!("/v1/proposals/{}/attachments/{}?submissionVersion={}&reviewContextField={}&effectDigest={}&contextSchemaDigest={}",
                        document.proposal_id, slot, frozen.version().get(), field,
                        frozen.effect_digest().as_str().replace(':', "%3A"), schema.digest.replace(':', "%3A"));
                    json!({"type":"document","slotId":slot,"sha256":manifest.sha256,
                        "contentType":manifest.content_type,"byteSize":manifest.byte_size,
                        "download":{"method":"GET","operation":"get-review-context",
                            "accessProfile":authority.common.access_profile(),"path":path}})
                } else if !definition.required {
                    Value::Null
                } else {
                    return Err(MutationError::PreconditionFailed);
                }
            }
            ProposalContextValueSource::Input { input } => match frozen.inputs().get(input) {
                Some(value) => value.clone(),
                None => absent_input(action, input)?,
            },
            ProposalContextValueSource::Record { input, field } => {
                let declared = action
                    .inputs
                    .iter()
                    .find(|declared| declared.id == *input)
                    .ok_or(MutationError::PreconditionFailed)?;
                let crate::contract::FieldTypeSource::Reference { target, .. } =
                    &declared.field_type
                else {
                    return Err(MutationError::PreconditionFailed);
                };
                let entity = registry
                    .entities()
                    .get(target)
                    .ok_or(MutationError::PreconditionFailed)?;
                let record = records
                    .get(target)
                    .ok_or(MutationError::PreconditionFailed)?;
                require_fields(record, std::slice::from_ref(field))?;
                install_disclosure(tx, record).await?;
                match frozen.inputs().get(input) {
                    // An omitted optional reference names no Record, and the
                    // compiler declares this context field nullable for it.
                    None => absent_input(action, input)?,
                    Some(Value::Null) if !declared.required => Value::Null,
                    Some(reference) => {
                        let id = reference
                            .as_str()
                            .and_then(|id| Uuid::parse_str(id).ok())
                            .ok_or(MutationError::PreconditionFailed)?;
                        let row = load_proposal_row(tx, entity, id, false).await?;
                        if !authority
                            .authorizes_snapshot(entity, id, &row.data)
                            .map_err(|_| MutationError::PreconditionFailed)?
                        {
                            return Err(MutationError::PreconditionFailed);
                        }
                        let optional = !entity
                            .fields
                            .get(field)
                            .ok_or(MutationError::PreconditionFailed)?
                            .required;
                        match row.data.get(field) {
                            Some(value) => value.clone(),
                            None if optional => Value::Null,
                            None => return Err(MutationError::PreconditionFailed),
                        }
                    }
                }
            }
            ProposalContextValueSource::Changes {
                record_type,
                fields,
            } => {
                let entity = registry
                    .entities()
                    .get(record_type)
                    .ok_or(MutationError::PreconditionFailed)?;
                let record = records
                    .get(record_type)
                    .ok_or(MutationError::PreconditionFailed)?;
                require_fields(record, fields)?;
                install_disclosure(tx, record).await?;
                let mut changes = Vec::new();
                for target in targets
                    .iter()
                    .filter(|target| target.entity_id == *record_type)
                {
                    // Existing targets also require current ordinary Record
                    // visibility. A moved or erased row cannot disclose its
                    // formerly visible values through a retained Proposal.
                    if target.operation == Operation::Patch || document.header.state == "applied" {
                        let row = load_proposal_row(tx, entity, target.record_id, false).await?;
                        require_snapshot(
                            tx,
                            entity,
                            record,
                            authority,
                            target.record_id,
                            &row.data,
                        )
                        .await?;
                    }
                    if let Some(before) = &target.before {
                        require_snapshot(tx, entity, record, authority, target.record_id, before)
                            .await?;
                    }
                    require_snapshot(
                        tx,
                        entity,
                        record,
                        authority,
                        target.record_id,
                        &target.after,
                    )
                    .await?;
                    changes.push(json!({
                        "recordId":target.record_id,"operation":target.operation,
                        "before":target.before.as_ref().map(|before| select(before, fields)),
                        "after":select(&target.after, fields),
                    }));
                }
                Value::Array(changes)
            }
        };
        projected.insert(field.clone(), resolved);
    }
    Ok(projected)
}

/// Prepare refuses a submission that omits a required input, so the frozen
/// inputs omit only optional ones, which the compiler declares nullable. A
/// required input missing here is a retained submission that no longer
/// matches its Action: an integrity failure for the operator, not a refusal
/// the caller caused.
fn absent_input(action: &CompiledAction, input: &str) -> Result<Value, MutationError> {
    match action.inputs.iter().find(|declared| declared.id == input) {
        Some(declared) if !declared.required => Ok(Value::Null),
        Some(_) => Err(MutationError::Unavailable),
        None => Err(MutationError::PreconditionFailed),
    }
}

fn require_fields(
    record: &ProposalRecordReadAuthority,
    fields: &[String],
) -> Result<(), MutationError> {
    if fields.iter().all(|field| record.fields.contains(field)) {
        Ok(())
    } else {
        Err(MutationError::PreconditionFailed)
    }
}

async fn install_disclosure(
    tx: &Transaction<'_>,
    record: &ProposalRecordReadAuthority,
) -> Result<(), MutationError> {
    record
        .context
        .install_row_boundaries(tx)
        .await
        .map_err(|_| MutationError::PreconditionFailed)?;
    let recipients = serde_json::to_string(record.context.recipients())
        .map_err(|_| MutationError::Unavailable)?;
    // The Proposal's target grant admits inspection, but must not become a
    // permissive alternative to ordinary Record membership or consent.
    tx.execute("SELECT set_config('registry.proposal_target_context','',true), set_config('registry.recipients',$1,true)", &[&recipients]).await.map_err(map_database_error)?;
    Ok(())
}

async fn require_snapshot(
    tx: &Transaction<'_>,
    entity: &CompiledEntity,
    record: &ProposalRecordReadAuthority,
    authority: &ProposalAuthority,
    id: Uuid,
    snapshot: &Map<String, Value>,
) -> Result<(), MutationError> {
    if !authority
        .authorizes_snapshot(entity, id, snapshot)
        .map_err(|_| MutationError::PreconditionFailed)?
        || !record
            .context
            .authorizes_record_snapshot(entity, snapshot, id)
            .map_err(|_| MutationError::PreconditionFailed)?
    {
        return Err(MutationError::PreconditionFailed);
    }
    // Reuse the same generated invoker probes as ordinary reads. Prospective
    // creates have no current table row; their selected values still require
    // today's membership and consent for the snapshot's exact subjects.
    for probe in crate::membership::row_probes(entity, record.context.access_profile()) {
        let key = if probe.field == "id" {
            id
        } else {
            snapshot
                .get(&probe.field)
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(MutationError::PreconditionFailed)?
        };
        let sql = format!("SELECT {}", probe.sql("$1::uuid"));
        if tx
            .query_one(&sql, &[&key])
            .await
            .map_err(map_database_error)?
            .get::<_, Option<bool>>(0)
            != Some(true)
        {
            return Err(MutationError::PreconditionFailed);
        }
    }
    Ok(())
}

fn select(snapshot: &Map<String, Value>, fields: &[String]) -> Map<String, Value> {
    fields
        .iter()
        .map(|field| {
            (
                field.clone(),
                snapshot.get(field).cloned().unwrap_or(Value::Null),
            )
        })
        .collect()
}
