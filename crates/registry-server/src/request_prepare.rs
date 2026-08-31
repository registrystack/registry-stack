// SPDX-License-Identifier: Apache-2.0

//! Fixed effect preparation, independent of HTTP payloads and database writes.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::contract::Operation;
use crate::data::{validate_field_value, FieldValue as DataFieldValue};
use crate::model::{
    CompiledChangeRequestMutation, CompiledChangeRequestTargetBinding, CompiledChangeRequestValue,
    CompiledEntity, CompiledRegistry,
};
use crate::mutation::MutationError;
use crate::request_workflow::{
    ContractFingerprint, EffectId, EntityId, FieldId, FieldValue, PackageFingerprint,
    PreparedEffect, PreparedFieldChange, PreparedProposal, PreparedTarget, RecordId,
    RecordRevision, MAX_REQUEST_SNAPSHOT_BYTES,
};

/// IDs are resolved once per submission attempt and retained through bounded
/// transaction retries. Only configured create effects reserve new identities.
pub(crate) struct ResolvedRequestTargets {
    pub effect_records: BTreeMap<String, Uuid>,
    pub records: BTreeMap<(String, Uuid), Operation>,
}

pub(crate) struct RequestTargetSnapshot {
    pub entity_id: String,
    pub record_id: Uuid,
    pub operation: Operation,
    pub expected_revision: Option<i64>,
    pub before: Option<Map<String, Value>>,
    pub after: Map<String, Value>,
}

pub(crate) struct PreparedRequest {
    pub proposal: PreparedProposal,
    pub targets: Vec<RequestTargetSnapshot>,
}

pub(crate) fn resolve_targets(
    request_entity: &CompiledEntity,
    intake: &Map<String, Value>,
    reserved_create_ids: &BTreeMap<String, Uuid>,
) -> Result<ResolvedRequestTargets, MutationError> {
    let plan = request_entity
        .change_request
        .as_ref()
        .ok_or(MutationError::InvalidRequest)?;
    if canonical_size(intake)? > MAX_REQUEST_SNAPSHOT_BYTES {
        return Err(MutationError::InvalidRequest);
    }
    let mut effect_records = BTreeMap::new();
    let mut records = BTreeMap::new();
    for effect in &plan.effects {
        let record = match &effect.target.binding {
            CompiledChangeRequestTargetBinding::Existing { from_field } => {
                let text = intake
                    .get(from_field)
                    .and_then(Value::as_str)
                    .ok_or(MutationError::InvalidRequest)?;
                let record = Uuid::parse_str(text).map_err(|_| MutationError::InvalidRequest)?;
                if record.to_string() != text {
                    return Err(MutationError::InvalidRequest);
                }
                record
            }
            CompiledChangeRequestTargetBinding::ReservedCreate { .. } => *reserved_create_ids
                .get(&effect.id)
                .ok_or(MutationError::InvalidRequest)?,
        };
        effect_records.insert(effect.id.clone(), record);
        // A single logical target can have disjoint patch mappings. Conflicting
        // operations on an alias are refused before taking mutation locks.
        if let Some(previous) =
            records.insert((effect.target.entity_id.clone(), record), effect.operation)
        {
            if previous != effect.operation || effect.operation == Operation::Create {
                return Err(MutationError::InvalidRequest);
            }
        }
    }
    if records.len() > usize::from(plan.maximum_targets) {
        return Err(MutationError::InvalidRequest);
    }
    Ok(ResolvedRequestTargets {
        effect_records,
        records,
    })
}

/// `bases` contains only exact existing targets selected by `resolve_targets`.
/// The storage adapter is responsible for protected source reads; this function
/// validates values and produces one merged result per physical target.
pub(crate) fn prepare(
    registry: &CompiledRegistry,
    request_entity: &CompiledEntity,
    intake: &Map<String, Value>,
    request_record_revision: i64,
    package_fingerprint: &str,
    resolved: &ResolvedRequestTargets,
    bases: BTreeMap<(String, Uuid), (i64, Map<String, Value>)>,
) -> Result<PreparedRequest, MutationError> {
    let plan = request_entity
        .change_request
        .as_ref()
        .ok_or(MutationError::InvalidRequest)?;
    let expected_bases = resolved
        .records
        .iter()
        .filter_map(|(key, operation)| (*operation == Operation::Patch).then_some(key.clone()))
        .collect::<BTreeSet<_>>();
    if bases.keys().cloned().collect::<BTreeSet<_>>() != expected_bases {
        return Err(MutationError::PreconditionFailed);
    }
    let mut snapshots = BTreeMap::new();
    for ((entity_id, record_id), operation) in &resolved.records {
        let (expected_revision, before, after) = match operation {
            Operation::Create => (None, None, Map::new()),
            Operation::Patch => {
                let (revision, data) = &bases[&(entity_id.clone(), *record_id)];
                if *revision <= 0 {
                    return Err(MutationError::PreconditionFailed);
                }
                (Some(*revision), Some(data.clone()), data.clone())
            }
            _ => return Err(MutationError::InvalidRequest),
        };
        snapshots.insert(
            (entity_id.clone(), *record_id),
            RequestTargetSnapshot {
                entity_id: entity_id.clone(),
                record_id: *record_id,
                operation: *operation,
                expected_revision,
                before,
                after,
            },
        );
    }
    let mut effects = Vec::new();
    let mut changed = BTreeSet::new();
    for effect in &plan.effects {
        let record_id = *resolved
            .effect_records
            .get(&effect.id)
            .ok_or(MutationError::InvalidRequest)?;
        let key = (effect.target.entity_id.clone(), record_id);
        let snapshot = snapshots
            .get_mut(&key)
            .ok_or(MutationError::InvalidRequest)?;
        let target_entity = registry
            .entities()
            .get(&effect.target.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        let target = match snapshot.expected_revision {
            Some(revision) => PreparedTarget::existing(
                workflow(EntityId::new(&snapshot.entity_id))?,
                workflow(RecordId::new(record_id.to_string()))?,
                workflow(RecordRevision::new(revision))?,
            ),
            None => PreparedTarget::reserved_create(
                workflow(EntityId::new(&snapshot.entity_id))?,
                workflow(RecordId::new(record_id.to_string()))?,
            ),
        };
        let mut field_changes = Vec::new();
        for mutation in &effect.mutations {
            let field = match mutation {
                CompiledChangeRequestMutation::Set { field, .. }
                | CompiledChangeRequestMutation::Clear { field } => field,
            };
            if !changed.insert((key.clone(), field.clone())) {
                return Err(MutationError::InvalidRequest);
            }
            let before = snapshot
                .before
                .as_ref()
                .and_then(|data| data.get(field))
                .map_or(FieldValue::Missing, |value| {
                    FieldValue::present(value.clone())
                });
            let field_id = workflow(FieldId::new(field))?;
            let compiled_field = target_entity
                .fields
                .get(field)
                .ok_or(MutationError::InvalidRequest)?;
            let change = match mutation {
                CompiledChangeRequestMutation::Set { value, .. } => {
                    let value = match value {
                        CompiledChangeRequestValue::FromField { field } => intake
                            .get(field)
                            .filter(|value| !value.is_null())
                            .cloned()
                            .ok_or(MutationError::InvalidRequest)?,
                        CompiledChangeRequestValue::FromEffect {
                            effect,
                            target_entity_id,
                        } => {
                            let source_effect = plan
                                .effects
                                .iter()
                                .find(|candidate| {
                                    candidate.id == *effect
                                        && candidate.operation == Operation::Create
                                        && candidate.target.entity_id == *target_entity_id
                                })
                                .ok_or(MutationError::InvalidRequest)?;
                            Value::String(
                                resolved
                                    .effect_records
                                    .get(&source_effect.id)
                                    .ok_or(MutationError::InvalidRequest)?
                                    .to_string(),
                            )
                        }
                    };
                    if !validate_field_value(
                        DataFieldValue::Json(&value),
                        &compiled_field.field_type,
                    ) {
                        return Err(MutationError::InvalidRequest);
                    }
                    snapshot.after.insert(field.clone(), value.clone());
                    workflow(PreparedFieldChange::set(field_id, before, value))?
                }
                CompiledChangeRequestMutation::Clear { .. } => {
                    if compiled_field.required {
                        return Err(MutationError::InvalidRequest);
                    }
                    snapshot.after.insert(field.clone(), Value::Null);
                    PreparedFieldChange::clear(field_id, before)
                }
            };
            field_changes.push(change);
        }
        effects.push(workflow(PreparedEffect::new(
            workflow(EffectId::new(&effect.id))?,
            effect.operation,
            target,
            field_changes,
        ))?);
    }
    if changed.len() > usize::from(plan.maximum_field_mutations) {
        return Err(MutationError::InvalidRequest);
    }
    let mut bytes = canonical_size(intake)?;
    for snapshot in snapshots.values() {
        let entity = registry
            .entities()
            .get(&snapshot.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        for field in entity.fields.values() {
            if field.required && snapshot.after.get(&field.id).is_none_or(Value::is_null) {
                return Err(MutationError::InvalidRequest);
            }
        }
        bytes = bytes
            .checked_add(canonical_size(&snapshot.after)?)
            .and_then(|bytes| {
                bytes.checked_add(
                    snapshot
                        .before
                        .as_ref()
                        .map_or(0, |before| canonical_size(before).unwrap_or(usize::MAX)),
                )
            })
            .ok_or(MutationError::InvalidRequest)?;
    }
    bytes = bytes
        .checked_add(
            canonicalize_json(
                &serde_json::to_value(&effects).map_err(|_| MutationError::InvalidRequest)?,
            )
            .map_err(|_| MutationError::InvalidRequest)?
            .len(),
        )
        .ok_or(MutationError::InvalidRequest)?;
    if bytes > MAX_REQUEST_SNAPSHOT_BYTES {
        return Err(MutationError::InvalidRequest);
    }
    let proposal = workflow(PreparedProposal::new(
        workflow(RecordRevision::new(request_record_revision))?,
        workflow(ContractFingerprint::new(&plan.contract_fingerprint))?,
        workflow(PackageFingerprint::new(package_fingerprint))?,
        plan.stages.clone(),
        effects,
        bytes,
    ))?;
    Ok(PreparedRequest {
        proposal,
        targets: snapshots.into_values().collect(),
    })
}

fn canonical_size(data: &Map<String, Value>) -> Result<usize, MutationError> {
    canonicalize_json(&Value::Object(data.clone()))
        .map(|bytes| bytes.len())
        .map_err(|_| MutationError::InvalidRequest)
}

fn workflow<T>(
    value: Result<T, crate::request_workflow::WorkflowError>,
) -> Result<T, MutationError> {
    value.map_err(|_| MutationError::InvalidRequest)
}

pub(crate) fn validate_frozen_targets(
    proposal: &crate::request_workflow::ProposalSnapshot,
    targets: &[RequestTargetSnapshot],
) -> Result<(), MutationError> {
    use crate::request_workflow::FieldValue as FrozenValue;
    let mut seen = BTreeSet::new();
    for target in targets {
        if !seen.insert((target.entity_id.as_str(), target.record_id)) {
            return Err(MutationError::PreconditionFailed);
        }
        let mut after = target.before.clone().unwrap_or_default();
        let mut changes = BTreeSet::new();
        for effect in proposal.effects().iter().filter(|effect| {
            effect.target().entity_id().as_str() == target.entity_id
                && effect
                    .target()
                    .existing_record_id()
                    .or_else(|| effect.target().reserved_record_id())
                    .is_some_and(|id| id.as_str() == target.record_id.to_string())
        }) {
            if effect.operation() != target.operation
                || effect
                    .target()
                    .base_revision()
                    .map(|revision| revision.get())
                    != target.expected_revision
            {
                return Err(MutationError::PreconditionFailed);
            }
            for change in effect.field_changes() {
                if !changes.insert(change.field().as_str()) {
                    return Err(MutationError::PreconditionFailed);
                }
                let before = target
                    .before
                    .as_ref()
                    .and_then(|data| data.get(change.field().as_str()));
                let expected_before = match change.before() {
                    FrozenValue::Missing => None,
                    FrozenValue::Present { value } => Some(value),
                };
                if before != expected_before {
                    return Err(MutationError::PreconditionFailed);
                }
                after.insert(
                    change.field().as_str().to_owned(),
                    match change.after() {
                        FrozenValue::Missing => Value::Null,
                        FrozenValue::Present { value } => value.clone(),
                    },
                );
            }
        }
        if changes.is_empty() || after != target.after {
            return Err(MutationError::PreconditionFailed);
        }
    }
    let effect_targets = proposal
        .effects()
        .iter()
        .map(|effect| {
            let id = effect
                .target()
                .existing_record_id()
                .or_else(|| effect.target().reserved_record_id())
                .ok_or(MutationError::PreconditionFailed)?;
            Ok((
                effect.target().entity_id().as_str(),
                Uuid::parse_str(id.as_str()).map_err(|_| MutationError::PreconditionFailed)?,
            ))
        })
        .collect::<Result<BTreeSet<_>, MutationError>>()?;
    if seen != effect_targets {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
