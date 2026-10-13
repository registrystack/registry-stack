// SPDX-License-Identifier: Apache-2.0

//! Bind the one validated neutral plan into an immutable Proposal submission.

use std::collections::{BTreeMap, BTreeSet};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use uuid::Uuid;
use crate::contract::Operation;
use crate::data::{validate_field_value, FieldValue as DataFieldValue};
use crate::model::{CompiledAction, CompiledActionExecution, CompiledPlanEffect,
    CompiledPlanFunctionKind, CompiledPlanMutation, CompiledPlanTargetBinding,
    CompiledPlanValue, CompiledRegistry};
use crate::mutation::MutationError;
use crate::proposal_workflow::{ContractFingerprint, EffectId, EntityId, FieldId,
    FieldValue, FrozenApplicationPreconditions, FrozenGuardTargetSnapshot,
    FrozenPlannerKind, FrozenPlanningBinding, PackageFingerprint, PreparedEffect,
    PreparedFieldChange, PreparedProposal, PreparedTarget, ProposalDigest,
    RecordId, RecordRevision, MAX_PROPOSAL_SNAPSHOT_BYTES};

pub(crate) struct ResolvedProposalTargets {
    pub effects: Vec<CompiledPlanEffect>,
    pub effect_records: BTreeMap<String, Uuid>,
    pub records: BTreeMap<(String, Uuid), Operation>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProposalTargetSnapshot {
    pub entity_id: String,
    pub record_id: Uuid,
    pub operation: Operation,
    pub expected_revision: Option<i64>,
    pub before: Option<Map<String, Value>>,
    pub after: Map<String, Value>,
}

pub(crate) struct PreparedProposalPlan {
    pub proposal: PreparedProposal,
    pub targets: Vec<ProposalTargetSnapshot>,
}

/// The evaluator has already checked the plan ceiling and dependency DAG.
/// This binding pass checks concrete identities, aliases and storage bounds.
pub(crate) fn resolve_targets(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    input: &Map<String, Value>,
    effects: Vec<CompiledPlanEffect>,
    reserved_create_ids: &BTreeMap<String, Uuid>,
) -> Result<ResolvedProposalTargets, MutationError> {
    if !action.execution.is_proposal() || canonical_size(input)? > action.maximum_snapshot_bytes as usize {
        return Err(MutationError::InvalidRequest);
    }
    let mut effect_records = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut visited = BTreeSet::new();
    for effect in &effects {
        if !visited.insert(effect.id.clone())
            || effect.depends_on.iter().any(|dependency| !effect_records.contains_key(dependency))
            || !matches!(effect.operation, Operation::Create | Operation::Patch) {
            return Err(MutationError::InvalidRequest);
        }
        let entity = registry.entities().get(&effect.target.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        if effect.mutations.iter().any(|mutation| {
            let (CompiledPlanMutation::Set {field,..} | CompiledPlanMutation::Clear {field}) = mutation;
            entity.fields.get(field).is_none_or(|field| field.encryption.is_some())
        }) { return Err(MutationError::InvalidRequest); }
        let record = match (&effect.target.binding, effect.operation) {
            (CompiledPlanTargetBinding::Existing {input: reference}, Operation::Patch) => {
                let text = input.get(reference).and_then(Value::as_str)
                    .ok_or(MutationError::InvalidRequest)?;
                let id = Uuid::parse_str(text).map_err(|_| MutationError::InvalidRequest)?;
                if id.to_string() != text { return Err(MutationError::InvalidRequest); }
                id
            }
            (CompiledPlanTargetBinding::Create, Operation::Create) => *reserved_create_ids
                .get(&effect.id).ok_or(MutationError::InvalidRequest)?,
            _ => return Err(MutationError::InvalidRequest),
        };
        if let Some(previous) = records.insert((entity.id.clone(), record), effect.operation) {
            if previous != effect.operation || effect.operation == Operation::Create {
                return Err(MutationError::InvalidRequest);
            }
        }
        effect_records.insert(effect.id.clone(), record);
    }
    if effects.is_empty() || records.len() > usize::from(action.maximum_targets) {
        return Err(MutationError::InvalidRequest);
    }
    Ok(ResolvedProposalTargets {effects, effect_records, records})
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    input: &Map<String, Value>,
    input_revision: i64,
    package_fingerprint: &str,
    resolved: &ResolvedProposalTargets,
    bases: BTreeMap<(String, Uuid), (i64, Map<String, Value>)>,
    guard_bases: BTreeMap<String, (Uuid, i64, Map<String, Value>)>,
) -> Result<PreparedProposalPlan, MutationError> {
    let CompiledActionExecution::Proposal {proposal: policy} = &action.execution else {
        return Err(MutationError::InvalidRequest);
    };
    let expected_bases = resolved.records.iter().filter_map(|(key,operation)|
        (*operation == Operation::Patch).then_some(key.clone())).collect::<BTreeSet<_>>();
    if bases.keys().cloned().collect::<BTreeSet<_>>() != expected_bases {
        return Err(MutationError::PreconditionFailed);
    }
    let mut snapshots = BTreeMap::new();
    for ((entity_id, record_id),operation) in &resolved.records {
        let (expected_revision,before,after) = match operation {
            Operation::Create => (None,None,Map::new()),
            Operation::Patch => {
                let (revision,data) = bases.get(&(entity_id.clone(),*record_id))
                    .ok_or(MutationError::PreconditionFailed)?;
                if *revision <= 0 { return Err(MutationError::PreconditionFailed); }
                (Some(*revision),Some(data.clone()),data.clone())
            }
            _ => return Err(MutationError::InvalidRequest),
        };
        snapshots.insert((entity_id.clone(),*record_id), ProposalTargetSnapshot {
            entity_id:entity_id.clone(),record_id:*record_id,operation:*operation,
            expected_revision,before,after,
        });
    }
    let mut changed = BTreeSet::new();
    let mut effects = Vec::new();
    for effect in &resolved.effects {
        let record_id = *resolved.effect_records.get(&effect.id).ok_or(MutationError::InvalidRequest)?;
        let key = (effect.target.entity_id.clone(),record_id);
        let snapshot = snapshots.get_mut(&key).ok_or(MutationError::InvalidRequest)?;
        let entity = registry.entities().get(&snapshot.entity_id).ok_or(MutationError::InvalidRequest)?;
        let target = match snapshot.expected_revision {
            Some(revision) => PreparedTarget::existing(workflow(EntityId::new(&snapshot.entity_id))?,
                workflow(RecordId::new(record_id.to_string()))?,workflow(RecordRevision::new(revision))?),
            None => PreparedTarget::reserved_create(workflow(EntityId::new(&snapshot.entity_id))?,
                workflow(RecordId::new(record_id.to_string()))?),
        };
        let mut fields = Vec::new();
        for mutation in &effect.mutations {
            let (CompiledPlanMutation::Set {field,..} | CompiledPlanMutation::Clear {field}) = mutation;
            if !changed.insert((key.clone(),field.clone())) { return Err(MutationError::InvalidRequest); }
            let compiled = entity.fields.get(field).ok_or(MutationError::InvalidRequest)?;
            if compiled.encryption.is_some() { return Err(MutationError::InvalidRequest); }
            let before = snapshot.before.as_ref().and_then(|row| row.get(field))
                .map_or(FieldValue::Missing, |value| FieldValue::present(value.clone()));
            let field_id = workflow(FieldId::new(field))?;
            let change = match mutation {
                CompiledPlanMutation::Set {value,..} => {
                    let value = match value {
                        CompiledPlanValue::Literal {value} => value.clone(),
                        CompiledPlanValue::FromInput {input: id} => input.get(id)
                            .filter(|v| !v.is_null()).cloned().ok_or(MutationError::InvalidRequest)?,
                        CompiledPlanValue::FromEffect {effect: source,target_entity_id} => {
                            if !resolved.effects.iter().any(|e| e.id == *source
                                && e.operation == Operation::Create && e.target.entity_id == *target_entity_id) {
                                return Err(MutationError::InvalidRequest);
                            }
                            Value::String(resolved.effect_records.get(source)
                                .ok_or(MutationError::InvalidRequest)?.to_string())
                        }
                    };
                    if !validate_field_value(DataFieldValue::Json(&value),&compiled.field_type) {
                        return Err(MutationError::InvalidRequest);
                    }
                    snapshot.after.insert(field.clone(),value.clone());
                    workflow(PreparedFieldChange::set(field_id,before,value))?
                }
                CompiledPlanMutation::Clear {..} => {
                    if compiled.required { return Err(MutationError::InvalidRequest); }
                    snapshot.after.insert(field.clone(),Value::Null);
                    PreparedFieldChange::clear(field_id,before)
                }
            };
            fields.push(change);
        }
        effects.push(workflow(PreparedEffect::new(workflow(EffectId::new(&effect.id))?,
            effect.operation,target,fields))?.with_dependencies(effect.depends_on.clone()));
    }
    if changed.len() > usize::from(action.maximum_field_mutations) { return Err(MutationError::InvalidRequest); }
    let mut bytes = canonical_size(input)?;
    for target in snapshots.values() {
        let entity = registry.entities().get(&target.entity_id).ok_or(MutationError::InvalidRequest)?;
        if entity.fields.values().any(|field| field.required && target.after.get(&field.id).is_none_or(Value::is_null)) {
            return Err(MutationError::InvalidRequest);
        }
        bytes = bytes.checked_add(canonical_size(&target.after)?)
            .and_then(|size| size.checked_add(target.before.as_ref()
                .map_or(0,|before| canonical_size(before).unwrap_or(usize::MAX))))
            .ok_or(MutationError::InvalidRequest)?;
    }
    bytes = bytes.checked_add(canonicalize_json(&serde_json::to_value(&effects)
        .map_err(|_| MutationError::InvalidRequest)?).map_err(|_| MutationError::InvalidRequest)?.len())
        .ok_or(MutationError::InvalidRequest)?;
    if bytes > MAX_PROPOSAL_SNAPSHOT_BYTES || bytes > action.maximum_snapshot_bytes as usize {
        return Err(MutationError::InvalidRequest);
    }
    let (kind,abi,digest) = match &action.handler {
        None => (FrozenPlannerKind::Declarative,"registry.action-plan/v1",None),
        Some(function) if function.kind == CompiledPlanFunctionKind::Rhai => (
            FrozenPlannerKind::Rhai,function.abi.as_str(),
            Some(workflow(ProposalDigest::new(function.script_sha256.as_ref()
                .ok_or(MutationError::InvalidRequest)?))?),
        ),
        _ => return Err(MutationError::InvalidRequest),
    };
    let mut proposal = workflow(PreparedProposal::new_with_binding(
        workflow(RecordRevision::new(input_revision))?,
        workflow(ContractFingerprint::new(&action.definition_revision))?,
        workflow(PackageFingerprint::new(package_fingerprint))?,policy.review.clone(),
        workflow(FrozenPlanningBinding::new(kind,abi,digest))?,effects,bytes))?;
    proposal = workflow(proposal.with_application_policy(policy.application.clone()))?;
    if !action.requires.is_empty() {
        let expected = action.requires.iter().map(|guard| guard.input.as_str()).collect::<BTreeSet<_>>();
        if guard_bases.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
            return Err(MutationError::PreconditionFailed);
        }
        let mut targets = Vec::new();
        for id in expected {
            let (record_id,revision,data) = guard_bases.get(id).ok_or(MutationError::PreconditionFailed)?;
            let guards = action.requires.iter().filter(|g| g.input == id).collect::<Vec<_>>();
            let entity_id = &guards[0].entity_id;
            if guards.iter().any(|g| g.entity_id != *entity_id) { return Err(MutationError::InvalidRequest); }
            let values = guards.iter().filter(|g| !g.field.is_empty()).map(|guard| {
                data.get(&guard.field).cloned().map(|value| (guard.field.clone(),value))
                    .ok_or(MutationError::PreconditionFailed)
            }).collect::<Result<BTreeMap<_,_>,_>>()?;
            targets.push(FrozenGuardTargetSnapshot {id:id.to_owned(),entity_id:entity_id.clone(),
                record_id:workflow(RecordId::new(record_id.to_string()))?,expected_revision:*revision,values});
        }
        proposal = workflow(proposal.with_application_preconditions(FrozenApplicationPreconditions {
            contract:action.requires.clone(),input_values:input.clone().into_iter().collect(),targets,
        }))?;
    } else if !guard_bases.is_empty() { return Err(MutationError::InvalidRequest); }
    Ok(PreparedProposalPlan {proposal,targets:snapshots.into_values().collect()})
}

fn canonical_size(data: &Map<String,Value>) -> Result<usize,MutationError> {
    canonicalize_json(&Value::Object(data.clone())).map(|bytes| bytes.len())
        .map_err(|_| MutationError::InvalidRequest)
}
fn workflow<T>(value: Result<T,crate::proposal_workflow::WorkflowError>) -> Result<T,MutationError> {
    value.map_err(|_| MutationError::InvalidRequest)
}

pub(crate) fn validate_frozen_targets(
    proposal: &crate::proposal_workflow::ProposalSnapshot,
    targets: &[ProposalTargetSnapshot],
) -> Result<(), MutationError> {
    use crate::proposal_workflow::FieldValue as FrozenValue;
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
