// SPDX-License-Identifier: Apache-2.0

//! Fixed effect preparation, independent of HTTP payloads and database writes.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::contract::Operation;
use crate::data::{validate_field_value, FieldValue as DataFieldValue};
use crate::model::{
    CompiledChangeRequestApplicationMode, CompiledChangeRequestDisposition,
    CompiledChangeRequestMutation, CompiledChangeRequestReviewMode,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledEntity,
    CompiledRegistry,
};
use crate::mutation::MutationError;
use crate::request_workflow::{
    ContractFingerprint, EffectId, EntityId, FieldId, FieldValue, FrozenPlannerDisposition,
    FrozenPlannerKind, FrozenPlanningBinding, FrozenQueueReason, FrozenReviewPolicy,
    PackageFingerprint, PreparedEffect, PreparedFieldChange, PreparedProposal, PreparedTarget,
    ProposalDigest, RecordId, RecordRevision, MAX_REQUEST_SNAPSHOT_BYTES,
};
use crate::rhai_planner::{
    CandidateChangeRequestEffect, CandidateChangeRequestMutation,
    CandidateChangeRequestTargetBinding, CandidateChangeRequestValue, CompiledEffectPlanCandidate,
};

/// IDs are resolved once per submission attempt and retained through bounded
/// transaction retries. Only configured create effects reserve new identities.
pub(crate) struct ResolvedRequestTargets {
    pub candidate: CompiledEffectPlanCandidate,
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
    registry: &CompiledRegistry,
    request_entity: &CompiledEntity,
    intake: &Map<String, Value>,
    mut candidate: CompiledEffectPlanCandidate,
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
    canonicalize_candidate_order(&mut candidate.effects)?;
    verify_candidate(registry, request_entity, intake, &candidate)?;
    for effect in &candidate.effects {
        let record = match &effect.target.binding {
            CandidateChangeRequestTargetBinding::Existing { from_field } => {
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
            CandidateChangeRequestTargetBinding::ReservedCreate { .. } => *reserved_create_ids
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
        candidate,
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
    for effect in &resolved.candidate.effects {
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
                CandidateChangeRequestMutation::Set { field, .. }
                | CandidateChangeRequestMutation::Clear { field } => field,
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
                CandidateChangeRequestMutation::Set { value, .. } => {
                    let value = match value {
                        CandidateChangeRequestValue::FromRequestField { field } => intake
                            .get(field)
                            .filter(|value| !value.is_null())
                            .cloned()
                            .ok_or(MutationError::InvalidRequest)?,
                        CandidateChangeRequestValue::FromEffect {
                            effect,
                            target_entity_id,
                        } => {
                            let source_effect = resolved
                                .candidate
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
                        CandidateChangeRequestValue::Literal(value) => value.clone(),
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
                CandidateChangeRequestMutation::Clear { .. } => {
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
    let planning = frozen_planning_binding(&resolved.candidate)?;
    let review = match plan.review_mode {
        CompiledChangeRequestReviewMode::None => FrozenReviewPolicy::None,
        CompiledChangeRequestReviewMode::Stages => FrozenReviewPolicy::Stages,
    };
    let proposal = workflow(PreparedProposal::new_with_binding(
        workflow(RecordRevision::new(request_record_revision))?,
        workflow(ContractFingerprint::new(&plan.contract_fingerprint))?,
        workflow(PackageFingerprint::new(package_fingerprint))?,
        review,
        planning,
        plan.stages.clone(),
        effects,
        bytes,
    ))?;
    Ok(PreparedRequest {
        proposal,
        targets: snapshots.into_values().collect(),
    })
}

fn verify_candidate(
    registry: &CompiledRegistry,
    request_entity: &CompiledEntity,
    intake: &Map<String, Value>,
    candidate: &CompiledEffectPlanCandidate,
) -> Result<(), MutationError> {
    let plan = request_entity
        .change_request
        .as_ref()
        .ok_or(MutationError::InvalidRequest)?;
    if candidate.effects.is_empty()
        || candidate.effects.len() > usize::from(plan.maximum_targets)
        || candidate
            .effects
            .iter()
            .map(|effect| effect.mutations.len())
            .sum::<usize>()
            > usize::from(plan.maximum_field_mutations)
    {
        return Err(MutationError::InvalidRequest);
    }
    match plan.application.mode {
        CompiledChangeRequestApplicationMode::Manual
            if candidate.disposition != CompiledChangeRequestDisposition::Queue =>
        {
            return Err(MutationError::InvalidRequest);
        }
        CompiledChangeRequestApplicationMode::Automatic
            if candidate.disposition != CompiledChangeRequestDisposition::Apply =>
        {
            return Err(MutationError::InvalidRequest);
        }
        CompiledChangeRequestApplicationMode::Planner
            if !plan
                .application
                .allowed_dispositions
                .contains(&candidate.disposition) =>
        {
            return Err(MutationError::InvalidRequest);
        }
        _ => {}
    }
    match (&candidate.disposition, &candidate.queue_reason) {
        (CompiledChangeRequestDisposition::Apply, None) => {}
        (CompiledChangeRequestDisposition::Queue, None)
            if plan.application.mode == CompiledChangeRequestApplicationMode::Manual => {}
        (CompiledChangeRequestDisposition::Queue, Some(reason))
            if plan.application.queue_reasons.get(&reason.code) == Some(&reason.label) => {}
        _ => return Err(MutationError::InvalidRequest),
    }
    let binding = &candidate.planner_binding;
    if binding.abi_identifier != crate::contract::CHANGE_REQUEST_PLAN_ABI_V1 {
        return Err(MutationError::InvalidRequest);
    }
    match (&plan.planner, binding.kind, &binding.script_sha256) {
        (None, "declarative", None) => {
            verify_declarative_effects(plan, intake, &candidate.effects)?
        }
        (Some(planner), "rhai", Some(script))
            if script == &planner.script_sha256 && binding.abi_identifier == planner.abi =>
        {
            for effect in &candidate.effects {
                verify_planner_ceiling(registry, planner, effect)?;
            }
        }
        _ => return Err(MutationError::InvalidRequest),
    }
    let mut ids = BTreeSet::new();
    for effect in &candidate.effects {
        workflow(EffectId::new(&effect.id))?;
        let referenced_effects = effect
            .mutations
            .iter()
            .filter_map(|mutation| match mutation {
                CandidateChangeRequestMutation::Set {
                    value: CandidateChangeRequestValue::FromEffect { effect, .. },
                    ..
                } => Some(effect.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if !ids.insert(effect.id.as_str())
            || effect
                .depends_on
                .iter()
                .any(|dependency| dependency == &effect.id)
            || effect.depends_on != referenced_effects
        {
            return Err(MutationError::InvalidRequest);
        }
    }
    if candidate
        .effects
        .iter()
        .flat_map(|effect| &effect.depends_on)
        .any(|dependency| !ids.contains(dependency.as_str()))
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

fn canonicalize_candidate_order(
    effects: &mut Vec<CandidateChangeRequestEffect>,
) -> Result<(), MutationError> {
    let mut remaining = BTreeMap::new();
    for effect in effects.drain(..) {
        if remaining.insert(effect.id.clone(), effect).is_some() {
            return Err(MutationError::InvalidRequest);
        }
    }
    let all_ids = remaining.keys().cloned().collect::<BTreeSet<_>>();
    if remaining.values().any(|effect| {
        effect.depends_on.contains(&effect.id)
            || effect
                .depends_on
                .iter()
                .any(|dependency| !all_ids.contains(dependency))
    }) {
        return Err(MutationError::InvalidRequest);
    }
    let mut emitted = BTreeSet::new();
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .filter(|(_, effect)| effect.depends_on.is_subset(&emitted))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(MutationError::InvalidRequest);
        }
        for id in ready {
            let effect = remaining.remove(&id).ok_or(MutationError::InvalidRequest)?;
            emitted.insert(id);
            effects.push(effect);
        }
    }
    Ok(())
}

fn verify_declarative_effects(
    plan: &crate::model::CompiledChangeRequest,
    _intake: &Map<String, Value>,
    effects: &[CandidateChangeRequestEffect],
) -> Result<(), MutationError> {
    if effects.len() != plan.effects.len() {
        return Err(MutationError::InvalidRequest);
    }
    for candidate in effects {
        let compiled = plan
            .effects
            .iter()
            .find(|effect| effect.id == candidate.id)
            .ok_or(MutationError::InvalidRequest)?;
        if compiled.operation != candidate.operation
            || compiled.target.entity_id != candidate.target.entity_id
            || !same_target_binding(&compiled.target.binding, &candidate.target.binding)
            || compiled.depends_on != candidate.depends_on
            || compiled.mutations.len() != candidate.mutations.len()
        {
            return Err(MutationError::InvalidRequest);
        }
        for (compiled, candidate) in compiled.mutations.iter().zip(&candidate.mutations) {
            match (compiled, candidate) {
                (
                    CompiledChangeRequestMutation::Clear { field: expected },
                    CandidateChangeRequestMutation::Clear { field },
                ) if expected == field => {}
                (
                    CompiledChangeRequestMutation::Set {
                        field: expected,
                        value: CompiledChangeRequestValue::FromField { field: source },
                    },
                    CandidateChangeRequestMutation::Set { field, value },
                ) if expected == field
                    && matches!(value, CandidateChangeRequestValue::FromRequestField { field } if field == source) =>
                    {}
                (
                    CompiledChangeRequestMutation::Set {
                        field: expected,
                        value:
                            CompiledChangeRequestValue::FromEffect {
                                effect: expected_effect,
                                target_entity_id: expected_entity,
                            },
                    },
                    CandidateChangeRequestMutation::Set {
                        field,
                        value:
                            CandidateChangeRequestValue::FromEffect {
                                effect,
                                target_entity_id,
                            },
                    },
                ) if expected == field
                    && expected_effect == effect
                    && expected_entity == target_entity_id => {}
                _ => return Err(MutationError::InvalidRequest),
            }
        }
    }
    Ok(())
}

fn same_target_binding(
    compiled: &CompiledChangeRequestTargetBinding,
    candidate: &CandidateChangeRequestTargetBinding,
) -> bool {
    matches!(
        (compiled, candidate),
        (
            CompiledChangeRequestTargetBinding::Existing { from_field: left },
            CandidateChangeRequestTargetBinding::Existing { from_field: right },
        ) if left == right
    ) || matches!(
        (compiled, candidate),
        (
            CompiledChangeRequestTargetBinding::ReservedCreate { effect: left },
            CandidateChangeRequestTargetBinding::ReservedCreate { effect: right },
        ) if left == right
    )
}

fn verify_planner_ceiling(
    registry: &CompiledRegistry,
    planner: &crate::model::CompiledChangeRequestPlanner,
    effect: &CandidateChangeRequestEffect,
) -> Result<(), MutationError> {
    let from_field = match &effect.target.binding {
        CandidateChangeRequestTargetBinding::Existing { from_field } => Some(from_field.as_str()),
        CandidateChangeRequestTargetBinding::ReservedCreate { effect: binding }
            if binding == &effect.id =>
        {
            None
        }
        _ => return Err(MutationError::InvalidRequest),
    };
    let ceiling = planner
        .writes
        .iter()
        .find(|write| {
            write.target_entity_id == effect.target.entity_id
                && write.operation == effect.operation
                && write.target_from_field.as_deref() == from_field
        })
        .ok_or(MutationError::InvalidRequest)?;
    let mut fields = BTreeSet::new();
    let target_entity = registry
        .entities()
        .get(&effect.target.entity_id)
        .ok_or(MutationError::InvalidRequest)?;
    for mutation in &effect.mutations {
        let field = match mutation {
            CandidateChangeRequestMutation::Set { field, .. }
            | CandidateChangeRequestMutation::Clear { field } => field,
        };
        if !ceiling.fields.contains(field) || !fields.insert(field) {
            return Err(MutationError::InvalidRequest);
        }
        let target_field = target_entity
            .fields
            .get(field)
            .ok_or(MutationError::InvalidRequest)?;
        if let CandidateChangeRequestMutation::Set { field, value } = mutation {
            let reference_sources = ceiling.reference_sources.get(field);
            match value {
                CandidateChangeRequestValue::Literal(value)
                    if reference_sources.is_none()
                        && !value.is_null()
                        && validate_field_value(
                            DataFieldValue::Json(value),
                            &target_field.field_type,
                        ) => {}
                CandidateChangeRequestValue::Literal(_) => {
                    return Err(MutationError::InvalidRequest);
                }
                CandidateChangeRequestValue::FromRequestField { field: source } => {
                    if !reference_sources
                        .is_some_and(|sources| sources.request_fields.contains(source))
                    {
                        return Err(MutationError::InvalidRequest);
                    }
                }
                CandidateChangeRequestValue::FromEffect {
                    target_entity_id, ..
                } => {
                    if !reference_sources
                        .is_some_and(|sources| sources.create_entities.contains(target_entity_id))
                    {
                        return Err(MutationError::InvalidRequest);
                    }
                }
            }
        } else if target_field.required {
            return Err(MutationError::InvalidRequest);
        }
    }
    Ok(())
}

fn frozen_planning_binding(
    candidate: &CompiledEffectPlanCandidate,
) -> Result<FrozenPlanningBinding, MutationError> {
    let kind = match candidate.planner_binding.kind {
        "declarative" => FrozenPlannerKind::Declarative,
        "rhai" => FrozenPlannerKind::Rhai,
        _ => return Err(MutationError::InvalidRequest),
    };
    let abi = candidate.planner_binding.abi_identifier.as_str();
    let script = candidate
        .planner_binding
        .script_sha256
        .as_ref()
        .map(|digest| workflow(ProposalDigest::new(digest)))
        .transpose()?;
    let disposition = match candidate.disposition {
        CompiledChangeRequestDisposition::Apply => FrozenPlannerDisposition::Apply,
        CompiledChangeRequestDisposition::Queue => FrozenPlannerDisposition::Queue,
    };
    let queue_reason = candidate
        .queue_reason
        .as_ref()
        .map(|reason| workflow(FrozenQueueReason::new(&reason.code, &reason.label)))
        .transpose()?;
    workflow(FrozenPlanningBinding::new(
        kind,
        abi,
        script,
        disposition,
        queue_reason,
    ))
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
