// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::contract::{
    ChangeRequestEffectSource, ChangeRequestValueSource, Classification, EntitySource,
    FieldTypeSource, MutationMode, Operation, RowBoundarySource,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    ChangeRequestOperation, CompiledChangeRequest, CompiledChangeRequestActionRoute,
    CompiledChangeRequestApplyGrant, CompiledChangeRequestEffect, CompiledChangeRequestMutation,
    CompiledChangeRequestPresenceGrant, CompiledChangeRequestRetentionMode,
    CompiledChangeRequestReviewGrant, CompiledChangeRequestStage, CompiledChangeRequestTarget,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledEntity,
};

pub const MAX_CHANGE_REQUEST_TARGETS: u16 = 16;
pub const MAX_CHANGE_REQUEST_FIELD_MUTATIONS: u16 = 128;
pub const MAX_CHANGE_REQUEST_SNAPSHOT_BYTES: u32 = 2_097_152;
pub const MAX_CHANGE_REQUEST_REVIEW_STAGES: u16 = 32;

type CompiledEffectSet = (
    Vec<CompiledChangeRequestEffect>,
    BTreeMap<String, BTreeSet<String>>,
    BTreeSet<String>,
);

pub(crate) fn compile_change_requests(
    sources: &BTreeMap<String, EntitySource>,
    entities: &mut BTreeMap<String, CompiledEntity>,
) -> Result<(), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    validate_change_controlled_direct_writes(entities, &mut errors);
    let request_entity_ids = sources
        .iter()
        .filter_map(|(entity_id, source)| {
            source.change_request.is_some().then_some(entity_id.clone())
        })
        .collect::<BTreeSet<_>>();

    let mut compiled = BTreeMap::new();
    for (entity_id, source) in sources {
        if source.change_request.is_some() {
            if let Some(entity) = entities.get(entity_id) {
                if let Some(plan) = compile_request_entity(
                    source,
                    entity,
                    entities,
                    &request_entity_ids,
                    &mut errors,
                ) {
                    compiled.insert(entity_id.clone(), plan);
                }
            }
        }
    }
    compile_presence_grants(entities, &mut compiled, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }
    for (entity_id, plan) in compiled {
        if let Some(entity) = entities.get_mut(&entity_id) {
            entity.change_request = Some(plan);
        }
    }
    Ok(())
}

fn validate_change_controlled_direct_writes(
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        if let Some(control) = &entity.change_control {
            if control.required_for.is_empty() {
                errors.push(Diagnostic::error(
                    "change_control.required_for.empty",
                    "entities[].changeControl.requiredFor",
                    "change control must name at least one controlled mutation operation",
                ));
            }
            for operation in &control.required_for {
                if !is_mutation_operation(*operation) {
                    errors.push(Diagnostic::error(
                        "change_control.operation.unsupported",
                        "entities[].changeControl.requiredFor",
                        "change control can require only finite mutation operations",
                    ));
                }
            }
            for profile in entity.access_profiles.values() {
                let direct = control
                    .required_for
                    .iter()
                    .any(|operation| profile.operations.contains(operation))
                    || (profile.operations.contains(&Operation::Batch)
                        && control.required_for.iter().any(|operation| {
                            matches!(operation, Operation::Create | Operation::Patch)
                        }));
                if direct {
                    errors.push(Diagnostic::error(
                        "change_control.direct_write_grant",
                        "entities[].accessProfiles[].operations",
                        "a controlled mutation operation cannot remain directly granted",
                    ));
                }
            }
        }
    }
}

fn compile_request_entity(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    request_entity_ids: &BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequest> {
    let request = source.change_request.as_ref()?;
    if source.mutation_mode != MutationMode::Mutable {
        errors.push(Diagnostic::error(
            "change_request.mutation_mode.invalid",
            "entities[].changeRequest",
            "a change-request entity must be mutable so draft revisions can be edited",
        ));
    }
    if source.change_control.is_some() {
        errors.push(Diagnostic::error(
            "change_request.change_control_conflict",
            "entities[].changeControl",
            "a change-request entity cannot also declare target change control",
        ));
    }
    if request_entity
        .access_profiles
        .values()
        .any(|profile| profile.operations.contains(&Operation::Tombstone))
    {
        errors.push(Diagnostic::error(
            "change_request.tombstone_forbidden",
            "entities[].accessProfiles[].operations",
            "request entities use cancellation and cannot expose ordinary tombstone access",
        ));
    }
    if request.effects.is_empty() {
        errors.push(Diagnostic::error(
            "change_request.effects.empty",
            "entities[].changeRequest.effects",
            "a change-request capability must declare at least one effect",
        ));
    }
    if request.review.stages.is_empty() {
        errors.push(Diagnostic::error(
            "change_request.review.stages_empty",
            "entities[].changeRequest.review.stages",
            "a change-request capability must declare at least one review stage",
        ));
    }

    let stages = compile_stages(request, errors);
    let (effects, changed_fields, target_entities) = compile_effects(
        source,
        request_entity,
        entities,
        request_entity_ids,
        &request.effects,
        errors,
    )?;
    validate_plan_bounds(request_entity, entities, &effects, errors);
    let actions = compile_action_routes(&stages);
    let review_grants =
        compile_review_grants(request_entity, &stages, &changed_fields, entities, errors);
    let apply_grants = compile_apply_grants(request_entity, &target_entities, entities, errors);
    if !request_entity
        .access_profiles
        .values()
        .any(|profile| profile.operations.contains(&Operation::SubmitRequest))
    {
        errors.push(Diagnostic::error(
            "change_request.submit_operation.missing",
            "entities[].accessProfiles[].operations",
            "a change-request type requires at least one submit_request grant",
        ));
    }
    let contract_fingerprint = contract_fingerprint(
        request_entity,
        entities,
        &effects,
        &stages,
        &review_grants,
        &apply_grants,
        &target_entities,
    );

    Some(CompiledChangeRequest {
        request_entity_id: source.id.clone(),
        contract_fingerprint,
        retention_mode: compile_retention_mode(request.retention.mode),
        effects,
        stages,
        actions,
        review_grants,
        apply_grants,
        presence_grants: Vec::new(),
        target_entities,
        maximum_targets: MAX_CHANGE_REQUEST_TARGETS,
        maximum_field_mutations: MAX_CHANGE_REQUEST_FIELD_MUTATIONS,
        maximum_snapshot_bytes: MAX_CHANGE_REQUEST_SNAPSHOT_BYTES,
    })
}

fn compile_retention_mode(
    mode: crate::contract::ChangeRequestRetentionModeSource,
) -> CompiledChangeRequestRetentionMode {
    match mode {
        crate::contract::ChangeRequestRetentionModeSource::Retain => {
            CompiledChangeRequestRetentionMode::Retain
        }
        crate::contract::ChangeRequestRetentionModeSource::OperatorErase => {
            CompiledChangeRequestRetentionMode::OperatorErase
        }
    }
}

fn compile_stages(
    request: &crate::contract::ChangeRequestSource,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestStage> {
    if request.review.stages.len() > usize::from(MAX_CHANGE_REQUEST_REVIEW_STAGES) {
        errors.push(Diagnostic::error(
            "change_request.review.stage_count",
            "entities[].changeRequest.review.stages",
            "change-request review stages must stay within the supported finite bound",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut stages = Vec::new();
    for stage in &request.review.stages {
        validate_id(
            &stage.id,
            "entities[].changeRequest.review.stages[].id",
            errors,
        );
        if !ids.insert(stage.id.as_str()) {
            errors.push(Diagnostic::error(
                "change_request.review.stage.duplicate",
                "entities[].changeRequest.review.stages[].id",
                "review stage identifiers must be duplicate-free",
            ));
        }
        if stage.approvals == 0 || stage.approvals > 32 {
            errors.push(Diagnostic::error(
                "change_request.review.stage.approvals_invalid",
                "entities[].changeRequest.review.stages[].approvals",
                "review stage approval counts must be within the supported bounds",
            ));
        }
        stages.push(CompiledChangeRequestStage {
            id: stage.id.clone(),
            approvals: stage.approvals,
            exclude_submitter: stage.exclude_submitter,
        });
    }
    stages
}

fn compile_effects(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    request_entity_ids: &BTreeSet<String>,
    effect_sources: &[ChangeRequestEffectSource],
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledEffectSet> {
    let mut effect_ids = BTreeSet::new();
    let mut create_targets = BTreeMap::new();
    for (index, effect) in effect_sources.iter().enumerate() {
        let id = effect_id(effect, index);
        validate_id(&id, "entities[].changeRequest.effects[].id", errors);
        if !effect_ids.insert(id.clone()) {
            errors.push(Diagnostic::error(
                "change_request.effect.id_duplicate",
                "entities[].changeRequest.effects[].id",
                "change-request effect identifiers must be duplicate-free",
            ));
        }
        if effect.operation == Operation::Create {
            if effect.id.is_none() {
                errors.push(Diagnostic::error(
                    "change_request.effect.create_id_required",
                    "entities[].changeRequest.effects[].id",
                    "create effects require an explicit identifier for reserved-record references",
                ));
            }
            if let Some(entity_id) = &effect.target.entity {
                create_targets.insert(id, entity_id.clone());
            }
        }
    }

    let mut compiled_by_id = BTreeMap::new();
    let mut changed_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut target_entities = BTreeSet::new();
    let mut writes = BTreeMap::new();
    for (index, effect) in effect_sources.iter().enumerate() {
        let id = effect_id(effect, index);
        let Some(target) = compile_target(
            source,
            request_entity,
            entities,
            request_entity_ids,
            &id,
            effect,
            errors,
        ) else {
            continue;
        };
        let Some(target_entity) = entities.get(&target.entity_id) else {
            continue;
        };
        if effect.set.is_empty() && effect.clear.is_empty() {
            errors.push(Diagnostic::error(
                "change_request.effect.empty",
                "entities[].changeRequest.effects[]",
                "a change-request effect must set or clear at least one field",
            ));
        }
        let mut mutations = Vec::new();
        let mut depends_on = BTreeSet::new();
        for (field, value) in &effect.set {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.field_unknown",
                    "entities[].changeRequest.effects[].set",
                    "a change-request effect writes an unknown stored target field",
                ));
                continue;
            };
            if let Some(compiled) = compile_value(
                source,
                request_entity,
                field,
                &target_field.field_type,
                value,
                &create_targets,
                errors,
            ) {
                if let CompiledChangeRequestValue::FromEffect { effect, .. } = &compiled {
                    depends_on.insert(effect.clone());
                }
                mutations.push(CompiledChangeRequestMutation::Set {
                    field: field.clone(),
                    value: compiled,
                });
                remember_write(&mut writes, &target, field, &id, errors);
                changed_fields
                    .entry(target.entity_id.clone())
                    .or_default()
                    .insert(field.clone());
            }
        }
        for field in &effect.clear {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.field_unknown",
                    "entities[].changeRequest.effects[].clear",
                    "a change-request effect clears an unknown stored target field",
                ));
                continue;
            };
            if effect.operation == Operation::Create {
                errors.push(Diagnostic::error(
                    "change_request.effect.clear_on_create",
                    "entities[].changeRequest.effects[].clear",
                    "create effects cannot clear target fields",
                ));
            }
            if target_field.required {
                errors.push(Diagnostic::error(
                    "change_request.effect.clear_required",
                    "entities[].changeRequest.effects[].clear",
                    "required target fields cannot be cleared",
                ));
            }
            mutations.push(CompiledChangeRequestMutation::Clear {
                field: field.clone(),
            });
            remember_write(&mut writes, &target, field, &id, errors);
            changed_fields
                .entry(target.entity_id.clone())
                .or_default()
                .insert(field.clone());
        }
        target_entities.insert(target.entity_id.clone());
        compiled_by_id.insert(
            id.clone(),
            CompiledChangeRequestEffect {
                id,
                target,
                operation: effect.operation,
                mutations,
                depends_on,
            },
        );
    }

    let ordered = order_effects(compiled_by_id, errors)?;
    Some((ordered, changed_fields, target_entities))
}

fn compile_target(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    request_entity_ids: &BTreeSet<String>,
    id: &str,
    effect: &ChangeRequestEffectSource,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequestTarget> {
    if !exactly_one(
        effect.target.entity.as_ref(),
        effect.target.from_field.as_ref(),
    ) {
        errors.push(Diagnostic::error(
            "change_request.effect.target.invalid",
            "entities[].changeRequest.effects[].target",
            "effect target must name exactly one entity or request reference field",
        ));
        return None;
    }
    match effect.operation {
        Operation::Create => {
            let Some(entity_id) = &effect.target.entity else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target.invalid",
                    "entities[].changeRequest.effects[].target",
                    "create effects must target a declared entity for reserved identity",
                ));
                return None;
            };
            let Some(target_entity) = entities.get(entity_id) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_unknown",
                    "entities[].changeRequest.effects[].target.entity",
                    "a change-request effect targets an unknown entity",
                ));
                return None;
            };
            if request_entity_ids.contains(entity_id) {
                errors.push(Diagnostic::error(
                    "change_request.effect.nested_request_target",
                    "entities[].changeRequest.effects[].target.entity",
                    "change-request effects cannot target another change-request entity",
                ));
                return None;
            }
            if !is_change_controlled(target_entity, Operation::Create) {
                errors.push(Diagnostic::error(
                    "change_request.effect.uncontrolled_target",
                    "entities[].changeRequest.effects[].operation",
                    "a change-request effect can mutate only a target operation declared in changeControl.requiredFor",
                ));
            }
            Some(CompiledChangeRequestTarget {
                entity_id: entity_id.clone(),
                binding: CompiledChangeRequestTargetBinding::ReservedCreate {
                    effect: id.to_owned(),
                },
            })
        }
        Operation::Patch => {
            let Some(field_id) = &effect.target.from_field else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target.invalid",
                    "entities[].changeRequest.effects[].target.fromField",
                    "patch effects must target a request reference field",
                ));
                return None;
            };
            let Some(field) = request_entity.fields.get(field_id) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_field_unknown",
                    "entities[].changeRequest.effects[].target.fromField",
                    "effect target refers to an unknown request field",
                ));
                return None;
            };
            let FieldTypeSource::Reference { target, .. } = &field.field_type else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_field_type",
                    "entities[].changeRequest.effects[].target.fromField",
                    "patch effect targets must come from a typed request reference field",
                ));
                return None;
            };
            let target_entity = entities.get(target)?;
            if request_entity_ids.contains(target) {
                errors.push(Diagnostic::error(
                    "change_request.effect.nested_request_target",
                    "entities[].changeRequest.effects[].target.fromField",
                    "change-request effects cannot target another change-request entity",
                ));
                return None;
            }
            if target_entity.mutation_mode != MutationMode::Mutable {
                errors.push(Diagnostic::error(
                    "change_request.effect.operation_unavailable",
                    "entities[].changeRequest.effects[].operation",
                    "patch effects require a mutable target entity",
                ));
            }
            if !is_change_controlled(target_entity, Operation::Patch) {
                errors.push(Diagnostic::error(
                    "change_request.effect.uncontrolled_target",
                    "entities[].changeRequest.effects[].operation",
                    "a change-request effect can mutate only a target operation declared in changeControl.requiredFor",
                ));
            }
            Some(CompiledChangeRequestTarget {
                entity_id: target.clone(),
                binding: CompiledChangeRequestTargetBinding::Existing {
                    from_field: field_id.clone(),
                },
            })
        }
        _ => {
            let _ = (source, id);
            errors.push(Diagnostic::error(
                "change_request.effect.operation_unsupported",
                "entities[].changeRequest.effects[].operation",
                "change-request effects support only create and patch operations",
            ));
            None
        }
    }
}

fn compile_value(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    target_field: &str,
    target_type: &FieldTypeSource,
    value: &ChangeRequestValueSource,
    create_targets: &BTreeMap<String, String>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequestValue> {
    if !exactly_one(value.from_field.as_ref(), value.from_effect.as_ref()) {
        errors.push(Diagnostic::error(
            "change_request.effect.value.invalid",
            "entities[].changeRequest.effects[].set",
            "set values must name exactly one request field or create effect",
        ));
        return None;
    }
    if let Some(field_id) = &value.from_field {
        let Some(field) = request_entity.fields.get(field_id) else {
            errors.push(Diagnostic::error(
                "change_request.effect.value_field_unknown",
                "entities[].changeRequest.effects[].set",
                "set value refers to an unknown request field",
            ));
            return None;
        };
        if !field.required {
            errors.push(Diagnostic::error(
                "change_request.effect.value_nullable",
                "entities[].changeRequest.effects[].set",
                "mapped set values must come from required request fields so null cannot mean leave unchanged",
            ));
        }
        if !compatible_field_types(&field.field_type, target_type) {
            errors.push(Diagnostic::error(
                "change_request.effect.value_type_mismatch",
                "entities[].changeRequest.effects[].set",
                "mapped request field type is not compatible with the target field",
            ));
        }
        return Some(CompiledChangeRequestValue::FromField {
            field: field_id.clone(),
        });
    }
    let effect_id = value.from_effect.as_ref()?;
    let Some(target_entity_id) = create_targets.get(effect_id) else {
        errors.push(Diagnostic::error(
            "change_request.effect.value_effect_unknown",
            "entities[].changeRequest.effects[].set",
            "fromEffect must refer to a declared create effect",
        ));
        return None;
    };
    match target_type {
        FieldTypeSource::Reference { target, .. } if target == target_entity_id => {
            Some(CompiledChangeRequestValue::FromEffect {
                effect: effect_id.clone(),
                target_entity_id: target_entity_id.clone(),
            })
        }
        FieldTypeSource::Reference { .. } => {
            errors.push(Diagnostic::error(
                "change_request.effect.value_reference_mismatch",
                "entities[].changeRequest.effects[].set",
                "fromEffect reserved identity does not match the target reference field",
            ));
            None
        }
        _ => {
            let _ = (source, target_field);
            errors.push(Diagnostic::error(
                "change_request.effect.value_reference_required",
                "entities[].changeRequest.effects[].set",
                "fromEffect can populate only typed reference fields",
            ));
            None
        }
    }
}

fn remember_write(
    writes: &mut BTreeMap<(String, String), String>,
    target: &CompiledChangeRequestTarget,
    field: &str,
    effect_id: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let key = (target_binding_key(target), field.to_owned());
    if let Some(existing) = writes.insert(key, effect_id.to_owned()) {
        if existing != effect_id {
            errors.push(Diagnostic::error(
                "change_request.effect.overlapping_write",
                "entities[].changeRequest.effects[]",
                "change-request effects cannot write the same target field more than once",
            ));
        } else {
            errors.push(Diagnostic::error(
                "change_request.effect.overlapping_write",
                "entities[].changeRequest.effects[]",
                "a change-request effect cannot both set and clear the same target field",
            ));
        }
    }
}

fn order_effects(
    effects: BTreeMap<String, CompiledChangeRequestEffect>,
    errors: &mut Vec<Diagnostic>,
) -> Option<Vec<CompiledChangeRequestEffect>> {
    let mut state = BTreeMap::<String, VisitState>::new();
    let mut ordered = Vec::new();
    for id in effects.keys() {
        visit_effect(id, &effects, &mut state, &mut ordered, errors);
    }
    if errors
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.dependency_cycle")
    {
        return None;
    }
    Some(
        ordered
            .into_iter()
            .filter_map(|id| effects.get(&id).cloned())
            .collect(),
    )
}

fn visit_effect(
    id: &str,
    effects: &BTreeMap<String, CompiledChangeRequestEffect>,
    state: &mut BTreeMap<String, VisitState>,
    ordered: &mut Vec<String>,
    errors: &mut Vec<Diagnostic>,
) {
    match state.get(id).copied() {
        Some(VisitState::Done) => return,
        Some(VisitState::Visiting) => {
            errors.push(Diagnostic::error(
                "change_request.effect.dependency_cycle",
                "entities[].changeRequest.effects[]",
                "reserved-create references cannot contain dependency cycles",
            ));
            return;
        }
        None => {}
    }
    state.insert(id.to_owned(), VisitState::Visiting);
    if let Some(effect) = effects.get(id) {
        for dependency in &effect.depends_on {
            visit_effect(dependency, effects, state, ordered, errors);
        }
    }
    state.insert(id.to_owned(), VisitState::Done);
    ordered.push(id.to_owned());
}

#[derive(Clone, Copy)]
enum VisitState {
    Visiting,
    Done,
}

fn validate_plan_bounds(
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledChangeRequestEffect],
    errors: &mut Vec<Diagnostic>,
) {
    let target_count = effects
        .iter()
        .map(|effect| target_binding_key(&effect.target))
        .collect::<BTreeSet<_>>()
        .len();
    if target_count > usize::from(MAX_CHANGE_REQUEST_TARGETS) {
        errors.push(Diagnostic::error(
            "change_request.bounds.targets",
            "entities[].changeRequest.effects",
            "a change-request plan exceeds the supported target-record ceiling",
        ));
    }
    let mutation_count: usize = effects.iter().map(|effect| effect.mutations.len()).sum();
    if mutation_count > usize::from(MAX_CHANGE_REQUEST_FIELD_MUTATIONS) {
        errors.push(Diagnostic::error(
            "change_request.bounds.field_mutations",
            "entities[].changeRequest.effects",
            "a change-request plan exceeds the supported field-mutation ceiling",
        ));
    }
    match maximum_snapshot_bytes(request_entity, entities, effects) {
        Some(bytes) if bytes <= u64::from(MAX_CHANGE_REQUEST_SNAPSHOT_BYTES) => {}
        Some(_) => errors.push(Diagnostic::error(
            "change_request.bounds.snapshot_bytes",
            "entities[].changeRequest.effects",
            "a change-request plan exceeds the supported snapshot-size ceiling",
        )),
        None => errors.push(Diagnostic::error(
            "change_request.bounds.snapshot_unknown",
            "entities[].changeRequest.effects",
            "a change-request plan contains a field whose snapshot size cannot be bounded",
        )),
    }
}

fn compile_action_routes(
    stages: &[CompiledChangeRequestStage],
) -> Vec<CompiledChangeRequestActionRoute> {
    let mut actions = vec![
        CompiledChangeRequestActionRoute {
            operation: ChangeRequestOperation::SubmitRequest,
            review_stage: None,
        },
        CompiledChangeRequestActionRoute {
            operation: ChangeRequestOperation::ReviseRequest,
            review_stage: None,
        },
        CompiledChangeRequestActionRoute {
            operation: ChangeRequestOperation::CancelRequest,
            review_stage: None,
        },
        CompiledChangeRequestActionRoute {
            operation: ChangeRequestOperation::ApplyRequest,
            review_stage: None,
        },
    ];
    for stage in stages {
        for operation in [
            ChangeRequestOperation::ApproveRequest,
            ChangeRequestOperation::RejectRequest,
            ChangeRequestOperation::RequestRevision,
        ] {
            actions.push(CompiledChangeRequestActionRoute {
                operation,
                review_stage: Some(stage.id.clone()),
            });
        }
    }
    actions
}

fn compile_review_grants(
    request_entity: &CompiledEntity,
    stages: &[CompiledChangeRequestStage],
    changed_fields: &BTreeMap<String, BTreeSet<String>>,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestReviewGrant> {
    let stage_ids = stages
        .iter()
        .map(|stage| stage.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut grants = Vec::new();
    for profile in request_entity.access_profiles.values() {
        for grant in &profile.review_stages {
            if !profile.operations.iter().any(|operation| {
                matches!(
                    operation,
                    Operation::ApproveRequest
                        | Operation::RejectRequest
                        | Operation::RequestRevision
                )
            }) {
                errors.push(Diagnostic::error(
                    "change_request.review_stage.operation_required",
                    "entities[].accessProfiles[].operations",
                    "review stage grants require approve_request, reject_request, or request_revision authority",
                ));
            }
            if !stage_ids.contains(grant.stage.as_str()) {
                errors.push(Diagnostic::error(
                    "change_request.review_stage.unknown",
                    "entities[].accessProfiles[].reviewStages[].stage",
                    "a review grant refers to an unknown review stage",
                ));
                continue;
            }
            for target in &grant.targets {
                let Some(target_entity) = entities.get(&target.entity) else {
                    errors.push(Diagnostic::error(
                        "change_request.review_stage.target_unknown",
                        "entities[].accessProfiles[].reviewStages[].targets[].entity",
                        "a review grant targets an unknown entity",
                    ));
                    continue;
                };
                validate_target_fields(
                    target_entity,
                    &target.readable_fields,
                    "entities[].accessProfiles[].reviewStages[].targets[].readableFields",
                    errors,
                );
                validate_row_boundaries(
                    target_entity,
                    &target.row_boundaries,
                    "entities[].accessProfiles[].reviewStages[].targets[].rowBoundaries",
                    errors,
                );
                if let Some(required) = changed_fields.get(&target.entity) {
                    if !required.is_subset(&target.readable_fields) {
                        errors.push(Diagnostic::error(
                            "change_request.review_projection.incomplete",
                            "entities[].accessProfiles[].reviewStages[].targets[].readableFields",
                            "review target projections must cover every changed target field",
                        ));
                    }
                }
                grants.push(CompiledChangeRequestReviewGrant {
                    profile_id: profile.id.clone(),
                    stage: grant.stage.clone(),
                    target_entity_id: target.entity.clone(),
                    readable_fields: target.readable_fields.clone(),
                    row_boundaries: target.row_boundaries.clone(),
                });
            }
        }
    }
    for stage in stages {
        let covered = request_entity.access_profiles.values().any(|profile| {
            let can_decide = profile.operations.iter().any(|operation| {
                matches!(
                    operation,
                    Operation::ApproveRequest
                        | Operation::RejectRequest
                        | Operation::RequestRevision
                )
            });
            can_decide
                && changed_fields.keys().all(|entity_id| {
                    profile.review_stages.iter().any(|grant| {
                        grant.stage == stage.id
                            && grant.targets.iter().any(|target| {
                                target.entity == *entity_id
                                    && changed_fields.get(entity_id).is_some_and(|fields| {
                                        fields.is_subset(&target.readable_fields)
                                    })
                            })
                    })
                })
        });
        if !covered {
            errors.push(Diagnostic::error(
                "change_request.review_projection.incomplete",
                "entities[].accessProfiles[].reviewStages",
                "each review stage requires at least one profile that can review every target change",
            ));
        }
    }
    grants.sort_by(|left, right| {
        (&left.stage, &left.profile_id, &left.target_entity_id).cmp(&(
            &right.stage,
            &right.profile_id,
            &right.target_entity_id,
        ))
    });
    grants
}

fn compile_apply_grants(
    request_entity: &CompiledEntity,
    target_entities: &BTreeSet<String>,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestApplyGrant> {
    let mut grants = Vec::new();
    for profile in request_entity.access_profiles.values() {
        if !profile.apply_targets.is_empty()
            && !profile.operations.contains(&Operation::ApplyRequest)
        {
            errors.push(Diagnostic::error(
                "change_request.apply_target.operation_required",
                "entities[].accessProfiles[].operations",
                "apply target grants require apply_request authority",
            ));
        }
        for target in &profile.apply_targets {
            let Some(target_entity) = entities.get(&target.entity) else {
                errors.push(Diagnostic::error(
                    "change_request.apply_target.unknown",
                    "entities[].accessProfiles[].applyTargets[].entity",
                    "an apply grant targets an unknown entity",
                ));
                continue;
            };
            validate_row_boundaries(
                target_entity,
                &target.row_boundaries,
                "entities[].accessProfiles[].applyTargets[].rowBoundaries",
                errors,
            );
            grants.push(CompiledChangeRequestApplyGrant {
                profile_id: profile.id.clone(),
                target_entity_id: target.entity.clone(),
                row_boundaries: target.row_boundaries.clone(),
            });
        }
    }
    let covered = request_entity.access_profiles.values().any(|profile| {
        profile.operations.contains(&Operation::ApplyRequest)
            && target_entities.iter().all(|entity_id| {
                profile
                    .apply_targets
                    .iter()
                    .any(|target| target.entity == *entity_id)
            })
    });
    if !target_entities.is_empty() && !covered {
        errors.push(Diagnostic::error(
            "change_request.apply_targets.incomplete",
            "entities[].accessProfiles[].applyTargets",
            "at least one profile must be able to apply the complete change-request target set",
        ));
    }
    grants.sort_by(|left, right| {
        (&left.profile_id, &left.target_entity_id)
            .cmp(&(&right.profile_id, &right.target_entity_id))
    });
    grants
}

fn compile_presence_grants(
    entities: &BTreeMap<String, CompiledEntity>,
    plans: &mut BTreeMap<String, CompiledChangeRequest>,
    errors: &mut Vec<Diagnostic>,
) {
    let target_by_request = plans
        .iter()
        .map(|(request_id, plan)| (request_id.clone(), plan.target_entities.clone()))
        .collect::<BTreeMap<_, _>>();
    for target_entity in entities.values() {
        for profile in target_entity.access_profiles.values() {
            for grant in &profile.request_presence {
                let Some(targets) = target_by_request.get(&grant.request_type) else {
                    errors.push(Diagnostic::error(
                        "change_request.presence.request_type_unknown",
                        "entities[].accessProfiles[].requestPresence[].requestType",
                        "a request-presence grant refers to an unknown request type",
                    ));
                    continue;
                };
                let Some(request_entity) = entities.get(&grant.request_type) else {
                    continue;
                };
                validate_row_boundaries(
                    request_entity,
                    &grant.row_boundaries,
                    "entities[].accessProfiles[].requestPresence[].rowBoundaries",
                    errors,
                );
                if !targets.contains(&target_entity.id) {
                    errors.push(Diagnostic::error(
                        "change_request.presence.target_unaffected",
                        "entities[].accessProfiles[].requestPresence[].requestType",
                        "a request-presence grant must name a request type that can affect the granted target entity",
                    ));
                    continue;
                }
                if profile.anonymous {
                    // Presence processes the request's existence and target
                    // linkage even when no intake values are disclosed.
                    let public_links = plans.get(&grant.request_type).is_some_and(|plan| {
                        plan.effects
                            .iter()
                            .filter(|effect| effect.target.entity_id == target_entity.id)
                            .all(|effect| match &effect.target.binding {
                                CompiledChangeRequestTargetBinding::Existing { from_field } => {
                                    request_entity.fields.get(from_field).is_some_and(|field| {
                                        field.classification == Classification::Public
                                    })
                                }
                                CompiledChangeRequestTargetBinding::ReservedCreate { .. } => true,
                            })
                    });
                    if request_entity.classification != Classification::Public || !public_links {
                        errors.push(Diagnostic::error(
                            "change_request.presence.anonymous_non_public",
                            "entities[].accessProfiles[].requestPresence",
                            "anonymous request presence requires a public request type and public target-link fields",
                        ));
                    }
                    if !grant.row_boundaries.is_empty() {
                        errors.push(Diagnostic::error(
                            "change_request.presence.anonymous_claim_boundary",
                            "entities[].accessProfiles[].requestPresence[].rowBoundaries",
                            "anonymous request presence cannot depend on verified claim boundaries",
                        ));
                    }
                }
                if let Some(plan) = plans.get_mut(&grant.request_type) {
                    plan.presence_grants
                        .push(CompiledChangeRequestPresenceGrant {
                            profile_id: profile.id.clone(),
                            target_entity_id: target_entity.id.clone(),
                            request_row_boundaries: grant.row_boundaries.clone(),
                        });
                }
            }
        }
    }
    for plan in plans.values_mut() {
        plan.presence_grants.sort_by(|left, right| {
            (&left.target_entity_id, &left.profile_id)
                .cmp(&(&right.target_entity_id, &right.profile_id))
        });
    }
}

fn validate_target_fields(
    entity: &CompiledEntity,
    fields: &BTreeSet<String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for field in fields {
        if !entity.fields.contains_key(field) {
            errors.push(Diagnostic::error(
                "change_request.grant.field_unknown",
                path,
                "a change-request grant refers to an unknown stored target field",
            ));
        }
    }
}

fn validate_row_boundaries(
    entity: &CompiledEntity,
    boundaries: &[RowBoundarySource],
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let mut seen = BTreeSet::new();
    for boundary in boundaries {
        if boundary.claim.is_empty()
            || !seen.insert((
                boundary.field.as_str(),
                boundary.claim.as_str(),
                boundary.operator,
            ))
        {
            errors.push(Diagnostic::error(
                "change_request.grant.row_boundary_invalid",
                path,
                "change-request grant row boundaries must be direct, non-empty, and duplicate-free",
            ));
        }
        if boundary.field == "id" {
            continue;
        }
        let Some(field) = entity.fields.get(&boundary.field) else {
            errors.push(Diagnostic::error(
                "change_request.grant.row_boundary_field_unknown",
                path,
                "a change-request grant row boundary refers to an unknown field",
            ));
            continue;
        };
        if matches!(
            field.field_type,
            FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
        ) {
            errors.push(Diagnostic::error(
                "change_request.grant.row_boundary_type_unsupported",
                path,
                "CRS84 point and structured fields cannot be change-request row-boundary fields",
            ));
        }
    }
}

// Static snapshot estimation covers request intake plus the fields this plan can
// change. The runtime still caps the complete prepared target before/after
// packet before acquiring mutation locks, including unchanged target fields.
fn maximum_snapshot_bytes(
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledChangeRequestEffect],
) -> Option<u64> {
    let mut total = 2_u64;
    for field in request_entity.fields.values() {
        let max = maximum_field_json_bytes(&field.field_type)?;
        total = total
            .checked_add(field.id.len() as u64 + 3)?
            .checked_add(if field.required { max } else { max.max(4) })?;
    }
    for effect in effects {
        let target = entities.get(&effect.target.entity_id)?;
        total = total
            .checked_add(effect.id.len() as u64 + effect.target.entity_id.len() as u64 + 32)?;
        for mutation in &effect.mutations {
            let field = match mutation {
                CompiledChangeRequestMutation::Set { field, .. }
                | CompiledChangeRequestMutation::Clear { field } => field,
            };
            let target_field = target.fields.get(field)?;
            let max = maximum_field_json_bytes(&target_field.field_type)?;
            let before = max.max(4);
            let after = match mutation {
                CompiledChangeRequestMutation::Set { .. } => max,
                CompiledChangeRequestMutation::Clear { .. } => 4,
            };
            total = total
                .checked_add(field.len() as u64 + 8)?
                .checked_add(before)?
                .checked_add(after)?;
        }
    }
    Some(total)
}

fn maximum_field_json_bytes(field_type: &FieldTypeSource) -> Option<u64> {
    match field_type {
        FieldTypeSource::Boolean => Some(5),
        FieldTypeSource::String { max_length, .. } | FieldTypeSource::Text { max_length } => {
            2_u64.checked_add(u64::from(*max_length).checked_mul(6)?)
        }
        FieldTypeSource::Int64 => Some(20),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => Some(
            2_u64
                .checked_add(u64::from(*precision))?
                .checked_add((*scale > 0) as u64)?
                .checked_add(1)?,
        ),
        FieldTypeSource::Date => Some(12),
        FieldTypeSource::Timestamp => Some(37),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => Some(38),
        FieldTypeSource::VocabularyCode { values, .. } => values
            .iter()
            .map(|value| 2_u64.checked_add(value.len() as u64))
            .max()
            .unwrap_or(Some(2)),
        FieldTypeSource::Crs84Point { .. } => Some(96),
        FieldTypeSource::Structured { max_bytes, .. } => Some(u64::from(*max_bytes)),
    }
}

fn contract_fingerprint(
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledChangeRequestEffect],
    stages: &[CompiledChangeRequestStage],
    review_grants: &[CompiledChangeRequestReviewGrant],
    apply_grants: &[CompiledChangeRequestApplyGrant],
    target_entities: &BTreeSet<String>,
) -> String {
    let target_contracts = target_entities
        .iter()
        .filter_map(|entity_id| {
            entities
                .get(entity_id)
                .map(|entity| (entity_id.clone(), entity_contract_payload(entity)))
        })
        .collect::<BTreeMap<_, _>>();
    let payload = json!({
        "version": 2,
        "requestEntity": entity_contract_payload(request_entity),
        "targetEntities": target_contracts,
        "effects": effects,
        "stages": stages,
        "reviewAuthority": authority_payload(
            request_entity,
            review_grants.iter().map(|grant| grant.profile_id.as_str()).collect(),
            [Operation::ApproveRequest, Operation::RejectRequest, Operation::RequestRevision]
        ),
        "reviewGrants": review_grant_payload(review_grants),
        "applyAuthority": authority_payload(
            request_entity,
            apply_grants.iter().map(|grant| grant.profile_id.as_str()).collect(),
            [Operation::ApplyRequest]
        ),
        "applyGrants": apply_grant_payload(apply_grants),
        "limits": {
            "maximumTargets": MAX_CHANGE_REQUEST_TARGETS,
            "maximumFieldMutations": MAX_CHANGE_REQUEST_FIELD_MUTATIONS,
            "maximumSnapshotBytes": MAX_CHANGE_REQUEST_SNAPSHOT_BYTES,
            "maximumReviewStages": MAX_CHANGE_REQUEST_REVIEW_STAGES
        }
    });
    let bytes =
        canonicalize_json(&payload).expect("compiled change-request contract canonicalizes");
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

fn entity_contract_payload(entity: &CompiledEntity) -> serde_json::Value {
    let fields = entity
        .fields
        .iter()
        .map(|(field_id, field)| {
            (
                field_id.clone(),
                json!({
                    "type": field.field_type,
                    "required": field.required,
                    "classification": field.classification,
                    "validTimeRole": field.valid_time_role,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!({
        "id": entity.id,
        "route": entity.route,
        "mutationMode": entity.mutation_mode,
        "tombstone": entity.tombstone,
        "classification": entity.classification,
        "fields": fields,
        "constraints": entity.constraints,
        "changeControl": entity.change_control,
    })
}

fn authority_payload<const N: usize>(
    entity: &CompiledEntity,
    profile_ids: BTreeSet<&str>,
    relevant_operations: [Operation; N],
) -> serde_json::Value {
    let operations = relevant_operations.into_iter().collect::<BTreeSet<_>>();
    let profiles = profile_ids
        .into_iter()
        .filter_map(|profile_id| entity.access_profiles.get(profile_id))
        .map(|profile| {
            let profile_operations = profile
                .operations
                .intersection(&operations)
                .copied()
                .collect::<BTreeSet<_>>();
            (
                profile.id.clone(),
                json!({
                    "anonymous": profile.anonymous,
                    "principalClaim": profile.principal_claim,
                    "requiredScopes": profile.required_scopes,
                    "requiredPurposes": profile.required_purposes,
                    "operations": profile_operations,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!(profiles)
}

fn review_grant_payload(grants: &[CompiledChangeRequestReviewGrant]) -> Vec<serde_json::Value> {
    let mut grants = grants.iter().collect::<Vec<_>>();
    grants.sort_by(|left, right| {
        (&left.profile_id, &left.stage, &left.target_entity_id).cmp(&(
            &right.profile_id,
            &right.stage,
            &right.target_entity_id,
        ))
    });
    grants
        .into_iter()
        .map(|grant| {
            json!({
                "profileId": grant.profile_id,
                "stage": grant.stage,
                "targetEntityId": grant.target_entity_id,
                "readableFields": grant.readable_fields,
                "rowBoundaries": grant.row_boundaries,
            })
        })
        .collect()
}

fn apply_grant_payload(grants: &[CompiledChangeRequestApplyGrant]) -> Vec<serde_json::Value> {
    let mut grants = grants.iter().collect::<Vec<_>>();
    grants.sort_by(|left, right| {
        (&left.profile_id, &left.target_entity_id)
            .cmp(&(&right.profile_id, &right.target_entity_id))
    });
    grants
        .into_iter()
        .map(|grant| {
            json!({
                "profileId": grant.profile_id,
                "targetEntityId": grant.target_entity_id,
                "rowBoundaries": grant.row_boundaries,
            })
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_change_controlled(entity: &CompiledEntity, operation: Operation) -> bool {
    entity
        .change_control
        .as_ref()
        .is_some_and(|control| control.required_for.contains(&operation))
}

fn is_mutation_operation(operation: Operation) -> bool {
    matches!(operation, Operation::Create | Operation::Patch)
}

fn compatible_field_types(source: &FieldTypeSource, target: &FieldTypeSource) -> bool {
    source == target
}

fn effect_id(effect: &ChangeRequestEffectSource, index: usize) -> String {
    effect
        .id
        .clone()
        .unwrap_or_else(|| format!("effect-{}", index + 1))
}

fn target_binding_key(target: &CompiledChangeRequestTarget) -> String {
    match &target.binding {
        CompiledChangeRequestTargetBinding::Existing { from_field } => {
            format!("existing:{}:{}", target.entity_id, from_field)
        }
        CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
            format!("create:{}:{}", target.entity_id, effect)
        }
    }
}

fn exactly_one<T>(left: Option<T>, right: Option<T>) -> bool {
    left.is_some() ^ right.is_some()
}

fn validate_id(value: &str, path: &str, errors: &mut Vec<Diagnostic>) {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if !valid {
        errors.push(Diagnostic::error(
            "identifier.invalid",
            path,
            "an identifier must use the closed lowercase identifier grammar",
        ));
    }
}
