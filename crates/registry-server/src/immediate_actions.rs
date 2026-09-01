// SPDX-License-Identifier: Apache-2.0
//! Immediate-action authoring compilation.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::change_request::{
    MAX_CHANGE_REQUEST_FIELD_MUTATIONS, MAX_CHANGE_REQUEST_SNAPSHOT_BYTES,
    MAX_CHANGE_REQUEST_TARGETS,
};
use crate::contract::{
    AccessProfileSource, ActionEffectSource, ActionSource, ActionValueSource, FieldTypeSource,
    Operation, ProjectAccessProfileSource, RowBoundarySource,
};
use crate::diagnostics::Diagnostic;
use crate::logical_names::{default_api_name, reserved_logical_name, valid_api_name};
use crate::model::{
    ActionRouteKind, CompiledAction, CompiledActionAccessEntry, CompiledActionEffect,
    CompiledActionGrant, CompiledActionInput, CompiledActionInventory, CompiledActionMutation,
    CompiledActionRoute, CompiledActionTarget, CompiledActionTargetBinding,
    CompiledActionTargetGrant, CompiledActionTargetUse, CompiledActionTargetUseSource,
    CompiledActionValue, CompiledEntity, HttpMethod,
};

type CompiledEffectSet = (
    Vec<CompiledActionEffect>,
    Vec<CompiledActionTargetUse>,
    BTreeSet<String>,
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedActionSource {
    pub source: ActionSource,
    pub source_module: Option<String>,
}

pub(crate) fn compile_immediate_actions(
    actions: &BTreeMap<String, CollectedActionSource>,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
) -> Result<CompiledActionInventory, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    validate_action_grant_sources(actions, profiles, &mut errors);
    let mut compiled_actions = Vec::new();
    let mut routes = Vec::new();
    let mut access = Vec::new();
    for collected in actions.values() {
        if let Some(compiled) = compile_action(collected, entities, profiles, &mut errors) {
            let action_routes = compile_action_routes(&compiled, profiles, &mut errors);
            let action_access = action_routes
                .iter()
                .map(|route| CompiledActionAccessEntry {
                    route_id: route.id.clone(),
                    action_id: route.action_id.clone(),
                    operation: route.operation,
                    profile_ids: route.access_profiles.iter().cloned().collect(),
                    default_profile_id: route.default_access_profile.clone(),
                })
                .collect::<Vec<_>>();
            routes.extend(action_routes);
            access.extend(action_access);
            compiled_actions.push(compiled);
        }
    }
    routes.sort_by(|left, right| {
        (&left.path, left.method, &left.id).cmp(&(&right.path, right.method, &right.id))
    });
    access.sort_by(|left, right| {
        (&left.action_id, &left.route_id).cmp(&(&right.action_id, &right.route_id))
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(CompiledActionInventory {
        actions: compiled_actions,
        routes,
        access,
    })
}

fn compile_action(
    collected: &CollectedActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledAction> {
    let action = &collected.source;
    validate_id(&action.id, "actions[].id", errors);
    if action.inputs.is_empty() {
        errors.push(Diagnostic::error(
            "action.inputs.empty",
            "actions[].inputs",
            "an immediate action must declare at least one typed input",
        ));
    }
    if action.effects.is_empty() {
        errors.push(Diagnostic::error(
            "action.effects.empty",
            "actions[].effects",
            "an immediate action must declare at least one fixed effect",
        ));
    }
    let inputs = compile_inputs(action, entities, errors);
    let input_map = inputs
        .iter()
        .map(|input| (input.id.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    let (effects, target_uses, result_effects) =
        compile_effects(action, &input_map, entities, errors)?;
    validate_plan_bounds(&inputs, entities, &effects, &target_uses, errors);
    let grants = compile_grants(
        action,
        entities,
        profiles,
        &target_uses,
        &result_effects,
        errors,
    );
    if grants.is_empty() {
        errors.push(Diagnostic::error(
            "action.grant.missing",
            "project.accessProfiles[].grants",
            "an immediate action requires at least one explicit invoke grant",
        ));
    }
    let condition_route = target_uses
        .iter()
        .any(|use_| use_.condition_required)
        .then(|| format!("/v1/actions/{}/target-conditions", action.id));
    Some(CompiledAction {
        id: action.id.clone(),
        source_module: collected.source_module.clone(),
        route: format!("/v1/actions/{}", action.id),
        condition_route,
        contract_fingerprint: contract_fingerprint(action, entities, &inputs, &effects, &grants),
        inputs,
        effects,
        target_uses,
        grants,
        result_effects,
        maximum_targets: MAX_CHANGE_REQUEST_TARGETS,
        maximum_field_mutations: MAX_CHANGE_REQUEST_FIELD_MUTATIONS,
        maximum_snapshot_bytes: MAX_CHANGE_REQUEST_SNAPSHOT_BYTES,
    })
}

fn compile_inputs(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionInput> {
    let mut ids = BTreeSet::new();
    let mut api_names = BTreeSet::new();
    let mut inputs = Vec::new();
    for input in &action.inputs {
        validate_id(&input.id, "actions[].inputs[].id", errors);
        if reserved_logical_name(&input.id) {
            errors.push(Diagnostic::error(
                "action.input.id.reserved",
                "actions[].inputs[].id",
                "an action input identifier collides with a reserved Registry field",
            ));
        }
        if !ids.insert(input.id.as_str()) {
            errors.push(Diagnostic::error(
                "action.input.id.duplicate",
                "actions[].inputs[].id",
                "action input identifiers must be duplicate-free",
            ));
        }
        let api_name = input
            .api_name
            .clone()
            .unwrap_or_else(|| default_api_name(&input.id));
        if !valid_api_name(&api_name) || reserved_logical_name(&api_name) {
            errors.push(Diagnostic::error(
                "action.input.api_name.invalid",
                "actions[].inputs[].apiName",
                "an action input API name must be a non-reserved lower camelCase identifier",
            ));
        }
        if !api_names.insert(api_name.clone()) {
            errors.push(Diagnostic::error(
                "action.input.api_name.duplicate",
                "actions[].inputs[].apiName",
                "action input API names must be unique within the action",
            ));
        }
        validate_field_type_bounds(&input.field_type, "actions[].inputs[]", errors);
        if let FieldTypeSource::Reference { target, .. } = &input.field_type {
            if !entities.contains_key(target) {
                errors.push(Diagnostic::error(
                    "action.input.reference.target_unknown",
                    "actions[].inputs[].target",
                    "an action reference input target does not resolve",
                ));
            }
        }
        inputs.push(CompiledActionInput {
            id: input.id.clone(),
            api_name,
            field_type: input.field_type.clone(),
            required: input.required,
            classification: input.classification,
        });
    }
    inputs
}

fn compile_effects(
    action: &ActionSource,
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledEffectSet> {
    let mut effect_ids = BTreeSet::new();
    let mut create_targets = BTreeMap::new();
    for (index, effect) in action.effects.iter().enumerate() {
        let id = effect_id(effect, index);
        validate_id(&id, "actions[].effects[].id", errors);
        if !effect_ids.insert(id.clone()) {
            errors.push(Diagnostic::error(
                "action.effect.id_duplicate",
                "actions[].effects[].id",
                "immediate-action effect identifiers must be duplicate-free",
            ));
        }
        if effect.operation == Operation::Create {
            if effect.id.is_none() {
                errors.push(Diagnostic::error(
                    "action.effect.create_id_required",
                    "actions[].effects[].id",
                    "create effects require an explicit identifier for reserved-record references",
                ));
            }
            if let Some(entity_id) = &effect.target.entity {
                create_targets.insert(id, entity_id.clone());
            }
        }
    }

    let mut compiled_by_id = BTreeMap::new();
    let mut writes = BTreeMap::new();
    let mut target_uses = BTreeMap::<(String, String, Operation), CompiledActionTargetUse>::new();
    for (index, effect) in action.effects.iter().enumerate() {
        let id = effect_id(effect, index);
        let Some(target) = compile_target(inputs, entities, &id, effect, errors) else {
            continue;
        };
        let Some(target_entity) = entities.get(&target.entity_id) else {
            continue;
        };
        if effect.set.is_empty() && effect.clear.is_empty() {
            errors.push(Diagnostic::error(
                "action.effect.empty",
                "actions[].effects[]",
                "an immediate-action effect must set or clear at least one field",
            ));
        }
        let mut mutations = Vec::new();
        let mut depends_on = BTreeSet::new();
        for (field, value) in &effect.set {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "action.effect.field_unknown",
                    "actions[].effects[].set",
                    "an immediate-action effect writes an unknown stored target field",
                ));
                continue;
            };
            if let Some(compiled) = compile_value(
                inputs,
                field,
                &target_field.field_type,
                target_field.required,
                value,
                &create_targets,
                errors,
            ) {
                if let CompiledActionValue::FromEffect { effect, .. } = &compiled {
                    depends_on.insert(effect.clone());
                }
                if let CompiledActionValue::FromInput { input } = &compiled {
                    remember_link_reference_use(input, inputs, &mut target_uses);
                }
                mutations.push(CompiledActionMutation::Set {
                    field: field.clone(),
                    value: compiled,
                });
                remember_write(&mut writes, &target, field, &id, errors);
            }
        }
        for field in &effect.clear {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "action.effect.field_unknown",
                    "actions[].effects[].clear",
                    "an immediate-action effect clears an unknown stored target field",
                ));
                continue;
            };
            if effect.operation == Operation::Create {
                errors.push(Diagnostic::error(
                    "action.effect.clear_on_create",
                    "actions[].effects[].clear",
                    "create effects cannot clear target fields",
                ));
            }
            if target_field.required {
                errors.push(Diagnostic::error(
                    "action.effect.clear_required",
                    "actions[].effects[].clear",
                    "required target fields cannot be cleared",
                ));
            }
            mutations.push(CompiledActionMutation::Clear {
                field: field.clone(),
            });
            remember_write(&mut writes, &target, field, &id, errors);
        }
        remember_effect_use(&id, effect.operation, &target, &mutations, &mut target_uses);
        compiled_by_id.insert(
            id.clone(),
            CompiledActionEffect {
                id,
                target,
                operation: effect.operation,
                mutations,
                depends_on,
            },
        );
    }

    let ordered = order_effects(compiled_by_id, errors)?;
    validate_required_create_fields(entities, &ordered, errors);
    let result_effects = ordered.iter().map(|effect| effect.id.clone()).collect();
    let conditioned_inputs = target_uses
        .values()
        .filter(|use_| use_.condition_required)
        .filter_map(|use_| match &use_.source {
            CompiledActionTargetUseSource::Input { input } => {
                Some((use_.entity_id.clone(), input.clone()))
            }
            CompiledActionTargetUseSource::Effect { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let mut target_uses = target_uses
        .into_values()
        .filter(|use_| {
            use_.condition_required
                || match &use_.source {
                    CompiledActionTargetUseSource::Input { input } => {
                        !conditioned_inputs.contains(&(use_.entity_id.clone(), input.clone()))
                    }
                    CompiledActionTargetUseSource::Effect { .. } => true,
                }
        })
        .collect::<Vec<_>>();
    target_uses.sort_by(|left, right| {
        (&left.entity_id, left.operation, &left.fields).cmp(&(
            &right.entity_id,
            right.operation,
            &right.fields,
        ))
    });
    Some((ordered, target_uses, result_effects))
}

fn compile_target(
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    entities: &BTreeMap<String, CompiledEntity>,
    effect_id: &str,
    effect: &ActionEffectSource,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledActionTarget> {
    if !matches!(effect.operation, Operation::Create | Operation::Patch) {
        errors.push(Diagnostic::error(
            "action.effect.operation.unsupported",
            "actions[].effects[].operation",
            "immediate-action effects can only create or patch target records",
        ));
        return None;
    }
    match (
        &effect.target.entity,
        &effect.target.from_field,
        effect.operation,
    ) {
        (Some(entity_id), None, Operation::Create) => {
            let Some(entity) = entities.get(entity_id) else {
                errors.push(Diagnostic::error(
                    "action.effect.target.unknown",
                    "actions[].effects[].target.entity",
                    "an immediate-action create target refers to an unknown entity",
                ));
                return None;
            };
            validate_mutable_target(entity, Operation::Create, errors)?;
            Some(CompiledActionTarget {
                entity_id: entity_id.clone(),
                binding: CompiledActionTargetBinding::Create,
            })
        }
        (None, Some(input_id), Operation::Patch) => {
            let Some(input) = inputs.get(input_id.as_str()) else {
                errors.push(Diagnostic::error(
                    "action.effect.target.input_unknown",
                    "actions[].effects[].target.fromField",
                    "an immediate-action patch target must refer to a declared reference input",
                ));
                return None;
            };
            let FieldTypeSource::Reference { target, .. } = &input.field_type else {
                errors.push(Diagnostic::error(
                    "action.effect.target.reference_required",
                    "actions[].effects[].target.fromField",
                    "an immediate-action patch target must refer to a reference input",
                ));
                return None;
            };
            let entity = entities.get(target)?;
            validate_mutable_target(entity, Operation::Patch, errors)?;
            Some(CompiledActionTarget {
                entity_id: target.clone(),
                binding: CompiledActionTargetBinding::Existing {
                    input: input_id.clone(),
                },
            })
        }
        _ => {
            let _ = effect_id;
            errors.push(Diagnostic::error(
                "action.effect.target.invalid",
                "actions[].effects[].target",
                "create effects must name an entity and patch effects must name one reference input",
            ));
            None
        }
    }
}

fn validate_mutable_target(
    entity: &CompiledEntity,
    operation: Operation,
    errors: &mut Vec<Diagnostic>,
) -> Option<()> {
    if entity.change_request.is_some() {
        errors.push(Diagnostic::error(
            "action.effect.request_target",
            "actions[].effects[].target",
            "immediate actions cannot target change-request workflow entities",
        ));
        return None;
    }
    if operation == Operation::Patch
        && entity.mutation_mode == crate::contract::MutationMode::CreateOnly
    {
        errors.push(Diagnostic::error(
            "action.effect.operation.unavailable",
            "actions[].effects[].operation",
            "immediate actions cannot patch create-only entities",
        ));
        return None;
    }
    if entity
        .change_control
        .as_ref()
        .is_some_and(|control| control.required_for.contains(&operation))
    {
        errors.push(Diagnostic::error(
            "action.effect.controlled_target",
            "actions[].effects[].target",
            "immediate actions cannot target operations that require reviewed change control",
        ));
        return None;
    }
    Some(())
}

fn compile_value(
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    target_field: &str,
    target_type: &FieldTypeSource,
    target_required: bool,
    value: &ActionValueSource,
    create_targets: &BTreeMap<String, String>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledActionValue> {
    match (&value.from_field, &value.from_effect) {
        (Some(input_id), None) => {
            let Some(input) = inputs.get(input_id.as_str()) else {
                errors.push(Diagnostic::error(
                    "action.effect.value.input_unknown",
                    "actions[].effects[].set",
                    "fromField must refer to a declared action input",
                ));
                return None;
            };
            if target_required && !input.required {
                errors.push(Diagnostic::error(
                    "action.effect.value_nullable",
                    "actions[].effects[].set",
                    "a nullable action input cannot populate a required target field",
                ));
            }
            if !compatible_field_types(&input.field_type, target_type) {
                errors.push(Diagnostic::error(
                    "action.effect.value.type_mismatch",
                    format!("actions[].effects[].set.{target_field}"),
                    "fromField input type must match the target field type",
                ));
                return None;
            }
            Some(CompiledActionValue::FromInput {
                input: input_id.clone(),
            })
        }
        (None, Some(effect_id)) => {
            let Some(target_entity_id) = create_targets.get(effect_id) else {
                errors.push(Diagnostic::error(
                    "action.effect.value.effect_unknown",
                    "actions[].effects[].set",
                    "fromEffect must refer to a declared create effect",
                ));
                return None;
            };
            match target_type {
                FieldTypeSource::Reference { target, .. } if target == target_entity_id => {
                    Some(CompiledActionValue::FromEffect {
                        effect: effect_id.clone(),
                        target_entity_id: target_entity_id.clone(),
                    })
                }
                FieldTypeSource::Reference { .. } => {
                    errors.push(Diagnostic::error(
                        "action.effect.value_reference_mismatch",
                        format!("actions[].effects[].set.{target_field}"),
                        "fromEffect reserved identity does not match the target reference field",
                    ));
                    None
                }
                _ => {
                    errors.push(Diagnostic::error(
                        "action.effect.value_reference_required",
                        format!("actions[].effects[].set.{target_field}"),
                        "fromEffect can populate only typed reference fields",
                    ));
                    None
                }
            }
        }
        _ => {
            errors.push(Diagnostic::error(
                "action.effect.value.invalid",
                "actions[].effects[].set",
                "effect mappings must declare exactly one fromField or fromEffect source",
            ));
            None
        }
    }
}

fn validate_required_create_fields(
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledActionEffect],
    errors: &mut Vec<Diagnostic>,
) {
    for effect in effects {
        if effect.operation != Operation::Create {
            continue;
        }
        let Some(entity) = entities.get(&effect.target.entity_id) else {
            continue;
        };
        let written = effect
            .mutations
            .iter()
            .filter_map(|mutation| match mutation {
                CompiledActionMutation::Set { field, .. } => Some(field.as_str()),
                CompiledActionMutation::Clear { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        for field in entity.fields.values().filter(|field| field.required) {
            if !written.contains(field.id.as_str()) {
                errors.push(Diagnostic::error(
                    "action.effect.create_required_field_missing",
                    "actions[].effects[].set",
                    "create effects must set every required target field",
                ));
            }
        }
    }
}

fn remember_effect_use(
    effect_id: &str,
    operation: Operation,
    target: &CompiledActionTarget,
    mutations: &[CompiledActionMutation],
    target_uses: &mut BTreeMap<(String, String, Operation), CompiledActionTargetUse>,
) {
    let fields = mutations
        .iter()
        .map(|mutation| match mutation {
            CompiledActionMutation::Set { field, .. } | CompiledActionMutation::Clear { field } => {
                field.clone()
            }
        })
        .collect::<BTreeSet<_>>();
    let (key_id, source, condition_required) = match &target.binding {
        CompiledActionTargetBinding::Create => (
            format!("effect:{effect_id}"),
            CompiledActionTargetUseSource::Effect {
                effect: effect_id.to_owned(),
            },
            false,
        ),
        CompiledActionTargetBinding::Existing { input } => (
            format!("input:{input}"),
            CompiledActionTargetUseSource::Input {
                input: input.clone(),
            },
            true,
        ),
    };
    let key = (target.entity_id.clone(), key_id, operation);
    target_uses
        .entry(key)
        .and_modify(|use_| use_.fields.extend(fields.iter().cloned()))
        .or_insert_with(|| CompiledActionTargetUse {
            entity_id: target.entity_id.clone(),
            operation,
            fields,
            source,
            condition_required,
        });
}

fn remember_link_reference_use(
    input_id: &str,
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    target_uses: &mut BTreeMap<(String, String, Operation), CompiledActionTargetUse>,
) {
    let Some(input) = inputs.get(input_id) else {
        return;
    };
    let FieldTypeSource::Reference { target, .. } = &input.field_type else {
        return;
    };
    let key = (
        target.clone(),
        format!("input:{input_id}"),
        Operation::Invoke,
    );
    target_uses
        .entry(key)
        .or_insert_with(|| CompiledActionTargetUse {
            entity_id: target.clone(),
            operation: Operation::Invoke,
            fields: BTreeSet::new(),
            source: CompiledActionTargetUseSource::Input {
                input: input_id.to_owned(),
            },
            condition_required: false,
        });
}

fn remember_write(
    writes: &mut BTreeMap<(String, String), String>,
    target: &CompiledActionTarget,
    field: &str,
    effect_id: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let key = (
        write_target_binding_key(target, effect_id),
        field.to_owned(),
    );
    if let Some(existing) = writes.insert(key, effect_id.to_owned()) {
        if existing != effect_id {
            errors.push(Diagnostic::error(
                "action.effect.overlapping_write",
                "actions[].effects[]",
                "immediate-action effects cannot write the same target field more than once",
            ));
        } else {
            errors.push(Diagnostic::error(
                "action.effect.overlapping_write",
                "actions[].effects[]",
                "an immediate-action effect cannot both set and clear the same target field",
            ));
        }
    }
}

fn order_effects(
    effects: BTreeMap<String, CompiledActionEffect>,
    errors: &mut Vec<Diagnostic>,
) -> Option<Vec<CompiledActionEffect>> {
    let mut state = BTreeMap::<String, VisitState>::new();
    let mut ordered = Vec::new();
    for id in effects.keys() {
        visit_effect(id, &effects, &mut state, &mut ordered, errors);
    }
    if errors
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.dependency_cycle")
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
    effects: &BTreeMap<String, CompiledActionEffect>,
    state: &mut BTreeMap<String, VisitState>,
    ordered: &mut Vec<String>,
    errors: &mut Vec<Diagnostic>,
) {
    match state.get(id).copied() {
        Some(VisitState::Done) => return,
        Some(VisitState::Visiting) => {
            errors.push(Diagnostic::error(
                "action.effect.dependency_cycle",
                "actions[].effects[]",
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
    inputs: &[CompiledActionInput],
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledActionEffect],
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) {
    let target_count = target_uses
        .iter()
        .map(|use_| match &use_.source {
            CompiledActionTargetUseSource::Effect { effect } => {
                format!("effect:{}:{}", use_.entity_id, effect)
            }
            CompiledActionTargetUseSource::Input { input } => {
                format!("input:{}:{}", use_.entity_id, input)
            }
        })
        .collect::<BTreeSet<_>>()
        .len();
    if target_count > usize::from(MAX_CHANGE_REQUEST_TARGETS) {
        errors.push(Diagnostic::error(
            "action.bounds.targets",
            "actions[].effects",
            "an immediate-action plan exceeds the supported target-record ceiling",
        ));
    }
    let mutation_count: usize = effects.iter().map(|effect| effect.mutations.len()).sum();
    if mutation_count > usize::from(MAX_CHANGE_REQUEST_FIELD_MUTATIONS) {
        errors.push(Diagnostic::error(
            "action.bounds.field_mutations",
            "actions[].effects",
            "an immediate-action plan exceeds the supported field-mutation ceiling",
        ));
    }
    match maximum_snapshot_bytes(inputs, entities, effects) {
        Some(bytes) if bytes <= u64::from(MAX_CHANGE_REQUEST_SNAPSHOT_BYTES) => {}
        Some(_) => errors.push(Diagnostic::error(
            "action.bounds.snapshot_bytes",
            "actions[].effects",
            "an immediate-action plan exceeds the supported snapshot-size ceiling",
        )),
        None => errors.push(Diagnostic::error(
            "action.bounds.snapshot_unknown",
            "actions[].effects",
            "an immediate-action plan contains a field whose snapshot size cannot be bounded",
        )),
    }
}

fn maximum_snapshot_bytes(
    inputs: &[CompiledActionInput],
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledActionEffect],
) -> Option<u64> {
    let mut total = 2_u64;
    for input in inputs {
        let max = maximum_field_json_bytes(&input.field_type)?;
        total = total
            .checked_add(input.id.len() as u64 + 3)?
            .checked_add(if input.required { max } else { max.max(4) })?;
    }
    for effect in effects {
        let target = entities.get(&effect.target.entity_id)?;
        total = total
            .checked_add(effect.id.len() as u64 + effect.target.entity_id.len() as u64 + 32)?;
        for mutation in &effect.mutations {
            let field = match mutation {
                CompiledActionMutation::Set { field, .. }
                | CompiledActionMutation::Clear { field } => field,
            };
            let target_field = target.fields.get(field)?;
            let max = maximum_field_json_bytes(&target_field.field_type)?;
            let before = max.max(4);
            let after = match mutation {
                CompiledActionMutation::Set { .. } => max,
                CompiledActionMutation::Clear { .. } => 4,
            };
            total = total
                .checked_add(field.len() as u64 + 8)?
                .checked_add(before)?
                .checked_add(after)?;
        }
    }
    Some(total)
}

fn compile_grants(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    target_uses: &[CompiledActionTargetUse],
    result_effects: &BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionGrant> {
    let mut grants = Vec::new();
    let mut profile_action = BTreeSet::new();
    for profile in profiles {
        for grant in profile
            .grants
            .iter()
            .filter(|grant| grant.action.as_deref() == Some(action.id.as_str()))
        {
            if !profile_action.insert((profile.id.as_str(), action.id.as_str())) {
                errors.push(Diagnostic::error(
                    "action.grant.duplicate",
                    "project.accessProfiles[].grants[].action",
                    "an access profile cannot grant the same action more than once",
                ));
            }
            if profile.anonymous {
                errors.push(Diagnostic::error(
                    "action.grant.anonymous_forbidden",
                    "project.accessProfiles[].grants[].action",
                    "anonymous access profiles cannot invoke immediate actions",
                ));
            }
            if !grant.entity.is_empty() {
                errors.push(Diagnostic::error(
                    "action.grant.exclusive",
                    "project.accessProfiles[].grants[]",
                    "an access grant must name either one entity or one action",
                ));
            }
            if grant.operations != BTreeSet::from([Operation::Invoke]) {
                errors.push(Diagnostic::error(
                    "action.grant.operation.invalid",
                    "project.accessProfiles[].grants[].operations",
                    "immediate-action grants support only the invoke operation",
                ));
            }
            if !entity_grant_fields_empty(grant) {
                errors.push(Diagnostic::error(
                    "action.grant.entity_fields_forbidden",
                    "project.accessProfiles[].grants[]",
                    "action grants cannot declare entity projection, query, request, or writable fields",
                ));
            }
            let targets = compile_grant_targets(entities, profile, grant, errors);
            validate_grant_covers_uses(&targets, target_uses, errors);
            for result in &grant.results {
                if !result_effects.contains(result) {
                    errors.push(Diagnostic::error(
                        "action.grant.result_unknown",
                        "project.accessProfiles[].grants[].results",
                        "action result grants must name declared effect identifiers",
                    ));
                }
            }
            grants.push(CompiledActionGrant {
                profile_id: profile.id.clone(),
                default: profile.default,
                anonymous: profile.anonymous,
                principal_claim: profile.principal_claim.clone(),
                required_scopes: profile.required_scopes.clone(),
                required_purposes: profile.required_purposes.clone(),
                operations: grant.operations.clone(),
                targets,
                results: grant.results.clone(),
            });
        }
    }
    grants.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    grants
}

fn validate_action_grant_sources(
    actions: &BTreeMap<String, CollectedActionSource>,
    profiles: &[ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) {
    for profile in profiles {
        for grant in &profile.grants {
            match (grant.entity.is_empty(), grant.action.as_deref()) {
                (true, None) => errors.push(Diagnostic::error(
                    "access_profile.grant.target_missing",
                    "project.accessProfiles[].grants[]",
                    "an access grant must name either one entity or one action",
                )),
                (false, Some(_)) => errors.push(Diagnostic::error(
                    "access_profile.grant.target_exclusive",
                    "project.accessProfiles[].grants[]",
                    "an access grant must name either one entity or one action",
                )),
                (true, Some(action)) if !actions.contains_key(action) => {
                    errors.push(Diagnostic::error(
                        "action.grant.action_unknown",
                        "project.accessProfiles[].grants[].action",
                        "an action grant refers to an unknown action",
                    ));
                }
                _ => {}
            }
        }
    }
}

fn compile_grant_targets(
    entities: &BTreeMap<String, CompiledEntity>,
    profile: &ProjectAccessProfileSource,
    grant: &crate::contract::AccessGrantSource,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionTargetGrant> {
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for target in &grant.targets {
        if !seen.insert(target.entity.as_str()) {
            errors.push(Diagnostic::error(
                "action.grant.target.duplicate",
                "project.accessProfiles[].grants[].targets[].entity",
                "action target grants must be unique per entity",
            ));
        }
        let Some(entity) = entities.get(&target.entity) else {
            errors.push(Diagnostic::error(
                "action.grant.target_unknown",
                "project.accessProfiles[].grants[].targets[].entity",
                "an action target grant refers to an unknown entity",
            ));
            continue;
        };
        validate_row_boundaries(
            entity,
            &target.row_boundaries,
            "project.accessProfiles[].grants[].targets[].rowBoundaries",
            errors,
        );
        validate_grant_access_requirements(
            entity,
            profile,
            &target.row_boundaries,
            "project.accessProfiles[].grants[].targets",
            errors,
        );
        targets.push(CompiledActionTargetGrant {
            entity_id: target.entity.clone(),
            row_boundaries: target.row_boundaries.clone(),
        });
    }
    targets.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
    targets
}

fn validate_grant_covers_uses(
    targets: &[CompiledActionTargetGrant],
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) {
    for use_ in target_uses {
        if !targets
            .iter()
            .any(|target| target.entity_id == use_.entity_id)
        {
            errors.push(Diagnostic::error(
                "action.grant.targets.incomplete",
                "project.accessProfiles[].grants[].targets",
                "action grants must cover every created, patched, and referenced target entity",
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
                "action.grant.row_boundary_invalid",
                path,
                "action target row boundaries must be direct, non-empty, and duplicate-free",
            ));
        }
        if boundary.field == "id" {
            continue;
        }
        let Some(field) = entity.fields.get(&boundary.field) else {
            errors.push(Diagnostic::error(
                "action.grant.row_boundary_field_unknown",
                path,
                "an action target row boundary refers to an unknown field",
            ));
            continue;
        };
        if matches!(
            field.field_type,
            FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
        ) {
            errors.push(Diagnostic::error(
                "action.grant.row_boundary_type_unsupported",
                path,
                "CRS84 point and structured fields cannot be action target row-boundary fields",
            ));
        }
    }
}

fn validate_grant_access_requirements(
    entity: &CompiledEntity,
    profile: &ProjectAccessProfileSource,
    row_boundaries: &[RowBoundarySource],
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(requirements) = &entity.access_requirements {
        let grant_profile = AccessProfileSource {
            id: profile.id.clone(),
            default: profile.default,
            anonymous: profile.anonymous,
            principal_claim: profile.principal_claim.clone(),
            required_scopes: profile.required_scopes.clone(),
            required_purposes: profile.required_purposes.clone(),
            operations: BTreeSet::from([Operation::Invoke]),
            readable_fields: BTreeSet::new(),
            writable_fields: BTreeSet::new(),
            filterable_fields: BTreeSet::new(),
            sortable_fields: BTreeSet::new(),
            row_boundaries: row_boundaries.to_vec(),
            lookups: Vec::new(),
            read_paths: Vec::new(),
            review_stages: Vec::new(),
            apply_targets: Vec::new(),
            request_presence: Vec::new(),
            allow_count: false,
            revision_access: false,
            provenance_fields: Vec::new(),
            allow_data_export: false,
        };
        crate::access::check_profile(requirements, &grant_profile, path, errors);
    }
}

fn compile_action_routes(
    action: &CompiledAction,
    profiles: &[ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionRoute> {
    let route_profiles = action
        .grants
        .iter()
        .filter_map(|grant| {
            profiles
                .iter()
                .find(|profile| profile.id == grant.profile_id)
                .map(|profile| (grant, profile))
        })
        .collect::<Vec<_>>();
    if route_profiles.is_empty() {
        return Vec::new();
    }
    let Some(default) = route_default_profile(
        &route_profiles
            .iter()
            .map(|(_, profile)| *profile)
            .collect::<Vec<_>>(),
        errors,
    ) else {
        return Vec::new();
    };
    let profile_ids = route_profiles
        .iter()
        .map(|(_, profile)| profile.id.clone())
        .collect::<BTreeSet<_>>();
    let mut routes = vec![CompiledActionRoute {
        id: format!("actions.{}.invoke", action.id),
        action_id: action.id.clone(),
        kind: ActionRouteKind::Invoke,
        method: HttpMethod::Post,
        path: action.route.clone(),
        operation: Operation::Invoke,
        access_profiles: profile_ids.iter().cloned().collect(),
        default_access_profile: default.id.clone(),
    }];
    if let Some(path) = &action.condition_route {
        routes.push(CompiledActionRoute {
            id: format!("actions.{}.target_conditions", action.id),
            action_id: action.id.clone(),
            kind: ActionRouteKind::TargetConditions,
            method: HttpMethod::Post,
            path: path.clone(),
            operation: Operation::Invoke,
            access_profiles: profile_ids.iter().cloned().collect(),
            default_access_profile: default.id.clone(),
        });
    }
    routes
}

fn route_default_profile<'a>(
    profiles: &[&'a ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) -> Option<&'a ProjectAccessProfileSource> {
    if profiles.len() == 1 {
        return Some(profiles[0]);
    }
    let defaults = profiles
        .iter()
        .copied()
        .filter(|profile| profile.default)
        .collect::<Vec<_>>();
    if defaults.len() == 1 {
        return Some(defaults[0]);
    }
    errors.push(Diagnostic::error(
        "action.route_access.default_missing",
        "project.accessProfiles[].default",
        "action routes with multiple profiles require exactly one route-eligible default",
    ));
    None
}

fn entity_grant_fields_empty(grant: &crate::contract::AccessGrantSource) -> bool {
    grant.readable_fields.is_empty()
        && grant.writable_fields.is_empty()
        && grant.filterable_fields.is_empty()
        && grant.sortable_fields.is_empty()
        && grant.row_boundaries.is_empty()
        && grant.lookups.is_empty()
        && grant.read_paths.is_empty()
        && grant.review_stages.is_empty()
        && grant.apply_targets.is_empty()
        && grant.request_presence.is_empty()
        && !grant.allow_count
        && !grant.revision_access
        && !grant.allow_data_export
}

fn contract_fingerprint(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    inputs: &[CompiledActionInput],
    effects: &[CompiledActionEffect],
    grants: &[CompiledActionGrant],
) -> String {
    let target_entities = effects
        .iter()
        .map(|effect| effect.target.entity_id.as_str())
        .collect::<BTreeSet<_>>();
    let target_contracts = target_entities
        .iter()
        .filter_map(|entity_id| {
            entities
                .get(*entity_id)
                .map(|entity| ((*entity_id).to_owned(), entity_contract_payload(entity)))
        })
        .collect::<BTreeMap<_, _>>();
    let payload = json!({
        "version": 1,
        "id": action.id,
        "inputs": inputs,
        "targetEntities": target_contracts,
        "effects": effects,
        "grants": grants,
        "limits": {
            "maximumTargets": MAX_CHANGE_REQUEST_TARGETS,
            "maximumFieldMutations": MAX_CHANGE_REQUEST_FIELD_MUTATIONS,
            "maximumSnapshotBytes": MAX_CHANGE_REQUEST_SNAPSHOT_BYTES
        }
    });
    let bytes = canonicalize_json(&payload).expect("compiled immediate action canonicalizes");
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
        "accessRequirements": entity.access_requirements,
        "fields": fields,
        "constraints": entity.constraints,
        "changeControl": entity.change_control,
    })
}

fn validate_field_type_bounds(
    field_type: &FieldTypeSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    match field_type {
        FieldTypeSource::String {
            min_length,
            max_length,
        } if *max_length == 0 || *max_length > 1_000_000 || min_length > max_length => {
            errors.push(Diagnostic::error(
                "action.input.string.bounds_invalid",
                path,
                "string length bounds are invalid",
            ))
        }
        FieldTypeSource::Text { max_length } if *max_length == 0 || *max_length > 10_000_000 => {
            errors.push(Diagnostic::error(
                "action.input.text.bound_invalid",
                path,
                "text length bound must be positive",
            ));
        }
        FieldTypeSource::VocabularyCode { values, .. }
            if values.is_empty()
                || has_duplicates(values)
                || values.iter().any(|value| !valid_code(value)) =>
        {
            errors.push(Diagnostic::error(
                "action.input.vocabulary.values_invalid",
                path,
                "a vocabulary input requires a non-empty duplicate-free value set",
            ));
        }
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } if !crate::contract::valid_decimal_bounds(
            *precision,
            *scale,
            minimum.as_deref(),
            maximum.as_deref(),
        ) =>
        {
            errors.push(Diagnostic::error(
                "action.input.decimal.bounds_invalid",
                path,
                "decimal precision, scale, or canonical bounds are invalid",
            ));
        }
        FieldTypeSource::Reference { target, .. } if target.is_empty() => {
            errors.push(Diagnostic::error(
                "action.input.reference.target_invalid",
                path,
                "a reference input must name a target entity",
            ));
        }
        FieldTypeSource::Crs84Point { precision, bbox }
            if *precision > 9
                || bbox.as_ref().is_some_and(|bbox| {
                    crate::contract::parsed_bbox(bbox, *precision).is_none()
                }) =>
        {
            errors.push(Diagnostic::error(
                "action.input.crs84_point.bounds_invalid",
                path,
                "CRS84 point precision or CRS84 bounding box is invalid",
            ));
        }
        FieldTypeSource::Structured { max_bytes, schema }
            if *max_bytes == 0
                || *max_bytes > crate::contract::MAX_STRUCTURED_VALUE_BYTES
                || !crate::contract::valid_structured_schema(schema) =>
        {
            errors.push(Diagnostic::error(
                "action.input.structured.schema_invalid",
                path,
                "structured input schema or byte bound is invalid",
            ));
        }
        _ => {}
    }
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

fn compatible_field_types(source: &FieldTypeSource, target: &FieldTypeSource) -> bool {
    source == target
}

fn effect_id(effect: &ActionEffectSource, index: usize) -> String {
    effect
        .id
        .clone()
        .unwrap_or_else(|| format!("effect-{}", index + 1))
}

fn write_target_binding_key(target: &CompiledActionTarget, effect_id: &str) -> String {
    match &target.binding {
        CompiledActionTargetBinding::Create => format!("create:{}:{}", target.entity_id, effect_id),
        CompiledActionTargetBinding::Existing { input } => {
            format!("existing:{}:{}", target.entity_id, input)
        }
    }
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

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn valid_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
