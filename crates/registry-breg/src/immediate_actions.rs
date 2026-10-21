// SPDX-License-Identifier: Apache-2.0
//! Immediate-action authoring compilation.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::contract::{
    AccessProfileSource, ActionEffectSource, ActionSource, ActionValueSource, FieldTypeSource,
    Operation, ProjectAccessProfileSource, RowBoundarySource, DECIMAL_BOUNDS_REQUIREMENTS,
};
use crate::diagnostics::Diagnostic;
use crate::logical_names::{default_api_name, reserved_logical_name, valid_api_name};
mod commit_evidence;
use crate::model::{
    ActionRouteKind, CompiledAction, CompiledActionAccessEntry, CompiledActionInput,
    CompiledActionInventory, CompiledActionPermission, CompiledActionRoute,
    CompiledActionTargetPermission, CompiledActionTargetUse, CompiledActionTargetUseSource,
    CompiledCommitGuard, CompiledEntity, CompiledPlanEffect, CompiledPlanMutation,
    CompiledPlanTarget, CompiledPlanTargetBinding, CompiledPlanValue, HttpMethod,
};
use crate::plan::{MAX_PLAN_FIELD_MUTATIONS, MAX_PLAN_SNAPSHOT_BYTES, MAX_PLAN_TARGETS};

type CompiledEffectSet = (
    Vec<CompiledPlanEffect>,
    Vec<CompiledActionTargetUse>,
    BTreeSet<String>,
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedActionSource {
    pub source: ActionSource,
    pub source_module: Option<String>,
}

pub(crate) struct CollectedFunctionSource {
    pub source: crate::contract::FunctionSource,
    pub source_module: Option<String>,
}

pub(crate) fn compile_immediate_actions(
    actions: &BTreeMap<String, CollectedActionSource>,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    assets: &[crate::contract::ModuleAssetSource],
    functions: &BTreeMap<String, CollectedFunctionSource>,
    review_authorities: &[crate::contract::ReviewAuthoritySource],
    project: &crate::contract::RegistryProject,
) -> Result<CompiledActionInventory, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    validate_action_permission_sources(actions, profiles, &mut errors);
    let mut compiled_actions = Vec::new();
    let mut routes = Vec::new();
    let mut access = Vec::new();
    let mut wasm_module_count = 0usize;
    for collected in actions.values() {
        let diagnostics_start = errors.len();
        if let Some(compiled) = compile_action(
            collected,
            entities,
            profiles,
            assets,
            functions,
            review_authorities,
            project,
            &mut wasm_module_count,
            &mut errors,
        ) {
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
        for diagnostic in &mut errors[diagnostics_start..] {
            diagnostic.path = diagnostic.path.replacen(
                "actions[]",
                &format!("actions[{}]", collected.source.id),
                1,
            );
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

#[allow(clippy::too_many_arguments)]
fn compile_action(
    collected: &CollectedActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    assets: &[crate::contract::ModuleAssetSource],
    functions: &BTreeMap<String, CollectedFunctionSource>,
    review_authorities: &[crate::contract::ReviewAuthoritySource],
    project: &crate::contract::RegistryProject,
    wasm_module_count: &mut usize,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledAction> {
    let action = &collected.source;
    validate_id(&action.id, "actions[].id", errors);
    if action
        .evidence
        .len()
        .saturating_add(action.commit_guards.evidence.len())
        > crate::action_evidence_contracts::MAX_EVIDENCE_CAPABILITIES
    {
        errors.push(Diagnostic::error(
            "breg.action.evidence-capabilities-bounds",
            "actions[].commitGuards.evidence",
            "plan and commit Evidence together support at most two capabilities",
        ));
    }
    if action.is_proposal() && action.consent_issuer.is_some() {
        errors.push(Diagnostic::error(
            "breg.action.proposal-consent-unsupported",
            "actions[].consentIssuer",
            "consentIssuer requires immediate Action authority semantics",
        ));
    }
    crate::consent::validate_action(action, entities, profiles, errors);
    if action.inputs.is_empty() {
        errors.push(Diagnostic::error(
            "breg.action.inputs-empty",
            "actions[].inputs",
            "an Action must declare at least one typed input",
        ));
    }
    let inputs = compile_inputs(action, entities, errors);
    let input_map = inputs
        .iter()
        .map(|input| (input.id.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    let (handler, (effects, mut target_uses, result_effects)) =
        if let crate::contract::ActionPlanSource::Function {
            function,
            inputs: bound_inputs,
            writes,
            refusals,
            capabilities,
        } = &action.plan
        {
            let Some(function_source) = functions.get(function) else {
                errors.push(Diagnostic::error(
                    "breg.action.function-unknown",
                    "actions[].plan.function",
                    "the plan must reference a declared function",
                ));
                return None;
            };
            let function = &function_source.source;
            if !capabilities.is_subset(&function.capabilities)
                || function.abi != crate::contract::ACTION_PLAN_ABI_V1
            {
                errors.push(Diagnostic::error("breg.action.function-contract-invalid", "actions[].plan.function", "the function requires the action-plan ABI and a capability ceiling containing every bound capability"));
            }
            if action.is_proposal()
                && (function.runtime != crate::contract::ActionHandlerKindSource::Rhai
                    || !capabilities.is_empty()
                    || !action.evidence.is_empty())
            {
                errors.push(Diagnostic::error("breg.action.proposal-capability-unsupported", "actions[].plan", "proposal planning is input-only Rhai; remove unsupported capabilities or runtime"));
            }
            if bound_inputs.iter().collect::<BTreeSet<_>>().len() != bound_inputs.len()
                || bound_inputs
                    .iter()
                    .any(|input| !input_map.contains_key(input.as_str()))
            {
                errors.push(Diagnostic::error(
                    "breg.action.function-input-unknown",
                    "actions[].plan.inputs",
                    "function inputs must uniquely name declared Action inputs",
                ));
            }
            let source = crate::contract::ActionHandlerSource {
                handler: match function.runtime {
                    crate::contract::ActionHandlerKindSource::Rhai => {
                        crate::contract::HookHandlerSource::Rhai {
                            script: function.source.clone(),
                            abi: Some(function.abi.clone()),
                        }
                    }
                    crate::contract::ActionHandlerKindSource::Wasm => {
                        crate::contract::HookHandlerSource::Wasm {
                            module: function.source.clone(),
                            abi: Some(function.abi.clone()),
                        }
                    }
                },
                writes: writes.clone(),
                refusals: refusals.clone(),
            };
            let function_inputs = bound_inputs
                .iter()
                .filter_map(|id| {
                    input_map
                        .get(id.as_str())
                        .map(|input| (id.as_str(), *input))
                })
                .collect::<BTreeMap<_, _>>();
            let (handler, effects) = compile_handler(
                collected,
                &source,
                function,
                function_source.source_module.as_deref(),
                bound_inputs,
                capabilities,
                &function_inputs,
                entities,
                assets,
                wasm_module_count,
                errors,
            )?;
            (Some(handler), effects)
        } else {
            (None, compile_effects(action, &input_map, entities, errors)?)
        };
    for input in &inputs {
        let FieldTypeSource::Reference { target, .. } = &input.field_type else {
            continue;
        };
        if !target_uses.iter().any(|use_| matches!(&use_.source, CompiledActionTargetUseSource::Input { input: binding } if binding == &input.id)) {
            target_uses.push(CompiledActionTargetUse { entity_id: target.clone(), operation: Operation::Get, fields: BTreeSet::new(), source: CompiledActionTargetUseSource::Input { input: input.id.clone() }, condition_required: false });
        }
    }
    for guard in &action.commit_guards.targets {
        let Some(input) = input_map.get(guard.input.as_str()) else {
            continue;
        };
        let FieldTypeSource::Reference { target, .. } = &input.field_type else {
            continue;
        };
        if let Some(use_) = target_uses.iter_mut().find(|use_| {
            use_.operation == Operation::Get
                && matches!(&use_.source,
            CompiledActionTargetUseSource::Input {input} if input == &guard.input)
        }) {
            if !guard.field.is_empty() {
                use_.fields.insert(guard.field.clone());
            }
            use_.condition_required |= !action.is_proposal() && guard.revision.is_some();
        } else {
            target_uses.push(CompiledActionTargetUse {
                entity_id: target.clone(),
                operation: Operation::Get,
                fields: if guard.field.is_empty() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([guard.field.clone()])
                },
                source: CompiledActionTargetUseSource::Input {
                    input: guard.input.clone(),
                },
                condition_required: !action.is_proposal() && guard.revision.is_some(),
            });
        }
    }
    let commit_evidence = commit_evidence::compile(
        project,
        action,
        &input_map,
        entities,
        assets,
        &mut target_uses,
        errors,
    );
    if let crate::contract::ActionExecutionSource::Proposal { proposal } = &action.execution {
        if let Some(context) = &proposal.review_context {
            for projection in context.fields.values() {
                if let crate::contract::ProposalContextValueSource::Record { input, field } =
                    projection
                {
                    if let Some(binding) = input_map.get(input.as_str()) {
                        if let FieldTypeSource::Reference { target, .. } = &binding.field_type {
                            if let Some(existing) = target_uses.iter_mut().find(|use_| use_.operation == Operation::Get && matches!(&use_.source, CompiledActionTargetUseSource::Input { input: selected } if selected == input)) {
                                existing.fields.insert(field.clone());
                            } else {
                                target_uses.push(CompiledActionTargetUse { entity_id: target.clone(), operation: Operation::Get, fields: BTreeSet::from([field.clone()]), source: CompiledActionTargetUseSource::Input { input: input.clone() }, condition_required: false });
                            }
                        }
                    }
                }
            }
        }
    }
    let requires = compile_requirements(action, &input_map, entities, &target_uses, errors);
    let writes_path = if handler.is_some() {
        "actions[].plan.writes"
    } else {
        "actions[].plan.effects"
    };
    validate_plan_bounds(
        writes_path,
        &inputs,
        entities,
        &effects,
        &target_uses,
        errors,
    );
    let permissions = compile_permissions(
        action,
        entities,
        profiles,
        &target_uses,
        &result_effects,
        errors,
    );
    if permissions.is_empty() {
        errors.push(Diagnostic::error(
            "breg.action.permission-missing",
            "project.accessProfiles[].permissions.actions",
            "an Action requires at least one explicit invoke permission",
        ));
    }
    let condition_route = (!action.is_proposal()
        && target_uses.iter().any(|use_| use_.condition_required))
    .then(|| format!("/v1/actions/{}/target-conditions", action.id));
    let execution = compile_execution(
        action,
        entities,
        profiles,
        review_authorities,
        &target_uses,
        errors,
    );
    let compiled = CompiledAction {
        api_name: action
            .api_name
            .clone()
            .unwrap_or_else(|| default_api_name(&action.id)),
        display: action.display.clone(),
        execution,
        definition_revision: String::new(),
        evidence: Vec::new(),
        commit_evidence,
        id: action.id.clone(),
        source_module: collected.source_module.clone(),
        route: format!(
            "/v1/actions/{}{}",
            action.id,
            if action.is_proposal() {
                "/proposals"
            } else {
                ""
            }
        ),
        condition_route,
        handler,
        inputs,
        effects,
        requires,
        target_uses,
        permissions,
        result_effects,
        maximum_targets: MAX_PLAN_TARGETS,
        maximum_field_mutations: MAX_PLAN_FIELD_MUTATIONS,
        maximum_snapshot_bytes: MAX_PLAN_SNAPSHOT_BYTES,
        consent_issuer: action.consent_issuer,
    };
    Some(compiled)
}

#[allow(clippy::too_many_arguments)]
fn compile_handler(
    collected: &CollectedActionSource,
    source: &crate::contract::ActionHandlerSource,
    function: &crate::contract::FunctionSource,
    function_module: Option<&str>,
    bound_inputs: &[String],
    capabilities: &BTreeSet<String>,
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    entities: &BTreeMap<String, CompiledEntity>,
    assets: &[crate::contract::ModuleAssetSource],
    wasm_module_count: &mut usize,
    errors: &mut Vec<Diagnostic>,
) -> Option<(crate::model::CompiledPlanFunction, CompiledEffectSet)> {
    use crate::model::{
        CompiledPlanFunction, CompiledPlanFunctionKind, CompiledPlanFunctionLimits,
        CompiledPlanFunctionWrite, CompiledPlanReferenceSources, CompiledPlanWrite,
    };

    let path = format!("actions[id={}].plan", collected.source.id);
    let function_path = format!("functions[id={}]", function.id);
    let Some(kind) = source.kind() else {
        // The shared handler declaration also offers a remote destination. An
        // action handler runs inside the triggering transaction and has no
        // executor on this path, so the kind is refused rather than compiled
        // into a handler that never runs.
        errors.push(Diagnostic::error(
            "breg.action.handler-kind-unsupported",
            format!("{function_path}.runtime"),
            "a plan function runs in the registry; declare runtime rhai or wasm",
        ));
        return None;
    };
    // A declared backend always carries its ABI: the declaration refuses a
    // handler that leaves it out.
    let abi = source.abi().unwrap_or_default();
    if abi != crate::contract::ACTION_PLAN_ABI_V1 {
        errors.push(Diagnostic::error(
            "breg.action.handler-abi-invalid",
            format!("{function_path}.abi"),
            "the action handler ABI is not supported; declare registry.action-plan/v1",
        ));
    }
    let is_wasm = kind == crate::contract::ActionHandlerKindSource::Wasm;
    #[cfg(not(feature = "wasm"))]
    if is_wasm {
        // Refuse the declared backend explicitly, before any Rhai-shaped
        // validation could misreport the module: this build carries no WASM
        // compiler support.
        errors.push(Diagnostic::error(
            "breg.action.handler-wasm-build-unsupported",
            format!("{function_path}.runtime"),
            "this build of the compiler does not admit WASM action handlers",
        ));
        return None;
    }
    // The authored source reference follows the declared backend exactly.
    let source_path: &str = if is_wasm {
        #[cfg(feature = "wasm")]
        {
            wasm_handler_module_path(source, &function_path, errors)?
        }
        #[cfg(not(feature = "wasm"))]
        {
            return None;
        }
    } else {
        rhai_handler_script_path(source, &function_path, errors)?
    };
    if is_wasm {
        *wasm_module_count += 1;
        if *wasm_module_count > crate::wasm_handler::MAX_PACKAGE_WASM_MODULES {
            errors.push(Diagnostic::error(
                "breg.action.handler-modules-bound",
                format!("{function_path}.source"),
                &format!(
                    "a package carries at most {} WASM handler modules",
                    crate::wasm_handler::MAX_PACKAGE_WASM_MODULES
                ),
            ));
            return None;
        }
    }
    if source.writes.is_empty() {
        errors.push(Diagnostic::error(
            "breg.action.handler-writes-empty",
            format!("{path}.writes"),
            "a handler requires at least one single-use write slot",
        ));
    }
    if inputs.len() > crate::rhai_planner::MAXIMUM_MAP_ENTRIES {
        errors.push(Diagnostic::error(
            "breg.action.handler-inputs-bound",
            format!("actions[{}].inputs", collected.source.id),
            "handler input count exceeds the engine map bound",
        ));
    }
    for input in inputs.values() {
        let input_path = format!("actions[{}].inputs[{}]", collected.source.id, input.id);
        match &input.field_type {
            FieldTypeSource::String { max_length, .. } | FieldTypeSource::Text { max_length }
                if u64::from(*max_length) * 4
                    > crate::rhai_planner::MAXIMUM_STRING_BYTES as u64 =>
            {
                errors.push(Diagnostic::error(
                    "breg.action.handler-input-string-bound",
                    format!("{input_path}.maximumLength"),
                    &format!(
                        "{} input strings support at most {} UTF-8 bytes; set maximumLength to {} or less so every Unicode value fits",
                        abi,
                        crate::rhai_planner::MAXIMUM_STRING_BYTES,
                        crate::rhai_planner::MAXIMUM_STRING_BYTES / 4,
                    ),
                ));
            }
            FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
                errors.push(Diagnostic::error(
                    "breg.action.handler-input-type-unsupported",
                    format!("{input_path}.type"),
                    &format!("{} accepts scalar inputs; use scalar fields or fixed effects for crs84-point and structured values", abi),
                ));
            }
            _ => {}
        }
    }
    if source.writes.len() > usize::from(MAX_PLAN_TARGETS) {
        errors.push(Diagnostic::error(
            "breg.action.handler-slots-bound",
            format!("{path}.writes"),
            "handler slot count exceeds the target ceiling",
        ));
    }
    let input_classification = inputs.values().map(|input| input.classification).max();
    let create_entities = source
        .writes
        .iter()
        .filter(|write| write.operation == Operation::Create)
        .filter_map(|write| write.target.entity.clone())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut writes = Vec::new();
    let mut effects = Vec::new();
    let mut target_uses = BTreeMap::new();
    let mut written = BTreeMap::new();
    for slot in &source.writes {
        let slot_path = format!("{path}.writes[slot={}]", slot.id);
        validate_id(&slot.id, &format!("{slot_path}.id"), errors);
        if !ids.insert(slot.id.clone()) {
            errors.push(Diagnostic::error(
                "breg.action.handler-slot-duplicate",
                &slot_path,
                "handler slot identifiers must be unique",
            ));
        }
        let synthetic = ActionEffectSource {
            id: Some(slot.id.clone()),
            target: slot.target.clone(),
            operation: slot.operation,
            set: BTreeMap::new(),
            clear: Default::default(),
        };
        let diagnostics_start = errors.len();
        let target = compile_target(
            inputs,
            entities,
            &slot.id,
            &synthetic,
            collected.source.is_proposal(),
            errors,
        );
        for diagnostic in &mut errors[diagnostics_start..] {
            diagnostic.path = diagnostic
                .path
                .replacen("actions[].plan.effects[]", &slot_path, 1);
        }
        let Some(target) = target else { continue };
        if let CompiledPlanTargetBinding::Existing { input } = &target.binding {
            if !inputs
                .get(input.as_str())
                .is_some_and(|input| input.required)
            {
                errors.push(Diagnostic::error(
                    "breg.action.handler-target-required",
                    &slot_path,
                    "a patch slot requires a required reference input",
                ));
            }
        }
        let target_entity = &entities[&target.entity_id];
        let mut fields = BTreeSet::new();
        let mut field_types = BTreeMap::new();
        let mut required_fields = BTreeSet::new();
        let mut reference_sources = BTreeMap::new();
        let mut mutations = Vec::new();
        if slot.fields.is_empty() {
            errors.push(Diagnostic::error(
                "breg.action.handler-fields-empty",
                &slot_path,
                "a write slot must declare at least one stored field",
            ));
        }
        for field_id in &slot.fields {
            let field_path = format!("{slot_path}.fields[field={field_id}]");
            if !fields.insert(field_id.clone()) {
                errors.push(Diagnostic::error(
                    "breg.action.handler-field-duplicate",
                    &field_path,
                    "slot fields must be unique",
                ));
            }
            let Some(field) = target_entity.fields.get(field_id) else {
                errors.push(Diagnostic::error(
                    "breg.action.handler-field-unknown",
                    &field_path,
                    "a slot field must name a stored target field",
                ));
                continue;
            };
            if input_classification
                .is_some_and(|classification| classification > field.classification)
            {
                errors.push(Diagnostic::error(
                    "breg.action.handler-classification-ceiling",
                    &field_path,
                    "handler inputs cannot flow to a less classified target field",
                ));
            }
            field_types.insert(field_id.clone(), field.field_type.clone());
            if field.required {
                required_fields.insert(field_id.clone());
            }
            if let FieldTypeSource::Reference {
                target: reference_target,
                ..
            } = &field.field_type
            {
                let reference_inputs = inputs.values().filter(|input| matches!(&input.field_type, FieldTypeSource::Reference { target, .. } if target == reference_target)).map(|input| input.id.clone()).collect::<BTreeSet<_>>();
                let allowed_creates = create_entities
                    .iter()
                    .filter(|entity| *entity == reference_target)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if reference_inputs.is_empty() && allowed_creates.is_empty() {
                    errors.push(Diagnostic::error(
                        "breg.action.handler-reference-source-missing",
                        &field_path,
                        "a reference write requires a compatible declared input or create slot",
                    ));
                }
                for input in &reference_inputs {
                    if !inputs[input.as_str()].required {
                        errors.push(Diagnostic::error(
                            "breg.action.handler-reference-required",
                            format!("actions[{}].inputs[{input}]", collected.source.id),
                            "reference sources admitted by a handler must be required inputs",
                        ));
                    }
                    remember_link_reference_use(input, inputs, &mut target_uses);
                }
                reference_sources.insert(
                    field_id.clone(),
                    CompiledPlanReferenceSources {
                        inputs: reference_inputs,
                        create_entities: allowed_creates,
                    },
                );
            }
            mutations.push(CompiledPlanMutation::Set {
                field: field_id.clone(),
                value: CompiledPlanValue::Literal {
                    value: serde_json::Value::Null,
                },
            });
            remember_write(
                &mut written,
                &target,
                field_id,
                &slot.id,
                &field_path,
                errors,
            );
        }
        if slot.operation == Operation::Create {
            required_fields = target_entity
                .fields
                .values()
                .filter(|field| field.required)
                .map(|field| field.id.clone())
                .collect();
            if !required_fields.is_subset(&fields) {
                errors.push(Diagnostic::error(
                    "breg.action.handler-create-fields-incomplete",
                    &slot_path,
                    "a create slot must include every required stored field",
                ));
            }
        }
        remember_effect_use(
            &slot.id,
            slot.operation,
            &target,
            &mutations,
            &mut target_uses,
        );
        writes.push(CompiledPlanFunctionWrite {
            id: slot.id.clone(),
            ceiling: CompiledPlanWrite {
                target_entity_id: target.entity_id.clone(),
                target_from_input: slot.target.from_field.clone(),
                operation: slot.operation,
                fields,
                field_types,
                required_fields,
                reference_sources,
            },
        });
        effects.push(CompiledPlanEffect {
            id: slot.id.clone(),
            target,
            operation: slot.operation,
            mutations,
            depends_on: BTreeSet::new(),
        });
    }
    let mut refusals = BTreeMap::new();
    for refusal in &source.refusals {
        if !valid_code(&refusal.code)
            || refusal.label.trim().is_empty()
            || refusal.label.len() > 256
            || refusal.label.chars().any(char::is_control)
            || registry_platform_yaml::DisplayText::new(refusal.label.as_str()).is_err()
            || refusals
                .insert(refusal.code.clone(), refusal.label.clone())
                .is_some()
        {
            errors.push(Diagnostic::error("breg.action.handler-refusal-invalid", format!("{path}.refusals"), "refusals require unique bounded codes and non-empty display labels of at most 256 bytes without control or unsafe display characters"));
        }
    }
    if refusals.len() > crate::rhai_planner::MAXIMUM_MAP_ENTRIES {
        errors.push(Diagnostic::error(
            "breg.action.handler-refusal-bound",
            format!("{path}.refusals"),
            "the refusal catalogue exceeds its fixed bound",
        ));
    }
    let Some(asset) = assets
        .iter()
        .find(|asset| asset.module.as_deref() == function_module && asset.path == source_path)
    else {
        let (code, message) = if is_wasm {
            (
                "breg.action.handler-module-asset-missing",
                format!("supply the action's owned handler module asset at {source_path}"),
            )
        } else {
            (
                "breg.action.handler-source-missing",
                format!("supply the action's owned handler asset at {source_path}"),
            )
        };
        errors.push(Diagnostic::error(
            code,
            format!("{function_path}.source"),
            &message,
        ));
        return None;
    };
    if is_wasm {
        if asset.bytes.is_empty()
            || asset.bytes.len() > crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES
        {
            errors.push(Diagnostic::error(
                "breg.action.handler-module-bound",
                format!("{function_path}.source"),
                &format!(
                    "the handler module must be non-empty and at most {} bytes; {} bytes supplied",
                    crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES,
                    asset.bytes.len()
                ),
            ));
            return None;
        }
        if !crate::wasm_handler::is_wasm_binary(&asset.bytes) {
            errors.push(Diagnostic::error(
                "breg.action.handler-module-invalid",
                format!("{function_path}.source"),
                "the handler module must be a WebAssembly binary, not WebAssembly text",
            ));
            return None;
        }
        #[cfg(feature = "wasm")]
        if let Some((code, message)) = crate::wasm_handler::structural_violation(&asset.bytes) {
            errors.push(Diagnostic::error(
                code,
                format!("{function_path}.source"),
                &message,
            ));
            return None;
        }
    } else {
        if asset.bytes.is_empty() || asset.bytes.len() > crate::rhai_planner::MAXIMUM_SOURCE_BYTES {
            errors.push(Diagnostic::error(
                "breg.action.handler-source-bound",
                format!("{function_path}.source"),
                "the handler source must be non-empty and within its fixed byte bound",
            ));
            return None;
        }
        let Ok(script) = std::str::from_utf8(&asset.bytes) else {
            errors.push(Diagnostic::error(
                "breg.action.handler-source-encoding",
                format!("{function_path}.source"),
                "the handler source must be UTF-8",
            ));
            return None;
        };
        if let Err(error) =
            crate::rhai_planner::compile_entrypoint_detailed(script, &function.entrypoint)
        {
            use crate::rhai_planner::EntrypointCompileError;
            let (code, message) = match error {
                EntrypointCompileError::SourceBound => (
                    "breg.action.handler-source-bound",
                    "the handler source exceeds its fixed byte bound".to_owned(),
                ),
                EntrypointCompileError::Parse(position) => {
                    let location = match (position.line(), position.position()) {
                        (Some(line), Some(column)) => format!(" at line {line}, column {column}"),
                        (Some(line), None) => format!(" at line {line}"),
                        _ => String::new(),
                    };
                    (
                        "breg.action.handler-parse",
                        format!("correct the Rhai syntax or unsupported construct{location}"),
                    )
                }
                EntrypointCompileError::Entrypoint => (
                    "breg.action.handler-entrypoint",
                    "declare exactly one public configured function entry point and do not overload functions".to_owned(),
                ),
            };
            let member = if code == "breg.action.handler-entrypoint" {
                "entrypoint"
            } else {
                "source"
            };
            errors.push(Diagnostic::error(
                code,
                format!("{function_path}.{member}"),
                &message,
            ));
            return None;
        }
        // The action's own Evidence declaration is what exposes the helper.
        // Its capabilities are checked against the reviewed contracts after
        // every handler has compiled, and an invalid declaration fails the
        // compile there.
        if crate::action_handler::compile_source_for_function(
            script,
            &function.entrypoint,
            !collected.source.evidence.is_empty(),
        )
        .is_err()
        {
            errors.push(Diagnostic::error(
                "breg.action.handler-helper-contract",
                format!("{function_path}.source"),
                "Evidence helpers require an evidence declaration on the action and evidence::resolve with exactly two arguments",
            ));
            return None;
        }
    }
    let conditioned = target_uses
        .values()
        .filter(|use_| use_.condition_required)
        .filter_map(|use_| match &use_.source {
            CompiledActionTargetUseSource::Input { input } => {
                Some((use_.entity_id.clone(), input.clone()))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let target_uses = target_uses
        .into_values()
        .filter(|use_| {
            use_.condition_required
                || match &use_.source {
                    CompiledActionTargetUseSource::Input { input } => {
                        !conditioned.contains(&(use_.entity_id.clone(), input.clone()))
                    }
                    _ => true,
                }
        })
        .collect();
    Some((
        CompiledPlanFunction {
            id: function.id.clone(),
            entrypoint: function.entrypoint.clone(),
            capabilities: capabilities.clone(),
            bound_inputs: bound_inputs.iter().cloned().collect(),
            kind: if is_wasm {
                CompiledPlanFunctionKind::Wasm
            } else {
                CompiledPlanFunctionKind::Rhai
            },
            source_module: function_module.map(str::to_owned),
            script_path: if is_wasm {
                String::new()
            } else {
                source_path.to_owned()
            },
            module_path: if is_wasm {
                source_path.to_owned()
            } else {
                String::new()
            },
            abi: abi.to_owned(),
            rhai_version: (!is_wasm).then(|| crate::plan::PLAN_RHAI_VERSION.to_owned()),
            script_sha256: (!is_wasm)
                .then(|| format!("sha256:{}", hex_lower(&Sha256::digest(&asset.bytes)))),
            module_sha256: is_wasm
                .then(|| format!("sha256:{}", hex_lower(&Sha256::digest(&asset.bytes)))),
            script_bytes: if is_wasm {
                Vec::new()
            } else {
                asset.bytes.clone()
            },
            module_bytes: if is_wasm {
                asset.bytes.clone()
            } else {
                Vec::new()
            },
            limits: (!is_wasm).then_some(CompiledPlanFunctionLimits {
                maximum_output_bytes: function.limits.maximum_output_bytes,
                maximum_source_bytes: crate::rhai_planner::MAXIMUM_SOURCE_BYTES as u32,
                maximum_operations: function
                    .limits
                    .maximum_operations
                    .min(crate::rhai_planner::MAXIMUM_OPERATIONS),
                maximum_call_depth: crate::rhai_planner::MAXIMUM_CALL_DEPTH as u16,
                maximum_expression_depth: crate::rhai_planner::MAXIMUM_EXPRESSION_DEPTH as u16,
                maximum_string_bytes: crate::rhai_planner::MAXIMUM_STRING_BYTES as u32,
                maximum_array_items: crate::rhai_planner::MAXIMUM_ARRAY_ITEMS as u16,
                maximum_map_entries: crate::rhai_planner::MAXIMUM_MAP_ENTRIES as u16,
                maximum_modules: 0,
            }),
            writes,
            refusals,
        },
        (effects, target_uses, ids),
    ))
}

/// Validate the source asset of an already resolved named Rhai function.
fn rhai_handler_script_path<'a>(
    source: &'a crate::contract::ActionHandlerSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<&'a str> {
    let script = source.script()?;
    if !crate::plan::valid_function_path(script) {
        errors.push(Diagnostic::error(
            "breg.action.handler-source-invalid",
            format!("{path}.source"),
            "the handler script must be a bounded relative .rhai path",
        ));
        return None;
    }
    Some(script)
}

/// Validate the source asset of an already resolved named WASM function.
#[cfg(feature = "wasm")]
fn wasm_handler_module_path<'a>(
    source: &'a crate::contract::ActionHandlerSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<&'a str> {
    let module = source.module()?;
    if !crate::wasm_handler::valid_wasm_module_path(module) {
        errors.push(Diagnostic::error(
            "breg.action.handler-module-source-invalid",
            format!("{path}.source"),
            "the handler module must be a bounded relative .wasm path",
        ));
        return None;
    }
    Some(module)
}

fn compile_requirements(
    action: &ActionSource,
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    entities: &BTreeMap<String, CompiledEntity>,
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledCommitGuard> {
    if action.commit_guards.targets.len() > usize::from(MAX_PLAN_FIELD_MUTATIONS)
        || serde_json::to_vec(&action.commit_guards.targets)
            .map_or(true, |bytes| bytes.len() > MAX_PLAN_SNAPSHOT_BYTES as usize)
    {
        errors.push(Diagnostic::error(
            "breg.action.commit_guards.targets-bounds",
            "actions[].commitGuards.targets",
            "action requirements exceed the supported count or byte ceiling",
        ));
        return Vec::new();
    }
    let mut compiled = Vec::new();
    let mut seen = BTreeSet::new();
    for requirement in &action.commit_guards.targets {
        if !seen.insert((&requirement.input, &requirement.field)) {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-duplicate",
                "actions[].commitGuards.targets",
                "an action can require a target field only once per reference input",
            ));
            continue;
        }
        let Some(input) = inputs.get(requirement.input.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-input-unknown",
                "actions[].commitGuards.targets[].input",
                "an action requirement must name a declared reference input",
            ));
            continue;
        };
        let FieldTypeSource::Reference { target, .. } = &input.field_type else {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-reference-required",
                "actions[].commitGuards.targets[].input",
                "an action requirement must name a required reference input used by its effects",
            ));
            continue;
        };
        if !input.required || !target_uses.iter().any(|target_use| {
            target_use.entity_id == *target
                && matches!(&target_use.source, CompiledActionTargetUseSource::Input { input } if input == &requirement.input)
        }) {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-reference-required",
                "actions[].commitGuards.targets[].input",
                "an action requirement must name a required reference input used by its effects",
            ));
            continue;
        }
        if requirement.revision.is_some() {
            let revision_is_bound = action.is_proposal()
                || target_uses.iter().any(|target| {
                    target.condition_required
                        && matches!(&target.source,
                    CompiledActionTargetUseSource::Input { input } if input == &requirement.input)
                });
            if !revision_is_bound
                || !requirement.field.is_empty()
                || requirement.equals.is_some()
                || requirement.equals_input.is_some()
                || requirement.is_null
                || requirement.at_least.is_some()
                || requirement.at_most.is_some()
                || requirement.current_date.is_some()
            {
                errors.push(Diagnostic::error(
                    "breg.action.guard-revision-invalid",
                    "actions[].commitGuards.targets[].revision",
                    "revision: unchanged requires a frozen Proposal or a bound immediate target condition and no field predicate",
                ));
            } else {
                compiled.push(CompiledCommitGuard {
                    input: requirement.input.clone(),
                    entity_id: target.clone(),
                    field: String::new(),
                    equals: None,
                    equals_input: None,
                    revision_unchanged: true,
                    at_least: None,
                    at_most: None,
                    current_date: None,
                });
            }
            continue;
        }
        let Some(field) = entities
            .get(target)
            .and_then(|entity| entity.fields.get(&requirement.field))
        else {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-field-unknown",
                "actions[].commitGuards.targets[].field",
                "an action requirement must name a stored field of its reference target",
            ));
            continue;
        };
        if field.encryption.is_some() {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-field-encrypted",
                "actions[].commitGuards.targets[].field",
                "an action requirement cannot name an encrypted field",
            ));
            continue;
        }
        let choices = usize::from(requirement.equals.is_some())
            + usize::from(requirement.is_null)
            + usize::from(requirement.equals_input.is_some())
            + usize::from(requirement.at_least.is_some())
            + usize::from(requirement.at_most.is_some())
            + usize::from(requirement.current_date.is_some());
        let literal = requirement.literal();
        let literal_invalid = literal.as_ref().is_some_and(|equals| {
            equals.is_array()
                || equals.is_object()
                || if equals.is_null() {
                    field.required
                } else {
                    !crate::data::validate_field_value(
                        crate::data::FieldValue::Json(equals),
                        &field.field_type,
                    )
                }
        });
        let input_invalid = requirement.equals_input.as_ref().is_some_and(|input_id| {
            inputs.get(input_id.as_str()).is_none_or(|expected| {
                !expected.required
                    || matches!(
                        expected.field_type,
                        FieldTypeSource::Structured { .. } | FieldTypeSource::Crs84Point { .. }
                    )
                    || !compatible_field_types(&expected.field_type, &field.field_type)
            })
        });
        if choices != 1
            || matches!(
                field.field_type,
                FieldTypeSource::Structured { .. } | FieldTypeSource::Crs84Point { .. }
            )
            || literal_invalid
            || input_invalid
            || ((requirement.at_least.is_some() || requirement.at_most.is_some())
                && field.field_type != FieldTypeSource::Int64)
            || (requirement.current_date.is_some() && field.field_type != FieldTypeSource::Date)
        {
            errors.push(Diagnostic::error(
                "breg.action.commit_guards.targets-value-invalid",
                "actions[].commitGuards.targets[]",
                "a guard declares one typed equality, null check, input equality, integer bound, or current-date comparison",
            ));
            continue;
        }
        compiled.push(CompiledCommitGuard {
            input: requirement.input.clone(),
            entity_id: target.clone(),
            field: requirement.field.clone(),
            equals: literal,
            equals_input: requirement.equals_input.clone(),
            revision_unchanged: false,
            at_least: requirement.at_least,
            at_most: requirement.at_most,
            current_date: requirement.current_date.map(|relation| match relation {
                crate::contract::CurrentDatePredicateSource::OnOrAfter => {
                    crate::model::CompiledCurrentDateRelation::OnOrAfter
                }
                crate::contract::CurrentDatePredicateSource::OnOrBefore => {
                    crate::model::CompiledCurrentDateRelation::OnOrBefore
                }
            }),
        });
    }
    compiled.sort_by(|left, right| (&left.input, &left.field).cmp(&(&right.input, &right.field)));
    compiled
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
                "breg.action.input-id-reserved",
                "actions[].inputs[].id",
                "an action input identifier collides with a reserved Registry field",
            ));
        }
        if !ids.insert(input.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.action.input-id-duplicate",
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
                "breg.action.input-api-name-invalid",
                "actions[].inputs[].apiName",
                "an action input API name must be a non-reserved lower camelCase identifier",
            ));
        }
        if !api_names.insert(api_name.clone()) {
            errors.push(Diagnostic::error(
                "breg.action.input-api-name-duplicate",
                "actions[].inputs[].apiName",
                "action input API names must be unique within the action",
            ));
        }
        validate_field_type_bounds(&input.field_type, "actions[].inputs[]", errors);
        if let FieldTypeSource::Reference { target, .. } = &input.field_type {
            if !entities.contains_key(target) {
                errors.push(Diagnostic::error(
                    "breg.action.input-reference-target-unknown",
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
            display: input.display.clone(),
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
    for (index, effect) in action.effects().iter().enumerate() {
        let id = effective_action_effect_id(effect, index);
        validate_id(&id, "actions[].plan.effects[].id", errors);
        if !effect_ids.insert(id.clone()) {
            errors.push(Diagnostic::error(
                "breg.action.effect-id-duplicate",
                "actions[].plan.effects[].id",
                "Action effect identifiers must be duplicate-free",
            ));
        }
        if effect.operation == Operation::Create {
            if effect.id.is_none() {
                errors.push(Diagnostic::error(
                    "breg.action.effect-create-id-required",
                    "actions[].plan.effects[].id",
                    "create effects require an explicit identifier for reserved-record references",
                ));
            }
            if let Some(entity_id) = &effect.target.entity {
                create_targets.insert(id, entity_id.clone());
            }
        }
    }

    let mut compiled_by_id = Vec::new();
    let mut writes = BTreeMap::new();
    let mut target_uses = BTreeMap::<(String, String, Operation), CompiledActionTargetUse>::new();
    for (index, effect) in action.effects().iter().enumerate() {
        let id = effective_action_effect_id(effect, index);
        let Some(target) =
            compile_target(inputs, entities, &id, effect, action.is_proposal(), errors)
        else {
            continue;
        };
        let Some(target_entity) = entities.get(&target.entity_id) else {
            continue;
        };
        if effect.set.is_empty() && effect.clear.is_empty() {
            errors.push(Diagnostic::error(
                "breg.action.effect-empty",
                "actions[].plan.effects[]",
                "an Action effect must set or clear at least one field",
            ));
        }
        let mut mutations = Vec::new();
        let mut depends_on = BTreeSet::new();
        for (field, value) in &effect.set {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-field-unknown",
                    "actions[].plan.effects[].set",
                    "an Action effect writes an unknown stored target field",
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
                if let CompiledPlanValue::FromEffect { effect, .. } = &compiled {
                    depends_on.insert(effect.clone());
                }
                if let CompiledPlanValue::FromInput { input } = &compiled {
                    remember_link_reference_use(input, inputs, &mut target_uses);
                }
                mutations.push(CompiledPlanMutation::Set {
                    field: field.clone(),
                    value: compiled,
                });
                remember_write(
                    &mut writes,
                    &target,
                    field,
                    &id,
                    &format!("actions[].plan.effects[effect={id}].set.{field}"),
                    errors,
                );
            }
        }
        for field in &effect.clear {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-field-unknown",
                    "actions[].plan.effects[].clear",
                    "an Action effect clears an unknown stored target field",
                ));
                continue;
            };
            if effect.operation == Operation::Create {
                errors.push(Diagnostic::error(
                    "breg.action.effect-clear-on-create",
                    "actions[].plan.effects[].clear",
                    "create effects cannot clear target fields",
                ));
            }
            if target_field.required {
                errors.push(Diagnostic::error(
                    "breg.action.effect-clear-required",
                    "actions[].plan.effects[].clear",
                    "required target fields cannot be cleared",
                ));
            }
            mutations.push(CompiledPlanMutation::Clear {
                field: field.clone(),
            });
            remember_write(
                &mut writes,
                &target,
                field,
                &id,
                &format!("actions[].plan.effects[effect={id}].clear"),
                errors,
            );
        }
        remember_effect_use(&id, effect.operation, &target, &mutations, &mut target_uses);
        compiled_by_id.push(CompiledPlanEffect {
            id,
            target,
            operation: effect.operation,
            mutations,
            depends_on,
        });
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
    proposal: bool,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledPlanTarget> {
    if !matches!(effect.operation, Operation::Create | Operation::Patch) {
        errors.push(Diagnostic::error(
            "breg.action.effect-operation-unsupported",
            "actions[].plan.effects[].operation",
            "Action effects can only create or patch target records",
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
                    "breg.action.effect-target-unknown",
                    "actions[].plan.effects[].target.entity",
                    "an Action create target refers to an unknown entity",
                ));
                return None;
            };
            validate_mutable_target(entity, Operation::Create, proposal, errors)?;
            Some(CompiledPlanTarget {
                entity_id: entity_id.clone(),
                binding: CompiledPlanTargetBinding::Create,
            })
        }
        (None, Some(input_id), Operation::Patch) => {
            let Some(input) = inputs.get(input_id.as_str()) else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-target-input-unknown",
                    "actions[].plan.effects[].target.fromInput",
                    "an Action patch target must refer to a declared reference input",
                ));
                return None;
            };
            let FieldTypeSource::Reference { target, .. } = &input.field_type else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-target-reference-required",
                    "actions[].plan.effects[].target.fromInput",
                    "an Action patch target must refer to a reference input",
                ));
                return None;
            };
            let entity = entities.get(target)?;
            validate_mutable_target(entity, Operation::Patch, proposal, errors)?;
            Some(CompiledPlanTarget {
                entity_id: target.clone(),
                binding: CompiledPlanTargetBinding::Existing {
                    input: input_id.clone(),
                },
            })
        }
        _ => {
            let _ = effect_id;
            errors.push(Diagnostic::error(
                "breg.action.effect-target-invalid",
                "actions[].plan.effects[].target",
                "create effects must name an entity and patch effects must name one reference input",
            ));
            None
        }
    }
}

fn validate_mutable_target(
    entity: &CompiledEntity,
    operation: Operation,
    proposal: bool,
    errors: &mut Vec<Diagnostic>,
) -> Option<()> {
    if operation == Operation::Patch
        && entity.mutation_mode == crate::contract::MutationMode::CreateOnly
    {
        errors.push(Diagnostic::error(
            "breg.action.effect-operation-unavailable",
            "actions[].plan.effects[].operation",
            "Actions cannot patch create-only entities",
        ));
        return None;
    }
    if !proposal
        && entity
            .change_control
            .as_ref()
            .is_some_and(|control| control.required_for.contains(&operation))
    {
        errors.push(Diagnostic::error(
            "breg.action.effect-controlled-target",
            "actions[].plan.effects[].target",
            "Actions cannot target operations that require reviewed change control",
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
) -> Option<CompiledPlanValue> {
    if let Some(literal) = &value.value {
        if !literal.is_null() && matches!(target_type, FieldTypeSource::Reference { .. }) {
            errors.push(Diagnostic::error(
                "breg.action.effect-reference-input-required",
                format!("actions[].plan.effects[].set.{target_field}"),
                "a reference must come from a typed input or an earlier create effect so its target can be authorized",
            ));
            return None;
        }
        if value.from_field.is_some()
            || value.from_effect.is_some()
            || (literal.is_null() && target_required)
            || (!literal.is_null()
                && !crate::data::validate_field_value(
                    crate::data::FieldValue::Json(literal),
                    target_type,
                ))
        {
            errors.push(Diagnostic::error("breg.action.effect-value-invalid","actions[].plan.effects[].set","a literal must match its target field and cannot be combined with another value source"));
            return None;
        }
        return Some(CompiledPlanValue::Literal {
            value: literal.clone(),
        });
    }
    match (&value.from_field, &value.from_effect) {
        (Some(input_id), None) => {
            let Some(input) = inputs.get(input_id.as_str()) else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-value-input-unknown",
                    "actions[].plan.effects[].set",
                    "fromField must refer to a declared action input",
                ));
                return None;
            };
            if target_required && !input.required {
                errors.push(Diagnostic::error(
                    "breg.action.effect-value-nullable",
                    "actions[].plan.effects[].set",
                    "a nullable action input cannot populate a required target field",
                ));
            }
            if !compatible_field_types(&input.field_type, target_type) {
                errors.push(Diagnostic::error(
                    "breg.action.effect-value-type-mismatch",
                    format!("actions[].plan.effects[].set.{target_field}"),
                    "fromField input type must match the target field type",
                ));
                return None;
            }
            Some(CompiledPlanValue::FromInput {
                input: input_id.clone(),
            })
        }
        (None, Some(effect_id)) => {
            let Some(target_entity_id) = create_targets.get(effect_id) else {
                errors.push(Diagnostic::error(
                    "breg.action.effect-value-effect-unknown",
                    "actions[].plan.effects[].set",
                    "fromEffect must refer to a declared create effect",
                ));
                return None;
            };
            match target_type {
                FieldTypeSource::Reference { target, .. } if target == target_entity_id => {
                    Some(CompiledPlanValue::FromEffect {
                        effect: effect_id.clone(),
                        target_entity_id: target_entity_id.clone(),
                    })
                }
                FieldTypeSource::Reference { .. } => {
                    errors.push(Diagnostic::error(
                        "breg.action.effect-value-reference-mismatch",
                        format!("actions[].plan.effects[].set.{target_field}"),
                        "fromEffect reserved identity does not match the target reference field",
                    ));
                    None
                }
                _ => {
                    errors.push(Diagnostic::error(
                        "breg.action.effect-value-reference-required",
                        format!("actions[].plan.effects[].set.{target_field}"),
                        "fromEffect can populate only typed reference fields",
                    ));
                    None
                }
            }
        }
        _ => {
            errors.push(Diagnostic::error(
                "breg.action.effect-value-invalid",
                "actions[].plan.effects[].set",
                "effect mappings must declare exactly one fromField or fromEffect source",
            ));
            None
        }
    }
}

fn validate_required_create_fields(
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledPlanEffect],
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
                CompiledPlanMutation::Set { field, .. } => Some(field.as_str()),
                CompiledPlanMutation::Clear { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        for field in entity.fields.values().filter(|field| field.required) {
            if !written.contains(field.id.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.action.effect-create-required-field-missing",
                    "actions[].plan.effects[].set",
                    "create effects must set every required target field",
                ));
            }
        }
    }
}

fn remember_effect_use(
    effect_id: &str,
    operation: Operation,
    target: &CompiledPlanTarget,
    mutations: &[CompiledPlanMutation],
    target_uses: &mut BTreeMap<(String, String, Operation), CompiledActionTargetUse>,
) {
    let fields = mutations
        .iter()
        .map(|mutation| match mutation {
            CompiledPlanMutation::Set { field, .. } | CompiledPlanMutation::Clear { field } => {
                field.clone()
            }
        })
        .collect::<BTreeSet<_>>();
    let (key_id, source, condition_required) = match &target.binding {
        CompiledPlanTargetBinding::Create => (
            format!("effect:{effect_id}"),
            CompiledActionTargetUseSource::Effect {
                effect: effect_id.to_owned(),
            },
            false,
        ),
        CompiledPlanTargetBinding::Existing { input } => (
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
    let key = (target.clone(), format!("input:{input_id}"), Operation::Get);
    target_uses
        .entry(key)
        .or_insert_with(|| CompiledActionTargetUse {
            entity_id: target.clone(),
            operation: Operation::Get,
            fields: BTreeSet::new(),
            source: CompiledActionTargetUseSource::Input {
                input: input_id.to_owned(),
            },
            condition_required: false,
        });
}

fn remember_write(
    writes: &mut BTreeMap<(String, String), String>,
    target: &CompiledPlanTarget,
    field: &str,
    effect_id: &str,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let key = (
        write_target_binding_key(target, effect_id),
        field.to_owned(),
    );
    if let Some(existing) = writes.insert(key, effect_id.to_owned()) {
        if existing != effect_id {
            errors.push(Diagnostic::error(
                "breg.action.effect-overlapping-write",
                path,
                "Action effects cannot write the same target field more than once",
            ));
        } else {
            errors.push(Diagnostic::error(
                "breg.action.effect-overlapping-write",
                path,
                "an Action effect cannot both set and clear the same target field",
            ));
        }
    }
}

fn order_effects(
    effects: Vec<CompiledPlanEffect>,
    errors: &mut Vec<Diagnostic>,
) -> Option<Vec<CompiledPlanEffect>> {
    match crate::plan::order_plan_effects(effects) {
        Ok(effects) => Some(effects),
        Err(failures) => {
            errors.extend(failures);
            None
        }
    }
}

fn validate_plan_bounds(
    path: &str,
    inputs: &[CompiledActionInput],
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledPlanEffect],
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
    if target_count > usize::from(MAX_PLAN_TARGETS) {
        errors.push(Diagnostic::error(
            "breg.action.bounds-targets",
            path,
            "an Action plan exceeds the supported target-record ceiling",
        ));
    }
    let mutation_count: usize = effects.iter().map(|effect| effect.mutations.len()).sum();
    if mutation_count > usize::from(MAX_PLAN_FIELD_MUTATIONS) {
        errors.push(Diagnostic::error(
            "breg.action.bounds-field-mutations",
            path,
            "an Action plan exceeds the supported field-mutation ceiling",
        ));
    }
    match maximum_snapshot_bytes(inputs, entities, effects) {
        Some(bytes) if bytes <= u64::from(MAX_PLAN_SNAPSHOT_BYTES) => {}
        Some(_) => errors.push(Diagnostic::error(
            "breg.action.bounds-snapshot-bytes",
            path,
            "an Action plan exceeds the supported snapshot-size ceiling",
        )),
        None => errors.push(Diagnostic::error(
            "breg.action.bounds-snapshot-unknown",
            path,
            "an Action plan contains a field whose snapshot size cannot be bounded",
        )),
    }
}

fn maximum_snapshot_bytes(
    inputs: &[CompiledActionInput],
    entities: &BTreeMap<String, CompiledEntity>,
    effects: &[CompiledPlanEffect],
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
                CompiledPlanMutation::Set { field, .. } | CompiledPlanMutation::Clear { field } => {
                    field
                }
            };
            let target_field = target.fields.get(field)?;
            let max = maximum_field_json_bytes(&target_field.field_type)?;
            let before = max.max(4);
            let after = match mutation {
                CompiledPlanMutation::Set { .. } => max,
                CompiledPlanMutation::Clear { .. } => 4,
            };
            total = total
                .checked_add(field.len() as u64 + 8)?
                .checked_add(before)?
                .checked_add(after)?;
        }
    }
    Some(total)
}

fn compile_permissions(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    target_uses: &[CompiledActionTargetUse],
    result_effects: &BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionPermission> {
    let mut grants = Vec::new();
    let mut profile_action = BTreeSet::new();
    for profile in profiles {
        for grant in profile
            .permissions
            .actions
            .iter()
            .filter(|grant| grant.action == action.id)
        {
            if !profile_action.insert((profile.id.as_str(), action.id.as_str())) {
                errors.push(Diagnostic::error(
                    "breg.action.permission-duplicate",
                    "project.accessProfiles[].permissions.actions[].action",
                    "an access profile cannot grant the same action more than once",
                ));
            }
            crate::consent::validate_action_permission(profile, grant, entities, errors);
            if *grant.operations
                != BTreeSet::from([if action.is_proposal() {
                    Operation::Start
                } else {
                    Operation::Invoke
                }])
            {
                errors.push(Diagnostic::error(
                    "breg.action.permission-operation-invalid",
                    "project.accessProfiles[].permissions.actions[].operations",
                    "Action permissions support only the invoke operation",
                ));
            }
            let target_locks = compile_permission_targets(entities, profile, grant, errors);
            validate_permission_covers_uses(&target_locks, target_uses, errors);
            let targets = discriminate_permission_targets(&target_locks, target_uses, errors);
            for result in grant.results.iter() {
                if !result_effects.contains(result) {
                    errors.push(Diagnostic::error(
                        "breg.action.permission-result-unknown",
                        "project.accessProfiles[].permissions.actions[].results",
                        "action result permissions must name declared effect identifiers",
                    ));
                }
            }
            grants.push(CompiledActionPermission {
                profile_id: profile.id.clone(),
                default: profile.default,
                actor_kind: profile.actor_kind,
                task_grant: profile.task_grant.clone(),
                requester_clients: profile.requester_clients.as_set().clone(),
                principal_claim: Some(profile.principal_claim.clone()),
                required_scopes: profile.required_scopes.as_set().clone(),
                required_purposes: profile.required_purposes.as_set().clone(),
                operations: grant.operations.clone().into_set(),
                targets,
                results: grant.results.clone().into_set(),
            });
        }
    }
    grants.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    grants
}

fn validate_action_permission_sources(
    actions: &BTreeMap<String, CollectedActionSource>,
    profiles: &[ProjectAccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) {
    for profile in profiles {
        for grant in &profile.permissions.actions {
            if !actions.contains_key(&grant.action) {
                errors.push(Diagnostic::error(
                    "breg.action.permission-action-unknown",
                    "project.accessProfiles[].permissions.actions[].action",
                    "an action permission refers to an unknown action",
                ));
            }
        }
    }
}

/// One authored action target grant before it is discriminated by the
/// action's target uses.
struct PermissionTargetLock {
    entity_id: String,
    row_boundaries: Vec<RowBoundarySource>,
}

fn compile_permission_targets(
    entities: &BTreeMap<String, CompiledEntity>,
    profile: &ProjectAccessProfileSource,
    grant: &crate::contract::ActionPermissionSource,
    errors: &mut Vec<Diagnostic>,
) -> Vec<PermissionTargetLock> {
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for target in &grant.targets {
        if !seen.insert(target.entity.as_str()) {
            errors.push(Diagnostic::error(
                "breg.action.permission-target-duplicate",
                "project.accessProfiles[].permissions.actions[].targets[].entity",
                "action target permissions must be unique per entity",
            ));
        }
        let Some(entity) = entities.get(&target.entity) else {
            errors.push(Diagnostic::error(
                "breg.action.permission-target-unknown",
                "project.accessProfiles[].permissions.actions[].targets[].entity",
                "an action target grant refers to an unknown entity",
            ));
            continue;
        };
        validate_row_boundaries(
            entity,
            &target.row_boundaries,
            "project.accessProfiles[].permissions.actions[].targets[].rowBoundaries",
            errors,
        );
        validate_permission_access_requirements(
            entity,
            profile,
            &target.row_boundaries,
            "project.accessProfiles[].permissions.actions[].targets",
            errors,
        );
        targets.push(PermissionTargetLock {
            entity_id: target.entity.clone(),
            row_boundaries: target.row_boundaries.clone(),
        });
    }
    targets.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
    targets
}

fn discriminate_permission_targets(
    target_locks: &[PermissionTargetLock],
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledActionTargetPermission> {
    let mut targets = Vec::new();
    for target_lock in target_locks {
        let mut matched = false;
        for target_use in target_uses
            .iter()
            .filter(|target_use| target_use.entity_id == target_lock.entity_id)
        {
            matched = true;
            targets.push(CompiledActionTargetPermission {
                entity_id: target_lock.entity_id.clone(),
                operation: target_use.operation,
                source: target_use.source.clone(),
                row_boundaries: target_lock.row_boundaries.clone(),
            });
        }
        if !matched {
            errors.push(Diagnostic::error(
                "breg.action.permission-targets-unused",
                "project.accessProfiles[].permissions.actions[].targets",
                "action permission targets must name an entity the action creates, patches, or references",
            ));
        }
    }
    targets
}

fn validate_permission_covers_uses(
    targets: &[PermissionTargetLock],
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) {
    for use_ in target_uses {
        if !targets
            .iter()
            .any(|target| target.entity_id == use_.entity_id)
        {
            errors.push(Diagnostic::error(
                "breg.action.permission-targets-incomplete",
                "project.accessProfiles[].permissions.actions[].targets",
                "action permissions must cover every created, patched, and referenced target entity",
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
                "breg.action.permission-row-boundary-invalid",
                path,
                "action target row boundaries must be direct, non-empty, and duplicate-free",
            ));
        }
        if boundary.field == "id" {
            continue;
        }
        let Some(field) = entity.fields.get(&boundary.field) else {
            errors.push(Diagnostic::error(
                "breg.action.permission-row-boundary-field-unknown",
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
                "breg.action.permission-row-boundary-type-unsupported",
                path,
                "CRS84 point and structured fields cannot be action target row-boundary fields",
            ));
        }
    }
}

fn validate_permission_access_requirements(
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
            actor_kind: profile.actor_kind,
            requester_clients: profile.requester_clients.clone(),
            task_grant: None,
            principal_claim: profile.principal_claim.clone(),
            required_scopes: profile.required_scopes.clone(),
            required_purposes: profile.required_purposes.clone(),
            operations: [Operation::Invoke].into(),
            readable_fields: Default::default(),
            writable_fields: Default::default(),
            filterable_fields: Default::default(),
            sortable_fields: Default::default(),
            spatial_queries: None,
            row_boundaries: row_boundaries.to_vec(),
            membership_boundaries: Vec::new(),
            require_consent: Vec::new(),
            lookups: Vec::new(),
            read_paths: Vec::new(),
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
        .permissions
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
    let default = route_default_profile(
        &route_profiles
            .iter()
            .map(|(_, profile)| *profile)
            .collect::<Vec<_>>(),
        errors,
    );
    let profile_ids = route_profiles
        .iter()
        .map(|(_, profile)| profile.id.clone())
        .collect::<BTreeSet<_>>();
    let mut routes = vec![CompiledActionRoute {
        id: format!(
            "actions.{}.{}",
            action.id,
            if action.execution.is_proposal() {
                "start"
            } else {
                "invoke"
            }
        ),
        action_id: action.id.clone(),
        kind: ActionRouteKind::Invoke,
        method: HttpMethod::Post,
        path: action.route.clone(),
        operation: if action.execution.is_proposal() {
            Operation::Start
        } else {
            Operation::Invoke
        },
        access_profiles: profile_ids.iter().cloned().collect(),
        default_access_profile: default.map(|profile| profile.id.clone()),
    }];
    if let Some(path) = &action.condition_route {
        routes.push(CompiledActionRoute {
            id: format!("actions.{}.target-conditions", action.id),
            action_id: action.id.clone(),
            kind: ActionRouteKind::TargetConditions,
            method: HttpMethod::Post,
            path: path.clone(),
            operation: Operation::Invoke,
            access_profiles: profile_ids.iter().cloned().collect(),
            default_access_profile: default.map(|profile| profile.id.clone()),
        });
    }
    if !action.execution.is_proposal()
        && action
            .inputs
            .iter()
            .any(|input| matches!(input.field_type, FieldTypeSource::Reference { .. }))
    {
        routes.push(CompiledActionRoute {
            id: format!("actions.{}.availability", action.id),
            action_id: action.id.clone(),
            kind: ActionRouteKind::Availability,
            method: HttpMethod::Post,
            path: format!("{}/availability", action.route),
            operation: Operation::Invoke,
            access_profiles: profile_ids.iter().cloned().collect(),
            default_access_profile: default.map(|profile| profile.id.clone()),
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
    if defaults.len() > 1 {
        errors.push(Diagnostic::error(
            "breg.action.route-access-default-multiple",
            "project.accessProfiles[].default",
            "an action route accepts at most one default profile; clear default on the other profiles",
        ));
    }
    defaults.first().copied()
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
                "breg.action.input-string-bounds-invalid",
                path,
                "string length bounds are invalid",
            ))
        }
        FieldTypeSource::Text { max_length } if *max_length == 0 || *max_length > 10_000_000 => {
            errors.push(Diagnostic::error(
                "breg.action.input-text-bound-invalid",
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
                "breg.action.input-vocabulary-values-invalid",
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
                "breg.action.input-decimal-bounds-invalid",
                path,
                DECIMAL_BOUNDS_REQUIREMENTS,
            ));
        }
        FieldTypeSource::Reference { target, .. } if target.is_empty() => {
            errors.push(Diagnostic::error(
                "breg.action.input-reference-target-invalid",
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
                "breg.action.input-crs84-point-bounds-invalid",
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
                "breg.action.input-structured-schema-invalid",
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
    if source == target {
        return true;
    }
    match (source, target) {
        (
            FieldTypeSource::VocabularyCode {
                vocabulary: source_vocabulary,
                values: source_values,
            },
            FieldTypeSource::VocabularyCode {
                vocabulary: target_vocabulary,
                values: target_values,
            },
        ) => {
            source_vocabulary == target_vocabulary
                && source_values
                    .iter()
                    .all(|value| target_values.contains(value))
        }
        _ => false,
    }
}

pub(crate) fn effective_action_effect_id(effect: &ActionEffectSource, index: usize) -> String {
    effect
        .id
        .clone()
        .unwrap_or_else(|| format!("effect-{}", index + 1))
}

fn write_target_binding_key(target: &CompiledPlanTarget, effect_id: &str) -> String {
    match &target.binding {
        CompiledPlanTargetBinding::Create => format!("create:{}:{}", target.entity_id, effect_id),
        CompiledPlanTargetBinding::Existing { input } => {
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
            "breg.identifier.invalid",
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

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn compile_execution(
    action: &ActionSource,
    entities: &BTreeMap<String, CompiledEntity>,
    profiles: &[ProjectAccessProfileSource],
    authorities: &[crate::contract::ReviewAuthoritySource],
    target_uses: &[CompiledActionTargetUse],
    errors: &mut Vec<Diagnostic>,
) -> crate::model::CompiledActionExecution {
    use crate::contract::*;
    use crate::model::*;
    let ActionExecutionSource::Proposal { proposal } = &action.execution else {
        return CompiledActionExecution::Immediate;
    };
    let attachment_field_names = action
        .inputs
        .iter()
        .flat_map(|input| [input.id.clone(), default_api_name(&input.id)])
        .chain([
            "proposalId".to_owned(),
            "actionId".to_owned(),
            "actionRevision".to_owned(),
            "submissionVersion".to_owned(),
            "revision".to_owned(),
            "status".to_owned(),
        ])
        .collect();
    crate::compiler::attachments::validate_slots(
        &proposal.attachments,
        &attachment_field_names,
        &format!("actions[id={}].execution.proposal.attachments", action.id),
        errors,
    );
    let attachments = crate::compiler::attachments::compile_slots(&proposal.attachments);
    let review = match &proposal.review {
        ProposalReviewSource::None {} => CompiledProposalReview::None,
        ProposalReviewSource::Required {
            authority,
            source,
            policy,
        } => {
            if !authorities.iter().any(|entry| {
                &entry.id == authority
                    && entry.protocol == "id.registrystack.org/protocols/review/v1"
            }) {
                errors.push(Diagnostic::error("breg.proposal.review-authority-unknown","actions[].execution.proposal.review.authority","required review must name a declared authority implementing the review protocol"));
            }
            let selection = registry_review_protocol::PolicySelection {
                id: policy.id.clone(),
                version: policy.version.clone(),
                digest: policy.digest.as_ref().map(|digest| {
                    registry_review_protocol::ContentDigest::parse(digest.as_str())
                        .expect("reader checked SHA-256 digest")
                }),
            };
            if selection.check().is_err()
                || source.is_empty()
                || source.len() > 256
                || source.chars().any(char::is_control)
            {
                errors.push(Diagnostic::error("breg.proposal.review-binding-invalid", "actions[].execution.proposal.review", "review source and policy identifier must satisfy the review protocol bounds; omit both version and digest to select the current policy, or supply both for an exact pin"));
            }
            CompiledProposalReview::Required {
                authority: authority.clone(),
                source: source.clone(),
                policy: selection,
            }
        }
    };
    let application = match &proposal.application {
        ProposalApplicationSource::Manual {} => CompiledProposalApplication::Manual,
        ProposalApplicationSource::Automatic { maximum_attempts } => {
            if !(1..=32).contains(maximum_attempts) {
                errors.push(Diagnostic::error(
                    "breg.proposal.application-invalid",
                    "actions[].execution.proposal.application",
                    "automatic application supports 1 through 32 built-in worker attempts",
                ));
            }
            CompiledProposalApplication::Automatic {
                maximum_attempts: *maximum_attempts,
            }
        }
    };
    let mut permissions = Vec::new();
    for profile in profiles {
        for grant in profile
            .permissions
            .proposals
            .iter()
            .filter(|grant| grant.action == action.id)
        {
            crate::consent::validate_proposal_permission(profile, grant, entities, errors);
            if application.is_automatic()
                && grant.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        ProposalOperation::Apply | ProposalOperation::Retry
                    )
                })
                && matches!(
                    profile.actor_kind,
                    Some(ActorKindSource::Agent | ActorKindSource::Service)
                )
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.automatic-recovery-requires-human",
                    format!("accessProfiles[id={}].permissions.proposals[action={}].operations", profile.id, action.id),
                    "external Apply or Retry on automatic work is human recovery; service and agent profiles cannot hold those grants",
                ));
            }
            let authority_status = grant.review_authority.is_some();
            if authority_status {
                let matches_authority = matches!(&review, CompiledProposalReview::Required { authority, .. }
                    if Some(authority) == grant.review_authority.as_ref());
                if !matches_authority
                    || profile.actor_kind != Some(ActorKindSource::Service)
                    || grant.operations.len() != 1
                    || !grant
                        .operations
                        .contains(&ProposalOperation::GetReviewStatus)
                    || grant.ownership.is_some()
                    || !grant.targets.is_empty()
                    || !grant.readable_context_fields.is_empty()
                    || !grant.readable_inputs.is_empty()
                    || !grant.readable_attachments.is_empty()
                    || !grant.writable_attachments.is_empty()
                {
                    errors.push(Diagnostic::error(
                        "breg.proposal.review-status-authority-invalid",
                        "accessProfiles[].permissions.proposals[].reviewAuthority",
                        "a named review authority requires a service-only GetReviewStatus grant with no Record targets or projected fields",
                    ));
                }
            }

            if profile.actor_kind == Some(ActorKindSource::Agent)
                && profile.task_grant.is_none()
                && (grant
                    .operations
                    .iter()
                    .any(|operation| !matches!(operation, ProposalOperation::Edit))
                    || (grant.operations.contains(&ProposalOperation::Edit)
                        && grant.ownership != Some(ProposalOwnership::Caller)))
            {
                errors.push(Diagnostic::error("breg.proposal.standing-agent-operation-forbidden", "accessProfiles[].permissions.proposals", "an agent without a task grant can only start and edit caller-owned draft Proposals; other operations require delegated or human authority"));
            }
            if grant.operations.is_empty()
                || permissions
                    .iter()
                    .any(|entry: &CompiledProposalPermission| entry.profile_id == profile.id)
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.permission-invalid",
                    "accessProfiles[].permissions.proposals",
                    "Proposal grants require operations and one entry per Action",
                ));
            }
            if grant
                .operations
                .contains(&ProposalOperation::GetApplicationActor)
                && !grant.operations.contains(&ProposalOperation::Get)
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.application-actor-grant-invalid",
                    "accessProfiles[].permissions.proposals[].operations",
                    "get-application-actor is a supplemental disclosure grant and requires get in the same Proposal grant",
                ));
            }
            let mut targets = Vec::new();
            let mut seen = BTreeSet::new();
            for target in &grant.targets {
                if !seen.insert(&target.record_type) {
                    errors.push(Diagnostic::error(
                        "breg.proposal.permission-target-duplicate",
                        "accessProfiles[].permissions.proposals[].targets",
                        "target grants must be unique",
                    ));
                }
                let Some(entity) = entities.get(&target.record_type) else {
                    errors.push(Diagnostic::error(
                        "breg.proposal.permission-target-unknown",
                        "accessProfiles[].permissions.proposals[].targets",
                        "target grant must name a declared Record type",
                    ));
                    continue;
                };
                validate_row_boundaries(
                    entity,
                    &target.row_boundaries,
                    "accessProfiles[].permissions.proposals[].targets[].rowBoundaries",
                    errors,
                );
                validate_permission_access_requirements(
                    entity,
                    profile,
                    &target.row_boundaries,
                    "accessProfiles[].permissions.proposals[].targets",
                    errors,
                );
                targets.push(CompiledProposalTargetPermission {
                    entity_id: target.record_type.clone(),
                    row_boundaries: target.row_boundaries.clone(),
                });
            }
            if !authority_status
                && target_uses
                    .iter()
                    .any(|use_| !seen.contains(&use_.entity_id))
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.permission-targets-incomplete",
                    "accessProfiles[].permissions.proposals[].targets",
                    "Proposal authority must cover every planned and referenced target type",
                ));
            }
            let context_fields = proposal
                .review_context
                .as_ref()
                .map(|context| context.fields.keys().cloned().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            if !grant.readable_context_fields.is_subset(&context_fields) {
                errors.push(Diagnostic::error(
                    "breg.proposal.context-field-unknown",
                    "accessProfiles[].permissions.proposals[].readableContextFields",
                    "context grants must name fields in this Action's declared review context",
                ));
            }
            let input_ids = action
                .inputs
                .iter()
                .map(|input| input.id.clone())
                .collect::<BTreeSet<_>>();
            if !grant.readable_inputs.is_subset(&input_ids)
                || (!grant.readable_inputs.is_empty()
                    && !grant.operations.contains(&ProposalOperation::Get))
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.input-grant-invalid",
                    "accessProfiles[].permissions.proposals[].readableInputs",
                    "input disclosure grants must name declared Action inputs and require Get",
                ));
            }
            let attachment_ids = attachments.keys().cloned().collect::<BTreeSet<_>>();
            if !grant.readable_attachments.is_subset(&attachment_ids)
                || !grant.writable_attachments.is_subset(&attachment_ids)
                || (!grant.readable_attachments.is_empty()
                    && !grant.operations.contains(&ProposalOperation::Get))
                || (!grant.writable_attachments.is_empty()
                    && !grant.operations.contains(&ProposalOperation::Edit))
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.attachment-grant-invalid",
                    "accessProfiles[].permissions.proposals",
                    "attachment grants must name declared slots and require Get for reads or Edit for writes",
                ));
            }
            permissions.push(CompiledProposalPermission {
                profile_id: profile.id.clone(),
                review_authority: grant.review_authority.clone(),
                default: profile.default,
                actor_kind: profile.actor_kind,
                task_grant: profile.task_grant.clone(),
                requester_clients: profile.requester_clients.as_set().clone(),
                principal_claim: Some(profile.principal_claim.clone()),
                required_scopes: profile.required_scopes.as_set().clone(),
                required_purposes: profile.required_purposes.as_set().clone(),
                operations: grant.operations.as_set().clone(),
                ownership: grant.ownership,
                targets,
                readable_context_fields: grant.readable_context_fields.as_set().clone(),
                readable_inputs: grant.readable_inputs.as_set().clone(),
                readable_attachments: grant.readable_attachments.as_set().clone(),
                writable_attachments: grant.writable_attachments.as_set().clone(),
            });
        }
    }
    if let Some(context) = &proposal.review_context {
        validate_id(
            &context.id,
            "actions[].execution.proposal.reviewContext.id",
            errors,
        );
        if context.fields.len() > 64 {
            errors.push(Diagnostic::error(
                "breg.proposal.context-bounds",
                "actions[].execution.proposal.reviewContext",
                "review context supports at most 64 fields",
            ));
        }
        for (name, value) in &context.fields {
            if !valid_api_name(name) || reserved_logical_name(name) {
                errors.push(Diagnostic::error(
                    "breg.proposal.context-name-invalid",
                    "actions[].execution.proposal.reviewContext.fields",
                    "review-context fields must use distinct public API names",
                ));
            }
            use crate::contract::ProposalContextValueSource;
            let valid = match value {
                ProposalContextValueSource::Document { slot } => attachments.contains_key(slot),
                ProposalContextValueSource::Input { input } => {
                    action.inputs.iter().any(|field| &field.id == input)
                }
                ProposalContextValueSource::Record { input, field } => action
                    .inputs
                    .iter()
                    .find(|entry| &entry.id == input)
                    .is_some_and(|entry| match &entry.field_type {
                        FieldTypeSource::Reference { target, .. } => entities
                            .get(target)
                            .and_then(|entity| entity.fields.get(field))
                            .is_some_and(|field| field.encryption.is_none()),
                        _ => false,
                    }),
                ProposalContextValueSource::Changes {
                    record_type,
                    fields,
                } => {
                    !fields.is_empty()
                        && fields.len() <= 64
                        && fields.iter().collect::<BTreeSet<_>>().len() == fields.len()
                        && entities.get(record_type).is_some_and(|entity| {
                            fields.iter().all(|field| {
                                entity
                                    .fields
                                    .get(field)
                                    .is_some_and(|field| field.encryption.is_none())
                            })
                        })
                }
            };
            if !valid {
                errors.push(Diagnostic::error(
                    "breg.proposal.context-mapping-invalid",
                    "actions[].execution.proposal.reviewContext.fields",
                    "context must select a declared document slot, an input, an unencrypted referenced Record field, or 1–64 distinct unencrypted fields from frozen Record changes",
                ));
            }
        }
    }
    CompiledActionExecution::Proposal {
        proposal: CompiledProposalPolicy {
            hooks: Vec::new(),
            system_apply_grant: None,
            review,
            application,
            retention: match proposal.retention.mode {
                ProposalRetentionMode::Retain => CompiledProposalRetentionMode::Retain,
                ProposalRetentionMode::OperatorErase => {
                    CompiledProposalRetentionMode::OperatorErase
                }
            },
            review_context: proposal.review_context.clone(),
            attachments,
            permissions,
        },
    }
}

pub(crate) fn finalize_action_revisions(
    inventory: &mut CompiledActionInventory,
    entities: &BTreeMap<String, CompiledEntity>,
) {
    for action in &mut inventory.actions {
        action.definition_revision = definition_revision(action, entities);
        let mut targets =
            BTreeMap::<(String, Operation), crate::model::CompiledSystemApplyTarget>::new();
        for use_ in &action.target_uses {
            let operation = if use_.operation == Operation::Invoke {
                Operation::Get
            } else {
                use_.operation
            };
            let target = targets
                .entry((use_.entity_id.clone(), operation))
                .or_insert_with(|| crate::model::CompiledSystemApplyTarget {
                    entity_id: use_.entity_id.clone(),
                    operation,
                    fields: BTreeSet::new(),
                    read_fields: BTreeSet::new(),
                });
            if matches!(operation, Operation::Create | Operation::Patch) {
                target.fields.extend(use_.fields.iter().cloned());
            }
            target.read_fields.extend(use_.fields.iter().cloned());
        }
        for guard in &action.requires {
            let target = targets
                .entry((guard.entity_id.clone(), Operation::Get))
                .or_insert_with(|| crate::model::CompiledSystemApplyTarget {
                    entity_id: guard.entity_id.clone(),
                    operation: Operation::Get,
                    fields: BTreeSet::new(),
                    read_fields: BTreeSet::new(),
                });
            if !guard.field.is_empty() {
                target.read_fields.insert(guard.field.clone());
            }
        }
        let targets = targets.into_values().collect::<Vec<_>>();
        let payload = json!({"actionId":action.id,"actionRevision":action.definition_revision,"targets":targets});
        let revision = format!(
            "sha256:{}",
            hex_lower(&Sha256::digest(
                canonicalize_json(&payload).expect("normalized system grant canonicalizes")
            ))
        );
        if let crate::model::CompiledActionExecution::Proposal { proposal } = &mut action.execution
        {
            if matches!(
                proposal.application,
                crate::model::CompiledProposalApplication::Automatic { .. }
            ) {
                proposal.system_apply_grant = Some(crate::model::CompiledSystemApplyGrant {
                    revision,
                    action_id: action.id.clone(),
                    action_revision: action.definition_revision.clone(),
                    targets,
                });
            }
        }
    }
}

pub(crate) fn definition_revision(
    action: &CompiledAction,
    entities: &BTreeMap<String, CompiledEntity>,
) -> String {
    let mut used = BTreeMap::<String, BTreeSet<String>>::new();
    for use_ in &action.target_uses {
        used.entry(use_.entity_id.clone())
            .or_default()
            .extend(use_.fields.iter().cloned());
    }
    for guard in &action.requires {
        if !guard.field.is_empty() {
            used.entry(guard.entity_id.clone())
                .or_default()
                .insert(guard.field.clone());
        }
    }
    let targets=used.into_iter().filter_map(|(id,mut fields)| {
        let target=entities.get(&id)?;
        // Both write operations freeze and validate complete before/after rows,
        // so requiredness and retained-field bounds belong to their closure.
        if action.effects.iter().any(|effect|effect.target.entity_id==id && matches!(effect.operation,Operation::Create|Operation::Patch)) {fields.extend(target.fields.keys().cloned());}
        let fields=fields.into_iter().filter_map(|id|target.fields.get(&id).map(|field|(id,json!({"type":field.field_type,"required":field.required,"classification":field.classification,"pattern":field.pattern,"encrypted":field.encryption})))).collect::<BTreeMap<_,_>>();
        Some((id,json!({"fields":fields,"constraints":target.constraints,"mutationMode":target.mutation_mode,"changeControl":target.change_control})))
    }).collect::<BTreeMap<_,_>>();
    let policy = match &action.execution {
        crate::model::CompiledActionExecution::Immediate => json!({"mode":"immediate"}),
        crate::model::CompiledActionExecution::Proposal { proposal } => {
            json!({"mode":"proposal","review":proposal.review,"application":proposal.application,"retention":proposal.retention,"reviewContext":proposal.review_context,"attachments":proposal.attachments})
        }
    };
    let inputs = action
        .inputs
        .iter()
        .map(|input| {
            json!({
                "id":input.id,"apiName":input.api_name,"fieldType":input.field_type,
                "required":input.required,"classification":input.classification,
            })
        })
        .collect::<Vec<_>>();
    let function = action.handler.as_ref().map(|function| {
        let mut value = serde_json::to_value(function).expect("compiled function serializes");
        value["refusals"] = json!(function.refusals.keys().collect::<Vec<_>>());
        value
    });
    let payload = json!({"id":action.id,"apiName":action.api_name,"inputs":inputs,"plan":{"effects":action.effects,"function":function},"commitGuards":{"targets":action.requires,"evidence":action.commit_evidence},"planEvidence":action.evidence,"targets":targets,"execution":policy,"consentIssuer":action.consent_issuer});
    format!(
        "sha256:{}",
        hex_lower(&Sha256::digest(
            canonicalize_json(&payload).expect("normalized Action canonicalizes")
        ))
    )
}
