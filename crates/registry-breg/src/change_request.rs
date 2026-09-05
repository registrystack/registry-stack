// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, ChangeRequestApplicationModeSource, ChangeRequestDispositionSource,
    ChangeRequestEffectSource, ChangeRequestPlannerSource, ChangeRequestValueSource,
    Classification, EntitySource, FieldTypeSource, ModuleAssetSource, MutationMode, Operation,
    RowBoundarySource, CHANGE_REQUEST_PLAN_ABI_V1,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    ChangeRequestOperation, CompiledChangeRequest, CompiledChangeRequestActionRoute,
    CompiledChangeRequestApplication, CompiledChangeRequestApplicationMode,
    CompiledChangeRequestApplyGrant, CompiledChangeRequestDisposition, CompiledChangeRequestEffect,
    CompiledChangeRequestMutation, CompiledChangeRequestPlanner, CompiledChangeRequestPlannerKind,
    CompiledChangeRequestPlannerLimits, CompiledChangeRequestPlannerWrite,
    CompiledChangeRequestPresenceGrant, CompiledChangeRequestReferenceSources,
    CompiledChangeRequestRetentionMode, CompiledChangeRequestReviewGrant,
    CompiledChangeRequestReviewMode, CompiledChangeRequestStage, CompiledChangeRequestTarget,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledEntity,
};

/// Path to an entity, identified so a diagnostic can name which entity it concerns.
fn entity_path(entity_id: &str) -> String {
    format!("entities[id={entity_id}]")
}

/// Path to an access profile declared on an entity.
fn profile_path(entity_id: &str, profile_id: &str) -> String {
    format!("{}.accessProfiles[id={profile_id}]", entity_path(entity_id))
}

/// Path to a declared review stage on a change-request entity.
fn stage_path(entity_id: &str, stage_id: &str) -> String {
    format!(
        "{}.changeRequest.review.stages[id={stage_id}]",
        entity_path(entity_id)
    )
}

/// Path to a declared change-request effect. Effects with an explicit id are
/// identified by that id; effects without one fall back to their zero-based
/// position, matching the compiler's own index convention for unidentified
/// collection members.
fn effect_path(entity_id: &str, effect_id: Option<&str>, index: usize) -> String {
    let base = entity_path(entity_id);
    match effect_id {
        Some(id) => format!("{base}.changeRequest.effects[id={id}]"),
        None => format!("{base}.changeRequest.effects[{index}]"),
    }
}

pub const MAX_CHANGE_REQUEST_TARGETS: u16 = 16;
pub const MAX_CHANGE_REQUEST_FIELD_MUTATIONS: u16 = 128;
pub const MAX_CHANGE_REQUEST_SNAPSHOT_BYTES: u32 = 2_097_152;
pub const MAX_CHANGE_REQUEST_REVIEW_STAGES: u16 = 32;
pub const MAX_CHANGE_REQUEST_PLANNER_SOURCE_BYTES: usize = 65_536;
pub const CHANGE_REQUEST_PLANNER_RHAI_VERSION: &str = "1.25.1";

type CompiledEffectSet = (
    Vec<CompiledChangeRequestEffect>,
    BTreeMap<String, BTreeSet<String>>,
    BTreeSet<String>,
);

fn compile_application(
    request_entity_id: &str,
    request: &crate::contract::ChangeRequestSource,
    has_planner: bool,
    errors: &mut Vec<Diagnostic>,
) -> CompiledChangeRequestApplication {
    let source = &request.application;
    let application_path = format!(
        "{}.changeRequest.application",
        entity_path(request_entity_id)
    );
    let queue_reasons_path = format!("{application_path}.queueReasons");
    if source.mode == ChangeRequestApplicationModeSource::Planner {
        if !has_planner || source.allowed_dispositions.is_empty() {
            errors.push(Diagnostic::error(
                "change_request.application.planner_invalid",
                application_path.as_str(),
                "planner application requires a Rhai planner and at least one allowed disposition",
            ));
        }
    } else if !source.allowed_dispositions.is_empty() || !source.queue_reasons.is_empty() {
        errors.push(Diagnostic::error(
            "change_request.application.policy_forbidden",
            application_path.as_str(),
            "only planner application can declare dispositions or queue reasons",
        ));
    }
    let queue_allowed = source
        .allowed_dispositions
        .contains(&ChangeRequestDispositionSource::Queue);
    // A queue disposition and a non-empty queue-reason catalogue go together.
    if queue_allowed == source.queue_reasons.is_empty() {
        errors.push(Diagnostic::error(
            "change_request.application.queue_reasons_invalid",
            queue_reasons_path.as_str(),
            "queue disposition and a non-empty closed queue-reason catalogue must be declared together",
        ));
    }
    for (code, label) in &source.queue_reasons {
        let queue_reason_path = format!("{queue_reasons_path}[code={code}]");
        validate_id(code, &queue_reason_path, errors);
        if label.trim().is_empty() || label.len() > 160 {
            errors.push(Diagnostic::error(
                "change_request.application.queue_reason_invalid",
                queue_reason_path,
                "queue reason labels must be non-empty and bounded",
            ));
        }
    }
    CompiledChangeRequestApplication {
        mode: match source.mode {
            ChangeRequestApplicationModeSource::Manual => {
                CompiledChangeRequestApplicationMode::Manual
            }
            ChangeRequestApplicationModeSource::Automatic => {
                CompiledChangeRequestApplicationMode::Automatic
            }
            ChangeRequestApplicationModeSource::Planner => {
                CompiledChangeRequestApplicationMode::Planner
            }
        },
        allowed_dispositions: source
            .allowed_dispositions
            .iter()
            .map(|value| match value {
                ChangeRequestDispositionSource::Apply => CompiledChangeRequestDisposition::Apply,
                ChangeRequestDispositionSource::Queue => CompiledChangeRequestDisposition::Queue,
            })
            .collect(),
        queue_reasons: source.queue_reasons.clone(),
    }
}

fn valid_planner_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.ends_with(".rhai")
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

struct PlannerCompileInput<'a> {
    source_entity: &'a EntitySource,
    request_entity: &'a CompiledEntity,
    entities: &'a BTreeMap<String, CompiledEntity>,
    request_entity_ids: &'a BTreeSet<String>,
    source: &'a ChangeRequestPlannerSource,
    source_module: Option<String>,
    assets: &'a [ModuleAssetSource],
}

struct CompiledPlannerContract {
    planner: CompiledChangeRequestPlanner,
    changed_fields: BTreeMap<String, BTreeSet<String>>,
    target_entities: BTreeSet<String>,
}

fn compile_planner(
    input: PlannerCompileInput<'_>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledPlannerContract> {
    let PlannerCompileInput {
        source_entity,
        request_entity,
        entities,
        request_entity_ids,
        source,
        source_module,
        assets,
    } = input;
    let planner_path = format!("{}.changeRequest.planner", entity_path(&request_entity.id));
    let request_fields_path = format!("{planner_path}.requestFields");
    let writes_path = format!("{planner_path}.writes");
    let script_path = format!("{planner_path}.script");
    if source.abi != CHANGE_REQUEST_PLAN_ABI_V1 {
        errors.push(Diagnostic::error(
            "change_request.planner.abi_invalid",
            format!("{planner_path}.abi"),
            "the planner ABI is not supported",
        ));
    }
    if !valid_planner_path(&source.script) {
        errors.push(Diagnostic::error(
            "change_request.planner.source_invalid",
            script_path.as_str(),
            "the planner script must be a bounded relative .rhai path",
        ));
    }
    let mut declared = BTreeSet::new();
    for field_id in &source.request_fields {
        let request_field_path = format!("{request_fields_path}[field={field_id}]");
        if !declared.insert(field_id.clone()) {
            errors.push(Diagnostic::error(
                "change_request.planner.request_field_duplicate",
                request_field_path.as_str(),
                "planner request fields must be duplicate-free",
            ));
        }
        if !request_entity.fields.contains_key(field_id) {
            errors.push(Diagnostic::error(
                "change_request.planner.request_field_unknown",
                request_field_path,
                "a planner request field is not declared on the request entity",
            ));
        }
    }
    if source.writes.is_empty() {
        errors.push(Diagnostic::error(
            "change_request.planner.writes_empty",
            writes_path.as_str(),
            "a planner must declare a non-empty write ceiling",
        ));
    }
    let input_classification = source
        .request_fields
        .iter()
        .filter_map(|id| {
            request_entity
                .fields
                .get(id)
                .map(|field| field.classification)
        })
        .max()
        .unwrap_or(Classification::Public);
    let create_entities = source
        .writes
        .iter()
        .filter(|write| write.operation == Operation::Create)
        .filter_map(|write| write.target.entity.clone())
        .collect::<BTreeSet<_>>();
    let mut writes = Vec::new();
    let mut changed_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut target_entities = BTreeSet::new();
    for (write_index, write) in source.writes.iter().enumerate() {
        let write_path = format!("{writes_path}[{write_index}]");
        if (write.target.from_field.is_some() as u8 + write.target.entity.is_some() as u8) != 1 {
            errors.push(Diagnostic::error(
                "change_request.planner.write_target_invalid",
                format!("{write_path}.target"),
                "a planner write target must name exactly one request reference or create entity",
            ));
            continue;
        }
        let (target_entity_id, target_from_field) = match (
            &write.target.from_field,
            &write.target.entity,
            write.operation,
        ) {
            (Some(field_id), None, Operation::Patch) => {
                let Some(field) = request_entity.fields.get(field_id) else {
                    errors.push(Diagnostic::error(
                        "change_request.planner.write_reference_unknown",
                        format!("{write_path}.target.fromField"),
                        "a planner write target refers to an unknown request field",
                    ));
                    continue;
                };
                if !declared.contains(field_id) {
                    errors.push(Diagnostic::error(
                        "change_request.planner.write_reference_undeclared",
                        format!("{write_path}.target.fromField"),
                        "an existing target reference must be present in planner requestFields",
                    ));
                }
                match &field.field_type {
                    FieldTypeSource::Reference { target, .. } => {
                        (target.clone(), Some(field_id.clone()))
                    }
                    _ => {
                        errors.push(Diagnostic::error(
                            "change_request.planner.write_reference_type",
                            format!("{write_path}.target.fromField"),
                            "an existing target must use a typed request reference",
                        ));
                        continue;
                    }
                }
            }
            (None, Some(entity_id), Operation::Create) => (entity_id.clone(), None),
            _ => {
                errors.push(Diagnostic::error(
                    "change_request.planner.write_operation_invalid",
                    format!("{write_path}.operation"),
                    "patch writes require fromField and create writes require entity",
                ));
                continue;
            }
        };
        let Some(target_entity) = entities.get(&target_entity_id) else {
            let target_path = if write.target.entity.is_some() {
                format!("{write_path}.target.entity")
            } else {
                format!("{write_path}.target.fromField")
            };
            errors.push(Diagnostic::error(
                "change_request.planner.write_entity_unknown",
                target_path,
                "a planner write targets an unknown entity",
            ));
            continue;
        };
        let synthetic_effect = ChangeRequestEffectSource {
            id: Some("planner-ceiling".to_owned()),
            target: crate::contract::ChangeRequestTargetSource {
                entity: write.target.entity.clone(),
                from_field: write.target.from_field.clone(),
            },
            operation: write.operation,
            set: BTreeMap::new(),
            clear: BTreeSet::new(),
        };
        if compile_target(
            source_entity,
            request_entity,
            entities,
            request_entity_ids,
            "planner-ceiling",
            &write_path,
            &synthetic_effect,
            errors,
        )
        .is_none()
        {
            continue;
        }
        if write.fields.is_empty() {
            errors.push(Diagnostic::error(
                "change_request.planner.write_fields_empty",
                format!("{write_path}.fields"),
                "a planner write ceiling must name at least one field",
            ));
        }
        let mut fields = BTreeSet::new();
        let mut field_types = BTreeMap::new();
        let mut required_fields = BTreeSet::new();
        let mut reference_sources = BTreeMap::new();
        for field_id in &write.fields {
            if !fields.insert(field_id.clone()) {
                errors.push(Diagnostic::error(
                    "change_request.planner.write_field_duplicate",
                    format!("{write_path}.fields[field={field_id}]"),
                    "planner write fields must be duplicate-free",
                ));
            }
            let Some(field) = target_entity.fields.get(field_id) else {
                errors.push(Diagnostic::error(
                    "change_request.planner.write_field_unknown",
                    format!("{write_path}.fields[field={field_id}]"),
                    "a planner write field is not declared on its target entity",
                ));
                continue;
            };
            if input_classification > field.classification {
                errors.push(Diagnostic::error(
                    "change_request.planner.classification_ceiling",
                    format!("{write_path}.fields[field={field_id}]"),
                    "planner inputs cannot flow to a less classified target field",
                ));
            }
            field_types.insert(field_id.clone(), field.field_type.clone());
            if field.required {
                required_fields.insert(field_id.clone());
            }
            if let FieldTypeSource::Reference { target, .. } = &field.field_type {
                let request_fields = source.request_fields.iter().filter(|candidate| request_entity.fields.get(*candidate).is_some_and(|source_field| matches!(&source_field.field_type, FieldTypeSource::Reference { target: source_target, .. } if source_target == target))).cloned().collect();
                let allowed_creates = create_entities
                    .iter()
                    .filter(|entity| *entity == target)
                    .cloned()
                    .collect();
                reference_sources.insert(
                    field_id.clone(),
                    CompiledChangeRequestReferenceSources {
                        request_fields,
                        create_entities: allowed_creates,
                    },
                );
            }
        }
        if write.operation == Operation::Create {
            let required_target_fields = target_entity
                .fields
                .values()
                .filter(|field| field.required)
                .map(|field| field.id.clone())
                .collect::<BTreeSet<_>>();
            if !required_target_fields.is_subset(&fields) {
                errors.push(Diagnostic::error(
                    "change_request.planner.create_fields_incomplete",
                    format!("{write_path}.fields"),
                    "a create write ceiling must include every required target field",
                ));
            }
            required_fields = required_target_fields;
        }
        changed_fields
            .entry(target_entity_id.clone())
            .or_default()
            .extend(fields.iter().cloned());
        target_entities.insert(target_entity_id.clone());
        if writes
            .iter()
            .any(|existing: &CompiledChangeRequestPlannerWrite| {
                existing.operation == write.operation
                    && existing.target_entity_id == target_entity_id
                    && existing.target_from_field == target_from_field
            })
        {
            errors.push(Diagnostic::error(
                "change_request.planner.write_duplicate",
                write_path.as_str(),
                "planner write ceilings must be unique by symbolic target and operation",
            ));
        }
        writes.push(CompiledChangeRequestPlannerWrite {
            target_entity_id,
            target_from_field,
            operation: write.operation,
            fields,
            field_types,
            required_fields,
            reference_sources,
        });
    }
    if writes.len() > usize::from(MAX_CHANGE_REQUEST_TARGETS)
        || writes.iter().map(|write| write.fields.len()).sum::<usize>()
            > usize::from(MAX_CHANGE_REQUEST_FIELD_MUTATIONS)
    {
        errors.push(Diagnostic::error(
            "change_request.planner.write_ceiling",
            writes_path.as_str(),
            "the planner write ceiling exceeds the supported resource bounds",
        ));
    }
    match maximum_planner_snapshot_bytes(request_entity, &writes) {
        Some(bytes) if bytes <= u64::from(MAX_CHANGE_REQUEST_SNAPSHOT_BYTES) => {}
        _ => errors.push(Diagnostic::error(
            "change_request.planner.snapshot_ceiling",
            writes_path.as_str(),
            "the planner write ceiling cannot satisfy the fixed snapshot-size bound",
        )),
    }
    let Some(asset) = assets
        .iter()
        .find(|asset| asset.module == source_module && asset.path == source.script)
    else {
        errors.push(Diagnostic::error(
            "change_request.planner.source_missing",
            script_path.as_str(),
            "the planner script must be supplied as an owned compilation asset",
        ));
        return None;
    };
    if asset.bytes.is_empty() || asset.bytes.len() > MAX_CHANGE_REQUEST_PLANNER_SOURCE_BYTES {
        errors.push(Diagnostic::error(
            "change_request.planner.source_bound",
            script_path.as_str(),
            "the planner source exceeds its fixed byte bound",
        ));
        return None;
    }
    let Ok(script) = std::str::from_utf8(&asset.bytes) else {
        errors.push(Diagnostic::error(
            "change_request.planner.source_encoding",
            script_path.as_str(),
            "the planner source must be UTF-8",
        ));
        return None;
    };
    if crate::rhai_planner::ChangeRequestPlannerRuntime::compile_source(script).is_err() {
        errors.push(Diagnostic::error(
            "change_request.planner.entrypoint",
            script_path.as_str(),
            "the planner source must compile with exactly one public fn plan(ctx) entry point",
        ));
    }
    let digest = Sha256::digest(&asset.bytes);
    Some(CompiledPlannerContract {
        planner: CompiledChangeRequestPlanner {
            kind: CompiledChangeRequestPlannerKind::Rhai,
            source_module,
            script_path: source.script.clone(),
            abi: source.abi.clone(),
            rhai_version: CHANGE_REQUEST_PLANNER_RHAI_VERSION.to_owned(),
            script_sha256: format!("sha256:{}", hex_lower(&digest)),
            script_bytes: asset.bytes.clone(),
            limits: CompiledChangeRequestPlannerLimits {
                maximum_source_bytes: MAX_CHANGE_REQUEST_PLANNER_SOURCE_BYTES as u32,
                maximum_operations: crate::rhai_planner::MAXIMUM_OPERATIONS,
                maximum_call_depth: crate::rhai_planner::MAXIMUM_CALL_DEPTH as u16,
                maximum_expression_depth: crate::rhai_planner::MAXIMUM_EXPRESSION_DEPTH as u16,
                maximum_string_bytes: crate::rhai_planner::MAXIMUM_STRING_BYTES as u32,
                maximum_array_items: crate::rhai_planner::MAXIMUM_ARRAY_ITEMS as u16,
                maximum_map_entries: crate::rhai_planner::MAXIMUM_MAP_ENTRIES as u16,
                maximum_modules: 0,
            },
            request_fields: source.request_fields.clone(),
            writes,
        },
        changed_fields,
        target_entities,
    })
}

pub(crate) fn compile_change_requests(
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<String, Option<String>>,
    assets: &[ModuleAssetSource],
    entities: &mut BTreeMap<String, CompiledEntity>,
) -> Result<(), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    validate_planner_assets(sources, origins, assets, &mut errors);
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
                    origins.get(entity_id).cloned().flatten(),
                    assets,
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

fn validate_planner_assets(
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<String, Option<String>>,
    assets: &[ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) {
    let declared = sources
        .iter()
        .filter_map(|(entity_id, entity)| {
            entity
                .change_request
                .as_ref()?
                .planner
                .as_ref()
                .map(|planner| {
                    (
                        origins.get(entity_id).cloned().flatten(),
                        planner.script.clone(),
                    )
                })
        })
        .collect::<BTreeSet<_>>();
    let supplied = assets
        .iter()
        .filter(|asset| asset.path.ends_with(".rhai"))
        .map(|asset| (asset.module.clone(), asset.path.clone()))
        .collect::<BTreeSet<_>>();
    for _ in supplied.difference(&declared) {
        errors.push(Diagnostic::error(
            "change_request.planner.asset_undeclared",
            "modules[].assets[]",
            "a Rhai asset is not declared by a change-request planner at the same ownership origin",
        ));
    }
}

fn validate_change_controlled_direct_writes(
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        if let Some(control) = &entity.change_control {
            let required_for_path =
                format!("{}.changeControl.requiredFor", entity_path(&entity.id));
            if control.required_for.is_empty() {
                errors.push(Diagnostic::error(
                    "change_control.required_for.empty",
                    required_for_path.as_str(),
                    "change control must name at least one controlled mutation operation",
                ));
            }
            for operation in &control.required_for {
                if !is_mutation_operation(*operation) {
                    errors.push(Diagnostic::error(
                        "change_control.operation.unsupported",
                        format!("{required_for_path}[value={}]", operation_id(*operation)),
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
                        format!("{}.operations", profile_path(&entity.id, &profile.id)),
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
    source_module: Option<String>,
    assets: &[ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequest> {
    let request = source.change_request.as_ref()?;
    if source.mutation_mode != MutationMode::Mutable {
        errors.push(Diagnostic::error(
            "change_request.mutation_mode.invalid",
            format!("{}.changeRequest", entity_path(&request_entity.id)),
            "a change-request entity must be mutable so draft revisions can be edited",
        ));
    }
    if source.change_control.is_some() {
        errors.push(Diagnostic::error(
            "change_request.change_control_conflict",
            format!("{}.changeControl", entity_path(&request_entity.id)),
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
            format!(
                "{}.accessProfiles[].operations",
                entity_path(&request_entity.id)
            ),
            "request entities use cancellation and cannot expose ordinary tombstone access",
        ));
    }
    if request.effects.is_empty() == request.planner.is_none() {
        errors.push(Diagnostic::error(
            "change_request.plan.exclusive",
            format!("{}.changeRequest", entity_path(&request_entity.id)),
            "a change-request capability must declare exactly one of effects or planner",
        ));
    }
    let review_mode = if request.review.mode.is_some() && request.review.stages.is_empty() {
        CompiledChangeRequestReviewMode::None
    } else if request.review.mode.is_none() && !request.review.stages.is_empty() {
        CompiledChangeRequestReviewMode::Stages
    } else {
        errors.push(Diagnostic::error(
            "change_request.review.mode_exclusive",
            format!("{}.changeRequest.review", entity_path(&request_entity.id)),
            "review must declare exactly one of mode none or a non-empty stage list",
        ));
        CompiledChangeRequestReviewMode::Stages
    };

    let application = compile_application(
        &request_entity.id,
        request,
        request.planner.is_some(),
        errors,
    );

    let stages = compile_stages(&request_entity.id, request, errors);
    let (effects, changed_fields, target_entities, planner) =
        if let Some(planner) = &request.planner {
            let compiled = compile_planner(
                PlannerCompileInput {
                    source_entity: source,
                    request_entity,
                    entities,
                    request_entity_ids,
                    source: planner,
                    source_module,
                    assets,
                },
                errors,
            )?;
            (
                Vec::new(),
                compiled.changed_fields,
                compiled.target_entities,
                Some(compiled.planner),
            )
        } else {
            let (effects, changed_fields, target_entities) = compile_effects(
                source,
                request_entity,
                entities,
                request_entity_ids,
                &request.effects,
                errors,
            )?;
            validate_plan_bounds(request_entity, entities, &effects, errors);
            (effects, changed_fields, target_entities, None)
        };
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
            format!(
                "{}.accessProfiles[].operations",
                entity_path(&request_entity.id)
            ),
            "a change-request type requires at least one submit_request grant",
        ));
    }
    validate_automatic_apply_profile(
        request_entity,
        review_mode,
        &application,
        &stages,
        &review_grants,
        &apply_grants,
        &target_entities,
        errors,
    );
    let contract_fingerprint = contract_fingerprint(ContractFingerprintInput {
        request_entity,
        entities,
        effects: &effects,
        stages: &stages,
        review_grants: &review_grants,
        apply_grants: &apply_grants,
        target_entities: &target_entities,
        review_mode,
        application: &application,
        planner: planner.as_ref(),
    });

    Some(CompiledChangeRequest {
        request_entity_id: source.id.clone(),
        contract_fingerprint,
        retention_mode: compile_retention_mode(request.retention.mode),
        review_mode,
        application,
        planner,
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

#[allow(clippy::too_many_arguments)]
fn validate_automatic_apply_profile(
    request_entity: &CompiledEntity,
    review_mode: CompiledChangeRequestReviewMode,
    application: &CompiledChangeRequestApplication,
    stages: &[CompiledChangeRequestStage],
    review_grants: &[CompiledChangeRequestReviewGrant],
    apply_grants: &[CompiledChangeRequestApplyGrant],
    target_entities: &BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) {
    let may_apply_when_ready = application.mode == CompiledChangeRequestApplicationMode::Automatic
        || (application.mode == CompiledChangeRequestApplicationMode::Planner
            && application
                .allowed_dispositions
                .contains(&CompiledChangeRequestDisposition::Apply));
    if !may_apply_when_ready {
        return;
    }
    let final_stage = stages.last().map(|stage| stage.id.as_str());
    let covered = request_entity.access_profiles.values().any(|profile| {
        let can_trigger_ready = match review_mode {
            CompiledChangeRequestReviewMode::None => {
                profile.operations.contains(&Operation::SubmitRequest)
            }
            CompiledChangeRequestReviewMode::Stages => {
                profile.operations.contains(&Operation::ApproveRequest)
                    && final_stage.is_some_and(|stage| {
                        target_entities.iter().all(|target_entity_id| {
                            review_grants.iter().any(|grant| {
                                grant.profile_id == profile.id
                                    && grant.stage == stage
                                    && grant.target_entity_id == *target_entity_id
                            })
                        })
                    })
            }
        };
        can_trigger_ready
            && target_entities.iter().all(|target_entity_id| {
                apply_grants.iter().any(|grant| {
                    grant.profile_id == profile.id && grant.target_entity_id == *target_entity_id
                })
            })
    });
    if !target_entities.is_empty() && !covered {
        errors.push(Diagnostic::error(
            "change_request.application.automatic_apply_profile_missing",
            format!("{}.accessProfiles", entity_path(&request_entity.id)),
            "an application policy that may apply when ready requires one profile with both readiness-trigger and complete target authority",
        ));
    }
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
    entity_id: &str,
    request: &crate::contract::ChangeRequestSource,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestStage> {
    if request.review.stages.len() > usize::from(MAX_CHANGE_REQUEST_REVIEW_STAGES) {
        errors.push(Diagnostic::error(
            "change_request.review.stage_count",
            format!("{}.changeRequest.review.stages", entity_path(entity_id)),
            "change-request review stages must stay within the supported finite bound",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut stages = Vec::new();
    for stage in &request.review.stages {
        let path = stage_path(entity_id, &stage.id);
        validate_id(&stage.id, &format!("{path}.id"), errors);
        if !ids.insert(stage.id.as_str()) {
            errors.push(Diagnostic::error(
                "change_request.review.stage.duplicate",
                format!("{path}.id"),
                "review stage identifiers must be duplicate-free",
            ));
        }
        if stage.approvals == 0 || stage.approvals > 32 {
            errors.push(Diagnostic::error(
                "change_request.review.stage.approvals_invalid",
                format!("{path}.approvals"),
                "review stage approval counts must be within the supported bounds",
            ));
        }
        stages.push(CompiledChangeRequestStage {
            id: stage.id.clone(),
            approvals: stage.approvals,
            exclude_submitter: stage.exclude_submitter,
            exclude_previous_reviewers: stage.exclude_previous_reviewers,
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
        let path = effect_path(&request_entity.id, effect.id.as_deref(), index);
        validate_id(&id, &format!("{path}.id"), errors);
        if !effect_ids.insert(id.clone()) {
            errors.push(Diagnostic::error(
                "change_request.effect.id_duplicate",
                format!("{path}.id"),
                "change-request effect identifiers must be duplicate-free",
            ));
        }
        if effect.operation == Operation::Create {
            if effect.id.is_none() {
                errors.push(Diagnostic::error(
                    "change_request.effect.create_id_required",
                    format!("{path}.id"),
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
        let path = effect_path(&request_entity.id, effect.id.as_deref(), index);
        let Some(target) = compile_target(
            source,
            request_entity,
            entities,
            request_entity_ids,
            &id,
            &path,
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
                path.as_str(),
                "a change-request effect must set or clear at least one field",
            ));
        }
        let mut mutations = Vec::new();
        let mut depends_on = BTreeSet::new();
        for (field, value) in &effect.set {
            let Some(target_field) = target_entity.fields.get(field) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.field_unknown",
                    format!("{path}.set[field={field}]"),
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
                &path,
                errors,
            ) {
                if let CompiledChangeRequestValue::FromEffect { effect, .. } = &compiled {
                    depends_on.insert(effect.clone());
                }
                mutations.push(CompiledChangeRequestMutation::Set {
                    field: field.clone(),
                    value: compiled,
                });
                remember_write(
                    &mut writes,
                    &target,
                    field,
                    &id,
                    &format!("{path}.set[field={field}]"),
                    errors,
                );
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
                    format!("{path}.clear[field={field}]"),
                    "a change-request effect clears an unknown stored target field",
                ));
                continue;
            };
            if effect.operation == Operation::Create {
                errors.push(Diagnostic::error(
                    "change_request.effect.clear_on_create",
                    format!("{path}.clear[field={field}]"),
                    "create effects cannot clear target fields",
                ));
            }
            if target_field.required {
                errors.push(Diagnostic::error(
                    "change_request.effect.clear_required",
                    format!("{path}.clear[field={field}]"),
                    "required target fields cannot be cleared",
                ));
            }
            mutations.push(CompiledChangeRequestMutation::Clear {
                field: field.clone(),
            });
            remember_write(
                &mut writes,
                &target,
                field,
                &id,
                &format!("{path}.clear[field={field}]"),
                errors,
            );
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

    let ordered = order_effects(&request_entity.id, compiled_by_id, errors)?;
    Some((ordered, changed_fields, target_entities))
}

#[allow(clippy::too_many_arguments)]
fn compile_target(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    request_entity_ids: &BTreeSet<String>,
    id: &str,
    path: &str,
    effect: &ChangeRequestEffectSource,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequestTarget> {
    if !exactly_one(
        effect.target.entity.as_ref(),
        effect.target.from_field.as_ref(),
    ) {
        errors.push(Diagnostic::error(
            "change_request.effect.target.invalid",
            format!("{path}.target"),
            "effect target must name exactly one entity or request reference field",
        ));
        return None;
    }
    match effect.operation {
        Operation::Create => {
            let Some(entity_id) = &effect.target.entity else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target.invalid",
                    format!("{path}.target"),
                    "create effects must target a declared entity for reserved identity",
                ));
                return None;
            };
            let Some(target_entity) = entities.get(entity_id) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_unknown",
                    format!("{path}.target.entity"),
                    "a change-request effect targets an unknown entity",
                ));
                return None;
            };
            if request_entity_ids.contains(entity_id) {
                errors.push(Diagnostic::error(
                    "change_request.effect.nested_request_target",
                    format!("{path}.target.entity"),
                    "change-request effects cannot target another change-request entity",
                ));
                return None;
            }
            if !is_change_controlled(target_entity, Operation::Create) {
                errors.push(Diagnostic::error(
                    "change_request.effect.uncontrolled_target",
                    format!("{path}.operation"),
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
                    format!("{path}.target.fromField"),
                    "patch effects must target a request reference field",
                ));
                return None;
            };
            let Some(field) = request_entity.fields.get(field_id) else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_field_unknown",
                    format!("{path}.target.fromField"),
                    "effect target refers to an unknown request field",
                ));
                return None;
            };
            let FieldTypeSource::Reference { target, .. } = &field.field_type else {
                errors.push(Diagnostic::error(
                    "change_request.effect.target_field_type",
                    format!("{path}.target.fromField"),
                    "patch effect targets must come from a typed request reference field",
                ));
                return None;
            };
            let target_entity = entities.get(target)?;
            if request_entity_ids.contains(target) {
                errors.push(Diagnostic::error(
                    "change_request.effect.nested_request_target",
                    format!("{path}.target.fromField"),
                    "change-request effects cannot target another change-request entity",
                ));
                return None;
            }
            if target_entity.mutation_mode != MutationMode::Mutable {
                errors.push(Diagnostic::error(
                    "change_request.effect.operation_unavailable",
                    format!("{path}.operation"),
                    "patch effects require a mutable target entity",
                ));
            }
            if !is_change_controlled(target_entity, Operation::Patch) {
                errors.push(Diagnostic::error(
                    "change_request.effect.uncontrolled_target",
                    format!("{path}.operation"),
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
                format!("{path}.operation"),
                "change-request effects support only create and patch operations",
            ));
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_value(
    source: &EntitySource,
    request_entity: &CompiledEntity,
    target_field: &str,
    target_type: &FieldTypeSource,
    value: &ChangeRequestValueSource,
    create_targets: &BTreeMap<String, String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledChangeRequestValue> {
    if !exactly_one(value.from_field.as_ref(), value.from_effect.as_ref()) {
        errors.push(Diagnostic::error(
            "change_request.effect.value.invalid",
            format!("{path}.set[field={target_field}]"),
            "set values must name exactly one request field or create effect",
        ));
        return None;
    }
    if let Some(field_id) = &value.from_field {
        let Some(field) = request_entity.fields.get(field_id) else {
            errors.push(Diagnostic::error(
                "change_request.effect.value_field_unknown",
                format!("{path}.set[field={target_field}]"),
                "set value refers to an unknown request field",
            ));
            return None;
        };
        if !field.required {
            errors.push(Diagnostic::error(
                "change_request.effect.value_nullable",
                format!("{path}.set[field={target_field}]"),
                "mapped set values must come from required request fields so null cannot mean leave unchanged",
            ));
        }
        if !compatible_field_types(&field.field_type, target_type) {
            errors.push(Diagnostic::error(
                "change_request.effect.value_type_mismatch",
                format!("{path}.set[field={target_field}]"),
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
            format!("{path}.set[field={target_field}]"),
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
                format!("{path}.set[field={target_field}]"),
                "fromEffect reserved identity does not match the target reference field",
            ));
            None
        }
        _ => {
            let _ = source;
            errors.push(Diagnostic::error(
                "change_request.effect.value_reference_required",
                format!("{path}.set[field={target_field}]"),
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
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let key = (target_binding_key(target), field.to_owned());
    if let Some(existing) = writes.insert(key, effect_id.to_owned()) {
        if existing != effect_id {
            errors.push(Diagnostic::error(
                "change_request.effect.overlapping_write",
                path,
                "change-request effects cannot write the same target field more than once",
            ));
        } else {
            errors.push(Diagnostic::error(
                "change_request.effect.overlapping_write",
                path,
                "a change-request effect cannot both set and clear the same target field",
            ));
        }
    }
}

fn order_effects(
    entity_id: &str,
    effects: BTreeMap<String, CompiledChangeRequestEffect>,
    errors: &mut Vec<Diagnostic>,
) -> Option<Vec<CompiledChangeRequestEffect>> {
    let mut state = BTreeMap::<String, VisitState>::new();
    let mut ordered = Vec::new();
    for id in effects.keys() {
        visit_effect(entity_id, id, &effects, &mut state, &mut ordered, errors);
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
    entity_id: &str,
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
                format!("{}.changeRequest.effects[id={id}]", entity_path(entity_id)),
                "reserved-create references cannot contain dependency cycles",
            ));
            return;
        }
        None => {}
    }
    state.insert(id.to_owned(), VisitState::Visiting);
    if let Some(effect) = effects.get(id) {
        for dependency in &effect.depends_on {
            visit_effect(entity_id, dependency, effects, state, ordered, errors);
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
    let effects_path = format!("{}.changeRequest.effects", entity_path(&request_entity.id));
    let target_count = effects
        .iter()
        .map(|effect| target_binding_key(&effect.target))
        .collect::<BTreeSet<_>>()
        .len();
    if target_count > usize::from(MAX_CHANGE_REQUEST_TARGETS) {
        errors.push(Diagnostic::error(
            "change_request.bounds.targets",
            effects_path.as_str(),
            "a change-request plan exceeds the supported target-record ceiling",
        ));
    }
    let mutation_count: usize = effects.iter().map(|effect| effect.mutations.len()).sum();
    if mutation_count > usize::from(MAX_CHANGE_REQUEST_FIELD_MUTATIONS) {
        errors.push(Diagnostic::error(
            "change_request.bounds.field_mutations",
            effects_path.as_str(),
            "a change-request plan exceeds the supported field-mutation ceiling",
        ));
    }
    match maximum_snapshot_bytes(request_entity, entities, effects) {
        Some(bytes) if bytes <= u64::from(MAX_CHANGE_REQUEST_SNAPSHOT_BYTES) => {}
        Some(_) => errors.push(Diagnostic::error(
            "change_request.bounds.snapshot_bytes",
            effects_path.as_str(),
            "a change-request plan exceeds the supported snapshot-size ceiling",
        )),
        None => errors.push(Diagnostic::error(
            "change_request.bounds.snapshot_unknown",
            effects_path.as_str(),
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
        let profile_base = profile_path(&request_entity.id, &profile.id);
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
                    format!("{profile_base}.operations"),
                    "review stage grants require approve_request, reject_request, or request_revision authority",
                ));
            }
            let stage_grant_path = format!("{profile_base}.reviewStages[stage={}]", grant.stage);
            if !stage_ids.contains(grant.stage.as_str()) {
                errors.push(Diagnostic::error(
                    "change_request.review_stage.unknown",
                    format!("{stage_grant_path}.stage"),
                    "a review grant refers to an unknown review stage",
                ));
                continue;
            }
            for target in &grant.targets {
                let target_grant_path =
                    format!("{stage_grant_path}.targets[entity={}]", target.entity);
                let Some(target_entity) = entities.get(&target.entity) else {
                    errors.push(Diagnostic::error(
                        "change_request.review_stage.target_unknown",
                        format!("{target_grant_path}.entity"),
                        "a review grant targets an unknown entity",
                    ));
                    continue;
                };
                validate_target_fields(
                    target_entity,
                    &target.readable_fields,
                    &format!("{target_grant_path}.readableFields"),
                    errors,
                );
                validate_row_boundaries(
                    target_entity,
                    &target.row_boundaries,
                    &format!("{target_grant_path}.rowBoundaries"),
                    errors,
                );
                validate_grant_access_requirements(
                    target_entity,
                    profile,
                    &target.row_boundaries,
                    &target_grant_path,
                    errors,
                );
                if let Some(required) = changed_fields.get(&target.entity) {
                    if !required.is_subset(&target.readable_fields) {
                        errors.push(Diagnostic::error(
                            "change_request.review_projection.incomplete",
                            format!("{target_grant_path}.readableFields"),
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
                format!(
                    "{}.accessProfiles[].reviewStages[stage={}]",
                    entity_path(&request_entity.id),
                    stage.id
                ),
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
        let profile_base = profile_path(&request_entity.id, &profile.id);
        if !profile.apply_targets.is_empty()
            && !profile.operations.contains(&Operation::ApplyRequest)
        {
            errors.push(Diagnostic::error(
                "change_request.apply_target.operation_required",
                format!("{profile_base}.operations"),
                "apply target grants require apply_request authority",
            ));
        }
        for target in &profile.apply_targets {
            let target_grant_path =
                format!("{profile_base}.applyTargets[entity={}]", target.entity);
            let Some(target_entity) = entities.get(&target.entity) else {
                errors.push(Diagnostic::error(
                    "change_request.apply_target.unknown",
                    format!("{target_grant_path}.entity"),
                    "an apply grant targets an unknown entity",
                ));
                continue;
            };
            validate_row_boundaries(
                target_entity,
                &target.row_boundaries,
                &format!("{target_grant_path}.rowBoundaries"),
                errors,
            );
            validate_grant_access_requirements(
                target_entity,
                profile,
                &target.row_boundaries,
                &target_grant_path,
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
            format!(
                "{}.accessProfiles[].applyTargets",
                entity_path(&request_entity.id)
            ),
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
            let profile_base = profile_path(&target_entity.id, &profile.id);
            for grant in &profile.request_presence {
                let presence_path = format!(
                    "{profile_base}.requestPresence[requestType={}]",
                    grant.request_type
                );
                let Some(targets) = target_by_request.get(&grant.request_type) else {
                    errors.push(Diagnostic::error(
                        "change_request.presence.request_type_unknown",
                        format!("{presence_path}.requestType"),
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
                    &format!("{presence_path}.rowBoundaries"),
                    errors,
                );
                validate_grant_access_requirements(
                    request_entity,
                    profile,
                    &grant.row_boundaries,
                    &presence_path,
                    errors,
                );
                if !targets.contains(&target_entity.id) {
                    errors.push(Diagnostic::error(
                        "change_request.presence.target_unaffected",
                        format!("{presence_path}.requestType"),
                        "a request-presence grant must name a request type that can affect the granted target entity",
                    ));
                    continue;
                }
                if profile.anonymous {
                    // Presence processes the request's existence and target
                    // linkage even when no intake values are disclosed.
                    let public_links = plans.get(&grant.request_type).is_some_and(|plan| {
                        let declarative_links_are_public = plan
                            .effects
                            .iter()
                            .filter(|effect| effect.target.entity_id == target_entity.id)
                            .all(|effect| match &effect.target.binding {
                                CompiledChangeRequestTargetBinding::Existing { from_field } => {
                                    request_entity.fields.get(from_field).is_some_and(|field| {
                                        field.classification == Classification::Public
                                    })
                                }
                                CompiledChangeRequestTargetBinding::ReservedCreate { .. } => true,
                            });
                        let planner_links_are_public =
                            plan.planner.as_ref().is_none_or(|planner| {
                                planner
                                    .writes
                                    .iter()
                                    .filter(|write| write.target_entity_id == target_entity.id)
                                    .all(|write| {
                                        write.target_from_field.as_ref().is_none_or(|from_field| {
                                            request_entity.fields.get(from_field).is_some_and(
                                                |field| {
                                                    field.classification == Classification::Public
                                                },
                                            )
                                        })
                                    })
                            });
                        declarative_links_are_public && planner_links_are_public
                    });
                    if request_entity.classification != Classification::Public || !public_links {
                        errors.push(Diagnostic::error(
                            "change_request.presence.anonymous_non_public",
                            presence_path.as_str(),
                            "anonymous request presence requires a public request type and public target-link fields",
                        ));
                    }
                    if !grant.row_boundaries.is_empty() {
                        errors.push(Diagnostic::error(
                            "change_request.presence.anonymous_claim_boundary",
                            format!("{presence_path}.rowBoundaries"),
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

fn validate_grant_access_requirements(
    entity: &CompiledEntity,
    profile: &AccessProfileSource,
    row_boundaries: &[RowBoundarySource],
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(requirements) = &entity.access_requirements {
        // A profile's own row bindings cannot substitute for this cross-entity
        // grant's bindings. Reuse the ordinary requirements check with the
        // grant's rows and the caller profile's scopes and purposes.
        let mut grant_profile = profile.clone();
        grant_profile.row_boundaries = row_boundaries.to_vec();
        crate::access::check_profile(requirements, &grant_profile, path, errors);
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

fn maximum_planner_snapshot_bytes(
    request_entity: &CompiledEntity,
    writes: &[CompiledChangeRequestPlannerWrite],
) -> Option<u64> {
    let mut request_bytes = 2_u64;
    for field in request_entity.fields.values() {
        let max = maximum_field_json_bytes(&field.field_type)?;
        request_bytes = request_bytes
            .checked_add(field.id.len() as u64 + 3)?
            .checked_add(if field.required { max } else { max.max(4) })?;
    }
    let largest_effect = writes
        .iter()
        .map(|write| {
            let mut bytes = (write.target_entity_id.len() + 32) as u64;
            for (field_id, field_type) in &write.field_types {
                let max = maximum_field_json_bytes(field_type)?;
                bytes = bytes
                    .checked_add(field_id.len() as u64 + 8)?
                    .checked_add(max.max(4))?
                    .checked_add(max.max(4))?;
            }
            Some(bytes)
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    request_bytes.checked_add(largest_effect.checked_mul(u64::from(MAX_CHANGE_REQUEST_TARGETS))?)
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

struct ContractFingerprintInput<'a> {
    request_entity: &'a CompiledEntity,
    entities: &'a BTreeMap<String, CompiledEntity>,
    effects: &'a [CompiledChangeRequestEffect],
    stages: &'a [CompiledChangeRequestStage],
    review_grants: &'a [CompiledChangeRequestReviewGrant],
    apply_grants: &'a [CompiledChangeRequestApplyGrant],
    target_entities: &'a BTreeSet<String>,
    review_mode: CompiledChangeRequestReviewMode,
    application: &'a CompiledChangeRequestApplication,
    planner: Option<&'a CompiledChangeRequestPlanner>,
}

fn contract_fingerprint(input: ContractFingerprintInput<'_>) -> String {
    let ContractFingerprintInput {
        request_entity,
        entities,
        effects,
        stages,
        review_grants,
        apply_grants,
        target_entities,
        review_mode,
        application,
        planner,
    } = input;
    let target_contracts = target_entities
        .iter()
        .filter_map(|entity_id| {
            entities
                .get(entity_id)
                .map(|entity| (entity_id.clone(), entity_contract_payload(entity)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut payload = json!({
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
    if planner.is_some()
        || review_mode != CompiledChangeRequestReviewMode::Stages
        || application.mode != CompiledChangeRequestApplicationMode::Manual
        || !application.allowed_dispositions.is_empty()
        || !application.queue_reasons.is_empty()
    {
        payload["version"] = json!(3);
        payload["reviewMode"] = json!(review_mode);
        payload["application"] = json!(application);
        payload["planner"] = json!(planner);
    }
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
        "accessRequirements": entity.access_requirements,
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
