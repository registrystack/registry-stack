// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::compiler::operation_id;
use crate::contract::{
    AccessProfileSource, ChangeRequestApplicationModeSource,
    ChangeRequestCurrentDatePredicateSource, ChangeRequestDispositionSource,
    ChangeRequestEffectSource, ChangeRequestPlannerSource, ChangeRequestPredicateSource,
    ChangeRequestSelectorSource, ChangeRequestValueSource, Classification, EntitySource,
    FieldTypeSource, ModuleAssetSource, MutationMode, Operation, RegistryProject,
    RowBoundarySource, CHANGE_REQUEST_PLAN_ABI_V1,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    ChangeRequestOperation, CompiledChangeRequest, CompiledChangeRequestActionRoute,
    CompiledChangeRequestApplication, CompiledChangeRequestApplicationMode,
    CompiledChangeRequestApplyPermission, CompiledChangeRequestDisposition,
    CompiledChangeRequestEffect, CompiledChangeRequestEvidence,
    CompiledChangeRequestEvidenceExpected, CompiledChangeRequestEvidenceRequirement,
    CompiledChangeRequestEvidenceSubject, CompiledChangeRequestGuardTarget,
    CompiledChangeRequestMutation, CompiledChangeRequestPlanner, CompiledChangeRequestPlannerKind,
    CompiledChangeRequestPlannerLimits, CompiledChangeRequestPlannerWrite,
    CompiledChangeRequestPreconditions, CompiledChangeRequestPredicate,
    CompiledChangeRequestPredicateExpected, CompiledChangeRequestPresencePermission,
    CompiledChangeRequestReferenceSources, CompiledChangeRequestRetentionMode,
    CompiledChangeRequestReviewMode, CompiledChangeRequestReviewPermission,
    CompiledChangeRequestSelector, CompiledChangeRequestStage, CompiledChangeRequestTarget,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledCurrentDateRelation,
    CompiledEntity, CompiledField,
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
    if !source.preconditions.is_empty()
        && (source.mode != ChangeRequestApplicationModeSource::Manual || has_planner)
    {
        errors.push(Diagnostic::error(
            "change_request.application.preconditions_manual_only",
            format!("{application_path}.preconditions"),
            "application preconditions require manual application and cannot run inside submit, approval, or planner transitions",
        ));
    }
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
        preconditions: CompiledChangeRequestPreconditions::default(),
    }
}

pub(crate) fn valid_planner_path(path: &str) -> bool {
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
    project: &RegistryProject,
    action_scripts: &BTreeSet<(Option<String>, String)>,
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<String, Option<String>>,
    assets: &[ModuleAssetSource],
    entities: &mut BTreeMap<String, CompiledEntity>,
) -> Result<(), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    validate_planner_assets(sources, origins, assets, action_scripts, &mut errors);
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
                    project,
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
    for entity in entities.values() {
        for profile in entity
            .access_profiles
            .values()
            .filter(|p| !p.submitter_targets.is_empty())
        {
            let authors_requests = profile.operations.contains(&Operation::Create)
                || profile.operations.contains(&Operation::Patch);
            let valid = compiled.get(&entity.id).is_some_and(|plan| {
                let references = plan
                    .effects
                    .iter()
                    .filter_map(|effect| match &effect.target.binding {
                        CompiledChangeRequestTargetBinding::Existing { from_field } => {
                            Some((&effect.target.entity_id, from_field))
                        }
                        CompiledChangeRequestTargetBinding::ReservedCreate { .. } => None,
                    })
                    .chain(
                        plan.application
                            .preconditions
                            .targets
                            .iter()
                            .map(|target| (&target.entity_id, &target.from_field)),
                    )
                    .collect::<Vec<_>>();
                let referenced_entities = references
                    .iter()
                    .map(|(entity_id, _)| (*entity_id).clone())
                    .collect::<BTreeSet<_>>();
                plan.planner.is_none()
                    && plan.application.mode
                        == crate::model::CompiledChangeRequestApplicationMode::Manual
                    && referenced_entities == profile.submitter_targets
                    && references.iter().all(|(_, from_field)| {
                        // Admission reads each exact target identifier from the
                        // request record, so an absent value would only surface
                        // as a runtime refusal.
                        profile.readable_fields.contains(*from_field)
                            && entity
                                .fields
                                .get(*from_field)
                                .is_some_and(|field| field.required)
                            // A profile that authors the request must be able to
                            // write the reference its admission contract reads.
                            && (!authors_requests || profile.writable_fields.contains(*from_field))
                    })
                    && profile.submitter_targets.iter().all(|id| {
                        !request_entity_ids.contains(id)
                            && entities
                                .get(id)
                                .and_then(|target| target.access_profiles.get(&profile.id))
                                .is_some_and(|target_profile| {
                                    target_profile.operations.contains(&Operation::Get)
                                        && target_profile.membership_boundaries.is_empty()
                                })
                    })
                    && !profile.anonymous
                    && !profile.operations.contains(&Operation::Batch)
            });
            if !valid {
                errors.push(Diagnostic::error(
                    "change_request.submitter_targets.invalid",
                    format!("{}.submitterTargets", profile_path(&entity.id, &profile.id)),
                    "submitterTargets requires manual application and exactly the fixed existing effect and application-guard reference targets; each reference must be required, readable, and writable wherever the profile authors the request, and each non-request target needs a same-profile get grant without membership boundaries",
                ));
            }
        }
    }
    compile_presence_permissions(entities, &mut compiled, &mut errors);

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
    action_scripts: &BTreeSet<(Option<String>, String)>,
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
        .chain(action_scripts.iter().cloned())
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
            "a Rhai asset is not declared by a change-request planner or action handler at the same ownership origin",
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

fn compile_preconditions(
    project: &RegistryProject,
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    assets: &[ModuleAssetSource],
    request: &crate::contract::ChangeRequestSource,
    errors: &mut Vec<Diagnostic>,
) -> CompiledChangeRequestPreconditions {
    let source = &request.application.preconditions;
    let base = format!(
        "{}.changeRequest.application.preconditions",
        entity_path(&request_entity.id)
    );
    let total_predicates = source
        .request
        .len()
        .saturating_add(
            source
                .targets
                .iter()
                .map(|target| target.requires.len())
                .sum(),
        )
        .saturating_add(source.evidence.iter().map(|item| item.requires.len()).sum());
    if source.targets.len() > usize::from(MAX_CHANGE_REQUEST_TARGETS)
        || source.evidence.len() > crate::action_evidence_contracts::MAX_EVIDENCE_CAPABILITIES
        || total_predicates > usize::from(MAX_CHANGE_REQUEST_FIELD_MUTATIONS)
        || serde_json::to_vec(source).map_or(true, |bytes| {
            bytes.len() > MAX_CHANGE_REQUEST_SNAPSHOT_BYTES as usize
        })
    {
        errors.push(Diagnostic::error(
            "change_request.preconditions.bounds",
            &base,
            "application preconditions exceed the finite target, Evidence, predicate, or byte ceiling",
        ));
        return CompiledChangeRequestPreconditions::default();
    }

    let request_predicates = compile_predicates(
        &source.request,
        request_entity,
        request_entity,
        true,
        &format!("{base}.request"),
        errors,
    );
    let mut targets = Vec::new();
    let mut target_ids = BTreeSet::new();
    let effect_ids = request
        .effects
        .iter()
        .enumerate()
        .map(|(index, effect)| effect_id(effect, index))
        .collect::<BTreeSet<_>>();
    for target in &source.targets {
        let path = format!("{base}.targets[id={}]", target.id);
        validate_id(&target.id, &format!("{path}.id"), errors);
        if !target_ids.insert(target.id.clone()) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_duplicate",
                &path,
                "precondition target identifiers must be duplicate-free",
            ));
            continue;
        }
        if effect_ids.contains(&target.id) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_effect_collision",
                format!("{path}.id"),
                "precondition target identifiers must not collide with effect identifiers",
            ));
            continue;
        }
        let Some(from_field) = request_entity.fields.get(&target.from_field) else {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_field_unknown",
                format!("{path}.fromField"),
                "a precondition target must use a declared request reference field",
            ));
            continue;
        };
        if !from_field.required
            || !matches!(&from_field.field_type, FieldTypeSource::Reference { target: entity, .. } if entity == &target.entity)
        {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_reference_invalid",
                format!("{path}.fromField"),
                "a precondition target must use a required request reference field for its exact entity",
            ));
            continue;
        }
        let Some(target_entity) = entities.get(&target.entity) else {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_entity_unknown",
                format!("{path}.entity"),
                "a precondition target must name a declared entity",
            ));
            continue;
        };
        if target.requires.is_empty() {
            errors.push(Diagnostic::error(
                "change_request.preconditions.target_empty",
                format!("{path}.requires"),
                "a precondition target must declare at least one finite predicate",
            ));
        }
        targets.push(CompiledChangeRequestGuardTarget {
            id: target.id.clone(),
            entity_id: target.entity.clone(),
            from_field: target.from_field.clone(),
            requires: compile_predicates(
                &target.requires,
                target_entity,
                request_entity,
                true,
                &format!("{path}.requires"),
                errors,
            ),
        });
    }
    targets.sort_by(|left, right| left.id.cmp(&right.id));

    let targets_by_id = targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let mut evidence = Vec::new();
    let mut evidence_ids = BTreeSet::new();
    for item in &source.evidence {
        let path = format!("{base}.evidence[id={}]", item.id);
        validate_id(&item.id, &format!("{path}.id"), errors);
        if !evidence_ids.insert(item.id.clone()) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.evidence_duplicate",
                &path,
                "Evidence precondition identifiers must be duplicate-free",
            ));
            continue;
        }
        let capability = match crate::action_evidence_contracts::compile_request_evidence(
            project, assets, item,
        ) {
            Ok(capability) => capability,
            Err(()) => {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.evidence_invalid",
                    &path,
                    "require one exact signed-JWS audience-scoped reviewed contract, request-origin selectors, unique typed scalar outputs, and observation age 1..300 seconds",
                ));
                continue;
            }
        };
        let mut subjects = BTreeMap::new();
        for (role, subject) in &item.subjects {
            let definition_subject = capability
                .definition
                .subjects
                .iter()
                .find(|candidate| candidate.role == *role);
            let expected_fields = definition_subject
                .into_iter()
                .flat_map(|candidate| candidate.selector.fields.iter())
                .map(registry_evidence_client::SelectorField::name)
                .collect::<BTreeSet<_>>();
            if expected_fields
                != subject
                    .selectors
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
            {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.selector_fields_invalid",
                    format!("{path}.subjects[{role}].selectors"),
                    "an Evidence subject must bind exactly every field in its reviewed selector profile",
                ));
            }
            let selectors = subject
                .selectors
                .iter()
                .filter_map(|(selector_field_id, selector)| {
                    let expected = definition_subject.and_then(|definition| {
                        definition
                            .selector
                            .fields
                            .iter()
                            .find(|field| field.name() == selector_field_id)
                    });
                    let (compiled, registry_field) = match selector {
                        ChangeRequestSelectorSource::RequestField { field } => (
                            CompiledChangeRequestSelector::RequestField {
                                field: field.clone(),
                            },
                            request_entity.fields.get(field),
                        ),
                        ChangeRequestSelectorSource::TargetField { target, field } => (
                            CompiledChangeRequestSelector::TargetField {
                                target: target.clone(),
                                field: field.clone(),
                            },
                            targets_by_id.get(target.as_str()).and_then(|selected| {
                                entities
                                    .get(&selected.entity_id)
                                    .and_then(|entity| entity.fields.get(field))
                            }),
                        ),
                    };
                    if expected.is_none_or(|expected| {
                        registry_field.is_none_or(|field| {
                            !field.required
                                || !crate::action_evidence_contracts::selector_field_matches_field_type(
                                    expected,
                                    &field.field_type,
                                )
                        })
                    }) {
                        errors.push(Diagnostic::error(
                            "change_request.preconditions.selector_binding_invalid",
                            format!(
                                "{path}.subjects[{role}].selectors[{selector_field_id}]"
                            ),
                            "an Evidence selector field must bind one required stored field of its exact scalar type",
                        ));
                        return None;
                    }
                    Some((selector_field_id.clone(), compiled))
                })
                .collect();
            subjects.insert(
                role.clone(),
                CompiledChangeRequestEvidenceSubject {
                    profile: subject.profile.clone(),
                    selectors,
                },
            );
        }
        evidence.push(CompiledChangeRequestEvidence {
            subjects,
            requires: item
                .requires
                .iter()
                .filter_map(|requirement| {
                    let expected = match (
                        requirement.equals.as_ref(),
                        requirement.equals_from_request_field.as_ref(),
                        requirement.at_least,
                        requirement.at_most,
                    ) {
                        (Some(value), None, None, None) => CompiledChangeRequestEvidenceExpected::Literal {
                            value: value.clone(),
                        },
                        (None, Some(field), None, None)
                            if request_entity.fields.get(field).is_some_and(|candidate| {
                                candidate.required
                                    && scalar_field(candidate)
                                    && crate::action_evidence_contracts::evidence_output_matches_field_type(
                                        &capability,
                                        &requirement.output,
                                        &candidate.field_type,
                                    )
                            }) =>
                        {
                            CompiledChangeRequestEvidenceExpected::RequestField {
                                field: field.clone(),
                            }
                        }
                        (None, None, Some(value), None) => {
                            CompiledChangeRequestEvidenceExpected::AtLeast { value }
                        }
                        (None, None, None, Some(value)) => {
                            CompiledChangeRequestEvidenceExpected::AtMost { value }
                        }
                        _ => {
                            errors.push(Diagnostic::error(
                                "change_request.preconditions.evidence_requirement_invalid",
                                format!("{path}.requires[output={}]", requirement.output),
                                "an Evidence output predicate must declare exactly one typed literal or required scalar request field",
                            ));
                            return None;
                        }
                    };
                    Some(CompiledChangeRequestEvidenceRequirement {
                        output: requirement.output.clone(),
                        expected,
                    })
                })
                .collect(),
            capability,
        });
    }
    evidence.sort_by(|left, right| left.capability.id.cmp(&right.capability.id));
    CompiledChangeRequestPreconditions {
        request: request_predicates,
        targets,
        evidence,
    }
}

fn compile_predicates(
    sources: &[ChangeRequestPredicateSource],
    target_entity: &CompiledEntity,
    request_entity: &CompiledEntity,
    allow_current_date: bool,
    base: &str,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestPredicate> {
    let mut compiled = Vec::new();
    let mut fields = BTreeSet::new();
    for source in sources {
        let path = format!("{base}[field={}]", source.field);
        if !fields.insert(source.field.clone()) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.predicate_duplicate",
                &path,
                "a precondition can test a stored field only once",
            ));
            continue;
        }
        let Some(target_field) = target_entity.fields.get(&source.field) else {
            errors.push(Diagnostic::error(
                "change_request.preconditions.predicate_field_unknown",
                format!("{path}.field"),
                "a precondition predicate must name a stored field",
            ));
            continue;
        };
        if !scalar_field(target_field) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.predicate_field_invalid",
                format!("{path}.field"),
                "a precondition predicate must use a scalar stored field",
            ));
            continue;
        }
        let choices = usize::from(source.equals.is_some())
            + usize::from(source.equals_from_request_field.is_some())
            + usize::from(source.current_date.is_some())
            + usize::from(source.at_least.is_some())
            + usize::from(source.at_most.is_some());
        let expected = if choices != 1 {
            errors.push(Diagnostic::error(
                "change_request.preconditions.predicate_operator_invalid",
                &path,
                "declare exactly one literal equality, request-field equality, or current UTC date comparison",
            ));
            continue;
        } else if let Some(value) = &source.equals {
            if !predicate_literal_valid(value, target_field) {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.predicate_value_invalid",
                    format!("{path}.equals"),
                    "a literal predicate must use a scalar value valid for its stored field",
                ));
                continue;
            }
            CompiledChangeRequestPredicateExpected::Literal {
                value: value.clone(),
            }
        } else if let Some(field) = &source.equals_from_request_field {
            if !request_entity
                .fields
                .get(field)
                .is_some_and(|request_field| {
                    request_field.required
                        && scalar_field(request_field)
                        && compatible_field_types(
                            &request_field.field_type,
                            &target_field.field_type,
                        )
                })
            {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.predicate_request_field_invalid",
                    format!("{path}.equalsFromRequestField"),
                    "request-field equality requires an exact compatible scalar field",
                ));
                continue;
            }
            CompiledChangeRequestPredicateExpected::RequestField {
                field: field.clone(),
            }
        } else if let Some(value) = source.at_least {
            if target_field.field_type != FieldTypeSource::Int64 {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.predicate_numeric_invalid",
                    &path,
                    "inclusive numeric predicates require an int64 field",
                ));
                continue;
            }
            CompiledChangeRequestPredicateExpected::AtLeast { value }
        } else if let Some(value) = source.at_most {
            if target_field.field_type != FieldTypeSource::Int64 {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.predicate_numeric_invalid",
                    &path,
                    "inclusive numeric predicates require an int64 field",
                ));
                continue;
            }
            CompiledChangeRequestPredicateExpected::AtMost { value }
        } else {
            if !allow_current_date || target_field.field_type != FieldTypeSource::Date {
                errors.push(Diagnostic::error(
                    "change_request.preconditions.predicate_current_date_invalid",
                    format!("{path}.currentDate"),
                    "current UTC date comparisons require a date field",
                ));
                continue;
            }
            CompiledChangeRequestPredicateExpected::CurrentDate {
                relation: match source.current_date.expect("one predicate choice") {
                    ChangeRequestCurrentDatePredicateSource::OnOrAfter => {
                        CompiledCurrentDateRelation::OnOrAfter
                    }
                    ChangeRequestCurrentDatePredicateSource::OnOrBefore => {
                        CompiledCurrentDateRelation::OnOrBefore
                    }
                },
            }
        };
        compiled.push(CompiledChangeRequestPredicate {
            field: source.field.clone(),
            expected,
        });
    }
    compiled.sort_by(|left, right| left.field.cmp(&right.field));
    compiled
}

fn scalar_field(field: &CompiledField) -> bool {
    !matches!(
        field.field_type,
        FieldTypeSource::Structured { .. } | FieldTypeSource::Crs84Point { .. }
    )
}

fn predicate_literal_valid(value: &Value, field: &CompiledField) -> bool {
    !value.is_array()
        && !value.is_object()
        && if value.is_null() {
            !field.required
        } else {
            crate::data::validate_field_value(
                crate::data::FieldValue::Json(value),
                &field.field_type,
            )
        }
}

#[allow(clippy::too_many_arguments)]
fn compile_request_entity(
    project: &RegistryProject,
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

    let mut application = compile_application(
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
    application.preconditions =
        compile_preconditions(project, request_entity, entities, assets, request, errors);
    if !application.preconditions.is_empty() {
        let base_bytes = match &planner {
            Some(planner) => maximum_planner_snapshot_bytes(request_entity, &planner.writes),
            None => maximum_snapshot_bytes(request_entity, entities, &effects),
        };
        let combined = base_bytes.and_then(|base| {
            maximum_precondition_snapshot_bytes(
                request_entity,
                entities,
                &application.preconditions,
            )
            .and_then(|guards| base.checked_add(guards))
        });
        if combined.is_none_or(|bytes| bytes > u64::from(MAX_CHANGE_REQUEST_SNAPSHOT_BYTES)) {
            errors.push(Diagnostic::error(
                "change_request.preconditions.bounds",
                format!("{}.changeRequest.application.preconditions", entity_path(&request_entity.id)),
                "the compiled Evidence contracts and maximum frozen guard values exceed the remaining proposal snapshot ceiling",
            ));
        }
    }
    let actions = compile_action_routes(&stages);
    let review_permissions =
        compile_review_permissions(request_entity, &stages, &changed_fields, entities, errors);
    let authority_targets = target_entities
        .iter()
        .cloned()
        .chain(
            application
                .preconditions
                .targets
                .iter()
                .map(|target| target.entity_id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let apply_permissions =
        compile_apply_permissions(request_entity, &authority_targets, entities, errors);
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
        &review_permissions,
        &apply_permissions,
        &authority_targets,
        errors,
    );
    let contract_fingerprint = contract_fingerprint(ContractFingerprintInput {
        request_entity,
        entities,
        effects: &effects,
        stages: &stages,
        review_permissions: &review_permissions,
        apply_permissions: &apply_permissions,
        target_entities: &authority_targets,
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
        review_permissions,
        apply_permissions,
        presence_permissions: Vec::new(),
        // This public set names records mutated by the request. Read-only
        // application guard entities are represented by apply grants and the
        // frozen precondition contract instead of becoming change targets.
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
    review_permissions: &[CompiledChangeRequestReviewPermission],
    apply_permissions: &[CompiledChangeRequestApplyPermission],
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
                            review_permissions.iter().any(|grant| {
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
                apply_permissions.iter().any(|grant| {
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

fn compile_review_permissions(
    request_entity: &CompiledEntity,
    stages: &[CompiledChangeRequestStage],
    changed_fields: &BTreeMap<String, BTreeSet<String>>,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestReviewPermission> {
    let stage_ids = stages
        .iter()
        .map(|stage| stage.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut permissions = Vec::new();
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
                    "review stage permissions require approve_request, reject_request, or request_revision authority",
                ));
            }
            let stage_permission_path =
                format!("{profile_base}.reviewStages[stage={}]", grant.stage);
            if !stage_ids.contains(grant.stage.as_str()) {
                errors.push(Diagnostic::error(
                    "change_request.review_stage.unknown",
                    format!("{stage_permission_path}.stage"),
                    "a review permission refers to an unknown review stage",
                ));
                continue;
            }
            for target in &grant.targets {
                let target_permission_path =
                    format!("{stage_permission_path}.targets[entity={}]", target.entity);
                let Some(target_entity) = entities.get(&target.entity) else {
                    errors.push(Diagnostic::error(
                        "change_request.review_stage.target_unknown",
                        format!("{target_permission_path}.entity"),
                        "a review permission targets an unknown entity",
                    ));
                    continue;
                };
                validate_target_fields(
                    target_entity,
                    &target.readable_fields,
                    &format!("{target_permission_path}.readableFields"),
                    errors,
                );
                validate_row_boundaries(
                    target_entity,
                    &target.row_boundaries,
                    &format!("{target_permission_path}.rowBoundaries"),
                    errors,
                );
                validate_permission_access_requirements(
                    target_entity,
                    profile,
                    &target.row_boundaries,
                    &target_permission_path,
                    errors,
                );
                if let Some(required) = changed_fields.get(&target.entity) {
                    if !required.is_subset(&target.readable_fields) {
                        errors.push(Diagnostic::error(
                            "change_request.review_projection.incomplete",
                            format!("{target_permission_path}.readableFields"),
                            "review target projections must cover every changed target field",
                        ));
                    }
                }
                permissions.push(CompiledChangeRequestReviewPermission {
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
    permissions.sort_by(|left, right| {
        (&left.stage, &left.profile_id, &left.target_entity_id).cmp(&(
            &right.stage,
            &right.profile_id,
            &right.target_entity_id,
        ))
    });
    permissions
}

fn compile_apply_permissions(
    request_entity: &CompiledEntity,
    target_entities: &BTreeSet<String>,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledChangeRequestApplyPermission> {
    let mut permissions = Vec::new();
    for profile in request_entity.access_profiles.values() {
        let profile_base = profile_path(&request_entity.id, &profile.id);
        if !profile.apply_targets.is_empty()
            && !profile.operations.contains(&Operation::ApplyRequest)
        {
            errors.push(Diagnostic::error(
                "change_request.apply_target.operation_required",
                format!("{profile_base}.operations"),
                "apply target permissions require apply_request authority",
            ));
        }
        for target in &profile.apply_targets {
            let target_permission_path =
                format!("{profile_base}.applyTargets[entity={}]", target.entity);
            let Some(target_entity) = entities.get(&target.entity) else {
                errors.push(Diagnostic::error(
                    "change_request.apply_target.unknown",
                    format!("{target_permission_path}.entity"),
                    "an apply permission targets an unknown entity",
                ));
                continue;
            };
            validate_row_boundaries(
                target_entity,
                &target.row_boundaries,
                &format!("{target_permission_path}.rowBoundaries"),
                errors,
            );
            validate_permission_access_requirements(
                target_entity,
                profile,
                &target.row_boundaries,
                &target_permission_path,
                errors,
            );
            permissions.push(CompiledChangeRequestApplyPermission {
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
    permissions.sort_by(|left, right| {
        (&left.profile_id, &left.target_entity_id)
            .cmp(&(&right.profile_id, &right.target_entity_id))
    });
    permissions
}

fn compile_presence_permissions(
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
                        "a request-presence permission refers to an unknown request type",
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
                validate_permission_access_requirements(
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
                        "a request-presence permission must name a request type that can affect the granted target entity",
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
                    plan.presence_permissions
                        .push(CompiledChangeRequestPresencePermission {
                            profile_id: profile.id.clone(),
                            target_entity_id: target_entity.id.clone(),
                            request_row_boundaries: grant.row_boundaries.clone(),
                        });
                }
            }
        }
    }
    for plan in plans.values_mut() {
        plan.presence_permissions.sort_by(|left, right| {
            (&left.target_entity_id, &left.profile_id)
                .cmp(&(&right.target_entity_id, &right.profile_id))
        });
    }
}

fn validate_permission_access_requirements(
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
        if !entity.fields.contains_key(field) && !entity.attachments.contains_key(field) {
            errors.push(Diagnostic::error(
                "change_request.permission.field_unknown",
                path,
                "a change-request permission refers to an unknown target field or attachment slot",
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
                "change_request.permission.row_boundary_invalid",
                path,
                "change-request permission row boundaries must be direct, non-empty, and duplicate-free",
            ));
        }
        if boundary.field == "id" {
            continue;
        }
        let Some(field) = entity.fields.get(&boundary.field) else {
            errors.push(Diagnostic::error(
                "change_request.permission.row_boundary_field_unknown",
                path,
                "a change-request permission row boundary refers to an unknown field",
            ));
            continue;
        };
        if matches!(
            field.field_type,
            FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
        ) {
            errors.push(Diagnostic::error(
                "change_request.permission.row_boundary_type_unsupported",
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

// Account for the exact frozen shape, including each cloned reviewed definition.
// Null placeholders avoid allocating maximum-sized strings during compilation.
fn maximum_precondition_snapshot_bytes(
    request_entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
    contract: &CompiledChangeRequestPreconditions,
) -> Option<u64> {
    let mut request_fields = BTreeSet::new();
    let mut target_fields = BTreeMap::<&str, BTreeSet<&str>>::new();
    for predicate in &contract.request {
        request_fields.insert(predicate.field.as_str());
        if let CompiledChangeRequestPredicateExpected::RequestField { field } = &predicate.expected
        {
            request_fields.insert(field.as_str());
        }
    }
    for target in &contract.targets {
        request_fields.insert(target.from_field.as_str());
        let fields = target_fields.entry(target.id.as_str()).or_default();
        for predicate in &target.requires {
            fields.insert(predicate.field.as_str());
            if let CompiledChangeRequestPredicateExpected::RequestField { field } =
                &predicate.expected
            {
                request_fields.insert(field.as_str());
            }
        }
    }
    for evidence in &contract.evidence {
        for selector in evidence
            .subjects
            .values()
            .flat_map(|subject| subject.selectors.values())
        {
            match selector {
                CompiledChangeRequestSelector::RequestField { field } => {
                    request_fields.insert(field.as_str());
                }
                CompiledChangeRequestSelector::TargetField { target, field } => {
                    target_fields
                        .get_mut(target.as_str())?
                        .insert(field.as_str());
                }
            }
        }
        for requirement in &evidence.requires {
            if let CompiledChangeRequestEvidenceExpected::RequestField { field } =
                &requirement.expected
            {
                request_fields.insert(field.as_str());
            }
        }
    }
    let mut extra = 0_u64;
    let mut values = |entity: &CompiledEntity,
                      fields: &BTreeSet<&str>|
     -> Option<BTreeMap<String, Value>> {
        let mut placeholders = BTreeMap::new();
        for id in fields {
            let field = entity.fields.get(*id)?;
            extra = extra.checked_add(maximum_field_json_bytes(&field.field_type)?.max(4) - 4)?;
            placeholders.insert((*id).to_owned(), Value::Null);
        }
        Some(placeholders)
    };
    let request_values = values(request_entity, &request_fields)?;
    let mut targets = Vec::new();
    for target in &contract.targets {
        targets.push(json!({
            "id":target.id, "entityId":target.entity_id,
            "recordId":"ffffffff-ffff-4fff-bfff-ffffffffffff", "expectedRevision":9_007_199_254_740_991_i64,
            "values":values(entities.get(&target.entity_id)?, target_fields.get(target.id.as_str())?)?,
        }));
    }
    // Canonical JSON admits only safe integers in the placeholder, while
    // PostgreSQL can retain an i64 revision. Reserve three digits per target.
    extra = extra.checked_add(3_u64.checked_mul(targets.len() as u64)?)?;
    let frozen = json!({"contract":contract, "requestValues":request_values, "targets":targets});
    (canonicalize_json(&frozen).ok()?.len() as u64).checked_add(extra)
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
    review_permissions: &'a [CompiledChangeRequestReviewPermission],
    apply_permissions: &'a [CompiledChangeRequestApplyPermission],
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
        review_permissions,
        apply_permissions,
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
            review_permissions.iter().map(|grant| grant.profile_id.as_str()).collect(),
            [Operation::ApproveRequest, Operation::RejectRequest, Operation::RequestRevision]
        ),
        "reviewPermissions": review_permission_payload(review_permissions),
        "applyAuthority": authority_payload(
            request_entity,
            apply_permissions.iter().map(|grant| grant.profile_id.as_str()).collect(),
            [Operation::ApplyRequest]
        ),
        "applyPermissions": apply_permission_payload(apply_permissions),
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
        || !application.preconditions.is_empty()
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
            let mut payload = json!({
                "type": field.field_type,
                "required": field.required,
                "classification": field.classification,
                "validTimeRole": field.valid_time_role,
            });
            if let Some(pattern) = &field.pattern {
                payload["postgresPattern"] = json!(pattern);
            }
            (field_id.clone(), payload)
        })
        .collect::<BTreeMap<_, _>>();
    let mut payload = json!({
        "id": entity.id,
        "route": entity.route,
        "mutationMode": entity.mutation_mode,
        "tombstone": entity.tombstone,
        "classification": entity.classification,
        "accessRequirements": entity.access_requirements,
        "fields": fields,
        "constraints": entity.constraints,
        "changeControl": entity.change_control,
    });
    if !entity.attachments.is_empty() {
        payload["attachments"] = json!(entity.attachments);
    }
    payload
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

fn review_permission_payload(
    grants: &[CompiledChangeRequestReviewPermission],
) -> Vec<serde_json::Value> {
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

fn apply_permission_payload(
    grants: &[CompiledChangeRequestApplyPermission],
) -> Vec<serde_json::Value> {
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
