// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use uuid::Uuid;

use crate::artifacts::{event_data_schema_binding, generate_artifacts};
use crate::contract::{
    parsed_bbox, valid_decimal_bounds, valid_structured_schema, AccessProfileSource, ActionSource,
    Classification, ConstraintSource, DerivedExecutionSource, DerivedFieldSource,
    EntityExtensionSource, EntitySource, EventConditionSource, EventScalarValue, EventTrigger,
    FieldSource, FieldTypeSource, LookupValueOrigin, ManifestProjectionTextSource,
    ModuleAssetSource, MutationMode, Operation, ReadPathGrantSource, RegistryModule,
    RegistryProject, UniqueWhenPredicate, ValidTimeRole, WebhookAuthenticationProfile,
    WebhookDeadLetterMode, MAX_STRUCTURED_VALUE_BYTES,
};
use crate::derived_sql::{validate_derived_sql, MAX_DERIVED_SQL_BYTES};
use crate::diagnostics::{CompileFailure, Diagnostic};
use crate::generated_ddl::generate_ddl_with_actions;
use crate::immediate_actions::{compile_immediate_actions, CollectedActionSource};
use crate::logical_names::{
    default_api_name, default_sql_name, reserved_logical_name, valid_api_name,
};
use crate::model::{
    request_query_field_id_for_api, request_state_query_filter_fields,
    request_state_query_sort_fields,
};
use crate::model::{
    ChangeRequestOperation, CompiledAccessEntry, CompiledAccessInventory, CompiledChangeControl,
    CompiledDerivedField, CompiledDerivedRelation, CompiledEntity, CompiledEventDelivery,
    CompiledEventDeliveryInventory, CompiledField, CompiledLogicalField, CompiledMetadataEntity,
    CompiledMetadataEntry, CompiledMetadataInventory, CompiledModuleIdentity,
    CompiledQueryFilterField, CompiledQueryFilterOperator, CompiledQueryInventory,
    CompiledQueryKind, CompiledQueryOperation, CompiledQuerySortDirection, CompiledQuerySortField,
    CompiledQueryTemporalBinding, CompiledQueryTemporalSemantics, CompiledReadPath,
    CompiledRegistry, CompiledRevisionKind, CompiledRoute, CompiledRouteInventory,
    CompiledSelectorProfile, CompiledSourceRelation, CompiledStoredField, CompiledTemporal,
    CompiledWebhookDeliveryMode, CompiledWebhookRetryProfile, HttpMethod,
    MAX_REVISION_HISTORY_RECORDS,
};
use crate::physical_names::{
    hex_prefix, EntityPhysicalNames, PhysicalNameBuilder, PhysicalNameInventory,
};

pub const AUTHORING_API_VERSION: &str = "registry.registrystack.org/v1alpha1";
pub const MAX_BATCH_ITEMS: u16 = 100;
pub const MAX_BATCH_BYTES: u32 = 2_097_152;
pub const MIN_WEBHOOK_ATTEMPT_TIMEOUT_MS: u32 = 100;
pub const WEBHOOK_ATTEMPT_TIMEOUT_MS: u32 = 5_000;
pub const WEBHOOK_INITIAL_BACKOFF_MS: u32 = 1_000;
pub const WEBHOOK_MAXIMUM_BACKOFF_MS: u32 = 8_000;
pub const WEBHOOK_MAXIMUM_ATTEMPTS: u8 = 5;
pub const MAX_WEBHOOK_ATTEMPT_TIMEOUT_MS: u32 = WEBHOOK_ATTEMPT_TIMEOUT_MS;
pub const MAX_WEBHOOK_ATTEMPTS: u8 = WEBHOOK_MAXIMUM_ATTEMPTS;
pub const MAX_EVENT_PACKAGE_REVISION_BYTES: u32 = 256;
/// Maximum canonical event body accepted by the governed webhook transport.
///
/// This intentionally matches the platform event-destination body ceiling.
/// Keeping it in the pure compiler avoids pulling an HTTP client into the
/// default no-I/O authoring graph; the runtime integration pins the equality.
pub const MAX_WEBHOOK_PAYLOAD_BYTES: u32 = 1_048_576;
pub const WEBHOOK_BACKOFF_MULTIPLIER: u8 = 2;

type CollectedEntities = (
    BTreeMap<String, EntitySource>,
    DerivedOriginMap,
    BTreeMap<String, CollectedActionSource>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileProfile {
    Authoring,
    Production,
}

/// Compile governed source without opening a file, network connection, or database.
pub fn compile_project(
    project: &RegistryProject,
    modules: &[RegistryModule],
    profile: CompileProfile,
) -> Result<CompiledRegistry, CompileFailure> {
    compile_project_with_assets(project, modules, &[], profile)
}

/// Compile governed source and caller-supplied module assets without opening files.
pub fn compile_project_with_assets(
    project: &RegistryProject,
    modules: &[RegistryModule],
    assets: &[ModuleAssetSource],
    profile: CompileProfile,
) -> Result<CompiledRegistry, CompileFailure> {
    let mut diagnostics = Vec::new();
    let mut findings = Vec::new();
    validate_project_header(project, profile, &mut diagnostics, &mut findings);
    let module_closure = validate_module_locks(
        project,
        modules,
        assets,
        profile,
        &mut diagnostics,
        &mut findings,
    );
    let (module_order, module_map) = order_modules(project, modules, &mut diagnostics);
    let (mut sources, mut derived_origins, mut action_sources) =
        collect_entities(project, &module_order, &module_map, &mut diagnostics);
    apply_temporal_roles(&mut sources, &mut diagnostics);
    apply_extensions(
        &mut sources,
        &mut derived_origins,
        &module_order,
        &module_map,
        &mut diagnostics,
    );
    validate_project_entity_access_profiles(project, &mut diagnostics);
    expand_project_access(project, &mut sources, &mut diagnostics);
    resolve_vocabularies(project, &mut sources, &mut action_sources, &mut diagnostics);
    validate_entities(&sources, profile, &mut diagnostics);
    crate::access::validate_access_requirements(&sources, &mut diagnostics);
    findings.extend(crate::access::access_findings(&sources));
    validate_derived_assets(&sources, &derived_origins, assets, &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(CompileFailure::from_errors(diagnostics));
    }

    let (mut entities, physical_names) = compile_entities(&sources, &derived_origins, assets)?;
    crate::change_request::compile_change_requests(&sources, &mut entities)
        .map_err(CompileFailure::from_errors)?;
    let action_inventory =
        compile_immediate_actions(&action_sources, &entities, &project.access_profiles)
            .map_err(CompileFailure::from_errors)?;
    let (route_inventory, access_inventory) = compile_routes_and_access(&entities)?;
    let metadata_inventory = compile_metadata_inventory(
        &project.registry.id,
        &project.registry.version,
        &entities,
        &route_inventory,
        &access_inventory,
    )
    .map_err(CompileFailure::from_one)?;
    let query_inventory = compile_query_inventory(&entities, &mut diagnostics);
    let event_delivery_inventory =
        compile_event_delivery_inventory(&project.registry.id, &entities)
            .map_err(CompileFailure::from_one)?;
    validate_manifest_projection(project, &entities, &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(CompileFailure::from_errors(diagnostics));
    }
    let ddl = generate_ddl_with_actions(&entities, &physical_names, &action_inventory);
    let artifacts = generate_artifacts(
        &project.registry.id,
        &project.registry.version,
        &project.registry.default_language,
        project.package.as_ref(),
        project.manifest_projection.as_ref(),
        &module_order,
        &module_closure,
        &entities,
        &physical_names,
        &action_inventory,
        &route_inventory,
        &access_inventory,
        &metadata_inventory,
        &query_inventory,
        &event_delivery_inventory,
        &ddl,
    )
    .map_err(CompileFailure::from_one)?;
    let artifact_bytes = artifacts
        .canonical_inventory_bytes()
        .map_err(CompileFailure::from_one)?;
    let revision_digest = Sha256::digest(artifact_bytes);
    let revision = format!(
        "sha256:{}",
        hex_prefix(&revision_digest, revision_digest.len())
    );
    findings.sort();

    Ok(CompiledRegistry::new(
        project.registry.id.clone(),
        project.registry.version.clone(),
        project.registry.default_language.clone(),
        project.package.clone(),
        project.manifest_projection.clone(),
        module_order,
        module_closure,
        entities,
        physical_names,
        action_inventory,
        route_inventory,
        access_inventory,
        metadata_inventory,
        query_inventory,
        event_delivery_inventory,
        ddl,
        artifacts,
        findings,
        revision,
    ))
}

fn validate_project_header(
    project: &RegistryProject,
    profile: CompileProfile,
    errors: &mut Vec<Diagnostic>,
    findings: &mut Vec<Diagnostic>,
) {
    if project.api_version != AUTHORING_API_VERSION {
        errors.push(Diagnostic::error(
            "project.api_version.unsupported",
            "project.apiVersion",
            "the project uses an unsupported API version",
        ));
    }
    if project.kind != "RegistryProject" {
        errors.push(Diagnostic::error(
            "project.kind.unsupported",
            "project.kind",
            "the project uses an unsupported document kind",
        ));
    }
    validate_id(&project.registry.id, "project.registry.id", errors);
    nonempty(
        &project.registry.version,
        "project.registry.version",
        "project.version.empty",
        errors,
    );
    validate_language(&project.registry.default_language, errors);

    match (&project.package, profile) {
        (None, CompileProfile::Authoring) => findings.push(Diagnostic::finding(
            "package.identity.missing",
            "project.package",
            "production package identity has not been declared",
        )),
        (None, CompileProfile::Production) => errors.push(Diagnostic::error(
            "package.identity.required",
            "project.package",
            "production compilation requires package identity",
        )),
        (Some(package), _) => {
            validate_id(&package.environment, "project.package.environment", errors);
            validate_id(&package.instance_id, "project.package.instanceId", errors);
            if package.sequence == 0 {
                errors.push(Diagnostic::error(
                    "package.sequence.invalid",
                    "project.package.sequence",
                    "package sequence must be positive",
                ));
            }
            nonempty(
                &package.source_revision,
                "project.package.sourceRevision",
                "package.source_revision.empty",
                errors,
            );
        }
    }

    match (&project.manifest_projection, profile) {
        (None, CompileProfile::Authoring) => findings.push(Diagnostic::finding(
            "manifest_projection.missing",
            "project.manifestProjection",
            "production Registry Manifest projection has not been declared",
        )),
        (None, CompileProfile::Production) => {}
        (Some(projection), _) => {
            validate_id(
                &projection.access_profile,
                "project.manifestProjection.accessProfile",
                errors,
            );
            nonempty(
                &projection.catalog.base_url,
                "project.manifestProjection.catalog.baseUrl",
                "manifest_projection.catalog.base_url.empty",
                errors,
            );
            validate_projection_text(
                &projection.catalog.title,
                "project.manifestProjection.catalog.title",
                errors,
            );
            nonempty(
                &projection.catalog.publisher.name,
                "project.manifestProjection.catalog.publisher.name",
                "manifest_projection.catalog.publisher.name_empty",
                errors,
            );
            if let Some(description) = projection.catalog.description.as_ref() {
                validate_projection_text(
                    description,
                    "project.manifestProjection.catalog.description",
                    errors,
                );
            }
            if let Some(description) = projection.dataset.description.as_ref() {
                validate_projection_text(
                    description,
                    "project.manifestProjection.dataset.description",
                    errors,
                );
            }
            validate_projection_text(
                &projection.dataset.title,
                "project.manifestProjection.dataset.title",
                errors,
            );
            if projection
                .dataset
                .owner
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                errors.push(Diagnostic::error(
                    "manifest_projection.dataset.owner_empty",
                    "project.manifestProjection.dataset.owner",
                    "optional Registry Manifest projection text must not be empty",
                ));
            }
            if let Some(service) = projection.data_service.as_ref() {
                validate_id(
                    &service.id,
                    "project.manifestProjection.dataService.id",
                    errors,
                );
                validate_projection_text(
                    &service.title,
                    "project.manifestProjection.dataService.title",
                    errors,
                );
                if let Some(description) = service.description.as_ref() {
                    validate_projection_text(
                        description,
                        "project.manifestProjection.dataService.description",
                        errors,
                    );
                }
                nonempty(
                    &service.endpoint_url,
                    "project.manifestProjection.dataService.endpointUrl",
                    "manifest_projection.data_service.endpoint_url_empty",
                    errors,
                );
            }
        }
    }

    let mut locks = BTreeSet::new();
    for lock in &project.modules {
        validate_id(&lock.id, "project.modules[].id", errors);
        if !locks.insert(lock.id.as_str()) {
            errors.push(Diagnostic::error(
                "module.lock.duplicate",
                "project.modules[].id",
                "a module lock identifier is duplicated",
            ));
        }
        match (&lock.digest, profile) {
            (None, CompileProfile::Authoring) => findings.push(Diagnostic::finding(
                "module.lock.digest_missing",
                "project.modules[].digest",
                "the authoring module lock has no production digest",
            )),
            (None, CompileProfile::Production) => errors.push(Diagnostic::error(
                "module.lock.digest_required",
                "project.modules[].digest",
                "production compilation requires every module digest",
            )),
            (Some(digest), _) if !valid_sha256(digest) => errors.push(Diagnostic::error(
                "module.lock.digest_invalid",
                "project.modules[].digest",
                "the module digest is not a canonical SHA-256 identifier",
            )),
            _ => {}
        }
    }
}

fn validate_manifest_projection(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(projection) = project.manifest_projection.as_ref() else {
        return;
    };
    let selected_profiles = entities
        .values()
        .filter_map(|entity| entity.access_profiles.get(&projection.access_profile))
        .collect::<Vec<_>>();
    if selected_profiles.is_empty() {
        errors.push(Diagnostic::error(
            "manifest_projection.access_profile.unknown",
            "project.manifestProjection.accessProfile",
            "the Registry Manifest projection selects an unknown access profile",
        ));
    }
    if selected_profiles
        .iter()
        .any(|profile| profile.anonymous != selected_profiles[0].anonymous)
    {
        errors.push(Diagnostic::error(
            "manifest_projection.access_profile.ambiguous",
            "project.manifestProjection.accessProfile",
            "the Registry Manifest projection access profile must have one disclosure mode",
        ));
    }

    let visible = entities
        .values()
        .filter(|entity| entity.classification <= projection.classification_ceiling)
        .filter_map(|entity| {
            let profile = entity.access_profiles.get(&projection.access_profile)?;
            (profile.operations.contains(&Operation::Get)
                || profile.operations.contains(&Operation::List))
            .then(|| {
                let fields = entity
                    .fields
                    .values()
                    .filter(|field| profile.readable_fields.contains(&field.id))
                    .filter(|field| field.classification <= projection.classification_ceiling)
                    .map(|field| (field.id.as_str(), field))
                    .collect::<BTreeMap<_, _>>();
                (entity.id.as_str(), (entity, fields))
            })
        })
        .collect::<BTreeMap<_, _>>();

    let mut entity_ids = BTreeSet::new();
    for metadata in &projection.entities {
        let path = format!("project.manifestProjection.entities[{}]", metadata.id);
        if !entity_ids.insert(metadata.id.as_str()) {
            errors.push(Diagnostic::error(
                "manifest_projection.entity.duplicate",
                path,
                "Registry Manifest entity metadata must be unique",
            ));
            continue;
        }
        let Some((_entity, visible_fields)) = visible.get(metadata.id.as_str()) else {
            errors.push(Diagnostic::error(
                "manifest_projection.entity.not_visible",
                path,
                "Registry Manifest metadata may describe only an entity visible through the selected access profile",
            ));
            continue;
        };
        if let Some(title) = metadata.title.as_ref() {
            validate_projection_text(title, &format!("{path}.title"), errors);
        }
        if let Some(description) = metadata.description.as_ref() {
            validate_projection_text(description, &format!("{path}.description"), errors);
        }
        let mut identifier_fields = BTreeSet::new();
        for identifier in &metadata.identifiers {
            let field_is_projected = visible_fields
                .get(identifier.field.as_str())
                .is_some_and(|field| manifest_projects_field(field));
            if !identifier_fields.insert(identifier.field.as_str())
                || !field_is_projected
                || identifier.kind.trim().is_empty()
            {
                errors.push(Diagnostic::error(
                    "manifest_projection.identifier.invalid",
                    format!("{path}.identifiers[{}]", identifier.field),
                    "Registry Manifest identifiers must uniquely reference visible fields and declare a kind",
                ));
            }
        }
        let mut field_ids = BTreeSet::new();
        for field_metadata in &metadata.fields {
            let field_path = format!("{path}.fields[{}]", field_metadata.id);
            if !field_ids.insert(field_metadata.id.as_str()) {
                errors.push(Diagnostic::error(
                    "manifest_projection.field.duplicate",
                    field_path,
                    "Registry Manifest field metadata must be unique within an entity",
                ));
                continue;
            }
            let Some(field) = visible_fields.get(field_metadata.id.as_str()) else {
                errors.push(Diagnostic::error(
                    "manifest_projection.field.not_visible",
                    field_path,
                    "Registry Manifest metadata may describe only a field visible through the selected access profile",
                ));
                continue;
            };
            let is_reference = matches!(&field.field_type, FieldTypeSource::Reference { .. });
            if !is_reference && !manifest_projects_field(field) {
                errors.push(Diagnostic::error(
                    "manifest_projection.field.not_representable",
                    field_path,
                    "Registry Manifest field metadata may describe only a field representable by the portable Manifest model",
                ));
                continue;
            }
            let has_scalar_metadata = !field_metadata.concepts.is_empty()
                || field_metadata.unit.is_some()
                || field_metadata.language.is_some();
            let has_relationship_metadata = field_metadata.relationship_role.is_some()
                || field_metadata.relationship_concept_uri.is_some();
            if (is_reference && has_scalar_metadata) || (!is_reference && has_relationship_metadata)
            {
                errors.push(Diagnostic::error(
                    "manifest_projection.field.metadata_kind",
                    field_path,
                    "Registry Manifest scalar and relationship metadata must match the configured field type",
                ));
            }
        }
    }

    let visible_vocabularies = visible
        .values()
        .flat_map(|(_entity, fields)| fields.values())
        .filter_map(|field| match &field.field_type {
            FieldTypeSource::VocabularyCode { vocabulary, values } => {
                Some((vocabulary.as_str(), values.as_slice()))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut vocabulary_ids = BTreeSet::new();
    for metadata in &projection.vocabularies {
        let path = format!("project.manifestProjection.vocabularies[{}]", metadata.id);
        if !vocabulary_ids.insert(metadata.id.as_str()) {
            errors.push(Diagnostic::error(
                "manifest_projection.vocabulary.duplicate",
                path,
                "Registry Manifest vocabulary metadata must be unique",
            ));
            continue;
        }
        let Some(values) = visible_vocabularies.get(metadata.id.as_str()) else {
            errors.push(Diagnostic::error(
                "manifest_projection.vocabulary.not_visible",
                path,
                "Registry Manifest metadata may describe only a vocabulary used by a visible field",
            ));
            continue;
        };
        let mut codes = BTreeSet::new();
        for concept in &metadata.concepts {
            if !codes.insert(concept.code.as_str()) || !values.contains(&concept.code) {
                errors.push(Diagnostic::error(
                    "manifest_projection.vocabulary.concept_invalid",
                    format!("{path}.concepts[{}]", concept.code),
                    "Registry Manifest vocabulary concepts must uniquely reference configured codes",
                ));
            }
            if let Some(label) = concept.label.as_ref() {
                validate_projection_text(label, &format!("{path}.concepts[].label"), errors);
            }
        }
    }
}

fn order_modules(
    project: &RegistryProject,
    modules: &[RegistryModule],
    errors: &mut Vec<Diagnostic>,
) -> (Vec<String>, BTreeMap<String, RegistryModule>) {
    let locked: BTreeSet<&str> = project
        .modules
        .iter()
        .map(|lock| lock.id.as_str())
        .collect();
    let mut module_map = BTreeMap::new();
    for module in modules {
        validate_id(&module.id, "modules[].id", errors);
        if module_map
            .insert(module.id.clone(), module.clone())
            .is_some()
        {
            errors.push(Diagnostic::error(
                "module.id.duplicate",
                "modules[].id",
                "a module identifier is duplicated",
            ));
        }
    }

    for module in module_map.values() {
        let mut dependencies = BTreeSet::new();
        for dependency in &module.dependencies {
            if !dependencies.insert(dependency) {
                errors.push(Diagnostic::error(
                    "module.dependency.duplicate",
                    "modules[].dependencies[]",
                    "a module dependency is duplicated",
                ));
            }
            if !module_map.contains_key(dependency) && !locked.contains(dependency.as_str()) {
                errors.push(Diagnostic::error(
                    "module.dependency.unknown",
                    "modules[].dependencies[]",
                    "a module dependency does not resolve",
                ));
            }
        }
    }

    let mut indegree: BTreeMap<String, usize> =
        module_map.keys().map(|id| (id.clone(), 0_usize)).collect();
    let mut outgoing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for module in module_map.values() {
        for dependency in &module.dependencies {
            if module_map.contains_key(dependency) {
                *indegree.get_mut(&module.id).expect("module was indexed") += 1;
                outgoing
                    .entry(dependency.clone())
                    .or_default()
                    .push(module.id.clone());
            }
        }
    }
    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut ordered_external = Vec::new();
    while let Some(id) = ready.pop_first() {
        ordered_external.push(id.clone());
        for dependent in outgoing.get(&id).into_iter().flatten() {
            let degree = indegree.get_mut(dependent).expect("dependent was indexed");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if ordered_external.len() != module_map.len() {
        errors.push(Diagnostic::error(
            "module.dependency.cycle",
            "modules[].dependencies",
            "module dependencies contain a cycle",
        ));
    }
    let mut order: Vec<String> = project
        .modules
        .iter()
        .filter(|lock| !module_map.contains_key(&lock.id))
        .map(|lock| lock.id.clone())
        .collect();
    order.sort();
    for id in ordered_external {
        if !order.contains(&id) {
            order.push(id);
        }
    }
    (order, module_map)
}

fn validate_module_locks(
    project: &RegistryProject,
    modules: &[RegistryModule],
    assets: &[ModuleAssetSource],
    profile: CompileProfile,
    errors: &mut Vec<Diagnostic>,
    findings: &mut Vec<Diagnostic>,
) -> Vec<CompiledModuleIdentity> {
    let locks: BTreeMap<&str, _> = project
        .modules
        .iter()
        .map(|lock| (lock.id.as_str(), lock))
        .collect();
    let loaded: BTreeMap<&str, _> = modules
        .iter()
        .map(|module| (module.id.as_str(), module))
        .collect();
    let mut ordered_locks: Vec<_> = project.modules.iter().collect();
    ordered_locks.sort_by(|left, right| left.id.cmp(&right.id));
    let mut closure = Vec::new();

    for lock in ordered_locks {
        let Some(module) = loaded.get(lock.id.as_str()).copied() else {
            let diagnostic = match profile {
                CompileProfile::Authoring => Diagnostic::finding(
                    "module.source.missing",
                    "project.modules[].id",
                    "an authoring module lock has no loaded source",
                ),
                CompileProfile::Production => Diagnostic::error(
                    "module.source.required",
                    "project.modules[].id",
                    "production compilation requires one source for every module lock",
                ),
            };
            match profile {
                CompileProfile::Authoring => findings.push(diagnostic),
                CompileProfile::Production => errors.push(diagnostic),
            }
            closure.push(CompiledModuleIdentity {
                id: lock.id.clone(),
                version: lock.version.clone(),
                digest: None,
            });
            continue;
        };
        if lock.version != module.version {
            errors.push(Diagnostic::error(
                "module.lock.version_mismatch",
                "project.modules[].version",
                "an authored module does not match its locked version",
            ));
        }
        let actual = module_digest_with_assets(module, assets);
        if let Some(expected) = &lock.digest {
            if expected != &actual {
                errors.push(Diagnostic::error(
                    "module.lock.digest_mismatch",
                    "project.modules[].digest",
                    "an authored module does not match its locked digest",
                ));
            }
        }
        closure.push(CompiledModuleIdentity {
            id: module.id.clone(),
            version: module.version.clone(),
            digest: Some(actual),
        });
    }

    for module in modules {
        if locks.contains_key(module.id.as_str()) {
            continue;
        }
        let diagnostic = match profile {
            CompileProfile::Authoring => Diagnostic::finding(
                "module.lock.missing",
                "modules[].id",
                "an authoring module source has no lock entry",
            ),
            CompileProfile::Production => Diagnostic::error(
                "module.lock.missing",
                "modules[].id",
                "production compilation requires one lock for every module source",
            ),
        };
        match profile {
            CompileProfile::Authoring => findings.push(diagnostic),
            CompileProfile::Production => errors.push(diagnostic),
        }
        closure.push(CompiledModuleIdentity {
            id: module.id.clone(),
            version: module.version.clone(),
            digest: Some(module_digest(module)),
        });
    }
    closure.sort_by(|left, right| left.id.cmp(&right.id));
    closure
}

pub fn module_digest(module: &RegistryModule) -> String {
    module_digest_with_assets(module, &[])
}

pub fn module_digest_with_assets(module: &RegistryModule, assets: &[ModuleAssetSource]) -> String {
    let value = serde_json::to_value(module).expect("module serializes");
    let bytes = canonicalize_json(&value).expect("module canonicalizes");
    let mut module_assets = assets
        .iter()
        .filter(|asset| asset.module.as_deref() == Some(module.id.as_str()))
        .collect::<Vec<_>>();
    if module_assets.is_empty() {
        let digest = Sha256::digest(bytes);
        return format!("sha256:{}", hex_prefix(&digest, digest.len()));
    }
    let mut digest = Sha256::new();
    digest.update(b"registry-server-module-v2\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    module_assets.sort_by(|left, right| left.path.cmp(&right.path));
    for asset in module_assets {
        digest.update((asset.path.len() as u64).to_be_bytes());
        digest.update(asset.path.as_bytes());
        digest.update((asset.bytes.len() as u64).to_be_bytes());
        digest.update(&asset.bytes);
    }
    let digest = digest.finalize();
    format!("sha256:{}", hex_prefix(&digest, digest.len()))
}

type DerivedOriginMap = BTreeMap<(String, String), Option<String>>;

fn collect_entities(
    project: &RegistryProject,
    module_order: &[String],
    modules: &BTreeMap<String, RegistryModule>,
    errors: &mut Vec<Diagnostic>,
) -> CollectedEntities {
    let mut entities = BTreeMap::new();
    let mut derived_origins = BTreeMap::new();
    let mut actions = BTreeMap::new();
    for entity in &project.entities {
        insert_entity(
            &mut entities,
            &mut derived_origins,
            entity,
            None,
            "project.entities[].id",
            errors,
        );
    }
    for action in &project.actions {
        insert_action(&mut actions, action, None, "project.actions[].id", errors);
    }
    for module_id in module_order {
        if let Some(module) = modules.get(module_id) {
            for entity in &module.entities {
                insert_entity(
                    &mut entities,
                    &mut derived_origins,
                    entity,
                    Some(module.id.clone()),
                    "modules[].entities[].id",
                    errors,
                );
            }
            for action in &module.actions {
                insert_action(
                    &mut actions,
                    action,
                    Some(module.id.clone()),
                    "modules[].actions[].id",
                    errors,
                );
            }
        }
    }
    (entities, derived_origins, actions)
}

fn insert_entity(
    entities: &mut BTreeMap<String, EntitySource>,
    derived_origins: &mut BTreeMap<(String, String), Option<String>>,
    entity: &EntitySource,
    module: Option<String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if entities.insert(entity.id.clone(), entity.clone()).is_some() {
        errors.push(Diagnostic::error(
            "entity.id.duplicate",
            path,
            "an entity identifier is contributed more than once",
        ));
        return;
    }
    for derived in &entity.derived {
        derived_origins.insert((entity.id.clone(), derived.id.clone()), module.clone());
    }
}

fn insert_action(
    actions: &mut BTreeMap<String, CollectedActionSource>,
    action: &ActionSource,
    module: Option<String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if actions
        .insert(
            action.id.clone(),
            CollectedActionSource {
                source: action.clone(),
                source_module: module,
            },
        )
        .is_some()
    {
        errors.push(Diagnostic::error(
            "action.id.duplicate",
            path,
            "an action identifier is contributed more than once",
        ));
    }
}

fn apply_temporal_roles(
    entities: &mut BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values_mut() {
        let Some(temporal) = &entity.temporal else {
            continue;
        };
        for (id, role) in [
            (&temporal.start_field, ValidTimeRole::ValidFrom),
            (&temporal.end_field, ValidTimeRole::ValidTo),
        ] {
            let Some(field) = entity.fields.iter_mut().find(|field| &field.id == id) else {
                errors.push(Diagnostic::error(
                    "temporal.field.unknown",
                    "entities[].temporal",
                    "a temporal role refers to an unknown field",
                ));
                continue;
            };
            if field
                .valid_time_role
                .is_some_and(|existing| existing != role)
            {
                errors.push(Diagnostic::error(
                    "temporal.role.conflict",
                    "entities[].temporal",
                    "a temporal role conflicts with the field declaration",
                ));
            } else {
                field.valid_time_role = Some(role);
            }
        }
    }
}

fn apply_extensions(
    entities: &mut BTreeMap<String, EntitySource>,
    derived_origins: &mut BTreeMap<(String, String), Option<String>>,
    module_order: &[String],
    modules: &BTreeMap<String, RegistryModule>,
    errors: &mut Vec<Diagnostic>,
) {
    for module_id in module_order {
        let Some(module) = modules.get(module_id) else {
            continue;
        };
        let mut extensions = module.extend_entities.clone();
        extensions.sort_by(|left, right| left.entity.cmp(&right.entity));
        for extension in &extensions {
            let Some(entity) = entities.get_mut(&extension.entity) else {
                errors.push(Diagnostic::error(
                    "extension.entity.unknown",
                    "modules[].extendEntities[].entity",
                    "an extension targets an unknown entity",
                ));
                continue;
            };
            merge_extension(
                entity,
                extension,
                Some(module.id.clone()),
                derived_origins,
                errors,
            );
        }
    }
}

fn merge_extension(
    entity: &mut EntitySource,
    extension: &EntityExtensionSource,
    module: Option<String>,
    derived_origins: &mut BTreeMap<(String, String), Option<String>>,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(requirements) = &extension.access_requirements {
        if entity.access_requirements.is_some() {
            errors.push(Diagnostic::error(
                "extension.access_requirements.replace_forbidden",
                format!("entities[id={}].accessRequirements", entity.id),
                "an extension cannot replace existing access requirements; edit and review the owning entity declaration",
            ));
        } else {
            entity.access_requirements = Some(requirements.clone());
        }
    }
    merge_by_id(
        &mut entity.fields,
        &extension.fields,
        |value| value.id.as_str(),
        "extension.field.duplicate",
        "modules[].extendEntities[].fields[].id",
        "a field identifier is contributed more than once",
        errors,
    );
    let existing_derived = entity.derived.len();
    merge_by_id(
        &mut entity.derived,
        &extension.derived,
        |value| value.id.as_str(),
        "extension.derived.duplicate",
        "modules[].extendEntities[].derived[].id",
        "a derived relation identifier is contributed more than once",
        errors,
    );
    for derived in entity.derived.iter().skip(existing_derived) {
        derived_origins.insert((entity.id.clone(), derived.id.clone()), module.clone());
    }
    merge_by_id(
        &mut entity.indexes,
        &extension.indexes,
        |value| value.id.as_str(),
        "extension.index.duplicate",
        "modules[].extendEntities[].indexes[].id",
        "an index identifier is contributed more than once",
        errors,
    );
    merge_by_id(
        &mut entity.access_profiles,
        &extension.access_profiles,
        |value| value.id.as_str(),
        "extension.access_profile.duplicate",
        "modules[].extendEntities[].accessProfiles[].id",
        "an access profile identifier is contributed more than once",
        errors,
    );
    merge_by_id(
        &mut entity.events,
        &extension.events,
        |value| value.id.as_str(),
        "extension.event.duplicate",
        "modules[].extendEntities[].events[].id",
        "an event identifier is contributed more than once",
        errors,
    );
    merge_by_id(
        &mut entity.selector_profiles,
        &extension.selector_profiles,
        |value| value.id.as_str(),
        "extension.selector_profile.duplicate",
        "modules[].extendEntities[].selectorProfiles[].id",
        "a selector profile identifier is contributed more than once",
        errors,
    );
    merge_by_id(
        &mut entity.read_paths,
        &extension.read_paths,
        |value| value.id.as_str(),
        "extension.read_path.duplicate",
        "modules[].extendEntities[].readPaths[].id",
        "a read path identifier is contributed more than once",
        errors,
    );
    merge_optional_capability(
        &mut entity.change_control,
        &extension.change_control,
        "extension.change_control.duplicate",
        "modules[].extendEntities[].changeControl",
        "a change-control capability is contributed more than once",
        errors,
    );
    merge_optional_capability(
        &mut entity.change_request,
        &extension.change_request,
        "extension.change_request.duplicate",
        "modules[].extendEntities[].changeRequest",
        "a change-request capability is contributed more than once",
        errors,
    );

    let mut known: BTreeSet<String> = entity
        .constraints
        .iter()
        .map(derived_constraint_id)
        .collect();
    for constraint in &extension.constraints {
        if known.insert(derived_constraint_id(constraint)) {
            entity.constraints.push(constraint.clone());
        } else {
            errors.push(Diagnostic::error(
                "extension.constraint.duplicate",
                "modules[].extendEntities[].constraints[]",
                "a constraint identifier is contributed more than once",
            ));
        }
    }
}

fn merge_optional_capability<T: Clone>(
    target: &mut Option<T>,
    contributed: &Option<T>,
    code: &str,
    path: &str,
    message: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(value) = contributed else {
        return;
    };
    if target.is_some() {
        errors.push(Diagnostic::error(code, path, message));
    } else {
        *target = Some(value.clone());
    }
}

#[allow(clippy::too_many_arguments)]
fn merge_by_id<T: Clone>(
    target: &mut Vec<T>,
    contributed: &[T],
    id: impl Fn(&T) -> &str,
    code: &str,
    path: &str,
    message: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let mut known: BTreeSet<String> = target.iter().map(|value| id(value).to_owned()).collect();
    for value in contributed {
        if known.insert(id(value).to_owned()) {
            target.push(value.clone());
        } else {
            errors.push(Diagnostic::error(code, path, message));
        }
    }
}

fn validate_project_entity_access_profiles(
    project: &RegistryProject,
    errors: &mut Vec<Diagnostic>,
) {
    if project
        .entities
        .iter()
        .any(|entity| !entity.access_profiles.is_empty())
    {
        errors.push(Diagnostic::error(
            "access_profile.project_entity_local.forbidden",
            "project.entities[].accessProfiles",
            "root project entities must declare access through top-level accessProfiles",
        ));
    }
}

fn expand_project_access(
    project: &RegistryProject,
    entities: &mut BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut profile_ids = BTreeSet::new();
    for profile in &project.access_profiles {
        validate_id(&profile.id, "project.accessProfiles[].id", errors);
        if !profile_ids.insert(profile.id.as_str()) {
            errors.push(Diagnostic::error(
                "access_profile.id.duplicate",
                "project.accessProfiles[].id",
                "an access profile identifier is duplicated",
            ));
        }
        if profile.anonymous {
            if profile.principal_claim.is_some() {
                errors.push(Diagnostic::error(
                    "access_profile.principal_claim.forbidden",
                    "project.accessProfiles[].principalClaim",
                    "an anonymous profile cannot declare a principal claim",
                ));
            }
            if !profile.required_scopes.is_empty() || !profile.required_purposes.is_empty() {
                errors.push(Diagnostic::error(
                    "access_profile.anonymous.claim_requirements_forbidden",
                    "project.accessProfiles[]",
                    "an anonymous profile cannot require scopes or purposes",
                ));
            }
        } else if profile.principal_claim.as_deref().is_none_or(str::is_empty) {
            errors.push(Diagnostic::error(
                "access_profile.principal_claim.required",
                "project.accessProfiles[].principalClaim",
                "an authenticated profile requires a direct principal claim",
            ));
        }
        let mut granted_entities = BTreeSet::new();
        for grant in &profile.grants {
            if grant.action.is_some() {
                if !grant.entity.is_empty() {
                    errors.push(Diagnostic::error(
                        "access_profile.grant.target_exclusive",
                        "project.accessProfiles[].grants[]",
                        "an access grant must name either one entity or one action",
                    ));
                }
                continue;
            }
            if !grant.targets.is_empty() || !grant.results.is_empty() {
                errors.push(Diagnostic::error(
                    "access_profile.grant.action_fields_forbidden",
                    "project.accessProfiles[].grants[]",
                    "entity access grants cannot declare action target or result fields",
                ));
            }
            if grant.entity.is_empty() {
                errors.push(Diagnostic::error(
                    "access_profile.grant.target_missing",
                    "project.accessProfiles[].grants[]",
                    "an access grant must name either one entity or one action",
                ));
                continue;
            }
            if !granted_entities.insert(grant.entity.as_str()) {
                errors.push(Diagnostic::error(
                    "access_profile.grant.duplicate",
                    "project.accessProfiles[].grants[].entity",
                    "an access profile contains duplicate entity grants",
                ));
                continue;
            }
            let Some(entity) = entities.get_mut(&grant.entity) else {
                errors.push(Diagnostic::error(
                    "access_profile.grant.entity_unknown",
                    "project.accessProfiles[].grants[].entity",
                    "an access grant refers to an unknown entity",
                ));
                continue;
            };
            if entity
                .access_profiles
                .iter()
                .any(|existing| existing.id == profile.id)
            {
                errors.push(Diagnostic::error(
                    "access_profile.id.duplicate",
                    "project.accessProfiles[].id",
                    "an access profile identifier is duplicated for an entity",
                ));
                continue;
            }
            entity.access_profiles.push(AccessProfileSource {
                id: profile.id.clone(),
                default: profile.default,
                anonymous: profile.anonymous,
                principal_claim: profile.principal_claim.clone(),
                required_scopes: profile.required_scopes.clone(),
                required_purposes: profile.required_purposes.clone(),
                operations: grant.operations.clone(),
                readable_fields: grant.readable_fields.clone(),
                writable_fields: grant.writable_fields.clone(),
                filterable_fields: grant.filterable_fields.clone(),
                sortable_fields: grant.sortable_fields.clone(),
                row_boundaries: grant.row_boundaries.clone(),
                lookups: grant.lookups.clone(),
                read_paths: grant.read_paths.clone(),
                review_stages: grant.review_stages.clone(),
                apply_targets: grant.apply_targets.clone(),
                request_presence: grant.request_presence.clone(),
                allow_count: grant.allow_count,
                revision_access: grant.revision_access,
                allow_data_export: grant.allow_data_export,
            });
        }
    }
}

fn resolve_vocabularies(
    project: &RegistryProject,
    entities: &mut BTreeMap<String, EntitySource>,
    actions: &mut BTreeMap<String, CollectedActionSource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut vocabularies = BTreeMap::new();
    for vocabulary in &project.vocabularies {
        validate_id(&vocabulary.id, "project.vocabularies[].id", errors);
        if vocabulary.values.is_empty()
            || has_duplicates(&vocabulary.values)
            || vocabulary.values.iter().any(|value| !valid_code(value))
        {
            errors.push(Diagnostic::error(
                "vocabulary.values.invalid",
                "project.vocabularies[].values",
                "a vocabulary must contain a non-empty duplicate-free value set",
            ));
        }
        if vocabularies
            .insert(vocabulary.id.clone(), vocabulary.values.clone())
            .is_some()
        {
            errors.push(Diagnostic::error(
                "vocabulary.id.duplicate",
                "project.vocabularies[].id",
                "a vocabulary identifier is duplicated",
            ));
        }
    }
    for entity in entities.values_mut() {
        for field in &mut entity.fields {
            if let FieldTypeSource::VocabularyCode { vocabulary, values } = &mut field.field_type {
                if values.is_empty() {
                    if let Some(resolved) = vocabularies.get(vocabulary) {
                        *values = resolved.clone();
                    } else {
                        errors.push(Diagnostic::error(
                            "field.vocabulary.unknown",
                            "entities[].fields[].vocabulary",
                            "a field refers to an unknown vocabulary",
                        ));
                    }
                }
            }
        }
    }
    for action in actions.values_mut() {
        for input in &mut action.source.inputs {
            if let FieldTypeSource::VocabularyCode { vocabulary, values } = &mut input.field_type {
                if values.is_empty() {
                    if let Some(resolved) = vocabularies.get(vocabulary) {
                        *values = resolved.clone();
                    } else {
                        errors.push(Diagnostic::error(
                            "action.input.vocabulary.unknown",
                            "actions[].inputs[].vocabulary",
                            "an action input refers to an unknown vocabulary",
                        ));
                    }
                }
            }
        }
    }
}

fn validate_entities(
    entities: &BTreeMap<String, EntitySource>,
    profile: CompileProfile,
    errors: &mut Vec<Diagnostic>,
) {
    let mut routes = BTreeSet::new();
    let mut event_ids = BTreeSet::new();
    for entity in entities.values() {
        validate_id(&entity.id, "entities[].id", errors);
        validate_id(&entity.route, "entities[].route", errors);
        if !routes.insert(entity.route.as_str()) {
            errors.push(Diagnostic::error(
                "entity.route.duplicate",
                "entities[].route",
                "an entity route is duplicated",
            ));
        }
        if entity.mutation_mode == MutationMode::CreateOnly && entity.tombstone {
            errors.push(Diagnostic::error(
                "entity.tombstone.create_only",
                "entities[].tombstone",
                "a create-only entity cannot expose tombstone behavior",
            ));
        }
        let grants_batch = entity
            .access_profiles
            .iter()
            .any(|profile| profile.operations.contains(&Operation::Batch));
        match entity.batch.as_ref() {
            None if grants_batch => errors.push(Diagnostic::error(
                "entity.batch.required",
                "entities[].batch",
                "an entity granted batch access must declare bounded batch configuration",
            )),
            Some(batch)
                if batch.maximum_items == 0
                    || batch.maximum_items > MAX_BATCH_ITEMS
                    || batch.maximum_bytes == 0
                    || batch.maximum_bytes > MAX_BATCH_BYTES =>
            {
                errors.push(Diagnostic::error(
                    "entity.batch.bounds_invalid",
                    "entities[].batch",
                    "batch maximumItems and maximumBytes must be within the supported bounds",
                ));
            }
            _ => {}
        }
        validate_entity_fields(entity, entities, errors);
        validate_derived(entity, errors);
        validate_logical_names(entity, errors);
        validate_constraints(entity, errors);
        validate_indexes(entity, errors);
        validate_selector_profiles(entity, errors);
        validate_read_paths(entity, entities, errors);
        validate_profiles(entity, entities, errors);
        validate_events(entity, profile, &mut event_ids, errors);
    }
    validate_read_path_cycles(entities, errors);
}

fn validate_entity_fields(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut fields = BTreeSet::new();
    let mut roles = BTreeMap::new();
    for field in &entity.fields {
        validate_id(&field.id, "entities[].fields[].id", errors);
        if reserved_logical_name(&field.id) {
            errors.push(Diagnostic::error(
                "field.id.reserved",
                "entities[].fields[].id",
                "a field identifier collides with a reserved Registry field",
            ));
        }
        if !fields.insert(field.id.as_str()) {
            errors.push(Diagnostic::error(
                "field.id.duplicate",
                "entities[].fields[].id",
                "a field identifier is duplicated",
            ));
        }
        match &field.field_type {
            FieldTypeSource::String {
                min_length,
                max_length,
            } if *max_length == 0 || *max_length > 1_000_000 || min_length > max_length => errors
                .push(Diagnostic::error(
                    "field.string.bounds_invalid",
                    "entities[].fields[]",
                    "string length bounds are invalid",
                )),
            FieldTypeSource::Text { max_length }
                if *max_length == 0 || *max_length > 10_000_000 =>
            {
                errors.push(Diagnostic::error(
                    "field.text.bound_invalid",
                    "entities[].fields[].maxLength",
                    "text length bound must be positive",
                ));
            }
            FieldTypeSource::VocabularyCode { values, .. }
                if values.is_empty()
                    || has_duplicates(values)
                    || values.iter().any(|value| !valid_code(value)) =>
            {
                errors.push(Diagnostic::error(
                    "field.vocabulary.values_invalid",
                    "entities[].fields[].values",
                    "a vocabulary field requires a non-empty duplicate-free value set",
                ));
            }
            FieldTypeSource::Decimal {
                precision,
                scale,
                minimum,
                maximum,
            } if !valid_decimal_bounds(
                *precision,
                *scale,
                minimum.as_deref(),
                maximum.as_deref(),
            ) =>
            {
                errors.push(Diagnostic::error(
                    "field.decimal.bounds_invalid",
                    "entities[].fields[]",
                    "decimal precision, scale, or canonical bounds are invalid",
                ));
            }
            FieldTypeSource::Reference { target, .. } if !entities.contains_key(target) => {
                errors.push(Diagnostic::error(
                    "field.reference.target_unknown",
                    "entities[].fields[].target",
                    "a reference target does not resolve",
                ));
            }
            FieldTypeSource::Crs84Point { precision, bbox }
                if *precision > 9
                    || bbox
                        .as_ref()
                        .is_some_and(|bbox| parsed_bbox(bbox, *precision).is_none()) =>
            {
                errors.push(Diagnostic::error(
                    "field.crs84_point.bounds_invalid",
                    "entities[].fields[]",
                    "CRS84 point precision or CRS84 bounding box is invalid",
                ));
            }
            FieldTypeSource::Structured { max_bytes, schema }
                if *max_bytes == 0
                    || *max_bytes > MAX_STRUCTURED_VALUE_BYTES
                    || !valid_structured_schema(schema) =>
            {
                errors.push(Diagnostic::error(
                    "field.structured.schema_invalid",
                    "entities[].fields[]",
                    "structured field schema or byte bound is invalid",
                ));
            }
            _ => {}
        }
        if let Some(role) = field.valid_time_role {
            if !matches!(
                field.field_type,
                FieldTypeSource::Date | FieldTypeSource::Timestamp
            ) {
                errors.push(Diagnostic::error(
                    "field.valid_time.type_invalid",
                    "entities[].fields[].validTimeRole",
                    "a valid-time role requires a date or timestamp field",
                ));
            }
            if roles.insert(role, &field.field_type).is_some() {
                errors.push(Diagnostic::error(
                    "field.valid_time.role_duplicate",
                    "entities[].fields[].validTimeRole",
                    "a valid-time role is declared more than once",
                ));
            }
            if role == ValidTimeRole::ValidFrom && !field.required {
                errors.push(Diagnostic::error(
                    "field.valid_time.start_required",
                    "entities[].fields[].required",
                    "a valid-time start field must be required",
                ));
            }
            if role == ValidTimeRole::ValidTo && field.required {
                errors.push(Diagnostic::error(
                    "field.valid_time.end_must_allow_open",
                    "entities[].fields[].required",
                    "a valid-time end field must permit an open interval",
                ));
            }
        }
    }
    if let (Some(from), Some(to)) = (
        roles.get(&ValidTimeRole::ValidFrom),
        roles.get(&ValidTimeRole::ValidTo),
    ) {
        if std::mem::discriminant(*from) != std::mem::discriminant(*to) {
            errors.push(Diagnostic::error(
                "field.valid_time.type_mismatch",
                "entities[].fields[].validTimeRole",
                "valid-time boundary fields must use the same type",
            ));
        }
    }
}

fn validate_derived(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let stored = stored_field_map(entity);
    let mut ids = BTreeSet::new();
    let mut field_ids = BTreeSet::new();
    field_ids.extend(entity.fields.iter().map(|field| field.id.clone()));
    for derived in &entity.derived {
        validate_id(&derived.id, "entities[].derived[].id", errors);
        if !ids.insert(derived.id.as_str()) {
            errors.push(Diagnostic::error(
                "derived.id.duplicate",
                "entities[].derived[].id",
                "a derived relation identifier is duplicated",
            ));
        }
        if !valid_relative_sql_path(&derived.sql) {
            errors.push(Diagnostic::error(
                "derived.sql_path.invalid",
                "entities[].derived[].sql",
                "derived SQL must be a module-relative .sql path",
            ));
        }
        if derived.key != "id" || stored.contains_key(derived.key.as_str()) {
            errors.push(Diagnostic::error(
                "derived.key.invalid",
                "entities[].derived[].key",
                "derived SQL must declare the canonical id key",
            ));
        }
        if derived.execution != DerivedExecutionSource::Live {
            errors.push(Diagnostic::error(
                "derived.execution.unsupported",
                "entities[].derived[].execution",
                "derived SQL currently supports only live execution",
            ));
        }
        if derived.fields.is_empty() {
            errors.push(Diagnostic::error(
                "derived.fields.empty",
                "entities[].derived[].fields",
                "derived SQL must declare at least one output field",
            ));
        }
        for field in &derived.fields {
            validate_derived_field(field, &mut field_ids, errors);
        }
    }
}

fn validate_derived_field(
    field: &DerivedFieldSource,
    field_ids: &mut BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) {
    validate_id(&field.id, "entities[].derived[].fields[].id", errors);
    if reserved_logical_name(&field.id) {
        errors.push(Diagnostic::error(
            "field.id.reserved",
            "entities[].derived[].fields[].id",
            "a field identifier collides with a reserved Registry field",
        ));
    }
    if !field_ids.insert(field.id.clone()) {
        errors.push(Diagnostic::error(
            "field.id.duplicate",
            "entities[].derived[].fields[].id",
            "a stored or derived field identifier is duplicated",
        ));
    }
    validate_field_type_bounds(&field.field_type, "entities[].derived[].fields[]", errors);
}

fn validate_logical_names(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let mut api_names = BTreeSet::from(["id".to_owned()]);
    let mut sql_names = BTreeSet::from(["id".to_owned()]);
    for field in entity
        .fields
        .iter()
        .map(|field| (&field.id, field.api_name.as_deref()))
        .chain(entity.derived.iter().flat_map(|derived| {
            derived
                .fields
                .iter()
                .map(|field| (&field.id, field.api_name.as_deref()))
        }))
    {
        let api_name = field
            .1
            .map(str::to_owned)
            .unwrap_or_else(|| default_api_name(field.0));
        if !valid_api_name(&api_name) || reserved_logical_name(&api_name) {
            errors.push(Diagnostic::error(
                "field.api_name.invalid",
                "entities[].fields[].apiName",
                "a field API name must be a non-reserved lower camelCase identifier",
            ));
        }
        if entity.change_request.is_some() && request_query_field_id_for_api(&api_name).is_some() {
            errors.push(Diagnostic::error(
                "change_request.field.api_name_reserved",
                "entities[].fields[].apiName",
                "request entities cannot reuse server-owned request state API names",
            ));
        }
        if !api_names.insert(api_name) {
            errors.push(Diagnostic::error(
                "field.api_name.duplicate",
                "entities[].fields[].apiName",
                "field API names must be unique within an entity",
            ));
        }
        let sql_name = default_sql_name(field.0);
        if reserved_logical_name(&sql_name) || !sql_names.insert(sql_name) {
            errors.push(Diagnostic::error(
                "field.sql_name.duplicate",
                "entities[].fields[].id",
                "field SQL names must be non-reserved and unique within an entity",
            ));
        }
    }
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
                "field.string.bounds_invalid",
                path,
                "string length bounds are invalid",
            ))
        }
        FieldTypeSource::Text { max_length } if *max_length == 0 || *max_length > 10_000_000 => {
            errors.push(Diagnostic::error(
                "field.text.bound_invalid",
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
                "field.vocabulary.values_invalid",
                path,
                "a vocabulary field requires a non-empty duplicate-free value set",
            ));
        }
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } if !valid_decimal_bounds(*precision, *scale, minimum.as_deref(), maximum.as_deref()) => {
            errors.push(Diagnostic::error(
                "field.decimal.bounds_invalid",
                path,
                "decimal precision, scale, or canonical bounds are invalid",
            ));
        }
        FieldTypeSource::Crs84Point { precision, bbox }
            if *precision > 9
                || bbox
                    .as_ref()
                    .is_some_and(|bbox| parsed_bbox(bbox, *precision).is_none()) =>
        {
            errors.push(Diagnostic::error(
                "field.crs84_point.bounds_invalid",
                path,
                "CRS84 point precision or CRS84 bounding box is invalid",
            ));
        }
        FieldTypeSource::Structured { max_bytes, schema }
            if *max_bytes == 0
                || *max_bytes > MAX_STRUCTURED_VALUE_BYTES
                || !valid_structured_schema(schema) =>
        {
            errors.push(Diagnostic::error(
                "field.structured.schema_invalid",
                path,
                "structured field schema or byte bound is invalid",
            ));
        }
        _ => {}
    }
}

fn validate_constraints(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let fields: BTreeMap<&str, &FieldSource> = entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect();
    let mut ids = BTreeSet::new();
    for constraint in &entity.constraints {
        let id = derived_constraint_id(constraint);
        if !ids.insert(id) {
            errors.push(Diagnostic::error(
                "constraint.id.duplicate",
                "entities[].constraints[]",
                "a constraint identifier is duplicated",
            ));
        }
        let referenced = match constraint {
            ConstraintSource::Unique { fields, .. } => fields.clone(),
            ConstraintSource::Compare { left, right, .. } => vec![left.clone(), right.clone()],
            ConstraintSource::IntRange { field, .. }
            | ConstraintSource::Vocabulary { field, .. } => vec![field.clone()],
            ConstraintSource::TemporalNonOverlap { scope_fields, .. } => scope_fields.clone(),
        };
        if referenced.is_empty()
            || referenced
                .iter()
                .any(|field| !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "constraint.field.unknown",
                "entities[].constraints[]",
                "a constraint has an empty or unresolved field set",
            ));
            continue;
        }
        if let ConstraintSource::Unique { when, .. } = constraint {
            validate_unique_when(entity, when.as_deref(), errors);
        }
        match constraint {
            ConstraintSource::Unique { .. } => {}
            ConstraintSource::Compare { left, right, .. } => {
                let left_type = &fields[left.as_str()].field_type;
                let right_type = &fields[right.as_str()].field_type;
                if std::mem::discriminant(left_type) != std::mem::discriminant(right_type)
                    || !matches!(
                        left_type,
                        FieldTypeSource::Int64 | FieldTypeSource::Date | FieldTypeSource::Timestamp
                    )
                {
                    errors.push(Diagnostic::error(
                        "constraint.compare.type_mismatch",
                        "entities[].constraints[]",
                        "compared fields must use the same ordered scalar type",
                    ));
                }
            }
            ConstraintSource::IntRange {
                field,
                minimum,
                maximum,
                ..
            } => {
                if !matches!(fields[field.as_str()].field_type, FieldTypeSource::Int64)
                    || minimum.is_none() && maximum.is_none()
                    || minimum.zip(*maximum).is_some_and(|(min, max)| min > max)
                {
                    errors.push(Diagnostic::error(
                        "constraint.range.invalid",
                        "entities[].constraints[]",
                        "an integer range has an incompatible field or invalid bounds",
                    ));
                }
            }
            ConstraintSource::Vocabulary { field, values, .. } => {
                let declared_values = match &fields[field.as_str()].field_type {
                    FieldTypeSource::VocabularyCode { values, .. } => Some(values),
                    _ => None,
                };
                if values.is_empty()
                    || has_duplicates(values)
                    || values.iter().any(|value| !valid_code(value))
                    || declared_values
                        .is_none_or(|declared| values.iter().any(|value| !declared.contains(value)))
                {
                    errors.push(Diagnostic::error(
                        "constraint.vocabulary.invalid",
                        "entities[].constraints[]",
                        "a vocabulary constraint is incompatible or has invalid values",
                    ));
                }
            }
            ConstraintSource::TemporalNonOverlap {
                start_field,
                end_field,
                scope_fields,
                ..
            } => {
                let from = entity
                    .fields
                    .iter()
                    .find(|field| field.valid_time_role == Some(ValidTimeRole::ValidFrom));
                let to = entity
                    .fields
                    .iter()
                    .find(|field| field.valid_time_role == Some(ValidTimeRole::ValidTo));
                if from.is_none()
                    || to.is_none()
                    || start_field
                        .as_ref()
                        .is_some_and(|id| from.is_none_or(|field| &field.id != id))
                    || end_field
                        .as_ref()
                        .is_some_and(|id| to.is_none_or(|field| &field.id != id))
                {
                    errors.push(Diagnostic::error(
                        "constraint.temporal.roles_invalid",
                        "entities[].constraints[]",
                        "a temporal constraint requires matching valid-time boundary fields",
                    ));
                }
                if scope_fields.iter().any(|field| {
                    fields
                        .get(field.as_str())
                        .is_some_and(|field| !field.required)
                }) {
                    errors.push(Diagnostic::error(
                        "constraint.temporal.scope_nullable",
                        "entities[].constraints[].scopeFields",
                        "a temporal non-overlap scope field must be required",
                    ));
                }
                if scope_fields.iter().any(|field| {
                    fields.get(field.as_str()).is_some_and(|field| {
                        !supports_temporal_non_overlap_scope(&field.field_type)
                    })
                }) {
                    errors.push(Diagnostic::error(
                        "constraint.temporal.scope_type_unsupported",
                        "entities[].constraints[].scopeFields",
                        "a temporal non-overlap scope field must use a supported scalar type",
                    ));
                }
            }
        }
        if matches!(
            constraint,
            ConstraintSource::Unique { fields, .. }
                if has_duplicates(fields)
        ) || matches!(
            constraint,
            ConstraintSource::TemporalNonOverlap { scope_fields, .. }
                if scope_fields.is_empty() || has_duplicates(scope_fields)
        ) {
            errors.push(Diagnostic::error(
                "constraint.fields.duplicate",
                "entities[].constraints[]",
                "a constraint field tuple must be non-empty and duplicate-free",
            ));
        }
    }
    validate_anonymous_constraint_processing(entity, &fields, errors);
    if let Some(temporal) = &entity.temporal {
        let matched = entity.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                ConstraintSource::TemporalNonOverlap {
                    scope_fields,
                    start_field,
                    end_field,
                    ..
                } if scope_fields == &temporal.scope_fields
                    && start_field.as_ref() == Some(&temporal.start_field)
                    && end_field.as_ref() == Some(&temporal.end_field)
            )
        });
        if !matched {
            errors.push(Diagnostic::error(
                "temporal.constraint.missing",
                "entities[].temporal",
                "the temporal declaration must match one non-overlap constraint",
            ));
        }
    }
}

fn validate_anonymous_constraint_processing(
    entity: &EntitySource,
    fields: &BTreeMap<&str, &FieldSource>,
    errors: &mut Vec<Diagnostic>,
) {
    // In the current contract, `anonymous` marks the public profile surface.
    // Every field processed by a constraint on that entity must therefore meet
    // the public classification floor even when it is not otherwise readable.
    if !entity
        .access_profiles
        .iter()
        .any(|profile| profile.anonymous)
    {
        return;
    }
    let processes_non_public = entity
        .constraints
        .iter()
        .flat_map(constraint_processed_fields)
        .any(|field| {
            fields
                .get(field)
                .is_some_and(|field| field.classification != Classification::Public)
        });
    if processes_non_public {
        errors.push(Diagnostic::error(
            "access_profile.public.processing_non_public",
            "entities[].constraints[]",
            "an anonymous profile is a public surface and may process only public constraint fields",
        ));
    }
}

fn constraint_processed_fields(constraint: &ConstraintSource) -> Vec<&str> {
    match constraint {
        ConstraintSource::Unique { fields, when, .. } => fields
            .iter()
            .map(String::as_str)
            .chain(
                when.iter()
                    .flatten()
                    .filter_map(unique_when_predicate_field),
            )
            .collect(),
        ConstraintSource::Compare { left, right, .. } => {
            vec![left.as_str(), right.as_str()]
        }
        ConstraintSource::IntRange { field, .. } | ConstraintSource::Vocabulary { field, .. } => {
            vec![field.as_str()]
        }
        ConstraintSource::TemporalNonOverlap {
            scope_fields,
            start_field,
            end_field,
            ..
        } => scope_fields
            .iter()
            .map(String::as_str)
            .chain(start_field.iter().map(String::as_str))
            .chain(end_field.iter().map(String::as_str))
            .collect(),
    }
}

fn supports_temporal_non_overlap_scope(field_type: &FieldTypeSource) -> bool {
    // These source types generate PostgreSQL scalar columns whose GiST equality
    // operator classes are supplied by the required btree_gist extension.
    // Structured and CRS84 point fields generate jsonb columns, for which this
    // compiler does not install or require a GiST equality operator class.
    matches!(
        field_type,
        FieldTypeSource::Boolean
            | FieldTypeSource::String { .. }
            | FieldTypeSource::Text { .. }
            | FieldTypeSource::Int64
            | FieldTypeSource::Decimal { .. }
            | FieldTypeSource::Date
            | FieldTypeSource::Timestamp
            | FieldTypeSource::Uuid
            | FieldTypeSource::VocabularyCode { .. }
            | FieldTypeSource::Reference { .. }
    )
}

fn stored_field_map(entity: &EntitySource) -> BTreeMap<&str, &FieldSource> {
    entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect()
}

fn derived_field_map(entity: &EntitySource) -> BTreeMap<&str, &DerivedFieldSource> {
    entity
        .derived
        .iter()
        .flat_map(|derived| {
            derived
                .fields
                .iter()
                .map(|field| (field.id.as_str(), field))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FieldStorageKind {
    Stored,
    Derived,
    Pseudo,
}

fn selector_field_supported(field_type: &FieldTypeSource) -> bool {
    !matches!(
        field_type,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
    )
}

fn infer_read_path_refs(
    source: &EntitySource,
    through: &EntitySource,
    target: &str,
) -> Option<(String, String)> {
    let source_refs = through
        .fields
        .iter()
        .filter_map(|field| match &field.field_type {
            FieldTypeSource::Reference { target, .. } if target == &source.id => {
                Some(field.id.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let target_refs = through
        .fields
        .iter()
        .filter_map(|field| match &field.field_type {
            FieldTypeSource::Reference {
                target: field_target,
                ..
            } if field_target == target => Some(field.id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    match (source_refs.as_slice(), target_refs.as_slice()) {
        ([source_ref], [target_ref]) if source_ref != target_ref => {
            Some((source_ref.clone(), target_ref.clone()))
        }
        _ => None,
    }
}

fn valid_relative_sql_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.ends_with(".sql")
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn validate_indexes(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let fields: BTreeSet<&str> = entity
        .fields
        .iter()
        .map(|field| field.id.as_str())
        .collect();
    let mut ids = BTreeSet::new();
    for index in &entity.indexes {
        validate_id(&index.id, "entities[].indexes[].id", errors);
        if !ids.insert(index.id.as_str()) {
            errors.push(Diagnostic::error(
                "index.id.duplicate",
                "entities[].indexes[].id",
                "an index identifier is duplicated",
            ));
        }
        if index.fields.is_empty()
            || has_duplicates(&index.fields)
            || index
                .fields
                .iter()
                .any(|field| !fields.contains(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "index.fields.invalid",
                "entities[].indexes[].fields",
                "an index has an empty, duplicate, or unresolved field set",
            ));
        }
    }
}

fn validate_selector_profiles(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let fields = stored_field_map(entity);
    let mut ids = BTreeSet::new();
    for selector in &entity.selector_profiles {
        validate_id(&selector.id, "entities[].selectorProfiles[].id", errors);
        if !ids.insert(selector.id.as_str()) {
            errors.push(Diagnostic::error(
                "selector_profile.id.duplicate",
                "entities[].selectorProfiles[].id",
                "a selector profile identifier is duplicated",
            ));
        }
        if selector.fields.is_empty()
            || selector.fields.len() > 16
            || has_duplicates(&selector.fields)
            || selector
                .fields
                .iter()
                .any(|field| !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "selector_profile.fields.invalid",
                "entities[].selectorProfiles[].fields",
                "a selector profile must name one to sixteen stored fields",
            ));
            continue;
        }
        if selector.fields.iter().any(|field| {
            fields
                .get(field.as_str())
                .is_some_and(|field| !selector_field_supported(&field.field_type))
        }) {
            errors.push(Diagnostic::error(
                "selector_profile.field_type_unsupported",
                "entities[].selectorProfiles[].fields",
                "selector profile fields must use supported scalar stored types",
            ));
        }
    }
}

fn validate_read_paths(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut ids = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for path in &entity.read_paths {
        validate_id(&path.id, "entities[].readPaths[].id", errors);
        validate_id(&path.route, "entities[].readPaths[].route", errors);
        if !ids.insert(path.id.as_str()) {
            errors.push(Diagnostic::error(
                "read_path.id.duplicate",
                "entities[].readPaths[].id",
                "a read path identifier is duplicated",
            ));
        }
        if !routes.insert(path.route.as_str()) {
            errors.push(Diagnostic::error(
                "read_path.route.duplicate",
                "entities[].readPaths[].route",
                "a read path route is duplicated for an entity",
            ));
        }
        if path.to == entity.id {
            errors.push(Diagnostic::error(
                "read_path.target.self",
                "entities[].readPaths[].to",
                "a read path target must differ from its source entity",
            ));
        }
        let Some(through) = entities.get(&path.through) else {
            errors.push(Diagnostic::error(
                "read_path.through.unknown",
                "entities[].readPaths[].through",
                "a read path association entity does not resolve",
            ));
            continue;
        };
        if !entities.contains_key(&path.to) {
            errors.push(Diagnostic::error(
                "read_path.target.unknown",
                "entities[].readPaths[].to",
                "a read path target entity does not resolve",
            ));
            continue;
        }
        if infer_read_path_refs(entity, through, &path.to).is_none() {
            errors.push(Diagnostic::error(
                "read_path.references.ambiguous",
                "entities[].readPaths[]",
                "a read path must have exactly one source reference and one target reference",
            ));
        }
    }
}

fn validate_read_path_cycles(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let edges = entities
        .values()
        .flat_map(|entity| {
            entity
                .read_paths
                .iter()
                .map(|path| (entity.id.as_str(), path.to.as_str()))
        })
        .collect::<Vec<_>>();
    for (source, target) in &edges {
        if reaches(target, source, &edges, &mut BTreeSet::new()) {
            errors.push(Diagnostic::error(
                "read_path.cycle",
                "entities[].readPaths[]",
                "read paths must not form a traversal cycle",
            ));
            return;
        }
    }
}

fn reaches<'a>(
    current: &'a str,
    target: &str,
    edges: &[(&'a str, &'a str)],
    visited: &mut BTreeSet<&'a str>,
) -> bool {
    if current == target {
        return true;
    }
    if !visited.insert(current) {
        return false;
    }
    edges
        .iter()
        .filter(|(source, _)| *source == current)
        .any(|(_, next)| reaches(next, target, edges, visited))
}

fn validate_profiles(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let fields = stored_field_map(entity);
    let derived = derived_field_map(entity);
    let mut ids = BTreeSet::new();
    for access in &entity.access_profiles {
        validate_id(&access.id, "entities[].accessProfiles[].id", errors);
        if !ids.insert(access.id.as_str()) {
            errors.push(Diagnostic::error(
                "access_profile.id.duplicate",
                "entities[].accessProfiles[].id",
                "an access profile identifier is duplicated",
            ));
        }
        if access.operations.is_empty() {
            errors.push(Diagnostic::error(
                "access_profile.operations.empty",
                "entities[].accessProfiles[].operations",
                "an access profile must grant at least one operation",
            ));
        }
        if !access.anonymous && access.principal_claim.as_deref().is_none_or(str::is_empty) {
            errors.push(Diagnostic::error(
                "access_profile.principal_claim.required",
                "entities[].accessProfiles[].principalClaim",
                "an authenticated profile requires a direct principal claim",
            ));
        }
        if access
            .required_scopes
            .iter()
            .chain(&access.required_purposes)
            .any(|value| value.is_empty())
        {
            errors.push(Diagnostic::error(
                "access_profile.claim_value.invalid",
                "entities[].accessProfiles[]",
                "required scope and purpose values must be non-empty",
            ));
        }
        for operation in &access.operations {
            if (entity.mutation_mode == MutationMode::CreateOnly
                && matches!(operation, Operation::Patch | Operation::Tombstone))
                || (*operation == Operation::Tombstone && !entity.tombstone)
                || (is_request_operation(*operation) && entity.change_request.is_none())
                || *operation == Operation::Invoke
            {
                errors.push(Diagnostic::error(
                    "access_profile.operation.unavailable",
                    "entities[].accessProfiles[].operations",
                    "an access profile grants an operation the entity does not expose",
                ));
            }
        }
        if access.operations.contains(&Operation::Batch)
            && !access
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::Create | Operation::Patch))
        {
            errors.push(Diagnostic::error(
                "access_profile.batch.underlying_operation_required",
                "entities[].accessProfiles[].operations",
                "a batch access profile must grant create or patch for its items",
            ));
        }
        if access.anonymous
            && access.operations.iter().any(|operation| {
                matches!(
                    operation,
                    Operation::Create
                        | Operation::Patch
                        | Operation::Tombstone
                        | Operation::Batch
                        | Operation::SubmitRequest
                        | Operation::ApproveRequest
                        | Operation::RejectRequest
                        | Operation::RequestRevision
                        | Operation::ReviseRequest
                        | Operation::CancelRequest
                        | Operation::ApplyRequest
                )
            })
        {
            errors.push(Diagnostic::error(
                "access_profile.anonymous.mutation_forbidden",
                "entities[].accessProfiles[].operations",
                "an anonymous access profile cannot grant a mutation operation",
            ));
        }
        if access.allow_data_export
            && (access.anonymous
                || !access.operations.contains(&Operation::List)
                || access.readable_fields.is_empty())
        {
            errors.push(Diagnostic::error(
                "access_profile.data_export.invalid",
                "entities[].accessProfiles[].allowDataExport",
                "bulk data export requires an authenticated list profile with a readable projection",
            ));
        }
        let mut read_processed = access.readable_fields.clone();
        read_processed.extend(access.filterable_fields.iter().cloned());
        read_processed.extend(access.sortable_fields.iter().cloned());
        let mut stored_processed = access.writable_fields.clone();
        stored_processed.extend(
            access
                .row_boundaries
                .iter()
                .map(|boundary| boundary.field.clone()),
        );
        if read_processed.iter().any(|field| {
            !fields.contains_key(field.as_str()) && !derived.contains_key(field.as_str())
        }) || stored_processed
            .iter()
            .any(|field| field != "id" && !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "access_profile.field.unknown",
                "entities[].accessProfiles[]",
                "an access profile refers to an unknown field",
            ));
        }
        if !access.filterable_fields.is_subset(&access.readable_fields)
            || !access.sortable_fields.is_subset(&access.readable_fields)
        {
            errors.push(Diagnostic::error(
                "access_profile.processing.wider_than_read",
                "entities[].accessProfiles[]",
                "filterable and sortable fields must be readable",
            ));
        }
        if access.anonymous
            && (entity.classification != Classification::Public
                || read_processed.iter().any(|field| {
                    fields
                        .get(field.as_str())
                        .is_some_and(|field| field.classification != Classification::Public)
                        || derived.contains_key(field.as_str())
                })
                || stored_processed.iter().any(|field| {
                    field != "id"
                        && fields
                            .get(field.as_str())
                            .is_some_and(|field| field.classification != Classification::Public)
                }))
        {
            errors.push(Diagnostic::error(
                "access_profile.public.processing_non_public",
                "entities[].accessProfiles[]",
                "an anonymous profile may process only public fields",
            ));
        }
        let mut boundaries = BTreeSet::new();
        for boundary in &access.row_boundaries {
            if boundary.field != "id"
                && fields.get(boundary.field.as_str()).is_some_and(|field| {
                    matches!(
                        field.field_type,
                        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
                    )
                })
            {
                errors.push(Diagnostic::error(
                    "access_profile.row_boundary.type_unsupported",
                    "entities[].accessProfiles[].rowBoundaries",
                    "CRS84 point and structured fields cannot be row-boundary fields",
                ));
            }
            if boundary.claim.is_empty()
                || !boundaries.insert((
                    boundary.field.as_str(),
                    boundary.claim.as_str(),
                    boundary.operator,
                ))
            {
                errors.push(Diagnostic::error(
                    "access_profile.row_boundary.invalid",
                    "entities[].accessProfiles[].rowBoundaries",
                    "row boundaries must be direct, non-empty, and duplicate-free",
                ));
            }
        }
        validate_lookup_grants(access, entity, &fields, errors);
        validate_read_path_grants(access, entity, entities, errors);
        if access.allow_count && !access.operations.contains(&Operation::List) {
            errors.push(Diagnostic::error(
                "access_profile.count.unavailable",
                "entities[].accessProfiles[].allowCount",
                "direct count access requires an explicit list grant",
            ));
        }
    }
    for operation in all_operations() {
        let profiles: Vec<&AccessProfileSource> = entity
            .access_profiles
            .iter()
            .filter(|access| access.operations.contains(&operation))
            .collect();
        if profiles.is_empty() {
            continue;
        }
        let explicit_defaults = profiles.iter().filter(|access| access.default).count();
        if profiles.len() > 1 && explicit_defaults != 1
            || profiles.len() == 1 && explicit_defaults > 1
        {
            errors.push(Diagnostic::error(
                "access_profile.default.invalid",
                "entities[].accessProfiles[].default",
                "each exposed operation requires exactly one default profile",
            ));
        }
    }
    for path in &entity.read_paths {
        let profiles: Vec<&AccessProfileSource> = entity
            .access_profiles
            .iter()
            .filter(|access| access.read_paths.iter().any(|grant| grant.path == path.id))
            .collect();
        if profiles.is_empty() {
            continue;
        }
        let explicit_defaults = profiles.iter().filter(|access| access.default).count();
        if profiles.len() > 1 && explicit_defaults != 1
            || profiles.len() == 1 && explicit_defaults > 1
        {
            errors.push(Diagnostic::error(
                "access_profile.default.invalid",
                "entities[].accessProfiles[].default",
                "each exposed read-path route requires exactly one default profile",
            ));
        }
    }
}

fn validate_lookup_grants(
    access: &AccessProfileSource,
    entity: &EntitySource,
    fields: &BTreeMap<&str, &FieldSource>,
    errors: &mut Vec<Diagnostic>,
) {
    if access.lookups.is_empty() {
        return;
    }
    if !access.operations.contains(&Operation::Lookup) {
        errors.push(Diagnostic::error(
            "access_profile.lookup.operation_required",
            "entities[].accessProfiles[].lookups",
            "lookup grants require the lookup operation",
        ));
    }
    let selectors = entity
        .selector_profiles
        .iter()
        .map(|selector| (selector.id.as_str(), selector))
        .collect::<BTreeMap<_, _>>();
    let mut granted = BTreeSet::new();
    for lookup in &access.lookups {
        if !granted.insert(lookup.selector.as_str()) {
            errors.push(Diagnostic::error(
                "access_profile.lookup.duplicate",
                "entities[].accessProfiles[].lookups",
                "lookup selector grants must be unique",
            ));
        }
        let Some(selector) = selectors.get(lookup.selector.as_str()) else {
            errors.push(Diagnostic::error(
                "access_profile.lookup.selector_unknown",
                "entities[].accessProfiles[].lookups[].selector",
                "a lookup grant refers to an unknown selector profile",
            ));
            continue;
        };
        if access.anonymous
            && selector.fields.iter().any(|field| {
                fields
                    .get(field.as_str())
                    .is_some_and(|field| field.classification != Classification::Public)
            })
        {
            errors.push(Diagnostic::error(
                "access_profile.public.processing_non_public",
                "entities[].accessProfiles[].lookups",
                "an anonymous lookup may process only public selector fields",
            ));
        }
        match lookup.value_origin {
            LookupValueOrigin::Request if !lookup.claim_mapping.is_empty() => {
                errors.push(Diagnostic::error(
                    "access_profile.lookup.claim_mapping_unavailable",
                    "entities[].accessProfiles[].lookups[].claimMapping",
                    "request-origin lookups must not declare claim mappings",
                ));
            }
            LookupValueOrigin::VerifiedClaim => {
                let expected = selector.fields.iter().cloned().collect::<BTreeSet<_>>();
                let actual = lookup
                    .claim_mapping
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if actual != expected || lookup.claim_mapping.values().any(|claim| claim.is_empty())
                {
                    errors.push(Diagnostic::error(
                        "access_profile.lookup.claim_mapping_invalid",
                        "entities[].accessProfiles[].lookups[].claimMapping",
                        "claim-origin lookups must map every selector field to one direct claim",
                    ));
                }
            }
            LookupValueOrigin::Request => {}
        }
    }
}

fn validate_read_path_grants(
    access: &AccessProfileSource,
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let paths = entity
        .read_paths
        .iter()
        .map(|path| (path.id.as_str(), path))
        .collect::<BTreeMap<_, _>>();
    let mut granted = BTreeSet::new();
    for grant in &access.read_paths {
        if !granted.insert(grant.path.as_str()) {
            errors.push(Diagnostic::error(
                "access_profile.read_path.duplicate",
                "entities[].accessProfiles[].readPaths",
                "read-path grants must be unique",
            ));
        }
        let Some(path) = paths.get(grant.path.as_str()) else {
            errors.push(Diagnostic::error(
                "access_profile.read_path.unknown",
                "entities[].accessProfiles[].readPaths[].path",
                "a read-path grant refers to an unknown path",
            ));
            continue;
        };
        validate_read_path_grant_fields(access, entity, entities, path, grant, errors);
    }
}

fn validate_read_path_grant_fields(
    access: &AccessProfileSource,
    source: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    path: &crate::contract::ReadPathSource,
    grant: &ReadPathGrantSource,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(target) = entities.get(&path.to) else {
        return;
    };
    let Some(through) = entities.get(&path.through) else {
        return;
    };
    let target_stored = stored_field_map(target);
    let target_derived = derived_field_map(target);
    if grant.readable_fields.is_empty() {
        errors.push(Diagnostic::error(
            "access_profile.read_path.readable_fields_empty",
            "entities[].accessProfiles[].readPaths[].readableFields",
            "a read-path grant must declare readable fields",
        ));
    }
    if !grant.filterable_fields.is_subset(&grant.readable_fields)
        || !grant.sortable_fields.is_subset(&grant.readable_fields)
    {
        errors.push(Diagnostic::error(
            "access_profile.read_path.processing.wider_than_read",
            "entities[].accessProfiles[].readPaths[]",
            "read-path filterable and sortable fields must be readable",
        ));
    }
    if access.anonymous && source.classification != Classification::Public {
        errors.push(Diagnostic::error(
            "access_profile.public.processing_non_public",
            "entities[].accessProfiles[].readPaths",
            "an anonymous read path may process only public source and join fields",
        ));
    }
    if access.anonymous {
        if let Some((source_ref, target_ref)) = infer_read_path_refs(source, through, &path.to) {
            let through_fields = stored_field_map(through);
            if [source_ref, target_ref].iter().any(|field| {
                through_fields
                    .get(field.as_str())
                    .is_some_and(|field| field.classification != Classification::Public)
            }) {
                errors.push(Diagnostic::error(
                    "access_profile.public.processing_non_public",
                    "entities[].accessProfiles[].readPaths",
                    "an anonymous read path may process only public join fields",
                ));
            }
        }
    }
    let processed = grant
        .readable_fields
        .iter()
        .chain(&grant.filterable_fields)
        .chain(&grant.sortable_fields)
        .collect::<BTreeSet<_>>();
    if processed.iter().any(|field| {
        field.as_str() != "id"
            && !target_stored.contains_key(field.as_str())
            && !target_derived.contains_key(field.as_str())
    }) {
        errors.push(Diagnostic::error(
            "access_profile.read_path.field_unknown",
            "entities[].accessProfiles[].readPaths[]",
            "a read-path grant refers to an unknown target field",
        ));
    }
    if access.anonymous
        && processed.iter().any(|field| {
            target_derived.contains_key(field.as_str())
                || (field.as_str() != "id"
                    && target_stored
                        .get(field.as_str())
                        .is_some_and(|field| field.classification != Classification::Public))
        })
    {
        errors.push(Diagnostic::error(
            "access_profile.public.processing_non_public",
            "entities[].accessProfiles[].readPaths",
            "an anonymous read path may process only public target fields and no derived fields",
        ));
    }
    if processed.is_empty() && grant.allow_count {
        errors.push(Diagnostic::error(
            "access_profile.read_path.count_without_fields",
            "entities[].accessProfiles[].readPaths[].allowCount",
            "read-path count access requires explicit path field capabilities",
        ));
    }
    if path.to == source.id {
        errors.push(Diagnostic::error(
            "access_profile.read_path.self_target",
            "entities[].accessProfiles[].readPaths[].path",
            "a read-path grant cannot target the source entity",
        ));
    }
}

fn validate_events(
    entity: &EntitySource,
    profile: CompileProfile,
    registry_event_ids: &mut BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) {
    let fields: BTreeMap<&str, &FieldSource> = entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect();
    let mut ids = BTreeSet::new();
    for event in &entity.events {
        validate_id(&event.id, "entities[].events[].id", errors);
        if !ids.insert(event.id.as_str()) {
            errors.push(Diagnostic::error(
                "event.id.duplicate",
                "entities[].events[].id",
                "an event identifier is duplicated",
            ));
        } else if !registry_event_ids.insert(event.id.clone()) {
            errors.push(Diagnostic::error(
                "event.id.registry_duplicate",
                "entities[].events[].id",
                "an event identifier must be unique across the Registry",
            ));
        }
        if event.projection.is_empty() {
            errors.push(Diagnostic::error(
                "event.projection.empty",
                "entities[].events[].projection",
                "an event projection must contain at least one field",
            ));
        }
        if event
            .projection
            .iter()
            .any(|field| !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "event.projection.field_unknown",
                "entities[].events[].projection",
                "an event projection refers to an unknown field",
            ));
        }
        let maximum_payload_bytes =
            maximum_event_payload_bytes(&entity.id, event.trigger, &event.projection, |field| {
                fields
                    .get(field)
                    .map(|field| (&field.field_type, field.required))
            });
        if matches!(
            event.trigger,
            EventTrigger::Patched | EventTrigger::Tombstoned
        ) && entity.mutation_mode == MutationMode::CreateOnly
        {
            errors.push(Diagnostic::error(
                "event.trigger.unavailable",
                "entities[].events[].trigger",
                "an event trigger is unavailable for a create-only entity",
            ));
        }
        if event.trigger == EventTrigger::Tombstoned && !entity.tombstone {
            errors.push(Diagnostic::error(
                "event.trigger.unavailable",
                "entities[].events[].trigger",
                "a tombstone event requires tombstone behavior",
            ));
        }
        if event.trigger == EventTrigger::RequestLifecycle && entity.change_request.is_none() {
            errors.push(Diagnostic::error(
                "event.trigger.request_lifecycle_requires_change_request",
                "entities[].events[].trigger",
                "a request lifecycle event can be declared only on a change-request entity",
            ));
        }
        validate_event_condition(event, &fields, errors);
        let Some(webhook) = event.webhook.as_ref() else {
            if profile == CompileProfile::Production {
                errors.push(Diagnostic::error(
                    "event.delivery.required",
                    "entities[].events[].webhook",
                    "a production event requires a supported delivery",
                ));
            }
            continue;
        };
        if maximum_payload_bytes
            .is_some_and(|maximum| maximum > u64::from(MAX_WEBHOOK_PAYLOAD_BYTES))
        {
            errors.push(Diagnostic::error(
                "event.webhook.projection_too_large",
                "entities[].events[].projection",
                "the webhook projection can exceed the governed transport body bound",
            ));
        }
        if !valid_logical_destination_id(&webhook.destination_id) {
            errors.push(Diagnostic::error(
                "event.webhook.destination.invalid",
                "entities[].events[].webhook.destinationId",
                "a webhook destination must use the closed logical identifier grammar",
            ));
        }
    }
}

fn validate_event_condition(
    event: &crate::contract::EventSource,
    fields: &BTreeMap<&str, &FieldSource>,
    errors: &mut Vec<Diagnostic>,
) {
    match event.when.as_ref() {
        Some(EventConditionSource::Fields {
            changed,
            before_equals,
            after_equals,
        }) => {
            if changed.is_empty() && before_equals.is_empty() && after_equals.is_empty() {
                errors.push(Diagnostic::error(
                    "event.when.empty",
                    "entities[].events[].when",
                    "a field event condition requires at least one predicate",
                ));
            }
            let compatible = match event.trigger {
                EventTrigger::Created => changed.is_empty() && before_equals.is_empty(),
                EventTrigger::Patched => true,
                EventTrigger::Tombstoned => changed.is_empty() && after_equals.is_empty(),
                EventTrigger::RequestLifecycle => false,
            };
            if !compatible {
                errors.push(Diagnostic::error(
                    "event.when.trigger_incompatible",
                    "entities[].events[].when",
                    "field predicates are unavailable for this event trigger",
                ));
            }
            for field in changed {
                if !fields.contains_key(field.as_str()) {
                    errors.push(Diagnostic::error(
                        "event.when.field_unknown",
                        "entities[].events[].when.changed",
                        "an event condition refers to an unknown field",
                    ));
                }
            }
            for (path, predicates) in [
                ("entities[].events[].when.beforeEquals", before_equals),
                ("entities[].events[].when.afterEquals", after_equals),
            ] {
                for (field, value) in predicates {
                    let Some(source) = fields.get(field.as_str()) else {
                        errors.push(Diagnostic::error(
                            "event.when.field_unknown",
                            path,
                            "an event condition refers to an unknown field",
                        ));
                        continue;
                    };
                    if matches!(value, EventScalarValue::Null) {
                        continue;
                    }
                    let value = serde_json::to_value(value).expect("event scalar value serializes");
                    if canonical_field_literal(&value, &source.field_type).is_none() {
                        errors.push(Diagnostic::error(
                            "event.when.value_invalid",
                            path,
                            "an event comparison value must be canonical for its declared field type",
                        ));
                    }
                }
            }
        }
        Some(EventConditionSource::RequestLifecycle {
            transitions,
            to_states,
            stages,
        }) => {
            if transitions.is_empty() && to_states.is_empty() && stages.is_empty() {
                errors.push(Diagnostic::error(
                    "event.when.empty",
                    "entities[].events[].when",
                    "a request lifecycle event condition requires at least one predicate",
                ));
            }
            if event.trigger != EventTrigger::RequestLifecycle {
                errors.push(Diagnostic::error(
                    "event.when.trigger_incompatible",
                    "entities[].events[].when",
                    "request lifecycle predicates are available only for request lifecycle events",
                ));
            }
            for transition in transitions {
                if !valid_request_lifecycle_transition(transition) {
                    errors.push(Diagnostic::error(
                        "event.when.request_lifecycle_transition_unknown",
                        "entities[].events[].when.transitions",
                        "a request lifecycle event condition refers to an unknown transition",
                    ));
                }
            }
            for state in to_states {
                if !valid_request_lifecycle_state(state) {
                    errors.push(Diagnostic::error(
                        "event.when.request_lifecycle_state_unknown",
                        "entities[].events[].when.toStates",
                        "a request lifecycle event condition refers to an unknown request state",
                    ));
                }
            }
            for stage in stages {
                validate_id(stage, "entities[].events[].when.stages", errors);
            }
        }
        None => {}
    }
}

fn valid_request_lifecycle_transition(value: &str) -> bool {
    matches!(
        value,
        "submit"
            | "approve"
            | "reject"
            | "request_revision"
            | "revise"
            | "rebase"
            | "cancel"
            | "apply"
    )
}

fn valid_request_lifecycle_state(value: &str) -> bool {
    matches!(
        value,
        "draft" | "submitted" | "approved" | "needs_changes" | "rejected" | "canceled" | "applied"
    )
}

fn valid_logical_destination_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn maximum_event_payload_bytes<'a>(
    entity_id: &str,
    trigger: EventTrigger,
    projection: &BTreeSet<String>,
    field: impl Fn(&str) -> Option<(&'a FieldTypeSource, bool)>,
) -> Option<u64> {
    let values = maximum_event_values_bytes(projection, field)?;
    let fixed_keys: &[&str] = if trigger == EventTrigger::RequestLifecycle {
        &[
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "request",
            "values",
        ]
    } else {
        &[
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "values",
        ]
    };
    // Canonical body object braces, one comma between members, and fixed key
    // encodings (two quotes plus a colon per key).
    let mut total = 2_u64.checked_add(fixed_keys.len().saturating_sub(1) as u64)?;
    for key in fixed_keys {
        total = total.checked_add(key.len() as u64 + 3)?;
    }
    if trigger == EventTrigger::RequestLifecycle {
        // The request lifecycle envelope contains bounded ASCII state/stage/
        // digest fields plus integer proposal/workflow revisions and a stable
        // deduplication key. The exact runtime payload is still checked against
        // the compiled delivery maximum before insert.
        let request_keys = [
            "proposalVersion",
            "workflowRevision",
            "transition",
            "fromState",
            "toState",
            "stage",
            "effectDigest",
            "deduplicationKey",
        ];
        total = total
            .checked_add(2)?
            .checked_add(request_keys.len() as u64 - 1)?;
        for key in request_keys {
            total = total.checked_add(key.len() as u64 + 3)?;
        }
        total = total
            .checked_add(10)?
            .checked_add(20)?
            .checked_add(34)?
            .checked_add(16)?
            .checked_add(16)?
            .checked_add(258)?
            .checked_add(73)?
            .checked_add(512)?;
    }
    // Entity ids and triggers use the compiler's closed ASCII grammars.
    total = total.checked_add(entity_id.len() as u64 + 2)?;
    // A UUID string, the largest positive i64 revision, and the longest
    // trigger string, including JSON quotes where applicable.
    let maximum_trigger_bytes = if trigger == EventTrigger::RequestLifecycle {
        21
    } else {
        12
    };
    total = total
        .checked_add(38)?
        .checked_add(19)?
        .checked_add(maximum_trigger_bytes)?;
    // Persisted package revisions are bounded to 256 bytes. Six bytes per
    // byte plus quotes safely covers JSON's longest control-character escape.
    total = total.checked_add(
        u64::from(MAX_EVENT_PACKAGE_REVISION_BYTES)
            .checked_mul(6)?
            .checked_add(2)?,
    )?;
    total.checked_add(values)
}

fn maximum_event_values_bytes<'a>(
    projection: &BTreeSet<String>,
    field: impl Fn(&str) -> Option<(&'a FieldTypeSource, bool)>,
) -> Option<u64> {
    // Canonical JSON object braces plus one comma between projected members.
    let mut total = 2_u64.checked_add(projection.len().saturating_sub(1) as u64)?;
    for field_id in projection {
        let (field_type, required) = field(field_id)?;
        // Field identifiers use the compiler's ASCII identifier grammar, so
        // their canonical key encoding is quotes plus the identifier bytes.
        // Optional SQL NULLs materialize as JSON null in the immutable event
        // projection, so their four bytes are also part of the maximum.
        let maximum_value_bytes = maximum_field_json_bytes(field_type)?;
        let maximum_value_bytes = if required {
            maximum_value_bytes
        } else {
            maximum_value_bytes.max(4)
        };
        total = total
            .checked_add(field_id.len() as u64 + 3)?
            .checked_add(maximum_value_bytes)?;
    }
    Some(total)
}

pub(crate) fn maximum_compiled_event_payload_bytes(
    entity: &CompiledEntity,
    event: &crate::contract::EventSource,
) -> Option<u32> {
    let maximum =
        maximum_event_payload_bytes(&entity.id, event.trigger, &event.projection, |field| {
            entity
                .fields
                .get(field)
                .map(|field| (&field.field_type, field.required))
        })?;
    u32::try_from(maximum).ok()
}

fn maximum_field_json_bytes(field_type: &FieldTypeSource) -> Option<u64> {
    let bytes = match field_type {
        FieldTypeSource::Boolean => 5,
        // A JSON string character needs at most six bytes as a `\uXXXX`
        // escape. Quotes add two bytes.
        FieldTypeSource::String { max_length, .. } | FieldTypeSource::Text { max_length } => {
            2_u64.checked_add(u64::from(*max_length).checked_mul(6)?)?
        }
        FieldTypeSource::Int64 => 20,
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => {
            // Decimal values are transported as JSON strings to preserve
            // exact scale. Account for the optional sign, decimal point, and
            // both JSON string quotes.
            u64::from(*precision)
                + u64::from(*scale > 0)
                + u64::from(*scale > 0 && scale == precision)
                + 3
        }
        FieldTypeSource::Date => 12,
        // RFC 3339 values accepted by `time` are bounded. Keep a conservative
        // envelope for quotes, subsecond precision, and a numeric offset.
        FieldTypeSource::Timestamp => 64,
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => 38,
        FieldTypeSource::VocabularyCode { values, .. } => values
            .iter()
            .filter_map(|value| canonicalize_json(&Value::String(value.clone())).ok())
            .map(|value| value.len() as u64)
            .max()?,
        // The closed Point shape and precision grammar fit well below this
        // conservative bound.
        FieldTypeSource::Crs84Point { .. } => 128,
        FieldTypeSource::Structured { max_bytes, .. } => u64::from(*max_bytes),
    };
    Some(bytes)
}

fn compile_event_delivery_inventory(
    registry_id: &str,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<CompiledEventDeliveryInventory, Diagnostic> {
    let mut deliveries = entities
        .values()
        .flat_map(|entity| {
            entity.events.values().filter_map(move |event| {
                event
                    .webhook
                    .as_ref()
                    .map(|webhook| (entity, event, webhook))
            })
        })
        .map(|(entity, event, webhook)| {
            let binding = event_data_schema_binding(registry_id, entity, event)?;
            let mut classifications = event
                .projection
                .iter()
                .chain(event_condition_fields(event))
                .filter_map(|field| entity.fields.get(field))
                .map(|field| field.classification)
                .collect::<Vec<_>>();
            if event.trigger == EventTrigger::RequestLifecycle {
                classifications.push(entity.classification);
            }
            let classification_ceiling = classifications
                .into_iter()
                .max()
                .expect("validated event projection is non-empty");
            Ok(CompiledEventDelivery {
                id: format!("events.{}.{}.webhook", entity.id, event.id),
                entity_id: entity.id.clone(),
                event_id: event.id.clone(),
                trigger: event.trigger,
                destination_id: webhook.destination_id.clone(),
                projection_fields: event.projection.iter().cloned().collect(),
                when: event.when.clone(),
                classification_ceiling,
                data_schema: binding.data_schema,
                data_schema_fingerprint: binding.fingerprint,
                data_schema_artifact_path: binding.artifact_path,
                authentication_profile: WebhookAuthenticationProfile::HmacSha256V1,
                delivery_mode: CompiledWebhookDeliveryMode::AfterCommit,
                retry_profile: CompiledWebhookRetryProfile::RegistryV1,
                attempt_timeout_ms: WEBHOOK_ATTEMPT_TIMEOUT_MS,
                initial_backoff_ms: WEBHOOK_INITIAL_BACKOFF_MS,
                maximum_backoff_ms: WEBHOOK_MAXIMUM_BACKOFF_MS,
                exponential_backoff_multiplier: WEBHOOK_BACKOFF_MULTIPLIER,
                maximum_attempts: WEBHOOK_MAXIMUM_ATTEMPTS,
                retry_delays_ms: webhook_retry_delays(
                    WEBHOOK_INITIAL_BACKOFF_MS,
                    WEBHOOK_MAXIMUM_BACKOFF_MS,
                    WEBHOOK_MAXIMUM_ATTEMPTS,
                ),
                maximum_payload_bytes: maximum_compiled_event_payload_bytes(entity, event)
                    .expect("validated webhook projection fields are bounded"),
                dead_letter: WebhookDeadLetterMode::Required,
                operator_replay: true,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    deliveries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(CompiledEventDeliveryInventory { deliveries })
}

fn event_condition_fields(
    event: &crate::contract::EventSource,
) -> Box<dyn Iterator<Item = &String> + '_> {
    match event.when.as_ref() {
        Some(EventConditionSource::Fields {
            changed,
            before_equals,
            after_equals,
        }) => Box::new(
            changed
                .iter()
                .chain(before_equals.keys())
                .chain(after_equals.keys()),
        ),
        Some(EventConditionSource::RequestLifecycle { .. }) | None => Box::new(std::iter::empty()),
    }
}

fn validate_derived_assets(
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<(String, String), Option<String>>,
    assets: &[ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) {
    let known_relations = sources
        .values()
        .map(|entity| default_sql_name(&entity.id))
        .collect::<Vec<_>>();
    let known_relations = known_relations.iter().map(String::as_str).collect();
    let assets = asset_map(assets, errors);
    for entity in sources.values() {
        for derived in &entity.derived {
            let path = format!("entities[{}].derived[{}].sql", entity.id, derived.id);
            let owner = origins
                .get(&(entity.id.clone(), derived.id.clone()))
                .cloned()
                .flatten();
            let Some(sql) = assets.get(&(owner.clone(), derived.sql.clone())) else {
                errors.push(Diagnostic::error(
                    "derived.sql.asset_missing",
                    path,
                    "derived SQL must be supplied as a compilation asset",
                ));
                continue;
            };
            validate_derived_sql(derived, sql, &known_relations, &path, errors);
        }
    }
}

fn asset_map<'a>(
    assets: &'a [ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) -> BTreeMap<(Option<String>, String), &'a [u8]> {
    let mut map = BTreeMap::new();
    for asset in assets {
        if asset.module.as_deref().is_some_and(str::is_empty)
            || !valid_relative_sql_path(&asset.path)
            || asset.bytes.is_empty()
            || asset.bytes.len() > MAX_DERIVED_SQL_BYTES
        {
            errors.push(Diagnostic::error(
                "module.asset.invalid",
                "modules[].assets[]",
                "module assets must be bounded module-relative SQL files",
            ));
            continue;
        }
        if map
            .insert(
                (asset.module.clone(), asset.path.clone()),
                asset.bytes.as_slice(),
            )
            .is_some()
        {
            errors.push(Diagnostic::error(
                "module.asset.duplicate",
                "modules[].assets[]",
                "module assets must be unique by module and path",
            ));
        }
    }
    map
}

fn webhook_retry_delays(initial_ms: u32, maximum_ms: u32, maximum_attempts: u8) -> Vec<u32> {
    let mut delay = initial_ms;
    (1..maximum_attempts)
        .map(|_| {
            let current = delay;
            delay = delay
                .saturating_mul(u32::from(WEBHOOK_BACKOFF_MULTIPLIER))
                .min(maximum_ms);
            current
        })
        .collect()
}

fn compile_entities(
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<(String, String), Option<String>>,
    assets: &[ModuleAssetSource],
) -> Result<(BTreeMap<String, CompiledEntity>, PhysicalNameInventory), CompileFailure> {
    let mut builder = PhysicalNameBuilder::new();
    let mut entities = BTreeMap::new();
    let mut inventory = BTreeMap::new();
    let asset_lookup = assets
        .iter()
        .map(|asset| ((asset.module.clone(), asset.path.clone()), asset))
        .collect::<BTreeMap<_, _>>();
    for source in sources.values() {
        let table = builder
            .derive("e", &source.id, "entities[].id")
            .map_err(CompileFailure::from_one)?;
        let mut field_names = BTreeMap::new();
        let mut fields = BTreeMap::new();
        let mut stored_fields = Vec::new();
        for field in source.fields.clone() {
            let physical = builder
                .derive(
                    "f",
                    &format!("{}.{}", source.id, field.id),
                    "entities[].fields[].id",
                )
                .map_err(CompileFailure::from_one)?;
            field_names.insert(field.id.clone(), physical.clone());
            let logical = logical_field(
                &field.id,
                field.api_name.as_deref(),
                field.field_type.clone(),
                field.classification,
            );
            stored_fields.push(CompiledStoredField {
                logical: logical.clone(),
                required: field.required,
                valid_time_role: field.valid_time_role,
                physical_name: physical.clone(),
            });
            fields.insert(
                field.id.clone(),
                CompiledField {
                    id: field.id,
                    field_type: field.field_type,
                    required: field.required,
                    classification: field.classification,
                    valid_time_role: field.valid_time_role,
                    physical_name: physical,
                },
            );
        }
        let mut derived_fields = BTreeMap::new();
        let mut derived_relations = BTreeMap::new();
        for derived in &source.derived {
            let owner = origins
                .get(&(source.id.clone(), derived.id.clone()))
                .cloned()
                .flatten();
            let asset = asset_lookup
                .get(&(owner, derived.sql.clone()))
                .expect("derived SQL asset was validated");
            let mut field_ids = Vec::new();
            for field in &derived.fields {
                let logical = logical_field(
                    &field.id,
                    field.api_name.as_deref(),
                    field.field_type.clone(),
                    field.classification,
                );
                field_ids.push(field.id.clone());
                derived_fields.insert(
                    field.id.clone(),
                    CompiledDerivedField {
                        logical,
                        derivation_id: derived.id.clone(),
                    },
                );
            }
            derived_relations.insert(
                derived.id.clone(),
                CompiledDerivedRelation {
                    id: derived.id.clone(),
                    sql_path: derived.sql.clone(),
                    key_field: derived.key.clone(),
                    execution: derived.execution,
                    sql_sha256: sha256_hex(&asset.bytes),
                    sql_bytes: asset.bytes.clone(),
                    fields: field_ids,
                },
            );
        }
        let canonical_id = logical_field(
            "id",
            Some("id"),
            FieldTypeSource::Uuid,
            Classification::Internal,
        );
        let source_relation = CompiledSourceRelation {
            entity_id: source.id.clone(),
            sql_name: default_sql_name(&source.id),
            stored_fields: stored_fields
                .iter()
                .map(|field| field.logical.id.clone())
                .collect(),
        };
        let selector_profiles = source
            .selector_profiles
            .iter()
            .map(|selector| {
                (
                    selector.id.clone(),
                    CompiledSelectorProfile {
                        id: selector.id.clone(),
                        fields: selector.fields.clone(),
                    },
                )
            })
            .collect();
        let read_paths = source
            .read_paths
            .iter()
            .map(|path| {
                let through = &sources[&path.through];
                let (source_ref, target_ref) = infer_read_path_refs(source, through, &path.to)
                    .expect("read-path refs were validated");
                (
                    path.id.clone(),
                    CompiledReadPath {
                        id: path.id.clone(),
                        through: path.through.clone(),
                        to: path.to.clone(),
                        route: path.route.clone(),
                        source_ref,
                        target_ref,
                    },
                )
            })
            .collect();
        let mut constraints = BTreeMap::new();
        let mut constraint_names = BTreeMap::new();
        for constraint in &source.constraints {
            let id = derived_constraint_id(constraint);
            let physical = builder
                .derive(
                    "c",
                    &format!("{}.{}", source.id, id),
                    "entities[].constraints[]",
                )
                .map_err(CompileFailure::from_one)?;
            constraint_names.insert(id.clone(), physical);
            constraints.insert(id, normalized_constraint(constraint));
        }
        for field in &source.fields {
            if matches!(field.field_type, FieldTypeSource::Reference { .. }) {
                let id = format!("reference:{}", field.id);
                let physical = builder
                    .derive(
                        "r",
                        &format!("{}.{}", source.id, field.id),
                        "entities[].fields[].target",
                    )
                    .map_err(CompileFailure::from_one)?;
                constraint_names.insert(id, physical);
            }
        }
        let mut indexes = BTreeMap::new();
        let mut index_names = BTreeMap::new();
        for index in &source.indexes {
            let physical = builder
                .derive(
                    "i",
                    &format!("{}.{}", source.id, index.id),
                    "entities[].indexes[].id",
                )
                .map_err(CompileFailure::from_one)?;
            index_names.insert(index.id.clone(), physical);
            indexes.insert(index.id.clone(), index.fields.clone());
        }
        let mut profiles = BTreeMap::new();
        let mut policy_names = BTreeMap::new();
        for access in &source.access_profiles {
            let physical = builder
                .derive(
                    "p",
                    &format!("{}.{}", source.id, access.id),
                    "entities[].accessProfiles[].id",
                )
                .map_err(CompileFailure::from_one)?;
            policy_names.insert(access.id.clone(), physical);
            profiles.insert(access.id.clone(), access.clone());
        }
        let events = source
            .events
            .iter()
            .map(|event| (event.id.clone(), event.clone()))
            .collect();
        inventory.insert(
            source.id.clone(),
            EntityPhysicalNames {
                table: table.clone(),
                fields: field_names,
                constraints: constraint_names,
                indexes: index_names,
                policies: policy_names,
            },
        );
        entities.insert(
            source.id.clone(),
            CompiledEntity {
                id: source.id.clone(),
                route: source.route.clone(),
                mutation_mode: source.mutation_mode.clone(),
                tombstone: source.tombstone,
                batch: source.batch.clone(),
                classification: source.classification,
                access_requirements: source.access_requirements.clone(),
                physical_table: table,
                temporal: source.temporal.clone().map(CompiledTemporal::from),
                canonical_id,
                stored_fields,
                derived_fields,
                derived_relations,
                source_relation,
                selector_profiles,
                read_paths,
                change_control: source.change_control.clone().map(|change_control| {
                    CompiledChangeControl {
                        required_for: change_control.required_for,
                    }
                }),
                change_request: None,
                fields,
                constraints,
                indexes,
                access_profiles: profiles,
                events,
            },
        );
    }
    Ok((
        entities,
        PhysicalNameInventory {
            entities: inventory,
        },
    ))
}

fn compile_routes_and_access(
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<(CompiledRouteInventory, CompiledAccessInventory), CompileFailure> {
    let mut routes = Vec::new();
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for entity in entities.values() {
        for operation in routed_operations() {
            if operation == Operation::Batch && entity.batch.is_none() {
                continue;
            }
            let profiles: Vec<&AccessProfileSource> = entity
                .access_profiles
                .values()
                .filter(|profile| {
                    profile.operations.contains(&operation)
                        && (operation != Operation::Revisions
                            || profile.revision_access && !profile.anonymous)
                })
                .collect();
            if profiles.is_empty() {
                continue;
            }
            let default = if profiles.len() == 1 {
                profiles[0]
            } else {
                profiles
                    .iter()
                    .copied()
                    .find(|profile| profile.default)
                    .expect("default profile was validated")
            };
            let profile_ids: BTreeSet<String> =
                profiles.iter().map(|profile| profile.id.clone()).collect();
            let (method, path) = route_shape(entity, operation);
            let route = CompiledRoute {
                id: format!("records.{}.{}", entity.id, operation_id(operation)),
                entity_id: entity.id.clone(),
                method,
                path,
                operation,
                query_kind: (operation == Operation::List).then_some(CompiledQueryKind::List),
                revision_kind: None,
                request_stage: None,
                maximum_records: None,
                access_profiles: profile_ids.iter().cloned().collect(),
                default_access_profile: default.id.clone(),
            };
            if operation == Operation::Revisions {
                routes.push(CompiledRoute {
                    id: format!("records.{}.revisions.list", entity.id),
                    revision_kind: Some(CompiledRevisionKind::List),
                    maximum_records: Some(MAX_REVISION_HISTORY_RECORDS),
                    ..route.clone()
                });
                routes.push(CompiledRoute {
                    id: format!("records.{}.revisions.detail", entity.id),
                    path: format!("{}/{{revision}}", route.path),
                    revision_kind: Some(CompiledRevisionKind::Detail),
                    maximum_records: Some(1),
                    ..route
                });
            } else {
                routes.push(route);
            }
            if operation == Operation::List && entity.temporal.is_some() {
                for kind in [CompiledQueryKind::Current, CompiledQueryKind::AsOf] {
                    routes.push(CompiledRoute {
                        id: format!("records.{}.{}", entity.id, query_kind_id(kind)),
                        entity_id: entity.id.clone(),
                        method: HttpMethod::Get,
                        path: format!("/v1/records/{}:{}", entity.route, query_kind_id(kind)),
                        operation,
                        query_kind: Some(kind),
                        revision_kind: None,
                        request_stage: None,
                        maximum_records: None,
                        access_profiles: profile_ids.iter().cloned().collect(),
                        default_access_profile: default.id.clone(),
                    });
                }
            }
            entries.push(CompiledAccessEntry {
                route_id: format!("records.{}.{}", entity.id, operation_id(operation)),
                entity_id: entity.id.clone(),
                operation,
                profile_ids,
                default_profile_id: default.id.clone(),
            });
        }
        if let Some(plan) = &entity.change_request {
            compile_change_request_routes_and_access(
                entity,
                plan,
                &mut routes,
                &mut entries,
                &mut errors,
            );
        }
        for read_path in entity.read_paths.values() {
            let profiles: Vec<&AccessProfileSource> = entity
                .access_profiles
                .values()
                .filter(|profile| {
                    profile
                        .read_paths
                        .iter()
                        .any(|grant| grant.path == read_path.id)
                })
                .collect();
            if profiles.is_empty() {
                continue;
            }
            let default = if profiles.len() == 1 {
                profiles[0]
            } else {
                profiles
                    .iter()
                    .copied()
                    .find(|profile| profile.default)
                    .expect("default profile was validated")
            };
            let profile_ids: BTreeSet<String> =
                profiles.iter().map(|profile| profile.id.clone()).collect();
            let route_id = format!("records.{}.path.{}", entity.id, read_path.id);
            routes.push(CompiledRoute {
                id: route_id.clone(),
                entity_id: entity.id.clone(),
                method: HttpMethod::Get,
                path: format!(
                    "/v1/records/{}/{{record_id}}/{}",
                    entity.route, read_path.route
                ),
                operation: Operation::List,
                query_kind: Some(CompiledQueryKind::List),
                revision_kind: None,
                request_stage: None,
                maximum_records: None,
                access_profiles: profile_ids.iter().cloned().collect(),
                default_access_profile: default.id.clone(),
            });
            entries.push(CompiledAccessEntry {
                route_id,
                entity_id: entity.id.clone(),
                operation: Operation::List,
                profile_ids,
                default_profile_id: default.id.clone(),
            });
        }
    }
    routes.sort_by(|left, right| {
        (&left.path, left.method, &left.id).cmp(&(&right.path, right.method, &right.id))
    });
    entries.sort_by(|left, right| {
        (&left.entity_id, left.operation, &left.route_id).cmp(&(
            &right.entity_id,
            right.operation,
            &right.route_id,
        ))
    });
    if !errors.is_empty() {
        return Err(CompileFailure::from_errors(errors));
    }
    Ok((
        CompiledRouteInventory { routes },
        CompiledAccessInventory { entries },
    ))
}

fn compile_change_request_routes_and_access(
    entity: &CompiledEntity,
    plan: &crate::model::CompiledChangeRequest,
    routes: &mut Vec<CompiledRoute>,
    entries: &mut Vec<CompiledAccessEntry>,
    errors: &mut Vec<Diagnostic>,
) {
    for action in &plan.actions {
        let operation = action.operation.access_operation();
        let route_id =
            change_request_route_id(entity, action.operation, action.review_stage.as_deref());
        let profiles = change_request_route_profiles(
            entity,
            plan,
            action.operation,
            action.review_stage.as_deref(),
        );
        if profiles.is_empty() {
            continue;
        }
        let Some(default) = route_default_profile(&profiles, &route_id, errors) else {
            continue;
        };
        let profile_ids: BTreeSet<String> =
            profiles.iter().map(|profile| profile.id.clone()).collect();
        routes.push(CompiledRoute {
            id: route_id.clone(),
            entity_id: entity.id.clone(),
            method: HttpMethod::Post,
            path: change_request_route_path(
                entity,
                action.operation,
                action.review_stage.as_deref(),
            ),
            operation,
            query_kind: None,
            revision_kind: None,
            request_stage: action.review_stage.clone(),
            maximum_records: Some(1),
            access_profiles: profile_ids.iter().cloned().collect(),
            default_access_profile: default.id.clone(),
        });
        entries.push(CompiledAccessEntry {
            route_id,
            entity_id: entity.id.clone(),
            operation,
            profile_ids,
            default_profile_id: default.id.clone(),
        });
    }
}

fn change_request_route_profiles<'a>(
    entity: &'a CompiledEntity,
    plan: &crate::model::CompiledChangeRequest,
    operation: ChangeRequestOperation,
    review_stage: Option<&str>,
) -> Vec<&'a AccessProfileSource> {
    entity
        .access_profiles
        .values()
        .filter(|profile| {
            profile.operations.contains(&operation.access_operation())
                && match operation {
                    ChangeRequestOperation::SubmitRequest
                    | ChangeRequestOperation::ReviseRequest
                    | ChangeRequestOperation::CancelRequest => true,
                    ChangeRequestOperation::ApproveRequest
                    | ChangeRequestOperation::RejectRequest
                    | ChangeRequestOperation::RequestRevision => {
                        review_stage.is_some_and(|stage| {
                            review_route_profile_covers_stage(plan, &profile.id, stage)
                        })
                    }
                    ChangeRequestOperation::ApplyRequest => {
                        apply_route_profile_covers_targets(plan, &profile.id)
                    }
                }
        })
        .collect()
}

fn review_route_profile_covers_stage(
    plan: &crate::model::CompiledChangeRequest,
    profile_id: &str,
    stage: &str,
) -> bool {
    plan.target_entities.iter().all(|target| {
        plan.review_grants.iter().any(|grant| {
            grant.profile_id == profile_id
                && grant.stage == stage
                && grant.target_entity_id == *target
        })
    })
}

fn apply_route_profile_covers_targets(
    plan: &crate::model::CompiledChangeRequest,
    profile_id: &str,
) -> bool {
    plan.target_entities.iter().all(|target| {
        plan.apply_grants
            .iter()
            .any(|grant| grant.profile_id == profile_id && grant.target_entity_id == *target)
    })
}

fn route_default_profile<'a>(
    profiles: &[&'a AccessProfileSource],
    _route_id: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<&'a AccessProfileSource> {
    if profiles.len() == 1 {
        return Some(profiles[0]);
    }
    if let Some(default) = profiles.iter().copied().find(|profile| profile.default) {
        return Some(default);
    }
    errors.push(Diagnostic::error(
        "change_request.route_access.default_missing",
        "entities[].accessProfiles[].default",
        "request action route has multiple profiles but no route-eligible default",
    ));
    None
}

fn change_request_route_id(
    entity: &CompiledEntity,
    operation: ChangeRequestOperation,
    review_stage: Option<&str>,
) -> String {
    match operation {
        ChangeRequestOperation::ApproveRequest
        | ChangeRequestOperation::RejectRequest
        | ChangeRequestOperation::RequestRevision => format!(
            "records.{}.request.stages.{}.{}",
            entity.id,
            review_stage.expect("review route stage is compiled"),
            request_action_id(operation)
        ),
        _ => format!(
            "records.{}.request.{}",
            entity.id,
            request_action_id(operation)
        ),
    }
}

fn change_request_route_path(
    entity: &CompiledEntity,
    operation: ChangeRequestOperation,
    review_stage: Option<&str>,
) -> String {
    let base = format!("/v1/records/{}/{{record_id}}/actions", entity.route);
    match operation {
        ChangeRequestOperation::SubmitRequest => format!("{base}/submit"),
        ChangeRequestOperation::ApproveRequest
        | ChangeRequestOperation::RejectRequest
        | ChangeRequestOperation::RequestRevision => format!(
            "{base}/stages/{}/{}",
            review_stage.expect("review route stage is compiled"),
            request_action_path_segment(operation)
        ),
        ChangeRequestOperation::ReviseRequest => format!("{base}/revise"),
        ChangeRequestOperation::CancelRequest => format!("{base}/cancel"),
        ChangeRequestOperation::ApplyRequest => format!("{base}/apply"),
    }
}

fn request_action_id(operation: ChangeRequestOperation) -> &'static str {
    match operation {
        ChangeRequestOperation::SubmitRequest => "submit",
        ChangeRequestOperation::ApproveRequest => "approve",
        ChangeRequestOperation::RejectRequest => "reject",
        ChangeRequestOperation::RequestRevision => "request_revision",
        ChangeRequestOperation::ReviseRequest => "revise",
        ChangeRequestOperation::CancelRequest => "cancel",
        ChangeRequestOperation::ApplyRequest => "apply",
    }
}

fn request_action_path_segment(operation: ChangeRequestOperation) -> &'static str {
    match operation {
        ChangeRequestOperation::SubmitRequest => "submit",
        ChangeRequestOperation::ApproveRequest => "approve",
        ChangeRequestOperation::RejectRequest => "reject",
        ChangeRequestOperation::RequestRevision => "request-revision",
        ChangeRequestOperation::ReviseRequest => "revise",
        ChangeRequestOperation::CancelRequest => "cancel",
        ChangeRequestOperation::ApplyRequest => "apply",
    }
}

fn compile_metadata_inventory(
    registry_id: &str,
    version: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    routes: &CompiledRouteInventory,
    access: &CompiledAccessInventory,
) -> Result<CompiledMetadataInventory, Diagnostic> {
    let access_by_route = access
        .entries
        .iter()
        .filter(|entry| !entry.route_id.is_empty())
        .map(|entry| ((entry.route_id.as_str(), entry.operation), entry))
        .collect::<BTreeMap<_, _>>();
    let access_by_operation = access
        .entries
        .iter()
        .map(|entry| ((entry.entity_id.as_str(), entry.operation), entry))
        .collect::<BTreeMap<_, _>>();
    let mut entries_by_entity: BTreeMap<String, Vec<CompiledMetadataEntry>> = BTreeMap::new();
    for route in &routes.routes {
        let Some(entity) = entities.get(&route.entity_id) else {
            return Err(inconsistent_metadata_inventory());
        };
        let Some(access_entry) = access_by_route
            .get(&(route.id.as_str(), route.operation))
            .or_else(|| access_by_operation.get(&(route.entity_id.as_str(), route.operation)))
        else {
            return Err(inconsistent_metadata_inventory());
        };
        for profile_id in &route.access_profiles {
            if !access_entry.profile_ids.contains(profile_id) {
                return Err(inconsistent_metadata_inventory());
            }
            let Some(profile) = entity.access_profiles.get(profile_id) else {
                return Err(inconsistent_metadata_inventory());
            };
            let (response_entity, readable_fields) =
                metadata_response_surface(entity, profile, route, entities)
                    .ok_or_else(inconsistent_metadata_inventory)?;
            entries_by_entity
                .entry(entity.id.clone())
                .or_default()
                .push(CompiledMetadataEntry {
                    route_id: route.id.clone(),
                    operation: route.operation,
                    access_profile: profile_id.clone(),
                    response_entity_id: response_entity.id.clone(),
                    readable_fields,
                });
        }
    }
    let entities = entities
        .values()
        .filter_map(|entity| {
            let mut entries = entries_by_entity.remove(&entity.id)?;
            entries.sort_by(|left, right| {
                (&left.route_id, left.operation, &left.access_profile).cmp(&(
                    &right.route_id,
                    right.operation,
                    &right.access_profile,
                ))
            });
            Some(CompiledMetadataEntity {
                id: entity.id.clone(),
                route: entity.route.clone(),
                schema_path: format!("/v1/schemas/{}", entity.id),
                entries,
            })
        })
        .collect();
    Ok(CompiledMetadataInventory {
        registry_id: registry_id.to_owned(),
        version: version.to_owned(),
        entities,
    })
}

fn metadata_response_surface<'a>(
    entity: &'a CompiledEntity,
    profile: &AccessProfileSource,
    route: &CompiledRoute,
    entities: &'a BTreeMap<String, CompiledEntity>,
) -> Option<(&'a CompiledEntity, BTreeSet<String>)> {
    let read_path = entity.read_paths.values().find(|path| {
        route.id == format!("records.{}.path.{}", entity.id, path.id)
            && route.path == format!("/v1/records/{}/{{record_id}}/{}", entity.route, path.route)
    });
    let (response_entity, configured_fields) = match read_path {
        Some(path) => {
            let grant = profile
                .read_paths
                .iter()
                .find(|grant| grant.path == path.id)?;
            (entities.get(&path.to)?, &grant.readable_fields)
        }
        None => (entity, &profile.readable_fields),
    };
    let readable_fields = configured_fields
        .iter()
        .filter(|field| {
            !profile.anonymous
                || response_entity
                    .fields
                    .get(*field)
                    .is_some_and(|field| field.classification == Classification::Public)
        })
        .cloned()
        .collect();
    Some((response_entity, readable_fields))
}

fn inconsistent_metadata_inventory() -> Diagnostic {
    Diagnostic::error(
        "metadata_inventory.inconsistent",
        "compiled.metadataInventory",
        "compiled metadata inventory no longer matches compiled route and access inventories",
    )
}

fn compile_query_inventory(
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) -> CompiledQueryInventory {
    let mut operations = Vec::new();
    let route_ids = entities
        .values()
        .flat_map(|entity| {
            [
                (entity.id.clone(), CompiledQueryKind::List),
                (entity.id.clone(), CompiledQueryKind::Current),
                (entity.id.clone(), CompiledQueryKind::AsOf),
            ]
        })
        .map(|(entity_id, kind)| {
            (
                (entity_id.clone(), kind),
                format!("records.{entity_id}.{}", query_kind_id(kind)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for entity in entities.values() {
        for profile in entity.access_profiles.values() {
            if profile.operations.contains(&Operation::List) {
                if let Some(operation) = query_operation(
                    QueryOperationInput {
                        entity,
                        profile,
                        route_id: &route_ids[&(entity.id.clone(), CompiledQueryKind::List)],
                        kind: CompiledQueryKind::List,
                        temporal: None,
                        allow_count: profile.allow_count,
                        selector_fields: Vec::new(),
                        read_path: None,
                    },
                    errors,
                ) {
                    operations.push(operation);
                }
                if let Some(temporal) = &entity.temporal {
                    let binding = temporal_binding(temporal);
                    if let Some(operation) = query_operation(
                        QueryOperationInput {
                            entity,
                            profile,
                            route_id: &route_ids[&(entity.id.clone(), CompiledQueryKind::Current)],
                            kind: CompiledQueryKind::Current,
                            temporal: Some(binding.clone()),
                            allow_count: profile.allow_count,
                            selector_fields: Vec::new(),
                            read_path: None,
                        },
                        errors,
                    ) {
                        operations.push(operation);
                    }
                    if let Some(operation) = query_operation(
                        QueryOperationInput {
                            entity,
                            profile,
                            route_id: &route_ids[&(entity.id.clone(), CompiledQueryKind::AsOf)],
                            kind: CompiledQueryKind::AsOf,
                            temporal: Some(binding),
                            allow_count: profile.allow_count,
                            selector_fields: Vec::new(),
                            read_path: None,
                        },
                        errors,
                    ) {
                        operations.push(operation);
                    }
                }
            }
            if profile.operations.contains(&Operation::Lookup) {
                for lookup in &profile.lookups {
                    if let Some(selector) = entity.selector_profiles.get(&lookup.selector) {
                        let route_id = format!("records.{}.lookup", entity.id);
                        if let Some(operation) = query_operation(
                            QueryOperationInput {
                                entity,
                                profile,
                                route_id: &route_id,
                                kind: CompiledQueryKind::List,
                                temporal: None,
                                allow_count: false,
                                selector_fields: selector.fields.clone(),
                                read_path: None,
                            },
                            errors,
                        ) {
                            operations.push(operation);
                        }
                    }
                }
            }
            for grant in &profile.read_paths {
                let Some(path) = entity.read_paths.get(&grant.path) else {
                    continue;
                };
                let Some(target) = entities.get(&path.to) else {
                    continue;
                };
                let route_id = format!("records.{}.path.{}", entity.id, path.id);
                if let Some(operation) =
                    read_path_query_operation(entity, target, profile, grant, &route_id, errors)
                {
                    operations.push(operation);
                }
            }
        }
    }
    operations.sort_by(|left, right| left.id.cmp(&right.id));
    CompiledQueryInventory { operations }
}

fn read_path_query_operation(
    source: &CompiledEntity,
    target: &CompiledEntity,
    profile: &AccessProfileSource,
    grant: &ReadPathGrantSource,
    route_id: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledQueryOperation> {
    let readable_fields = grant.readable_fields.clone();
    let filterable_fields = grant.filterable_fields.clone();
    let sortable_fields = grant.sortable_fields.clone();
    let mut projection_fields = readable_fields.iter().cloned().collect::<Vec<_>>();
    projection_fields.sort();
    let filter_fields = filterable_fields
        .iter()
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(target, field)?;
            query_filter_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let sort_fields = sortable_fields
        .iter()
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(target, field)?;
            query_sort_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let mut processing_fields = readable_fields;
    processing_fields.extend(filterable_fields);
    processing_fields.extend(sortable_fields);
    if let Some(path) = source.read_paths.get(&grant.path) {
        processing_fields.insert(path.source_ref.clone());
        processing_fields.insert(path.target_ref.clone());
    }
    Some(CompiledQueryOperation {
        id: format!("records.{}.{}.path.{}", source.id, profile.id, grant.path),
        route_id: route_id.to_owned(),
        entity_id: target.id.clone(),
        profile_id: profile.id.clone(),
        kind: CompiledQueryKind::List,
        max_page_size: 100,
        projection_fields,
        filter_fields,
        sort_fields,
        allow_count: grant.allow_count,
        selector_fields: Vec::new(),
        read_path: Some(grant.path.clone()),
        processing_fields: processing_fields.into_iter().collect(),
        stable_tie_breaker: "record_id".to_owned(),
        temporal: None,
    })
}

struct QueryOperationInput<'a> {
    entity: &'a CompiledEntity,
    profile: &'a AccessProfileSource,
    route_id: &'a str,
    kind: CompiledQueryKind,
    temporal: Option<CompiledQueryTemporalBinding>,
    allow_count: bool,
    selector_fields: Vec<String>,
    read_path: Option<String>,
}

fn query_operation(
    input: QueryOperationInput<'_>,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledQueryOperation> {
    let QueryOperationInput {
        entity,
        profile,
        route_id,
        kind,
        temporal,
        allow_count,
        selector_fields,
        read_path,
    } = input;
    if let Some(binding) = &temporal {
        let temporal_fields = [&binding.start_field, &binding.end_field];
        if temporal_fields
            .iter()
            .any(|field| !profile.readable_fields.contains(*field))
        {
            errors.push(Diagnostic::error(
                "query.temporal.field_not_readable",
                "entities[].accessProfiles[].readableFields",
                "temporal query boundary fields must be readable by the selected profile",
            ));
            return None;
        }
        if profile.anonymous
            && temporal_fields.iter().any(|field| {
                entity
                    .fields
                    .get(*field)
                    .is_some_and(|compiled| compiled.classification != Classification::Public)
            })
        {
            errors.push(Diagnostic::error(
                "query.temporal.public_processing_non_public",
                "entities[].accessProfiles[]",
                "an anonymous temporal query may process only public boundary fields",
            ));
            return None;
        }
    }

    let mut projection_fields = profile
        .readable_fields
        .iter()
        .cloned()
        .collect::<Vec<String>>();
    projection_fields.sort();
    let filter_fields = profile
        .filterable_fields
        .iter()
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(entity, field)?;
            query_filter_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let mut filter_fields = filter_fields;
    let sort_fields = profile
        .sortable_fields
        .iter()
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(entity, field)?;
            query_sort_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let mut sort_fields = sort_fields;
    if entity.change_request.is_some() && kind == CompiledQueryKind::List {
        // A proposal digest commits to the full frozen packet, including
        // private values. Anonymous polling must not become a hash oracle.
        filter_fields.extend(
            request_state_query_filter_fields()
                .into_iter()
                .filter(|field| {
                    !profile.anonymous
                        || field.field != crate::model::REQUEST_EFFECT_DIGEST_QUERY_FIELD
                }),
        );
        sort_fields.extend(
            request_state_query_sort_fields()
                .into_iter()
                .filter(|field| {
                    !profile.anonymous
                        || field.field != crate::model::REQUEST_EFFECT_DIGEST_QUERY_FIELD
                }),
        );
    }
    let mut processing_fields = profile.readable_fields.clone();
    processing_fields.extend(profile.filterable_fields.iter().cloned());
    processing_fields.extend(profile.sortable_fields.iter().cloned());
    processing_fields.extend(selector_fields.iter().cloned());
    processing_fields.extend(
        profile
            .row_boundaries
            .iter()
            .map(|boundary| boundary.field.clone()),
    );
    let id = if !selector_fields.is_empty() {
        format!("records.{}.{}.lookup", entity.id, profile.id)
    } else {
        format!(
            "records.{}.{}.{}",
            entity.id,
            profile.id,
            query_kind_id(kind)
        )
    };

    Some(CompiledQueryOperation {
        id,
        route_id: route_id.to_owned(),
        entity_id: entity.id.clone(),
        profile_id: profile.id.clone(),
        kind,
        max_page_size: 100,
        projection_fields,
        filter_fields,
        sort_fields,
        allow_count,
        selector_fields,
        read_path,
        processing_fields: processing_fields.into_iter().collect(),
        stable_tie_breaker: "record_id".to_owned(),
        temporal,
    })
}

fn query_filter_field(
    field_type: &FieldTypeSource,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledQueryFilterField> {
    let mut operators = vec![
        CompiledQueryFilterOperator::Equals,
        CompiledQueryFilterOperator::In,
        CompiledQueryFilterOperator::IsNull,
        CompiledQueryFilterOperator::IsNotNull,
    ];
    match field_type {
        FieldTypeSource::Boolean | FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {}
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. } => {
            operators.push(CompiledQueryFilterOperator::Prefix);
            operators.push(CompiledQueryFilterOperator::Contains);
        }
        FieldTypeSource::Int64
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp => {
            operators.push(CompiledQueryFilterOperator::Range);
        }
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            errors.push(Diagnostic::error(
                "query.filter.field_type_unsupported",
                "entities[].accessProfiles[].filterableFields",
                "a query filter field must use a supported scalar type",
            ));
            return None;
        }
    }
    operators.sort();
    Some(CompiledQueryFilterField {
        field: field.to_owned(),
        operators,
    })
}

fn compiled_field_type<'a>(
    entity: &'a CompiledEntity,
    field: &str,
) -> Option<(&'a FieldTypeSource, FieldStorageKind)> {
    if field == "id" {
        return Some((&entity.canonical_id.field_type, FieldStorageKind::Pseudo));
    }
    if let Some(stored) = entity.fields.get(field) {
        return Some((&stored.field_type, FieldStorageKind::Stored));
    }
    entity
        .derived_fields
        .get(field)
        .map(|derived| (&derived.logical.field_type, FieldStorageKind::Derived))
}

fn logical_field(
    id: &str,
    api_name: Option<&str>,
    field_type: FieldTypeSource,
    classification: Classification,
) -> CompiledLogicalField {
    CompiledLogicalField {
        id: id.to_owned(),
        api_name: api_name
            .map(str::to_owned)
            .unwrap_or_else(|| default_api_name(id)),
        sql_name: default_sql_name(id),
        field_type,
        classification,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_prefix(&digest, digest.len()))
}

fn query_sort_field(
    field_type: &FieldTypeSource,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledQuerySortField> {
    if matches!(
        field_type,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
    ) {
        errors.push(Diagnostic::error(
            "query.sort.field_type_unsupported",
            "entities[].accessProfiles[].sortableFields",
            "a query sort field must use a supported scalar type",
        ));
        return None;
    }
    Some(CompiledQuerySortField {
        field: field.to_owned(),
        directions: vec![CompiledQuerySortDirection::Asc],
    })
}

fn temporal_binding(temporal: &CompiledTemporal) -> CompiledQueryTemporalBinding {
    CompiledQueryTemporalBinding {
        start_field: temporal.start_field.clone(),
        end_field: temporal.end_field.clone(),
        scope_fields: temporal.scope_fields.clone(),
        semantics: CompiledQueryTemporalSemantics::StartInclusiveEndExclusive,
    }
}

fn query_kind_id(kind: CompiledQueryKind) -> &'static str {
    match kind {
        CompiledQueryKind::List => "list",
        CompiledQueryKind::Current => "current",
        CompiledQueryKind::AsOf => "as-of",
    }
}

fn route_shape(entity: &CompiledEntity, operation: Operation) -> (HttpMethod, String) {
    let base = format!("/v1/records/{}", entity.route);
    match operation {
        Operation::Create => (HttpMethod::Post, base),
        Operation::Get => (HttpMethod::Get, format!("{base}/{{record_id}}")),
        Operation::Lookup => (HttpMethod::Post, format!("{base}:lookup")),
        Operation::List => (HttpMethod::Get, base),
        Operation::Patch => (HttpMethod::Patch, format!("{base}/{{record_id}}")),
        Operation::Tombstone => (HttpMethod::Delete, format!("{base}/{{record_id}}")),
        Operation::Batch => (HttpMethod::Post, format!("{base}:batch")),
        Operation::Revisions => (HttpMethod::Get, format!("{base}/{{record_id}}/revisions")),
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest
        | Operation::Invoke => {
            unreachable!("request and immediate actions use compiled action metadata")
        }
    }
}

fn routed_operations() -> [Operation; 8] {
    [
        Operation::Create,
        Operation::Get,
        Operation::Lookup,
        Operation::List,
        Operation::Patch,
        Operation::Tombstone,
        Operation::Batch,
        Operation::Revisions,
    ]
}

fn all_operations() -> [Operation; 16] {
    [
        Operation::Create,
        Operation::Get,
        Operation::Lookup,
        Operation::List,
        Operation::Patch,
        Operation::Tombstone,
        Operation::Batch,
        Operation::Revisions,
        Operation::SubmitRequest,
        Operation::ApproveRequest,
        Operation::RejectRequest,
        Operation::RequestRevision,
        Operation::ReviseRequest,
        Operation::CancelRequest,
        Operation::ApplyRequest,
        Operation::Invoke,
    ]
}

fn is_request_operation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
    )
}

fn operation_id(operation: Operation) -> &'static str {
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
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        Operation::Invoke => "invoke",
    }
}

fn derived_constraint_id(constraint: &ConstraintSource) -> String {
    if let Some(id) = constraint.explicit_id() {
        return id.to_owned();
    }
    let normalized = normalized_constraint(constraint);
    let value = serde_json::to_value(&normalized).expect("constraint serializes");
    let bytes = canonicalize_json(&value).expect("constraint canonicalizes");
    let digest = Sha256::digest(bytes);
    let kind = match constraint {
        ConstraintSource::Unique { .. } => "unique",
        ConstraintSource::Compare { .. } => "compare",
        ConstraintSource::IntRange { .. } => "int-range",
        ConstraintSource::Vocabulary { .. } => "vocabulary",
        ConstraintSource::TemporalNonOverlap { .. } => "temporal-non-overlap",
    };
    format!("{kind}-{}", hex_prefix(&digest, 8))
}

fn validate_unique_when(
    entity: &EntitySource,
    when: Option<&[UniqueWhenPredicate]>,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(when) = when else {
        return;
    };
    if when.is_empty() {
        errors.push(Diagnostic::error(
            "constraint.unique.when.empty",
            "entities[].constraints[].when",
            "a partial unique constraint requires at least one closed predicate",
        ));
        return;
    }

    let fields: BTreeMap<&str, &FieldSource> = entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect();
    let mut active_lifecycle = false;
    let mut field_states: BTreeMap<&str, UniqueWhenFieldState> = BTreeMap::new();

    for predicate in when {
        match predicate {
            UniqueWhenPredicate::ActiveLifecycle {} => {
                if active_lifecycle {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.duplicate",
                        "entities[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                active_lifecycle = true;
            }
            UniqueWhenPredicate::FieldEquals { field, value } => {
                let Some(source) = validate_unique_when_field(field, &fields, errors) else {
                    continue;
                };
                let Some(canonical) = canonical_field_literal(value, &source.field_type) else {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.literal_invalid",
                        "entities[].constraints[].when[].value",
                        "a partial unique literal must be canonical for the field type",
                    ));
                    continue;
                };
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.contradiction",
                        "entities[].constraints[].when",
                        "partial unique predicates contain a contradiction",
                    ));
                }
                if state.is_not_null {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.duplicate",
                        "entities[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if let Some(existing) = &state.equals {
                    errors.push(Diagnostic::error(
                        if existing == &canonical {
                            "constraint.unique.when.duplicate"
                        } else {
                            "constraint.unique.when.contradiction"
                        },
                        "entities[].constraints[].when",
                        if existing == &canonical {
                            "partial unique predicates must be duplicate-free"
                        } else {
                            "partial unique predicates contain a contradiction"
                        },
                    ));
                }
                state.equals = Some(canonical);
            }
            UniqueWhenPredicate::FieldIsNull { field } => {
                let Some(source) = validate_unique_when_field(field, &fields, errors) else {
                    continue;
                };
                if source.required {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.null_invalid",
                        "entities[].constraints[].when[].field",
                        "a partial unique null predicate must be useful for the field",
                    ));
                    continue;
                }
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.duplicate",
                        "entities[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if state.is_not_null || state.equals.is_some() {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.contradiction",
                        "entities[].constraints[].when",
                        "partial unique predicates contain a contradiction",
                    ));
                }
                state.is_null = true;
            }
            UniqueWhenPredicate::FieldIsNotNull { field } => {
                let Some(source) = validate_unique_when_field(field, &fields, errors) else {
                    continue;
                };
                if source.required {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.null_invalid",
                        "entities[].constraints[].when[].field",
                        "a partial unique null predicate must be useful for the field",
                    ));
                    continue;
                }
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_not_null || state.equals.is_some() {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.duplicate",
                        "entities[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "constraint.unique.when.contradiction",
                        "entities[].constraints[].when",
                        "partial unique predicates contain a contradiction",
                    ));
                }
                state.is_not_null = true;
            }
        }
    }
}

#[derive(Default)]
struct UniqueWhenFieldState {
    equals: Option<String>,
    is_null: bool,
    is_not_null: bool,
}

fn validate_unique_when_field<'a>(
    field: &str,
    fields: &BTreeMap<&str, &'a FieldSource>,
    errors: &mut Vec<Diagnostic>,
) -> Option<&'a FieldSource> {
    let Some(source) = fields.get(field).copied() else {
        errors.push(Diagnostic::error(
            "constraint.unique.when.field_unknown",
            "entities[].constraints[].when[].field",
            "a partial unique predicate refers to an unknown field",
        ));
        return None;
    };
    if matches!(
        source.field_type,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
    ) {
        errors.push(Diagnostic::error(
            "constraint.unique.when.field_unsupported",
            "entities[].constraints[].when[].field",
            "CRS84 point and structured fields cannot be partial unique predicates",
        ));
        return None;
    }
    Some(source)
}

fn canonical_field_literal(value: &Value, field_type: &FieldTypeSource) -> Option<String> {
    match field_type {
        FieldTypeSource::Boolean => value.as_bool().map(|value| value.to_string()),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => value.as_str().and_then(|value| {
            let length = value.chars().count();
            (length >= *min_length as usize && length <= *max_length as usize)
                .then(|| value.to_owned())
        }),
        FieldTypeSource::Text { max_length } => value
            .as_str()
            .filter(|value| value.chars().count() <= *max_length as usize)
            .map(str::to_owned),
        FieldTypeSource::Int64 => value.as_i64().map(|parsed| parsed.to_string()),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => value.as_str().and_then(|value| {
            crate::contract::valid_decimal_value(
                value,
                *precision,
                *scale,
                minimum.as_deref(),
                maximum.as_deref(),
            )
            .then(|| value.to_owned())
        }),
        FieldTypeSource::Date => value
            .as_str()
            .filter(|value| valid_iso_date(value))
            .map(str::to_owned),
        FieldTypeSource::Timestamp => value
            .as_str()
            .and_then(|value| canonical_timestamp(value).then(|| value.to_owned())),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => value
            .as_str()
            .filter(|value| valid_uuid(value))
            .map(str::to_owned),
        FieldTypeSource::VocabularyCode { values, .. } => value
            .as_str()
            .filter(|value| values.iter().any(|allowed| allowed == *value))
            .map(str::to_owned),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => None,
    }
}

fn valid_iso_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Some(month) = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
    else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    (1..=9999).contains(&year) && Date::from_calendar_date(year, month, day).is_ok()
}

fn canonical_timestamp(value: &str) -> bool {
    let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) else {
        return false;
    };
    let Ok(formatted) = timestamp.format(&Rfc3339) else {
        return false;
    };
    formatted == value
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes()[8] == b'-'
        && value.as_bytes()[13] == b'-'
        && value.as_bytes()[18] == b'-'
        && value.as_bytes()[23] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

fn unique_when_predicate_field(predicate: &UniqueWhenPredicate) -> Option<&str> {
    match predicate {
        UniqueWhenPredicate::FieldEquals { field, .. }
        | UniqueWhenPredicate::FieldIsNull { field }
        | UniqueWhenPredicate::FieldIsNotNull { field } => Some(field),
        UniqueWhenPredicate::ActiveLifecycle {} => None,
    }
}

fn normalized_constraint(constraint: &ConstraintSource) -> ConstraintSource {
    match constraint {
        ConstraintSource::Unique { id, fields, when } => ConstraintSource::Unique {
            id: id.clone(),
            fields: fields.clone(),
            when: when.as_ref().map(|predicates| {
                let mut predicates = predicates.clone();
                predicates.sort_by_key(unique_when_predicate_sort_key);
                predicates
            }),
        },
        _ => constraint.clone(),
    }
}

fn unique_when_predicate_sort_key(predicate: &UniqueWhenPredicate) -> String {
    match predicate {
        UniqueWhenPredicate::FieldEquals { field, value } => {
            format!("field:{field}:equals:{}", value)
        }
        UniqueWhenPredicate::FieldIsNull { field } => format!("field:{field}:is_null"),
        UniqueWhenPredicate::FieldIsNotNull { field } => format!("field:{field}:is_not_null"),
        UniqueWhenPredicate::ActiveLifecycle {} => "lifecycle:active".to_owned(),
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

fn validate_language(value: &str, errors: &mut Vec<Diagnostic>) {
    if value.is_empty()
        || value.len() > 35
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        errors.push(Diagnostic::error(
            "project.default_language.invalid",
            "project.registry.defaultLanguage",
            "the default language tag is invalid",
        ));
    }
}

fn validate_projection_text(
    value: &ManifestProjectionTextSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let invalid = match value {
        ManifestProjectionTextSource::Plain(value) => value.trim().is_empty(),
        ManifestProjectionTextSource::Localized(values) => {
            values.is_empty() || values.values().any(|value| value.trim().is_empty())
        }
    };
    if invalid {
        errors.push(Diagnostic::error(
            "manifest_projection.text.empty",
            path,
            "Registry Manifest projection text and every localized value must not be empty",
        ));
    }
}

fn manifest_projects_field(field: &CompiledField) -> bool {
    !matches!(
        &field.field_type,
        FieldTypeSource::Reference { .. }
            | FieldTypeSource::Crs84Point { .. }
            | FieldTypeSource::Structured { .. }
    )
}

fn nonempty(value: &str, path: &str, code: &str, errors: &mut Vec<Diagnostic>) {
    if value.trim().is_empty() {
        errors.push(Diagnostic::error(
            code,
            path,
            "a required source field is empty",
        ));
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn valid_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| !character.is_control())
}
