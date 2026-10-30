// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_hooks::HOOK_HANDLER_ABI_V1;
use registry_platform_yaml::{duplicate_display_text_pairs, lookalike_local_id_pairs, DisplayText};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use uuid::Uuid;

use crate::artifacts::{event_data_schema_binding, generate_artifacts};
use crate::contract::{
    parsed_bbox, valid_decimal_bounds, valid_structured_schema, AccessProfileSource,
    ActionExecutionSource, ActionSource, Classification, ConstraintSource, DerivedExecutionSource,
    DerivedFieldSource, DisplayPurpose, DisplaySource, EntityExtensionSource, EntitySource,
    EventConditionSource, EventTrigger, FieldGenerationSource, FieldSource, FieldTypeSource,
    GeoJsonSource, HookAuthenticationProfile, HookDeadLetterMode, HookHandlerSource, HookPhase,
    LookupValueOrigin, ManifestProjectionTextSource, ModelDisplaySource, ModuleAssetSource,
    MutationMode, Operation, PresentationSource, ReadPathPermissionSource, RegistryModule,
    RegistryProject, SpatialBboxPermissionSource, SpatialQueryPermissionSource, TimerInputSource,
    TimerPredicateSource, TimerSource, TimerValueSource, UniqueWhenPredicate, ValidTimeRole,
    DECIMAL_BOUNDS_REQUIREMENTS, MAX_ACCESS_LOG_EXEMPTIONS, MAX_ACCESS_LOG_EXEMPTION_REASON_BYTES,
    MAX_ACCESS_LOG_RETENTION_DAYS, MAX_ACCESS_LOG_SUBJECT_CHARACTERS,
    MAX_ACCESS_LOG_TRUSTED_INTERMEDIARIES, MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES,
    MAX_ENCRYPTED_FIELD_STRING_CHARACTERS, MAX_FIELD_LOOKUP_NORMALIZATION_STEPS,
    MAX_GENERATED_IDENTIFIER_COMPONENT_LENGTH, MAX_GENERATED_IDENTIFIER_SCOPE_FIELDS,
    MAX_STRUCTURED_VALUE_BYTES,
};
use crate::derived_sql::{derived_sql_dependencies, validate_derived_sql};
use crate::diagnostics::{CompileFailure, Diagnostic};
use crate::generated_ddl::generate_ddl_with_actions;
use crate::immediate_actions::{
    compile_immediate_actions, hex_lower, CollectedActionSource, CollectedFunctionSource,
};
use crate::logical_names::{
    canonical_sql_name, default_api_name, reserved_logical_name, valid_api_name,
};
use crate::model::{
    leading_field_indexed, leading_field_indexed_for_list_finding, REFERENCE_INDEX_PREFIX,
};
use crate::model::{
    CompiledAccessEntry, CompiledAccessInventory, CompiledBboxQueryCapability, CompiledBlindIndex,
    CompiledChangeControl, CompiledDerivedField, CompiledDerivedRelation, CompiledEntity,
    CompiledEntityModuleOrigins, CompiledEventDelivery, CompiledEventDeliveryInventory,
    CompiledField, CompiledFieldEncryption, CompiledGeneratedIdentifier,
    CompiledGeneratedIdentifierStrategy, CompiledGeoJsonBinding, CompiledHookDeliveryMode,
    CompiledHookHandler, CompiledHookHandlerKind, CompiledHookRetryProfile, CompiledLogicalField,
    CompiledManifestAuthority, CompiledManifestDataService, CompiledManifestDataset,
    CompiledManifestDistribution, CompiledManifestProjection, CompiledManifestPublicService,
    CompiledMetadataEntity, CompiledMetadataEntry, CompiledMetadataInventory,
    CompiledModuleIdentity, CompiledQueryFilterField, CompiledQueryFilterOperator,
    CompiledQueryInventory, CompiledQueryKind, CompiledQueryOperation, CompiledQuerySortDirection,
    CompiledQuerySortField, CompiledQueryTemporalBinding, CompiledQueryTemporalSemantics,
    CompiledReadPath, CompiledRegistry, CompiledRevisionKind, CompiledRoute,
    CompiledRouteInventory, CompiledSelectorProfile, CompiledSourceRelation,
    CompiledSpatialQueryCapability, CompiledStoredField, CompiledTemporal, CompiledTimer,
    CompiledTimerInput, CompiledTimerPredicate, CompiledTimerValue, HttpMethod,
    MAX_REVISION_HISTORY_RECORDS,
};
use crate::physical_names::{
    hex_prefix, EntityPhysicalNames, PhysicalNameBuilder, PhysicalNameInventory,
};

pub(crate) mod attachments;
pub mod review_context;
mod statistics;
mod timezone;

pub const AUTHORING_API_VERSION: &str = "id.registrystack.org/formats/breg/project/v1alpha1";
pub const AUTHORING_KIND: &str = "BRegProject";
pub const MAX_BATCH_ITEMS: u16 = 100;
pub const MAX_BATCH_BYTES: u32 = 2_097_152;
/// The transport ceiling a chunk-submission request body is read under: the
/// batch byte ceiling plus the chunk envelope's own members. A chunk's
/// canonical batch body is bounded by the run's `maximumBytes` (whose highest
/// configurable value is `MAX_BATCH_BYTES`), but the request that carries it
/// adds the envelope around it: the chunk index, the two 64-character hex
/// digests, their member names, and the JSON punctuation, which together stay
/// far below this 1 KiB allowance. Reading at the bare batch ceiling would
/// refuse a chunk the run's own bounds admit before it is ever parsed.
pub const INGESTION_CHUNK_REQUEST_CEILING: u32 = MAX_BATCH_BYTES + 1024;
/// The attempt budget starts at the claim's database timestamp and covers the claim
/// commit and reload round trips before the request leaves, so this floor is a
/// validation bound: samples and fixtures should use a realistic value such as 1000 ms.
pub const MIN_HOOK_ATTEMPT_TIMEOUT_MS: u32 = 100;
pub const HOOK_ATTEMPT_TIMEOUT_MS: u32 = 5_000;
pub const HOOK_INITIAL_BACKOFF_MS: u32 = 1_000;
pub const HOOK_MAXIMUM_BACKOFF_MS: u32 = 8_000;
pub const HOOK_MAXIMUM_ATTEMPTS: u8 = 5;
pub const MAX_HOOK_ATTEMPT_TIMEOUT_MS: u32 = HOOK_ATTEMPT_TIMEOUT_MS;
pub const MAX_HOOK_ATTEMPTS: u8 = HOOK_MAXIMUM_ATTEMPTS;
pub const MAX_EVENT_PACKAGE_REVISION_BYTES: u32 = 256;
/// The longest build identity value, shared by the environment, instance, and
/// database identifiers a package build request carries.
pub const MAX_BUILD_ID_BYTES: u32 = 64;
/// Largest canonical statistical release document admitted by compilation
/// and retained by the runtime release store.
pub(crate) const MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum canonical event body accepted by the governed hook transport.
///
/// This intentionally matches the platform event-destination body ceiling.
/// The compiler uses this bound without constructing a transport; the runtime
/// integration pins the equality.
pub const MAX_HOOK_PAYLOAD_BYTES: u32 = 1_048_576;
pub const HOOK_BACKOFF_MULTIPLIER: u8 = 2;

/// One ingestion-run operation of the published HTTP surface, carrying the
/// problem-response catalogue the operation's OpenAPI entry must publish.
///
/// Each operation's set is its closed response vocabulary: the handler's own
/// admission refusals, the problem codes that operation's mutation-service
/// ingestion errors map onto, and the shared admission envelope every
/// secured route answers with (the bearer refusal, the authorization
/// concealment, and the audit-gated unavailability). The OpenAPI builder
/// publishes exactly these sets, and the ingestion contract test holds the
/// published document to them, so the catalogue cannot drift from what the
/// routes can actually answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestionApiOperation {
    CreateRun,
    ListRuns,
    ReadRun,
    SubmitChunk,
    CancelRun,
    ChunkReceipt,
}

impl IngestionApiOperation {
    /// Every ingestion operation the published document can carry.
    pub const ALL: [Self; 6] = [
        Self::CreateRun,
        Self::ListRuns,
        Self::ReadRun,
        Self::SubmitChunk,
        Self::CancelRun,
        Self::ChunkReceipt,
    ];

    /// The `x-registry-operation` marker the operation's OpenAPI entry
    /// carries, so the contract test can find the published entry.
    #[must_use]
    pub const fn openapi_marker(self) -> &'static str {
        match self {
            Self::CreateRun => "ingestionCreateRun",
            Self::ListRuns => "ingestionListRuns",
            Self::ReadRun => "ingestionReadRun",
            Self::SubmitChunk => "ingestionSubmitChunk",
            Self::CancelRun => "ingestionCancelRun",
            Self::ChunkReceipt => "ingestionChunkReceipt",
        }
    }

    /// Every problem response the operation can answer with.
    #[must_use]
    pub const fn problem_codes(self) -> &'static [crate::problem::ProblemCode] {
        match self {
            Self::CreateRun => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::IngestionProfileMismatch,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::PreconditionFailed,
                crate::problem::ProblemCode::UnsupportedMediaType,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
            Self::ListRuns => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
            Self::ReadRun => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::IngestionProfileMismatch,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
            Self::SubmitChunk => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::IngestionProfileMismatch,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::IngestionRunNotOpen,
                crate::problem::ProblemCode::IngestionRunBlocked,
                crate::problem::ProblemCode::IngestionChunkMismatch,
                crate::problem::ProblemCode::IngestionReceiptErased,
                crate::problem::ProblemCode::PreconditionFailed,
                crate::problem::ProblemCode::UnsupportedMediaType,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
            Self::CancelRun => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::IngestionProfileMismatch,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::IngestionRunNotOpen,
                crate::problem::ProblemCode::UnsupportedMediaType,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
            Self::ChunkReceipt => &[
                crate::problem::ProblemCode::RequestInvalid,
                crate::problem::ProblemCode::AuthenticationRefused,
                crate::problem::ProblemCode::IngestionProfileMismatch,
                crate::problem::ProblemCode::ResourceNotFound,
                crate::problem::ProblemCode::IngestionReceiptErased,
                crate::problem::ProblemCode::ServiceUnavailable,
            ],
        }
    }
}

type CollectedEntities = (
    BTreeMap<String, EntitySource>,
    CollectedOrigins,
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
    if modules
        .iter()
        .flat_map(|module| &module.actions)
        .any(|action| !action.evidence.is_empty())
    {
        diagnostics.push(Diagnostic::error(
            "breg.action.evidence-module-unsupported",
            "modules[].actions[].evidence",
            "the trial declares Evidence capabilities in project actions",
        ));
    }

    validate_project_header(project, profile, &mut diagnostics, &mut findings);
    validate_native_definitions(project, &mut diagnostics);
    for module in modules {
        validate_local_value_types(
            &module.value_types,
            &format!("modules[id={}].valueTypes", module.id),
            &mut diagnostics,
        );
    }
    let module_closure = validate_module_locks(
        project,
        modules,
        assets,
        profile,
        &mut diagnostics,
        &mut findings,
    );
    let (module_order, module_map) = order_modules(project, modules, &mut diagnostics);
    validate_cross_file_local_id_collisions(project, modules, &mut diagnostics);
    validate_cross_file_duplicate_display_labels(project, modules, &mut findings);
    validate_authored_display_text(project, modules, &mut diagnostics);
    let mut functions = BTreeMap::new();
    for (module, function) in project
        .functions
        .iter()
        .map(|function| (None, function))
        .chain(
            module_order
                .iter()
                .filter_map(|id| module_map.get(id))
                .flat_map(|module| {
                    module
                        .functions
                        .iter()
                        .map(move |function| (Some(module.id.clone()), function))
                }),
        )
    {
        validate_id(&function.id, "functions[].id", &mut diagnostics);
        if !(1..=100000).contains(&function.limits.maximum_operations)
            || !(1..=1048576).contains(&function.limits.maximum_output_bytes)
            || functions
                .insert(
                    function.id.clone(),
                    CollectedFunctionSource {
                        source: function.clone(),
                        source_module: module,
                    },
                )
                .is_some()
        {
            diagnostics.push(Diagnostic::error("breg.function.contract-invalid", "functions[]", "functions require unique IDs across the module closure and bounded positive execution/output limits"));
        }
    }
    let (mut sources, mut origins, mut action_sources) =
        collect_entities(project, &module_order, &module_map, &mut diagnostics);
    apply_temporal_roles(&mut sources, &mut diagnostics);
    apply_extensions(
        &mut sources,
        &mut origins,
        &module_order,
        &module_map,
        &mut diagnostics,
    );
    validate_project_entity_access_profiles(project, &mut diagnostics);
    validate_module_access_profile_task_grants(&sources, &mut diagnostics);
    let module_profiles = crate::access::module_profile_keys(&sources);
    expand_project_access(project, &mut sources, &mut diagnostics);
    resolve_vocabularies(project, &mut sources, &mut action_sources, &mut diagnostics);
    validate_entities(
        &project.project.id,
        &sources,
        &origins.hook_paths,
        profile,
        &mut diagnostics,
    );
    crate::access::validate_access_requirements(&sources, &mut diagnostics);
    crate::membership::validate(&sources, &mut diagnostics);
    crate::consent::validate(project, &sources, &mut diagnostics);
    crate::event_record::validate(&sources, &mut diagnostics);
    findings.extend(crate::access::access_findings(&sources));
    findings.extend(crate::access::project_access_findings(project, &sources));
    findings.extend(crate::access::module_access_findings(
        &sources,
        &module_profiles,
    ));
    findings.extend(create_required_field_findings(&sources));
    validate_derived_assets(&sources, &origins.derived, assets, &mut diagnostics);
    validate_hook_assets(&sources, &origins.hooks, assets, &mut diagnostics);
    if !diagnostics.is_empty() {
        findings.push(stopped_stage_finding(
            "source validation",
            "compiled model and Manifest projection checks did not run",
        ));
        return Err(CompileFailure::from_errors(diagnostics).with_findings(&findings));
    }

    let (mut entities, physical_names) =
        compile_entities(&sources, &origins, assets).map_err(|failure| {
            stopped_compile_failure(failure, &findings, "compiled model construction")
        })?;
    compile_relationships(&mut entities).map_err(|errors| {
        stopped_compile_failure(
            CompileFailure::from_errors(errors),
            &findings,
            "relationship compilation",
        )
    })?;
    let statistical_datasets = statistics::compile(project, &entities).map_err(|errors| {
        stopped_compile_failure(
            CompileFailure::from_errors(errors),
            &findings,
            "statistical release compilation",
        )
    })?;
    crate::membership::compile(&mut entities);
    let recipients = crate::consent::compile(project, &sources, &mut entities);
    crate::event_record::compile(&sources, &mut entities);
    let timer_actions = sources
        .values()
        .flat_map(|entity| entity.timers.iter().map(|timer| timer.invoke.clone()))
        .collect::<BTreeSet<_>>();
    let mut action_inventory = compile_immediate_actions(
        &action_sources,
        &entities,
        &project.access_profiles,
        assets,
        &functions,
        &project.review_authorities,
        project,
        &timer_actions,
    )
    .map_err(|errors| {
        stopped_compile_failure(
            CompileFailure::from_errors(errors),
            &findings,
            "Action compilation",
        )
    })?;
    crate::action_evidence_contracts::compile_evidence(project, assets, &mut action_inventory)
        .map_err(|errors| {
            stopped_compile_failure(
                CompileFailure::from_errors(errors),
                &findings,
                "Action Evidence compilation",
            )
        })?;
    crate::proposal_hooks::compile_hooks(&action_sources, &mut action_inventory, assets).map_err(
        |errors| {
            stopped_compile_failure(
                CompileFailure::from_errors(errors),
                &findings,
                "Proposal hook compilation",
            )
        },
    )?;
    crate::immediate_actions::finalize_action_revisions(&mut action_inventory, &entities);
    findings.extend(stored_field_fillability_findings(
        &entities,
        &action_inventory,
    ));
    findings.extend(crate::access::compiled_access_findings(
        &entities,
        &action_inventory,
    ));
    let (route_inventory, access_inventory) =
        compile_routes_and_access(&entities).map_err(|failure| {
            stopped_compile_failure(failure, &findings, "route and access compilation")
        })?;
    let metadata_inventory = compile_metadata_inventory(
        &project.project.id,
        &project.project.version,
        &entities,
        &route_inventory,
        &access_inventory,
    )
    .map_err(|error| {
        stopped_compile_failure(
            CompileFailure::from_one(error),
            &findings,
            "metadata compilation",
        )
    })?;
    let query_inventory = compile_query_inventory(&entities, &mut diagnostics);
    if profile == CompileProfile::Authoring {
        findings.extend(unindexed_list_findings(&entities));
    }
    let mut event_delivery_inventory =
        compile_event_delivery_inventory(&project.project.id, &entities, &origins.hooks, assets)
            .map_err(|error| CompileFailure::from_one(error).with_findings(&findings))?;
    for action in &action_inventory.actions {
        if let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution {
            event_delivery_inventory.deliveries.extend(
                proposal
                    .hooks
                    .iter()
                    .map(|hook| crate::proposal_hooks::compile_delivery(action, hook)),
            );
        }
    }
    event_delivery_inventory
        .deliveries
        .sort_by(|left, right| left.id.cmp(&right.id));
    compile_timers(
        project,
        &sources,
        &origins.timers,
        &mut entities,
        &action_inventory,
        &event_delivery_inventory,
        &mut diagnostics,
    );
    diagnostics.extend(timezone::validate(
        project.project.timezone.as_deref(),
        &entities,
        &route_inventory,
        &action_inventory,
        &statistical_datasets,
    ));
    validate_manifest_projection(project, &entities, &mut diagnostics);
    if !diagnostics.is_empty() {
        findings.push(stopped_stage_finding(
            "Manifest projection validation",
            "explain output could not be produced",
        ));
        return Err(CompileFailure::from_errors(diagnostics).with_findings(&findings));
    }
    let ddl = generate_ddl_with_actions(&entities, &physical_names, &action_inventory);
    let manifest_projection = compile_manifest_projection(project, &entities);
    if let Some(projection) = manifest_projection.as_ref() {
        findings.extend(crate::manifest_adapter::cross_dataset_reference_findings(
            projection, &entities,
        ));
    }
    let access_profile_displays = project
        .access_profiles
        .iter()
        .map(|profile| crate::model::CompiledAccessProfileDisplay {
            id: profile.id.clone(),
            display: profile.display.clone(),
        })
        .collect::<Vec<_>>();
    let artifacts = generate_artifacts(
        &project.project.id,
        &project.project.version,
        &project.project.default_language,
        &project.project.display,
        project.project.timezone.as_deref(),
        &project.review_authorities,
        &project.datasets,
        &access_profile_displays,
        manifest_projection.as_ref(),
        &module_order,
        &module_closure,
        &entities,
        &statistical_datasets,
        &physical_names,
        &action_inventory,
        &route_inventory,
        &access_inventory,
        &metadata_inventory,
        &query_inventory,
        &event_delivery_inventory,
        &recipients,
        &ddl,
    )
    .map_err(|error| CompileFailure::from_one(error).with_findings(&findings))?;
    let artifact_bytes = artifacts
        .canonical_inventory_bytes()
        .map_err(|error| CompileFailure::from_one(error).with_findings(&findings))?;
    let revision_digest = Sha256::digest(artifact_bytes);
    let revision = format!(
        "sha256:{}",
        hex_prefix(&revision_digest, revision_digest.len())
    );
    findings.sort();

    Ok(CompiledRegistry::new(
        project.project.id.clone(),
        project.project.version.clone(),
        project.project.default_language.clone(),
        project.project.display.clone(),
        project.project.timezone.clone(),
        project.review_authorities.clone(),
        project.datasets.clone(),
        access_profile_displays,
        project.package.clone(),
        manifest_projection,
        module_order,
        module_closure,
        entities,
        statistical_datasets,
        physical_names,
        action_inventory,
        route_inventory,
        access_inventory,
        metadata_inventory,
        query_inventory,
        event_delivery_inventory,
        recipients,
        ddl,
        artifacts,
        findings,
        revision,
    ))
}

const MAX_TIMER_PREDICATE_FIELDS: usize = 16;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn compile_timers(
    project: &RegistryProject,
    sources: &BTreeMap<String, EntitySource>,
    origins: &EntityMemberOriginMap,
    entities: &mut BTreeMap<String, CompiledEntity>,
    actions: &crate::model::CompiledActionInventory,
    event_deliveries: &CompiledEventDeliveryInventory,
    errors: &mut Vec<Diagnostic>,
) {
    let mut grants = BTreeSet::new();
    for grant in &project.timer_grants {
        if !grants.insert((grant.entity.as_str(), grant.timer.as_str())) {
            errors.push(Diagnostic::error(
                "breg.timer.grant-duplicate",
                "timerGrants[]",
                "a root project cannot grant the same Record timer more than once",
            ));
        }
        if !sources
            .get(&grant.entity)
            .is_some_and(|entity| entity.timers.iter().any(|timer| timer.id == grant.timer))
        {
            errors.push(Diagnostic::error(
                "breg.timer.grant-unknown",
                "timerGrants[]",
                "a timer grant must name one declared Record timer",
            ));
        }
    }

    let mut compiled = Vec::new();
    for source_entity in sources.values() {
        let Some(entity) = entities.get(&source_entity.id) else {
            continue;
        };
        for timer in &source_entity.timers {
            let path = format!(
                "recordTypes[id={}].timers[id={}]",
                source_entity.id, timer.id
            );
            if !grants.contains(&(source_entity.id.as_str(), timer.id.as_str())) {
                errors.push(Diagnostic::error(
                    "breg.timer.grant-missing",
                    &path,
                    "a declared timer requires an exact root timerGrants entry",
                ));
                continue;
            }
            let Some(action) = actions
                .actions
                .iter()
                .find(|action| action.id == timer.invoke)
            else {
                errors.push(Diagnostic::error(
                    "breg.timer.action-unknown",
                    format!("{path}.invoke"),
                    "a timer must invoke one declared Action",
                ));
                continue;
            };
            if action.execution.is_proposal() {
                errors.push(Diagnostic::error(
                    "breg.timer.action-not-immediate",
                    format!("{path}.invoke"),
                    "a timer must invoke an immediate Action",
                ));
            }
            if !action.permissions.is_empty() {
                errors.push(Diagnostic::error(
                    "breg.timer.action-public-invoke",
                    format!("{path}.invoke"),
                    "a timer Action cannot have a public Invoke grant",
                ));
            }
            if action
                .requires
                .iter()
                .any(|requirement| requirement.revision_unchanged)
            {
                errors.push(Diagnostic::error(
                    "breg.timer.action-revision-guard-forbidden",
                    format!("{path}.invoke"),
                    "a timer Action cannot require revision: unchanged because timer execution has no caller condition token",
                ));
            }
            if !action.evidence.is_empty()
                || !action.commit_evidence.is_empty()
                || action.consent_issuer.is_some()
                || action
                    .handler
                    .as_ref()
                    .is_some_and(|handler| !handler.capabilities.is_empty())
            {
                errors.push(Diagnostic::error(
                    "breg.timer.action-capability-forbidden",
                    format!("{path}.invoke"),
                    "a timer Action must be local and cannot depend on Evidence, consent issuance, or remote capabilities",
                ));
            }

            let fields = &entity.fields;
            let Some(at) = fields.get(&timer.at) else {
                errors.push(Diagnostic::error(
                    "breg.timer.control-field-unknown",
                    format!("{path}.at"),
                    "at must name a stored timestamp field on the timer Record type",
                ));
                continue;
            };
            if at.field_type != FieldTypeSource::Timestamp {
                errors.push(Diagnostic::error(
                    "breg.timer.control-field-type",
                    format!("{path}.at"),
                    "at must name a stored timestamp field",
                ));
            }
            if let Some(not_after) = &timer.not_after {
                if not_after == &timer.at
                    || fields
                        .get(not_after)
                        .is_none_or(|field| field.field_type != FieldTypeSource::Timestamp)
                {
                    errors.push(Diagnostic::error(
                        "breg.timer.control-field-type",
                        format!("{path}.notAfter"),
                        "notAfter must name a distinct stored timestamp field",
                    ));
                }
            }
            if let Some(rearm_on) = &timer.rearm_on {
                if fields.get(rearm_on).is_none_or(|field| {
                    !matches!(
                        field.field_type,
                        FieldTypeSource::Uuid | FieldTypeSource::Int64
                    )
                }) {
                    errors.push(Diagnostic::error(
                        "breg.timer.control-field-type",
                        format!("{path}.rearmOn"),
                        "rearmOn must name a stored UUID or integer field",
                    ));
                }
            }

            let (when, predicate_fields) = compile_timer_predicate(timer, fields, &path, errors);
            let control_fields = [
                Some(timer.at.clone()),
                timer.not_after.clone(),
                timer.rearm_on.clone(),
            ]
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>();
            let action_inputs = action
                .inputs
                .iter()
                .map(|input| (input.id.as_str(), input))
                .collect::<BTreeMap<_, _>>();
            let mapped_ids = timer
                .input
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let expected_ids = action_inputs.keys().copied().collect::<BTreeSet<_>>();
            if mapped_ids != expected_ids {
                errors.push(Diagnostic::error(
                    "breg.timer.input-incomplete",
                    format!("{path}.input"),
                    "timer input must map every Action input exactly once and no others",
                ));
            }
            let mut input = BTreeMap::new();
            let mut effect_input_fields = BTreeSet::new();
            for (id, mapping) in &timer.input {
                let Some(action_input) = action_inputs.get(id.as_str()) else {
                    continue;
                };
                if let Some(compiled_input) = compile_timer_input(
                    mapping,
                    action_input,
                    entity,
                    &mut effect_input_fields,
                    &format!("{path}.input.{id}"),
                    errors,
                ) {
                    input.insert(id.clone(), compiled_input);
                }
            }

            for effect in &action.effects {
                if matches!(effect.operation, Operation::Patch | Operation::Tombstone) {
                    let crate::model::CompiledPlanTargetBinding::Existing { input: target } =
                        &effect.target.binding
                    else {
                        errors.push(Diagnostic::error(
                            "breg.timer.action-existing-target-forbidden",
                            format!("{path}.invoke"),
                            "a timer Action may mutate only its anchor or create bounded records",
                        ));
                        continue;
                    };
                    if effect.target.entity_id != source_entity.id
                        || !matches!(input.get(target), Some(CompiledTimerInput::RecordId))
                    {
                        errors.push(Diagnostic::error(
                            "breg.timer.action-existing-target-forbidden",
                            format!("{path}.invoke"),
                            "a timer Action may mutate only its anchor or create bounded records",
                        ));
                    }
                }
            }

            let anchor_read_fields = control_fields
                .iter()
                .chain(&predicate_fields)
                .chain(&effect_input_fields)
                .cloned()
                .collect();
            let system_grant = crate::immediate_actions::system_grant_for_timer_action(
                action,
                entities,
                &source_entity.id,
                &anchor_read_fields,
            );
            let anchor_inputs = input
                .iter()
                .filter_map(|(id, mapping)| {
                    matches!(mapping, CompiledTimerInput::RecordId).then_some(id.clone())
                })
                .collect::<BTreeSet<_>>();
            crate::immediate_actions::validate_timer_plan_bounds(
                &format!("{path}.invoke"),
                action,
                entities,
                &source_entity.id,
                &anchor_inputs,
                &anchor_read_fields,
                errors,
            );
            for target in &system_grant.targets {
                if matches!(
                    target.operation,
                    Operation::Create | Operation::Patch | Operation::Tombstone
                ) && entities
                    .get(&target.entity_id)
                    .is_some_and(|target_entity| {
                        target_entity
                            .change_control
                            .as_ref()
                            .is_some_and(|control| control.required_for.contains(&target.operation))
                    })
                {
                    errors.push(Diagnostic::error(
                        "breg.timer.action-proposal-policy-bypass",
                        format!("{path}.invoke"),
                        "a timer Action cannot mutate a target whose current policy requires a Proposal",
                    ));
                }
            }

            let relevant_deliveries = event_deliveries
                .deliveries
                .iter()
                .filter(|delivery| {
                    let crate::model::CompiledEventOwner::RecordType {
                        record_type,
                        trigger,
                    } = &delivery.owner
                    else {
                        return false;
                    };
                    action.effects.iter().any(|effect| {
                        effect.target.entity_id == *record_type
                            && matches!(
                                (effect.operation, trigger),
                                (Operation::Create, crate::contract::EventTrigger::Created)
                                    | (Operation::Patch, crate::contract::EventTrigger::Patched)
                                    | (
                                        Operation::Tombstone,
                                        crate::contract::EventTrigger::Tombstoned
                                    )
                            )
                    })
                })
                .collect::<Vec<_>>();
            let event_delivery_ids = relevant_deliveries
                .iter()
                .map(|delivery| delivery.id.clone())
                .collect::<Vec<_>>();
            let revision_payload = serde_json::json!({
                "recordType":source_entity.id,
                "id":timer.id,
                "at":timer.at,
                "notAfter":timer.not_after,
                "rearmOn":timer.rearm_on,
                "when":when,
                "input":input,
                "invoke":action.id,
                "actionRevision":action.definition_revision,
                "systemGrant":system_grant,
                "eventDeliveries":relevant_deliveries,
            });
            let definition_revision = format!(
                "sha256:{}",
                crate::immediate_actions::hex_lower(&Sha256::digest(
                    canonicalize_json(&revision_payload)
                        .expect("compiled timer revision payload canonicalizes")
                ))
            );
            compiled.push((
                source_entity.id.clone(),
                CompiledTimer {
                    record_type: source_entity.id.clone(),
                    id: timer.id.clone(),
                    source_module: origins
                        .get(&(source_entity.id.clone(), timer.id.clone()))
                        .cloned()
                        .flatten(),
                    at: timer.at.clone(),
                    not_after: timer.not_after.clone(),
                    rearm_on: timer.rearm_on.clone(),
                    when,
                    invoke: action.id.clone(),
                    input,
                    control_fields,
                    predicate_fields,
                    effect_input_fields,
                    action_revision: action.definition_revision.clone(),
                    system_grant,
                    event_deliveries: event_delivery_ids,
                    definition_revision,
                },
            ));
        }
    }
    if errors.is_empty() {
        for (record_type, timer) in compiled {
            entities
                .get_mut(&record_type)
                .expect("compiled timer Record type exists")
                .timers
                .insert(timer.id.clone(), timer);
        }
    }
}

fn compile_timer_predicate(
    timer: &TimerSource,
    fields: &BTreeMap<String, CompiledField>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) -> (Option<CompiledTimerPredicate>, BTreeSet<String>) {
    let Some(TimerPredicateSource::Fields { equals }) = &timer.when else {
        return (None, BTreeSet::new());
    };
    if equals.is_empty() || equals.len() > MAX_TIMER_PREDICATE_FIELDS {
        errors.push(Diagnostic::error(
            "breg.timer.predicate-bounds",
            format!("{path}.when.equals"),
            "a timer field predicate requires one through sixteen equality checks",
        ));
    }
    let mut literals_are_valid = true;
    for (field, value) in equals {
        let value = serde_json::to_value(value).expect("timer scalar value serializes");
        if fields
            .get(field)
            .is_none_or(|source| canonical_field_literal(&value, &source.field_type).is_none())
            || canonicalize_json(&value).is_err()
        {
            literals_are_valid = false;
            errors.push(Diagnostic::error(
                "breg.timer.predicate-invalid",
                format!("{path}.when.equals.{field}"),
                "a timer predicate literal must match a supported stored scalar field and its canonical JSON representation",
            ));
        }
    }
    let predicate = literals_are_valid.then(|| CompiledTimerPredicate {
        equals: equals
            .iter()
            .map(|(field, value)| {
                (
                    field.clone(),
                    serde_json::to_value(value).expect("timer scalar value serializes"),
                )
            })
            .collect(),
        timestamp_fields: equals
            .keys()
            .filter(|field| {
                fields
                    .get(*field)
                    .is_some_and(|field| field.field_type == FieldTypeSource::Timestamp)
            })
            .cloned()
            .collect(),
    });
    (predicate, equals.keys().cloned().collect())
}

fn compile_timer_input(
    mapping: &TimerInputSource,
    action_input: &crate::model::CompiledActionInput,
    entity: &CompiledEntity,
    effect_input_fields: &mut BTreeSet<String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) -> Option<CompiledTimerInput> {
    let selected = usize::from(mapping.from_record_id)
        + usize::from(mapping.from_field.is_some())
        + usize::from(mapping.from_timer.is_some())
        + usize::from(mapping.value.is_some());
    if selected != 1 {
        errors.push(Diagnostic::error(
            "breg.timer.input-source-invalid",
            path,
            "a timer input mapping must select exactly one value source",
        ));
        return None;
    }
    if mapping.from_record_id {
        if !matches!(&action_input.field_type, FieldTypeSource::Reference { target, .. } if target == &entity.id)
        {
            errors.push(Diagnostic::error(
                "breg.timer.input-type-mismatch",
                path,
                "fromRecordId requires a reference input targeting the timer Record type",
            ));
            return None;
        }
        return Some(CompiledTimerInput::RecordId);
    }
    if let Some(field) = &mapping.from_field {
        let Some(source) = entity.fields.get(field) else {
            errors.push(Diagnostic::error(
                "breg.timer.input-field-unknown",
                path,
                "fromField must name one stored field on the timer Record type",
            ));
            return None;
        };
        if !crate::immediate_actions::compatible_field_types(
            &source.field_type,
            &action_input.field_type,
        ) {
            errors.push(Diagnostic::error(
                "breg.timer.input-type-mismatch",
                path,
                "fromField must match the Action input type",
            ));
            return None;
        }
        effect_input_fields.insert(field.clone());
        return Some(CompiledTimerInput::Field {
            field: field.clone(),
        });
    }
    if let Some(value) = mapping.from_timer {
        let valid = matches!(
            (value, &action_input.field_type),
            (TimerValueSource::OccurrenceId, FieldTypeSource::Uuid)
                | (TimerValueSource::DueAt, FieldTypeSource::Timestamp)
        );
        if !valid {
            errors.push(Diagnostic::error(
                "breg.timer.input-type-mismatch",
                path,
                "fromTimer occurrence-id requires UUID and due-at requires timestamp",
            ));
            return None;
        }
        return Some(CompiledTimerInput::Timer {
            value: match value {
                TimerValueSource::OccurrenceId => CompiledTimerValue::OccurrenceId,
                TimerValueSource::DueAt => CompiledTimerValue::DueAt,
            },
        });
    }
    let value = mapping
        .value
        .as_ref()
        .expect("one timer mapping source exists");
    if value.is_null()
        || !crate::data::validate_field_value(
            crate::data::FieldValue::Json(value),
            &action_input.field_type,
        )
        || canonicalize_json(value).is_err()
    {
        errors.push(Diagnostic::error(
            "breg.timer.input-type-mismatch",
            path,
            "a timer literal must match the Action input type and its canonical JSON representation",
        ));
        return None;
    }
    Some(CompiledTimerInput::Literal {
        value: value.clone(),
    })
}

struct SourcedLocalId<'a> {
    id: String,
    path: String,
    source: Option<&'a str>,
}

fn add_cross_file_collisions(
    code: &str,
    values: &[SourcedLocalId<'_>],
    errors: &mut Vec<Diagnostic>,
) {
    for (first, second) in lookalike_local_id_pairs(values.iter().map(|value| value.id.as_str())) {
        let first = &values[first];
        let second = &values[second];
        if first.source == second.source {
            continue;
        }
        errors.push(
            Diagnostic::error(
                code,
                &second.path,
                &format!(
                    "local identifiers `{}` and `{}` differ only by `-` versus `_`",
                    first.id, second.id
                ),
            )
            .with_related(&first.path, "the first identifier is defined here"),
        );
    }
}

struct SourcedDisplayText<'a> {
    id: Option<&'a str>,
    text: &'a str,
    path: String,
    source: Option<&'a str>,
}

fn add_cross_file_duplicate_labels(
    code: &str,
    kind: &str,
    values: &[SourcedDisplayText<'_>],
    findings: &mut Vec<Diagnostic>,
) {
    for (first, second) in duplicate_display_text_pairs(values.iter().map(|value| value.text)) {
        let first = &values[first];
        let second = &values[second];
        if first.source == second.source {
            continue;
        }
        let message = match (first.id, second.id) {
            (Some(first), Some(second)) => {
                format!("{kind} `{first}` and `{second}` have display text that compares the same")
            }
            _ => format!("two {kind} have display text that compares the same"),
        };
        findings.push(
            Diagnostic::finding(code, &second.path, &message)
                .with_related(&first.path, "the first display text is defined here"),
        );
    }
}

fn collect_profile_and_hook_labels<'a>(
    profiles: &'a [AccessProfileSource],
    hooks: &'a [crate::contract::HookSource],
    path: &str,
    source: Option<&'a str>,
    profile_labels: &mut Vec<SourcedDisplayText<'a>>,
    hook_labels: &mut Vec<SourcedDisplayText<'a>>,
) {
    profile_labels.extend(profiles.iter().filter_map(|profile| {
        profile
            .display
            .label
            .as_deref()
            .map(|text| SourcedDisplayText {
                id: Some(&profile.id),
                text,
                path: format!("{path}.accessProfiles[id={}].display.label", profile.id),
                source,
            })
    }));
    hook_labels.extend(hooks.iter().filter_map(|hook| {
        hook.display
            .label
            .as_deref()
            .map(|text| SourcedDisplayText {
                id: Some(&hook.id),
                text,
                path: format!("{path}.hooks[id={}].display.label", hook.id),
                source,
            })
    }));
}

fn collect_entity_field_labels<'a>(
    entity: &'a EntitySource,
    path: &str,
    source: Option<&'a str>,
    labels: &mut Vec<SourcedDisplayText<'a>>,
) {
    labels.extend(entity.fields.iter().filter_map(|field| {
        field
            .display
            .label
            .as_deref()
            .map(|text| SourcedDisplayText {
                id: Some(&field.id),
                text,
                path: format!("{path}.fields[id={}].display.label", field.id),
                source,
            })
    }));
    for derived in &entity.derived {
        labels.extend(derived.fields.iter().filter_map(|field| {
            field
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&field.id),
                    text,
                    path: format!(
                        "{path}.derived[id={}].fields[id={}].display.label",
                        derived.id, field.id
                    ),
                    source,
                })
        }));
    }
}

fn collect_extension_field_labels<'a>(
    extension: &'a EntityExtensionSource,
    path: &str,
    source: &'a str,
    labels: &mut Vec<SourcedDisplayText<'a>>,
) {
    labels.extend(extension.fields.iter().filter_map(|field| {
        field
            .display
            .label
            .as_deref()
            .map(|text| SourcedDisplayText {
                id: Some(&field.id),
                text,
                path: format!("{path}.fields[id={}].display.label", field.id),
                source: Some(source),
            })
    }));
    for derived in &extension.derived {
        labels.extend(derived.fields.iter().filter_map(|field| {
            field
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&field.id),
                    text,
                    path: format!(
                        "{path}.derived[id={}].fields[id={}].display.label",
                        derived.id, field.id
                    ),
                    source: Some(source),
                })
        }));
    }
}

fn collect_action_refusal_labels<'a>(
    actions: &'a [ActionSource],
    path: &str,
    source: Option<&'a str>,
    labels: &mut BTreeMap<&'a str, Vec<SourcedDisplayText<'a>>>,
) {
    for action in actions {
        let crate::contract::ActionPlanSource::Function { refusals, .. } = &action.plan else {
            continue;
        };
        labels
            .entry(&action.id)
            .or_default()
            .extend(
                refusals
                    .iter()
                    .enumerate()
                    .map(|(index, refusal)| SourcedDisplayText {
                        id: None,
                        text: &refusal.label,
                        path: format!("{path}[id={}].plan.refusals[{index}].label", action.id),
                        source,
                    }),
            );
    }
}

fn collect_projection_text<'a>(
    default_language: &str,
    id: Option<&'a str>,
    path: &str,
    text: &'a ManifestProjectionTextSource,
    source: Option<&'a str>,
    labels: &mut BTreeMap<String, Vec<SourcedDisplayText<'a>>>,
) {
    match text {
        ManifestProjectionTextSource::Plain(text) => {
            labels
                .entry(default_language.to_ascii_lowercase())
                .or_default()
                .push(SourcedDisplayText {
                    id,
                    text: text.as_str(),
                    path: path.to_owned(),
                    source,
                });
        }
        ManifestProjectionTextSource::Localized(values) => {
            for (language, text) in values {
                labels
                    .entry(language.as_str().to_ascii_lowercase())
                    .or_default()
                    .push(SourcedDisplayText {
                        id,
                        text: text.as_str(),
                        path: format!("{path}[language={}]", language.as_str()),
                        source,
                    });
            }
        }
    }
}

#[cfg(test)]
mod projection_text_tests {
    use super::*;

    #[test]
    fn compiler_groups_projection_language_tags_case_insensitively() {
        let plain: ManifestProjectionTextSource =
            serde_json::from_value(serde_json::json!("Café")).expect("plain display text");
        let localized: ManifestProjectionTextSource =
            serde_json::from_value(serde_json::json!({"en":"CAFE\u{301}"}))
                .expect("localized display text");
        let mut labels = BTreeMap::new();
        collect_projection_text(
            "EN",
            Some("first"),
            "manifestProjection.datasets[id=first].title",
            &plain,
            None,
            &mut labels,
        );
        collect_projection_text(
            "EN",
            Some("second"),
            "manifestProjection.datasets[id=second].title",
            &localized,
            None,
            &mut labels,
        );

        assert_eq!(labels.len(), 1);
        let entries = labels.get("en").expect("one normalized language scope");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1].path,
            "manifestProjection.datasets[id=second].title[language=en]"
        );
    }
}

#[derive(Default)]
struct MergedLocalIdNamespaces<'a> {
    fields: Vec<SourcedLocalId<'a>>,
    derived: Vec<SourcedLocalId<'a>>,
    constraints: Vec<SourcedLocalId<'a>>,
    indexes: Vec<SourcedLocalId<'a>>,
    profiles: Vec<SourcedLocalId<'a>>,
    selectors: Vec<SourcedLocalId<'a>>,
    timers: Vec<SourcedLocalId<'a>>,
    read_paths: Vec<SourcedLocalId<'a>>,
}

fn collect_entity_local_ids<'a>(
    entity: &'a EntitySource,
    path: &str,
    source: Option<&'a str>,
    namespaces: &mut MergedLocalIdNamespaces<'a>,
    hooks: &mut Vec<SourcedLocalId<'a>>,
) {
    namespaces
        .fields
        .extend(entity.fields.iter().map(|field| SourcedLocalId {
            id: field.id.clone(),
            path: format!("{path}.fields[id={}].id", field.id),
            source,
        }));
    for derived in &entity.derived {
        namespaces.derived.push(SourcedLocalId {
            id: derived.id.clone(),
            path: format!("{path}.derived[id={}].id", derived.id),
            source,
        });
        namespaces
            .fields
            .extend(derived.fields.iter().map(|field| SourcedLocalId {
                id: field.id.clone(),
                path: format!(
                    "{path}.derived[id={}].fields[id={}].id",
                    derived.id, field.id
                ),
                source,
            }));
    }
    namespaces
        .constraints
        .extend(
            entity
                .constraints
                .iter()
                .enumerate()
                .map(|(index, constraint)| {
                    let id = derived_constraint_id(constraint);
                    let path = if constraint.explicit_id().is_some() {
                        format!("{path}.constraints[id={id}].id")
                    } else {
                        format!("{path}.constraints[{index}]")
                    };
                    SourcedLocalId { id, path, source }
                }),
        );
    namespaces
        .indexes
        .extend(entity.indexes.iter().map(|index| SourcedLocalId {
            id: index.id.clone(),
            path: format!("{path}.indexes[id={}].id", index.id),
            source,
        }));
    namespaces
        .profiles
        .extend(entity.access_profiles.iter().map(|profile| SourcedLocalId {
            id: profile.id.clone(),
            path: format!("{path}.accessProfiles[id={}].id", profile.id),
            source,
        }));
    namespaces.selectors.extend(
        entity
            .selector_profiles
            .iter()
            .map(|selector| SourcedLocalId {
                id: selector.id.clone(),
                path: format!("{path}.selectorProfiles[id={}].id", selector.id),
                source,
            }),
    );
    namespaces
        .timers
        .extend(entity.timers.iter().map(|timer| SourcedLocalId {
            id: timer.id.clone(),
            path: format!("{path}.timers[id={}].id", timer.id),
            source,
        }));
    namespaces
        .read_paths
        .extend(entity.read_paths.iter().map(|read_path| SourcedLocalId {
            id: read_path.id.clone(),
            path: format!("{path}.readPaths[id={}].id", read_path.id),
            source,
        }));
    hooks.extend(entity.hooks.iter().map(|hook| SourcedLocalId {
        id: hook.id.clone(),
        path: format!("{path}.hooks[id={}].id", hook.id),
        source,
    }));
}

fn collect_extension_local_ids<'a>(
    extension: &'a EntityExtensionSource,
    path: &str,
    source: &'a str,
    namespaces: &mut MergedLocalIdNamespaces<'a>,
    hooks: &mut Vec<SourcedLocalId<'a>>,
) {
    namespaces
        .fields
        .extend(extension.fields.iter().map(|field| SourcedLocalId {
            id: field.id.clone(),
            path: format!("{path}.fields[id={}].id", field.id),
            source: Some(source),
        }));
    for derived in &extension.derived {
        namespaces.derived.push(SourcedLocalId {
            id: derived.id.clone(),
            path: format!("{path}.derived[id={}].id", derived.id),
            source: Some(source),
        });
        namespaces
            .fields
            .extend(derived.fields.iter().map(|field| SourcedLocalId {
                id: field.id.clone(),
                path: format!(
                    "{path}.derived[id={}].fields[id={}].id",
                    derived.id, field.id
                ),
                source: Some(source),
            }));
    }
    namespaces
        .constraints
        .extend(
            extension
                .constraints
                .iter()
                .enumerate()
                .map(|(index, constraint)| {
                    let id = derived_constraint_id(constraint);
                    let path = if constraint.explicit_id().is_some() {
                        format!("{path}.constraints[id={id}].id")
                    } else {
                        format!("{path}.constraints[{index}]")
                    };
                    SourcedLocalId {
                        id,
                        path,
                        source: Some(source),
                    }
                }),
        );
    namespaces
        .indexes
        .extend(extension.indexes.iter().map(|index| SourcedLocalId {
            id: index.id.clone(),
            path: format!("{path}.indexes[id={}].id", index.id),
            source: Some(source),
        }));
    namespaces.profiles.extend(
        extension
            .access_profiles
            .iter()
            .map(|profile| SourcedLocalId {
                id: profile.id.clone(),
                path: format!("{path}.accessProfiles[id={}].id", profile.id),
                source: Some(source),
            }),
    );
    namespaces
        .selectors
        .extend(
            extension
                .selector_profiles
                .iter()
                .map(|selector| SourcedLocalId {
                    id: selector.id.clone(),
                    path: format!("{path}.selectorProfiles[id={}].id", selector.id),
                    source: Some(source),
                }),
        );
    namespaces
        .timers
        .extend(extension.timers.iter().map(|timer| SourcedLocalId {
            id: timer.id.clone(),
            path: format!("{path}.timers[id={}].id", timer.id),
            source: Some(source),
        }));
    namespaces
        .read_paths
        .extend(extension.read_paths.iter().map(|read_path| SourcedLocalId {
            id: read_path.id.clone(),
            path: format!("{path}.readPaths[id={}].id", read_path.id),
            source: Some(source),
        }));
    hooks.extend(extension.hooks.iter().map(|hook| SourcedLocalId {
        id: hook.id.clone(),
        path: format!("{path}.hooks[id={}].id", hook.id),
        source: Some(source),
    }));
}

#[allow(clippy::too_many_lines)]
fn validate_cross_file_local_id_collisions(
    project: &RegistryProject,
    modules: &[RegistryModule],
    errors: &mut Vec<Diagnostic>,
) {
    let mut module_ids = project
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| SourcedLocalId {
            id: module.id.clone(),
            path: format!("project.modules[{index}].id"),
            source: None,
        })
        .collect::<Vec<_>>();
    let mut records = project
        .entities
        .iter()
        .map(|entity| SourcedLocalId {
            id: entity.id.clone(),
            path: format!("recordTypes[id={}].id", entity.id),
            source: None,
        })
        .collect::<Vec<_>>();
    let mut actions = project
        .actions
        .iter()
        .map(|action| SourcedLocalId {
            id: action.id.clone(),
            path: format!("actions[id={}].id", action.id),
            source: None,
        })
        .collect::<Vec<_>>();
    let mut functions = project
        .functions
        .iter()
        .map(|function| SourcedLocalId {
            id: function.id.clone(),
            path: format!("functions[id={}].id", function.id),
            source: None,
        })
        .collect::<Vec<_>>();
    let mut entities = BTreeMap::<&str, MergedLocalIdNamespaces<'_>>::new();
    let mut hooks = Vec::new();
    for entity in &project.entities {
        collect_entity_local_ids(
            entity,
            &format!("recordTypes[id={}]", entity.id),
            None,
            entities.entry(&entity.id).or_default(),
            &mut hooks,
        );
    }
    for (profile_index, profile) in project.access_profiles.iter().enumerate() {
        for grant in &profile.permissions.entities {
            entities
                .entry(&grant.entity)
                .or_default()
                .profiles
                .push(SourcedLocalId {
                    id: profile.id.clone(),
                    path: format!("accessProfiles[{profile_index}].id"),
                    source: None,
                });
        }
    }

    let mut ordered_modules = modules.iter().collect::<Vec<_>>();
    ordered_modules.sort_by(|left, right| left.id.cmp(&right.id));
    for module in ordered_modules {
        let source = module.id.as_str();
        module_ids.push(SourcedLocalId {
            id: module.id.clone(),
            path: format!("modules[id={}].id", module.id),
            source: Some(source),
        });
        records.extend(module.entities.iter().map(|entity| SourcedLocalId {
            id: entity.id.clone(),
            path: format!("modules[id={}].recordTypes[id={}].id", module.id, entity.id),
            source: Some(source),
        }));
        actions.extend(module.actions.iter().map(|action| SourcedLocalId {
            id: action.id.clone(),
            path: format!("modules[id={}].actions[id={}].id", module.id, action.id),
            source: Some(source),
        }));
        functions.extend(module.functions.iter().map(|function| SourcedLocalId {
            id: function.id.clone(),
            path: format!("modules[id={}].functions[id={}].id", module.id, function.id),
            source: Some(source),
        }));
        for entity in &module.entities {
            collect_entity_local_ids(
                entity,
                &format!("modules[id={}].recordTypes[id={}]", module.id, entity.id),
                Some(source),
                entities.entry(&entity.id).or_default(),
                &mut hooks,
            );
        }
        for extension in &module.extend_entities {
            collect_extension_local_ids(
                extension,
                &format!(
                    "modules[id={}].extendRecordTypes[recordType={}]",
                    module.id, extension.entity
                ),
                source,
                entities.entry(&extension.entity).or_default(),
                &mut hooks,
            );
        }
    }

    for (code, values) in [
        ("breg.module.id-collision", &module_ids),
        ("breg.record-type.id-collision", &records),
        ("breg.action.id-collision", &actions),
        ("breg.function.id-collision", &functions),
        ("breg.hook.id-collision", &hooks),
    ] {
        add_cross_file_collisions(code, values, errors);
    }
    for namespaces in entities.values() {
        for (code, values) in [
            ("breg.field.id-collision", &namespaces.fields),
            ("breg.derived.id-collision", &namespaces.derived),
            ("breg.constraint.id-collision", &namespaces.constraints),
            ("breg.index.id-collision", &namespaces.indexes),
            ("breg.access-profile.id-collision", &namespaces.profiles),
            ("breg.selector-profile.id-collision", &namespaces.selectors),
            ("breg.timer.id-collision", &namespaces.timers),
            ("breg.read-path.id-collision", &namespaces.read_paths),
        ] {
            add_cross_file_collisions(code, values, errors);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_cross_file_duplicate_display_labels(
    project: &RegistryProject,
    modules: &[RegistryModule],
    findings: &mut Vec<Diagnostic>,
) {
    let mut records = project
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&entity.id),
                    text,
                    path: format!("recordTypes[id={}].display.label", entity.id),
                    source: None,
                })
        })
        .collect::<Vec<_>>();
    let mut actions = project
        .actions
        .iter()
        .filter_map(|action| {
            action
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&action.id),
                    text,
                    path: format!("actions[id={}].display.label", action.id),
                    source: None,
                })
        })
        .collect::<Vec<_>>();
    let mut fields = BTreeMap::<&str, Vec<SourcedDisplayText<'_>>>::new();
    let mut profiles = BTreeMap::<&str, Vec<SourcedDisplayText<'_>>>::new();
    let mut hooks = BTreeMap::<&str, Vec<SourcedDisplayText<'_>>>::new();
    for profile in &project.access_profiles {
        if let Some(text) = profile.display.label.as_deref() {
            for grant in &profile.permissions.entities {
                profiles
                    .entry(&grant.entity)
                    .or_default()
                    .push(SourcedDisplayText {
                        id: Some(&profile.id),
                        text,
                        path: format!("accessProfiles[id={}].display.label", profile.id),
                        source: None,
                    });
            }
        }
    }
    let mut refusals = BTreeMap::new();
    collect_action_refusal_labels(&project.actions, "actions", None, &mut refusals);
    for entity in &project.entities {
        collect_profile_and_hook_labels(
            &entity.access_profiles,
            &entity.hooks,
            &format!("recordTypes[id={}]", entity.id),
            None,
            profiles.entry(&entity.id).or_default(),
            hooks.entry(&entity.id).or_default(),
        );
        collect_entity_field_labels(
            entity,
            &format!("recordTypes[id={}]", entity.id),
            None,
            fields.entry(&entity.id).or_default(),
        );
    }

    let mut ordered_modules = modules.iter().collect::<Vec<_>>();
    ordered_modules.sort_by(|left, right| left.id.cmp(&right.id));
    for module in ordered_modules {
        let source = module.id.as_str();
        records.extend(module.entities.iter().filter_map(|entity| {
            entity
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&entity.id),
                    text,
                    path: format!(
                        "modules[id={}].recordTypes[id={}].display.label",
                        module.id, entity.id
                    ),
                    source: Some(source),
                })
        }));
        actions.extend(module.actions.iter().filter_map(|action| {
            action
                .display
                .label
                .as_deref()
                .map(|text| SourcedDisplayText {
                    id: Some(&action.id),
                    text,
                    path: format!(
                        "modules[id={}].actions[id={}].display.label",
                        module.id, action.id
                    ),
                    source: Some(source),
                })
        }));
        collect_action_refusal_labels(
            &module.actions,
            &format!("modules[id={}].actions", module.id),
            Some(source),
            &mut refusals,
        );
        for entity in &module.entities {
            collect_profile_and_hook_labels(
                &entity.access_profiles,
                &entity.hooks,
                &format!("modules[id={}].recordTypes[id={}]", module.id, entity.id),
                Some(source),
                profiles.entry(&entity.id).or_default(),
                hooks.entry(&entity.id).or_default(),
            );
            collect_entity_field_labels(
                entity,
                &format!("modules[id={}].recordTypes[id={}]", module.id, entity.id),
                Some(source),
                fields.entry(&entity.id).or_default(),
            );
        }
        for extension in &module.extend_entities {
            collect_profile_and_hook_labels(
                &extension.access_profiles,
                &extension.hooks,
                &format!(
                    "modules[id={}].extendRecordTypes[recordType={}]",
                    module.id, extension.entity
                ),
                Some(source),
                profiles.entry(&extension.entity).or_default(),
                hooks.entry(&extension.entity).or_default(),
            );
            collect_extension_field_labels(
                extension,
                &format!(
                    "modules[id={}].extendRecordTypes[recordType={}]",
                    module.id, extension.entity
                ),
                source,
                fields.entry(&extension.entity).or_default(),
            );
        }
    }

    add_cross_file_duplicate_labels(
        "breg.record-type.duplicate-label",
        "record types",
        &records,
        findings,
    );
    add_cross_file_duplicate_labels("breg.action.duplicate-label", "actions", &actions, findings);
    for labels in refusals.values() {
        add_cross_file_duplicate_labels(
            "breg.action-refusal.duplicate-label",
            "action refusals",
            labels,
            findings,
        );
    }
    for labels in fields.values() {
        add_cross_file_duplicate_labels("breg.field.duplicate-label", "fields", labels, findings);
    }
    for labels in profiles.values() {
        add_cross_file_duplicate_labels(
            "breg.access-profile.duplicate-label",
            "access profiles",
            labels,
            findings,
        );
    }
    for labels in hooks.values() {
        add_cross_file_duplicate_labels(
            "breg.hook.duplicate-label",
            "record hooks",
            labels,
            findings,
        );
    }

    if let Some(recipients) = &project.recipients {
        let mut names = recipients
            .organizations
            .iter()
            .map(|item| SourcedDisplayText {
                id: Some(&item.id),
                text: &item.name,
                path: format!("recipients.organizations[id={}].name", item.id),
                source: None,
            })
            .collect::<Vec<_>>();
        names.extend(recipients.groups.iter().map(|item| SourcedDisplayText {
            id: Some(&item.id),
            text: &item.name,
            path: format!("recipients.groups[id={}].name", item.id),
            source: None,
        }));
        add_cross_file_duplicate_labels(
            "breg.recipient.duplicate-name",
            "recipients",
            &names,
            findings,
        );
    }

    if let Some(projection) = &project.manifest_projection {
        let default_language = &project.project.default_language;
        let mut datasets = BTreeMap::new();
        for item in &projection.datasets {
            collect_projection_text(
                default_language,
                Some(&item.id),
                &format!("manifestProjection.datasets[id={}].title", item.id),
                &item.title,
                None,
                &mut datasets,
            );
        }
        let mut data_services = BTreeMap::new();
        for item in &projection.data_services {
            collect_projection_text(
                default_language,
                Some(&item.id),
                &format!("manifestProjection.dataServices[id={}].title", item.id),
                &item.title,
                None,
                &mut data_services,
            );
        }
        let mut distributions = BTreeMap::new();
        for item in &projection.distributions {
            if let Some(title) = &item.title {
                collect_projection_text(
                    default_language,
                    Some(&item.id),
                    &format!("manifestProjection.distributions[id={}].title", item.id),
                    title,
                    None,
                    &mut distributions,
                );
            }
        }
        let mut entities = BTreeMap::new();
        for item in &projection.entities {
            if let Some(title) = &item.title {
                collect_projection_text(
                    default_language,
                    Some(&item.id),
                    &format!("manifestProjection.entities[id={}].title", item.id),
                    title,
                    None,
                    &mut entities,
                );
            }
        }
        for (code, kind, labels) in [
            (
                "breg.manifest-dataset.duplicate-title",
                "manifest datasets",
                &datasets,
            ),
            (
                "breg.manifest-data-service.duplicate-title",
                "manifest data services",
                &data_services,
            ),
            (
                "breg.manifest-distribution.duplicate-title",
                "manifest distributions",
                &distributions,
            ),
            (
                "breg.manifest-entity.duplicate-title",
                "manifest entities",
                &entities,
            ),
        ] {
            for labels in labels.values() {
                add_cross_file_duplicate_labels(code, kind, labels, findings);
            }
        }
        for vocabulary in &projection.vocabularies {
            let mut concepts = BTreeMap::new();
            for (index, concept) in vocabulary.concepts.iter().enumerate() {
                if let Some(label) = &concept.label {
                    collect_projection_text(
                        default_language,
                        None,
                        &format!(
                            "manifestProjection.vocabularies[id={}].concepts[{index}].label",
                            vocabulary.id
                        ),
                        label,
                        None,
                        &mut concepts,
                    );
                }
            }
            for labels in concepts.values() {
                add_cross_file_duplicate_labels(
                    "breg.manifest-vocabulary-concept.duplicate-label",
                    "manifest vocabulary concepts",
                    labels,
                    findings,
                );
            }
        }
    }
}

/// Reapply the authoring reader's display-text boundary to public source
/// values that a Rust caller can construct without deserializing them.
fn validate_authored_display_text(
    project: &RegistryProject,
    modules: &[RegistryModule],
    errors: &mut Vec<Diagnostic>,
) {
    validate_display_source(&project.project.display, "project.project.display", errors);
    for dataset in &project.datasets {
        validate_display_source(
            &dataset.display,
            &format!("datasets[id={}].display", dataset.id),
            errors,
        );
    }
    for authority in &project.review_authorities {
        validate_display_source(
            &authority.display,
            &format!("reviewAuthorities[id={}].display", authority.id),
            errors,
        );
    }
    for profile in &project.access_profiles {
        validate_presentation_source(
            &profile.display,
            &format!("accessProfiles[id={}].display", profile.id),
            errors,
        );
    }
    for dataset in &project.statistical_datasets {
        validate_presentation_source(
            &dataset.display,
            &format!("statisticalDatasets[id={}].display", dataset.id),
            errors,
        );
    }
    for entity in &project.entities {
        validate_entity_display_text(entity, &format!("recordTypes[id={}]", entity.id), errors);
    }
    for action in &project.actions {
        validate_action_display_text(action, &format!("actions[id={}]", action.id), errors);
    }

    for module in modules {
        for entity in &module.entities {
            validate_entity_display_text(
                entity,
                &format!("modules[id={}].recordTypes[id={}]", module.id, entity.id),
                errors,
            );
        }
        for (index, extension) in module.extend_entities.iter().enumerate() {
            let path = format!("modules[id={}].extendRecordTypes[{index}]", module.id);
            for field in &extension.fields {
                validate_display_source(
                    &field.display,
                    &format!("{path}.fields[id={}].display", field.id),
                    errors,
                );
            }
            for derived in &extension.derived {
                for field in &derived.fields {
                    validate_display_source(
                        &field.display,
                        &format!(
                            "{path}.derived[id={}].fields[id={}].display",
                            derived.id, field.id
                        ),
                        errors,
                    );
                }
            }
            for profile in &extension.access_profiles {
                validate_presentation_source(
                    &profile.display,
                    &format!("{path}.accessProfiles[id={}].display", profile.id),
                    errors,
                );
            }
            for hook in &extension.hooks {
                validate_presentation_source(
                    &hook.display,
                    &format!("{path}.hooks[id={}].display", hook.id),
                    errors,
                );
            }
        }
        for action in &module.actions {
            validate_action_display_text(
                action,
                &format!("modules[id={}].actions[id={}]", module.id, action.id),
                errors,
            );
        }
    }
}

fn validate_entity_display_text(entity: &EntitySource, path: &str, errors: &mut Vec<Diagnostic>) {
    validate_model_display(&entity.display, &format!("{path}.display"), errors);
    if entity.display.purpose == Some(DisplayPurpose::SyntheticSeed) {
        errors.push(Diagnostic::error(
            "breg.display.purpose-surface",
            format!("{path}.display.purpose"),
            "purpose \"synthetic-seed\" applies only to Actions",
        ));
    }
    for field in &entity.fields {
        validate_display_source(
            &field.display,
            &format!("{path}.fields[id={}].display", field.id),
            errors,
        );
    }
    for derived in &entity.derived {
        for field in &derived.fields {
            validate_display_source(
                &field.display,
                &format!(
                    "{path}.derived[id={}].fields[id={}].display",
                    derived.id, field.id
                ),
                errors,
            );
        }
    }
    for profile in &entity.access_profiles {
        validate_presentation_source(
            &profile.display,
            &format!("{path}.accessProfiles[id={}].display", profile.id),
            errors,
        );
    }
    for hook in &entity.hooks {
        validate_presentation_source(
            &hook.display,
            &format!("{path}.hooks[id={}].display", hook.id),
            errors,
        );
    }
}

fn validate_action_display_text(action: &ActionSource, path: &str, errors: &mut Vec<Diagnostic>) {
    validate_model_display(&action.display, &format!("{path}.display"), errors);
    for input in &action.inputs {
        validate_display_source(
            &input.display,
            &format!("{path}.inputs[id={}].display", input.id),
            errors,
        );
    }
    if let ActionExecutionSource::Proposal { proposal } = &action.execution {
        for hook in &proposal.hooks {
            validate_presentation_source(
                &hook.display,
                &format!("{path}.execution.proposal.hooks[id={}].display", hook.id),
                errors,
            );
        }
    }
}

fn validate_display_source(display: &DisplaySource, path: &str, errors: &mut Vec<Diagnostic>) {
    if let Some(label) = display.label.as_deref() {
        validate_display_text(label, &format!("{path}.label"), errors);
    }
    if let Some(description) = display.description.as_deref() {
        validate_display_text(description, &format!("{path}.description"), errors);
    }
}

fn validate_model_display(display: &ModelDisplaySource, path: &str, errors: &mut Vec<Diagnostic>) {
    validate_display_source(&display.display(), path, errors);
    if let Some(group) = display.group.as_deref() {
        validate_display_text(group, &format!("{path}.group"), errors);
    }
}

fn validate_presentation_source(
    display: &PresentationSource,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(label) = display.label.as_deref() {
        validate_display_text(label, &format!("{path}.label"), errors);
    }
    if let Some(description) = display.description.as_deref() {
        validate_display_text(description, &format!("{path}.description"), errors);
    }
}

pub(crate) fn validate_display_text_at(
    value: Option<&str>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(value) = value {
        validate_display_text(value, path, errors);
    }
}

fn validate_display_text(value: &str, path: &str, errors: &mut Vec<Diagnostic>) {
    if DisplayText::new(value).is_err() {
        errors.push(Diagnostic::error(
            "breg.display-text.invalid",
            path,
            "display text contains a character that cannot be shown safely",
        ));
    }
}

fn validate_project_header(
    project: &RegistryProject,
    profile: CompileProfile,
    errors: &mut Vec<Diagnostic>,
    findings: &mut Vec<Diagnostic>,
) {
    if project.api_version != AUTHORING_API_VERSION {
        errors.push(Diagnostic::error(
            "breg.project.api-version-unsupported",
            "project.apiVersion",
            "the project uses an unsupported API version",
        ));
    }
    if project.kind != AUTHORING_KIND {
        errors.push(Diagnostic::error(
            "breg.project.kind-unsupported",
            "project.kind",
            "the project uses an unsupported document kind",
        ));
    }
    validate_id(&project.project.id, "project.project.id", errors);
    nonempty(
        &project.project.version,
        "project.project.version",
        "breg.project.version-empty",
        errors,
    );
    validate_language(&project.project.default_language, errors);
    nonempty(
        &project.project.canonical_base_iri,
        "project.project.canonicalBaseIri",
        "breg.registry.canonical-base-iri-required",
        errors,
    );

    match (&project.package, profile) {
        (None, CompileProfile::Authoring) => findings.push(Diagnostic::finding(
            "breg.package.identity-missing",
            "project.package",
            &format!(
                "production package identity has not been declared; a production package requires {}",
                quoted_list(&PACKAGE_IDENTITY_KEYS)
            ),
        )),
        (None, CompileProfile::Production) => errors.push(Diagnostic::error(
            "breg.package.identity-required",
            "project.package",
            &format!(
                "production compilation requires package identity; declare {}",
                quoted_list(&PACKAGE_IDENTITY_KEYS)
            ),
        )),
        (Some(package), _) => {
            nonempty(
                &package.source_revision,
                "project.package.sourceRevision",
                "breg.package.source-revision-empty",
                errors,
            );
        }
    }

    match (&project.manifest_projection, profile) {
        (None, _) => {}
        (Some(projection), _) => {
            validate_id(
                &projection.access_profile,
                "project.manifestProjection.accessProfile",
                errors,
            );
            nonempty(
                &projection.catalog.base_url,
                "project.manifestProjection.catalog.baseUrl",
                "breg.manifest-projection.catalog-base-url-empty",
                errors,
            );
            validate_projection_text(
                &projection.catalog.title,
                "project.manifestProjection.catalog.title",
                errors,
            );
            nonempty(
                &projection.catalog.publisher.id,
                "project.manifestProjection.catalog.publisher.id",
                "breg.manifest-projection.catalog-publisher-id-empty",
                errors,
            );
            validate_id(
                &projection.catalog.publisher.id,
                "project.manifestProjection.catalog.publisher.id",
                errors,
            );
            nonempty(
                &projection.catalog.publisher.name,
                "project.manifestProjection.catalog.publisher.name",
                "breg.manifest-projection.catalog-publisher-name-empty",
                errors,
            );
            validate_display_text(
                &projection.catalog.publisher.name,
                "project.manifestProjection.catalog.publisher.name",
                errors,
            );
            if let Some(description) = projection.catalog.description.as_ref() {
                validate_projection_text(
                    description,
                    "project.manifestProjection.catalog.description",
                    errors,
                );
            }
            validate_id(
                &projection.public_service.id,
                "project.manifestProjection.publicService.id",
                errors,
            );
            validate_projection_text(
                &projection.public_service.title,
                "project.manifestProjection.publicService.title",
                errors,
            );
            if projection.datasets.is_empty() {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.datasets-empty",
                    "project.manifestProjection.datasets",
                    "manifestProjection.datasets must contain at least one dataset",
                ));
            }
            for (index, dataset) in projection.datasets.iter().enumerate() {
                let path = format!("project.manifestProjection.datasets[{index}]");
                validate_id(&dataset.id, &format!("{path}.id"), errors);
                validate_projection_text(&dataset.title, &format!("{path}.title"), errors);
                if let Some(description) = dataset.description.as_ref() {
                    validate_projection_text(description, &format!("{path}.description"), errors);
                }
                if dataset
                    .owner
                    .as_deref()
                    .is_some_and(|value| value.trim().is_empty())
                {
                    errors.push(Diagnostic::error(
                        "breg.manifest-projection.dataset-owner-empty",
                        format!("{path}.owner"),
                        "optional Registry Manifest projection text must not be empty",
                    ));
                }
                if let Some(owner) = dataset.owner.as_deref() {
                    validate_display_text(owner, &format!("{path}.owner"), errors);
                }
                if let Some(access_profile) = dataset.access_profile.as_deref() {
                    validate_id(access_profile, &format!("{path}.accessProfile"), errors);
                }
            }
            if projection.data_services.is_empty() {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.data-services-empty",
                    "project.manifestProjection.dataServices",
                    "manifestProjection.dataServices must contain at least one data service",
                ));
            }
            for (index, service) in projection.data_services.iter().enumerate() {
                let path = format!("project.manifestProjection.dataServices[{index}]");
                validate_id(&service.id, &format!("{path}.id"), errors);
                validate_projection_text(&service.title, &format!("{path}.title"), errors);
                if let Some(description) = service.description.as_ref() {
                    validate_projection_text(description, &format!("{path}.description"), errors);
                }
                nonempty(
                    &service.endpoint_url,
                    &format!("{path}.endpointUrl"),
                    "breg.manifest-projection.data-service-endpoint-url-empty",
                    errors,
                );
                if service.serves_datasets.is_empty() {
                    errors.push(Diagnostic::error(
                        "breg.manifest-projection.data-service-datasets-empty",
                        format!("{path}.servesDatasets"),
                        "a data service must serve at least one dataset",
                    ));
                }
            }
            for (index, distribution) in projection.distributions.iter().enumerate() {
                let path = format!("project.manifestProjection.distributions[{index}]");
                validate_id(&distribution.id, &format!("{path}.id"), errors);
                validate_id(&distribution.dataset, &format!("{path}.dataset"), errors);
                if let Some(title) = distribution.title.as_ref() {
                    validate_projection_text(title, &format!("{path}.title"), errors);
                }
                if let Some(description) = distribution.description.as_ref() {
                    validate_projection_text(description, &format!("{path}.description"), errors);
                }
            }
        }
    }

    let mut locks = BTreeSet::new();
    for lock in &project.modules {
        validate_id(&lock.id, "project.modules[].id", errors);
        if !locks.insert(lock.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.module.lock-duplicate",
                "project.modules[].id",
                "a module lock identifier is duplicated",
            ));
        }
        match (&lock.digest, profile) {
            (None, CompileProfile::Authoring) => findings.push(Diagnostic::finding(
                "breg.module.lock-digest-missing",
                "project.modules[].digest",
                "the authoring module lock has no production digest",
            )),
            (None, CompileProfile::Production) => errors.push(Diagnostic::error(
                "breg.module.lock-digest-required",
                "project.modules[].digest",
                "production compilation requires every module digest",
            )),
            (Some(digest), _) if !valid_sha256(digest) => errors.push(Diagnostic::error(
                "breg.module.lock-digest-invalid",
                "project.modules[].digest",
                "the module digest is not a canonical SHA-256 identifier",
            )),
            _ => {}
        }
    }
}

/// Refusals for project identity that a deployable package must not carry.
///
/// They are not part of [`compile_project`]: a freshly initialized project
/// carries a placeholder identity that local development and schema tests
/// run unchanged. Tooling applies them where it builds a package for
/// deployment or asserts production readiness.
pub fn deployment_diagnostics(project: &RegistryProject) -> Vec<Diagnostic> {
    let mut errors = Vec::new();
    if reserved_production_iri(&project.project.canonical_base_iri) {
        errors.push(Diagnostic::error(
            "breg.registry.canonical-base-iri-reserved",
            "project.project.canonicalBaseIri",
            "production canonicalBaseIri must not use the reserved .invalid namespace",
        ));
    }
    errors
}

fn reserved_production_iri(value: &str) -> bool {
    let Ok(iri) = url::Url::parse(value) else {
        return false;
    };
    let Some(host) = iri.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.');
    host == "invalid" || host.ends_with(".invalid")
}

fn validate_manifest_projection(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(projection) = project.manifest_projection.as_ref() else {
        return;
    };
    let mut dataset_ids = BTreeSet::new();
    for (index, dataset) in projection.datasets.iter().enumerate() {
        if !dataset_ids.insert(dataset.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.dataset-duplicate",
                format!("project.manifestProjection.datasets[{index}].id"),
                "a dataset identifier is duplicated",
            ));
        }
    }
    let datasets = projection
        .datasets
        .iter()
        .map(|dataset| (dataset.id.as_str(), dataset))
        .collect::<BTreeMap<_, _>>();

    let mut members = BTreeMap::<&str, BTreeSet<&str>>::new();
    for entity in entities.values() {
        let path = format!("project.recordTypes[{}].primaryDataset", entity.id);
        let Some(dataset_id) = entity.primary_dataset.as_deref() else {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.entity-primary-dataset-required",
                path,
                "every exposed entity must name one primaryDataset",
            ));
            continue;
        };
        if dataset_id.is_empty() {
            continue;
        }
        if !datasets.contains_key(dataset_id) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.entity-dataset-dangling",
                path,
                "entity primaryDataset must reference manifestProjection.datasets[]",
            ));
            continue;
        }
        members.entry(dataset_id).or_default().insert(&entity.id);
    }
    for (index, dataset) in projection.datasets.iter().enumerate() {
        if !members.contains_key(dataset.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.dataset-entities-empty",
                format!("project.manifestProjection.datasets[{index}]"),
                "every dataset must contain at least one exposed entity",
            ));
        }
        let effective_profile = dataset
            .access_profile
            .as_deref()
            .unwrap_or(&projection.access_profile);
        let selected_profiles = entities
            .values()
            .filter(|entity| entity.primary_dataset.as_deref() == Some(dataset.id.as_str()))
            .filter_map(|entity| entity.access_profiles.get(effective_profile))
            .collect::<Vec<_>>();
        if selected_profiles.is_empty() {
            let path = dataset.access_profile.as_ref().map_or_else(
                || "project.manifestProjection.accessProfile".to_owned(),
                |_| format!("project.manifestProjection.datasets[{index}].accessProfile"),
            );
            errors.push(Diagnostic::error(
                "breg.manifest-projection.dataset-access-profile-unknown",
                path,
                "the effective dataset access profile is not exposed by any member entity",
            ));
        }
    }

    let mut data_service_ids = BTreeSet::new();
    for (index, service) in projection.data_services.iter().enumerate() {
        if !data_service_ids.insert(service.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.data-service-duplicate",
                format!("project.manifestProjection.dataServices[{index}].id"),
                "a data service identifier is duplicated",
            ));
        }
        let mut served = BTreeSet::new();
        for (dataset_index, dataset_id) in service.serves_datasets.iter().enumerate() {
            let path = format!(
                "project.manifestProjection.dataServices[{index}].servesDatasets[{dataset_index}]"
            );
            if !served.insert(dataset_id.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.data-service-dataset-duplicate",
                    path,
                    "servesDatasets must not contain duplicate dataset references",
                ));
            } else if !datasets.contains_key(dataset_id.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.data-service-dataset-dangling",
                    path,
                    "servesDatasets must reference manifestProjection.datasets[]",
                ));
            }
        }
    }

    let mut distribution_ids = BTreeSet::new();
    for (index, distribution) in projection.distributions.iter().enumerate() {
        let path = format!("project.manifestProjection.distributions[{index}]");
        if !distribution_ids.insert(distribution.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.distribution-duplicate",
                format!("{path}.id"),
                "a distribution identifier is duplicated",
            ));
        }
        if !datasets.contains_key(distribution.dataset.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.distribution-dataset-dangling",
                format!("{path}.dataset"),
                "distribution dataset must reference manifestProjection.datasets[]",
            ));
        }
        if let Some(service_id) = distribution.access_service.as_deref() {
            let service = projection
                .data_services
                .iter()
                .find(|service| service.id == service_id);
            match service {
                None => errors.push(Diagnostic::error(
                    "breg.manifest-projection.distribution-access-service-dangling",
                    format!("{path}.accessService"),
                    "distribution accessService must reference manifestProjection.dataServices[]",
                )),
                Some(service)
                    if !service
                        .serves_datasets
                        .iter()
                        .any(|dataset| dataset == &distribution.dataset) =>
                {
                    errors.push(Diagnostic::error(
                        "breg.manifest-projection.distribution-service-coverage",
                        format!("{path}.accessService"),
                        "distribution accessService must serve the distribution dataset",
                    ));
                }
                _ => {}
            }
        }
        if distribution.access_service.is_none()
            && distribution.access_url.is_none()
            && distribution.download_url.is_none()
        {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.distribution-location-missing",
                path,
                "a distribution must declare accessService, accessUrl, or downloadUrl",
            ));
        }
    }

    let visible = entities
        .values()
        .filter_map(|entity| {
            let dataset = datasets.get(entity.primary_dataset.as_deref()?)?;
            let access_profile = dataset
                .access_profile
                .as_deref()
                .unwrap_or(&projection.access_profile);
            let ceiling = dataset
                .classification_ceiling
                .unwrap_or(projection.classification_ceiling);
            if entity.classification > ceiling {
                return None;
            }
            let profile = entity.access_profiles.get(access_profile)?;
            (profile.operations.contains(&Operation::Get)
                || profile.operations.contains(&Operation::List))
            .then(|| {
                let fields = entity
                    .fields
                    .values()
                    .filter(|field| profile.readable_fields.contains(&field.id))
                    .filter(|field| field.classification <= ceiling)
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
                "breg.manifest-projection.entity-duplicate",
                path,
                "Registry Manifest entity metadata must be unique",
            ));
            continue;
        }
        let Some((entity, visible_fields)) = visible.get(metadata.id.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.entity-not-visible",
                path,
                "Registry Manifest metadata may describe only an entity visible through the selected access profile",
            ));
            continue;
        };
        let dataset = datasets
            .get(
                entity
                    .primary_dataset
                    .as_deref()
                    .expect("projected entity has a dataset"),
            )
            .expect("projected entity dataset was validated");
        let access_profile = dataset
            .access_profile
            .as_deref()
            .unwrap_or(&projection.access_profile);
        let classification_ceiling = dataset
            .classification_ceiling
            .unwrap_or(projection.classification_ceiling);
        if let Some(title) = metadata.title.as_ref() {
            validate_projection_text(title, &format!("{path}.title"), errors);
        }
        if let Some(description) = metadata.description.as_ref() {
            validate_projection_text(description, &format!("{path}.description"), errors);
        }
        let mut identifier_fields = BTreeSet::new();
        for identifier in &metadata.identifiers {
            let identifier_path = format!("{path}.identifiers[field={}]", identifier.field);
            let field_is_projected = visible_fields
                .get(identifier.field.as_str())
                .is_some_and(|field| manifest_projects_field(field));
            if !identifier_fields.insert(identifier.field.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.identifier-duplicate",
                    identifier_path.clone(),
                    &format!(
                        "manifestProjection entity `{}` repeats the identifier for field `{}`",
                        metadata.id, identifier.field
                    ),
                ));
            }
            if !field_is_projected {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.identifier-field-not-visible",
                    identifier_path.clone(),
                    &format!(
                        "identifier field `{}` is not a portable field readable by access profile `{access_profile}` at classification ceiling `{}`",
                        identifier.field,
                        classification_name(classification_ceiling)
                    ),
                ));
            }
            if identifier.kind.trim().is_empty() {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.identifier-kind-missing",
                    identifier_path,
                    &format!(
                        "identifier field `{}` has no kind; every Registry Manifest identifier must declare one",
                        identifier.field
                    ),
                ));
            }
        }
        let mut field_ids = BTreeSet::new();
        for field_metadata in &metadata.fields {
            let field_path = format!("{path}.fields[id={}]", field_metadata.id);
            if !field_ids.insert(field_metadata.id.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.field-duplicate",
                    field_path,
                    "Registry Manifest field metadata must be unique within an entity",
                ));
                continue;
            }
            let Some(field) = visible_fields.get(field_metadata.id.as_str()) else {
                let rule = match entity.fields.get(field_metadata.id.as_str()) {
                    None => "does not exist on the Record type".to_owned(),
                    Some(field)
                        if !entity.access_profiles[access_profile]
                            .readable_fields
                            .contains(&field.id) =>
                    {
                        format!("is not readable by access profile `{access_profile}`")
                    }
                    Some(field) if field.classification > classification_ceiling => format!(
                        "is classified `{}`, above classification ceiling `{}`",
                        classification_name(field.classification),
                        classification_name(classification_ceiling)
                    ),
                    Some(_) => format!("is not visible through access profile `{access_profile}`"),
                };
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.field-not-visible",
                    field_path,
                    &format!(
                        "manifestProjection field `{}` {rule}; selected access profile `{access_profile}` may project only readable fields at or below its classification ceiling",
                        field_metadata.id
                    ),
                ));
                continue;
            };
            let is_reference = matches!(&field.field_type, FieldTypeSource::Reference { .. });
            if !is_reference && !manifest_projects_field(field) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.field-not-representable",
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
                    "breg.manifest-projection.field-metadata-kind",
                    field_path,
                    "Registry Manifest scalar and relationship metadata must match the configured field type",
                ));
            }
        }
    }

    // A vocabulary's describable codes are the union over every visible field
    // that uses it, so a field narrowed to fewer codes hides none of the codes
    // another visible field admits.
    let mut visible_vocabularies = BTreeMap::<&str, BTreeSet<&String>>::new();
    for field in visible
        .values()
        .flat_map(|(_entity, fields)| fields.values())
    {
        if let FieldTypeSource::VocabularyCode { vocabulary, values } = &field.field_type {
            visible_vocabularies
                .entry(vocabulary.as_str())
                .or_default()
                .extend(values);
        }
    }
    let projection_profiles = datasets
        .values()
        .map(|dataset| {
            dataset
                .access_profile
                .as_deref()
                .unwrap_or(&projection.access_profile)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    let mut vocabulary_ids = BTreeSet::new();
    for metadata in &projection.vocabularies {
        let path = format!("project.manifestProjection.vocabularies[{}]", metadata.id);
        if !vocabulary_ids.insert(metadata.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.vocabulary-duplicate",
                path,
                "Registry Manifest vocabulary metadata must be unique",
            ));
            continue;
        }
        let Some(values) = visible_vocabularies.get(metadata.id.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.manifest-projection.vocabulary-not-visible",
                path,
                &format!(
                    "vocabulary `{}` is not used by a field visible through selected access profile `{projection_profiles}`; project only vocabularies used by a readable field at or below its classification ceiling",
                    metadata.id
                ),
            ));
            continue;
        };
        let mut codes = BTreeSet::new();
        for concept in &metadata.concepts {
            if !codes.insert(concept.code.as_str()) || !values.contains(&concept.code) {
                errors.push(Diagnostic::error(
                    "breg.manifest-projection.vocabulary-concept-invalid",
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

fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::Public => "public",
        Classification::Internal => "internal",
        Classification::Restricted => "restricted",
    }
}

fn compile_manifest_projection(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Option<CompiledManifestProjection> {
    let projection = project.manifest_projection.as_ref()?;
    let canonical_base_iri = project.project.canonical_base_iri.clone();
    let entity_datasets = entities
        .values()
        .map(|entity| {
            (
                entity.id.clone(),
                entity
                    .primary_dataset
                    .clone()
                    .expect("compiled entity dataset membership was validated"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let datasets = projection
        .datasets
        .iter()
        .map(|source| {
            let members = entity_datasets
                .iter()
                .filter_map(|(entity, dataset)| (dataset == &source.id).then_some(entity.clone()))
                .collect();
            (
                source.id.clone(),
                CompiledManifestDataset {
                    iri: compiled_resource_iri(
                        &canonical_base_iri,
                        "datasets",
                        &source.id,
                        source.iri.as_deref(),
                    ),
                    source: source.clone(),
                    effective_access_profile: source
                        .access_profile
                        .clone()
                        .unwrap_or_else(|| projection.access_profile.clone()),
                    effective_classification_ceiling: source
                        .classification_ceiling
                        .unwrap_or(projection.classification_ceiling),
                    entities: members,
                },
            )
        })
        .collect();
    let data_services = projection
        .data_services
        .iter()
        .map(|source| {
            (
                source.id.clone(),
                CompiledManifestDataService {
                    iri: compiled_resource_iri(
                        &canonical_base_iri,
                        "data-services",
                        &source.id,
                        source.iri.as_deref(),
                    ),
                    source: source.clone(),
                    serves_datasets: source.serves_datasets.iter().cloned().collect(),
                },
            )
        })
        .collect();
    let distributions = projection
        .distributions
        .iter()
        .map(|source| {
            (
                source.id.clone(),
                CompiledManifestDistribution {
                    iri: compiled_resource_iri(
                        &canonical_base_iri,
                        "distributions",
                        &source.id,
                        source.iri.as_deref(),
                    ),
                    source: source.clone(),
                    dataset: source.dataset.clone(),
                    access_service: source.access_service.clone(),
                },
            )
        })
        .collect();
    Some(CompiledManifestProjection {
        canonical_base_iri: canonical_base_iri.clone(),
        access_profile: projection.access_profile.clone(),
        classification_ceiling: projection.classification_ceiling,
        catalog: projection.catalog.clone(),
        primary_authority: CompiledManifestAuthority {
            id: projection.catalog.publisher.id.clone(),
            iri: compiled_resource_iri(
                &canonical_base_iri,
                "authorities",
                &projection.catalog.publisher.id,
                projection.catalog.publisher.iri.as_deref(),
            ),
            name: projection.catalog.publisher.name.clone(),
            authority_type: projection.catalog.publisher.authority_type.clone(),
        },
        public_service: CompiledManifestPublicService {
            source: projection.public_service.clone(),
            iri: compiled_resource_iri(
                &canonical_base_iri,
                "public-services",
                &projection.public_service.id,
                None,
            ),
            competent_authority: projection.catalog.publisher.id.clone(),
            produces: projection
                .datasets
                .iter()
                .map(|dataset| dataset.id.clone())
                .collect(),
            data_services: projection
                .data_services
                .iter()
                .map(|service| service.id.clone())
                .collect(),
        },
        datasets,
        data_services,
        distributions,
        entity_datasets,
        entities: projection.entities.clone(),
        vocabularies: projection.vocabularies.clone(),
    })
}

fn compiled_resource_iri(
    canonical_base_iri: &str,
    collection: &str,
    id: &str,
    explicit: Option<&str>,
) -> String {
    explicit.map(str::to_owned).unwrap_or_else(|| {
        format!(
            "{}/{collection}/{id}",
            canonical_base_iri.trim_end_matches('/')
        )
    })
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
                "breg.module.id-duplicate",
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
                    "breg.module.dependency-duplicate",
                    "modules[].dependencies[]",
                    "a module dependency is duplicated",
                ));
            }
            if !module_map.contains_key(dependency) && !locked.contains(dependency.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.module.dependency-unknown",
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
            "breg.module.dependency-cycle",
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
                    "breg.module.source-missing",
                    "project.modules[].id",
                    "an authoring module lock has no loaded source",
                ),
                CompileProfile::Production => Diagnostic::error(
                    "breg.module.source-required",
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
                "breg.module.lock-version-mismatch",
                "project.modules[].version",
                "an authored module does not match its locked version",
            ));
        }
        let actual = module_digest_with_assets(module, assets);
        if let Some(expected) = &lock.digest {
            if expected != &actual {
                errors.push(Diagnostic::error(
                    "breg.module.lock-digest-mismatch",
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
                "breg.module.lock-missing",
                "modules[].id",
                "an authoring module source has no lock entry",
            ),
            CompileProfile::Production => Diagnostic::error(
                "breg.module.lock-missing",
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
    digest.update(b"breg-module-v2\0");
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
/// Which module contributed each hook, by `(entity id, hook id)`. A local
/// handler names a script or module path inside its contributing module, so
/// the delivery inventory resolves its bytes against the same asset namespace
/// an action handler resolves against.
type HookOriginMap = BTreeMap<(String, String), Option<String>>;
/// Exact authored path of each collected hook, including module extensions.
type HookPathMap = BTreeMap<(String, String), String>;
/// Which module contributed one id-keyed member of an entity, by
/// `(entity id, member id)`.
type EntityMemberOriginMap = BTreeMap<(String, String), Option<String>>;
/// Which module declared each entity, by entity id.
type EntityOriginMap = BTreeMap<String, Option<String>>;

/// Every origin map `collect_entities` and `apply_extensions` populate.
/// `None` means the project root contributed the id; `Some(module)` names
/// the contributing module. Folded into one struct so a declaring or
/// extending entity threads one argument instead of a map per collection;
/// `compile_entities` reads every field to attribute the module that
/// contributed each part of a compiled entity, while
/// `validate_derived_assets`, `validate_hook_assets`, `hook_handler_scripts`,
/// `compile_event_delivery_inventory` reads
/// only the one field their own asset or delivery resolution needs.
#[derive(Default)]
struct CollectedOrigins {
    entities: EntityOriginMap,
    fields: EntityMemberOriginMap,
    constraints: EntityMemberOriginMap,
    derived: DerivedOriginMap,
    indexes: EntityMemberOriginMap,
    access_profiles: EntityMemberOriginMap,
    selector_profiles: EntityMemberOriginMap,
    timers: EntityMemberOriginMap,
    read_paths: EntityMemberOriginMap,
    hooks: HookOriginMap,
    hook_paths: HookPathMap,
}

fn collect_entities(
    project: &RegistryProject,
    module_order: &[String],
    modules: &BTreeMap<String, RegistryModule>,
    errors: &mut Vec<Diagnostic>,
) -> CollectedEntities {
    let mut entities = BTreeMap::new();
    let mut origins = CollectedOrigins::default();
    let mut actions = BTreeMap::new();
    for entity in &project.entities {
        insert_entity(
            &mut entities,
            &mut origins,
            entity,
            None,
            "project.recordTypes[].id",
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
                    &mut origins,
                    entity,
                    Some(module.id.clone()),
                    "modules[].recordTypes[].id",
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
    (entities, origins, actions)
}

fn insert_entity(
    entities: &mut BTreeMap<String, EntitySource>,
    origins: &mut CollectedOrigins,
    entity: &EntitySource,
    module: Option<String>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if entities.insert(entity.id.clone(), entity.clone()).is_some() {
        errors.push(Diagnostic::error(
            "breg.record-type.id-duplicate",
            path,
            "a record type identifier is contributed more than once",
        ));
        return;
    }
    origins.entities.insert(entity.id.clone(), module.clone());
    for field in &entity.fields {
        origins
            .fields
            .insert((entity.id.clone(), field.id.clone()), module.clone());
    }
    for constraint in &entity.constraints {
        origins.constraints.insert(
            (entity.id.clone(), derived_constraint_id(constraint)),
            module.clone(),
        );
    }
    for derived in &entity.derived {
        origins
            .derived
            .insert((entity.id.clone(), derived.id.clone()), module.clone());
    }
    for index in &entity.indexes {
        origins
            .indexes
            .insert((entity.id.clone(), index.id.clone()), module.clone());
    }
    for access in &entity.access_profiles {
        origins
            .access_profiles
            .insert((entity.id.clone(), access.id.clone()), module.clone());
    }
    for selector in &entity.selector_profiles {
        origins
            .selector_profiles
            .insert((entity.id.clone(), selector.id.clone()), module.clone());
    }
    for timer in &entity.timers {
        origins
            .timers
            .insert((entity.id.clone(), timer.id.clone()), module.clone());
    }
    for read_path in &entity.read_paths {
        origins
            .read_paths
            .insert((entity.id.clone(), read_path.id.clone()), module.clone());
    }
    for hook in &entity.hooks {
        origins
            .hooks
            .insert((entity.id.clone(), hook.id.clone()), module.clone());
        let path = match module.as_deref() {
            Some(module) => format!(
                "modules[id={module}].recordTypes[id={}].hooks[id={}]",
                entity.id, hook.id
            ),
            None => format!("recordTypes[id={}].hooks[id={}]", entity.id, hook.id),
        };
        origins
            .hook_paths
            .insert((entity.id.clone(), hook.id.clone()), path);
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
            "breg.action.id-duplicate",
            path,
            "an action identifier is contributed more than once",
        ));
    }
}

fn apply_temporal_roles(
    entities: &mut BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for (entity_id, entity) in entities.iter_mut() {
        let Some(temporal) = &entity.temporal else {
            continue;
        };
        let path = format!("recordTypes[id={entity_id}].temporal");
        let Some(end) = temporal.closing_field().map(str::to_owned) else {
            errors.push(Diagnostic::error(
                "breg.temporal.end-conflict",
                path,
                "a temporal interval names exactly one of endField and lastDayField",
            ));
            continue;
        };
        let start = temporal.start_field.clone();
        if temporal.last_day_field.is_some() {
            let is_date = |id: &str| {
                entity.fields.iter().any(|field| {
                    field.id == id && matches!(field.field_type, FieldTypeSource::Date)
                })
            };
            if !is_date(&start) || !is_date(&end) {
                errors.push(Diagnostic::error(
                    "breg.temporal.last-day-type",
                    format!("{path}.lastDayField"),
                    "a last day closes a date interval: the start and the last day must both be date fields",
                ));
            }
        }
        for (id, role) in [
            (&start, ValidTimeRole::ValidFrom),
            (&end, ValidTimeRole::ValidTo),
        ] {
            let Some(field) = entity.fields.iter_mut().find(|field| &field.id == id) else {
                errors.push(Diagnostic::error(
                    "breg.temporal.field-unknown",
                    "recordTypes[].temporal",
                    "a temporal role refers to an unknown field",
                ));
                continue;
            };
            if field
                .valid_time_role
                .is_some_and(|existing| existing != role)
            {
                errors.push(Diagnostic::error(
                    "breg.temporal.role-conflict",
                    "recordTypes[].temporal",
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
    origins: &mut CollectedOrigins,
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
            let extension_path = format!(
                "modules[id={}].extendRecordTypes[recordType={}]",
                module.id, extension.entity
            );
            let Some(entity) = entities.get_mut(&extension.entity) else {
                errors.push(Diagnostic::error(
                    "breg.extension.record-type-unknown",
                    format!("{extension_path}.recordType"),
                    "an extension targets an unknown record type",
                ));
                continue;
            };
            let diagnostics_start = errors.len();
            merge_extension(entity, extension, Some(module.id.clone()), origins, errors);
            for diagnostic in &mut errors[diagnostics_start..] {
                diagnostic.path =
                    diagnostic
                        .path
                        .replacen("modules[].extendRecordTypes[]", &extension_path, 1);
            }
        }
    }
}

fn merge_extension(
    entity: &mut EntitySource,
    extension: &EntityExtensionSource,
    module: Option<String>,
    origins: &mut CollectedOrigins,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(geojson) = &extension.geojson {
        if let Some(existing) = &entity.geojson {
            if existing != geojson {
                errors.push(Diagnostic::error(
                    "breg.extension.geojson-conflict",
                    format!("recordTypes[id={}].geojson.geometryField", entity.id),
                    "an extension cannot change a record type GeoJSON geometry field",
                ));
            }
        } else {
            entity.geojson = Some(geojson.clone());
        }
    }
    if let Some(requirements) = &extension.access_requirements {
        if entity.access_requirements.is_some() {
            errors.push(Diagnostic::error(
                "breg.extension.access-requirements-replace-forbidden",
                format!("recordTypes[id={}].accessRequirements", entity.id),
                "an extension cannot replace existing access requirements; edit and review the owning record type declaration",
            ));
        } else {
            entity.access_requirements = Some(requirements.clone());
        }
    }
    let existing_fields = entity.fields.len();
    merge_by_id(
        &mut entity.fields,
        &extension.fields,
        |value| value.id.as_str(),
        "breg.extension.field-duplicate",
        "modules[].extendRecordTypes[].fields[].id",
        "a field identifier is contributed more than once",
        errors,
    );
    for field in entity.fields.iter().skip(existing_fields) {
        origins
            .fields
            .insert((entity.id.clone(), field.id.clone()), module.clone());
    }
    let existing_derived = entity.derived.len();
    merge_by_id(
        &mut entity.derived,
        &extension.derived,
        |value| value.id.as_str(),
        "breg.extension.derived-duplicate",
        "modules[].extendRecordTypes[].derived[].id",
        "a derived relation identifier is contributed more than once",
        errors,
    );
    for derived in entity.derived.iter().skip(existing_derived) {
        origins
            .derived
            .insert((entity.id.clone(), derived.id.clone()), module.clone());
    }
    let existing_indexes = entity.indexes.len();
    merge_by_id(
        &mut entity.indexes,
        &extension.indexes,
        |value| value.id.as_str(),
        "breg.extension.index-duplicate",
        "modules[].extendRecordTypes[].indexes[].id",
        "an index identifier is contributed more than once",
        errors,
    );
    for index in entity.indexes.iter().skip(existing_indexes) {
        origins
            .indexes
            .insert((entity.id.clone(), index.id.clone()), module.clone());
    }
    let existing_access_profiles = entity.access_profiles.len();
    merge_by_id(
        &mut entity.access_profiles,
        &extension.access_profiles,
        |value| value.id.as_str(),
        "breg.extension.access-profile-duplicate",
        "modules[].extendRecordTypes[].accessProfiles[].id",
        "an access profile identifier is contributed more than once",
        errors,
    );
    for access in entity.access_profiles.iter().skip(existing_access_profiles) {
        origins
            .access_profiles
            .insert((entity.id.clone(), access.id.clone()), module.clone());
    }
    let existing_hooks = entity.hooks.len();
    merge_by_id(
        &mut entity.hooks,
        &extension.hooks,
        |value| value.id.as_str(),
        "breg.extension.event-duplicate",
        "modules[].extendRecordTypes[].hooks[].id",
        "an event identifier is contributed more than once",
        errors,
    );
    for hook in entity.hooks.iter().skip(existing_hooks) {
        origins
            .hooks
            .insert((entity.id.clone(), hook.id.clone()), module.clone());
        let path = match module.as_deref() {
            Some(module) => format!(
                "modules[id={module}].extendRecordTypes[recordType={}].hooks[id={}]",
                entity.id, hook.id
            ),
            None => format!("recordTypes[id={}].hooks[id={}]", entity.id, hook.id),
        };
        origins
            .hook_paths
            .insert((entity.id.clone(), hook.id.clone()), path);
    }
    let existing_selector_profiles = entity.selector_profiles.len();
    merge_by_id(
        &mut entity.selector_profiles,
        &extension.selector_profiles,
        |value| value.id.as_str(),
        "breg.extension.selector-profile-duplicate",
        "modules[].extendRecordTypes[].selectorProfiles[].id",
        "a selector profile identifier is contributed more than once",
        errors,
    );
    for selector in entity
        .selector_profiles
        .iter()
        .skip(existing_selector_profiles)
    {
        origins
            .selector_profiles
            .insert((entity.id.clone(), selector.id.clone()), module.clone());
    }
    let existing_timers = entity.timers.len();
    merge_by_id(
        &mut entity.timers,
        &extension.timers,
        |value| value.id.as_str(),
        "breg.extension.timer-duplicate",
        "modules[].extendRecordTypes[].timers[].id",
        "a timer identifier is contributed more than once",
        errors,
    );
    for timer in entity.timers.iter().skip(existing_timers) {
        origins
            .timers
            .insert((entity.id.clone(), timer.id.clone()), module.clone());
    }
    let existing_read_paths = entity.read_paths.len();
    merge_by_id(
        &mut entity.read_paths,
        &extension.read_paths,
        |value| value.id.as_str(),
        "breg.extension.read-path-duplicate",
        "modules[].extendRecordTypes[].readPaths[].id",
        "a read path identifier is contributed more than once",
        errors,
    );
    for read_path in entity.read_paths.iter().skip(existing_read_paths) {
        origins
            .read_paths
            .insert((entity.id.clone(), read_path.id.clone()), module.clone());
    }
    merge_optional_capability(
        &mut entity.mutation_policy,
        &extension.mutation_policy,
        "breg.extension.mutation-policy-duplicate",
        "modules[].extendRecordTypes[].mutationPolicy",
        "a mutation policy is contributed more than once",
        errors,
    );
    let mut known: BTreeSet<String> = entity
        .constraints
        .iter()
        .map(derived_constraint_id)
        .collect();
    for constraint in &extension.constraints {
        let id = derived_constraint_id(constraint);
        if known.insert(id.clone()) {
            origins
                .constraints
                .insert((entity.id.clone(), id), module.clone());
            entity.constraints.push(constraint.clone());
        } else {
            errors.push(Diagnostic::error(
                "breg.extension.constraint-duplicate",
                "modules[].extendRecordTypes[].constraints[]",
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
            "breg.access-profile.project-record-type-local-forbidden",
            "project.recordTypes[].accessProfiles",
            "root project record types must declare access through top-level accessProfiles",
        ));
    }
}

/// A task grant is authored only in project `accessProfiles`, where
/// `expand_project_access` checks its ceiling and compiles its collection
/// bounds. Before that expansion, every entity profile was contributed by a
/// module (root project entities cannot declare local profiles), so a task
/// grant here would escape the standing-agent ceiling and meet no task-grant
/// ceiling.
fn validate_module_access_profile_task_grants(
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    for entity in entities.values() {
        for access in &entity.access_profiles {
            if access.task_grant.is_some() {
                errors.push(Diagnostic::error(
                    "breg.access-profile.task-grant-module-forbidden",
                    format!(
                        "recordTypes[id={}].accessProfiles[id={}].taskGrant",
                        entity.id, access.id
                    ),
                    "a module cannot contribute a task-grant profile; declare task grants in project accessProfiles",
                ));
            }
        }
    }
}

pub(crate) fn expand_project_access(
    project: &RegistryProject,
    entities: &mut BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut profile_ids = BTreeSet::new();
    for profile in &project.access_profiles {
        validate_id(&profile.id, "project.accessProfiles[].id", errors);
        reject_system_profile_id(&profile.id, "accessProfiles[].id", errors);
        if !profile_ids.insert(profile.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.access-profile.id-duplicate",
                "project.accessProfiles[].id",
                "an access profile identifier is duplicated",
            ));
        }
        if profile.principal_claim.is_empty() {
            errors.push(Diagnostic::error(
                "breg.access-profile.principal-claim-required",
                "project.accessProfiles[].principalClaim",
                "an authenticated profile requires a direct principal claim",
            ));
        }
        if profile.requester_clients.iter().any(|client| {
            client.is_empty()
                || client.len() > 512
                || client.chars().any(char::is_control)
                || client.chars().any(char::is_whitespace)
        }) {
            errors.push(Diagnostic::error(
                "breg.access-profile.requester-client-invalid",
                "project.accessProfiles[].requesterClients",
                "a requester client must be a bounded non-whitespace identifier",
            ));
        }
        if profile.actor_kind.is_some() == profile.requester_clients.is_empty() {
            errors.push(Diagnostic::error(
                "breg.access-profile.actor-client-binding-required",
                "project.accessProfiles[]",
                "actorKind and requesterClients must be declared together",
            ));
        }
        if profile.task_grant.is_some()
            && (profile.actor_kind != Some(crate::contract::ActorKindSource::Agent)
                || profile.requester_clients.is_empty()
                || profile.required_purposes.is_empty())
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.task-grant-binding-required",
                "project.accessProfiles[].taskGrant",
                "a task-grant profile must be authenticated, actorKind agent, and declare requesterClients and requiredPurposes",
            ));
        }
        // An immediate action commits its effects at once, with no draft for
        // a human to confirm, so a standing agent holds none. Action grants
        // are authored only here: a module contributes entity profiles, which
        // cannot grant `invoke` at all.
        if profile.actor_kind == Some(crate::contract::ActorKindSource::Agent)
            && profile.task_grant.is_none()
        {
            let path = if profile
                .permissions
                .actions
                .iter()
                .any(|permission| permission.operations.contains(&Operation::Invoke))
            {
                Some("project.accessProfiles[].permissions.actions[]")
            } else if profile
                .permissions
                .entities
                .iter()
                .any(|permission| permission.operations.contains(&Operation::Invoke))
            {
                Some("project.accessProfiles[].permissions.records[]")
            } else {
                None
            };
            if let Some(path) = path {
                errors.push(Diagnostic::error(
                    "breg.access-profile.standing-agent-action-forbidden",
                    path,
                    "a standing agent profile without a taskGrant cannot invoke an immediate action; a human confirms every change it proposes",
                ));
            }
        }
        if let Some(task_grant) = &profile.task_grant {
            if !task_grant.source_issuer.starts_with("https://")
                || task_grant.source_issuer.chars().any(char::is_whitespace)
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.task-grant-invalid",
                    "project.accessProfiles[].taskGrant",
                    "taskGrant must declare an absolute sourceIssuer URI",
                ));
            }
            if profile.permissions.entities.iter().any(|permission| {
                permission
                    .operations
                    .iter()
                    .any(|operation| is_direct_target_mutation(*operation))
            }) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.task-grant-direct-mutation-forbidden",
                    "accessProfiles[].permissions.records[].operations",
                    "a task-grant profile must use a named Action or Proposal; direct Record mutations, imports, batches, and tombstones are forbidden",
                ));
            }
        }
        let compiled_task_grant = profile.task_grant.as_ref().map(|task_grant| {
            let permissions = profile
                .permissions
                .entities
                .iter()
                .filter_map(|permission| {
                    entities.get(&permission.entity).map(|entity| {
                        crate::contract::CompiledTaskGrantPermissionSource {
                            collection: entity.route.clone(),
                            operations: permission.operations.clone(),
                        }
                    })
                })
                .collect();
            crate::contract::CompiledTaskGrantSource {
                source_issuer: task_grant.source_issuer.clone(),
                permissions,
            }
        });
        let mut granted_entities = BTreeSet::new();
        for grant in &profile.permissions.entities {
            if !granted_entities.insert(grant.entity.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.permission-duplicate",
                    "project.accessProfiles[].permissions.records[].recordType",
                    "an access profile contains duplicate record type permissions",
                ));
                continue;
            }
            let Some(entity) = entities.get_mut(&grant.entity) else {
                errors.push(Diagnostic::error(
                    "breg.access-profile.permission-record-type-unknown",
                    "project.accessProfiles[].permissions.records[].recordType",
                    "an access permission refers to an unknown record type",
                ));
                continue;
            };
            if entity
                .access_profiles
                .iter()
                .any(|existing| existing.id == profile.id)
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.id-duplicate",
                    "project.accessProfiles[].id",
                    "an access profile identifier is duplicated for a record type",
                ));
                continue;
            }
            entity.access_profiles.push(AccessProfileSource {
                id: profile.id.clone(),
                display: profile.display.clone(),
                default: profile.default,
                actor_kind: profile.actor_kind,
                requester_clients: profile.requester_clients.clone(),
                task_grant: compiled_task_grant.clone(),
                principal_claim: profile.principal_claim.clone(),
                required_scopes: profile.required_scopes.clone(),
                required_purposes: profile.required_purposes.clone(),
                operations: grant.operations.clone(),
                readable_fields: grant.readable_fields.clone(),
                writable_fields: grant.writable_fields.clone(),
                filterable_fields: grant.filterable_fields.clone(),
                sortable_fields: grant.sortable_fields.clone(),
                spatial_queries: grant.spatial_queries.clone(),
                row_boundaries: grant.row_boundaries.clone(),
                membership_boundaries: grant.membership_boundaries.clone(),
                require_consent: grant.require_consent.clone(),
                lookups: grant.lookups.clone(),
                read_paths: grant.read_paths.clone(),
                allow_count: grant.allow_count,
                revision_access: grant.revision_access,
                provenance_fields: grant.provenance_fields.clone(),
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
) -> BTreeMap<String, Vec<String>> {
    let mut vocabularies = BTreeMap::new();
    for vocabulary in &project.vocabularies {
        validate_id(&vocabulary.id, "project.vocabularies[].id", errors);
        if crate::consent::is_reserved_vocabulary(&vocabulary.id) {
            errors.push(Diagnostic::error(
                "breg.consent.vocabulary-reserved",
                "project.vocabularies[].id",
                "registry-recipients and registry-consent-scopes are synthesized from recipients and gated profiles and cannot be declared",
            ));
            continue;
        }
        if vocabulary.values.is_empty()
            || has_duplicates(&vocabulary.values)
            || vocabulary.values.iter().any(|value| !valid_code(value))
        {
            errors.push(Diagnostic::error(
                "breg.vocabulary.values-invalid",
                "project.vocabularies[].values",
                "a vocabulary must contain a non-empty duplicate-free value set",
            ));
        }
        if vocabularies
            .insert(vocabulary.id.clone(), vocabulary.values.clone())
            .is_some()
        {
            errors.push(Diagnostic::error(
                "breg.vocabulary.id-duplicate",
                "project.vocabularies[].id",
                "a vocabulary identifier is duplicated",
            ));
        }
    }
    for (id, values) in crate::consent::synthesized_vocabularies(project, entities) {
        vocabularies.insert(id.to_owned(), values);
    }
    // The scope vocabulary lists the profiles that require consent, so until
    // one does, a consent record's scope has nothing to resolve to.
    let unused_consent = crate::consent::unused_record_message(entities);
    for entity in entities.values_mut() {
        for field in &mut entity.fields {
            let diagnostics_start = errors.len();
            if let FieldTypeSource::VocabularyCode { vocabulary, values } = &mut field.field_type {
                if !values.is_empty() && crate::consent::is_reserved_vocabulary(vocabulary) {
                    errors.push(Diagnostic::error(
                        "breg.consent.vocabulary-reserved",
                        "recordTypes[].fields[].values",
                        "a field bound to a synthesized consent vocabulary takes its values from the compiler",
                    ));
                }
                if values.is_empty() {
                    if let Some(resolved) = vocabularies.get(vocabulary) {
                        *values = resolved.clone();
                    } else if vocabulary == crate::consent::SCOPES_VOCABULARY {
                        errors.push(Diagnostic::error(
                            "breg.consent.require-unused",
                            "recordTypes[].fields[].vocabulary",
                            &unused_consent,
                        ));
                    } else {
                        errors.push(Diagnostic::error(
                            "breg.field.vocabulary-unknown",
                            "recordTypes[].fields[].vocabulary",
                            "a field refers to an unknown vocabulary",
                        ));
                    }
                }
            }
            for diagnostic in &mut errors[diagnostics_start..] {
                diagnostic.path = diagnostic
                    .path
                    .replacen(
                        "recordTypes[]",
                        &format!("recordTypes[id={}]", entity.id),
                        1,
                    )
                    .replacen("fields[]", &format!("fields[id={}]", field.id), 1);
            }
        }
    }
    for action in actions.values_mut() {
        for input in &mut action.source.inputs {
            let diagnostics_start = errors.len();
            if let FieldTypeSource::VocabularyCode { vocabulary, values } = &mut input.field_type {
                if values.is_empty() {
                    if let Some(resolved) = vocabularies.get(vocabulary) {
                        *values = resolved.clone();
                    } else if vocabulary == crate::consent::SCOPES_VOCABULARY {
                        errors.push(Diagnostic::error(
                            "breg.consent.require-unused",
                            "actions[].inputs[].vocabulary",
                            &unused_consent,
                        ));
                    } else {
                        errors.push(Diagnostic::error(
                            "breg.action.input-vocabulary-unknown",
                            "actions[].inputs[].vocabulary",
                            "an action input refers to an unknown vocabulary",
                        ));
                    }
                }
            }
            for diagnostic in &mut errors[diagnostics_start..] {
                diagnostic.path = diagnostic
                    .path
                    .replacen("actions[]", &format!("actions[id={}]", action.source.id), 1)
                    .replacen("inputs[]", &format!("inputs[id={}]", input.id), 1);
            }
        }
    }
    vocabularies
}

fn validate_entities(
    registry_id: &str,
    entities: &BTreeMap<String, EntitySource>,
    hook_paths: &HookPathMap,
    profile: CompileProfile,
    errors: &mut Vec<Diagnostic>,
) {
    let mut routes = BTreeSet::new();
    let mut sql_names = BTreeSet::new();
    let mut event_ids = BTreeSet::new();
    for entity in entities.values() {
        let diagnostics_start = errors.len();
        validate_id(&entity.id, "recordTypes[].id", errors);
        if !sql_names.insert(canonical_sql_name(&entity.id)) {
            errors.push(Diagnostic::error(
                "breg.record-type.sql-name-duplicate",
                "recordTypes[].id",
                "record type SQL names must be unique after PostgreSQL canonicalization",
            ));
        }
        nonempty(
            &entity.primary_dataset,
            "recordTypes[].primaryDataset",
            "breg.manifest-projection.entity-primary-dataset-required",
            errors,
        );
        validate_id(&entity.route, "recordTypes[].route", errors);
        if !routes.insert(entity.route.as_str()) {
            errors.push(Diagnostic::error(
                "breg.record-type.route-duplicate",
                "recordTypes[].route",
                "a record type route is duplicated",
            ));
        }
        if entity.mutation_mode == MutationMode::CreateOnly && entity.tombstone {
            errors.push(Diagnostic::error(
                "breg.record-type.tombstone-create-only",
                "recordTypes[].tombstone",
                "a create-only record type cannot expose tombstone behavior",
            ));
        }
        let grants_batch = entity
            .access_profiles
            .iter()
            .any(|profile| profile.operations.contains(&Operation::Batch));
        match entity.batch.as_ref() {
            None if grants_batch => errors.push(Diagnostic::error(
                "breg.record-type.batch-required",
                format!("recordTypes[id={}].batch", entity.id),
                &format!("declare batch maximumItems from 1 to {MAX_BATCH_ITEMS} and maximumBytes from 1 to {MAX_BATCH_BYTES} for this record type's batch access"),
            )),
            Some(batch)
                if batch.maximum_items == 0
                    || batch.maximum_items > MAX_BATCH_ITEMS
                    || batch.maximum_bytes == 0
                    || batch.maximum_bytes > MAX_BATCH_BYTES =>
            {
                errors.push(Diagnostic::error(
                    "breg.record-type.batch-bounds-invalid",
                    format!("recordTypes[id={}].batch", entity.id),
                    &format!("batch maximumItems must be from 1 to {MAX_BATCH_ITEMS} and maximumBytes from 1 to {MAX_BATCH_BYTES}"),
                ));
            }
            _ => {}
        }
        validate_entity_fields(entity, entities, errors);
        validate_access_log(entity, entities, errors);
        validate_geojson(entity, errors);
        validate_derived(entity, errors);
        validate_logical_names(entity, errors);
        validate_constraints(entity, errors);
        validate_indexes(entity, errors);
        validate_selector_profiles(entity, errors);
        validate_read_paths(entity, entities, errors);
        validate_profiles(entity, entities, errors);
        validate_hooks(
            registry_id,
            entity,
            hook_paths,
            profile,
            &mut event_ids,
            errors,
        );
        for diagnostic in &mut errors[diagnostics_start..] {
            diagnostic.path = diagnostic.path.replacen(
                "recordTypes[]",
                &format!("recordTypes[id={}]", entity.id),
                1,
            );
        }
    }
    validate_read_path_cycles(entities, errors);
}

fn validate_access_log(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(access_log) = &entity.access_log else {
        return;
    };
    let path = format!("recordTypes[id={}].accessLog", entity.id);
    let fields = stored_field_map(entity);
    match fields.get(access_log.subject_field.as_str()) {
        Some(field)
            if field.required
                && !field.encrypted
                && matches!(
                    field.field_type,
                    FieldTypeSource::String { max_length, .. }
                        | FieldTypeSource::Text { max_length }
                        if max_length <= MAX_ACCESS_LOG_SUBJECT_CHARACTERS
                ) => {}
        _ => errors.push(Diagnostic::error(
            "breg.access-log.subject-field-invalid",
            format!("{path}.subjectField"),
            &format!(
                "subjectField must name a required plaintext stored string or text field with maximumLength at most {MAX_ACCESS_LOG_SUBJECT_CHARACTERS}"
            ),
        )),
    }
    if !(1..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&access_log.retention_days) {
        errors.push(Diagnostic::error(
            "breg.access-log.retention-days-invalid",
            format!("{path}.retentionDays"),
            &format!("retentionDays must be between 1 and {MAX_ACCESS_LOG_RETENTION_DAYS}"),
        ));
    }
    if access_log.trusted_intermediaries.len() > MAX_ACCESS_LOG_TRUSTED_INTERMEDIARIES {
        errors.push(Diagnostic::error(
            "breg.access-log.trusted-intermediaries-too-many",
            format!("{path}.trustedIntermediaries"),
            &format!(
                "an access log may trust at most {MAX_ACCESS_LOG_TRUSTED_INTERMEDIARIES} intermediary clients"
            ),
        ));
    }
    if access_log.trusted_intermediaries.iter().any(|client| {
        client.is_empty()
            || client.len() > 512
            || client.chars().any(char::is_control)
            || client.chars().any(char::is_whitespace)
    }) {
        errors.push(Diagnostic::error(
            "breg.access-log.trusted-intermediary-invalid",
            format!("{path}.trustedIntermediaries"),
            "a trusted intermediary must be a bounded non-whitespace verified client identifier",
        ));
    }
    if access_log.exemptions.len() > MAX_ACCESS_LOG_EXEMPTIONS {
        errors.push(Diagnostic::error(
            "breg.access-log.exemptions-too-many",
            format!("{path}.exemptions"),
            &format!("an access log may declare at most {MAX_ACCESS_LOG_EXEMPTIONS} exemptions"),
        ));
    }
    for (profile_id, exemption) in &access_log.exemptions {
        validate_id(profile_id, &format!("{path}.exemptions"), errors);
        let source_entity_id = exemption.source_entity.as_deref().unwrap_or(&entity.id);
        if exemption.source_entity.is_some() {
            validate_id(
                source_entity_id,
                &format!("{path}.exemptions[{profile_id}].sourceRecordType"),
                errors,
            );
        }
        let valid_profile = entities.get(source_entity_id).is_some_and(|source_entity| {
            source_entity
                .access_profiles
                .iter()
                .find(|profile| profile.id == *profile_id)
                .is_some_and(|profile| {
                    if source_entity_id == entity.id {
                        profile_has_direct_logged_read(profile)
                    } else {
                        profile_has_read_path_to(source_entity, profile, &entity.id)
                    }
                })
        });
        if !valid_profile {
            errors.push(Diagnostic::error(
                "breg.access-log.exemption-profile-invalid",
                format!("{path}.exemptions[{profile_id}]"),
                "an access-log exemption must name a profile on sourceRecordType that directly reads the logged record type or has a declared read path to it",
            ));
        }
        if exemption.reason.is_empty()
            || exemption.reason != exemption.reason.trim()
            || exemption.reason.len() > MAX_ACCESS_LOG_EXEMPTION_REASON_BYTES
            || exemption.reason.chars().any(char::is_control)
            || DisplayText::new(exemption.reason.as_str()).is_err()
        {
            errors.push(Diagnostic::error(
                "breg.access-log.exemption-reason-invalid",
                format!("{path}.exemptions[{profile_id}].reason"),
                &format!(
                    "an access-log exemption reason must be trimmed display text of at most {MAX_ACCESS_LOG_EXEMPTION_REASON_BYTES} UTF-8 bytes"
                ),
            ));
        }
        if exemption.delay_days == 0 || exemption.delay_days >= access_log.retention_days {
            errors.push(Diagnostic::error(
                "breg.access-log.exemption-delay-invalid",
                format!("{path}.exemptions[{profile_id}].delayDays"),
                "delayDays must be at least 1 and less than retentionDays",
            ));
        }
    }
}

fn profile_has_direct_logged_read(profile: &AccessProfileSource) -> bool {
    profile.operations.iter().any(|operation| {
        matches!(
            operation,
            Operation::Get
                | Operation::Lookup
                | Operation::List
                | Operation::Revisions
                | Operation::Snapshot
        )
    })
}

fn profile_has_read_path_to(
    source_entity: &EntitySource,
    profile: &AccessProfileSource,
    target_entity_id: &str,
) -> bool {
    profile.read_paths.iter().any(|grant| {
        source_entity
            .read_paths
            .iter()
            .any(|path| path.id == grant.path && path.to == target_entity_id)
    })
}

fn validate_geojson(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let Some(GeoJsonSource { geometry_field }) = &entity.geojson else {
        return;
    };
    let fields = stored_field_map(entity);
    let Some(field) = fields.get(geometry_field.as_str()) else {
        errors.push(Diagnostic::error(
            "breg.geojson.geometry-field-unknown",
            "recordTypes[].geojson.geometryField",
            "a GeoJSON geometry field must name one stored CRS84 point field",
        ));
        return;
    };
    if !matches!(field.field_type, FieldTypeSource::Crs84Point { .. }) {
        errors.push(Diagnostic::error(
            "breg.geojson.geometry-field-type-unsupported",
            "recordTypes[].geojson.geometryField",
            "a GeoJSON geometry field must name one stored CRS84 point field",
        ));
    }
}

fn validate_entity_fields(
    entity: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    errors: &mut Vec<Diagnostic>,
) {
    if entity.fields.iter().filter(|field| field.encrypted).count()
        > crate::contract::MAX_ENCRYPTED_FIELDS_PER_ENTITY
    {
        errors.push(Diagnostic::error(
            "breg.record-type.encrypted-fields-too-many",
            format!("recordTypes[{}].fields", entity.id),
            &format!(
                "a record type may declare at most {} encrypted fields so every valid Phase 1 plaintext snapshot has bounded envelope expansion",
                crate::contract::MAX_ENCRYPTED_FIELDS_PER_ENTITY
            ),
        ));
    }
    let mut fields = BTreeSet::new();
    let mut roles = BTreeMap::new();
    for field in &entity.fields {
        validate_id(&field.id, "recordTypes[].fields[].id", errors);
        if reserved_logical_name(&field.id) {
            errors.push(Diagnostic::error(
                "breg.field.id-reserved",
                "recordTypes[].fields[].id",
                "a field identifier collides with a reserved Registry field",
            ));
        }
        if !fields.insert(field.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.field.id-duplicate",
                "recordTypes[].fields[].id",
                "a field identifier is duplicated",
            ));
        }
        if let Some(pattern) = &field.pattern {
            let path = format!("recordTypes[{}].fields[{}].pattern", entity.id, field.id);
            if !matches!(
                field.field_type,
                FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
            ) {
                errors.push(Diagnostic::error(
                    "breg.field.pattern-type-unsupported",
                    &path,
                    "pattern requires a persisted string or text field",
                ));
            } else if !native_pattern_within_bounds(pattern) {
                errors.push(Diagnostic::error("breg.field.pattern-bounds-invalid", &path,
                    "PostgreSQL pattern must be at most 4096 UTF-8 bytes and contain no NUL; syntax is validated by PostgreSQL schema-test"));
            }
        }
        if field.encrypted {
            let path = format!("recordTypes[{}].fields[{}].encrypted", entity.id, field.id);
            if field.pattern.is_some() {
                errors.push(Diagnostic::error(
                    "breg.field.encrypted-pattern-refused",
                    format!("recordTypes[{}].fields[{}].pattern", entity.id, field.id),
                    "an encrypted field cannot declare pattern in Phase 1; remove pattern or store the field as plaintext",
                ));
            }
            if field.classification != Classification::Restricted {
                errors.push(Diagnostic::error(
                    "breg.field.encrypted-classification-invalid",
                    &path,
                    "an encrypted field must carry the restricted classification",
                ));
            }
            if !matches!(
                field.field_type,
                FieldTypeSource::String { .. }
                    | FieldTypeSource::Text { .. }
                    | FieldTypeSource::Date
                    | FieldTypeSource::Decimal { .. }
                    | FieldTypeSource::Structured { .. }
            ) {
                errors.push(Diagnostic::error(
                    "breg.field.encrypted-type-unsupported",
                    &path,
                    "an encrypted field must use a persisted string, text, date, decimal, or structured type",
                ));
            }
            match &field.field_type {
                FieldTypeSource::String { max_length, .. }
                | FieldTypeSource::Text { max_length }
                    if *max_length > MAX_ENCRYPTED_FIELD_STRING_CHARACTERS =>
                {
                    errors.push(Diagnostic::error(
                        "breg.field.encrypted-size-bound-exceeds-seal-limit",
                        format!("recordTypes[{}].fields[{}].maximumLength", entity.id, field.id),
                        &format!(
                            "an encrypted string or text field maximumLength must be at most {MAX_ENCRYPTED_FIELD_STRING_CHARACTERS} characters so every valid UTF-8 value fits the {MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES}-byte Phase 1 seal limit"
                        ),
                    ));
                }
                FieldTypeSource::Structured { max_bytes, .. }
                    if *max_bytes > MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES =>
                {
                    errors.push(Diagnostic::error(
                        "breg.field.encrypted-size-bound-exceeds-seal-limit",
                        format!("recordTypes[{}].fields[{}].maximumBytes", entity.id, field.id),
                        &format!(
                            "an encrypted structured field maximumBytes must be at most {MAX_ENCRYPTED_FIELD_PLAINTEXT_BYTES} bytes to fit the Phase 1 seal limit"
                        ),
                    ));
                }
                _ => {}
            }
            if let Some(lookup) = &field.lookup {
                let lookup_path = format!("recordTypes[{}].fields[{}].lookup", entity.id, field.id);
                if matches!(field.field_type, FieldTypeSource::Structured { .. }) {
                    errors.push(Diagnostic::error(
                        "breg.field.encrypted-lookup-type-unsupported",
                        &lookup_path,
                        "a structured encrypted field cannot declare lookup in Phase 1; remove lookup or use an encrypted string field for exact-match lookup",
                    ));
                }
                if lookup.normalization.len() > MAX_FIELD_LOOKUP_NORMALIZATION_STEPS {
                    errors.push(Diagnostic::error(
                        "breg.field.encrypted-lookup-normalization-too-long",
                        format!("{lookup_path}.normalization"),
                        &format!(
                            "an encrypted field lookup may declare at most {MAX_FIELD_LOOKUP_NORMALIZATION_STEPS} normalization steps"
                        ),
                    ));
                }
            }
            if field.valid_time_role.is_some() {
                errors.push(Diagnostic::error(
                    "breg.field.encrypted-valid-time-refused",
                    "recordTypes[].fields[].validTimeRole",
                    "an encrypted field cannot carry a valid-time role",
                ));
            }
        }
        validate_generated_identifier(entity, field, errors);
        match &field.field_type {
            FieldTypeSource::String {
                min_length,
                max_length,
            } if *max_length == 0 || *max_length > 1_000_000 || min_length > max_length => errors
                .push(Diagnostic::error(
                    "breg.field.string-bounds-invalid",
                    "recordTypes[].fields[]",
                    "string length bounds are invalid",
                )),
            FieldTypeSource::Text { max_length }
                if *max_length == 0 || *max_length > 10_000_000 =>
            {
                errors.push(Diagnostic::error(
                    "breg.field.text-bound-invalid",
                    "recordTypes[].fields[].maximumLength",
                    "text length bound must be positive",
                ));
            }
            FieldTypeSource::VocabularyCode { values, .. }
                if values.is_empty()
                    || has_duplicates(values)
                    || values.iter().any(|value| !valid_code(value)) =>
            {
                errors.push(Diagnostic::error(
                    "breg.field.vocabulary-values-invalid",
                    "recordTypes[].fields[].values",
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
                    "breg.field.decimal-bounds-invalid",
                    format!("recordTypes[id={}].fields[id={}]", entity.id, field.id),
                    DECIMAL_BOUNDS_REQUIREMENTS,
                ));
            }
            FieldTypeSource::Reference { target, .. } if !entities.contains_key(target) => {
                errors.push(Diagnostic::error(
                    "breg.field.reference-target-unknown",
                    "recordTypes[].fields[].target",
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
                    "breg.field.crs84-point-bounds-invalid",
                    "recordTypes[].fields[]",
                    "CRS84 point precision or CRS84 bounding box is invalid",
                ));
            }
            FieldTypeSource::Structured { max_bytes, schema }
                if *max_bytes == 0
                    || *max_bytes > MAX_STRUCTURED_VALUE_BYTES
                    || !valid_structured_schema(schema) =>
            {
                errors.push(Diagnostic::error(
                    "breg.field.structured-schema-invalid",
                    "recordTypes[].fields[]",
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
                    "breg.field.valid-time-type-invalid",
                    "recordTypes[].fields[].validTimeRole",
                    "a valid-time role requires a date or timestamp field",
                ));
            }
            if roles.insert(role, &field.field_type).is_some() {
                errors.push(Diagnostic::error(
                    "breg.field.valid-time-role-duplicate",
                    "recordTypes[].fields[].validTimeRole",
                    "a valid-time role is declared more than once",
                ));
            }
            if role == ValidTimeRole::ValidFrom && !field.required {
                errors.push(Diagnostic::error(
                    "breg.field.valid-time-start-required",
                    format!("recordTypes[].fields[id={}].required", field.id),
                    "a valid-time start field must be required",
                ));
            }
            if role == ValidTimeRole::ValidTo && field.required {
                errors.push(Diagnostic::error(
                    "breg.field.valid-time-end-must-allow-open",
                    "recordTypes[].fields[].required",
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
                "breg.field.valid-time-type-mismatch",
                "recordTypes[].fields[].validTimeRole",
                "valid-time boundary fields must use the same type",
            ));
        }
    }
}

fn validate_generated_identifier(
    entity: &EntitySource,
    field: &FieldSource,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(generate) = &field.generate else {
        return;
    };
    let path = format!(
        "recordTypes[id={}].fields[id={}].generate",
        entity.id, field.id
    );
    let FieldTypeSource::String {
        min_length,
        max_length,
    } = &field.field_type
    else {
        errors.push(Diagnostic::error(
            "breg.field.generate-type-unsupported",
            &path,
            "generate is supported only on a persisted string field",
        ));
        return;
    };
    if field.encrypted
        || field.lookup.is_some()
        || field.pattern.is_some()
        || field.valid_time_role.is_some()
        || field.relationship.is_some()
    {
        errors.push(Diagnostic::error(
            "breg.field.generate-options-incompatible",
            &path,
            "a generated identifier cannot be encrypted, looked up through a blind index, pattern-constrained, a valid-time boundary, or a relationship",
        ));
    }
    // The migration seed copies retained values into the append-only
    // reservation ledger, which keeps them after record erasure.
    if field.classification > Classification::Internal {
        errors.push(Diagnostic::error(
            "breg.field.generate-classification-sensitive",
            &path,
            "a generated identifier must be classified public or internal, because the reservation ledger keeps issued and migrated values after record erasure",
        ));
    }

    let prefix = generate.prefix();
    if prefix.len() > MAX_GENERATED_IDENTIFIER_COMPONENT_LENGTH as usize
        || prefix.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        errors.push(Diagnostic::error(
            "breg.field.generate-prefix-invalid",
            format!("{path}.prefix"),
            &format!(
                "a generated identifier prefix must contain at most {MAX_GENERATED_IDENTIFIER_COMPONENT_LENGTH} printable ASCII characters and no whitespace"
            ),
        ));
    }

    let (minimum_output_length, maximum_output_length) = match generate {
        FieldGenerationSource::Sequence { minimum_digits, .. } => {
            let minimum = prefix.len().saturating_add(*minimum_digits as usize);
            let maximum = prefix
                .len()
                .saturating_add((*minimum_digits as usize).max(19));
            (minimum, maximum)
        }
        FieldGenerationSource::Random { length, .. } => {
            let exact = prefix.len().saturating_add(*length as usize);
            (exact, exact)
        }
    };
    if minimum_output_length < *min_length as usize || maximum_output_length > *max_length as usize
    {
        let message = match generate {
            FieldGenerationSource::Sequence { .. } => format!(
                "a sequence identifier is the prefix plus max(minimumDigits, 19) digits, because the sequence is not capped at minimumDigits and must fit the longest i64 value; this field needs minimumLength at most {minimum_output_length} and maximumLength at least {maximum_output_length}"
            ),
            FieldGenerationSource::Random { .. } => format!(
                "a random identifier is the prefix plus length, exactly {maximum_output_length} characters here; this field needs minimumLength at most {minimum_output_length} and maximumLength at least {maximum_output_length}"
            ),
        };
        errors.push(Diagnostic::error(
            "breg.field.generate-length-outside-field",
            &path,
            &message,
        ));
    }

    if generate
        .scope()
        .is_some_and(|scope| scope.len() > MAX_GENERATED_IDENTIFIER_SCOPE_FIELDS)
    {
        errors.push(Diagnostic::error(
            "breg.field.generate-scope-too-large",
            format!("{path}.scope"),
            &format!(
                "a generated identifier may name at most {MAX_GENERATED_IDENTIFIER_SCOPE_FIELDS} scope fields"
            ),
        ));
    }
    // Both the reservation key and the Record's scoped unique constraint use
    // B-tree indexes. Migration also retains existing identifier values, which
    // can be longer and non-ASCII even when newly generated values are short.
    // Budget every indexed field's worst-case UTF-8 size before PostgreSQL.
    const MAX_INDEXED_BYTES: u64 = 1024;
    let fields = stored_field_map(entity);
    let mut maximum_indexed_bytes = u64::from(*max_length) * 4;
    for scope_field_id in generate.scope().into_iter().flatten() {
        let scope_path = format!("{path}.scope[field={scope_field_id}]");
        let Some(scope_field) = fields.get(scope_field_id.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.field.generate-scope-field-unknown",
                scope_path,
                "a generated identifier scope refers to an unknown stored field",
            ));
            continue;
        };
        if !scope_field.required {
            errors.push(Diagnostic::error(
                "breg.field.generate-scope-field-optional",
                &scope_path,
                "a generated identifier scope field must be required",
            ));
        }
        if scope_field.generate.is_some() || scope_field.encrypted {
            errors.push(Diagnostic::error(
                "breg.field.generate-scope-field-managed",
                &scope_path,
                "a generated identifier scope field cannot itself be generated or encrypted",
            ));
        }
        // The append-only reservation ledger keeps scope values after record
        // erasure, so a scope must not carry restricted data or point at a
        // person.
        if scope_field.classification > Classification::Internal
            || matches!(scope_field.field_type, FieldTypeSource::Reference { .. })
        {
            errors.push(Diagnostic::error(
                "breg.field.generate-scope-field-sensitive",
                &scope_path,
                "a generated identifier scope field must be classified public or internal and cannot be a reference, because the reservation ledger keeps scope values after record erasure; scope by a non-personal field such as a jurisdiction or category code",
            ));
        }
        match generated_identifier_scope_max_bytes(&scope_field.field_type) {
            Some(bytes) => maximum_indexed_bytes = maximum_indexed_bytes.saturating_add(bytes),
            None => errors.push(Diagnostic::error(
                "breg.field.generate-scope-type-unsupported",
                &scope_path,
                "a generated identifier scope field must use a stored scalar type",
            )),
        }
    }
    if maximum_indexed_bytes > MAX_INDEXED_BYTES {
        errors.push(Diagnostic::error(
            "breg.field.generate-index-key-too-large",
            &path,
            "the generated field and its scope fields exceed the combined 1024-byte index budget; lower their maximumLength or use shorter scope fields",
        ));
    }
}

fn generated_identifier_scope_max_bytes(field_type: &FieldTypeSource) -> Option<u64> {
    match field_type {
        FieldTypeSource::String { max_length, .. } | FieldTypeSource::Text { max_length } => {
            Some(u64::from(*max_length) * 4)
        }
        FieldTypeSource::VocabularyCode { values, .. } => Some(
            values
                .iter()
                .map(|value| value.len() as u64)
                .max()
                .unwrap_or(0),
        ),
        FieldTypeSource::Boolean => Some(5),
        FieldTypeSource::Int64 => Some(20),
        FieldTypeSource::Decimal { .. } | FieldTypeSource::Timestamp => Some(64),
        FieldTypeSource::Date => Some(10),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => Some(36),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => None,
    }
}

fn validate_derived(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let stored = stored_field_map(entity);
    let mut ids = BTreeSet::new();
    let mut field_ids = BTreeSet::new();
    field_ids.extend(entity.fields.iter().map(|field| field.id.clone()));
    for derived in &entity.derived {
        validate_id(&derived.id, "recordTypes[].derived[].id", errors);
        if !ids.insert(derived.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.derived.id-duplicate",
                "recordTypes[].derived[].id",
                "a derived relation identifier is duplicated",
            ));
        }
        if !valid_relative_sql_path(&derived.sql) {
            errors.push(Diagnostic::error(
                "breg.derived.sql-path-invalid",
                "recordTypes[].derived[].sql",
                "derived SQL must be a module-relative .sql path",
            ));
        }
        if derived.key != "id" || stored.contains_key(derived.key.as_str()) {
            errors.push(Diagnostic::error(
                "breg.derived.key-invalid",
                "recordTypes[].derived[].key",
                "derived SQL must declare the canonical id key",
            ));
        }
        if derived.execution != DerivedExecutionSource::Live {
            errors.push(Diagnostic::error(
                "breg.derived.execution-unsupported",
                "recordTypes[].derived[].execution",
                "derived SQL currently supports only live execution",
            ));
        }
        if derived.fields.is_empty() {
            errors.push(Diagnostic::error(
                "breg.derived.fields-empty",
                "recordTypes[].derived[].fields",
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
    validate_id(&field.id, "recordTypes[].derived[].fields[].id", errors);
    if reserved_logical_name(&field.id) {
        errors.push(Diagnostic::error(
            "breg.field.id-reserved",
            "recordTypes[].derived[].fields[].id",
            "a field identifier collides with a reserved Registry field",
        ));
    }
    if !field_ids.insert(field.id.clone()) {
        errors.push(Diagnostic::error(
            "breg.field.id-duplicate",
            "recordTypes[].derived[].fields[].id",
            "a stored or derived field identifier is duplicated",
        ));
    }
    validate_field_type_bounds(
        &field.field_type,
        "recordTypes[].derived[].fields[]",
        errors,
    );
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
                "breg.field.api-name-invalid",
                "recordTypes[].fields[].apiName",
                "a field API name must be a non-reserved lower camelCase identifier",
            ));
        }
        if !api_names.insert(api_name) {
            errors.push(Diagnostic::error(
                "breg.field.api-name-duplicate",
                "recordTypes[].fields[].apiName",
                "field API names must be unique within a record type",
            ));
        }
        let sql_name = canonical_sql_name(field.0);
        if reserved_logical_name(&sql_name) || !sql_names.insert(sql_name) {
            errors.push(Diagnostic::error(
                "breg.field.sql-name-duplicate",
                "recordTypes[].fields[].id",
                "field SQL names must be non-reserved and unique within a record type",
            ));
        }
    }
}

/// Whether a native PostgreSQL pattern fits the authored bounds shared by Record
/// fields and Action inputs. Syntax is PostgreSQL's to judge, not the compiler's.
pub(crate) fn native_pattern_within_bounds(pattern: &str) -> bool {
    pattern.len() <= 4096 && !pattern.contains('\0')
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
                "breg.field.string-bounds-invalid",
                path,
                "string length bounds are invalid",
            ))
        }
        FieldTypeSource::Text { max_length } if *max_length == 0 || *max_length > 10_000_000 => {
            errors.push(Diagnostic::error(
                "breg.field.text-bound-invalid",
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
                "breg.field.vocabulary-values-invalid",
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
                "breg.field.decimal-bounds-invalid",
                path,
                DECIMAL_BOUNDS_REQUIREMENTS,
            ));
        }
        FieldTypeSource::Crs84Point { precision, bbox }
            if *precision > 9
                || bbox
                    .as_ref()
                    .is_some_and(|bbox| parsed_bbox(bbox, *precision).is_none()) =>
        {
            errors.push(Diagnostic::error(
                "breg.field.crs84-point-bounds-invalid",
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
                "breg.field.structured-schema-invalid",
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
        let constraint_path = format!("recordTypes[id={}].constraints[id={id}]", entity.id);
        if !ids.insert(id) {
            errors.push(Diagnostic::error(
                "breg.constraint.id-duplicate",
                "recordTypes[].constraints[]",
                "a constraint identifier is duplicated",
            ));
        }
        let referenced = match constraint {
            ConstraintSource::Unique { fields, .. } => fields
                .iter()
                .map(|field| ("fields", field.as_str()))
                .collect::<Vec<_>>(),
            ConstraintSource::Compare { left, right, .. } => {
                vec![("left", left.as_str()), ("right", right.as_str())]
            }
            ConstraintSource::IntRange { field, .. }
            | ConstraintSource::Vocabulary { field, .. } => vec![("field", field.as_str())],
            ConstraintSource::TemporalNonOverlap {
                scope_fields,
                start_field,
                end_field,
                last_day_field,
                ..
            } => scope_fields
                .iter()
                .map(|field| ("scopeFields", field.as_str()))
                .chain(
                    start_field
                        .iter()
                        .map(|field| ("startField", field.as_str())),
                )
                .chain(end_field.iter().map(|field| ("endField", field.as_str())))
                .chain(
                    last_day_field
                        .iter()
                        .map(|field| ("lastDayField", field.as_str())),
                )
                .collect(),
        };
        if referenced.is_empty() {
            let member = match constraint {
                ConstraintSource::TemporalNonOverlap { .. } => "scopeFields",
                _ => "fields",
            };
            errors.push(Diagnostic::error(
                "breg.constraint.field-unknown",
                format!("{constraint_path}.{member}"),
                "a constraint must name at least one field",
            ));
            continue;
        }
        let mut unresolved = false;
        for (member, field) in &referenced {
            if !fields.contains_key(*field) {
                errors.push(Diagnostic::error(
                    "breg.constraint.field-unknown",
                    format!("{constraint_path}.{member}[field={field}]"),
                    "a constraint refers to an unknown field",
                ));
                unresolved = true;
            }
        }
        if unresolved {
            continue;
        }
        if referenced.iter().any(|(_, field)| fields[*field].encrypted) {
            errors.push(Diagnostic::error(
                "breg.constraint.field-encrypted",
                "recordTypes[].constraints[]",
                "an encrypted field cannot take part in a storage constraint; declare blind-index uniqueness with the field lookup instead",
            ));
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
                        "breg.constraint.compare-type-mismatch",
                        "recordTypes[].constraints[]",
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
                        "breg.constraint.range-invalid",
                        "recordTypes[].constraints[]",
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
                        "breg.constraint.vocabulary-invalid",
                        "recordTypes[].constraints[]",
                        "a vocabulary constraint is incompatible or has invalid values",
                    ));
                }
            }
            ConstraintSource::TemporalNonOverlap {
                start_field,
                end_field,
                last_day_field,
                scope_fields,
                ..
            } => {
                let interval_has_last_day = entity
                    .temporal
                    .as_ref()
                    .is_some_and(|temporal| temporal.last_day_field.is_some());
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
                    || last_day_field
                        .as_ref()
                        .is_some_and(|id| to.is_none_or(|field| &field.id != id))
                    || (end_field.is_some() && interval_has_last_day)
                    || (last_day_field.is_some() && !interval_has_last_day)
                {
                    errors.push(Diagnostic::error(
                        "breg.constraint.temporal-roles-invalid",
                        "recordTypes[].constraints[]",
                        "a temporal constraint requires matching valid-time boundary fields",
                    ));
                }
                if scope_fields.iter().any(|field| {
                    fields
                        .get(field.as_str())
                        .is_some_and(|field| !field.required)
                }) {
                    errors.push(Diagnostic::error(
                        "breg.constraint.temporal-scope-nullable",
                        "recordTypes[].constraints[].scopeFields",
                        "a temporal non-overlap scope field must be required",
                    ));
                }
                if scope_fields.iter().any(|field| {
                    fields.get(field.as_str()).is_some_and(|field| {
                        !supports_temporal_non_overlap_scope(&field.field_type)
                    })
                }) {
                    errors.push(Diagnostic::error(
                        "breg.constraint.temporal-scope-type-unsupported",
                        "recordTypes[].constraints[].scopeFields",
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
                "breg.constraint.fields-duplicate",
                "recordTypes[].constraints[]",
                "a constraint field tuple must be non-empty and duplicate-free",
            ));
        }
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

/// PostgreSQL allows 32 key columns in an index, and an authored index ends
/// with the record identifier.
const MAX_AUTHORED_INDEX_FIELDS: usize = 31;

fn validate_indexes(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let fields: BTreeMap<&str, &FieldSource> = entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect();
    let mut ids = BTreeSet::new();
    for index in &entity.indexes {
        let index_path = format!("recordTypes[id={}].indexes[id={}]", entity.id, index.id);
        validate_id(&index.id, "recordTypes[].indexes[].id", errors);
        if !ids.insert(index.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.index.id-duplicate",
                "recordTypes[].indexes[].id",
                "an index identifier is duplicated",
            ));
        }
        if index.fields.is_empty()
            || has_duplicates(&index.fields)
            || index
                .fields
                .iter()
                .any(|field| !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "breg.index.fields-invalid",
                format!("{index_path}.fields"),
                "an index has an empty, duplicate, or unresolved field set",
            ));
        }
        if index.fields.len() > MAX_AUTHORED_INDEX_FIELDS {
            errors.push(Diagnostic::error(
                "breg.index.fields-too-many",
                format!("{index_path}.fields"),
                &format!(
                    "an index may declare at most {MAX_AUTHORED_INDEX_FIELDS} fields; the record identifier takes the last of the 32 key columns PostgreSQL allows in an index"
                ),
            ));
        }
        if index.fields.iter().any(|field| {
            fields
                .get(field.as_str())
                .is_some_and(|field| field.encrypted)
        }) {
            errors.push(Diagnostic::error(
                "breg.index.fields-encrypted",
                format!("{index_path}.fields"),
                "an encrypted field cannot back an authored index; declare blind-index lookup on the field instead",
            ));
        }
    }
}

fn validate_selector_profiles(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let fields = stored_field_map(entity);
    let mut ids = BTreeSet::new();
    for selector in &entity.selector_profiles {
        validate_id(&selector.id, "recordTypes[].selectorProfiles[].id", errors);
        if !ids.insert(selector.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.selector-profile.id-duplicate",
                "recordTypes[].selectorProfiles[].id",
                "a selector profile identifier is duplicated",
            ));
        }
        let mut refused = false;
        if selector.fields.is_empty() || selector.fields.len() > 16 {
            errors.push(Diagnostic::error(
                "breg.selector-profile.fields-invalid",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "selector profile `{}` names {} fields; a selector profile must name one to sixteen stored fields",
                    selector.id,
                    selector.fields.len()
                ),
            ));
            refused = true;
        }
        let duplicates = duplicate_members(&selector.fields);
        if !duplicates.is_empty() {
            errors.push(Diagnostic::error(
                "breg.selector-profile.fields-duplicate",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "selector profile `{}` repeats {}; name each stored field once",
                    selector.id,
                    quoted_list(&duplicates)
                ),
            ));
            refused = true;
        }
        let unknown: Vec<&str> = selector
            .fields
            .iter()
            .map(String::as_str)
            .filter(|field| !fields.contains_key(field))
            .collect();
        if !unknown.is_empty() {
            errors.push(Diagnostic::error(
                "breg.selector-profile.fields-unknown",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "selector profile `{}` names {}, which record type `{}` does not store; a selector profile may name only stored fields",
                    selector.id,
                    quoted_list(&unknown),
                    entity.id
                ),
            ));
            refused = true;
        }
        if refused {
            continue;
        }
        let spatial: Vec<&str> = selector
            .fields
            .iter()
            .map(String::as_str)
            .filter(|field| {
                fields.get(field).is_some_and(|field| {
                    matches!(field.field_type, FieldTypeSource::Crs84Point { .. })
                })
            })
            .collect();
        let unsupported: Vec<&str> = selector
            .fields
            .iter()
            .map(String::as_str)
            .filter(|field| {
                fields
                    .get(field)
                    .is_some_and(|field| !selector_field_supported(&field.field_type))
            })
            .collect();
        if !spatial.is_empty() {
            errors.push(Diagnostic::error(
                "breg.selector-profile.field-type-unsupported",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "CRS84 point fields cannot be selector fields; {} must leave selector profile `{}`, use spatialQueries.bbox for bounded spatial search",
                    quoted_list(&spatial),
                    selector.id
                ),
            ));
        } else if !unsupported.is_empty() {
            errors.push(Diagnostic::error(
                "breg.selector-profile.field-type-unsupported",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "selector profile fields must use supported scalar stored types; {} in selector profile `{}` does not qualify",
                    quoted_list(&unsupported),
                    selector.id
                ),
            ));
        }
        // An encrypted field can serve direct record lookup only through its
        // declared blind index; without one there is nothing to select on.
        let without_lookup: Vec<&str> = selector
            .fields
            .iter()
            .map(String::as_str)
            .filter(|field| {
                fields
                    .get(field)
                    .is_some_and(|field| field.encrypted && field.lookup.is_none())
            })
            .collect();
        if !without_lookup.is_empty() {
            errors.push(Diagnostic::error(
                "breg.selector-profile.encrypted-lookup-required",
                "recordTypes[].selectorProfiles[].fields",
                &format!(
                    "an encrypted selector field requires a declared lookup; {} in selector profile `{}` declares none",
                    quoted_list(&without_lookup),
                    selector.id
                ),
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
        validate_id(&path.id, "recordTypes[].readPaths[].id", errors);
        validate_id(&path.route, "recordTypes[].readPaths[].route", errors);
        if !ids.insert(path.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.read-path.id-duplicate",
                "recordTypes[].readPaths[].id",
                "a read path identifier is duplicated",
            ));
        }
        if !routes.insert(path.route.as_str()) {
            errors.push(Diagnostic::error(
                "breg.read-path.route-duplicate",
                "recordTypes[].readPaths[].route",
                "a read path route is duplicated for a record type",
            ));
        }
        if path.to == entity.id {
            errors.push(Diagnostic::error(
                "breg.read-path.target-self",
                "recordTypes[].readPaths[].to",
                "a read path target must differ from its source record type",
            ));
        }
        let Some(through) = entities.get(&path.through) else {
            errors.push(Diagnostic::error(
                "breg.read-path.through-unknown",
                "recordTypes[].readPaths[].through",
                "a read path association record type does not resolve",
            ));
            continue;
        };
        if !entities.contains_key(&path.to) {
            errors.push(Diagnostic::error(
                "breg.read-path.target-unknown",
                "recordTypes[].readPaths[].to",
                "a read path target record type does not resolve",
            ));
            continue;
        }
        if infer_read_path_refs(entity, through, &path.to).is_none() {
            errors.push(Diagnostic::error(
                "breg.read-path.references-ambiguous",
                "recordTypes[].readPaths[]",
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
                "breg.read-path.cycle",
                "recordTypes[].readPaths[]",
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

/// An `import` grant creates records only through a durable ingestion run,
/// so it needs the entity's chunk bounds and no raw batch grant beside it on
/// the entity: a batch grant would write the same records outside any import
/// authority, leaving the authority bounding nothing. The creator a run is
/// scoped to is the principal claim every profile names.
fn validate_import_grant(
    entity: &EntitySource,
    access: &AccessProfileSource,
    errors: &mut Vec<Diagnostic>,
) {
    let path = format!(
        "recordTypes[id={}].accessProfiles[id={}].operations",
        entity.id, access.id
    );
    if entity.batch.is_none() {
        errors.push(Diagnostic::error(
            "breg.import.batch-bounds-required",
            path.clone(),
            "an import grant loads records in chunks, so the record type must declare batch maximumItems and maximumBytes",
        ));
    }
    if entity
        .access_profiles
        .iter()
        .any(|profile| profile.operations.contains(&Operation::Batch))
    {
        errors.push(Diagnostic::error(
            "breg.import.batch-redundant",
            path,
            "a batch grant on the same record type writes records outside any import authority; remove batch and load through import",
        ));
    }
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
        validate_id(&access.id, "recordTypes[].accessProfiles[].id", errors);
        reject_system_profile_id(&access.id, "recordTypes[].accessProfiles[].id", errors);
        if !ids.insert(access.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.access-profile.id-duplicate",
                "recordTypes[].accessProfiles[].id",
                "an access profile identifier is duplicated",
            ));
        }
        if access.operations.is_empty() {
            errors.push(Diagnostic::error(
                "breg.access-profile.operations-empty",
                "recordTypes[].accessProfiles[].operations",
                "an access profile must grant at least one operation",
            ));
        }
        if access.principal_claim.is_empty() {
            errors.push(Diagnostic::error(
                "breg.access-profile.principal-claim-required",
                "recordTypes[].accessProfiles[].principalClaim",
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
                "breg.access-profile.claim-value-invalid",
                "recordTypes[].accessProfiles[]",
                "required scope and purpose values must be non-empty",
            ));
        }
        for operation in &access.operations {
            if (entity.mutation_mode == MutationMode::CreateOnly
                && matches!(operation, Operation::Patch | Operation::Tombstone))
                || (*operation == Operation::Tombstone && !entity.tombstone)
                || *operation == Operation::Invoke
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.operation-unavailable",
                    "recordTypes[].accessProfiles[].operations",
                    "an access profile grants an operation the record type does not expose",
                ));
            }
        }
        if access.operations.contains(&Operation::Import) {
            validate_import_grant(entity, access, errors);
        }
        if access.operations.contains(&Operation::Batch)
            && !access
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::Create | Operation::Patch))
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.batch-underlying-operation-required",
                "recordTypes[].accessProfiles[].operations",
                "a batch access profile must grant create or patch for its items",
            ));
        }
        // A task grant carries the approval of the human who assigned the
        // task. A standing agent carries none, so a human must submit what it
        // drafts. Checked here so module-contributed profiles meet it too.
        if access.actor_kind == Some(crate::contract::ActorKindSource::Agent)
            && access.task_grant.is_none()
            && access
                .operations
                .iter()
                .any(|operation| is_direct_target_mutation(*operation))
        {
            errors.push(Diagnostic::error(
                    "breg.access-profile.standing-agent-direct-mutation-forbidden",
                    "recordTypes[].accessProfiles[].operations",
                    "a standing agent profile without a taskGrant can author only Proposal drafts; direct target mutations, imports, batch operations, and tombstones are forbidden",
                ));
        }
        if !access.provenance_fields.is_empty()
            && (!access.revision_access || has_duplicates(&access.provenance_fields))
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.provenance-fields-invalid",
                "recordTypes[].accessProfiles[].provenanceFields",
                "provenance fields require authenticated revision access and must be duplicate-free",
            ));
        }
        if access.allow_data_export
            && (!access.operations.contains(&Operation::List) || access.readable_fields.is_empty())
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.data-export-invalid",
                "recordTypes[].accessProfiles[].allowDataExport",
                "bulk data export requires an authenticated list profile with a readable projection",
            ));
        }
        validate_spatial_queries(access, entity, errors);
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
        let profile_path = format!(
            "recordTypes[id={}].accessProfiles[id={}]",
            entity.id, access.id
        );
        for (member, referenced) in [
            ("readableFields", &access.readable_fields),
            ("filterableFields", &access.filterable_fields),
            ("sortableFields", &access.sortable_fields),
        ] {
            for field in referenced {
                if !fields.contains_key(field.as_str()) && !derived.contains_key(field.as_str()) {
                    errors.push(Diagnostic::error(
                        "breg.access-profile.field-unknown",
                        format!("{profile_path}.{member}[field={field}]"),
                        "an access profile refers to an unknown field",
                    ));
                }
            }
        }
        for (member, field) in access
            .writable_fields
            .iter()
            .map(|field| ("writableFields", field))
            .chain(
                access
                    .row_boundaries
                    .iter()
                    .map(|boundary| ("rowBoundaries", &boundary.field)),
            )
        {
            if field != "id" && !fields.contains_key(field.as_str()) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.field-unknown",
                    format!("{profile_path}.{member}[field={field}]"),
                    "an access profile refers to an unknown field",
                ));
            }
        }
        for field in &access.writable_fields {
            if fields
                .get(field.as_str())
                .is_some_and(|field| field.generate.is_some())
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.generated-field-writable",
                    format!("{profile_path}.writableFields[field={field}]"),
                    "a server-generated identifier must not be granted as a caller-writable field",
                ));
            }
        }
        for (member, processed) in [
            ("filterableFields", &access.filterable_fields),
            ("sortableFields", &access.sortable_fields),
        ] {
            for field in processed.difference(&access.readable_fields) {
                errors.push(Diagnostic::error(
                    "breg.access-profile.processing-wider-than-read",
                    format!("{profile_path}.{member}[field={field}]"),
                    &format!(
                        "access profile `{}` processes field `{field}` for filtering or sorting, so `{field}` must also be readable",
                        access.id
                    ),
                ));
            }
        }
        // Query processing over ciphertext cannot filter or order: an
        // encrypted field leaves the filterable and sortable sets.
        if let Some((member, field)) = access
            .filterable_fields
            .iter()
            .map(|field| ("filterableFields", field))
            .chain(
                access
                    .sortable_fields
                    .iter()
                    .map(|field| ("sortableFields", field)),
            )
            .find(|(_, field)| {
                fields
                    .get(field.as_str())
                    .is_some_and(|field| field.encrypted)
            })
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.processing-encrypted",
                format!("{profile_path}.{member}[field={field}]"),
                "an encrypted field cannot be a filterable or sortable field",
            ));
        }
        let mut boundaries = BTreeSet::new();
        for boundary in &access.row_boundaries {
            if boundary.field != "id"
                && fields.get(boundary.field.as_str()).is_some_and(|field| {
                    matches!(field.field_type, FieldTypeSource::Crs84Point { .. })
                })
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.row-boundary-type-unsupported",
                    "recordTypes[].accessProfiles[].rowBoundaries",
                    "CRS84 point fields cannot be row-boundary fields; use spatialQueries.bbox for bounded spatial search",
                ));
            } else if boundary.field != "id"
                && fields.get(boundary.field.as_str()).is_some_and(|field| {
                    matches!(field.field_type, FieldTypeSource::Structured { .. })
                })
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.row-boundary-type-unsupported",
                    "recordTypes[].accessProfiles[].rowBoundaries",
                    "CRS84 point and structured fields cannot be row-boundary fields",
                ));
            } else if boundary.field != "id"
                && fields
                    .get(boundary.field.as_str())
                    .is_some_and(|field| field.encrypted)
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.row-boundary-encrypted",
                    "recordTypes[].accessProfiles[].rowBoundaries",
                    "an encrypted field cannot be a row-boundary field",
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
                    "breg.access-profile.row-boundary-invalid",
                    "recordTypes[].accessProfiles[].rowBoundaries",
                    "row boundaries must be direct, non-empty, and duplicate-free",
                ));
            }
        }
        validate_lookup_permissions(access, entity, errors);
        validate_read_path_permissions(access, entity, entities, errors);
        if access.allow_count
            && !access.operations.contains(&Operation::List)
            && !access.operations.contains(&Operation::Snapshot)
        {
            errors.push(Diagnostic::error(
                "breg.access-profile.count-unavailable",
                "recordTypes[].accessProfiles[].allowCount",
                "direct count access requires an explicit list or snapshot permission",
            ));
        }
    }
    for operation in all_operations() {
        let profiles: Vec<&AccessProfileSource> = entity
            .access_profiles
            .iter()
            .filter(|access| access.operations.contains(&operation))
            .collect();
        validate_single_default(
            &entity.id,
            &format!("operation `{}`", operation_id(operation)),
            &profiles,
            errors,
        );
    }
    for path in &entity.read_paths {
        let profiles: Vec<&AccessProfileSource> = entity
            .access_profiles
            .iter()
            .filter(|access| access.read_paths.iter().any(|grant| grant.path == path.id))
            .collect();
        validate_single_default(
            &entity.id,
            &format!("read-path route `{}`", path.id),
            &profiles,
            errors,
        );
    }
}

fn create_required_field_findings(entities: &BTreeMap<String, EntitySource>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for entity in entities.values() {
        for access in &entity.access_profiles {
            let create_operation = match (
                access.operations.contains(&Operation::Create),
                access.operations.contains(&Operation::Import),
            ) {
                (true, true) => "`create` and `import`",
                (true, false) => "`create`",
                (false, true) => "`import`",
                (false, false) => continue,
            };
            // Engine-managed record identity, revision, and lifecycle columns
            // are not authored EntitySource fields and are therefore excluded.
            for field in entity.fields.iter().filter(|field| {
                field.required
                    && field.generate.is_none()
                    && !access.writable_fields.contains(field.id.as_str())
            }) {
                findings.push(Diagnostic::finding(
                    "breg.access.profile-create-required-field-not-writable",
                    format!(
                        "recordTypes[id={}].accessProfiles[id={}].writableFields[field={}]",
                        entity.id, access.id, field.id
                    ),
                    &format!(
                        "this required stored field cannot be supplied through {create_operation}; add it to writableFields or remove the operation from this permission"
                    ),
                ));
            }
        }
    }
    findings
}

fn stored_field_fillability_findings(
    entities: &BTreeMap<String, CompiledEntity>,
    actions: &crate::model::CompiledActionInventory,
) -> Vec<Diagnostic> {
    let mut fillable = BTreeSet::<(String, String)>::new();
    for entity in entities.values() {
        for profile in entity.access_profiles.values().filter(|profile| {
            [Operation::Create, Operation::Patch, Operation::Import]
                .iter()
                .any(|operation| profile.operations.contains(operation))
        }) {
            fillable.extend(
                profile
                    .writable_fields
                    .iter()
                    .map(|field| (entity.id.clone(), field.clone())),
            );
        }
    }
    for action in &actions.actions {
        for effect in &action.effects {
            fillable.extend(
                effect
                    .mutations
                    .iter()
                    .filter_map(|mutation| match mutation {
                        crate::model::CompiledPlanMutation::Set { field, .. } => {
                            Some((effect.target.entity_id.clone(), field.clone()))
                        }
                        crate::model::CompiledPlanMutation::Clear { .. } => None,
                    }),
            );
        }
        if let Some(handler) = &action.handler {
            for write in &handler.writes {
                fillable.extend(
                    write
                        .ceiling
                        .fields
                        .iter()
                        .map(|field| (write.ceiling.target_entity_id.clone(), field.clone())),
                );
            }
        }
    }
    let mut findings = Vec::new();
    for entity in entities.values() {
        for field in entity.stored_fields.iter().filter(|field| {
            !field.required && !fillable.contains(&(entity.id.clone(), field.logical.id.clone()))
        }) {
            findings.push(Diagnostic::finding(
                "breg.record-type.stored-field-unfillable",
                format!(
                    "recordTypes[id={}].fields[id={}]",
                    entity.id, field.logical.id
                ),
                "this optional stored field has no writable access grant, fixed Action set, function-plan write, or import that can supply a value; add the field to one of those writers, or remove the field",
            ));
        }
    }
    findings
}

fn stopped_stage_finding(stage: &str, skipped_checks: &str) -> Diagnostic {
    Diagnostic::finding(
        "breg.compile.later-checks-skipped",
        "project",
        &format!(
            "compilation stopped during {stage}; {skipped_checks}. Correct the errors above and check again. Explain subjects model, access, routes, queries, actions, proposals, and events require a successful compiled model and did not run"
        ),
    )
}

fn stopped_compile_failure(
    failure: CompileFailure,
    findings: &[Diagnostic],
    stage: &str,
) -> CompileFailure {
    let mut findings = findings.to_vec();
    findings.push(stopped_stage_finding(
        stage,
        "remaining compiler checks did not run",
    ));
    failure.with_findings(&findings)
}

/// Refuse multiple defaults. With no default, an ambiguous route requires
/// the caller to select its profile explicitly.
fn validate_single_default(
    entity_id: &str,
    route: &str,
    profiles: &[&AccessProfileSource],
    errors: &mut Vec<Diagnostic>,
) {
    if profiles.len() < 2 {
        return;
    }
    let defaults: Vec<&str> = profiles
        .iter()
        .filter(|access| access.default)
        .map(|access| access.id.as_str())
        .collect();
    let Some((claimed, duplicates)) = defaults.split_first() else {
        return;
    };
    for duplicate in duplicates {
        errors.push(Diagnostic::error(
            "breg.access-profile.default-invalid",
            format!(
                "recordTypes[id={}].accessProfiles[id={duplicate}].default",
                entity_id
            ),
            &format!(
                "{route} on record type `{}` accepts one default profile and `{claimed}` already claims it; clear `default: true` on `{duplicate}`",
                entity_id
            ),
        ));
    }
}

fn validate_spatial_queries(
    access: &AccessProfileSource,
    entity: &EntitySource,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(spatial) = &access.spatial_queries else {
        return;
    };
    if spatial.bbox.is_none() {
        errors.push(Diagnostic::error(
            "breg.access-profile.spatial-queries-empty",
            "recordTypes[].accessProfiles[].spatialQueries",
            "spatial query permissions must declare one supported query",
        ));
        return;
    }
    let Some(bbox) = &spatial.bbox else {
        return;
    };
    validate_bbox_span(
        &bbox.maximum_longitude_span_degrees,
        360.0,
        "breg.access-profile.spatial-queries-bbox-maximum-longitude-span-degrees-invalid",
        "recordTypes[].accessProfiles[].spatialQueries.bbox.maximumLongitudeSpanDegrees",
        "bbox maximumLongitudeSpanDegrees must be finite, positive, and no greater than 360",
        errors,
    );
    validate_bbox_span(
        &bbox.maximum_latitude_span_degrees,
        180.0,
        "breg.access-profile.spatial-queries-bbox-maximum-latitude-span-degrees-invalid",
        "recordTypes[].accessProfiles[].spatialQueries.bbox.maximumLatitudeSpanDegrees",
        "bbox maximumLatitudeSpanDegrees must be finite, positive, and no greater than 180",
        errors,
    );
    if !access.operations.contains(&Operation::List) {
        errors.push(Diagnostic::error(
            "breg.access-profile.spatial-queries-bbox-list-required",
            "recordTypes[].accessProfiles[].spatialQueries.bbox",
            "bbox spatial queries require an explicit list permission",
        ));
    }
    let Some(geojson) = &entity.geojson else {
        errors.push(Diagnostic::error(
            "breg.access-profile.spatial-queries-bbox-geometry-required",
            "recordTypes[].geojson.geometryField",
            "bbox spatial queries require a record type GeoJSON geometry field",
        ));
        return;
    };
    if !access.readable_fields.contains(&geojson.geometry_field) {
        errors.push(Diagnostic::error(
            "breg.access-profile.spatial-queries-bbox-geometry-not-readable",
            "recordTypes[].accessProfiles[].readableFields",
            "bbox spatial queries require readable access to the GeoJSON geometry field",
        ));
    }
}

fn validate_bbox_span(
    value: &serde_json::Number,
    maximum: f64,
    code: &str,
    path: &str,
    message: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if !value
        .as_f64()
        .is_some_and(|parsed| parsed.is_finite() && parsed > 0.0 && parsed <= maximum)
    {
        errors.push(Diagnostic::error(code, path, message));
    }
}

fn validate_lookup_permissions(
    access: &AccessProfileSource,
    entity: &EntitySource,
    errors: &mut Vec<Diagnostic>,
) {
    if access.lookups.is_empty() {
        return;
    }
    if !access.operations.contains(&Operation::Lookup) {
        errors.push(Diagnostic::error(
            "breg.access-profile.lookup-operation-required",
            "recordTypes[].accessProfiles[].lookups",
            "lookup permissions require the lookup operation",
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
                "breg.access-profile.lookup-duplicate",
                "recordTypes[].accessProfiles[].lookups",
                "lookup selector permissions must be unique",
            ));
        }
        let Some(selector) = selectors.get(lookup.selector.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.access-profile.lookup-selector-unknown",
                "recordTypes[].accessProfiles[].lookups[].selector",
                "a lookup permission refers to an unknown selector profile",
            ));
            continue;
        };
        match lookup.value_origin {
            LookupValueOrigin::Request if !lookup.claim_mapping.is_empty() => {
                errors.push(Diagnostic::error(
                    "breg.access-profile.lookup-claim-mapping-unavailable",
                    "recordTypes[].accessProfiles[].lookups[].claimMapping",
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
                        "breg.access-profile.lookup-claim-mapping-invalid",
                        "recordTypes[].accessProfiles[].lookups[].claimMapping",
                        "claim-origin lookups must map every selector field to one direct claim",
                    ));
                }
            }
            LookupValueOrigin::Request => {}
        }
    }
}

fn validate_read_path_permissions(
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
                "breg.access-profile.read-path-duplicate",
                "recordTypes[].accessProfiles[].readPaths",
                "read-path permissions must be unique",
            ));
        }
        let Some(path) = paths.get(grant.path.as_str()) else {
            errors.push(Diagnostic::error(
                "breg.access-profile.read-path-unknown",
                "recordTypes[].accessProfiles[].readPaths[].path",
                "a read-path permission refers to an unknown path",
            ));
            continue;
        };
        validate_read_path_permission_fields(access, entity, entities, path, grant, errors);
    }
}

fn validate_read_path_permission_fields(
    access: &AccessProfileSource,
    source: &EntitySource,
    entities: &BTreeMap<String, EntitySource>,
    path: &crate::contract::ReadPathSource,
    grant: &ReadPathPermissionSource,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(target) = entities.get(&path.to) else {
        return;
    };
    if !entities.contains_key(&path.through) {
        return;
    }
    let target_stored = stored_field_map(target);
    let target_derived = derived_field_map(target);
    let grant_path = format!(
        "recordTypes[id={}].accessProfiles[id={}].readPaths[path={}]",
        source.id, access.id, grant.path
    );
    if grant.readable_fields.is_empty() {
        errors.push(Diagnostic::error(
            "breg.access-profile.read-path-readable-fields-empty",
            format!("{grant_path}.readableFields"),
            "a read-path permission must declare readable fields",
        ));
    }
    for (member, processed) in [
        ("filterableFields", &grant.filterable_fields),
        ("sortableFields", &grant.sortable_fields),
    ] {
        for field in processed.difference(&grant.readable_fields) {
            errors.push(Diagnostic::error(
                "breg.access-profile.read-path-processing-wider-than-read",
                format!("{grant_path}.{member}[field={field}]"),
                &format!(
                    "access profile `{}` read path `{}` processes field `{field}` for filtering or sorting, so `{field}` must also be readable",
                    access.id, grant.path
                ),
            ));
        }
    }
    for (member, referenced) in [
        ("readableFields", &grant.readable_fields),
        ("filterableFields", &grant.filterable_fields),
        ("sortableFields", &grant.sortable_fields),
    ] {
        for field in referenced {
            if field != "id"
                && !target_stored.contains_key(field.as_str())
                && !target_derived.contains_key(field.as_str())
            {
                errors.push(Diagnostic::error(
                    "breg.access-profile.read-path-field-unknown",
                    format!("{grant_path}.{member}[field={field}]"),
                    "a read-path permission refers to an unknown target field",
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
    if processed.is_empty() && grant.allow_count {
        errors.push(Diagnostic::error(
            "breg.access-profile.read-path-count-without-fields",
            "recordTypes[].accessProfiles[].readPaths[].allowCount",
            "read-path count access requires explicit path field capabilities",
        ));
    }
    if path.to == source.id {
        errors.push(Diagnostic::error(
            "breg.access-profile.read-path-self-target",
            "recordTypes[].accessProfiles[].readPaths[].path",
            "a read-path permission cannot target the source record type",
        ));
    }
}

fn validate_hooks(
    registry_id: &str,
    entity: &EntitySource,
    hook_paths: &HookPathMap,
    profile: CompileProfile,
    registry_event_ids: &mut BTreeSet<String>,
    errors: &mut Vec<Diagnostic>,
) {
    let fields: BTreeMap<&str, &FieldSource> = entity
        .fields
        .iter()
        .map(|field| (field.id.as_str(), field))
        .collect();
    let mut hook_id_counts = BTreeMap::new();
    for hook in &entity.hooks {
        *hook_id_counts.entry(hook.id.as_str()).or_insert(0_usize) += 1;
    }
    let mut ids = BTreeSet::new();
    for hook in &entity.hooks {
        let hook_path = if hook_id_counts.get(hook.id.as_str()) == Some(&1) {
            hook_paths
                .get(&(entity.id.clone(), hook.id.clone()))
                .cloned()
                .unwrap_or_else(|| format!("recordTypes[id={}].hooks[id={}]", entity.id, hook.id))
        } else {
            format!("recordTypes[id={}].hooks[]", entity.id)
        };
        validate_id(&hook.id, "recordTypes[].hooks[].id", errors);
        if !ids.insert(hook.id.as_str()) {
            errors.push(Diagnostic::error(
                "breg.event.id-duplicate",
                "recordTypes[].hooks[].id",
                "an event identifier is duplicated",
            ));
        } else if !registry_event_ids.insert(hook.id.clone()) {
            errors.push(Diagnostic::error(
                "breg.event.id-registry-duplicate",
                "recordTypes[].hooks[].id",
                "an event identifier must be unique across the Registry",
            ));
        }
        if hook.phase != HookPhase::After {
            errors.push(Diagnostic::error(
                "breg.hook.phase-unsupported",
                format!("{hook_path}.phase"),
                "an entity hook runs after the triggering transaction commits; declare phase: after",
            ));
        }
        if hook.projection.is_empty() {
            errors.push(Diagnostic::error(
                "breg.event.projection-empty",
                format!("{hook_path}.projection"),
                "an event projection must contain at least one field",
            ));
        }
        for field in hook
            .projection
            .iter()
            .filter(|field| !fields.contains_key(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "breg.event.projection-field-unknown",
                format!("{hook_path}.projection[field={field}]"),
                "an event projection refers to an unknown field",
            ));
        }
        for field in hook.projection.iter().filter(|field| {
            fields
                .get(field.as_str())
                .is_some_and(|field| field.encrypted)
        }) {
            errors.push(Diagnostic::error(
                "breg.event.projection-encrypted",
                format!("{hook_path}.projection[field={field}]"),
                "an encrypted field cannot be projected into an event",
            ));
        }
        let maximum_payload_bytes =
            maximum_event_payload_bytes(registry_id, &entity.id, hook, |field| {
                fields
                    .get(field)
                    .map(|field| (&field.field_type, field.required))
            });
        if matches!(
            hook.trigger,
            EventTrigger::Patched | EventTrigger::Tombstoned
        ) && entity.mutation_mode == MutationMode::CreateOnly
        {
            errors.push(Diagnostic::error(
                "breg.event.trigger-unavailable",
                format!("{hook_path}.trigger"),
                "an event trigger is unavailable for a create-only entity",
            ));
        }
        if hook.trigger == EventTrigger::Tombstoned && !entity.tombstone {
            errors.push(Diagnostic::error(
                "breg.event.trigger-unavailable",
                format!("{hook_path}.trigger"),
                "a tombstone event requires tombstone behavior",
            ));
        }
        validate_event_condition(hook, &fields, &hook_path, errors);
        let destination_id = match hook.handler.as_ref() {
            // A remote call inside the triggering transaction would hold row
            // locks for the length of a network round trip, so the one
            // combination version one refuses is `before` with `url`.
            Some(HookHandlerSource::Url { .. }) if hook.phase != HookPhase::After => {
                errors.push(Diagnostic::error(
                    "breg.hook.handler-kind-unsupported",
                    format!("{hook_path}.handler.type"),
                    "handler type url cannot run in phase before; declare phase: after",
                ));
                continue;
            }
            Some(HookHandlerSource::Url { destination_id }) => Some(destination_id),
            // A local kind holds a reviewed program instead of a destination.
            // Its script or module asset is resolved and checked against the
            // supplied assets by `validate_hook_assets`.
            Some(handler) => {
                validate_hook_handler_abi(handler, &hook_path, errors);
                None
            }
            None => {
                if profile == CompileProfile::Production {
                    errors.push(Diagnostic::error(
                        "breg.event.delivery-required",
                        format!("{hook_path}.handler"),
                        "a production event requires a supported delivery",
                    ));
                }
                continue;
            }
        };
        if maximum_payload_bytes.is_some_and(|maximum| maximum > u64::from(MAX_HOOK_PAYLOAD_BYTES))
        {
            errors.push(Diagnostic::error(
                "breg.event.hook-projection-too-large",
                format!("{hook_path}.projection"),
                "the hook projection can exceed the governed transport body bound",
            ));
        }
        if destination_id.is_some_and(|value| !valid_logical_destination_id(value)) {
            errors.push(Diagnostic::error(
                "breg.event.hook-destination-invalid",
                format!("{hook_path}.handler.destinationId"),
                "a hook destination must use the closed logical identifier grammar",
            ));
        }
    }
}

/// A local handler runs the one handler ABI version one defines, so a hook
/// declaring any other spelling is refused rather than compiled into a
/// program the worker would call with a contract it does not implement.
fn validate_hook_handler_abi(
    handler: &HookHandlerSource,
    hook_path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let abi = match handler {
        HookHandlerSource::Rhai { abi, .. } | HookHandlerSource::Wasm { abi, .. } => abi.as_deref(),
        HookHandlerSource::Url { .. } => return,
    };
    if abi != Some(HOOK_HANDLER_ABI_V1) {
        errors.push(Diagnostic::error(
            "breg.hook.handler-abi-unsupported",
            format!("{hook_path}.handler.abi"),
            &format!("a local hook handler requires abi {HOOK_HANDLER_ABI_V1}"),
        ));
    }
}

/// Resolve and check the reviewed program behind every local hook handler.
///
/// This mirrors the action handler's asset pass: the bytes must be present in
/// the contributing module's asset namespace, within their fixed bound, and
/// admissible under the executor that will run them.
fn validate_hook_assets(
    sources: &BTreeMap<String, EntitySource>,
    hook_origins: &HookOriginMap,
    assets: &[ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) {
    for entity in sources.values() {
        for hook in &entity.hooks {
            let hook_path = format!("recordTypes[id={}].hooks[id={}]", entity.id, hook.id);
            let Some(handler) = hook.handler.as_ref() else {
                continue;
            };
            let (source_path, is_wasm) = match handler {
                HookHandlerSource::Rhai { script, .. } => (script.as_str(), false),
                HookHandlerSource::Wasm { module, .. } => (module.as_str(), true),
                HookHandlerSource::Url { .. } => continue,
            };
            #[cfg(not(feature = "wasm"))]
            if is_wasm {
                // Refuse the declared backend explicitly, before the module is
                // looked up: this build carries no WASM executor, so a hook it
                // compiled could only fail when it fires.
                errors.push(Diagnostic::error(
                    "breg.hook.handler-wasm-build-unsupported",
                    format!("{hook_path}.handler.type"),
                    "this build of the compiler does not admit WASM hook handlers",
                ));
                continue;
            }
            let module = hook_origins
                .get(&(entity.id.clone(), hook.id.clone()))
                .cloned()
                .unwrap_or_default();
            let Some(asset) = assets
                .iter()
                .find(|asset| asset.module == module && asset.path == source_path)
            else {
                let (code, member) = if is_wasm {
                    ("breg.hook.handler-module-asset-missing", "module")
                } else {
                    ("breg.hook.handler-source-missing", "script")
                };
                errors.push(Diagnostic::error(
                    code,
                    format!("{hook_path}.handler.{member}"),
                    &format!("supply the hook's owned handler asset at {source_path}"),
                ));
                continue;
            };
            let diagnostic_start = errors.len();
            if is_wasm {
                validate_hook_module_asset(&asset.bytes, errors);
            } else {
                validate_hook_script_asset(&asset.bytes, errors);
            }
            for diagnostic in &mut errors[diagnostic_start..] {
                if let Some(rest) = diagnostic.path.strip_prefix("recordTypes[].hooks[]") {
                    diagnostic.path = format!("{hook_path}{rest}");
                }
            }
        }
    }
}

pub(crate) fn validate_hook_module_asset(bytes: &[u8], errors: &mut Vec<Diagnostic>) {
    if bytes.is_empty() || bytes.len() > crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES {
        errors.push(Diagnostic::error(
            "breg.hook.handler-module-bound",
            "recordTypes[].hooks[].handler.module",
            &format!(
                "the handler module must be non-empty and at most {} bytes; {} bytes supplied",
                crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES,
                bytes.len()
            ),
        ));
        return;
    }
    if !crate::wasm_handler::is_wasm_binary(bytes) {
        errors.push(Diagnostic::error(
            "breg.hook.handler-module-invalid",
            "recordTypes[].hooks[].handler.module",
            "the handler module must be a WebAssembly binary, not WebAssembly text",
        ));
        return;
    }
    validate_hook_module_structure(bytes, errors);
}

/// Structural admission runs only where the wasm executor is linked in; a
/// build without it refuses every WASM hook in `validate_hook_assets` before
/// its module is read, so the no-op below is never reached with a module.
#[cfg(feature = "wasm")]
fn validate_hook_module_structure(bytes: &[u8], errors: &mut Vec<Diagnostic>) {
    if let Some((_, message)) = crate::wasm_handler::structural_violation(bytes) {
        errors.push(Diagnostic::error(
            "breg.hook.handler-module-invalid",
            "recordTypes[].hooks[].handler.module",
            &message,
        ));
    }
}

#[cfg(not(feature = "wasm"))]
fn validate_hook_module_structure(_bytes: &[u8], _errors: &mut Vec<Diagnostic>) {}

pub(crate) fn validate_hook_script_asset(bytes: &[u8], errors: &mut Vec<Diagnostic>) {
    if bytes.is_empty()
        || bytes.len() > registry_platform_hooks::executor::RHAI_HOOK_MAX_SOURCE_BYTES
    {
        errors.push(Diagnostic::error(
            "breg.hook.handler-source-bound",
            "recordTypes[].hooks[].handler.script",
            "the handler source must be non-empty and within its fixed byte bound",
        ));
        return;
    }
    let Ok(script) = std::str::from_utf8(bytes) else {
        errors.push(Diagnostic::error(
            "breg.hook.handler-source-encoding",
            "recordTypes[].hooks[].handler.script",
            "the handler source must be UTF-8",
        ));
        return;
    };
    // A hook program runs on the bare platform engine under the shared hook
    // profile, so admission compiles it the same way the executor does.
    if let Err(error) = registry_platform_hooks::executor::compile_rhai_hook(script) {
        use registry_platform_script::rhai::RhaiCompileError;
        let (code, message) = match error {
            RhaiCompileError::SourceBound => (
                "breg.hook.handler-source-bound",
                "the handler source exceeds its fixed byte bound".to_owned(),
            ),
            RhaiCompileError::Parse(position) => {
                let location = match (position.line(), position.position()) {
                    (Some(line), Some(column)) => format!(" at line {line}, column {column}"),
                    (Some(line), None) => format!(" at line {line}"),
                    _ => String::new(),
                };
                (
                    "breg.hook.handler-parse",
                    format!("correct the Rhai syntax or unsupported construct{location}"),
                )
            }
            RhaiCompileError::Entrypoint => (
                "breg.hook.handler-entrypoint",
                "declare exactly one public fn handle(ctx) entry point and do not overload functions"
                    .to_owned(),
            ),
        };
        errors.push(Diagnostic::error(
            code,
            "recordTypes[].hooks[].handler.script",
            &message,
        ));
    }
}

fn validate_event_condition(
    event: &crate::contract::HookSource,
    fields: &BTreeMap<&str, &FieldSource>,
    hook_path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    match event.when.as_ref() {
        Some(EventConditionSource::Fields {
            changed,
            before_equals,
            after_equals,
            before_is_null,
            after_is_null,
        }) => {
            if changed.is_empty()
                && before_equals.is_empty()
                && after_equals.is_empty()
                && before_is_null.is_empty()
                && after_is_null.is_empty()
            {
                errors.push(Diagnostic::error(
                    "breg.event.when-empty",
                    format!("{hook_path}.when"),
                    "a field event condition requires at least one predicate",
                ));
            }
            let compatible = match event.trigger {
                EventTrigger::Created => {
                    changed.is_empty() && before_equals.is_empty() && before_is_null.is_empty()
                }
                EventTrigger::Patched => true,
                EventTrigger::Tombstoned => {
                    changed.is_empty() && after_equals.is_empty() && after_is_null.is_empty()
                }
            };
            if !compatible {
                errors.push(Diagnostic::error(
                    "breg.event.when-trigger-incompatible",
                    format!("{hook_path}.when"),
                    "field predicates are unavailable for this event trigger",
                ));
            }
            for field in changed {
                let path = format!("{hook_path}.when.changed[field={field}]");
                if !fields.contains_key(field.as_str()) {
                    errors.push(Diagnostic::error(
                        "breg.event.when-field-unknown",
                        &path,
                        "an event condition refers to an unknown field",
                    ));
                }
                if fields
                    .get(field.as_str())
                    .is_some_and(|field| field.encrypted)
                {
                    errors.push(Diagnostic::error(
                        "breg.event.when-encrypted",
                        &path,
                        "an event condition cannot name an encrypted field",
                    ));
                }
            }
            for (member, unset) in [
                ("beforeIsNull", before_is_null),
                ("afterIsNull", after_is_null),
            ] {
                for field in unset {
                    let path = format!("{hook_path}.when.{member}[field={field}]");
                    let Some(source) = fields.get(field.as_str()) else {
                        errors.push(Diagnostic::error(
                            "breg.event.when-field-unknown",
                            &path,
                            "an event condition refers to an unknown field",
                        ));
                        continue;
                    };
                    if source.encrypted {
                        errors.push(Diagnostic::error(
                            "breg.event.when-encrypted",
                            &path,
                            "an event condition cannot name an encrypted field",
                        ));
                    }
                }
            }
            for (member, predicates) in [
                ("beforeEquals", before_equals),
                ("afterEquals", after_equals),
            ] {
                for (field, value) in predicates {
                    let path = format!("{hook_path}.when.{member}[field={field}]");
                    let Some(source) = fields.get(field.as_str()) else {
                        errors.push(Diagnostic::error(
                            "breg.event.when-field-unknown",
                            &path,
                            "an event condition refers to an unknown field",
                        ));
                        continue;
                    };
                    if source.encrypted {
                        errors.push(Diagnostic::error(
                            "breg.event.when-encrypted",
                            &path,
                            "an event condition cannot name an encrypted field",
                        ));
                    }
                    let value = serde_json::to_value(value).expect("event scalar value serializes");
                    if canonical_field_literal(&value, &source.field_type).is_none() {
                        errors.push(Diagnostic::error(
                            "breg.event.when-value-invalid",
                            &path,
                            "an event comparison value must be canonical for its declared field type",
                        ));
                    }
                }
            }
        }
        None => {}
    }
}

/// The `project.package` members a production compilation requires. Authoring
/// documentation reads this list rather than restating it.
pub const PACKAGE_IDENTITY_KEYS: [&str; 1] = ["package.sourceRevision"];

/// Every member that appears more than once, in first-seen order.
fn duplicate_members(values: &[String]) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    let mut repeated = Vec::new();
    for value in values {
        if !seen.insert(value.as_str()) && !repeated.contains(&value.as_str()) {
            repeated.push(value.as_str());
        }
    }
    repeated
}

/// Render one closed list as backticked members an adopter can copy.
fn quoted_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn valid_logical_destination_id(value: &str) -> bool {
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

/// The worst-case canonical bytes of one captured event, envelope included.
///
/// The runtime stores and delivers the whole canonical envelope and measures
/// it against the compiled bound, so the compile-time proof measures the same
/// document: the `data` object below plus the envelope wrapper
/// [`maximum_envelope_wrapper_bytes`] covers.
fn maximum_event_payload_bytes<'a>(
    registry_id: &str,
    entity_id: &str,
    event: &crate::contract::HookSource,
    field: impl Fn(&str) -> Option<(&'a FieldTypeSource, bool)>,
) -> Option<u64> {
    let values = maximum_event_values_bytes(&event.projection, field)?;
    let fixed_keys = [
        "recordType",
        "recordId",
        "revision",
        "trigger",
        "packageRevision",
        "values",
    ];
    // Canonical body object braces, one comma between members, and fixed key
    // encodings (two quotes plus a colon per key).
    let mut total = 2_u64.checked_add(fixed_keys.len().saturating_sub(1) as u64)?;
    for key in fixed_keys {
        total = total.checked_add(key.len() as u64 + 3)?;
    }
    // Entity ids and triggers use the compiler's closed ASCII grammars.
    total = total.checked_add(entity_id.len() as u64 + 2)?;
    // A UUID string, the largest positive i64 revision, and the longest
    // trigger string, including JSON quotes where applicable.
    let maximum_trigger_bytes = 12;
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
    total = total.checked_add(values)?;
    total.checked_add(maximum_envelope_wrapper_bytes(
        registry_id,
        entity_id,
        &event.id,
    )?)
}

/// The worst-case canonical bytes of the envelope members that carry the
/// `data` object: `causation`, `dataschema`, `id`, `source`, `subject`,
/// `time`, and `type`, plus the object punctuation of all eight members.
///
/// Every term is a length the compiler already knows or a bound the engine
/// already enforces. The identifiers use the closed lowercase grammar
/// [`validate_id`] holds, so none of them needs JSON string escaping.
pub(crate) fn maximum_envelope_wrapper_bytes(
    registry_id: &str,
    entity_id: &str,
    event_id: &str,
) -> Option<u64> {
    // Canonical envelope object braces, one comma between members, and fixed
    // key encodings (two quotes plus a colon per key).
    let envelope_keys = [
        "causation",
        "data",
        "dataschema",
        "id",
        "source",
        "subject",
        "time",
        "type",
    ];
    let mut total = 2_u64.checked_add(envelope_keys.len() as u64 - 1)?;
    for key in envelope_keys {
        total = total.checked_add(key.len() as u64 + 3)?;
    }
    // `causation` is `{"hop":N,"parent":"<uuid>","root":"<uuid>"}`. An event a
    // hook caused carries a parent, so the worst case keeps it, and `hop` is a
    // decimal the hook library refuses to raise past its own ceiling.
    let causation_keys = ["hop", "parent", "root"];
    let mut causation = 2_u64.checked_add(causation_keys.len() as u64 - 1)?;
    for key in causation_keys {
        causation = causation.checked_add(key.len() as u64 + 3)?;
    }
    causation = causation
        .checked_add(decimal_digits(u64::from(
            registry_platform_hooks::HOP_CEILING,
        )))?
        .checked_add(38)?
        .checked_add(38)?;
    total = total.checked_add(causation)?;
    // `dataschema` is the quoted event schema URN the compiler builds: a fixed
    // prefix, three identifiers with one separator each, and a `sha256:` hex
    // digest of the data contract.
    total = total.checked_add(
        2 + "urn:breg:event-schema:".len() as u64
            + registry_id.len() as u64
            + 1
            + entity_id.len() as u64
            + 1
            + event_id.len() as u64
            + 1
            + "sha256:".len() as u64
            + 64,
    )?;
    // `id` is a quoted UUID.
    total = total.checked_add(38)?;
    // `source` is the quoted deployment URN `crate::hooks::delivery_source`
    // builds. Its package id is this registry's id; its instance id is the
    // runtime configuration's `identity.instanceId`, recorded in registry
    // state by `bregctl apply`, which the configuration loader holds to the
    // closed `valid_build_id` grammar within MAX_BUILD_ID_BYTES, so no longer
    // spelling reaches the envelope.
    total = total.checked_add(
        2 + "urn:registrystack:registry:".len() as u64
            + registry_id.len() as u64
            + ":instance:".len() as u64
            + u64::from(MAX_BUILD_ID_BYTES),
    )?;
    // `subject` is `{"recordReference":"<reference>","recordRevision":N}`. The
    // reference is the audit key hasher's longest prefix and its hex digest,
    // and the revision is the largest positive i64, the same bound the data
    // object's own `revision` carries.
    let subject_keys = ["recordReference", "recordRevision"];
    let mut subject = 2_u64.checked_add(subject_keys.len() as u64 - 1)?;
    for key in subject_keys {
        subject = subject.checked_add(key.len() as u64 + 3)?;
    }
    subject = subject
        .checked_add(2 + "hmac-sha256:".len() as u64 + 64)?
        .checked_add(19)?;
    total = total.checked_add(subject)?;
    // `time` is the quoted UTC millisecond RFC 3339 spelling the envelope
    // normalizes every instant to: `YYYY-MM-DDThh:mm:ss.sssZ`.
    total = total.checked_add(26)?;
    // `type` is the quoted event identifier.
    total.checked_add(event_id.len() as u64 + 2)
}

/// The decimal spelling width of `value`.
fn decimal_digits(value: u64) -> u64 {
    let mut digits = 1;
    let mut remaining = value / 10;
    while remaining > 0 {
        digits += 1;
        remaining /= 10;
    }
    digits
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
    registry_id: &str,
    entity: &CompiledEntity,
    event: &crate::contract::HookSource,
) -> Option<u32> {
    let maximum = maximum_event_payload_bytes(registry_id, &entity.id, event, |field| {
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

/// Derive outbound classification from every value the event can disclose.
/// Mutation planning uses this same rule when checking the compiled inventory.
pub(crate) fn event_classification_ceiling(
    entity: &CompiledEntity,
    event: &crate::contract::HookSource,
) -> Option<Classification> {
    event
        .projection
        .iter()
        .chain(event_condition_fields(event))
        .filter_map(|field| entity.fields.get(field))
        .map(|field| field.classification)
        .max()
}

fn compile_event_delivery_inventory(
    registry_id: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    hook_origins: &HookOriginMap,
    assets: &[ModuleAssetSource],
) -> Result<CompiledEventDeliveryInventory, Diagnostic> {
    let mut deliveries = entities
        .values()
        .flat_map(|entity| {
            entity.hooks.values().filter_map(move |event| {
                event
                    .handler
                    .as_ref()
                    .map(|handler| (entity, event, handler))
            })
        })
        .map(|(entity, event, handler)| {
            let (destination_id, handler) =
                compile_hook_handler(entity, event, handler, hook_origins, assets)?;
            let binding = event_data_schema_binding(registry_id, entity, event)?;
            let classification_ceiling = event_classification_ceiling(entity, event)
                .expect("validated event projection is non-empty");
            Ok(CompiledEventDelivery {
                id: format!("events.{}.{}.webhook", entity.id, event.id),
                owner: crate::model::CompiledEventOwner::RecordType {
                    record_type: entity.id.clone(),
                    trigger: event.trigger,
                },
                event_id: event.id.clone(),
                destination_id,
                handler,
                projection_fields: event.projection.iter().cloned().collect(),
                when: event.when.clone(),
                principal: event.principal.clone(),
                classification_ceiling,
                data_schema: binding.data_schema,
                data_schema_fingerprint: binding.fingerprint,
                data_schema_artifact_path: binding.artifact_path,
                authentication_profile: HookAuthenticationProfile::HmacSha256V1,
                delivery_mode: CompiledHookDeliveryMode::AfterCommit,
                retry_profile: CompiledHookRetryProfile::RegistryV1,
                attempt_timeout_ms: HOOK_ATTEMPT_TIMEOUT_MS,
                initial_backoff_ms: HOOK_INITIAL_BACKOFF_MS,
                maximum_backoff_ms: HOOK_MAXIMUM_BACKOFF_MS,
                exponential_backoff_multiplier: HOOK_BACKOFF_MULTIPLIER,
                maximum_attempts: HOOK_MAXIMUM_ATTEMPTS,
                retry_delays_ms: hook_retry_delays(
                    HOOK_INITIAL_BACKOFF_MS,
                    HOOK_MAXIMUM_BACKOFF_MS,
                    HOOK_MAXIMUM_ATTEMPTS,
                ),
                maximum_payload_bytes: maximum_compiled_event_payload_bytes(
                    registry_id,
                    entity,
                    event,
                )
                .expect("validated hook projection fields are bounded"),
                dead_letter: HookDeadLetterMode::Required,
                operator_replay: true,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    deliveries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(CompiledEventDeliveryInventory { deliveries })
}

/// Split a validated hook handler into the delivery row's two exclusive
/// halves: the bound destination a `url` handler is sent to, or the reviewed
/// program a local handler runs.
fn compile_hook_handler(
    entity: &CompiledEntity,
    event: &crate::contract::HookSource,
    handler: &HookHandlerSource,
    hook_origins: &HookOriginMap,
    assets: &[ModuleAssetSource],
) -> Result<(Option<String>, Option<CompiledHookHandler>), Diagnostic> {
    let (kind, source_path) = match handler {
        HookHandlerSource::Url { destination_id } => {
            return Ok((Some(destination_id.clone()), None));
        }
        HookHandlerSource::Rhai { script, .. } => (CompiledHookHandlerKind::Rhai, script.as_str()),
        HookHandlerSource::Wasm { module, .. } => (CompiledHookHandlerKind::Wasm, module.as_str()),
    };
    let source_module = hook_origins
        .get(&(entity.id.clone(), event.id.clone()))
        .cloned()
        .unwrap_or_default();
    let asset = assets
        .iter()
        .find(|asset| asset.module == source_module && asset.path == source_path)
        .ok_or_else(|| {
            Diagnostic::error(
                "breg.hook.handler-source-missing",
                "recordTypes[].hooks[].handler",
                &format!("supply the hook's owned handler asset at {source_path}"),
            )
        })?;
    Ok((
        None,
        Some(CompiledHookHandler {
            kind,
            abi: HOOK_HANDLER_ABI_V1.to_owned(),
            source_module,
            source_path: source_path.to_owned(),
            digest: format!("sha256:{}", hex_lower(&Sha256::digest(&asset.bytes))),
            bytes: asset.bytes.clone(),
        }),
    ))
}

fn event_condition_fields(
    event: &crate::contract::HookSource,
) -> Box<dyn Iterator<Item = &String> + '_> {
    match event.when.as_ref() {
        Some(EventConditionSource::Fields {
            changed,
            before_equals,
            after_equals,
            before_is_null,
            after_is_null,
        }) => Box::new(
            changed
                .iter()
                .chain(before_equals.keys())
                .chain(after_equals.keys())
                .chain(before_is_null.iter())
                .chain(after_is_null.iter()),
        ),
        None => Box::new(std::iter::empty()),
    }
}

fn validate_derived_assets(
    sources: &BTreeMap<String, EntitySource>,
    origins: &BTreeMap<(String, String), Option<String>>,
    assets: &[ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) {
    let source_columns = sources
        .values()
        .map(|entity| {
            let columns = std::iter::once("id".to_owned())
                .chain(
                    entity
                        .fields
                        .iter()
                        .map(|field| canonical_sql_name(&field.id)),
                )
                .collect::<BTreeSet<_>>();
            (canonical_sql_name(&entity.id), columns)
        })
        .collect::<BTreeMap<_, _>>();
    // Encrypted fields leave the registry_source layer, so derived SQL can
    // never resolve them; collect their logical column names per relation.
    let encrypted_columns = sources
        .values()
        .map(|entity| {
            let columns = entity
                .fields
                .iter()
                .filter(|field| field.encrypted)
                .map(|field| canonical_sql_name(&field.id))
                .collect::<BTreeSet<_>>();
            (canonical_sql_name(&entity.id), columns)
        })
        .collect::<BTreeMap<_, _>>();
    let assets = asset_map(assets, errors);
    for entity in sources.values() {
        for derived in &entity.derived {
            let path = format!("recordTypes[{}].derived[{}].sql", entity.id, derived.id);
            let owner = origins
                .get(&(entity.id.clone(), derived.id.clone()))
                .cloned()
                .flatten();
            let Some(sql) = assets.get(&(owner.clone(), derived.sql.clone())) else {
                errors.push(Diagnostic::error(
                    "breg.derived.sql-asset-missing",
                    path,
                    "derived SQL must be supplied as a compilation asset",
                ));
                continue;
            };
            validate_derived_sql(
                derived,
                sql,
                &source_columns,
                &encrypted_columns,
                &path,
                errors,
            );
        }
    }
}

fn asset_map<'a>(
    assets: &'a [ModuleAssetSource],
    errors: &mut Vec<Diagnostic>,
) -> BTreeMap<(Option<String>, String), &'a [u8]> {
    let mut map = BTreeMap::new();
    for asset in assets {
        // WASM handler modules are sized against their own budget at handler
        // admission, which owns the diagnostic naming the action and the
        // ceiling; every other asset family is bounded here.
        let bytes_within_bound = if asset.path.ends_with(".wasm") {
            true
        } else {
            asset.bytes.len() <= usize::try_from(MAX_STRUCTURED_VALUE_BYTES).unwrap_or(usize::MAX)
        };
        if asset.module.as_deref().is_some_and(str::is_empty)
            || !(valid_relative_asset_path(&asset.path)
                || (asset.module.is_none()
                    && crate::action_evidence_contracts::valid_contract_path(&asset.path)))
            || asset.bytes.is_empty()
            || !bytes_within_bound
        {
            errors.push(Diagnostic::error(
                "breg.module.asset-invalid",
                "modules[].assets[]",
                "assets must be bounded relative SQL, Rhai, or project Evidence contract files",
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
                "breg.module.asset-duplicate",
                "modules[].assets[]",
                "module assets must be unique by module and path",
            ));
        }
    }
    map
}

fn valid_relative_asset_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && (path.ends_with(".sql") || path.ends_with(".rhai") || path.ends_with(".wasm"))
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(crate) fn hook_retry_delays(
    initial_ms: u32,
    maximum_ms: u32,
    maximum_attempts: u8,
) -> Vec<u32> {
    registry_platform_hooks::exponential_retry_delays_ms(
        initial_ms,
        maximum_ms,
        u32::from(HOOK_BACKOFF_MULTIPLIER),
        maximum_attempts,
    )
}

/// Projects one entity's slice out of a whole-project `(entity_id, item_id) ->
/// Option<module>` origin map, keeping only the ids that a module (rather
/// than the project root) contributed.
fn member_origins_for_entity(
    origins: &EntityMemberOriginMap,
    entity_id: &str,
) -> BTreeMap<String, String> {
    origins
        .iter()
        .filter_map(|((owner, member_id), module)| {
            if owner == entity_id {
                module.clone().map(|module| (member_id.clone(), module))
            } else {
                None
            }
        })
        .collect()
}

fn compile_generated_identifier(source: &FieldGenerationSource) -> CompiledGeneratedIdentifier {
    let (strategy, prefix, scope) = match source {
        FieldGenerationSource::Sequence {
            prefix,
            minimum_digits,
            scope,
        } => (
            CompiledGeneratedIdentifierStrategy::Sequence {
                minimum_digits: *minimum_digits,
            },
            prefix.clone(),
            scope.iter().cloned().collect(),
        ),
        FieldGenerationSource::Random { prefix, length } => (
            CompiledGeneratedIdentifierStrategy::Random { length: *length },
            prefix.clone(),
            Vec::new(),
        ),
    };
    CompiledGeneratedIdentifier {
        strategy,
        prefix,
        scope,
    }
}

fn compile_entities(
    sources: &BTreeMap<String, EntitySource>,
    origins: &CollectedOrigins,
    assets: &[ModuleAssetSource],
) -> Result<(BTreeMap<String, CompiledEntity>, PhysicalNameInventory), CompileFailure> {
    let mut builder = PhysicalNameBuilder::new();
    let mut entities = BTreeMap::new();
    let mut inventory = BTreeMap::new();
    let reference_targets = sources
        .values()
        .flat_map(|source| &source.fields)
        .filter_map(|field| match &field.field_type {
            FieldTypeSource::Reference { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let asset_lookup = assets
        .iter()
        .map(|asset| ((asset.module.clone(), asset.path.clone()), asset))
        .collect::<BTreeMap<_, _>>();
    for source in sources.values() {
        let table = builder
            .derive("e", &source.id, "recordTypes[].id")
            .map_err(CompileFailure::from_one)?;
        let mut field_names = BTreeMap::new();
        let mut fields = BTreeMap::new();
        let mut stored_fields = Vec::new();
        for field in source.fields.clone() {
            // An encrypted field stores an envelope column ("x") instead of
            // the plaintext column ("f"); the field's physical name always
            // points at its storage column.
            let physical = builder
                .derive(
                    if field.encrypted { "x" } else { "f" },
                    &format!("{}.{}", source.id, field.id),
                    "recordTypes[].fields[].id",
                )
                .map_err(CompileFailure::from_one)?;
            let encryption = if field.encrypted {
                let blind_index = match &field.lookup {
                    Some(lookup) => {
                        let blind_physical = builder
                            .derive(
                                "i",
                                &format!("{}.{}", source.id, field.id),
                                "recordTypes[].fields[].lookup",
                            )
                            .map_err(CompileFailure::from_one)?;
                        // Bind the blind-index sibling column for reviewed
                        // migrations the same way fields bind, under a member
                        // id that cannot collide with a field id.
                        field_names.insert(format!("{}#lookup", field.id), blind_physical.clone());
                        Some(CompiledBlindIndex {
                            physical_name: blind_physical,
                            normalization: lookup.normalization.clone(),
                            unique: lookup.unique,
                        })
                    }
                    None => None,
                };
                Some(CompiledFieldEncryption { blind_index })
            } else {
                None
            };
            field_names.insert(field.id.clone(), physical.clone());
            let mut logical = logical_field(
                &field.id,
                field.api_name.as_deref(),
                field.field_type.clone(),
                field.classification,
            );
            logical.encryption = encryption.clone();
            let generate = field.generate.as_ref().map(compile_generated_identifier);
            stored_fields.push(CompiledStoredField {
                logical: logical.clone(),
                required: field.required || generate.is_some(),
                valid_time_role: field.valid_time_role,
                physical_name: physical.clone(),
            });
            fields.insert(
                field.id.clone(),
                CompiledField {
                    display: field.display,
                    relationship: field.relationship,
                    id: field.id,
                    field_type: field.field_type,
                    pattern: field.pattern,
                    required: field.required || generate.is_some(),
                    classification: field.classification,
                    valid_time_role: field.valid_time_role,
                    physical_name: physical,
                    encryption,
                    generate,
                },
            );
        }
        let mut derived_fields = BTreeMap::new();
        let mut derived_relations = BTreeMap::new();
        for derived in &source.derived {
            let owner = origins
                .derived
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
                        display: field.display.clone(),
                        derivation_id: derived.id.clone(),
                    },
                );
            }
            let dependencies = derived_sql_dependencies(&asset.bytes);
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
                    source_entities: dependencies
                        .source_relations
                        .into_iter()
                        .filter_map(|relation| {
                            sources.values().find_map(|candidate| {
                                (canonical_sql_name(&candidate.id) == relation)
                                    .then(|| candidate.id.clone())
                            })
                        })
                        .collect(),
                    uses_evaluation_date: dependencies.uses_evaluation_date,
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
            sql_name: canonical_sql_name(&source.id),
            // Encrypted columns never surface through registry_source views:
            // the logical source layer exposes plaintext columns only.
            stored_fields: stored_fields
                .iter()
                .filter(|field| field.logical.encryption.is_none())
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
        if reference_targets.contains(source.id.as_str()) {
            constraint_names.insert(
                "active-reference-key:record-lifecycle".to_owned(),
                builder
                    .derive("rk", &source.id, "recordTypes[].fields[].target")
                    .map_err(CompileFailure::from_one)?,
            );
        }
        for constraint in &source.constraints {
            let id = derived_constraint_id(constraint);
            let physical = builder
                .derive(
                    "c",
                    &format!("{}.{}", source.id, id),
                    "recordTypes[].constraints[]",
                )
                .map_err(CompileFailure::from_one)?;
            constraint_names.insert(id.clone(), physical);
            constraints.insert(id, normalized_constraint(constraint));
        }
        for field in source
            .fields
            .iter()
            .filter(|field| field.generate.is_some())
        {
            let id = format!("generated:{}", field.id);
            let mut constraint_fields = field
                .generate
                .as_ref()
                .expect("filtered generated field")
                .scope()
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            constraint_fields.push(field.id.clone());
            constraint_names.insert(
                id.clone(),
                builder
                    .derive(
                        "c",
                        &format!("{}.{}", source.id, id),
                        "recordTypes[].fields[].generate",
                    )
                    .map_err(CompileFailure::from_one)?,
            );
            constraints.insert(
                id.clone(),
                ConstraintSource::Unique {
                    id: Some(id),
                    fields: constraint_fields,
                    when: None,
                },
            );
        }
        for field in &source.fields {
            if field.pattern.is_some() {
                constraint_names.insert(
                    format!("pattern:{}", field.id),
                    crate::generated_ddl::field_pattern_constraint_name(&source.id, &field.id),
                );
            }
            if matches!(field.field_type, FieldTypeSource::Reference { .. }) {
                let id = format!("reference:{}", field.id);
                let physical = builder
                    .derive(
                        "r",
                        &format!("{}.{}", source.id, field.id),
                        "recordTypes[].fields[].target",
                    )
                    .map_err(CompileFailure::from_one)?;
                constraint_names.insert(id, physical);
                constraint_names.insert(
                    format!("active-reference:{}", field.id),
                    builder
                        .derive(
                            "ar",
                            &format!("{}.{}", source.id, field.id),
                            "recordTypes[].fields[].target",
                        )
                        .map_err(CompileFailure::from_one)?,
                );
            }
        }
        let mut indexes = BTreeMap::new();
        let mut index_names = BTreeMap::new();
        for index in &source.indexes {
            let physical = builder
                .derive(
                    "i",
                    &format!("{}.{}", source.id, index.id),
                    "recordTypes[].indexes[].id",
                )
                .map_err(CompileFailure::from_one)?;
            index_names.insert(index.id.clone(), physical);
            indexes.insert(index.id.clone(), index.fields.clone());
        }
        for field in &source.fields {
            if field.lookup.as_ref().is_some_and(|lookup| lookup.unique) {
                // The unique blind index carries a content-addressed managed
                // name, bound like authored indexes for reviewed migrations.
                index_names.insert(
                    format!("lookup:{}", field.id),
                    crate::generated_ddl::field_lookup_index_name(&source.id, &field.id),
                );
            }
        }
        for field in &source.fields {
            // A reference column is where the foreign key's delete check and
            // read-path joins look rows up, so it carries a compiler-owned
            // btree index unless an authored index or a whole-table unique
            // constraint already leads with it. The reserved member id cannot
            // collide with an authored index id.
            if !matches!(field.field_type, FieldTypeSource::Reference { .. })
                || leading_field_indexed(&field.id, &indexes, &constraints)
            {
                continue;
            }
            let physical = builder
                .derive(
                    "ri",
                    &format!("{}.{}", source.id, field.id),
                    "recordTypes[].fields[].target",
                )
                .map_err(CompileFailure::from_one)?;
            let id = format!("{REFERENCE_INDEX_PREFIX}{}", field.id);
            index_names.insert(id.clone(), physical);
            indexes.insert(id, vec![field.id.clone()]);
        }
        let mut profiles = BTreeMap::new();
        let mut policy_names = BTreeMap::new();
        for access in &source.access_profiles {
            let physical = builder
                .derive(
                    "p",
                    &format!("{}.{}", source.id, access.id),
                    "recordTypes[].accessProfiles[].id",
                )
                .map_err(CompileFailure::from_one)?;
            policy_names.insert(access.id.clone(), physical);
            let mut profile = access.clone();
            if let Some(bbox) = profile
                .spatial_queries
                .as_mut()
                .and_then(|spatial| spatial.bbox.as_mut())
            {
                // Signed package JSON normalizes 1.0 to 1. Normalize before
                // equality and migration planning so reloading that package
                // cannot turn equivalent limits into an access change.
                bbox.maximum_longitude_span_degrees =
                    canonical_spatial_span(&bbox.maximum_longitude_span_degrees);
                bbox.maximum_latitude_span_degrees =
                    canonical_spatial_span(&bbox.maximum_latitude_span_degrees);
            }
            profiles.insert(access.id.clone(), profile);
        }
        let hooks = source
            .hooks
            .iter()
            .map(|hook| (hook.id.clone(), hook.clone()))
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
        let source_module = origins.entities.get(&source.id).cloned().flatten();
        let module_origins = CompiledEntityModuleOrigins {
            fields: member_origins_for_entity(&origins.fields, &source.id),
            constraints: member_origins_for_entity(&origins.constraints, &source.id),
            hooks: member_origins_for_entity(&origins.hooks, &source.id),
            derived_relations: member_origins_for_entity(&origins.derived, &source.id),
            indexes: member_origins_for_entity(&origins.indexes, &source.id),
            access_profiles: member_origins_for_entity(&origins.access_profiles, &source.id),
            selector_profiles: member_origins_for_entity(&origins.selector_profiles, &source.id),
            timers: member_origins_for_entity(&origins.timers, &source.id),
            read_paths: member_origins_for_entity(&origins.read_paths, &source.id),
        };
        entities.insert(
            source.id.clone(),
            CompiledEntity {
                api_name: source
                    .api_name
                    .clone()
                    .unwrap_or_else(|| type_api_name(&source.id)),
                display: source.display.display(),
                grouping: source.display.grouping(),
                event_record: None,
                definition_revision: record_definition_revision(source, &constraints),
                id: source.id.clone(),
                source_module,
                primary_dataset: Some(source.primary_dataset.clone()),
                route: source.route.clone(),
                mutation_mode: source.mutation_mode.clone(),
                tombstone: source.tombstone,
                batch: source.batch.clone(),
                classification: source.classification,
                access_requirements: source.access_requirements.clone(),
                access_log: source.access_log.clone(),
                geojson: source
                    .geojson
                    .as_ref()
                    .map(|geojson| CompiledGeoJsonBinding {
                        geometry_field: geojson.geometry_field.clone(),
                    }),
                physical_table: table,
                temporal: source
                    .temporal
                    .as_ref()
                    .and_then(CompiledTemporal::from_source),
                canonical_id,
                stored_fields,
                derived_fields,
                derived_relations,
                source_relation,
                selector_profiles,
                timers: BTreeMap::new(),
                read_paths,
                change_control: source.mutation_policy.clone().map(|change_control| {
                    CompiledChangeControl {
                        required_for: change_control.proposal_required_operations(),
                    }
                }),
                relationships: BTreeMap::new(),
                fields,
                constraints,
                indexes,
                access_profiles: profiles,
                membership_boundaries: BTreeMap::new(),
                consent_record: None,
                consent_requirements: BTreeMap::new(),
                hooks,
                module_origins,
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
    let errors = Vec::new();
    for entity in entities.values() {
        for operation in routed_operations() {
            if matches!(operation, Operation::Batch | Operation::Import) && entity.batch.is_none() {
                continue;
            }
            let profiles: Vec<&AccessProfileSource> = entity
                .access_profiles
                .values()
                .filter(|profile| {
                    profile.operations.contains(&operation)
                        && (operation != Operation::Revisions || profile.revision_access)
                })
                .collect();
            if profiles.is_empty() {
                continue;
            }
            let default = route_default_profile(&profiles);
            let profile_ids: BTreeSet<String> =
                profiles.iter().map(|profile| profile.id.clone()).collect();
            let (method, path) = route_shape(entity, operation);
            let route = CompiledRoute {
                id: format!("records.{}.{}", entity.id, operation_id(operation)),
                entity_id: entity.id.clone(),
                method,
                path,
                operation,
                query_kind: if operation == Operation::List {
                    Some(CompiledQueryKind::List)
                } else if operation == Operation::Snapshot {
                    Some(CompiledQueryKind::Snapshot)
                } else {
                    None
                },
                revision_kind: None,
                maximum_records: None,
                access_profiles: profile_ids.iter().cloned().collect(),
                default_access_profile: default.map(|profile| profile.id.clone()),
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
                        maximum_records: None,
                        access_profiles: profile_ids.iter().cloned().collect(),
                        default_access_profile: default.map(|profile| profile.id.clone()),
                    });
                }
            }
            entries.push(CompiledAccessEntry {
                route_id: format!("records.{}.{}", entity.id, operation_id(operation)),
                entity_id: entity.id.clone(),
                operation,
                profile_ids,
                default_profile_id: default.map(|profile| profile.id.clone()),
            });
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
            let default = route_default_profile(&profiles);
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
                maximum_records: None,
                access_profiles: profile_ids.iter().cloned().collect(),
                default_access_profile: default.map(|profile| profile.id.clone()),
            });
            entries.push(CompiledAccessEntry {
                route_id,
                entity_id: entity.id.clone(),
                operation: Operation::List,
                profile_ids,
                default_profile_id: default.map(|profile| profile.id.clone()),
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

fn route_default_profile<'a>(
    profiles: &[&'a AccessProfileSource],
) -> Option<&'a AccessProfileSource> {
    if profiles.len() == 1 {
        Some(profiles[0])
    } else {
        profiles.iter().copied().find(|profile| profile.default)
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
                    provenance_fields: if route.operation == Operation::Revisions {
                        profile.provenance_fields.clone()
                    } else {
                        Vec::new()
                    },
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
            route.operation != Operation::Snapshot
                || response_entity.fields.contains_key(field.as_str())
        })
        .cloned()
        .collect();
    Some((response_entity, readable_fields))
}

fn inconsistent_metadata_inventory() -> Diagnostic {
    Diagnostic::error(
        "breg.metadata-inventory.inconsistent",
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
                (entity.id.clone(), CompiledQueryKind::Snapshot),
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
                        stored_only: false,
                    },
                    errors,
                ) {
                    operations.push(operation);
                }
                if let Some(temporal) = &entity.temporal {
                    let Some(binding) = temporal_binding(entity, temporal) else {
                        continue;
                    };
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
                            stored_only: false,
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
                            stored_only: false,
                        },
                        errors,
                    ) {
                        operations.push(operation);
                    }
                }
            }
            if profile.operations.contains(&Operation::Snapshot) {
                let binding = entity
                    .temporal
                    .as_ref()
                    .and_then(|temporal| temporal_binding(entity, temporal));
                if let Some(operation) = query_operation(
                    QueryOperationInput {
                        entity,
                        profile,
                        route_id: &route_ids[&(entity.id.clone(), CompiledQueryKind::Snapshot)],
                        kind: CompiledQueryKind::Snapshot,
                        temporal: binding,
                        allow_count: profile.allow_count,
                        selector_fields: Vec::new(),
                        read_path: None,
                        stored_only: true,
                    },
                    errors,
                ) {
                    operations.push(operation);
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
                                stored_only: false,
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

/// A list filter or sort over a stored field that no index leads with scans
/// the table on every page. Production compiles stay silent: the entity may
/// be small, and only its author knows.
fn unindexed_list_findings(entities: &BTreeMap<String, CompiledEntity>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for entity in entities.values() {
        for profile in entity.access_profiles.values() {
            let path = format!(
                "recordTypes[id={}].accessProfiles[id={}]",
                entity.id, profile.id
            );
            if profile.operations.contains(&Operation::List) {
                unindexed_field_findings(
                    entity,
                    &path,
                    &profile.filterable_fields,
                    &profile.sortable_fields,
                    &mut findings,
                );
            }
            for grant in &profile.read_paths {
                let Some(target) = entity
                    .read_paths
                    .get(&grant.path)
                    .and_then(|path| entities.get(&path.to))
                else {
                    continue;
                };
                unindexed_field_findings(
                    target,
                    &format!("{path}.readPaths[path={}]", grant.path),
                    &grant.filterable_fields,
                    &grant.sortable_fields,
                    &mut findings,
                );
            }
        }
    }
    findings
}

fn unindexed_field_findings<'a>(
    entity: &CompiledEntity,
    path: &str,
    filterable_fields: impl IntoIterator<Item = &'a String>,
    sortable_fields: impl IntoIterator<Item = &'a String>,
    findings: &mut Vec<Diagnostic>,
) {
    // A consent record's compiler-generated key index (see
    // `consent::index_statements`) always leads with its scope column, so a
    // filter or sort on the scope field already has an index to lean on even
    // without an authored one.
    let consent_scope_indexed = |field: &str| {
        entity.consent_record.as_ref().is_some_and(|record| {
            entity
                .fields
                .get(field)
                .is_some_and(|compiled| compiled.physical_name == record.scope_column)
        })
    };
    // Only plaintext stored columns can carry an authored index; the
    // canonical id is the primary key, and derived fields are views.
    let unindexed = |field: &str| {
        entity
            .fields
            .get(field)
            .is_some_and(|compiled| compiled.encryption.is_none())
            && !leading_field_indexed_for_list_finding(field, &entity.indexes, &entity.constraints)
            && !consent_scope_indexed(field)
    };
    // A temporal exclusion constraint is backed by a GiST index that answers
    // equality on its first scope field but cannot return rows in order.
    let exclusion_leading = |field: &str| {
        entity.constraints.values().any(|constraint| {
            matches!(
                constraint,
                ConstraintSource::TemporalNonOverlap { scope_fields, .. }
                    if scope_fields.first().is_some_and(|first| first == field)
            )
        })
    };
    for field in filterable_fields {
        if unindexed(field) && !exclusion_leading(field) {
            findings.push(Diagnostic::finding(
                "breg.record-type.list-unindexed-filter",
                format!("{path}.filterableFields[field={field}]"),
                "no index leads with this filterable field, so a filtered list scans every row the caller may read. If this Record type will hold more than a few thousand rows, declare an index that leads with the field under recordTypes[].indexes",
            ));
        }
    }
    for field in sortable_fields {
        if unindexed(field) {
            findings.push(Diagnostic::finding(
                "breg.record-type.list-unindexed-sort",
                format!("{path}.sortableFields[field={field}]"),
                "no index leads with this sortable field, so a sorted list orders every row the caller may read before returning a page. If this Record type will hold more than a few thousand rows, declare an index that leads with the field under recordTypes[].indexes",
            ));
        }
    }
}

fn read_path_query_operation(
    source: &CompiledEntity,
    target: &CompiledEntity,
    profile: &AccessProfileSource,
    grant: &ReadPathPermissionSource,
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
        spatial: None,
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
    stored_only: bool,
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
        stored_only,
    } = input;
    if let Some(binding) = &temporal {
        let temporal_fields = [&binding.start_field, &binding.end_field];
        let mut missing = false;
        for field in temporal_fields
            .into_iter()
            .filter(|field| !profile.readable_fields.contains(field.as_str()))
        {
            errors.push(Diagnostic::error(
                "breg.query.temporal-field-not-readable",
                format!(
                    "recordTypes[id={}].accessProfiles[id={}].readableFields",
                    entity.id, profile.id
                ),
                &format!(
                    "access profile `{}` must include temporal boundary field `{field}` in readableFields",
                    profile.id
                ),
            ));
            missing = true;
        }
        if missing {
            return None;
        }
    }

    let mut projection_fields = profile
        .readable_fields
        .iter()
        .filter(|field| !stored_only || entity.fields.contains_key(field.as_str()))
        .cloned()
        .collect::<Vec<String>>();
    projection_fields.sort();
    let filter_fields = profile
        .filterable_fields
        .iter()
        .filter(|field| !stored_only || entity.fields.contains_key(field.as_str()))
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(entity, field)?;
            query_filter_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let sort_fields = profile
        .sortable_fields
        .iter()
        .filter(|field| !stored_only || entity.fields.contains_key(field.as_str()))
        .filter_map(|field| {
            let (field_type, _) = compiled_field_type(entity, field)?;
            query_sort_field(field_type, field, errors)
        })
        .collect::<Vec<_>>();
    let mut processing_fields = projection_fields.iter().cloned().collect::<BTreeSet<_>>();
    processing_fields.extend(
        profile
            .filterable_fields
            .iter()
            .filter(|field| !stored_only || entity.fields.contains_key(field.as_str()))
            .cloned(),
    );
    processing_fields.extend(
        profile
            .sortable_fields
            .iter()
            .filter(|field| !stored_only || entity.fields.contains_key(field.as_str()))
            .cloned(),
    );
    processing_fields.extend(selector_fields.iter().cloned());
    processing_fields.extend(
        profile
            .row_boundaries
            .iter()
            .map(|boundary| boundary.field.clone()),
    );
    let spatial =
        if kind == CompiledQueryKind::List && temporal.is_none() && selector_fields.is_empty() {
            compiled_spatial_capability(entity, profile)
        } else {
            None
        };
    if let Some(geometry_field) = spatial
        .as_ref()
        .and_then(|capability| capability.bbox.as_ref())
        .map(|bbox| bbox.geometry_field.clone())
    {
        processing_fields.insert(geometry_field);
    }
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
        spatial,
        temporal,
    })
}

fn canonical_spatial_span(value: &serde_json::Number) -> serde_json::Number {
    let bytes = canonicalize_json(&Value::Number(value.clone()))
        .expect("validated spatial span canonicalizes");
    serde_json::from_slice(&bytes).expect("canonical spatial span remains a JSON number")
}

fn compiled_spatial_capability(
    entity: &CompiledEntity,
    profile: &AccessProfileSource,
) -> Option<CompiledSpatialQueryCapability> {
    let SpatialQueryPermissionSource {
        bbox:
            Some(SpatialBboxPermissionSource {
                maximum_longitude_span_degrees,
                maximum_latitude_span_degrees,
            }),
    } = profile.spatial_queries.as_ref()?
    else {
        return None;
    };
    let geojson = entity.geojson.as_ref()?;
    Some(CompiledSpatialQueryCapability {
        bbox: Some(CompiledBboxQueryCapability {
            geometry_field: geojson.geometry_field.clone(),
            maximum_longitude_span_degrees: maximum_longitude_span_degrees.clone(),
            maximum_latitude_span_degrees: maximum_latitude_span_degrees.clone(),
        }),
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
        FieldTypeSource::Crs84Point { .. } => {
            errors.push(Diagnostic::error(
                "breg.query.filter-field-type-unsupported",
                "recordTypes[].accessProfiles[].filterableFields",
                "CRS84 point fields cannot be filterableFields; use spatialQueries.bbox for bounded spatial search",
            ));
            return None;
        }
        FieldTypeSource::Structured { .. } => {
            errors.push(Diagnostic::error(
                "breg.query.filter-field-type-unsupported",
                "recordTypes[].accessProfiles[].filterableFields",
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
        sql_name: canonical_sql_name(id),
        field_type,
        classification,
        // Only stored fields can be encrypted; derived fields and the canonical
        // id stay plaintext, and the authoring contract refuses `encrypted` on
        // derived fields at deserialization.
        encryption: None,
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
    if matches!(field_type, FieldTypeSource::Crs84Point { .. }) {
        errors.push(Diagnostic::error(
            "breg.query.sort-field-type-unsupported",
            "recordTypes[].accessProfiles[].sortableFields",
            "CRS84 point fields cannot be sortableFields; use spatialQueries.bbox for bounded spatial search",
        ));
        return None;
    }
    if matches!(field_type, FieldTypeSource::Structured { .. }) {
        errors.push(Diagnostic::error(
            "breg.query.sort-field-type-unsupported",
            "recordTypes[].accessProfiles[].sortableFields",
            "a query sort field must use a supported scalar type",
        ));
        return None;
    }
    Some(CompiledQuerySortField {
        field: field.to_owned(),
        directions: vec![CompiledQuerySortDirection::Asc],
    })
}

pub(crate) fn temporal_binding(
    entity: &CompiledEntity,
    temporal: &CompiledTemporal,
) -> Option<CompiledQueryTemporalBinding> {
    let start = entity.fields.get(&temporal.start_field)?;
    let value_kind = match start.field_type {
        FieldTypeSource::Date => crate::model::CompiledQueryTemporalValueKind::Date,
        FieldTypeSource::Timestamp => crate::model::CompiledQueryTemporalValueKind::Timestamp,
        _ => return None,
    };
    Some(CompiledQueryTemporalBinding {
        start_field: temporal.start_field.clone(),
        end_field: temporal.end_field.clone(),
        value_kind,
        semantics: if temporal.last_day {
            CompiledQueryTemporalSemantics::StartInclusiveLastDayInclusive
        } else {
            CompiledQueryTemporalSemantics::StartInclusiveEndExclusive
        },
    })
}

fn query_kind_id(kind: CompiledQueryKind) -> &'static str {
    match kind {
        CompiledQueryKind::List => "list",
        CompiledQueryKind::Current => "current",
        CompiledQueryKind::AsOf => "as-of",
        CompiledQueryKind::Snapshot => "snapshot",
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
        Operation::Snapshot => (HttpMethod::Get, format!("{base}:snapshot")),
        // The ingestion-run surface is the only place an import grant is
        // exercised; the HTTP router never mounts this route directly.
        Operation::Import => (HttpMethod::Post, format!("{base}/ingestion-runs")),
        Operation::Invoke | Operation::Start => {
            unreachable!("Actions use compiled action metadata")
        }
    }
}

fn routed_operations() -> [Operation; 10] {
    [
        Operation::Create,
        Operation::Get,
        Operation::Lookup,
        Operation::List,
        Operation::Patch,
        Operation::Tombstone,
        Operation::Batch,
        Operation::Revisions,
        Operation::Snapshot,
        Operation::Import,
    ]
}

fn all_operations() -> [Operation; 11] {
    [
        Operation::Create,
        Operation::Get,
        Operation::Lookup,
        Operation::List,
        Operation::Patch,
        Operation::Tombstone,
        Operation::Batch,
        Operation::Revisions,
        Operation::Snapshot,
        Operation::Invoke,
        Operation::Import,
    ]
}

/// Native Record writes are independent of Action and Proposal authority.
fn is_direct_target_mutation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::Create
            | Operation::Patch
            | Operation::Tombstone
            | Operation::Batch
            | Operation::Import
    )
}

pub(crate) fn operation_id(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Get => "get",
        Operation::Lookup => "lookup",
        Operation::List => "list",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::Snapshot => "snapshot",
        Operation::Invoke => "invoke",
        Operation::Start => "start",
        Operation::Import => "import",
    }
}

pub(crate) fn derived_constraint_id(constraint: &ConstraintSource) -> String {
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
            "breg.constraint.unique-when-empty",
            "recordTypes[].constraints[].when",
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
                        "breg.constraint.unique-when-duplicate",
                        "recordTypes[].constraints[].when",
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
                        "breg.constraint.unique-when-literal-invalid",
                        "recordTypes[].constraints[].when[].value",
                        "a partial unique literal must be canonical for the field type",
                    ));
                    continue;
                };
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-contradiction",
                        "recordTypes[].constraints[].when",
                        "partial unique predicates contain a contradiction",
                    ));
                }
                if state.is_not_null {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-duplicate",
                        "recordTypes[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if let Some(existing) = &state.equals {
                    errors.push(Diagnostic::error(
                        if existing == &canonical {
                            "breg.constraint.unique-when-duplicate"
                        } else {
                            "breg.constraint.unique-when-contradiction"
                        },
                        "recordTypes[].constraints[].when",
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
                        "breg.constraint.unique-when-null-invalid",
                        "recordTypes[].constraints[].when[].field",
                        "a partial unique null predicate must be useful for the field",
                    ));
                    continue;
                }
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-duplicate",
                        "recordTypes[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if state.is_not_null || state.equals.is_some() {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-contradiction",
                        "recordTypes[].constraints[].when",
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
                        "breg.constraint.unique-when-null-invalid",
                        "recordTypes[].constraints[].when[].field",
                        "a partial unique null predicate must be useful for the field",
                    ));
                    continue;
                }
                let state = field_states.entry(field.as_str()).or_default();
                if state.is_not_null || state.equals.is_some() {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-duplicate",
                        "recordTypes[].constraints[].when",
                        "partial unique predicates must be duplicate-free",
                    ));
                }
                if state.is_null {
                    errors.push(Diagnostic::error(
                        "breg.constraint.unique-when-contradiction",
                        "recordTypes[].constraints[].when",
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
            "breg.constraint.unique-when-field-unknown",
            "recordTypes[].constraints[].when[].field",
            "a partial unique predicate refers to an unknown field",
        ));
        return None;
    };
    if matches!(
        source.field_type,
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }
    ) {
        errors.push(Diagnostic::error(
            "breg.constraint.unique-when-field-unsupported",
            "recordTypes[].constraints[].when[].field",
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
        UniqueWhenPredicate::FieldIsNull { field } => format!("field:{field}:is-null"),
        UniqueWhenPredicate::FieldIsNotNull { field } => format!("field:{field}:is-not-null"),
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
            "breg.identifier.invalid",
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
            "breg.project.default-language-invalid",
            "project.project.defaultLanguage",
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
            "breg.manifest-projection.text-empty",
            path,
            "Registry Manifest projection text and every localized value must not be empty",
        ));
    }
}

fn manifest_projects_field(field: &CompiledField) -> bool {
    // Encrypted storage has no portable plaintext representation, so the
    // dataset projection refuses it alongside the non-scalar types.
    field.encryption.is_none()
        && !matches!(
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

fn reject_system_profile_id(id: &str, path: &str, errors: &mut Vec<Diagnostic>) {
    if id == "system-proposal-apply" {
        errors.push(Diagnostic::error(
            "breg.access-profile.system-id-reserved",
            path,
            "this profile identifier is reserved for the built-in Proposal executor",
        ));
    }
}

fn type_api_name(id: &str) -> String {
    let mut name = crate::logical_names::default_api_name(id);
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    name
}
fn record_definition_revision(
    source: &EntitySource,
    constraints: &BTreeMap<String, ConstraintSource>,
) -> String {
    let fields = source
        .fields
        .iter()
        .map(|field| {
            let mut definition = serde_json::json!({
                "apiName": field.api_name,
                "type": field.field_type,
                "required": field.required || field.generate.is_some(),
                "pattern": field.pattern,
                "classification": field.classification,
                "encrypted": field.encrypted,
                "relationship": field.relationship,
            });
            if let Some(generate) = &field.generate {
                definition
                    .as_object_mut()
                    .expect("field definition is an object")
                    .insert(
                        "generate".to_owned(),
                        serde_json::to_value(generate).expect("generation source serializes"),
                    );
            }
            (&field.id, definition)
        })
        .collect::<BTreeMap<_, _>>();
    let payload = serde_json::json!({"id":source.id,"apiName":source.api_name.clone().unwrap_or_else(||type_api_name(&source.id)),"fields":fields,"mutationMode":source.mutation_mode,"mutationPolicy":source.mutation_policy,"constraints":constraints});
    let digest = Sha256::digest(
        registry_platform_canonical_json::canonicalize_json(&payload)
            .expect("Record definition canonicalizes"),
    );
    format!("sha256:{}", hex_prefix(&digest, digest.len()))
}

fn compile_relationships(
    entities: &mut BTreeMap<String, CompiledEntity>,
) -> Result<(), Vec<Diagnostic>> {
    use crate::model::{CompiledRelationship, RelationshipCardinality};
    let mut relationships = Vec::new();
    let mut errors = Vec::new();
    for entity in entities.values() {
        for stored in &entity.stored_fields {
            let field = &entity.fields[&stored.logical.id];
            let FieldTypeSource::Reference { target, .. } = &field.field_type else {
                continue;
            };
            let inverse_name = field
                .relationship
                .as_ref()
                .and_then(|relationship| relationship.inverse_name.clone());
            relationships.push((
                entity.id.clone(),
                CompiledRelationship {
                    name: stored.logical.api_name.clone(),
                    source_entity_id: entity.id.clone(),
                    target_entity_id: target.clone(),
                    field_id: field.id.clone(),
                    cardinality: if field.required {
                        RelationshipCardinality::One
                    } else {
                        RelationshipCardinality::OptionalOne
                    },
                    inverse: false,
                    inverse_name: inverse_name.clone(),
                    read_path: None,
                },
            ));
            if let Some(name) = inverse_name {
                let unique = entity.constraints.values().any(|constraint| matches!(constraint, ConstraintSource::Unique { fields, when, .. }
                    if fields.as_slice() == [field.id.as_str()] && when.as_ref().is_none_or(|predicates| predicates.as_slice() == [crate::contract::UniqueWhenPredicate::ActiveLifecycle {}])));
                relationships.push((
                    target.clone(),
                    CompiledRelationship {
                        name,
                        source_entity_id: target.clone(),
                        target_entity_id: entity.id.clone(),
                        field_id: field.id.clone(),
                        cardinality: if unique {
                            RelationshipCardinality::OptionalOne
                        } else {
                            RelationshipCardinality::Many
                        },
                        inverse: true,
                        inverse_name: Some(stored.logical.api_name.clone()),
                        read_path: None,
                    },
                ));
            }
        }
    }
    for (owner, relationship) in relationships {
        let Some(entity) = entities.get_mut(&owner) else {
            continue;
        };
        let collision = !crate::logical_names::valid_api_name(&relationship.name)
            || crate::logical_names::reserved_logical_name(&relationship.name)
            || entity.relationships.contains_key(&relationship.name)
            || (relationship.inverse
                && (entity.stored_fields.iter().any(|field| {
                    field.logical.id == relationship.name
                        || field.logical.api_name == relationship.name
                }) || entity.derived_fields.values().any(|field| {
                    field.logical.id == relationship.name
                        || field.logical.api_name == relationship.name
                })))
            || entity.read_paths.contains_key(&relationship.name);
        if collision {
            errors.push(Diagnostic::error("breg.relationship.name-collision", format!("recordTypes[id={owner}].relationships"), "forward and inverse relationship names must be unique nonreserved API names without field or read-path collisions"));
        } else {
            entity
                .relationships
                .insert(relationship.name.clone(), relationship);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
fn validate_native_definitions(project: &RegistryProject, errors: &mut Vec<Diagnostic>) {
    let mut datasets = BTreeSet::new();
    for dataset in &project.datasets {
        validate_id(&dataset.id, "datasets[].id", errors);
        if !datasets.insert(&dataset.id) {
            errors.push(Diagnostic::error(
                "breg.dataset.id-duplicate",
                "datasets[].id",
                "dataset identifiers must be unique",
            ));
        }
    }
    let mut record_names = BTreeSet::new();
    for record in &project.entities {
        if !datasets.contains(&record.primary_dataset) {
            errors.push(Diagnostic::error(
                "breg.record-type.dataset-unknown",
                "recordTypes[].primaryDataset",
                "primaryDataset must name a declared native dataset",
            ));
        }
        let name = record
            .api_name
            .clone()
            .unwrap_or_else(|| type_api_name(&record.id));
        if !name.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !record_names.insert(name)
        {
            errors.push(Diagnostic::error(
                "breg.record-type.api-name-invalid",
                format!("recordTypes[id={}].apiName", record.id),
                "Record type API names must be unique upper camel case names",
            ));
        }
        if record.display.title_field.as_ref().is_some_and(|id| {
            !record.fields.iter().any(|field| {
                &field.id == id
                    && matches!(
                        field.field_type,
                        FieldTypeSource::String { .. } | FieldTypeSource::Text { .. }
                    )
            })
        }) {
            errors.push(Diagnostic::error(
                "breg.record-type.title-field-invalid",
                "recordTypes[].display.titleField",
                "titleField must name a declared string or text field",
            ));
        }
        let mut relationships = BTreeSet::new();
        for field in &record.fields {
            if let Some(relationship) = &field.relationship {
                if !matches!(field.field_type, FieldTypeSource::Reference { .. }) {
                    errors.push(Diagnostic::error(
                        "breg.relationship.reference-required",
                        "recordTypes[].fields[].relationship",
                        "relationship metadata requires a reference field",
                    ));
                }
                if let Some(inverse) = &relationship.inverse_name {
                    if !crate::logical_names::valid_api_name(inverse)
                        || !relationships.insert(inverse)
                    {
                        errors.push(Diagnostic::error(
                            "breg.relationship.inverse-name-invalid",
                            "recordTypes[].fields[].relationship.inverseName",
                            "inverse names must be unique lower camel case names",
                        ));
                    }
                }
            }
        }
    }
    let mut action_names = BTreeSet::new();
    for action in &project.actions {
        let name = action
            .api_name
            .clone()
            .unwrap_or_else(|| crate::logical_names::default_api_name(&action.id));
        if !crate::logical_names::valid_api_name(&name)
            || crate::logical_names::reserved_logical_name(&name)
            || !action_names.insert(name)
        {
            errors.push(Diagnostic::error(
                "breg.action.api-name-invalid",
                "actions[].apiName",
                "Action API names must be unique nonreserved lower camel case names",
            ));
        }
    }
    let mut functions = BTreeSet::new();
    validate_local_value_types(&project.value_types, "valueTypes", errors);
    for function in &project.functions {
        validate_id(&function.id, "functions[].id", errors);
        if !functions.insert(&function.id)
            || !(1..=100000).contains(&function.limits.maximum_operations)
            || !(1..=1048576).contains(&function.limits.maximum_output_bytes)
        {
            errors.push(Diagnostic::error(
                "breg.function.contract-invalid",
                "functions[]",
                "functions require unique IDs and bounded positive execution/output limits",
            ));
        }
    }
    let mut authorities = BTreeSet::new();
    for authority in &project.review_authorities {
        validate_id(&authority.id, "reviewAuthorities[].id", errors);
        if !authorities.insert(&authority.id) {
            errors.push(Diagnostic::error(
                "breg.review-authority.id-duplicate",
                "reviewAuthorities[].id",
                "review authority IDs must be unique",
            ));
        }
    }
    for profile in &project.access_profiles {
        for grant in &profile.permissions.proposals {
            if !project
                .actions
                .iter()
                .any(|action| action.id == grant.action && action.is_proposal())
            {
                errors.push(Diagnostic::error(
                    "breg.proposal.permission-action-unknown",
                    "accessProfiles[].permissions.proposals[].action",
                    "Proposal grants must name a proposal-mode Action",
                ));
            }
        }
    }
}

fn validate_local_value_types(
    value_types: &BTreeMap<String, FieldTypeSource>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    for (id, field_type) in value_types {
        validate_id(id, path, errors);
        if matches!(
            field_type,
            FieldTypeSource::Reference { .. }
                | FieldTypeSource::Structured { .. }
                | FieldTypeSource::Crs84Point { .. }
        ) {
            errors.push(Diagnostic::error(
                "breg.value-type.scalar-required",
                format!("{path}.{id}"),
                "local value types declare reusable scalar constraints",
            ));
        }
        if !matches!(field_type, FieldTypeSource::VocabularyCode { .. }) {
            validate_field_type_bounds(field_type, &format!("{path}.{id}"), errors);
        }
    }
}
