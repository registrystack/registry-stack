// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::{
    EventTrigger, FieldTypeSource, HookSource, MutationMode, Operation, ProvenanceFieldSource,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::manifest_adapter::project_manifest_artifacts;
use crate::model::{
    ActionRouteKind, CompiledAccessInventory, CompiledAction, CompiledActionInput,
    CompiledActionInventory, CompiledActionRoute, CompiledEntity, CompiledEventDeliveryInventory,
    CompiledManifestProjection, CompiledMetadataInventory, CompiledModuleIdentity,
    CompiledQueryInventory, CompiledQueryKind, CompiledQueryOperation,
    CompiledQueryTemporalValueKind, CompiledRecipients, CompiledRevisionKind, CompiledRoute,
    CompiledRouteInventory, CompiledStatisticalDataset, HttpMethod,
};
use crate::physical_names::{hex_prefix, PhysicalNameInventory};
use crate::record_profile::{link_header_value, CONTEXT_IDENTIFIER, PROFILE_IDENTIFIER};

#[path = "project_sdk.rs"]
mod project_sdk;
#[path = "proposal_artifacts.rs"]
mod proposal_artifacts;
pub(crate) use proposal_artifacts::append_proposal_openapi;

pub const REGISTRY_METADATA_ARTIFACT_PATH: &str = "generated/metadata/registry.json";
pub const ACTION_CONTRACTS_API_VERSION: &str =
    "id.registrystack.org/formats/breg/action-contracts/v1";
pub const ACTION_CONTRACTS_KIND: &str = "BRegActionContracts";

pub(crate) struct EventDataSchemaBinding {
    pub schema: Value,
    pub fingerprint: String,
    pub data_schema: String,
    pub artifact_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratedArtifact {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GeneratedArtifacts {
    artifacts: BTreeMap<String, GeneratedArtifact>,
}

impl GeneratedArtifacts {
    pub fn entries(&self) -> &BTreeMap<String, GeneratedArtifact> {
        &self.artifacts
    }

    pub fn get(&self, path: &str) -> Option<&GeneratedArtifact> {
        self.artifacts.get(path)
    }

    pub fn canonical_inventory_bytes(&self) -> Result<Vec<u8>, Diagnostic> {
        let value = serde_json::to_value(self).map_err(|_| canonicalization_error())?;
        canonicalize_json(&value).map_err(|_| canonicalization_error())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EffectiveModel<'a> {
    pub registry_id: &'a str,
    pub version: &'a str,
    pub default_language: &'a str,
    #[serde(skip_serializing_if = "crate::model::display_is_empty")]
    pub display: &'a crate::contract::DisplaySource,
    #[serde(skip_serializing_if = "<[crate::contract::ReviewAuthoritySource]>::is_empty")]
    pub review_authorities: &'a [crate::contract::ReviewAuthoritySource],
    pub datasets: &'a [crate::contract::DatasetSource],
    pub access_profiles: &'a [crate::model::CompiledAccessProfileDisplay],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_projection: Option<&'a CompiledManifestProjection>,
    pub module_order: &'a [String],
    pub module_closure: &'a [CompiledModuleIdentity],
    #[serde(rename = "recordTypes")]
    pub entities: &'a BTreeMap<String, CompiledEntity>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub statistical_datasets: &'a BTreeMap<String, CompiledStatisticalDataset>,
    pub physical_names: &'a PhysicalNameInventory,
    #[serde(skip_serializing_if = "CompiledActionInventory::is_empty")]
    pub action_inventory: &'a CompiledActionInventory,
    pub metadata_inventory: &'a CompiledMetadataInventory,
    pub query_inventory: &'a CompiledQueryInventory,
    pub event_delivery_inventory: &'a CompiledEventDeliveryInventory,
    #[serde(skip_serializing_if = "CompiledRecipients::is_empty")]
    pub recipients: &'a CompiledRecipients,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_artifacts(
    registry_id: &str,
    version: &str,
    default_language: &str,
    display: &crate::contract::DisplaySource,
    review_authorities: &[crate::contract::ReviewAuthoritySource],
    datasets: &[crate::contract::DatasetSource],
    access_profiles: &[crate::model::CompiledAccessProfileDisplay],
    manifest_projection: Option<&CompiledManifestProjection>,
    module_order: &[String],
    module_closure: &[CompiledModuleIdentity],
    entities: &BTreeMap<String, CompiledEntity>,
    statistical_datasets: &BTreeMap<String, CompiledStatisticalDataset>,
    physical_names: &PhysicalNameInventory,
    actions: &CompiledActionInventory,
    routes: &CompiledRouteInventory,
    access: &CompiledAccessInventory,
    metadata: &CompiledMetadataInventory,
    query: &CompiledQueryInventory,
    event_deliveries: &CompiledEventDeliveryInventory,
    recipients: &CompiledRecipients,
    ddl: &DdlInventory,
) -> Result<GeneratedArtifacts, Diagnostic> {
    let mut artifacts = BTreeMap::new();
    let effective_model = EffectiveModel {
        registry_id,
        version,
        default_language,
        display,
        review_authorities,
        datasets,
        access_profiles,
        manifest_projection,
        module_order,
        module_closure,
        entities,
        statistical_datasets,
        physical_names,
        action_inventory: actions,
        metadata_inventory: metadata,
        query_inventory: query,
        event_delivery_inventory: event_deliveries,
        recipients,
    };
    insert_json_value(
        &mut artifacts,
        "compiled/effective-model.json",
        &sanitized_effective_model(&effective_model)?,
    )?;
    insert_json(&mut artifacts, "compiled/modules.json", &module_closure)?;
    if !statistical_datasets.is_empty() {
        insert_json(
            &mut artifacts,
            "compiled/statistical-datasets.json",
            statistical_datasets,
        )?;
    }
    if !actions.is_empty() {
        insert_json(&mut artifacts, "compiled/actions.json", actions)?;
        insert_json_value(
            &mut artifacts,
            "generated/action-contracts.json",
            &action_contracts(actions),
        )?;
        insert_json_value(
            &mut artifacts,
            "generated/action-contracts.schema.json",
            &action_contracts_schema(),
        )?;
    }
    insert_json(&mut artifacts, "compiled/routes.json", routes)?;
    insert_json(&mut artifacts, "compiled/access.json", access)?;
    insert_json(&mut artifacts, "compiled/metadata-inventory.json", metadata)?;
    insert_json(&mut artifacts, "compiled/query-inventory.json", query)?;
    insert_json(
        &mut artifacts,
        "compiled/event-deliveries.json",
        event_deliveries,
    )?;
    insert_json_value(
        &mut artifacts,
        REGISTRY_METADATA_ARTIFACT_PATH,
        &registry_metadata_artifact(metadata, actions, statistical_datasets),
    )?;
    insert_bytes(
        &mut artifacts,
        "generated/postgres/schema.sql",
        "application/sql",
        ddl.script().into_bytes(),
    );

    let mut schemas = BTreeMap::new();
    for entity in entities.values() {
        let schema = entity_schema(entity);
        let path = format!("generated/schemas/{}.schema.json", entity.id);
        insert_json_value(&mut artifacts, &path, &schema)?;
        schemas.insert(entity.id.clone(), schema);
    }
    for delivery in &event_deliveries.deliveries {
        let crate::model::CompiledEventOwner::RecordType { record_type, .. } = &delivery.owner
        else {
            insert_json_value(
                &mut artifacts,
                crate::proposal_hooks::PROPOSAL_EVENT_SCHEMA_PATH,
                &crate::proposal_hooks::proposal_event_schema(),
            )?;
            continue;
        };
        let entity = entities
            .get(record_type)
            .expect("compiled event delivery refers to a compiled entity");
        let event = entity
            .hooks
            .get(&delivery.event_id)
            .expect("compiled event delivery refers to a compiled event");
        let binding = event_data_schema_binding(registry_id, entity, event)?;
        debug_assert_eq!(delivery.data_schema, binding.data_schema);
        debug_assert_eq!(delivery.data_schema_fingerprint, binding.fingerprint);
        debug_assert_eq!(delivery.data_schema_artifact_path, binding.artifact_path);
        insert_json_value(&mut artifacts, &binding.artifact_path, &binding.schema)?;
    }
    for action in &actions.actions {
        insert_json_value(
            &mut artifacts,
            &format!(
                "generated/action-schemas/{}.invoke.input.schema.json",
                action.id
            ),
            &openapi_action_input_schema(action),
        )?;
        insert_json_value(
            &mut artifacts,
            &format!(
                "generated/action-schemas/{}.invoke.response.schema.json",
                action.id
            ),
            &openapi_action_response_schema(action, None),
        )?;
        if action.condition_route.is_some() {
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.target-conditions.input.schema.json",
                    action.id
                ),
                &openapi_action_condition_request_schema(action),
            )?;
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.target-conditions.response.schema.json",
                    action.id
                ),
                &openapi_action_condition_response_schema(action),
            )?;
        }
        if action_has_availability(action) {
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.availability.input.schema.json",
                    action.id
                ),
                &openapi_action_availability_request_schema(action),
            )?;
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.availability.response.schema.json",
                    action.id
                ),
                &openapi_action_availability_response_schema(action),
            )?;
        }
    }
    let openapi = openapi_document(OpenApiDocumentInput {
        registry_id,
        version,
        entities,
        routes,
        actions,
        query,
        schemas: &schemas,
        statistical_datasets,
    });
    insert_json_value(&mut artifacts, "generated/openapi.json", &openapi)?;
    if let Some(projection) = manifest_projection {
        let projected = project_manifest_artifacts(registry_id, projection, entities)?;
        insert_bytes(
            &mut artifacts,
            "generated/manifest/registry-manifest.json",
            "application/json",
            projected.manifest,
        );
        insert_bytes(
            &mut artifacts,
            "generated/manifest/dcat.jsonld",
            "application/ld+json",
            projected.dcat,
        );
    }
    let mut review_contexts = BTreeMap::new();
    for action in &actions.actions {
        if let Some(context) = crate::compiler::review_context::compile_schema_from_parts(
            registry_id,
            entities,
            action,
        )? {
            let path = format!("generated/review-context-schemas/{}.schema.json", action.id);
            review_contexts.insert(action.id.clone(),json!({"id":context.id,"revision":context.revision,"digest":context.digest,"path":path}));
            insert_bytes(
                &mut artifacts,
                &path,
                "application/schema+json",
                context.bytes,
            );
        }
    }
    if !review_contexts.is_empty() {
        insert_json(
            &mut artifacts,
            "generated/review-context-schemas/index.json",
            &review_contexts,
        )?;
    }
    project_sdk::generate(&mut artifacts, registry_id, entities, actions)?;
    Ok(GeneratedArtifacts { artifacts })
}

/// Compiled function assets already exclude executable bytes and local paths.
fn sanitized_effective_model(model: &EffectiveModel<'_>) -> Result<Value, Diagnostic> {
    serde_json::to_value(model).map_err(|_| canonicalization_error())
}

pub(crate) fn event_data_schema_binding(
    registry_id: &str,
    entity: &CompiledEntity,
    event: &HookSource,
) -> Result<EventDataSchemaBinding, Diagnostic> {
    let mut value_properties = Map::new();
    for field_id in &event.projection {
        let field = entity
            .fields
            .get(field_id)
            .expect("validated event projection refers to a compiled field");
        let schema = field_schema(&field.field_type);
        let mut schema = if field.required {
            schema
        } else {
            json!({"anyOf": [schema, {"type": "null"}]})
        };
        if field.generate.is_some() {
            schema
                .as_object_mut()
                .expect("field schemas are objects")
                .insert("readOnly".to_owned(), Value::Bool(true));
        }
        value_properties.insert(field_id.clone(), schema);
    }
    let trigger = match event.trigger {
        EventTrigger::Created => "created",
        EventTrigger::Patched => "patched",
        EventTrigger::Tombstoned => "tombstoned",
    };
    let mut properties = Map::new();
    properties.insert("recordType".to_owned(), json!({"const": entity.id}));
    properties.insert(
        "recordId".to_owned(),
        json!({"type": "string", "format": "uuid"}),
    );
    properties.insert(
        "revision".to_owned(),
        json!({"type": "integer", "format": "int64", "minimum": 1}),
    );
    properties.insert("trigger".to_owned(), json!({"const": trigger}));
    properties.insert("packageRevision".to_owned(), json!({"type": "string"}));
    properties.insert(
        "values".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": value_properties,
            "required": event.projection,
        }),
    );
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": ["recordType", "recordId", "revision", "trigger", "packageRevision", "values"]
    });
    let bytes = canonicalize_json(&schema).map_err(|_| canonicalization_error())?;
    let digest = Sha256::digest(&bytes);
    let fingerprint = format!("sha256:{}", hex_prefix(&digest, digest.len()));
    let data_schema = format!(
        "urn:breg:event-schema:{registry_id}:{}:{}:{fingerprint}",
        entity.id, event.id
    );
    let artifact_path = format!(
        "generated/event-schemas/{}.{}.schema.json",
        entity.id, event.id
    );
    Ok(EventDataSchemaBinding {
        schema,
        fingerprint,
        data_schema,
        artifact_path,
    })
}

fn entity_schema(entity: &CompiledEntity) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        properties.insert(
            field.logical.api_name.clone(),
            stored_field_value_schema(field, entity.fields[&field.logical.id].generate.is_some()),
        );
        if field.required {
            required.push(Value::String(field.logical.api_name.clone()));
        }
    }
    for field in entity.derived_fields.values() {
        let mut schema = field_value_schema(&field.logical.field_type, true);
        schema
            .as_object_mut()
            .expect("field schemas are objects")
            .insert("readOnly".to_owned(), Value::Bool(true));
        properties.insert(field.logical.api_name.clone(), schema);
    }

    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:record-type:{}", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create-only",
        }
    });
    let object = schema.as_object_mut().expect("entity schema is an object");
    if entity.change_control.is_some() {
        object.insert(
            "x-registry-mutationPolicy".to_owned(),
            render_mutation_policy(entity),
        );
    }
    schema
}

pub(crate) fn openapi_input_schema_id(entity_id: &str, operation: Operation) -> String {
    format!("{entity_id}-{}-input", operation_name(operation))
}

pub(crate) fn openapi_entity_input_schema(
    entity: &CompiledEntity,
    writable_fields: Option<&BTreeSet<String>>,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        if entity.fields[&field.logical.id].generate.is_some() {
            continue;
        }
        if writable_fields.is_some_and(|fields| !fields.contains(&field.logical.id)) {
            continue;
        }
        properties.insert(
            field.logical.api_name.clone(),
            field_value_schema(&field.logical.field_type, !field.required),
        );
        if field.required {
            required.push(Value::String(field.logical.api_name.clone()));
        }
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:record-type:{}:input", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create-only",
        }
    })
}

fn stored_field_value_schema(field: &crate::model::CompiledStoredField, generated: bool) -> Value {
    let mut schema = field_value_schema(&field.logical.field_type, !field.required);
    if generated {
        schema
            .as_object_mut()
            .expect("field schemas are objects")
            .insert("readOnly".to_owned(), Value::Bool(true));
    }
    schema
}

fn application_reason_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": crate::proposal_workflow::MAX_APPLICATION_REASON_CHARS,
        "pattern": "^[^\\u0000]*$",
        "description": "Optional application explanation, preserved unchanged. At most 4096 Unicode characters; NUL is refused."
    })
}

pub(crate) fn render_mutation_policy(entity: &CompiledEntity) -> Value {
    let mut policy = Map::new();
    if let Some(control) = &entity.change_control {
        for operation in &control.required_for {
            policy.insert(
                operation_name(*operation).to_owned(),
                json!("proposal-required"),
            );
        }
    }
    Value::Object(policy)
}

/// Author inspection of a normalized Action definition. Program bytes are never
/// included; caller metadata separately selects only its permitted fields.
pub fn inspect_action(action: &CompiledAction) -> Value {
    let plan = match &action.handler {
        Some(function) => json!({"type": "function", "function": inspect_plan_function(function)}),
        None => json!({"type": "fixed", "effects": action.effects,
            "order": action.effects.iter().map(|effect| &effect.id).collect::<Vec<_>>()}),
    };
    let guards = action
        .requires
        .iter()
        .map(|guard| {
            let mut value = serde_json::to_value(guard).expect("compiled guard serializes");
            value
                .as_object_mut()
                .expect("guard is an object")
                .retain(|key, value| {
                    // A present equals:null is an authored comparison, not a placeholder.
                    key == "equals" || !(value.is_null() || key == "field" && value == "")
                });
            value
        })
        .collect::<Vec<_>>();
    json!({
        "id": action.id, "apiName": action.api_name,
        "revision": action.definition_revision, "display": action.display,
        "migrationReviewRevision": crate::immediate_actions::migration_review_revision(action),
        "execution": action.execution,
        "inputs": action.inputs.iter().map(|input| action_input_metadata(input, action.handler.is_some())).collect::<Vec<_>>(),
        "plan": plan,
        "permissions": action.permissions,
        "commitGuards": guards,
        "dependencies": {"evidence": action.evidence},
        "bounds": {"maximumTargets": action.maximum_targets,
            "maximumFieldMutations": action.maximum_field_mutations,
            "maximumSnapshotBytes": action.maximum_snapshot_bytes},
    })
}

fn inspect_plan_function(function: &crate::model::CompiledPlanFunction) -> Value {
    let mut value = serde_json::to_value(function).expect("compiled function serializes");
    value["source"] = json!(match function.kind {
        crate::model::CompiledPlanFunctionKind::Rhai => &function.script_path,
        crate::model::CompiledPlanFunctionKind::Wasm => &function.module_path,
    });
    value
}

fn compact_event_condition(value: &mut Value) {
    if let Some(condition) = value.get_mut("when").and_then(Value::as_object_mut) {
        condition.retain(|_, value| match value {
            Value::Array(values) => !values.is_empty(),
            Value::Object(values) => !values.is_empty(),
            _ => true,
        });
    }
}

/// Inspect deliveries with the lifecycle selection owned by their definitions.
/// Delivery inventories alone do not carry Proposal transitions or hook phases.
pub fn inspect_events(registry: &crate::model::CompiledRegistry) -> Value {
    let deliveries = registry
        .event_deliveries()
        .deliveries
        .iter()
        .map(|delivery| {
            let mut value = serde_json::to_value(delivery).expect("compiled delivery serializes");
            value["handlerType"] = json!(delivery.handler_kind().as_str());
            match &delivery.owner {
                crate::model::CompiledEventOwner::RecordType { record_type, .. } => {
                    let hook = &registry.entities()[record_type].hooks[&delivery.event_id];
                    value["phase"] = json!(hook.phase);
                }
                crate::model::CompiledEventOwner::ProposalAction { action } => {
                    let action = registry
                        .actions()
                        .actions
                        .iter()
                        .find(|candidate| candidate.id == *action)
                        .expect("compiled Proposal delivery owns an Action");
                    let crate::model::CompiledActionExecution::Proposal { proposal } =
                        &action.execution
                    else {
                        unreachable!("compiled Proposal delivery owns a Proposal Action")
                    };
                    let hook = proposal
                        .hooks
                        .iter()
                        .find(|hook| hook.id == delivery.event_id)
                        .expect("compiled Proposal delivery owns a hook");
                    value["transitions"] = json!(crate::proposal_hooks::matching_transitions(
                        &hook.transitions
                    )
                    .collect::<Vec<_>>());
                    value["phase"] = json!(crate::contract::HookPhase::After);
                    let schema = crate::proposal_hooks::proposal_event_schema();
                    value["envelopeFields"] = json!(schema["properties"]
                        .as_object()
                        .expect("Proposal event schema defines its envelope properties")
                        .keys()
                        .collect::<Vec<_>>());
                    value["includesRecordValues"] = json!(false);
                }
            }
            compact_event_condition(&mut value);
            value
        })
        .collect::<Vec<_>>();
    json!({"deliveries": deliveries})
}

/// Author inspection uses exactly the normalized definitions used by execution.
pub fn inspect_registry(registry: &crate::model::CompiledRegistry) -> Value {
    let record_types = registry
        .entities()
        .values()
        .map(|record_type| {
            let hooks = record_type
                .hooks
                .iter()
                .map(|(id, hook)| {
                    let mut value = serde_json::to_value(hook).expect("compiled hook serializes");
                    compact_event_condition(&mut value);
                    (id, value)
                })
                .collect::<BTreeMap<_, _>>();
            json!({
                "id": record_type.id, "apiName": record_type.api_name,
                "revision": record_type.definition_revision, "display": record_type.display,
                "sourceModule": record_type.source_module,
                "moduleOrigins": record_type.module_origins,
                "primaryDataset": record_type.primary_dataset, "route": record_type.route,
                "mutationMode": record_type.mutation_mode,
                "mutationPolicy": render_mutation_policy(record_type),
                "classification": record_type.classification,
                "canonicalId": {"id": record_type.canonical_id.id,
                    "apiName": record_type.canonical_id.api_name,
                    "classification": record_type.canonical_id.classification,
                    "fieldType": record_type.canonical_id.field_type,
                    "schema": field_value_schema(&record_type.canonical_id.field_type, false)},
                "tombstone": record_type.tombstone, "batch": record_type.batch,
                "temporal": record_type.temporal, "geojson": record_type.geojson,
                "accessLog": record_type.access_log,
                "constraints": record_type.constraints, "indexes": record_type.indexes,
                "selectorProfiles": record_type.selector_profiles,
                "readPaths": record_type.read_paths, "hooks": hooks,
                "relationships": record_type.relationships,
                "derivedRelations": record_type.derived_relations.values().map(|relation| json!({
                    "id": relation.id, "source": relation.sql_path,
                    "sha256": relation.sql_sha256, "keyField": relation.key_field,
                    "execution": relation.execution, "fields": relation.fields,
                    "sourceRecordTypes": relation.source_entities,
                    "usesEvaluationDate": relation.uses_evaluation_date,
                })).collect::<Vec<_>>(),
                "fields": record_type.stored_fields.iter().map(|field| json!({
                    "id": field.logical.id, "apiName": field.logical.api_name,
                    "display": record_type.fields[&field.logical.id].display,
                    "fieldType": field.logical.field_type,
                    "schema": stored_field_value_schema(field, record_type.fields[&field.logical.id].generate.is_some()),
                    "classification": field.logical.classification,
                    "encrypted": field.logical.encryption.is_some(),
                    "required": field.required, "validTimeRole": field.valid_time_role,
                })).chain(record_type.derived_fields.values().map(|field| json!({
                    "id": field.logical.id, "apiName": field.logical.api_name,
                    "display": field.display,
                    "fieldType": field.logical.field_type,
                    "schema": field_value_schema(&field.logical.field_type, true),
                    "classification": field.logical.classification,
                    "encrypted": false,
                    "required": false, "derivation": field.derivation_id,
                }))).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    json!({"registryId": registry.registry_id(), "revision": registry.revision(),
        "display": registry.display(), "reviewAuthorities": registry.review_authorities(),
        "datasets": registry.datasets(), "accessProfiles": registry.access_profile_displays(),
        "recordTypes": record_types,
        "statisticalDatasets": registry.statistical_datasets().values().collect::<Vec<_>>(),
        "actions": registry.actions().actions.iter().map(inspect_action).collect::<Vec<_>>()})
}

pub(crate) fn openapi_action_input_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-invoke-input")
}

pub(crate) fn openapi_action_condition_request_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-target-conditions-input")
}

pub(crate) fn openapi_action_condition_response_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-target-conditions-response")
}

pub(crate) fn openapi_action_availability_request_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-availability-input")
}

pub(crate) fn openapi_action_availability_response_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-availability-response")
}

pub(crate) fn openapi_action_response_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-invoke-response")
}

pub(crate) fn openapi_action_input_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    let mut input_schema = action_input_properties_schema(
        action.inputs.iter(),
        &condition_inputs,
        action.handler.is_some(),
    );
    if action.execution.is_proposal() {
        input_schema["required"] = json!([]);
    }
    let mut properties = Map::from_iter([("input".to_owned(), input_schema)]);
    if !action.execution.is_proposal() {
        properties.insert(
            "preconditions".to_owned(),
            action_preconditions_schema(condition_inputs.iter().copied()),
        );
    }
    let mut required = vec![Value::String("input".to_owned())];
    if !condition_inputs.is_empty() {
        required.push(Value::String("preconditions".to_owned()));
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:invoke-input", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
        "x-registry-action": action.id,
        "x-registry-requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn openapi_action_condition_request_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:target-conditions-input", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["input"],
        "properties": {
            "input": action_condition_input_properties_schema(condition_inputs.iter().copied()),
        },
        "x-registry-action": action.id,
        "x-registry-requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn openapi_action_condition_response_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:target-conditions-response", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["preconditions"],
        "properties": {
            "preconditions": action_preconditions_schema(condition_inputs.iter().copied()),
        },
        "x-registry-action": action.id,
    })
}

pub(crate) fn action_has_availability(action: &CompiledAction) -> bool {
    !action.execution.is_proposal()
        && action
            .inputs
            .iter()
            .any(|input| matches!(&input.field_type, FieldTypeSource::Reference { .. }))
}

pub(crate) fn openapi_action_availability_request_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    let reference_inputs = action
        .inputs
        .iter()
        .filter(|input| matches!(&input.field_type, FieldTypeSource::Reference { .. }))
        .collect::<Vec<_>>();
    let mut input_schema = action_input_properties_schema(
        action.inputs.iter(),
        &condition_inputs,
        action.handler.is_some(),
    );
    input_schema["required"] = json!([]);
    let target_input_names = reference_inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    let target_shapes = reference_inputs
        .iter()
        .map(|input| {
            json!({
                "properties": {
                    "targetInput": {"const": input.api_name},
                    "input": {
                        "required": [input.api_name],
                        "properties": {
                            (input.api_name.clone()): field_schema(&input.field_type),
                        },
                    },
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:availability-input", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["targetInput", "input"],
        "properties": {
            "targetInput": {"type": "string", "enum": target_input_names},
            "input": input_schema,
        },
        "oneOf": target_shapes,
        "x-registry-action": action.id,
    })
}

pub(crate) fn openapi_action_availability_response_schema(action: &CompiledAction) -> Value {
    let input_names = action
        .inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    let observed_revision = json!({"type": "integer", "format": "int64", "minimum": 1});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:availability-response", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["availability"],
        "properties": {
            "availability": {
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["available", "observedRevision"],
                        "properties": {
                            "available": {"const": true},
                            "observedRevision": observed_revision,
                        },
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["available", "observedRevision", "reason", "recovery"],
                        "properties": {
                            "available": {"const": false},
                            "observedRevision": observed_revision,
                            "reason": {"const": "guard-not-satisfied"},
                            "guardReason": {"type":"string","pattern":"^[a-z][a-z0-9_-]{0,63}$"},
                            "recovery": {"const": "none"},
                        },
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["available", "observedRevision", "reason", "recovery", "missingInputs"],
                        "properties": {
                            "available": {"type": "null"},
                            "observedRevision": observed_revision,
                            "reason": {"const": "input-required"},
                            "recovery": {"const": "correct-input"},
                            "missingInputs": {
                                "type": "array",
                                "minItems": 1,
                                "uniqueItems": true,
                                "items": {"type": "string", "enum": input_names},
                            },
                        },
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["available", "observedRevision", "reason", "recovery"],
                        "properties": {
                            "available": {"type": "null"},
                            "observedRevision": {"type": "null"},
                            "reason": {"const": "not-disclosed"},
                            "recovery": {"const": "none"},
                        },
                    },
                ]
            }
        },
        "x-registry-action": action.id,
    })
}

pub(crate) fn openapi_action_response_schema(
    action: &CompiledAction,
    selected_result_effects: Option<&BTreeSet<String>>,
) -> Value {
    if action.execution.is_proposal() {
        return proposal_schema();
    }
    let result_shapes = action_response_result_shapes(action, selected_result_effects);
    let results_schema = match result_shapes.as_slice() {
        [shape] => action_results_schema(action, shape),
        shapes => Value::Object(Map::from_iter([(
            if action.handler.is_some() {
                "anyOf"
            } else {
                "oneOf"
            }
            .to_owned(),
            Value::Array(
                shapes
                    .iter()
                    .map(|shape| action_results_schema(action, shape))
                    .collect(),
            ),
        )])),
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:invoke-response", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["action", "applicationId", "results"],
        "properties": {
            "action": {"const": action.id},
            "applicationId": {"type": "string", "format": "uuid"},
            "results": results_schema
        }
    })
}

fn action_response_result_shapes(
    action: &CompiledAction,
    selected_result_effects: Option<&BTreeSet<String>>,
) -> Vec<BTreeSet<String>> {
    if let Some(results) = selected_result_effects {
        return vec![known_action_result_effects(action, results)];
    }
    let mut shapes = action
        .permissions
        .iter()
        .map(|grant| known_action_result_effects(action, &grant.results))
        .collect::<BTreeSet<_>>();
    if shapes.is_empty() {
        shapes.insert(known_action_result_effects(action, &action.result_effects));
    }
    shapes.into_iter().collect()
}

fn known_action_result_effects(
    action: &CompiledAction,
    results: &BTreeSet<String>,
) -> BTreeSet<String> {
    action
        .effects
        .iter()
        .filter(|effect| results.contains(&effect.id))
        .map(|effect| effect.id.clone())
        .collect()
}

fn action_results_schema(action: &CompiledAction, effect_ids: &BTreeSet<String>) -> Value {
    let result_properties = action
        .effects
        .iter()
        .filter(|effect| effect_ids.contains(&effect.id))
        .map(|effect| {
            (
                effect.id.clone(),
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["recordType", "recordId", "revision"],
                    "properties": {
                        "recordType": {"const": effect.target.entity_id},
                        "recordId": {"type": "string", "format": "uuid"},
                        "revision": {"type": "integer", "format": "int64", "minimum": 1}
                    }
                }),
            )
        })
        .collect::<Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": if action.handler.is_some() {
            Vec::<String>::new()
        } else {
            effect_ids.iter().cloned().collect()
        },
        "properties": result_properties,
    })
}

pub(crate) fn openapi_action_operation(
    route: &CompiledActionRoute,
    action: &CompiledAction,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Value {
    let mut operation = Map::from_iter([
        ("operationId".to_owned(), json!(route.id)),
        (
            "x-registry-action".to_owned(),
            public_action_metadata_entry(
                action,
                selected_profile_from_access_profiles(access_profiles),
            ),
        ),
        (
            "x-registry-operation".to_owned(),
            json!(operation_name(route.operation)),
        ),
        (
            "x-registry-routeKind".to_owned(),
            json!(action_route_kind_name(route.kind)),
        ),
        ("security".to_owned(), bearer_security()),
    ]);
    match access_profiles {
        OpenApiAccessProfiles::All => {
            operation.insert(
                "x-registry-accessProfiles".to_owned(),
                json!(route.access_profiles),
            );
            operation.insert(
                "x-registry-defaultAccessProfile".to_owned(),
                json!(route.default_access_profile),
            );
        }
        OpenApiAccessProfiles::Selected(profile) => {
            operation.insert("x-registry-accessProfile".to_owned(), json!(profile));
        }
    }
    let mut parameters = vec![
        header_parameter(
            "traceparent",
            false,
            traceparent_schema(),
            "Optional W3C trace context. Responses carry Registry trace context for the request.",
        ),
        access_profile_parameter(route.default_access_profile.is_none()),
    ];
    if route.kind == ActionRouteKind::Invoke {
        parameters.push(header_parameter(
            "Idempotency-Key",
            true,
            json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
            "Idempotency key bound to the action route, selected profile, package revision, normalized action input, preconditions, and granted result contract.",
        ));
    }
    operation.insert("parameters".to_owned(), Value::Array(parameters));
    operation.insert(
        "requestBody".to_owned(),
        json_request_body(json!({"$ref": format!(
            "#/components/schemas/{}",
            match route.kind {
                ActionRouteKind::Availability => {
                    openapi_action_availability_request_schema_id(&action.id)
                }
                ActionRouteKind::Invoke => openapi_action_input_schema_id(&action.id),
                ActionRouteKind::TargetConditions => {
                    openapi_action_condition_request_schema_id(&action.id)
                }
            }
        )})),
    );
    operation.insert(
        "responses".to_owned(),
        action_operation_responses(route, action),
    );
    Value::Object(operation)
}

pub(crate) fn public_action_metadata(actions: &CompiledActionInventory) -> Value {
    json!({
        "actions": actions
            .actions
            .iter()
            .map(|action| public_action_metadata_entry(action, None))
            .collect::<Vec<_>>()
    })
}

/// Portable interaction contracts derived from the same definitions and schemas
/// as the receiving API. They describe policy without exporting its grants.
fn action_contracts(actions: &CompiledActionInventory) -> Value {
    let entries = actions
        .actions
        .iter()
        .map(|action| {
            let mut contract = json!({
                "id": action.id,
                "revision": action.definition_revision,
                "display": action.display,
                "mode": if action.execution.is_proposal() { "proposal" } else { "immediate" },
                "input": openapi_action_input_schema(action),
                "output": openapi_action_response_schema(action, None),
            });
            if let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution
            {
                contract["review"] =
                    serde_json::to_value(&proposal.review).expect("compiled review serializes");
                contract["application"] = serde_json::to_value(&proposal.application)
                    .expect("compiled application policy serializes");
            }
            let refusals: Vec<_> = action
                .handler
                .iter()
                .flat_map(|handler| handler.refusals.keys())
                .collect();
            // A Proposal invocation creates a draft. Its planner only runs on
            // Submit, so these invocation schemas must not promise that refusal.
            if !action.execution.is_proposal() && !refusals.is_empty() {
                contract["declaredRefusal"] = json!({
                    "type": "object", "additionalProperties": false,
                    "required": ["refusalCode"],
                    "properties": { "refusalCode": { "type": "string", "enum": refusals } }
                });
            }
            contract
        })
        .collect::<Vec<_>>();
    json!({ "apiVersion": ACTION_CONTRACTS_API_VERSION, "kind": ACTION_CONTRACTS_KIND, "actions": entries })
}

/// Closed envelope for the public Action contract projection. Embedded schemas
/// retain their owning API's JSON Schema vocabulary and validation rules.
fn action_contracts_schema() -> Value {
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$id":"https://id.registrystack.org/schemas/breg/action-contracts/action-contracts.v1.schema.json",
        "title":"BReg Action contracts", "type":"object", "additionalProperties":false,
        "required":["apiVersion","kind","actions"],
        "properties":{
            "apiVersion":{"const":ACTION_CONTRACTS_API_VERSION},
            "kind":{"const":ACTION_CONTRACTS_KIND},
            "actions":{"type":"array","items":{"$ref":"#/$defs/Action"}}
        },
        "$defs":{
            "Schema":{"type":["object","boolean"]},
            "Display":{"type":"object","additionalProperties":false,"properties":{
                "label":{"type":"string"},"description":{"type":"string"},"titleField":{"type":"string"}
            }},
            "PolicySelection":{"type":"object","additionalProperties":false,"required":["id"],
                "dependentRequired":{"version":["digest"],"digest":["version"]},"properties":{
                "id":{"type":"string"},"version":{"type":"string"},"digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
            }},
            "Review":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["type"],"properties":{"type":{"const":"none"}}},
                {"type":"object","additionalProperties":false,"required":["type","authority","source","policy"],"properties":{
                    "type":{"const":"required"},"authority":{"type":"string"},"source":{"type":"string"},"policy":{"$ref":"#/$defs/PolicySelection"}
                }}
            ]},
            "Application":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["mode"],"properties":{"mode":{"const":"manual"}}},
                {"type":"object","additionalProperties":false,"required":["mode","maximumAttempts"],"properties":{
                    "mode":{"const":"automatic"},"maximumAttempts":{"type":"integer","minimum":1,"maximum":32}
                }}
            ]},
            "Action":{"type":"object","additionalProperties":false,"required":["id","revision","display","mode","input","output"],"properties":{
                "id":{"type":"string"},"revision":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                "display":{"$ref":"#/$defs/Display"},"mode":{"enum":["immediate","proposal"]},
                "input":{"$ref":"#/$defs/Schema"},"output":{"$ref":"#/$defs/Schema"},
                "declaredRefusal":{"$ref":"#/$defs/Schema"},"review":{"$ref":"#/$defs/Review"},"application":{"$ref":"#/$defs/Application"}
            },"allOf":[{"if":{"properties":{"mode":{"const":"proposal"}}},"then":{"required":["review","application"]},"else":{"not":{"anyOf":[{"required":["review"]},{"required":["application"]}]}}}]}
        }
    })
}

fn registry_metadata_artifact(
    metadata: &CompiledMetadataInventory,
    actions: &CompiledActionInventory,
    statistical_datasets: &BTreeMap<String, CompiledStatisticalDataset>,
) -> Value {
    let mut value = serde_json::to_value(metadata).expect("compiled metadata serializes");
    let object = value
        .as_object_mut()
        .expect("compiled metadata serializes as object");
    if !actions.is_empty() {
        object.insert(
            "actions".to_owned(),
            public_action_metadata(actions)["actions"].clone(),
        );
    }
    if !statistical_datasets.is_empty() {
        object.insert(
            "statisticalDatasets".to_owned(),
            crate::statistical_artifacts::all_statistical_dataset_metadata(statistical_datasets),
        );
    }
    value
}

pub(crate) fn public_action_metadata_entry(
    action: &CompiledAction,
    selected_profile: Option<&str>,
) -> Value {
    let inspection = inspect_action(action);
    let condition_inputs = action_condition_inputs(action);
    let selected_result_effects = action_selected_result_effects(action, selected_profile);
    let access = match selected_profile {
        Some(profile) => json!({"selectedProfile": profile}),
        None => json!({"accessProfiles": action_profile_ids(action)}),
    };
    let mut metadata = json!({
        "id": inspection["id"],
        "apiName": inspection["apiName"],
        "revision": inspection["revision"],
        "display": inspection["display"],
        "execution": {"mode": if action.execution.is_proposal() { "proposal" } else { "immediate" }},
        "route": action.route,
        "conditionRoute": action.condition_route,
        "inputMode": if action.handler.is_some() { "handler" } else { "fixed" },
        "maximumInputStringBytes": action.handler.as_ref().map(|_| crate::rhai_planner::MAXIMUM_STRING_BYTES),
        "inputs": inspection["inputs"],
        "referenceInputs": action.inputs.iter().filter_map(reference_input_metadata).collect::<Vec<_>>(),
        "requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
        "resultEffects": action.effects.iter()
            .filter(|effect| selected_result_effects.contains(&effect.id))
            .map(|effect| json!({
                "effect": effect.id,
                "recordType": effect.target.entity_id,
                "operation": operation_name(effect.operation),
            }))
            .collect::<Vec<_>>(),
        "access": access,
        "routes": {
            "invoke": {
                "method": "POST",
                "path": action.route,
                "operationId": format!("actions.{}.invoke", action.id),
                "requiresIdempotencyKey": true,
                "inputSchema": openapi_action_input_schema_id(&action.id),
                "responseSchema": openapi_action_response_schema_id(&action.id),
            },
            "targetConditions": action.condition_route.as_ref().map(|path| json!({
                "method": "POST",
                "path": path,
                "operationId": format!("actions.{}.target-conditions", action.id),
                "requiresIdempotencyKey": false,
                "inputSchema": openapi_action_condition_request_schema_id(&action.id),
                "responseSchema": openapi_action_condition_response_schema_id(&action.id),
            })),
            "availability": action_has_availability(action).then(|| json!({
                "method": "POST",
                "path": format!("{}/availability", action.route),
                "operationId": format!("actions.{}.availability", action.id),
                "requiresIdempotencyKey": false,
                "inputSchema": openapi_action_availability_request_schema_id(&action.id),
                "responseSchema": openapi_action_availability_response_schema_id(&action.id),
            })),
        },
        "bounds": {
            "maximumTargets": action.maximum_targets,
            "maximumFieldMutations": action.maximum_field_mutations,
            "maximumSnapshotBytes": action.maximum_snapshot_bytes,
        }
    });
    if let crate::model::CompiledActionExecution::Proposal { proposal } = &action.execution {
        metadata["attachments"] = json!(proposal
            .attachments
            .values()
            .map(|slot| json!({
                "id": slot.id,
                "required": slot.required,
                "contentTypes": slot.content_types,
                "maximumBytes": slot.maximum_bytes,
            }))
            .collect::<Vec<_>>());
        metadata
            .as_object_mut()
            .expect("action metadata object")
            .remove("conditionRoute");
        metadata["routes"]
            .as_object_mut()
            .expect("route object")
            .remove("targetConditions");
        metadata["requiredConditionKeys"] = json!([]);
        let mut start = metadata["routes"]["invoke"].take();
        start["operationId"] = json!(format!("actions.{}.start", action.id));
        metadata["routes"]
            .as_object_mut()
            .expect("route object")
            .remove("invoke");
        metadata["routes"]["start"] = start;
    }
    metadata
}

/// Shared schema for the distinct Proposal resource, never a Record envelope.
pub fn proposal_apply_input_schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["submissionVersion","effectDigest"],
        "properties":{"submissionVersion":{"type":"integer","minimum":1,"maximum":u32::MAX},
            "effectDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "reason":application_reason_schema()}})
}

pub fn proposal_schema() -> Value {
    json!({"type":"object", "additionalProperties":false,
    "required":["id","actionId","actionRevision","submissionVersion","revision","state","turn","links"],
    "properties": {
        "id":{"type":"string","format":"uuid"},
        "actionId":{"type":"string"},"actionRevision":{"type":"string"},
        "submissionVersion":{"type":"integer","minimum":0},"revision":{"type":"integer","minimum":1},
        "state":{"enum":["draft","submitted","applied","cancelled","rejected"]},
        "title":{"type":"string","maxLength":1024},
        "input":{"type":"object"},
        "application":proposal_application_schema(),
        "applicationStatus":proposal_application_status_schema(),
        "turn":{"enum":["party","official","nobody"]},
        "decision":proposal_decision_schema(),
        "blockedReason":{"enum":["package-changed"]},"effectDigest":{"type":"string"},
        "attachments":{"type":"object","maxProperties":8,"additionalProperties":proposal_attachment_schema()},
        "links":{"type":"object","additionalProperties":{
            "type":"object","additionalProperties":false,
            "required":["method","path","accessProfile","operation"],
            "properties":{"method":{"enum":["GET","POST"]},"path":{"type":"string"},
                "accessProfile":{"type":"string"},"operation":{"type":"string"},
                "ifMatch":{"type":"string"},"availability":availability_schema()}
        }}
    }})
}

/// The reviewer's decision on a submission. The public reason is the only
/// reviewer text BReg serves.
pub fn proposal_decision_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["status","decidedAt"],
    "properties":{
        "status":{"enum":["approved","rejected","changes-requested","answered"]},
        "decidedAt":{"type":"string","format":"date-time"},
        "publicReason":{"type":"string","minLength":1,
            "pattern":r"^[^\u0000-\u001F\u007F-\u009F]*[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000][^\u0000-\u001F\u007F-\u009F]*$",
            "x-maximum-utf8-bytes":registry_review_protocol::MAXIMUM_PUBLIC_REASON_BYTES}
    }})
}

fn proposal_application_status_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["state","mode"],
    "properties":{
        "state":{"enum":["awaiting-review","pending","applying","blocked","applied","cancelled","rejected"]},
        "mode":{"enum":["automatic","manual"]},
        "reason":{"enum":["contract-changed","dependency-outage","lease-expired","application-refused","attempts-exhausted"]},
        "recovery":{"enum":["retry","correct-input"]},
        "automaticRetry":{"type":"object","additionalProperties":false,
            "required":["scheduled","attempts","maximumAttempts"],"properties":{
                "scheduled":{"type":"boolean"},"attempts":{"type":"integer","minimum":0,"maximum":1000},
                "maximumAttempts":{"type":"integer","minimum":1,"maximum":1000}
            }}
    }})
}

fn proposal_application_schema() -> Value {
    let reference = json!({"type":"object","additionalProperties":false,"required":["recordType","recordId","revision"],
        "properties":{"recordType":{"type":"string"},"recordId":{"type":"string","format":"uuid"},"revision":{"type":"integer","minimum":1}}});
    json!({"type":"object","additionalProperties":false,
        "required":["applicationId","submissionVersion","effectDigest","resultLinks"],
        "properties":{"applicationId":{"type":"string","format":"uuid"},"submissionVersion":{"type":"integer","minimum":1},
            "effectDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "resultLinks":{"type":"array","maxItems":16,"items":reference}}})
}

fn proposal_attachment_schema() -> Value {
    let value = json!({"type":"object","additionalProperties":false,
        "required":["submissionVersion","sha256","contentType","byteSize","verificationStatus"],
        "properties":{"submissionVersion":{"type":"integer","minimum":0},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},
            "contentType":{"type":"string"},"byteSize":{"type":"integer","minimum":1},
            "uploadedAt":{"type":"string"},
            "verificationStatus":{"enum":["notRequired","pending","approved","rejected"]}}});
    let link = json!({"type":"object","additionalProperties":false,
        "required":["method","path","accessProfile","operation"],
        "properties":{"method":{"enum":["GET","PATCH","DELETE"]},"path":{"type":"string"},
            "accessProfile":{"type":"string"},"operation":{"enum":["download","upload","remove"]},
            "ifMatch":{"type":"string"},"availability":availability_schema()}});
    json!({"type":"object","additionalProperties":false,
        "required":["id","required","maximumBytes","contentTypes","classification","links"],
        "properties":{"id":{"type":"string"},"required":{"type":"boolean"},
            "maximumBytes":{"type":"integer","minimum":1,"maximum":16777216},
            "contentTypes":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string"}},
            "classification":{"enum":["public","internal","restricted"]},
            "links":{"type":"object","additionalProperties":link},"value":value}})
}

pub fn availability_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["available","observedRevision"],
        "properties":{"available":{"type":"boolean"},"observedRevision":{"type":"integer","minimum":1},
            "reason":{"enum":["pending-review","review-rejected","review-changes-requested","review-ended","stale-revision","contract-changed","dependency-outage","invalid-input","already-applied"]},
            "recovery":{"enum":["refresh","revise","retry","correct-input","receipt-only"]}},
        "if":{"properties":{"available":{"const":false}}},"then":{"required":["reason","recovery"]}})
}

fn action_input_metadata(input: &CompiledActionInput, handler: bool) -> Value {
    let mut metadata = json!({
        "id": input.id,
        "apiName": input.api_name,
        "label": input.display.label.as_deref().unwrap_or(&input.api_name),
        "schema": field_value_schema(&input.field_type, handler && !input.required),
        "fieldType": input.field_type,
        "required": input.required,
        "nullable": handler && !input.required,
        "classification": input.classification,
    });
    if !crate::model::display_is_empty(&input.display) {
        metadata["display"] = json!(input.display);
    }
    if let Some(description) = &input.display.description {
        metadata["description"] = json!(description);
    }
    metadata
}

fn selected_profile_from_access_profiles(
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Option<&str> {
    match access_profiles {
        OpenApiAccessProfiles::All => None,
        OpenApiAccessProfiles::Selected(profile) => Some(profile),
    }
}

fn action_profile_ids(action: &CompiledAction) -> Vec<String> {
    action
        .permissions
        .iter()
        .map(|grant| grant.profile_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn action_selected_result_effects(
    action: &CompiledAction,
    selected_profile: Option<&str>,
) -> BTreeSet<String> {
    match selected_profile {
        Some(profile) => action
            .permissions
            .iter()
            .filter(|grant| grant.profile_id == profile)
            .flat_map(|grant| grant.results.iter().cloned())
            .collect(),
        None => action.result_effects.clone(),
    }
}

fn reference_input_metadata(input: &CompiledActionInput) -> Option<Value> {
    let FieldTypeSource::Reference { target, .. } = &input.field_type else {
        return None;
    };
    Some(json!({
        "input": input.id,
        "apiName": input.api_name,
        "targetRecordType": target,
    }))
}

fn action_input_properties_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
    condition_inputs: &[&CompiledActionInput],
    handler_inputs: bool,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let is_required = |input: &CompiledActionInput| {
        input.required || condition_inputs.iter().any(|target| target.id == input.id)
    };
    let properties = inputs
        .iter()
        .map(|input| {
            (
                input.api_name.clone(),
                field_value_schema(&input.field_type, handler_inputs && !is_required(input)),
            )
        })
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .filter(|input| is_required(input))
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_condition_input_properties_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let properties = inputs
        .iter()
        .map(|input| (input.api_name.clone(), field_schema(&input.field_type)))
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_preconditions_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let properties = inputs
        .iter()
        .map(|input| {
            (
                input.api_name.clone(),
                immediate_action_precondition_schema(),
            )
        })
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_condition_inputs(action: &CompiledAction) -> Vec<&CompiledActionInput> {
    if action.execution.is_proposal() {
        return Vec::new();
    }
    let condition_input_ids = crate::plan::condition_inputs(action);
    action
        .inputs
        .iter()
        .filter(|input| condition_input_ids.contains(input.id.as_str()))
        .collect()
}

fn immediate_action_precondition_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["ifMatch"],
        "properties": {
            "ifMatch": {"type": "string", "minLength": 3, "maxLength": 256, "pattern": "^\\\"[\\x21\\x23-\\x7E]+\\\"$"}
        }
    })
}

fn immediate_action_result_reference_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordType", "recordId", "revision"],
        "properties": {
            "recordType": {"type": "string"},
            "recordId": {"type": "string", "format": "uuid"},
            "revision": {"type": "integer", "format": "int64", "minimum": 1}
        }
    })
}

/// Every governed operation requires a bearer credential: the registry serves
/// authenticated callers only.
fn bearer_security() -> Value {
    json!([{"bearerAuth": []}])
}

fn action_operation_responses(route: &CompiledActionRoute, action: &CompiledAction) -> Value {
    let (success_status, success) = if route.operation == Operation::Start {
        (
            "201",
            success_response(
                "Proposal created",
                StatusResponseHeaders::ProposalCreate,
                json!({"$ref": format!("#/components/schemas/{}", openapi_action_response_schema_id(&action.id))}),
            ),
        )
    } else {
        let success = match route.kind {
            ActionRouteKind::Availability => success_response(
                "Action availability returned",
                StatusResponseHeaders::NoStore,
                json!({"$ref": format!(
                    "#/components/schemas/{}",
                    openapi_action_availability_response_schema_id(&action.id)
                )}),
            ),
            ActionRouteKind::Invoke => success_response(
                "Immediate action committed",
                StatusResponseHeaders::ActionMutation,
                json!({"$ref": format!("#/components/schemas/{}", openapi_action_response_schema_id(&action.id))}),
            ),
            ActionRouteKind::TargetConditions => success_response(
                "Action target conditions returned",
                StatusResponseHeaders::NoStore,
                json!({"$ref": format!(
                    "#/components/schemas/{}",
                    openapi_action_condition_response_schema_id(&action.id)
                )}),
            ),
        };
        ("200", success)
    };
    let mut responses = Map::from_iter([(success_status.to_owned(), success)]);
    for (status, problems) in action_problem_responses(route.kind, action) {
        let mut examples = problems
            .iter()
            .map(|problem| {
                (
                    problem.code.to_owned(),
                    json!({"value": problem_example(status, problem.code, problem.detail)}),
                )
            })
            .collect::<Map<_, _>>();
        if status == "422" {
            examples = action
                .handler
                .as_ref()
                .into_iter()
                .flat_map(|handler| &handler.refusals)
                .map(|(code, label)| {
                    let mut example = problem_example(status, "action.refused", label);
                    example["refusalCode"] = json!(code);
                    (code.clone(), json!({"value": example}))
                })
                .collect();
        }
        responses.insert(
            status.to_owned(),
            json!({
                "description": "Problem response",
                "headers": {
                    "traceparent": traceparent_header("Trace context for this problem response."),
                    "Cache-Control": no_store_header()
                },
                "content": {
                    "application/problem+json": {
                        "schema": {"$ref": "#/components/schemas/Problem"},
                        "examples": examples
                    }
                }
            }),
        );
    }
    Value::Object(responses)
}

fn action_problem_responses(
    kind: ActionRouteKind,
    action: &CompiledAction,
) -> BTreeMap<&'static str, Vec<ProblemExample>> {
    let mut responses = BTreeMap::from([
        (
            "400",
            vec![ProblemExample {
                code: "request.invalid",
                detail: "The request is invalid.",
            }],
        ),
        (
            "401",
            vec![ProblemExample {
                code: "authentication.refused",
                detail: "The bearer credential is missing or refused.",
            }],
        ),
        (
            "404",
            vec![ProblemExample {
                code: "resource.not_found",
                detail: "The requested resource was not found.",
            }],
        ),
        (
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        ),
        (
            "503",
            vec![ProblemExample {
                code: "service.unavailable",
                detail: "The Registry mutation service is unavailable.",
            }],
        ),
        (
            "504",
            vec![ProblemExample {
                code: "request.timeout",
                detail: "The request timed out.",
            }],
        ),
    ]);
    if kind == ActionRouteKind::Availability
        || (kind == ActionRouteKind::Invoke && !action.execution.is_proposal())
    {
        responses.entry("503").or_default().push(ProblemExample {
            code: "runtime.field_encryption.unavailable",
            detail: "The Registry field-encryption service is unavailable.",
        });
    }
    if kind == ActionRouteKind::Invoke {
        if !action.execution.is_proposal() {
            if !action.evidence.is_empty() || !action.commit_evidence.is_empty() {
                responses.entry("503").or_default().push(ProblemExample {
                    code: "action.evidence_failed",
                    detail: "The declared Evidence dependency could not be accepted.",
                });
            }
            if let Some(handler) = &action.handler {
                responses.insert(
                    "500",
                    vec![ProblemExample {
                        code: "action.handler_failed",
                        detail: "The action handler could not produce an accepted result.",
                    }],
                );
                if !handler.refusals.is_empty() {
                    responses.insert("422", Vec::new());
                }
            }
        }
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.key-reused",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "410",
            vec![ProblemExample {
                code: "idempotency.expired",
                detail: "The held response of the idempotency key expired; the key stays spent.",
            }],
        );
        let mut precondition_problems = vec![ProblemExample {
            code: "precondition.failed",
            detail: "The mutation precondition failed.",
        }];
        if !action.execution.is_proposal() {
            precondition_problems.insert(
                0,
                ProblemExample {
                    code: "action.guard_failed",
                    detail: "The action guard was not satisfied.",
                },
            );
        }
        responses.insert("412", precondition_problems);
    }
    responses
}

fn action_route_kind_name(kind: ActionRouteKind) -> &'static str {
    match kind {
        ActionRouteKind::Availability => "availability",
        ActionRouteKind::Invoke => "invoke",
        ActionRouteKind::TargetConditions => "target-conditions",
    }
}

pub(crate) fn field_value_schema(field_type: &FieldTypeSource, nullable: bool) -> Value {
    let schema = field_schema(field_type);
    if nullable {
        json!({"anyOf": [schema, {"type": "null"}]})
    } else {
        schema
    }
}

pub(crate) fn field_schema(field_type: &FieldTypeSource) -> Value {
    match field_type {
        FieldTypeSource::Boolean => json!({"type": "boolean"}),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => json!({
            "type": "string",
            "minLength": min_length,
            "maxLength": max_length,
        }),
        FieldTypeSource::Text { max_length } => json!({
            "type": "string",
            "maxLength": max_length,
        }),
        FieldTypeSource::Int64 => json!({
            "type": "integer",
            "format": "int64",
        }),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => {
            let mut schema = json!({
                "type": "string",
                "pattern": decimal_pattern(*precision, *scale),
                "x-registry-decimalPrecision": precision,
                "x-registry-decimalScale": scale,
            });
            let object = schema.as_object_mut().expect("decimal schema is an object");
            if let Some(minimum) = minimum {
                object.insert(
                    "x-registry-decimalMinimum".to_owned(),
                    Value::String(minimum.clone()),
                );
            }
            if let Some(maximum) = maximum {
                object.insert(
                    "x-registry-decimalMaximum".to_owned(),
                    Value::String(maximum.clone()),
                );
            }
            schema
        }
        FieldTypeSource::Date => json!({"type": "string", "format": "date"}),
        FieldTypeSource::Timestamp => json!({"type": "string", "format": "date-time"}),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            json!({"type": "string", "format": "uuid"})
        }
        FieldTypeSource::VocabularyCode { vocabulary, values } => json!({
            "type": "string",
            "enum": values,
            "x-registry-vocabulary": vocabulary,
        }),
        FieldTypeSource::Crs84Point { precision, bbox } => {
            let mut schema = json!({
                "type": "object",
                "description": "CRS84 GeoJSON Point with coordinates in [longitude, latitude] order.",
                "additionalProperties": false,
                "properties": {
                    "type": {"const": "Point"},
                    "coordinates": {
                        "type": "array",
                        "prefixItems": [
                            {"type": "number", "minimum": -180, "maximum": 180},
                            {"type": "number", "minimum": -90, "maximum": 90}
                        ],
                        "items": false,
                        "minItems": 2,
                        "maxItems": 2
                    }
                },
                "required": ["type", "coordinates"],
                "x-registry-coordinateReferenceSystem": "CRS84",
                "x-registry-coordinatePrecision": precision,
            });
            if let Some(bbox) = bbox {
                schema
                    .as_object_mut()
                    .expect("point schema is an object")
                    .insert("x-registry-bbox".to_owned(), json!(bbox));
            }
            schema
        }
        FieldTypeSource::Structured { max_bytes, schema } => {
            let mut schema = schema.clone();
            schema
                .as_object_mut()
                .expect("validated structured schema is an object")
                .insert("x-registry-maxBytes".to_owned(), json!(max_bytes));
            schema
        }
    }
}

pub(crate) fn decimal_pattern(precision: u8, scale: u8) -> String {
    let integer_digits = precision - scale;
    let integer = if integer_digits == 0 {
        "0".to_owned()
    } else {
        format!("(0|[1-9][0-9]{{0,{}}})", integer_digits - 1)
    };
    if scale == 0 {
        format!("^-?{integer}$")
    } else {
        format!("^-?{integer}\\.[0-9]{{{scale}}}$")
    }
}

struct OpenApiDocumentInput<'a> {
    registry_id: &'a str,
    version: &'a str,
    entities: &'a BTreeMap<String, CompiledEntity>,
    routes: &'a CompiledRouteInventory,
    actions: &'a CompiledActionInventory,
    query: &'a CompiledQueryInventory,
    schemas: &'a BTreeMap<String, Value>,
    statistical_datasets: &'a BTreeMap<String, CompiledStatisticalDataset>,
}

fn openapi_document(input: OpenApiDocumentInput<'_>) -> Value {
    let OpenApiDocumentInput {
        registry_id,
        version,
        entities,
        routes,
        actions,
        query,
        schemas,
        statistical_datasets,
    } = input;
    let mut paths = Map::new();
    let mut input_schemas = Map::new();
    let mut has_access_log = false;
    for route in &routes.routes {
        // An import grant is exercised only through the ingestion-run
        // surface, which the static document does not describe.
        if route.operation == Operation::Import {
            continue;
        }
        let entity = entities
            .get(&route.entity_id)
            .expect("compiled route refers to a compiled entity");
        let response_entity = response_entity_for_route(route, entities);
        let path_entry = paths
            .entry(route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(operations) = path_entry else {
            unreachable!("OpenAPI path entries are objects")
        };
        let request_schema_ref = openapi_input_schema_id(&entity.id, route.operation);
        if matches!(route.operation, Operation::Create | Operation::Batch) {
            let writable_fields = writable_fields_for_route(route, entity);
            input_schemas.insert(
                request_schema_ref.clone(),
                openapi_entity_input_schema(entity, Some(&writable_fields)),
            );
        }
        operations.insert(
            method_name(route.method).to_owned(),
            openapi_operation(OpenApiOperationSpec {
                registry_identifier: registry_id,
                route,
                entity,
                response_entity,
                query,
                schema_ref: &response_entity.id,
                request_schema_ref: &request_schema_ref,
                readable_fields: None,
                access_profiles: OpenApiAccessProfiles::All,
            }),
        );
        if route.operation == Operation::Get
            && read_path_for_route(route, entity).is_none()
            && entity.access_log.is_some()
        {
            let path = paths
                .entry(access_log_path(route))
                .or_insert_with(|| Value::Object(Map::new()));
            path.as_object_mut()
                .expect("OpenAPI path entries are objects")
                .insert(
                    "get".to_owned(),
                    openapi_access_log_operation(route, entity, OpenApiAccessProfiles::All),
                );
            has_access_log = true;
        }
    }

    let mut has_immediate_actions = false;
    for action in &actions.actions {
        has_immediate_actions = true;
        input_schemas.insert(
            openapi_action_input_schema_id(&action.id),
            openapi_action_input_schema(action),
        );
        if action.condition_route.is_some() {
            input_schemas.insert(
                openapi_action_condition_request_schema_id(&action.id),
                openapi_action_condition_request_schema(action),
            );
            input_schemas.insert(
                openapi_action_condition_response_schema_id(&action.id),
                openapi_action_condition_response_schema(action),
            );
        }
        if action_has_availability(action) {
            input_schemas.insert(
                openapi_action_availability_request_schema_id(&action.id),
                openapi_action_availability_request_schema(action),
            );
            input_schemas.insert(
                openapi_action_availability_response_schema_id(&action.id),
                openapi_action_availability_response_schema(action),
            );
        }
        input_schemas.insert(
            openapi_action_response_schema_id(&action.id),
            openapi_action_response_schema(action, None),
        );
    }
    for route in &actions.routes {
        let action = actions
            .actions
            .iter()
            .find(|action| action.id == route.action_id)
            .expect("compiled action route refers to a compiled action");
        let path_entry = paths
            .entry(route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(operations) = path_entry else {
            unreachable!("OpenAPI path entries are objects")
        };
        operations.insert(
            method_name(route.method).to_owned(),
            openapi_action_operation(route, action, OpenApiAccessProfiles::All),
        );
    }
    append_proposal_openapi(&mut paths, actions, None);
    let mut component_schemas: Map<String, Value> = schemas
        .iter()
        .map(|(id, schema)| (id.clone(), schema.clone()))
        .collect();
    component_schemas.extend(input_schemas);
    if has_access_log {
        component_schemas.insert(
            ACCESS_LOG_RESPONSE_SCHEMA_ID.to_owned(),
            openapi_access_log_response_schema(),
        );
    }
    append_review_completion_openapi(&mut paths, &mut component_schemas);
    crate::statistical_artifacts::append_statistics_openapi(
        &mut paths,
        &mut component_schemas,
        statistical_datasets,
        statistical_datasets,
        false,
    );
    json!({
        "openapi": "3.1.0",
        "info": {"title": registry_id, "version": version},
        "paths": paths,
        "components": openapi_components(component_schemas, has_immediate_actions)
    })
}

pub(crate) const ACCESS_LOG_RESPONSE_SCHEMA_ID: &str = "SubjectAccessLogPage";

pub(crate) fn access_log_path(route: &CompiledRoute) -> String {
    format!("{}/access-log", route.path)
}

pub(crate) fn openapi_access_log_operation(
    route: &CompiledRoute,
    entity: &CompiledEntity,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Value {
    debug_assert_eq!(route.operation, Operation::Get);
    debug_assert!(entity.access_log.is_some());
    let mut operation = Map::from_iter([
        (
            "operationId".to_owned(),
            json!(format!("{}.access-log", route.id)),
        ),
        ("x-registry-recordType".to_owned(), json!(entity.id)),
        ("x-registry-operation".to_owned(), json!("access_log")),
        (
            "x-registry-responseShape".to_owned(),
            json!("BRegSubjectAccessLogV1"),
        ),
        (
            "description".to_owned(),
            json!(
                "Return the subject-facing access history for this record. The selected profile must currently grant get, and the record's configured subject field must exactly match the verified principal. Other records are concealed as 404."
            ),
        ),
        ("security".to_owned(), json!([{"bearerAuth": []}])),
    ]);
    match access_profiles {
        OpenApiAccessProfiles::All => {
            operation.insert(
                "x-registry-accessProfiles".to_owned(),
                json!(route.access_profiles),
            );
        }
        OpenApiAccessProfiles::Selected(profile) => {
            operation.insert("x-registry-accessProfile".to_owned(), json!(profile));
        }
    }
    operation.insert(
        "parameters".to_owned(),
        json!([
            path_parameter(
                "record_id",
                json!({"type": "string", "format": "uuid"}),
                "Canonical record UUID owned by the verified subject."
            ),
            header_parameter(
                "traceparent",
                false,
                traceparent_schema(),
                "Optional W3C trace context. Responses carry Registry trace context for the request."
            ),
            access_profile_parameter(route.default_access_profile.is_none()),
            query_parameter(
                "limit",
                false,
                false,
                json!({"type": "integer", "minimum": 1, "maximum": 100, "default": 50}),
                "Maximum visible access events returned in this page."
            ),
            query_parameter(
                "cursor",
                false,
                false,
                json!({"type": "string", "format": "uuid"}),
                "Opaque event cursor from the preceding page, scoped to this record and verified subject."
            )
        ]),
    );
    operation.insert(
        "responses".to_owned(),
        json!({
            "200": {
                "description": "Subject-facing access events returned",
                "headers": {
                    "traceparent": traceparent_header("Trace context for this response."),
                    "Cache-Control": no_store_header()
                },
                "content": {
                    "application/json": {
                        "schema": {"$ref": format!("#/components/schemas/{ACCESS_LOG_RESPONSE_SCHEMA_ID}")}
                    }
                }
            },
            "400": access_log_problem_response("The query or cursor is invalid."),
            "404": access_log_problem_response("The record or subject-owned access log was not found."),
            "503": access_log_problem_response("The subject access-log service is unavailable.")
        }),
    );
    Value::Object(operation)
}

fn access_log_problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "traceparent": traceparent_header("Trace context for this problem response."),
            "Cache-Control": no_store_header()
        },
        "content": {
            "application/problem+json": {
                "schema": {"$ref": "#/components/schemas/Problem"}
            }
        }
    })
}

pub(crate) fn openapi_access_log_response_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["events", "nextCursor"],
        "properties": {
            "events": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "id", "accessedAt", "requester", "serviceClient", "purpose",
                        "operationId", "visibleAfter", "exemptionReason"
                    ],
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "accessedAt": {"type": "string", "format": "date-time"},
                        "requester": {"type": "string", "minLength": 1, "maxLength": 512},
                        "serviceClient": {"type": ["string", "null"], "minLength": 1, "maxLength": 512},
                        "purpose": {"type": ["string", "null"], "minLength": 1, "maxLength": 512},
                        "operationId": {"type": "string", "minLength": 1, "maxLength": 256},
                        "visibleAfter": {"type": "string", "format": "date-time"},
                        "exemptionReason": {"type": ["string", "null"], "minLength": 1, "maxLength": 256}
                    }
                }
            },
            "nextCursor": {"type": ["string", "null"], "format": "uuid"}
        }
    })
}

pub(crate) fn append_review_completion_openapi(
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
) {
    schemas.insert(
        "ReviewCompletion".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "type": {"const": "review.completed"},
                "eventId": {"type": "string", "format": "uuid"},
                "requestId": {"type": "string", "format": "uuid"},
                "resultId": {"type": "string", "format": "uuid"},
                "completedAt": {"type": "string", "format": "date-time"}
            },
            "required": ["type", "eventId", "requestId", "resultId", "completedAt"]
        }),
    );
    paths.insert(
        "/v1/review-completions".to_owned(),
        json!({
            "post": {
                "operationId": "receiveReviewCompletion",
                "summary": "Receive a Casework review completion",
                "description": "Available when a review authority configures a completion token and recipient binding.",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "Registry-Recipient-Binding",
                        "in": "header",
                        "required": true,
                        "schema": {"type": "string", "minLength": 1, "maxLength": 256}
                    },
                    {
                        "name": "Idempotency-Key",
                        "in": "header",
                        "required": true,
                        "description": "Must equal eventId.",
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ReviewCompletion"}
                        }
                    }
                },
                "responses": {
                    "204": {"description": "Completion accepted or already recorded."},
                    "400": {"description": "The completion or idempotency binding is invalid."},
                    "401": {"description": "The completion authority could not be authenticated."},
                    "415": {"description": "The request is not application/json."},
                    "503": {"description": "The completion could not be durably recorded."}
                }
            }
        }),
    );
}

#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) enum OpenApiAccessProfiles<'a> {
    All,
    Selected(&'a str),
}

#[derive(Clone, Copy)]
pub(crate) struct OpenApiOperationSpec<'a> {
    pub registry_identifier: &'a str,
    pub route: &'a CompiledRoute,
    pub entity: &'a CompiledEntity,
    pub response_entity: &'a CompiledEntity,
    pub query: &'a CompiledQueryInventory,
    pub schema_ref: &'a str,
    pub request_schema_ref: &'a str,
    pub readable_fields: Option<&'a BTreeSet<String>>,
    pub access_profiles: OpenApiAccessProfiles<'a>,
}

const OPENAPI_EXAMPLE_TRACE_ID: &str = "11111111111111111111111111111111";
const OPENAPI_EXAMPLE_TRACEPARENT: &str = "00-11111111111111111111111111111111-2222222222222222-01";

pub(crate) fn openapi_components(
    mut schemas: Map<String, Value>,
    has_immediate_actions: bool,
) -> Value {
    schemas.insert("Problem".to_owned(), problem_schema());
    if has_immediate_actions {
        schemas.insert(
            "ImmediateActionResultReference".to_owned(),
            immediate_action_result_reference_schema(),
        );
        schemas.insert(
            "ImmediateActionPrecondition".to_owned(),
            immediate_action_precondition_schema(),
        );
    }
    json!({
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        },
        "schemas": schemas
    })
}

pub(crate) fn openapi_operation(spec: OpenApiOperationSpec<'_>) -> Value {
    let geojson_profiles = geojson_profiles(spec);
    let mut operation = Map::from_iter([
        ("operationId".to_owned(), json!(spec.route.id)),
        (
            "x-registry-recordType".to_owned(),
            json!(spec.route.entity_id),
        ),
        (
            "x-registry-responseRecordType".to_owned(),
            json!(spec.response_entity.id),
        ),
        (
            "x-registry-operation".to_owned(),
            json!(operation_name(spec.route.operation)),
        ),
        ("security".to_owned(), bearer_security()),
    ]);
    if geojson_profiles.is_empty() {
        operation.insert(
            "x-registry-responseShape".to_owned(),
            json!(operation_response_shape(spec)),
        );
    } else {
        operation.insert(
            "x-registry-responseShapes".to_owned(),
            json!({
                "application/json": operation_response_shape(spec),
                "application/ld+json": operation_response_shape(spec),
                "application/geo+json": geojson_operation_response_shape(spec),
            }),
        );
    }
    if is_registry_record_response(spec) {
        operation.insert(
            "x-registry-responseProfile".to_owned(),
            json!(PROFILE_IDENTIFIER),
        );
    }
    match spec.access_profiles {
        OpenApiAccessProfiles::All => {
            operation.insert(
                "x-registry-accessProfiles".to_owned(),
                json!(spec.route.access_profiles),
            );
        }
        OpenApiAccessProfiles::Selected(profile) => {
            operation.insert("x-registry-accessProfile".to_owned(), json!(profile));
        }
    }
    if let Some(kind) = spec.route.query_kind {
        operation.insert(
            "x-registry-queryKind".to_owned(),
            Value::String(query_kind_name(kind).to_owned()),
        );
    }
    if let Some(kind) = spec.route.revision_kind {
        operation.insert(
            "x-registry-revisionKind".to_owned(),
            Value::String(revision_kind_name(kind).to_owned()),
        );
        operation.insert(
            "x-registry-maximumRecords".to_owned(),
            json!(spec.route.maximum_records),
        );
    }
    if spec.route.operation == Operation::Batch {
        let batch = spec
            .entity
            .batch
            .as_ref()
            .expect("batch routes require compiled bounds");
        operation.insert(
            "x-registry-maximumItems".to_owned(),
            json!(batch.maximum_items),
        );
        operation.insert(
            "x-registry-maximumBytes".to_owned(),
            json!(batch.maximum_bytes),
        );
    }
    if let Some(query_profile) = query_profile_extension(spec) {
        operation.insert(query_profile.0, query_profile.1);
    }
    let mut parameters = operation_parameters(spec.route, spec.query, spec.access_profiles);
    if !geojson_profiles.is_empty() {
        if let Some(select) = parameters
            .iter_mut()
            .find(|parameter| parameter["name"] == "$select")
        {
            select["examples"] = geojson_selection_examples(spec, &geojson_profiles);
        }
        operation.insert(
            "x-registry-geojsonProfiles".to_owned(),
            json!(geojson_profiles),
        );
    }
    if is_registry_record_response(spec) {
        let mut media_types = vec!["application/json", "application/ld+json"];
        if !geojson_profiles.is_empty() {
            media_types.push("application/geo+json");
        }
        parameters.push(header_parameter(
            "Accept",
            false,
            json!({"type": "string", "enum": media_types}),
            if geojson_profiles.is_empty() {
                "Choose the ordinary JSON or JSON-LD Registry Record representation."
            } else {
                "Choose ordinary JSON, JSON-LD, or GeoJSON. Selecting fields without the primary Point returns null geometry; include that Point in $select to display a map feature."
            },
        ));
    }
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if let Some(request_body) = operation_request_body(spec) {
        operation.insert("requestBody".to_owned(), request_body);
    }
    operation.insert("responses".to_owned(), operation_responses(spec));
    Value::Object(operation)
}

fn is_registry_record_response(spec: OpenApiOperationSpec<'_>) -> bool {
    matches!(
        spec.route.operation,
        Operation::Create
            | Operation::Get
            | Operation::Lookup
            | Operation::List
            | Operation::Snapshot
            | Operation::Patch
            | Operation::Tombstone
            | Operation::Revisions
    )
}

fn operation_response_shape(spec: OpenApiOperationSpec<'_>) -> &'static str {
    match spec.route.operation {
        Operation::Create
        | Operation::Get
        | Operation::Lookup
        | Operation::Patch
        | Operation::Tombstone => "RegistryRecordSingleV1",
        Operation::List => "RegistryRecordCollectionV1",
        Operation::Snapshot => "BRegSnapshotCollectionV1",
        Operation::Revisions if spec.route.revision_kind == Some(CompiledRevisionKind::Detail) => {
            "BRegRevisionRecordV1"
        }
        Operation::Revisions => "BRegRevisionCollectionV1",
        Operation::Batch => "BRegAtomicBatchMutationResponseV1",
        Operation::Invoke => "BRegActionReceiptV1",
        Operation::Start => "BRegProposalV1",
        Operation::Import => {
            unreachable!("import routes are served only by the ingestion-run surface")
        }
    }
}

fn geojson_operation_response_shape(spec: OpenApiOperationSpec<'_>) -> &'static str {
    match spec.route.operation {
        Operation::Get => "BRegGeoJsonFeatureV1",
        Operation::List => "BRegGeoJsonFeatureCollectionV1",
        _ => unreachable!("only record get and list routes expose GeoJSON"),
    }
}

fn operation_parameters(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<Value> {
    let mut parameters = Vec::new();
    if route.path.contains("{record_id}") {
        parameters.push(path_parameter(
            "record_id",
            json!({"type": "string", "format": "uuid"}),
            "Canonical record UUID.",
        ));
    }
    if route.path.contains("{revision}") {
        parameters.push(path_parameter(
            "revision",
            json!({"type": "integer", "format": "int64", "minimum": 1}),
            "Exact positive record revision.",
        ));
    }
    parameters.push(header_parameter(
        "traceparent",
        false,
        traceparent_schema(),
        "Optional W3C trace context. Responses carry Registry trace context for the request.",
    ));
    parameters.push(access_profile_parameter(
        route.default_access_profile.is_none(),
    ));
    match route.operation {
        Operation::Get => {
            parameters.push(query_parameter(
                "$select",
                false,
                false,
                json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
                "Comma-separated subset of readable API property names.",
            ));
        }
        Operation::List => {
            parameters.extend(read_query_parameters(route, query, access_profiles));
        }
        Operation::Snapshot => {
            parameters.extend(read_query_parameters(route, query, access_profiles));
            parameters.push(query_parameter(
                "snapshot",
                false,
                false,
                json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}),
                "Opaque Registry history snapshot reference. Omit to capture the latest committed position.",
            ));
            if let Some(schema) = snapshot_valid_at_schema(route, query, access_profiles) {
                parameters.push(query_parameter(
                    "validAt",
                    false,
                    false,
                    schema,
                    "Effective-validity value evaluated within the selected historical snapshot.",
                ));
            }
        }
        Operation::Lookup => parameters.push(query_parameter(
            "$select",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Comma-separated subset of readable API property names.",
        )),
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch => {
            parameters.push(header_parameter(
                "Idempotency-Key",
                true,
                json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
                "Idempotency key bound to method, route, caller, target record, package revision, request body, and response field set.",
            ));
            if matches!(route.operation, Operation::Patch | Operation::Tombstone) {
                parameters.push(header_parameter(
                    "If-Match",
                    true,
                    json!({"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}),
                    "Strong Registry ETag for the currently visible record representation.",
                ));
            }
        }
        Operation::Revisions => {}
        Operation::Invoke | Operation::Start => {}
        Operation::Import => {
            unreachable!("import routes are served only by the ingestion-run surface")
        }
    }
    parameters
}

fn read_query_parameters(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<Value> {
    let mut parameters = vec![
        query_parameter(
            "$select",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Comma-separated subset of readable API property names.",
        ),
        query_parameter(
            "$filter",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Strict Registry read filter expression over compiled filterable API properties.",
        ),
        query_parameter(
            "$orderby",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES}),
            "One compiled sortable property, ascending only.",
        ),
        query_parameter(
            "$top",
            false,
            false,
            json!({"type": "integer", "minimum": 1, "maximum": max_page_size(route, query, access_profiles)}),
            "Bounded page size.",
        ),
        query_parameter(
            "$count",
            false,
            false,
            json!({"type": "boolean"}),
            "Request count when the selected compiled query profile allows it.",
        ),
        query_parameter(
            "$skiptoken",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_CURSOR_TOKEN_BYTES}),
            "Opaque continuation cursor for the next page.",
        ),
    ];
    if route.query_kind == Some(CompiledQueryKind::AsOf) {
        parameters.push(query_parameter(
            "asOf",
            true,
            false,
            json!({"type": "string", "format": "date-time"}),
            "Strict UTC RFC3339 instant for the as-of temporal query.",
        ));
    }
    if query_profiles_for_route(route, query, access_profiles)
        .iter()
        .any(|profile| {
            profile
                .spatial
                .as_ref()
                .and_then(|spatial| spatial.bbox.as_ref())
                .is_some()
        })
    {
        parameters.push(query_parameter(
            "bbox",
            false,
            false,
            json!({"type": "string", "maxLength": 256, "example": "100.4,13.6,100.6,13.8"}),
            "Inclusive west,south,east,north CRS84 bounds within the selected profile's maximum spans. Finite decimal or exponent coordinates only; zero spans are valid. No crossing, 3D, alternate CRS or temporal queries. ANDed with $filter. Continuations carry only $skiptoken and routing/profile context.",
        ));
    }
    parameters
}

fn snapshot_valid_at_schema(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Option<Value> {
    let kind = query_profiles_for_route(route, query, access_profiles)
        .into_iter()
        .filter_map(|operation| {
            operation
                .temporal
                .as_ref()
                .map(|temporal| temporal.value_kind)
        })
        .max()?;
    Some(match kind {
        CompiledQueryTemporalValueKind::Date => json!({"type": "string", "format": "date"}),
        CompiledQueryTemporalValueKind::Timestamp => {
            json!({"type": "string", "format": "date-time"})
        }
    })
}

fn query_parameter(
    name: &str,
    required: bool,
    repeatable: bool,
    schema: Value,
    description: &str,
) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": schema,
        "explode": repeatable,
    })
}

fn access_profile_parameter(required: bool) -> Value {
    query_parameter(
        "accessProfile",
        required,
        false,
        json!({"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES}),
        "Select one compiled access profile. Required when the route has no default; otherwise omission uses its default.",
    )
}

fn header_parameter(name: &str, required: bool, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "header",
        "required": required,
        "description": description,
        "schema": schema,
    })
}

fn path_parameter(name: &str, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": schema,
    })
}

fn operation_request_body(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    match spec.route.operation {
        Operation::Create => Some(json_request_body(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["data"],
            "properties": {
                "data": {"$ref": format!("#/components/schemas/{}", spec.request_schema_ref)}
            }
        }))),
        Operation::Patch => Some(json_patch_request_body()),
        Operation::Lookup => Some(json_request_body(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["selector"],
            "properties": {
                "selector": {"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES},
                "values": {
                    "type": "object",
                    "maxProperties": 16,
                    "additionalProperties": {
                        "oneOf": [
                            {"type": "string", "maxLength": crate::query::MAX_LITERAL_BYTES},
                            {"type": "integer", "format": "int64"},
                            {"type": "boolean"}
                        ]
                    }
                }
            }
        }))),
        Operation::Batch => {
            let batch = spec
                .entity
                .batch
                .as_ref()
                .expect("batch routes require compiled bounds");
            let (allow_create, allow_patch) = batch_permissions(spec);
            Some(batch_request_body(
                spec.request_schema_ref,
                batch.maximum_items,
                allow_create,
                allow_patch,
            ))
        }
        Operation::Get
        | Operation::List
        | Operation::Tombstone
        | Operation::Revisions
        | Operation::Snapshot => None,
        Operation::Invoke | Operation::Start => None,
        Operation::Import => {
            unreachable!("import routes are served only by the ingestion-run surface")
        }
    }
}

fn json_request_body(schema: Value) -> Value {
    json!({
        "required": true,
        "content": {"application/json": {"schema": schema}}
    })
}

fn json_patch_request_body() -> Value {
    json!({
        "required": true,
        "content": {"application/json-patch+json": {"schema": json_patch_array_schema()}}
    })
}

fn batch_request_body(
    schema_ref: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    json_request_body(batch_input_schema(
        json!({"$ref": format!("#/components/schemas/{schema_ref}")}),
        maximum_items,
        allow_create,
        allow_patch,
    ))
}

#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn openapi_batch_input_schema(
    entity: &CompiledEntity,
    writable_fields: Option<&BTreeSet<String>>,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    batch_input_schema(
        openapi_entity_input_schema(entity, writable_fields),
        maximum_items,
        allow_create,
        allow_patch,
    )
}

fn batch_input_schema(
    create_data_schema: Value,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["items"],
        "properties": {
            "changeContext": change_context_request_schema(),
            "items": openapi_batch_items_schema(
                create_data_schema,
                maximum_items,
                allow_create,
                allow_patch,
            )
        }
    })
}

/// The bounded array of batch items one grant admits. The batch request body
/// and the ingestion chunk body carry the same item shapes.
pub(crate) fn openapi_batch_items_schema(
    create_data_schema: Value,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let mut item_schemas = Vec::new();
    if allow_create {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "data"],
            "properties": {
                "operation": {"const": "create"},
                "data": create_data_schema,
            }
        }));
    }
    if allow_patch {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "recordId", "ifMatch", "patch"],
            "properties": {
                "operation": {"const": "patch"},
                "recordId": {"type": "string", "format": "uuid"},
                "ifMatch": {"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"},
                "patch": json_patch_array_schema(),
            }
        }));
    }
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": maximum_items,
        "items": {"oneOf": item_schemas}
    })
}

fn change_context_request_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "x-registry-maxCanonicalBytes": 16 * 1024,
        "properties": {
            "kind": {"type": "string", "enum": ["change", "correction"]},
            "reasonCode": bounded_nonempty_text_schema(64),
            "reasonText": bounded_nonempty_text_schema(4 * 1024),
            "sourceReferences": {
                "type": "array",
                "maxItems": 16,
                "items": bounded_nonempty_text_schema(256)
            }
        },
        "allOf": [{
            "if": {
                "required": ["kind"],
                "properties": {"kind": {"const": "correction"}}
            },
            "then": {"required": ["reasonCode"]}
        }]
    })
}

fn bounded_nonempty_text_schema(max_bytes: usize) -> Value {
    let mut schema = bounded_text_schema(max_bytes);
    schema
        .as_object_mut()
        .expect("bounded text schema is an object")
        .insert("minLength".to_owned(), json!(1));
    schema
}

fn bounded_text_schema(max_bytes: usize) -> Value {
    json!({
        "type": "string",
        "maxLength": max_bytes,
        "x-registry-maxBytes": max_bytes
    })
}

pub(crate) fn json_patch_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 128,
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["op", "path"],
            "properties": {
                "op": {"type": "string", "enum": ["add", "replace", "remove", "test"]},
                "path": {"type": "string"},
                "value": true
            },
            "if": {"properties": {"op": {"const": "remove"}}},
            "then": {"not": {"required": ["value"]}},
            "else": {"required": ["value"]}
        }
    })
}

fn operation_responses(spec: OpenApiOperationSpec<'_>) -> Value {
    let mut success = match spec.route.operation {
        Operation::Create => registry_record_success_response(
            spec,
            "Record created",
            StatusResponseHeaders::MutationCreate,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Get => registry_record_success_response(
            spec,
            "Record returned",
            StatusResponseHeaders::ReadDetail,
            single_response_schema(spec, record_member_schema(spec), false),
            single_response_schema(spec, record_member_schema(spec), true),
        ),
        Operation::Lookup => registry_record_success_response(
            spec,
            "Lookup resolved to one record",
            StatusResponseHeaders::NoStore,
            single_response_schema(spec, record_member_schema(spec), false),
            single_response_schema(spec, record_member_schema(spec), true),
        ),
        Operation::List => registry_record_success_response(
            spec,
            "Records returned",
            StatusResponseHeaders::NoStore,
            list_response_schema(spec, false),
            list_response_schema(spec, true),
        ),
        Operation::Snapshot => registry_record_success_response(
            spec,
            "Historical records returned",
            StatusResponseHeaders::NoStore,
            snapshot_response_schema(spec, false),
            snapshot_response_schema(spec, true),
        ),
        Operation::Patch => registry_record_success_response(
            spec,
            "Record patched",
            StatusResponseHeaders::Mutation,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Tombstone => registry_record_success_response(
            spec,
            "Record tombstoned",
            StatusResponseHeaders::Mutation,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Batch => {
            let batch = spec
                .entity
                .batch
                .as_ref()
                .expect("batch routes require compiled bounds");
            let (allow_create, allow_patch) = batch_permissions(spec);
            success_response(
                "Atomic batch committed",
                StatusResponseHeaders::Mutation,
                batch_response_schema(
                    spec.schema_ref,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            )
        }
        Operation::Revisions => registry_record_success_response(
            spec,
            "Record revisions returned",
            StatusResponseHeaders::NoStore,
            revision_response_schema(spec, false),
            revision_response_schema(spec, true),
        ),
        Operation::Import => {
            unreachable!("import routes are served only by the ingestion-run surface")
        }
        Operation::Invoke | Operation::Start => success_response(
            "Action accepted",
            StatusResponseHeaders::ActionMutation,
            json!({"type": "object"}),
        ),
    };
    if let Some(schema) = geojson_response_schema(spec) {
        success["content"]["application/geo+json"] = json!({"schema": schema});
        success["headers"]["Vary"] = json!({
            "description": "Responses vary by authorization and negotiated representation.",
            "schema": {"type": "string"}
        });
        if spec.route.operation == Operation::Get {
            success["headers"]["ETag"]["description"] = json!(
                "Strong Registry mutation precondition for JSON and JSON-LD only. GeoJSON does not return this validator."
            );
            success["headers"]["Cache-Control"] = json!({
                "description": "Protected GeoJSON responses are not stored.",
                "schema": {"type": "string"}
            });
        }
    }
    let success_status = if spec.route.operation == Operation::Create {
        "201"
    } else {
        "200"
    };
    let mut responses = Map::from_iter([(success_status.to_owned(), success)]);
    for (status, problems) in
        problem_responses(spec.route.operation, operation_has_row_boundaries(spec))
    {
        let examples = problems
            .iter()
            .map(|problem| {
                (
                    problem.code.to_owned(),
                    json!({"value": problem_example(status, problem.code, problem.detail)}),
                )
            })
            .collect::<Map<_, _>>();
        responses.insert(
            status.to_owned(),
            json!({
                "description": "Problem response",
                "headers": {
                    "traceparent": traceparent_header("Trace context for this problem response."),
                    "Cache-Control": no_store_header()
                },
                "content": {
                    "application/problem+json": {
                        "schema": {"$ref": "#/components/schemas/Problem"},
                        "examples": examples
                    }
                }
            }),
        );
    }
    Value::Object(responses)
}

#[derive(Clone, Copy)]
enum StatusResponseHeaders {
    ReadDetail,
    NoStore,
    Mutation,
    MutationCreate,
    ProposalCreate,
    ActionMutation,
}

fn success_response(description: &str, headers: StatusResponseHeaders, schema: Value) -> Value {
    let mut response = Map::from_iter([
        ("description".to_owned(), json!(description)),
        (
            "content".to_owned(),
            json!({"application/json": {"schema": schema}}),
        ),
    ]);
    let mut header_map = match headers {
        StatusResponseHeaders::ReadDetail => json!({
            "ETag": etag_header(),
        }),
        StatusResponseHeaders::NoStore => json!({
            "Cache-Control": no_store_header(),
        }),
        StatusResponseHeaders::Mutation => json!({
            "ETag": etag_header(),
        }),
        StatusResponseHeaders::MutationCreate => json!({
            "ETag": etag_header(),
            "Location": {"description": "Relative URL of the created record.", "schema": {"type": "string"}},
        }),
        StatusResponseHeaders::ProposalCreate => json!({
            "ETag": proposal_etag_header(),
            "Location": {"description": "Relative URL of the created Proposal.", "schema": {"type": "string"}},
        }),
        StatusResponseHeaders::ActionMutation => json!({}),
    };
    header_map
        .as_object_mut()
        .expect("response headers are objects")
        .insert(
            "traceparent".to_owned(),
            traceparent_header("Trace context for this response."),
        );
    header_map
        .as_object_mut()
        .expect("response headers are objects")
        .insert("Cache-Control".to_owned(), no_store_header());
    response.insert("headers".to_owned(), header_map);
    Value::Object(response)
}

fn registry_record_success_response(
    spec: OpenApiOperationSpec<'_>,
    description: &str,
    headers: StatusResponseHeaders,
    json_schema: Value,
    json_ld_schema: Value,
) -> Value {
    let mut response = success_response(description, headers, json_schema);
    response["content"]["application/ld+json"] = json!({"schema": json_ld_schema});
    response["headers"]["Link"] = json!({
        "description": "Emitted only for application/json and application/ld+json Registry Record responses and omitted for application/geo+json. Carries the Registry Record profile and caller-visible record type schema. The describedby target includes the configured deployment prefix and is never derived from Host or forwarded headers.",
        "schema": {
            "type": "string",
            "example": link_header_value(spec.response_entity, "")
                .expect("compiled entity identifiers are safe response-header components")
        }
    });
    response["headers"]["Vary"] = json!({
        "description": "Responses vary by authorization and negotiated representation.",
        "schema": {"type": "string"}
    });
    response
}

fn no_store_header() -> Value {
    json!({"description": "Caller-dependent responses must not be stored.", "schema": {"const": "no-store"}})
}

fn etag_header() -> Value {
    json!({
        "description": "Strong Registry ETag bound to the record, package revision, caller profile, and response field set.",
        "schema": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}
    })
}

fn proposal_etag_header() -> Value {
    json!({
        "description": "Strong Registry ETag for the created Proposal.",
        "schema": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}
    })
}

fn traceparent_header(description: &str) -> Value {
    json!({
        "description": description,
        "schema": traceparent_schema(),
        "example": OPENAPI_EXAMPLE_TRACEPARENT,
    })
}

fn traceparent_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 55,
        "maxLength": 55,
        "pattern": "^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
    })
}

fn record_member_schema(spec: OpenApiOperationSpec<'_>) -> Value {
    let profiles = match spec.access_profiles {
        OpenApiAccessProfiles::All => spec
            .route
            .access_profiles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        OpenApiAccessProfiles::Selected(profile) => vec![profile],
    };
    let readable = profiles
        .into_iter()
        .flat_map(|profile| selectable_fields_for_profile(spec, profile))
        .collect::<BTreeSet<_>>();
    let properties = spec
        .response_entity
        .stored_fields
        .iter()
        .filter(|field| readable.contains(&field.logical.id))
        .map(|field| {
            (
                field.logical.api_name.clone(),
                stored_field_value_schema(
                    field,
                    spec.response_entity.fields[&field.logical.id]
                        .generate
                        .is_some(),
                ),
            )
        })
        .chain(
            spec.response_entity
                .derived_fields
                .values()
                .filter(|field| readable.contains(&field.logical.id))
                .map(|field| {
                    (
                        field.logical.api_name.clone(),
                        field_value_schema(&field.logical.field_type, true),
                    )
                }),
        )
        .collect::<Map<_, _>>();
    json!({"type":"object","additionalProperties":false,
        "required":["recordIdentifier","revisionIdentifier","domainData"],
        "properties":{"recordIdentifier":{"type":"string","format":"uuid"},
            "revisionIdentifier":{"type":"string","pattern":"^[1-9][0-9]*$"},
            "domainData":{"type":"object","additionalProperties":false,"properties":properties}}})
}

fn mutation_record_member_schema(schema_ref: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordIdentifier", "revisionIdentifier", "domainData", "snapshot"],
        "properties": {
            "recordIdentifier": {"type": "string", "format": "uuid"},
            "revisionIdentifier": {"type": "string", "pattern": "^[1-9][0-9]*$"},
            "snapshot": snapshot_reference_schema(),
            "domainData": {"$ref": format!("#/components/schemas/{schema_ref}")},
        }
    })
}

fn snapshot_reference_schema() -> Value {
    json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES})
}

fn response_meta_schema(spec: OpenApiOperationSpec<'_>) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["registryIdentifier", "datasetIdentifier", "entityTypeIdentifier"],
        "properties": {
            "registryIdentifier": {"const": spec.registry_identifier},
            "datasetIdentifier": {
                "const": spec.response_entity.primary_dataset.as_deref()
                    .expect("served entities have a compiled primary dataset")
            },
            "entityTypeIdentifier": {"const": spec.response_entity.id}
        }
    })
}

fn single_response_schema(
    spec: OpenApiOperationSpec<'_>,
    member_schema: Value,
    json_ld: bool,
) -> Value {
    let mut required = vec!["data", "meta"];
    let mut properties = Map::from_iter([
        ("data".to_owned(), member_schema),
        ("meta".to_owned(), response_meta_schema(spec)),
    ]);
    if json_ld {
        required.push("@context");
        properties.insert("@context".to_owned(), json!({"const": CONTEXT_IDENTIFIER}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn collection_response_schema(
    spec: OpenApiOperationSpec<'_>,
    member_schema: Value,
    mut extensions: Map<String, Value>,
    required_extensions: &[&'static str],
    json_ld: bool,
) -> Value {
    let mut required = vec!["items", "pageInfo", "meta"];
    required.extend_from_slice(required_extensions);
    let mut properties = Map::from_iter([
        (
            "items".to_owned(),
            json!({"type": "array", "items": member_schema}),
        ),
        (
            "pageInfo".to_owned(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["nextCursor"],
                "properties": {
                    "nextCursor": {"type": ["string", "null"], "maxLength": crate::query::MAX_CURSOR_TOKEN_BYTES}
                }
            }),
        ),
        ("meta".to_owned(), response_meta_schema(spec)),
    ]);
    properties.append(&mut extensions);
    if json_ld {
        required.push("@context");
        properties.insert("@context".to_owned(), json!({"const": CONTEXT_IDENTIFIER}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn list_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    collection_response_schema(
        spec,
        record_member_schema(spec),
        Map::from_iter([(
            "count".to_owned(),
            json!({"type": "integer", "format": "int64", "minimum": 0}),
        )]),
        &[],
        json_ld,
    )
}

fn snapshot_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    let mut extensions = Map::from_iter([
        ("snapshot".to_owned(), snapshot_reference_schema()),
        (
            "count".to_owned(),
            json!({"type": "integer", "format": "int64", "minimum": 0}),
        ),
    ]);
    if let Some(valid_at) = snapshot_valid_at_schema(spec.route, spec.query, spec.access_profiles) {
        extensions.insert("validAt".to_owned(), valid_at);
    }
    collection_response_schema(
        spec,
        record_member_schema(spec),
        extensions,
        &["snapshot"],
        json_ld,
    )
}

fn geojson_profiles<'a>(spec: OpenApiOperationSpec<'a>) -> Vec<&'a str> {
    let Some(binding) = &spec.response_entity.geojson else {
        return Vec::new();
    };
    if spec.route.revision_kind.is_some()
        || spec.entity.id != spec.response_entity.id
        || read_path_for_route(spec.route, spec.entity).is_some()
        || !matches!(
            (spec.route.operation, spec.route.query_kind),
            (Operation::Get, None) | (Operation::List, Some(CompiledQueryKind::List))
        )
    {
        return Vec::new();
    }
    spec.route
        .access_profiles
        .iter()
        .filter(|profile_id| match spec.access_profiles {
            OpenApiAccessProfiles::All => true,
            OpenApiAccessProfiles::Selected(selected) => profile_id.as_str() == selected,
        })
        .filter(|profile_id| {
            spec.entity
                .access_profiles
                .get(profile_id.as_str())
                .is_some_and(|profile| profile.readable_fields.contains(&binding.geometry_field))
        })
        .map(String::as_str)
        .collect()
}

fn geojson_response_schema(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    let profiles = geojson_profiles(spec);
    if profiles.is_empty() {
        return None;
    }
    let entity = spec.response_entity;
    let binding = entity.geojson.as_ref()?;
    let geometry = entity.fields.get(&binding.geometry_field)?;
    let fields: BTreeSet<_> = profiles
        .iter()
        .flat_map(|profile| selectable_fields_for_profile(spec, profile))
        .collect();
    let mut properties = Map::new();
    for field in &entity.stored_fields {
        if fields.contains(&field.logical.id) && field.logical.id != binding.geometry_field {
            properties.insert(
                field.logical.api_name.clone(),
                stored_field_value_schema(
                    field,
                    entity.fields[&field.logical.id].generate.is_some(),
                ),
            );
        }
    }
    for field in entity.derived_fields.values() {
        if fields.contains(&field.logical.id) {
            properties.insert(
                field.logical.api_name.clone(),
                json!({
                    "anyOf": [field_schema(&field.logical.field_type), {"type": "null"}]
                }),
            );
        }
    }
    let feature = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "id", "geometry", "properties", "registry"],
        "properties": {
            "type": {"const": "Feature"},
            "id": {"type": "string", "format": "uuid"},
            "geometry": {"anyOf": [field_schema(&geometry.field_type), {"type": "null"}]},
            "properties": {"type": "object", "additionalProperties": false, "properties": properties},
            "registry": {
                "type": "object",
                "additionalProperties": false,
                "required": ["revision"],
                "properties": {"revision": {"type": "integer", "format": "int64", "minimum": 1}}
            }
        },
        "description": "Selected logical fields use their API names. The primary Point appears only as geometry. Omitting it from $select returns null geometry. Registry record metadata is in the registry foreign member."
    });
    if spec.route.operation == Operation::Get {
        return Some(feature);
    }
    let collection = list_response_schema(spec, false);
    Some(json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "features", "numberReturned", "registry"],
        "properties": {
            "type": {"const": "FeatureCollection"},
            "features": {"type": "array", "items": feature},
            "numberReturned": {"type": "integer", "minimum": 0},
            "registry": {
                "type": "object",
                "additionalProperties": false,
                "required": ["pageInfo"],
                "properties": {
                    "pageInfo": collection["properties"]["pageInfo"],
                    "count": collection["properties"]["count"]
                }
            }
        },
        "description": "Live authorized collection. Follow registry.pageInfo.nextCursor with the same representation and authority. A refresh starts a fresh traversal; concurrent edits can change membership. Count is present only when requested and permitted."
    }))
}

fn geojson_selection_examples(spec: OpenApiOperationSpec<'_>, profiles: &[&str]) -> Value {
    let binding = spec
        .response_entity
        .geojson
        .as_ref()
        .expect("GeoJSON profiles have a binding");
    let geometry = api_field_name(spec.response_entity, &binding.geometry_field)
        .expect("compiled GeoJSON binding has an API field");
    let attributes: BTreeSet<_> = profiles
        .iter()
        .flat_map(|profile| selectable_fields_for_profile(spec, profile))
        .filter(|field| field != &binding.geometry_field)
        .filter_map(|field| api_field_name(spec.response_entity, &field).map(str::to_owned))
        .collect();
    let attributes: Vec<_> = attributes.into_iter().take(2).collect();
    let mut with_geometry = attributes.clone();
    with_geometry.push(geometry.to_owned());
    let mut examples = Map::from_iter([(
        "withGeometry".to_owned(),
        json!({
            "summary": "Include the Point to render a map feature",
            "value": with_geometry.join(",")
        }),
    )]);
    if !attributes.is_empty() {
        examples.insert(
            "withoutGeometry".to_owned(),
            json!({
                "summary": "Select attributes only; GeoJSON geometry is null",
                "value": attributes.join(",")
            }),
        );
    }
    Value::Object(examples)
}

fn batch_response_schema(
    schema_ref: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let operations = [
        allow_create.then_some("create"),
        allow_patch.then_some("patch"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["snapshot", "results"],
        "properties": {
            "snapshot": snapshot_reference_schema(),
            "results": {
                "type": "array",
                "minItems": 1,
                "maxItems": maximum_items,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["operation", "id", "revision", "etag", "data"],
                    "properties": {
                        "operation": {"enum": operations},
                        "id": {"type": "string", "format": "uuid"},
                        "revision": {"type": "integer", "format": "int64", "minimum": 1},
                        "etag": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"},
                        "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
                    }
                }
            }
        }
    })
}

fn revision_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    let mut properties = Map::from_iter([
        (
            "recordIdentifier".to_owned(),
            json!({"type": "string", "format": "uuid"}),
        ),
        (
            "revisionIdentifier".to_owned(),
            json!({"type": "string", "pattern": "^[1-9][0-9]*$"}),
        ),
        (
            "predecessorRevision".to_owned(),
            json!({"type": ["integer", "null"], "format": "int64", "minimum": 1}),
        ),
        (
            "lifecycle".to_owned(),
            json!({"type": "string", "enum": ["active", "tombstoned"]}),
        ),
        (
            "mutationKind".to_owned(),
            json!({"type": "string", "enum": ["create", "patch", "tombstone", "migration"]}),
        ),
        ("packageRevision".to_owned(), json!({"type": "string"})),
        ("operationIdentifier".to_owned(), json!({"type": "string"})),
        ("actorReference".to_owned(), json!({"type": "string"})),
        ("requestReference".to_owned(), json!({"type": "string"})),
        (
            "createdAt".to_owned(),
            json!({"type": "string", "format": "date-time"}),
        ),
        (
            "domainData".to_owned(),
            json!({"$ref": format!("#/components/schemas/{}", spec.schema_ref)}),
        ),
    ]);
    if let Some(change_context) = revision_change_context_schema(spec) {
        properties.insert("changeContext".to_owned(), change_context);
    }
    let item = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "recordIdentifier",
            "revisionIdentifier",
            "predecessorRevision",
            "lifecycle",
            "packageRevision",
            "operationIdentifier",
            "mutationKind",
            "actorReference",
            "requestReference",
            "createdAt",
            "domainData"
        ],
        "properties": properties
    });
    if spec.route.revision_kind == Some(CompiledRevisionKind::Detail) {
        single_response_schema(spec, item, json_ld)
    } else {
        let mut collection = collection_response_schema(spec, item, Map::new(), &[], json_ld);
        collection["properties"]["items"]["maxItems"] =
            json!(crate::model::MAX_REVISION_HISTORY_RECORDS);
        collection
    }
}

fn revision_change_context_schema(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    let mut fields = Vec::new();
    match spec.access_profiles {
        OpenApiAccessProfiles::All => {
            for profile_id in &spec.route.access_profiles {
                let Some(profile) = spec.entity.access_profiles.get(profile_id) else {
                    continue;
                };
                for field in &profile.provenance_fields {
                    if !fields.contains(field) {
                        fields.push(*field);
                    }
                }
            }
        }
        OpenApiAccessProfiles::Selected(profile_id) => {
            let profile = spec.entity.access_profiles.get(profile_id)?;
            fields.extend(profile.provenance_fields.iter().copied());
        }
    }
    change_context_response_schema(&fields)
}

fn change_context_response_schema(fields: &[ProvenanceFieldSource]) -> Option<Value> {
    if fields.is_empty() {
        return None;
    }
    let mut properties = Map::new();
    for field in fields {
        match field {
            ProvenanceFieldSource::Kind => {
                properties.insert(
                    "kind".to_owned(),
                    json!({"type": "string", "enum": ["change", "correction"]}),
                );
            }
            ProvenanceFieldSource::ReasonCode => {
                properties.insert("reasonCode".to_owned(), bounded_nonempty_text_schema(64));
            }
            ProvenanceFieldSource::ReasonText => {
                properties.insert("reasonText".to_owned(), bounded_text_schema(4 * 1024));
            }
            ProvenanceFieldSource::SourceReferences => {
                properties.insert(
                    "sourceReferences".to_owned(),
                    json!({
                        "type": "array",
                        "maxItems": 16,
                        "items": bounded_text_schema(256)
                    }),
                );
            }
        }
    }
    Some(Value::Object(Map::from_iter([
        ("type".to_owned(), json!("object")),
        ("additionalProperties".to_owned(), json!(false)),
        ("properties".to_owned(), Value::Object(properties)),
    ])))
}

#[cfg(test)]
#[path = "tests/artifacts_response_schema_tests.rs"]
mod artifacts_response_schema_tests;

#[derive(Clone, Copy)]
struct ProblemExample {
    code: &'static str,
    detail: &'static str,
}

fn operation_has_row_boundaries(spec: OpenApiOperationSpec<'_>) -> bool {
    let profile_has_boundaries = |profile_id: &str| {
        spec.entity
            .access_profiles
            .get(profile_id)
            .is_some_and(|profile| !profile.row_boundaries.is_empty())
    };
    match spec.access_profiles {
        OpenApiAccessProfiles::All => spec
            .route
            .access_profiles
            .iter()
            .any(|profile_id| profile_has_boundaries(profile_id)),
        OpenApiAccessProfiles::Selected(profile_id) => profile_has_boundaries(profile_id),
    }
}

fn problem_responses(
    operation: Operation,
    has_row_boundaries: bool,
) -> BTreeMap<&'static str, Vec<ProblemExample>> {
    let mut responses = BTreeMap::from([
        (
            "400",
            vec![ProblemExample {
                code: "request.invalid",
                detail: "The request is invalid.",
            }],
        ),
        (
            "401",
            vec![ProblemExample {
                code: "authentication.refused",
                detail: "The bearer credential is missing or refused.",
            }],
        ),
        (
            "404",
            vec![ProblemExample {
                code: "resource.not_found",
                detail: "The requested resource was not found.",
            }],
        ),
        (
            "503",
            vec![ProblemExample {
                code: "source.unavailable",
                detail: "The Registry data service is unavailable.",
            }],
        ),
        (
            "504",
            vec![ProblemExample {
                code: "request.timeout",
                detail: "The request timed out.",
            }],
        ),
    ]);
    if matches!(
        operation,
        Operation::List | Operation::Lookup | Operation::Snapshot
    ) {
        responses.entry("400").or_default().extend([
            ProblemExample {
                code: "query.invalid",
                detail: "The query request is invalid.",
            },
            ProblemExample {
                code: "query.cursor_invalid",
                detail: "The query cursor is invalid.",
            },
        ]);
    }
    if operation == Operation::Lookup {
        responses.entry("404").or_default().push(ProblemExample {
            code: "lookup.unresolved",
            detail: "The lookup did not resolve exactly one record.",
        });
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
    }
    if matches!(
        operation,
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch
    ) {
        responses.insert(
            "503",
            vec![ProblemExample {
                code: "service.unavailable",
                detail: "The Registry mutation service is unavailable.",
            }],
        );
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.key-reused",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "410",
            vec![ProblemExample {
                code: "idempotency.expired",
                detail: "The held response of the idempotency key expired; the key stays spent.",
            }],
        );
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
    }
    if matches!(operation, Operation::Create | Operation::Batch) && has_row_boundaries {
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The mutation precondition failed.",
            }],
        );
    }
    if matches!(operation, Operation::Patch | Operation::Tombstone) {
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The mutation precondition failed.",
            }],
        );
        responses.insert(
            "428",
            vec![ProblemExample {
                code: "precondition.required",
                detail: "The mutation precondition is required.",
            }],
        );
    }
    responses
}

fn problem_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "title", "status", "detail", "code", "traceId"],
        "properties": {
            "type": {"type": "string", "format": "uri", "maxLength": 256},
            "title": {"type": "string", "maxLength": 128},
            "status": {"type": "integer", "minimum": 400, "maximum": 599},
            "detail": {"type": "string", "maxLength": 256},
            "traceId": {"type": "string", "minLength": 32, "maxLength": 32, "pattern": "^[0-9a-f]{32}$"},
            "fieldPath": {"type": "string", "maxLength": 256},
            "refusalCode": {"type": "string", "minLength": 1, "maxLength": 128},
            "guardReason": {"type":"string","pattern":"^[a-z][a-z0-9_-]{0,63}$"},
            "reasonCode": {
                "type": "string",
                "enum": ["computation-error", "source-data-error", "disclosure-risk"]
            },
            "recordType": {"type": "string", "minLength": 1, "maxLength": 128},
            "fieldId": {"type": "string", "minLength": 1, "maxLength": 128},
            "constraintId": {"type": "string", "minLength": 1, "maxLength": 128},
            "constraintKind": {"type": "string", "enum": ["compare", "int-range", "vocabulary"]},
            "left": {"type": "string", "minLength": 1, "maxLength": 128},
            "right": {"type": "string", "minLength": 1, "maxLength": 128},
            "field": {"type": "string", "minLength": 1, "maxLength": 128},
            "code": {
                "type": "string",
                "enum": crate::problem::ProblemCode::DOCUMENTED
                    .iter()
                    .map(|code| code.code())
                    .collect::<Vec<_>>()
            }
        },
        "allOf": [
            {
                "if":{"properties":{"code":{"not":{"const":"action.guard_failed"}}}},
                "then":{"not":{"required":["guardReason"]}}
            },
            {
                "if": {"properties": {"code": {"const": "action.refused"}}},
                "then": {"required": ["refusalCode"], "properties": {"status": {"const": 422}}}
            },
            {
                "if": {"properties": {"code": {"const": "statistical_dataset.release_refused"}}},
                "then": {
                    "required": ["refusalCode"],
                    "properties": {
                        "status": {"const": 422},
                        "refusalCode": {"enum": [
                            "period-not-ended",
                            "before-first-period",
                            "provisional-after-final",
                            "already-withdrawn"
                        ]}
                    }
                }
            },
            {
                "if": {"properties": {"code": {"not": {"enum": [
                    "action.refused",
                    "statistical_dataset.release_refused"
                ]}}}},
                "then": {"not": {"required": ["refusalCode"]}}
            },
            {
                "if": {"properties": {"code": {"const": "statistical_dataset.version_withdrawn"}}},
                "then": {"required": ["reasonCode"], "properties": {"status": {"const": 410}}}
            },
            {
                "if": {"properties": {"code": {"not": {"const": "statistical_dataset.version_withdrawn"}}}},
                "then": {"not": {"required": ["reasonCode"]}}
            },
            {
                "if": {"properties": {"code": {"const": "action.evidence_failed"}}},
                "then": {"properties": {
                    "status": {"const": 503},
                    "detail": {"const": "The declared Evidence dependency could not be accepted."},
                    "fieldPath": {"type": "string", "pattern": "^/evidence/[a-z][a-z0-9_-]{0,63}$"}
                }}
            },
            {
                "if": {"properties": {"code": {"const": "action.handler_failed"}}},
                "then": {"properties": {"status": {"const": 500}}}
            },
            {
                "if": {"anyOf": [
                    {"required": ["recordType"]}, {"required": ["fieldId"]},
                    {"required": ["constraintId"]}, {"required": ["constraintKind"]},
                    {"required": ["left"]}, {"required": ["right"]}, {"required": ["field"]}
                ]},
                "then": {
                    "required": ["recordType"],
                    "properties": {"code": {"const": "mutation.conflict"}, "status": {"const": 409}},
                    "oneOf": [
                        {
                            "required": ["fieldId"],
                            "not": {"anyOf": [
                                {"required": ["constraintId"]}, {"required": ["constraintKind"]},
                                {"required": ["left"]}, {"required": ["right"]}, {"required": ["field"]}
                            ]}
                        },
                        {
                            "required": ["constraintId", "constraintKind"],
                            "not": {"required": ["fieldId"]},
                            "oneOf": [
                                {
                                    "required": ["left", "right"],
                                    "properties": {"constraintKind": {"const": "compare"}},
                                    "not": {"required": ["field"]}
                                },
                                {
                                    "required": ["field"],
                                    "properties": {"constraintKind": {"enum": ["int-range", "vocabulary"]}},
                                    "not": {"anyOf": [{"required": ["left"]}, {"required": ["right"]}]}
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    })
}

fn problem_example(status: &str, code: &str, detail: &str) -> Value {
    json!({
        "type": crate::problem::type_uri(code),
        "title": match status {
            "400" => "Bad Request",
            "401" => "Unauthorized",
            "404" => "Not Found",
            "409" => "Conflict",
            "410" => "Gone",
            "412" => "Precondition Failed",
            "415" => "Unsupported Media Type",
            "422" => "Unprocessable Entity",
            "428" => "Precondition Required",
            "500" => "Internal Server Error",
            "503" => "Service Unavailable",
            "504" => "Gateway Timeout",
            _ => "Request failed",
        },
        "status": status.parse::<u16>().expect("problem status is numeric"),
        "detail": detail,
        "code": code,
        "traceId": OPENAPI_EXAMPLE_TRACE_ID,
    })
}

fn batch_permissions(spec: OpenApiOperationSpec<'_>) -> (bool, bool) {
    match spec.access_profiles {
        OpenApiAccessProfiles::All => (
            spec.route.access_profiles.iter().any(|profile_id| {
                spec.entity.access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Create)
            }),
            spec.route.access_profiles.iter().any(|profile_id| {
                spec.entity.access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Patch)
            }),
        ),
        OpenApiAccessProfiles::Selected(profile_id) => {
            let profile = &spec.entity.access_profiles[profile_id];
            (
                profile.operations.contains(&Operation::Create),
                profile.operations.contains(&Operation::Patch),
            )
        }
    }
}

fn writable_fields_for_route(route: &CompiledRoute, entity: &CompiledEntity) -> BTreeSet<String> {
    route
        .access_profiles
        .iter()
        .filter_map(|profile_id| entity.access_profiles.get(profile_id))
        .flat_map(|profile| profile.writable_fields.iter().cloned())
        .collect()
}

fn query_profile_extension(spec: OpenApiOperationSpec<'_>) -> Option<(String, Value)> {
    if spec.route.query_kind.is_none() && spec.route.operation != Operation::Lookup {
        return None;
    }
    let profiles = query_profiles_for_route(spec.route, spec.query, spec.access_profiles);
    if profiles.is_empty() {
        return None;
    }
    match spec.access_profiles {
        OpenApiAccessProfiles::Selected(_) => Some((
            "x-registry-queryProfile".to_owned(),
            render_query_profile(
                spec.response_entity,
                profiles[0],
                selectable_fields_for_profile(spec, &profiles[0].profile_id),
            ),
        )),
        OpenApiAccessProfiles::All => Some((
            "x-registry-queryProfiles".to_owned(),
            Value::Object(
                profiles
                    .into_iter()
                    .map(|profile| {
                        (
                            profile.profile_id.clone(),
                            render_query_profile(
                                spec.response_entity,
                                profile,
                                selectable_fields_for_profile(spec, &profile.profile_id),
                            ),
                        )
                    })
                    .collect(),
            ),
        )),
    }
}

fn query_profiles_for_route<'a>(
    route: &CompiledRoute,
    query: &'a CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<&'a CompiledQueryOperation> {
    let mut profiles = query
        .operations
        .iter()
        .filter(|operation| operation.route_id == route.id)
        .filter(|operation| match access_profiles {
            OpenApiAccessProfiles::All => route
                .access_profiles
                .iter()
                .any(|profile| profile == &operation.profile_id),
            OpenApiAccessProfiles::Selected(profile) => operation.profile_id == profile,
        })
        .collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    profiles
}

fn render_query_profile(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    selectable_fields: BTreeSet<String>,
) -> Value {
    let mut rendered = json!({
        "profile": operation.profile_id,
        "kind": query_kind_name(operation.kind),
        "maximumPageSize": operation.max_page_size,
        "allowCount": operation.allow_count,
        "selectableProperties": api_field_names(entity, &selectable_fields),
        "filterableProperties": operation.filter_fields.iter().map(|field| {
            json!({
                "property": api_field_name(entity, &field.field).unwrap_or(field.field.as_str()),
                "operators": field.operators.iter().map(|operator| query_filter_operator_name(*operator)).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>(),
        "sortableProperties": operation.sort_fields.iter().map(|field| {
            json!({
                "property": api_field_name(entity, &field.field).unwrap_or(field.field.as_str()),
                "directions": field.directions.iter().map(|direction| match direction {
                    crate::model::CompiledQuerySortDirection::Asc => "asc",
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>(),
        "selectorProperties": api_field_names(entity, &operation.selector_fields),
        "temporal": operation.temporal.as_ref().map(|temporal| json!({
            "startProperty": api_field_name(entity, &temporal.start_field).unwrap_or(temporal.start_field.as_str()),
            "endProperty": api_field_name(entity, &temporal.end_field).unwrap_or(temporal.end_field.as_str()),
            "valueKind": match temporal.value_kind {
                CompiledQueryTemporalValueKind::Date => "date",
                CompiledQueryTemporalValueKind::Timestamp => "timestamp",
            },
            "semantics": "start-inclusive-end-exclusive",
        }))
    });
    if let Some(bbox) = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
    {
        rendered["spatialQueries"] = json!({"bbox": {
            "geometryProperty": api_field_name(entity, &bbox.geometry_field).unwrap_or(&bbox.geometry_field),
            "maximumLongitudeSpanDegrees": bbox.maximum_longitude_span_degrees,
            "maximumLatitudeSpanDegrees": bbox.maximum_latitude_span_degrees,
            "coordinateReferenceSystem": "CRS84",
            "semantics": "inclusive_2d_non_crossing"
        }});
    }
    rendered
}

fn query_filter_operator_name(operator: crate::model::CompiledQueryFilterOperator) -> &'static str {
    match operator {
        crate::model::CompiledQueryFilterOperator::Equals => "equals",
        crate::model::CompiledQueryFilterOperator::In => "in",
        crate::model::CompiledQueryFilterOperator::Range => "range",
        crate::model::CompiledQueryFilterOperator::IsNull => "is-null",
        crate::model::CompiledQueryFilterOperator::IsNotNull => "is-not-null",
        crate::model::CompiledQueryFilterOperator::Prefix => "prefix",
        crate::model::CompiledQueryFilterOperator::Contains => "contains",
    }
}

fn selectable_fields_for_profile(
    spec: OpenApiOperationSpec<'_>,
    profile_id: &str,
) -> BTreeSet<String> {
    if let Some(readable_fields) = spec.readable_fields {
        return readable_fields.clone();
    }
    if let Some(read_path) = read_path_for_route(spec.route, spec.entity) {
        return spec
            .entity
            .access_profiles
            .get(profile_id)
            .and_then(|profile| {
                profile
                    .read_paths
                    .iter()
                    .find(|grant| grant.path == read_path.id)
            })
            .map(|grant| grant.readable_fields.as_set().clone())
            .unwrap_or_default();
    }
    spec.entity
        .access_profiles
        .get(profile_id)
        .map(|profile| profile.readable_fields.as_set().clone())
        .unwrap_or_default()
}

fn api_field_names<'a>(
    entity: &CompiledEntity,
    fields: impl IntoIterator<Item = &'a String>,
) -> Vec<String> {
    fields
        .into_iter()
        .filter_map(|field| api_field_name(entity, field).map(str::to_owned))
        .collect()
}

fn api_field_name<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<&'a str> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| field.logical.api_name.as_str())
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| field.logical.api_name.as_str())
        })
        .or_else(|| {
            (entity.canonical_id.id == field_id).then_some(entity.canonical_id.api_name.as_str())
        })
}

fn max_page_size(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> u16 {
    query_profiles_for_route(route, query, access_profiles)
        .into_iter()
        .map(|operation| operation.max_page_size)
        .max()
        .unwrap_or(crate::query::MAX_TOP as u16)
}

fn response_entity_for_route<'a>(
    route: &CompiledRoute,
    entities: &'a BTreeMap<String, CompiledEntity>,
) -> &'a CompiledEntity {
    let entity = entities
        .get(&route.entity_id)
        .expect("compiled route refers to a compiled entity");
    if route.operation == Operation::List && route.id.contains(".path.") {
        if let Some(path) = read_path_for_route(route, entity) {
            return entities
                .get(&path.to)
                .expect("compiled read path refers to a compiled entity");
        }
    }
    entity
}

fn read_path_for_route<'a>(
    route: &CompiledRoute,
    entity: &'a CompiledEntity,
) -> Option<&'a crate::model::CompiledReadPath> {
    entity
        .read_paths
        .values()
        .find(|path| route.id == format!("records.{}.path.{}", entity.id, path.id))
}

fn revision_kind_name(kind: CompiledRevisionKind) -> &'static str {
    match kind {
        CompiledRevisionKind::List => "list",
        CompiledRevisionKind::Detail => "detail",
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "delete",
        HttpMethod::Get => "get",
        HttpMethod::Patch => "patch",
        HttpMethod::Post => "post",
    }
}

fn query_kind_name(kind: CompiledQueryKind) -> &'static str {
    match kind {
        CompiledQueryKind::List => "list",
        CompiledQueryKind::Current => "current",
        CompiledQueryKind::AsOf => "as-of",
        CompiledQueryKind::Snapshot => "snapshot",
    }
}

fn operation_name(operation: Operation) -> &'static str {
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

fn insert_json<T: Serialize>(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    value: &T,
) -> Result<(), Diagnostic> {
    let value = serde_json::to_value(value).map_err(|_| canonicalization_error())?;
    insert_json_value(artifacts, path, &value)
}

fn insert_json_value(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    value: &Value,
) -> Result<(), Diagnostic> {
    let bytes = canonicalize_json(value).map_err(|_| canonicalization_error())?;
    insert_bytes(artifacts, path, "application/json", bytes);
    Ok(())
}

fn insert_bytes(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    media_type: &str,
    bytes: Vec<u8>,
) {
    let digest = Sha256::digest(&bytes);
    artifacts.insert(
        path.to_owned(),
        GeneratedArtifact {
            path: path.to_owned(),
            media_type: media_type.to_owned(),
            sha256: format!("sha256:{}", hex_prefix(&digest, digest.len())),
            bytes,
        },
    );
}

fn canonicalization_error() -> Diagnostic {
    Diagnostic::error(
        "breg.artifact.canonicalization-failed",
        "artifacts",
        "the generated artifact could not be canonicalized",
    )
}

#[cfg(test)]
mod problem_contract_tests {
    use super::*;

    #[test]
    fn application_reason_contract_is_optional_bounded_and_closed() {
        {
            let schema = proposal_apply_input_schema();
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .unwrap();
            let mut body = json!({"submissionVersion": 1, "effectDigest": format!("sha256:{}", "a".repeat(64))});
            assert!(validator.is_valid(&body));
            for reason in [json!(""), json!(" สาเหตุ\n🙂 "), json!("🙂".repeat(4096))]
            {
                body["reason"] = reason;
                assert!(validator.is_valid(&body));
            }
            for reason in [
                Value::Null,
                json!(false),
                json!(42),
                json!([]),
                json!({}),
                json!("🙂".repeat(4097)),
                json!("a\0b"),
            ] {
                body["reason"] = reason;
                assert!(!validator.is_valid(&body));
            }
            body.as_object_mut().unwrap().remove("reason");
            body["unexpected"] = json!(true);
            assert!(!validator.is_valid(&body));
        }
    }

    #[test]
    fn proposal_schema_is_a_distinct_closed_resource() {
        let schema = proposal_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let mut proposal = json!({"id":"00000000-0000-4000-8000-000000000001","actionId":"correct-address", "actionRevision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "submissionVersion":1,"revision":2,"state":"submitted","turn":"official","links":{}});
        assert!(validator.is_valid(&proposal));
        proposal.as_object_mut().unwrap().remove("turn");
        assert!(!validator.is_valid(&proposal));
        proposal["turn"] = json!("official");
        proposal["request"] = json!({});
        assert!(!validator.is_valid(&proposal));
        proposal.as_object_mut().unwrap().remove("request");
        proposal["state"] = json!("approved");
        assert!(!validator.is_valid(&proposal));
    }

    #[test]
    fn proposal_public_reason_schema_matches_client_text_rules() {
        let schema = proposal_decision_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let decision = |public_reason: &str| {
            json!({
                "status": "approved",
                "decidedAt": "2025-01-01T00:00:00Z",
                "publicReason": public_reason,
            })
        };

        for valid in ["accepted", " accepted ", "เหตุผล 🙂"] {
            assert!(validator.is_valid(&decision(valid)), "{valid:?}");
        }
        for invalid in [
            "",
            " \t\n",
            "\u{00a0}",
            "\u{1680}",
            "\u{2003}",
            "\u{202f}",
            "\u{3000}",
            "contains\0control",
            "contains\u{0085}control",
        ] {
            assert!(!validator.is_valid(&decision(invalid)), "{invalid:?}");
        }
    }

    #[test]
    fn problem_contract_accepts_declared_refusals_and_server_faults() {
        let schema = problem_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let mut refusal = problem_example("422", "action.refused", "A name is required.");
        assert!(
            !validator.is_valid(&refusal),
            "a refusal needs its declared code"
        );
        refusal["refusalCode"] = json!("blank-name");
        refusal["fieldPath"] = json!("/input/givenName");
        assert!(validator.is_valid(&refusal));
        refusal["status"] = json!(400);
        assert!(!validator.is_valid(&refusal));

        let mut fault = problem_example(
            "500",
            "action.handler_failed",
            "The action handler could not produce an accepted result.",
        );
        assert!(validator.is_valid(&fault));
        fault["status"] = json!(400);
        assert!(
            !validator.is_valid(&fault),
            "a package fault is not a caller error"
        );
    }

    #[test]
    fn problem_contract_accepts_closed_statistical_release_details() {
        let schema = problem_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();

        let mut refused = problem_example(
            "422",
            "statistical_dataset.release_refused",
            "The statistical release was refused.",
        );
        refused["refusalCode"] = json!("period-not-ended");
        assert!(validator.is_valid(&refused));
        refused["refusalCode"] = json!("unreviewed-reason");
        assert!(!validator.is_valid(&refused));
        refused.as_object_mut().unwrap().remove("refusalCode");
        assert!(!validator.is_valid(&refused));
        refused["refusalCode"] = json!("already-withdrawn");
        refused["status"] = json!(409);
        assert!(!validator.is_valid(&refused));

        let mut withdrawn = problem_example(
            "410",
            "statistical_dataset.version_withdrawn",
            "The statistical release version was withdrawn.",
        );
        withdrawn["reasonCode"] = json!("source-data-error");
        assert!(validator.is_valid(&withdrawn));
        withdrawn["reasonCode"] = json!("unreviewed-reason");
        assert!(!validator.is_valid(&withdrawn));
        withdrawn.as_object_mut().unwrap().remove("reasonCode");
        assert!(!validator.is_valid(&withdrawn));
        withdrawn["reasonCode"] = json!("disclosure-risk");
        withdrawn["status"] = json!(422);
        assert!(!validator.is_valid(&withdrawn));

        let mut unrelated = problem_example("404", "resource.not_found", "Not found.");
        unrelated["reasonCode"] = json!("computation-error");
        assert!(!validator.is_valid(&unrelated));
    }

    #[test]
    fn evidence_dependency_problem_is_static_and_has_service_unavailable_status() {
        let schema = problem_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let mut problem = problem_example(
            "503",
            "action.evidence_failed",
            "The declared Evidence dependency could not be accepted.",
        );
        assert!(validator.is_valid(&problem));
        problem["fieldPath"] = json!("/evidence/status");
        assert!(validator.is_valid(&problem));
        problem["fieldPath"] = json!("/evidence/status/raw-selector");
        assert!(!validator.is_valid(&problem));
        problem["fieldPath"] = json!("/evidence/status");
        problem["detail"] = json!("provider response or selector canary");
        assert!(!validator.is_valid(&problem));
        problem["detail"] = json!("The declared Evidence dependency could not be accepted.");
        problem["status"] = json!(422);
        assert!(!validator.is_valid(&problem));
    }

    #[test]
    fn problem_contract_keeps_declared_locations_complete_and_errors_closed() {
        let schema = problem_schema();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let mut problem = problem_example("409", "mutation.conflict", "The write was refused.");
        assert!(validator.is_valid(&problem));
        problem["recordType"] = json!("person");
        assert!(!validator.is_valid(&problem));
        problem["fieldId"] = json!("identifier");
        assert!(validator.is_valid(&problem));
        problem.as_object_mut().unwrap().remove("fieldId");
        problem["constraintId"] = json!("chronological");
        problem["constraintKind"] = json!("compare");
        problem["left"] = json!("valid-from");
        assert!(!validator.is_valid(&problem));
        problem["right"] = json!("valid-to");
        assert!(validator.is_valid(&problem));
        problem["field"] = json!("status");
        assert!(!validator.is_valid(&problem));
        problem.as_object_mut().unwrap().remove("left");
        problem.as_object_mut().unwrap().remove("right");
        problem["constraintKind"] = json!("vocabulary");
        assert!(validator.is_valid(&problem));
        problem["code"] = json!("resource.not_found");
        assert!(!validator.is_valid(&problem));
        problem["code"] = json!("mutation.conflict");
        problem["refusalCode"] = json!("undeclared-refusal");
        assert!(!validator.is_valid(&problem));
        problem.as_object_mut().unwrap().remove("refusalCode");
        problem["recordValue"] = json!("must-not-be-disclosed");
        assert!(!validator.is_valid(&problem));
    }
}

#[cfg(test)]
mod spatial_tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use crate::model::CompiledRegistry;

    fn registry() -> CompiledRegistry {
        let project = parse_project_json(br#"{
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
            "kind":"BRegProject",
            "project":{"id":"spatial-artifacts","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://spatial-artifacts.example.test"},
            "datasets":[{"id":"test-dataset"}],"recordTypes":[{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
                "geojson":{"geometryField":"location"},
                "fields":[
                    {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"label","type":"string","maximumLength":64,"classification":"internal"},
                    {"id":"location","apiName":"position","type":"crs84-point","precision":9,"classification":"internal"}
                ]
            }],
            "accessProfiles":[
                {"id":"map","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"site","operations":["get","list"],"readableFields":["code","label","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.5,"maximumLatitudeSpanDegrees":0.25}}, "rowBoundaries": "unrestricted"}]}},
                {"id":"plain","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"site","operations":["get","list"],"readableFields":["code"], "rowBoundaries": "unrestricted"}]}},
                {"id":"geometry-only","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"site","operations":["get","list"],"readableFields":["location"], "rowBoundaries": "unrestricted"}]}}
            ]
        }"#).expect("spatial artifact fixture parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("spatial artifact fixture compiles")
    }

    fn operation(registry: &CompiledRegistry, method: Operation, profile: &str) -> Value {
        let entity = &registry.entities()["site"];
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.operation == method)
            .expect("fixture route exists");
        openapi_operation(OpenApiOperationSpec {
            registry_identifier: registry.registry_id(),
            route,
            entity,
            response_entity: entity,
            query: registry.queries(),
            schema_ref: "site",
            request_schema_ref: "site",
            readable_fields: None,
            access_profiles: OpenApiAccessProfiles::Selected(profile),
        })
    }

    #[test]
    fn selected_profile_controls_bbox_and_geojson_advertisement() {
        let registry = registry();
        let map = operation(&registry, Operation::List, "map");
        assert!(map["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
        assert_eq!(
            map["x-registry-queryProfile"]["spatialQueries"]["bbox"]["geometryProperty"],
            "position"
        );
        assert_eq!(
            map["x-registry-queryProfile"]["spatialQueries"]["bbox"]["maximumLatitudeSpanDegrees"],
            0.25
        );
        assert!(map.get("x-registry-responseShape").is_none());
        assert_eq!(
            map["x-registry-responseShapes"],
            json!({
                "application/json": "RegistryRecordCollectionV1",
                "application/ld+json": "RegistryRecordCollectionV1",
                "application/geo+json": "BRegGeoJsonFeatureCollectionV1",
            })
        );
        assert_eq!(
            map["x-registry-responseProfile"], PROFILE_IDENTIFIER,
            "the stable profile marker governs only the JSON and JSON-LD shapes in the media map"
        );
        let feature = &map["responses"]["200"]["content"]["application/geo+json"]["schema"]
            ["properties"]["features"]["items"];
        assert!(feature["properties"]["properties"]["properties"]["code"].is_object());
        assert!(feature["properties"]["properties"]["properties"]
            .get("position")
            .is_none());
        assert_eq!(
            feature["properties"]["geometry"]["anyOf"][1]["type"],
            "null"
        );
        assert_eq!(
            feature["properties"]["registry"]["required"],
            json!(["revision"])
        );
        let collection = &map["responses"]["200"]["content"]["application/geo+json"]["schema"];
        assert!(collection["required"]
            .as_array()
            .unwrap()
            .contains(&json!("numberReturned")));
        assert_eq!(
            collection["properties"]["numberReturned"],
            json!({"type": "integer", "minimum": 0})
        );
        let select = map["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "$select")
            .unwrap();
        assert_eq!(select["examples"]["withoutGeometry"]["value"], "code,label");
        assert_eq!(
            select["examples"]["withGeometry"]["value"],
            "code,label,position"
        );

        let plain = operation(&registry, Operation::List, "plain");
        assert!(!plain["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
        assert!(plain["responses"]["200"]["content"]
            .get("application/geo+json")
            .is_none());
        assert_eq!(
            plain["x-registry-responseShape"],
            "RegistryRecordCollectionV1"
        );
        assert_eq!(plain["x-registry-responseProfile"], PROFILE_IDENTIFIER);
        assert!(plain.get("x-registry-responseShapes").is_none());
        assert!(plain.get("x-registry-geojsonProfiles").is_none());
        assert!(plain["x-registry-queryProfile"]
            .get("spatialQueries")
            .is_none());
    }

    #[test]
    fn geojson_without_bbox_does_not_widen_properties() {
        let registry = registry();
        let get = operation(&registry, Operation::Get, "geometry-only");
        let content = &get["responses"]["200"]["content"];
        assert!(content["application/json"].is_object());
        assert_eq!(
            get["x-registry-responseShapes"]["application/geo+json"],
            "BRegGeoJsonFeatureV1"
        );
        assert_eq!(
            get["x-registry-responseShapes"]["application/json"],
            "RegistryRecordSingleV1"
        );
        let schema = &content["application/geo+json"]["schema"];
        assert_eq!(schema["properties"]["type"]["const"], "Feature");
        assert_eq!(schema["properties"]["properties"]["properties"], json!({}));
        assert!(!get["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;
    #[test]
    fn proposal_attachment_metadata_has_closed_verification_and_bounded_content() {
        let schema = proposal_attachment_schema();
        let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
        let mut value = json!({"id":"support","required":false,"maximumBytes":1024,"contentTypes":["application/pdf"],"classification":"restricted","links":{},"value":{"submissionVersion":1,"sha256":"a".repeat(64),"contentType":"application/pdf","byteSize":512,"verificationStatus":"approved"}});
        assert!(validator.is_valid(&value));
        for status in ["notRequired", "pending", "approved", "rejected"] {
            value["value"]["verificationStatus"] = json!(status);
            assert!(validator.is_valid(&value));
        }
        value["value"]["verificationStatus"] = json!("unknown");
        assert!(!validator.is_valid(&value));
        value["value"]["verificationStatus"] = json!("approved");
        value["value"]["uploadedBy"] = json!("private-actor-reference");
        assert!(!validator.is_valid(&value));
        value["value"].as_object_mut().unwrap().remove("uploadedBy");
        value["value"]["legacyRecordProjection"] = json!(true);
        assert!(!validator.is_valid(&value));
    }
}
