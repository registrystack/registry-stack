// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::{
    EventSource, EventTrigger, FieldTypeSource, ManifestProjectionSource, MutationMode, Operation,
    PackageIdentitySource,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::manifest_adapter::project_manifest_artifacts;
use crate::model::{
    CompiledAccessInventory, CompiledChangeRequestMutation, CompiledChangeRequestRetentionMode,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledEntity,
    CompiledEventDeliveryInventory, CompiledMetadataInventory, CompiledModuleIdentity,
    CompiledQueryInventory, CompiledQueryKind, CompiledQueryOperation, CompiledRevisionKind,
    CompiledRoute, CompiledRouteInventory, HttpMethod,
};
use crate::physical_names::{hex_prefix, PhysicalNameInventory};

pub const REGISTRY_METADATA_ARTIFACT_PATH: &str = "generated/metadata/registry.json";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<&'a PackageIdentitySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_projection: Option<&'a ManifestProjectionSource>,
    pub module_order: &'a [String],
    pub module_closure: &'a [CompiledModuleIdentity],
    pub entities: &'a BTreeMap<String, CompiledEntity>,
    pub physical_names: &'a PhysicalNameInventory,
    pub metadata_inventory: &'a CompiledMetadataInventory,
    pub query_inventory: &'a CompiledQueryInventory,
    pub event_delivery_inventory: &'a CompiledEventDeliveryInventory,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_artifacts(
    registry_id: &str,
    version: &str,
    default_language: &str,
    package: Option<&PackageIdentitySource>,
    manifest_projection: Option<&ManifestProjectionSource>,
    module_order: &[String],
    module_closure: &[CompiledModuleIdentity],
    entities: &BTreeMap<String, CompiledEntity>,
    physical_names: &PhysicalNameInventory,
    routes: &CompiledRouteInventory,
    access: &CompiledAccessInventory,
    metadata: &CompiledMetadataInventory,
    query: &CompiledQueryInventory,
    event_deliveries: &CompiledEventDeliveryInventory,
    ddl: &DdlInventory,
) -> Result<GeneratedArtifacts, Diagnostic> {
    let mut artifacts = BTreeMap::new();
    insert_json(
        &mut artifacts,
        "compiled/effective-model.json",
        &EffectiveModel {
            registry_id,
            version,
            default_language,
            package,
            manifest_projection,
            module_order,
            module_closure,
            entities,
            physical_names,
            metadata_inventory: metadata,
            query_inventory: query,
            event_delivery_inventory: event_deliveries,
        },
    )?;
    insert_json(&mut artifacts, "compiled/modules.json", &module_closure)?;
    insert_json(&mut artifacts, "compiled/routes.json", routes)?;
    insert_json(&mut artifacts, "compiled/access.json", access)?;
    insert_json(&mut artifacts, "compiled/metadata-inventory.json", metadata)?;
    insert_json(&mut artifacts, "compiled/query-inventory.json", query)?;
    insert_json(
        &mut artifacts,
        "compiled/event-deliveries.json",
        event_deliveries,
    )?;
    insert_json(&mut artifacts, REGISTRY_METADATA_ARTIFACT_PATH, metadata)?;
    insert_bytes(
        &mut artifacts,
        "generated/postgres/schema.sql",
        "application/sql",
        ddl.script().into_bytes(),
    );

    let mut schemas = BTreeMap::new();
    for entity in entities.values() {
        let schema = entity_schema(entity, entities);
        let path = format!("generated/schemas/{}.schema.json", entity.id);
        insert_json_value(&mut artifacts, &path, &schema)?;
        schemas.insert(entity.id.clone(), schema);
    }
    for delivery in &event_deliveries.deliveries {
        let entity = entities
            .get(&delivery.entity_id)
            .expect("compiled event delivery refers to a compiled entity");
        let event = entity
            .events
            .get(&delivery.event_id)
            .expect("compiled event delivery refers to a compiled event");
        let binding = event_data_schema_binding(registry_id, entity, event)?;
        debug_assert_eq!(delivery.data_schema, binding.data_schema);
        debug_assert_eq!(delivery.data_schema_fingerprint, binding.fingerprint);
        debug_assert_eq!(delivery.data_schema_artifact_path, binding.artifact_path);
        insert_json_value(&mut artifacts, &binding.artifact_path, &binding.schema)?;
    }
    let openapi = openapi_document(registry_id, version, entities, routes, query, &schemas);
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
    Ok(GeneratedArtifacts { artifacts })
}

pub(crate) fn event_data_schema_binding(
    registry_id: &str,
    entity: &CompiledEntity,
    event: &EventSource,
) -> Result<EventDataSchemaBinding, Diagnostic> {
    let mut value_properties = Map::new();
    for field_id in &event.projection {
        let field = entity
            .fields
            .get(field_id)
            .expect("validated event projection refers to a compiled field");
        let schema = field_schema(&field.field_type);
        let schema = if field.required {
            schema
        } else {
            json!({"anyOf": [schema, {"type": "null"}]})
        };
        value_properties.insert(field_id.clone(), schema);
    }
    let trigger = match event.trigger {
        EventTrigger::Created => "created",
        EventTrigger::Patched => "patched",
        EventTrigger::Tombstoned => "tombstoned",
        EventTrigger::RequestLifecycle => "request_lifecycle",
    };
    let mut properties = Map::new();
    properties.insert("entity".to_owned(), json!({"const": entity.id}));
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
    if event.trigger == EventTrigger::RequestLifecycle {
        properties.insert(
            "request".to_owned(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "proposalVersion": {"type": "integer", "minimum": 1},
                    "workflowRevision": {"type": "integer", "minimum": 1},
                    "transition": {"type": "string"},
                    "fromState": {"type": "string"},
                    "toState": {"type": "string"},
                    "stage": {"type": ["string", "null"]},
                    "effectDigest": {"type": ["string", "null"]},
                    "deduplicationKey": {"type": "string"}
                },
                "required": [
                    "proposalVersion",
                    "workflowRevision",
                    "transition",
                    "fromState",
                    "toState",
                    "stage",
                    "effectDigest",
                    "deduplicationKey"
                ]
            }),
        );
    }
    properties.insert(
        "values".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": value_properties,
            "required": event.projection,
        }),
    );
    let required = if event.trigger == EventTrigger::RequestLifecycle {
        vec![
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "request",
            "values",
        ]
    } else {
        vec![
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "values",
        ]
    };
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required
    });
    let bytes = canonicalize_json(&schema).map_err(|_| canonicalization_error())?;
    let digest = Sha256::digest(&bytes);
    let fingerprint = format!("sha256:{}", hex_prefix(&digest, digest.len()));
    let data_schema = format!(
        "urn:registry-server:event-schema:{registry_id}:{}:{}:{fingerprint}",
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

fn entity_schema(entity: &CompiledEntity, entities: &BTreeMap<String, CompiledEntity>) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        properties.insert(
            field.logical.api_name.clone(),
            field_value_schema(&field.logical.field_type, !field.required),
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
        "$id": format!("urn:registry-server:entity:{}", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create_only",
        }
    });
    let object = schema.as_object_mut().expect("entity schema is an object");
    if entity.change_control.is_some() {
        object.insert(
            "x-registry-changeControl".to_owned(),
            render_change_control(entity, entities),
        );
    }
    if entity.change_request.is_some() {
        object.insert(
            "x-registry-changeRequest".to_owned(),
            render_change_request(entity, entities),
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
        "$id": format!("urn:registry-server:entity:{}:input", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create_only",
        }
    })
}

pub(crate) fn openapi_request_action_input_schema(operation: Operation) -> Value {
    let proposal_binding = json!({
        "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
        "effectDigest": {
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
            "description": "Digest of the immutable proposal effects displayed to the actor."
        }
    });
    match operation {
        Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ApplyRequest => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["proposalVersion", "effectDigest"],
            "properties": proposal_binding,
        }),
        Operation::ReviseRequest => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["rebase"],
            "properties": {
                "rebase": {"type": "boolean"}
            }
        }),
        _ => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
    }
}

fn render_change_control(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Value {
    let controlled_operations = entity
        .change_control
        .as_ref()
        .map(|control| {
            control
                .required_for
                .iter()
                .map(|operation| operation_name(*operation))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let eligible_request_types = entities
        .values()
        .filter_map(|request_entity| {
            let request = request_entity.change_request.as_ref()?;
            let operations = request
                .effects
                .iter()
                .filter(|effect| effect.target.entity_id == entity.id)
                .map(|effect| operation_name(effect.operation))
                .collect::<BTreeSet<_>>();
            (!operations.is_empty()).then(|| {
                json!({
                    "requestEntity": request_entity.id,
                    "requestRoute": request_entity.route,
                    "operations": operations.into_iter().collect::<Vec<_>>(),
                    "contractFingerprint": request.contract_fingerprint,
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "requiredFor": controlled_operations,
        "directWriteRestriction": "controlled_operations_require_compiled_change_request_application",
        "eligibleRequestTypes": eligible_request_types,
    })
}

fn render_change_request(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Value {
    let request = entity
        .change_request
        .as_ref()
        .expect("caller checked change request presence");
    json!({
        "requestEntity": request.request_entity_id,
        "contractFingerprint": request.contract_fingerprint,
        "retention": render_request_retention(request.retention_mode),
        "bounds": {
            "maximumTargets": request.maximum_targets,
            "maximumFieldMutations": request.maximum_field_mutations,
            "maximumSnapshotBytes": request.maximum_snapshot_bytes,
        },
        "stateEnvelope": {
            "states": ["draft", "submitted", "approved", "needs_changes", "rejected", "canceled", "applied"],
            "proposalBinding": ["proposalVersion", "effectDigest", "contractFingerprint"],
            "actionAvailability": "advisory_rechecked_on_use",
        },
        "effects": request.effects.iter().map(|effect| {
            let target = entities.get(&effect.target.entity_id);
            json!({
                "id": effect.id,
                "operation": operation_name(effect.operation),
                "target": {
                    "entity": effect.target.entity_id,
                    "binding": render_target_binding(&effect.target.binding),
                },
                "mutations": effect.mutations.iter().map(|mutation| {
                    render_request_mutation(mutation, target)
                }).collect::<Vec<_>>(),
                "dependsOn": effect.depends_on.iter().collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "stages": request.stages,
        "actions": request.actions.iter().map(|action| json!({
            "operation": operation_name(action.operation.access_operation()),
            "stage": action.review_stage,
            "method": "POST",
            "requiresIdempotencyKey": true,
            "requiresRecordPrecondition": true,
            "inputSchema": openapi_input_schema_id(&entity.id, action.operation.access_operation()),
            "responseSchema": "ChangeRequestActionResponse",
        })).collect::<Vec<_>>(),
        "reviewGrants": request.review_grants,
        "applyGrants": request.apply_grants,
        "presenceGrants": request.presence_grants,
        "targetEntities": request.target_entities,
    })
}

fn render_request_retention(mode: CompiledChangeRequestRetentionMode) -> Value {
    let mode = match mode {
        CompiledChangeRequestRetentionMode::Retain => "retain",
        CompiledChangeRequestRetentionMode::OperatorErase => "operator_erase",
    };
    json!({
        "mode": mode,
        "effectivePolicy": {
            "payloadSnapshots": match mode {
                "retain" => "retained_until_package_or_operator_policy_changes",
                "operator_erase" => "operator_erasable_after_terminal_state",
                _ => unreachable!("closed retention mode"),
            },
            "provenanceStub": "retained_while_target_revisions_reference_request",
            "erasedDetailMarker": "request.detailErased",
        }
    })
}

fn render_target_binding(binding: &CompiledChangeRequestTargetBinding) -> Value {
    match binding {
        CompiledChangeRequestTargetBinding::Existing { from_field } => {
            json!({"kind": "existing", "fromField": from_field})
        }
        CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
            json!({"kind": "reserved_create", "effect": effect})
        }
    }
}

fn render_request_mutation(
    mutation: &CompiledChangeRequestMutation,
    target: Option<&CompiledEntity>,
) -> Value {
    match mutation {
        CompiledChangeRequestMutation::Set { field, value } => json!({
            "kind": "set",
            "field": field,
            "apiName": target.and_then(|entity| api_field_name(entity, field)),
            "value": render_request_value(value),
        }),
        CompiledChangeRequestMutation::Clear { field } => json!({
            "kind": "clear",
            "field": field,
            "apiName": target.and_then(|entity| api_field_name(entity, field)),
        }),
    }
}

fn render_request_value(value: &CompiledChangeRequestValue) -> Value {
    match value {
        CompiledChangeRequestValue::FromField { field } => {
            json!({"kind": "from_field", "field": field})
        }
        CompiledChangeRequestValue::FromEffect {
            effect,
            target_entity_id,
        } => json!({
            "kind": "from_effect",
            "effect": effect,
            "targetEntity": target_entity_id,
        }),
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

fn openapi_document(
    registry_id: &str,
    version: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    routes: &CompiledRouteInventory,
    query: &CompiledQueryInventory,
    schemas: &BTreeMap<String, Value>,
) -> Value {
    let mut paths = Map::new();
    let mut input_schemas = Map::new();
    for route in &routes.routes {
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
        } else if is_request_action(route.operation) {
            input_schemas.insert(
                request_schema_ref.clone(),
                openapi_request_action_input_schema(route.operation),
            );
        }
        operations.insert(
            method_name(route.method).to_owned(),
            openapi_operation(OpenApiOperationSpec {
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
    }
    let mut component_schemas: Map<String, Value> = schemas
        .iter()
        .map(|(id, schema)| (id.clone(), schema.clone()))
        .collect();
    component_schemas.extend(input_schemas);
    let has_request_actions = routes
        .routes
        .iter()
        .any(|route| is_request_action(route.operation));
    json!({
        "openapi": "3.1.0",
        "info": {"title": registry_id, "version": version},
        "paths": paths,
        "components": openapi_components(component_schemas, has_request_actions)
    })
}

#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) enum OpenApiAccessProfiles<'a> {
    All,
    Selected(&'a str),
}

#[derive(Clone, Copy)]
pub(crate) struct OpenApiOperationSpec<'a> {
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
    has_request_actions: bool,
) -> Value {
    schemas.insert("Problem".to_owned(), problem_schema());
    if has_request_actions {
        schemas.insert(
            "ChangeRequestActionResponse".to_owned(),
            request_action_response_schema(),
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
    let mut operation = Map::from_iter([
        ("operationId".to_owned(), json!(spec.route.id)),
        ("x-registry-entity".to_owned(), json!(spec.route.entity_id)),
        (
            "x-registry-responseEntity".to_owned(),
            json!(spec.response_entity.id),
        ),
        (
            "x-registry-operation".to_owned(),
            json!(operation_name(spec.route.operation)),
        ),
        ("security".to_owned(), operation_security(spec)),
    ]);
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
    if is_request_action(spec.route.operation) {
        operation.insert(
            "x-registry-requestAction".to_owned(),
            render_request_action(spec),
        );
    }
    if let Some(query_profile) = query_profile_extension(spec) {
        operation.insert(query_profile.0, query_profile.1);
    }
    let parameters = operation_parameters(
        spec.route,
        spec.response_entity,
        spec.query,
        spec.access_profiles,
    );
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if let Some(request_body) = operation_request_body(spec) {
        operation.insert("requestBody".to_owned(), request_body);
    }
    operation.insert("responses".to_owned(), operation_responses(spec));
    Value::Object(operation)
}

fn render_request_action(spec: OpenApiOperationSpec<'_>) -> Value {
    json!({
        "operation": operation_name(spec.route.operation),
        "stage": spec.route.request_stage,
        "method": method_name(spec.route.method),
        "path": spec.route.path,
        "requestEntity": spec.route.entity_id,
        "requiredPreconditions": request_action_preconditions(spec.route.operation),
        "inputSchema": openapi_input_schema_id(&spec.entity.id, spec.route.operation),
        "responseSchema": "ChangeRequestActionResponse",
        "proposalBinding": {
            "versionField": "proposalVersion",
            "digestField": "effectDigest",
            "recordPrecondition": "If-Match",
            "idempotencyHeader": "Idempotency-Key",
        },
        "targetEntities": request_action_target_entities(spec),
    })
}

fn request_action_target_entities(spec: OpenApiOperationSpec<'_>) -> Vec<String> {
    let Some(request) = spec.entity.change_request.as_ref() else {
        return Vec::new();
    };
    match spec.access_profiles {
        OpenApiAccessProfiles::All => request.target_entities.iter().cloned().collect(),
        OpenApiAccessProfiles::Selected(profile) => {
            let mut targets = BTreeSet::new();
            match spec.route.operation {
                Operation::ApproveRequest
                | Operation::RejectRequest
                | Operation::RequestRevision => {
                    if let Some(stage) = spec.route.request_stage.as_deref() {
                        targets.extend(
                            request
                                .review_grants
                                .iter()
                                .filter(|grant| grant.profile_id == profile && grant.stage == stage)
                                .map(|grant| grant.target_entity_id.clone()),
                        );
                    }
                }
                Operation::ApplyRequest => {
                    targets.extend(
                        request
                            .apply_grants
                            .iter()
                            .filter(|grant| grant.profile_id == profile)
                            .map(|grant| grant.target_entity_id.clone()),
                    );
                }
                Operation::SubmitRequest
                | Operation::ReviseRequest
                | Operation::CancelRequest
                | Operation::Create
                | Operation::Get
                | Operation::List
                | Operation::Patch
                | Operation::Tombstone
                | Operation::Batch
                | Operation::Lookup
                | Operation::Revisions => {}
            }
            targets.into_iter().collect()
        }
    }
}

fn request_action_preconditions(operation: Operation) -> Vec<&'static str> {
    let mut preconditions = vec!["Idempotency-Key", "If-Match"];
    if matches!(
        operation,
        Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ApplyRequest
    ) {
        preconditions.push("proposalVersion");
        preconditions.push("effectDigest");
    }
    preconditions
}

fn operation_security(spec: OpenApiOperationSpec<'_>) -> Value {
    let profiles = match spec.access_profiles {
        OpenApiAccessProfiles::All => spec.route.access_profiles.clone(),
        OpenApiAccessProfiles::Selected(profile) => vec![profile.to_owned()],
    };
    let mut allows_anonymous = false;
    let mut requires_bearer = false;
    for profile_id in profiles {
        let Some(profile) = spec.entity.access_profiles.get(&profile_id) else {
            continue;
        };
        if profile.anonymous {
            allows_anonymous = true;
        } else {
            requires_bearer = true;
        }
    }
    let mut alternatives = Vec::new();
    if allows_anonymous {
        alternatives.push(json!({}));
    }
    if requires_bearer {
        alternatives.push(json!({"bearerAuth": []}));
    }
    if alternatives.is_empty() {
        alternatives.push(json!({"bearerAuth": []}));
    }
    Value::Array(alternatives)
}

fn operation_parameters(
    route: &CompiledRoute,
    entity: &CompiledEntity,
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
    parameters.push(access_profile_parameter());
    match route.operation {
        Operation::Get => {
            parameters.push(query_parameter(
                "$select",
                false,
                false,
                json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
                "Comma-separated subset of readable API property names.",
            ));
            if entity.change_request.is_some() && route.query_kind.is_none() {
                parameters.push(query_parameter(
                    "requestHistoryAfterProposalVersion",
                    false,
                    false,
                    json!({"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX}),
                    "Positive proposal-version cursor for the request history page returned with this request record.",
                ));
            }
        }
        Operation::List => {
            parameters.extend(read_query_parameters(route, query, access_profiles));
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
                    json!({"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"}),
                    "Strong Registry ETag for the currently visible record representation.",
                ));
            }
        }
        Operation::Revisions => {}
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => {
            parameters.push(header_parameter(
                "Idempotency-Key",
                true,
                json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
                "Idempotency key bound to method, route, caller, request record, package revision, action body, and response field set.",
            ));
            parameters.push(header_parameter(
                "If-Match",
                true,
                json!({"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"}),
                "Strong Registry ETag for the currently visible request record representation.",
            ));
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
            json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}),
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
    parameters
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

fn access_profile_parameter() -> Value {
    query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES}),
        "Select one compiled access profile. Omit to use the route default.",
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
        Operation::Get | Operation::List | Operation::Tombstone | Operation::Revisions => None,
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => Some(json_request_body(json!({
            "$ref": format!("#/components/schemas/{}", spec.request_schema_ref)
        }))),
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
    let mut item_schemas = Vec::new();
    if allow_create {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "data"],
            "properties": {
                "operation": {"const": "create"},
                "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
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
                "ifMatch": {"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"},
                "patch": json_patch_array_schema(),
            }
        }));
    }
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["items"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": maximum_items,
                            "items": {"oneOf": item_schemas}
                        }
                    }
                }
            }
        }
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
    let success = match spec.route.operation {
        Operation::Create => success_response(
            "Record created",
            StatusResponseHeaders::MutationCreate,
            record_response_schema(spec.response_entity, spec.schema_ref),
        ),
        Operation::Get => success_response(
            "Record returned",
            StatusResponseHeaders::ReadDetail,
            record_response_schema(spec.response_entity, spec.schema_ref),
        ),
        Operation::Lookup => success_response(
            "Lookup resolved to one record",
            StatusResponseHeaders::NoStore,
            record_response_schema(spec.response_entity, spec.schema_ref),
        ),
        Operation::List => success_response(
            "Records returned",
            StatusResponseHeaders::NoStore,
            list_response_schema(spec.response_entity, spec.schema_ref),
        ),
        Operation::Patch => success_response(
            "Record patched",
            StatusResponseHeaders::Mutation,
            record_response_schema(spec.response_entity, spec.schema_ref),
        ),
        Operation::Tombstone => success_response(
            "Record tombstoned",
            StatusResponseHeaders::Mutation,
            record_response_schema(spec.response_entity, spec.schema_ref),
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
        Operation::Revisions => success_response(
            "Record revisions returned",
            StatusResponseHeaders::NoStore,
            revision_response_schema(spec.schema_ref, spec.route.revision_kind),
        ),
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => success_response(
            "Request action accepted",
            StatusResponseHeaders::Mutation,
            json!({"$ref": "#/components/schemas/ChangeRequestActionResponse"}),
        ),
    };
    let success_status = if spec.route.operation == Operation::Create {
        "201"
    } else {
        "200"
    };
    let mut responses = Map::from_iter([(success_status.to_owned(), success)]);
    for (status, problems) in problem_responses(spec.route.operation) {
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

fn no_store_header() -> Value {
    json!({"description": "Caller-dependent responses must not be stored.", "schema": {"const": "no-store"}})
}

fn etag_header() -> Value {
    json!({
        "description": "Strong Registry ETag bound to the record, package revision, caller profile, and response field set.",
        "schema": {"type": "string", "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"}
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

fn record_response_schema(entity: &CompiledEntity, schema_ref: &str) -> Value {
    let mut properties = Map::from_iter([
        ("id".to_owned(), json!({"type": "string", "format": "uuid"})),
        (
            "revision".to_owned(),
            json!({"type": "integer", "format": "int64", "minimum": 1}),
        ),
        ("data".to_owned(), json!({"type": "object"})),
    ]);
    if entity.change_request.is_some() {
        properties.insert("request".to_owned(), request_record_metadata_schema());
    }
    if entity
        .access_profiles
        .values()
        .any(|profile| !profile.request_presence.is_empty())
    {
        properties.insert(
            "requestPresence".to_owned(),
            request_presence_metadata_schema(),
        );
    }
    let mut schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "revision", "data"],
        "properties": properties,
        "allOf": [{
            "if": {
                "required": ["request"],
                "properties": {
                    "request": {
                        "type": "object",
                        "required": ["detailErased"],
                        "properties": {
                            "detailErased": {"const": true}
                        }
                    }
                }
            },
            "then": {
                "properties": {
                    "data": {
                        "type": "object",
                        "additionalProperties": false,
                        "maxProperties": 0
                    }
                }
            },
            "else": {
                "properties": {
                    "data": {"$ref": format!("#/components/schemas/{schema_ref}")}
                }
            }
        }]
    });
    if entity.change_request.is_none() {
        schema
            .as_object_mut()
            .expect("record schema is object")
            .remove("allOf");
        schema["properties"]["data"] =
            json!({"$ref": format!("#/components/schemas/{schema_ref}")});
    }
    schema
}

fn list_response_schema(entity: &CompiledEntity, schema_ref: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["items", "pageInfo"],
        "properties": {
            "items": {
                "type": "array",
                "items": record_response_schema(entity, schema_ref),
            },
            "pageInfo": {
                "type": "object",
                "additionalProperties": false,
                "required": ["nextCursor"],
                "properties": {
                    "nextCursor": {"type": ["string", "null"], "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}
                }
            },
            "count": {"type": "integer", "format": "int64", "minimum": 0}
        }
    })
}

fn request_record_metadata_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["serverState", "proposalVersion", "editable"],
        "properties": {
            "serverState": request_state_schema(),
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": nullable_effect_digest_schema(),
            "editable": {"type": "boolean"},
            "detailErased": {"const": true},
            "actions": {
                "type": "array",
                "maxItems": 64,
                "items": request_action_link_schema(),
            },
            "application": request_application_metadata_schema(false),
            "history": retained_request_history_schema(),
        }
    })
}

fn request_action_link_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["operation", "method", "href", "ifMatch"],
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["submit_request", "approve_request", "reject_request", "request_revision", "revise_request", "cancel_request", "apply_request"]
            },
            "method": {"const": "POST"},
            "href": {"type": "string", "maxLength": 2048},
            "ifMatch": {"type": "string", "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"},
            "stage": {"type": "string", "minLength": 1},
            "rebase": {"type": "boolean"},
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": effect_digest_schema(),
            "review": {
                "type": "object",
                "additionalProperties": false,
                "required": ["targets"],
                "properties": {
                    "targets": {
                        "type": "array",
                        "maxItems": 16,
                        "items": request_review_target_schema(),
                    }
                }
            }
        }
    })
}

fn request_review_target_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["entityId", "recordId", "operation", "baseRevision", "before", "after"],
        "properties": {
            "entityId": {"type": "string"},
            "recordId": {"type": "string", "format": "uuid"},
            "operation": {"type": "string", "enum": ["create", "patch"]},
            "baseRevision": {"type": ["integer", "null"], "format": "int64", "minimum": 1},
            "before": {
                "type": ["object", "null"],
                "maxProperties": 128,
                "additionalProperties": true,
            },
            "after": {
                "type": "object",
                "maxProperties": 128,
                "additionalProperties": true,
            }
        }
    })
}

fn request_application_metadata_schema(require_receipt_fields: bool) -> Value {
    let required = if require_receipt_fields {
        json!([
            "applicationId",
            "proposalVersion",
            "effectDigest",
            "appliedAt"
        ])
    } else {
        json!(["applicationId", "proposalVersion"])
    };
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": required,
        "properties": {
            "applicationId": {"type": "string", "format": "uuid"},
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": effect_digest_schema(),
            "appliedAt": {"type": "string", "format": "date-time"}
        }
    })
}

fn retained_request_history_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["proposals", "nextAfterProposalVersion"],
        "properties": {
            "proposals": {
                "type": "array",
                "maxItems": 50,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "requestEntityId",
                        "requestId",
                        "proposalVersion",
                        "serverState",
                        "current",
                        "contractFingerprint",
                        "detailErased",
                        "applicationId",
                        "resultLinkCount",
                        "resultLinks"
                    ],
                    "properties": {
                        "requestEntityId": {"type": "string"},
                        "requestId": {"type": "string", "format": "uuid"},
                        "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
                        "serverState": request_state_schema(),
                        "current": {"type": "boolean"},
                        "contractFingerprint": {"type": "string"},
                        "detailErased": {"type": "boolean"},
                        "applicationId": {"type": ["string", "null"], "format": "uuid"},
                        "resultLinkCount": {"type": "integer", "minimum": 0, "maximum": 16},
                        "resultLinks": {
                            "type": "array",
                            "maxItems": 16,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["targetEntityId", "targetRecordId", "targetRevision"],
                                "properties": {
                                    "targetEntityId": {"type": "string"},
                                    "targetRecordId": {"type": "string", "format": "uuid"},
                                    "targetRevision": {"type": "integer", "format": "int64", "minimum": 1}
                                }
                            }
                        },
                        "effectDigest": effect_digest_schema()
                    }
                }
            },
            "nextAfterProposalVersion": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": u32::MAX}
        }
    })
}

fn request_presence_metadata_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["requests"],
        "properties": {
            "requests": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["requestType", "pending"],
                    "properties": {
                        "requestType": {"type": "string"},
                        "pending": {"type": "boolean"}
                    }
                }
            }
        }
    })
}

fn request_state_schema() -> Value {
    json!({"type": "string", "enum": ["draft", "submitted", "approved", "needs_changes", "rejected", "canceled", "applied"]})
}

fn effect_digest_schema() -> Value {
    json!({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})
}

fn nullable_effect_digest_schema() -> Value {
    json!({"type": ["string", "null"], "pattern": "^sha256:[0-9a-f]{64}$"})
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
        "required": ["results"],
        "properties": {
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
                        "etag": {"type": "string", "pattern": "^\\\"rs-[\\x21\\x23-\\x7E]+\\\"$"},
                        "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
                    }
                }
            }
        }
    })
}

fn revision_response_schema(schema_ref: &str, kind: Option<CompiledRevisionKind>) -> Value {
    let item = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "revision",
            "predecessorRevision",
            "lifecycle",
            "mutationKind",
            "actorReference",
            "requestReference",
            "createdAt",
            "data"
        ],
        "properties": {
            "revision": {"type": "integer", "format": "int64", "minimum": 1},
            "predecessorRevision": {"type": ["integer", "null"], "format": "int64", "minimum": 1},
            "lifecycle": {"type": "string", "enum": ["active", "tombstoned"]},
            "mutationKind": {"type": "string", "enum": ["create", "patch", "tombstone"]},
            "actorReference": {"type": "string"},
            "requestReference": {"type": "string"},
            "createdAt": {"type": "string", "format": "date-time"},
            "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
        }
    });
    if kind == Some(CompiledRevisionKind::Detail) {
        item
    } else {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "properties": {
                "items": {
                    "type": "array",
                    "maxItems": crate::model::MAX_REVISION_HISTORY_RECORDS,
                    "items": item
                }
            }
        })
    }
}

fn request_action_response_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "revision", "request"],
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "revision": {"type": "integer", "format": "int64", "minimum": 1},
            "request": {
                "type": "object",
                "additionalProperties": false,
                "required": ["serverState", "proposalVersion", "effectDigest", "application"],
                "properties": {
                    "serverState": request_state_schema(),
                    "proposalVersion": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": u32::MAX},
                    "effectDigest": nullable_effect_digest_schema(),
                    "application": request_application_metadata_schema(true)
                }
            }
        }
    })
}

#[cfg(test)]
#[path = "tests/artifacts_response_schema_tests.rs"]
mod artifacts_response_schema_tests;

#[derive(Clone, Copy)]
struct ProblemExample {
    code: &'static str,
    detail: &'static str,
}

fn problem_responses(operation: Operation) -> BTreeMap<&'static str, Vec<ProblemExample>> {
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
    if matches!(operation, Operation::List | Operation::Lookup) {
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
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.conflict",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
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
    if is_request_action(operation) {
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "request.conflict",
                    detail: "The request action conflicts with current request state.",
                },
                ProblemExample {
                    code: "idempotency.conflict",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The request action precondition failed.",
            }],
        );
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
        responses.insert(
            "428",
            vec![ProblemExample {
                code: "precondition.required",
                detail: "The request action precondition is required.",
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
            "code": {
                "type": "string",
                "enum": [
                    "authentication.refused",
                    "idempotency.conflict",
                    "lookup.unresolved",
                    "mutation.conflict",
                    "precondition.failed",
                    "precondition.required",
                    "query.cursor_invalid",
                    "query.invalid",
                    "request.conflict",
                    "request.invalid",
                    "request.timeout",
                    "resource.not_found",
                    "service.unavailable",
                    "source.unavailable",
                    "unsupported.media_type"
                ]
            }
        }
    })
}

fn problem_example(status: &str, code: &str, detail: &str) -> Value {
    json!({
        "type": format!("urn:registry-server:problem:{code}"),
        "title": match status {
            "400" => "Bad Request",
            "401" => "Unauthorized",
            "404" => "Not Found",
            "409" => "Conflict",
            "412" => "Precondition Failed",
            "415" => "Unsupported Media Type",
            "428" => "Precondition Required",
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
    json!({
        "profile": operation.profile_id,
        "kind": query_kind_name(operation.kind),
        "maxPageSize": operation.max_page_size,
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
            "scopeProperties": api_field_names(entity, &temporal.scope_fields),
            "semantics": "start_inclusive_end_exclusive",
        }))
    })
}

fn query_filter_operator_name(operator: crate::model::CompiledQueryFilterOperator) -> &'static str {
    match operator {
        crate::model::CompiledQueryFilterOperator::Equals => "equals",
        crate::model::CompiledQueryFilterOperator::In => "in",
        crate::model::CompiledQueryFilterOperator::Range => "range",
        crate::model::CompiledQueryFilterOperator::IsNull => "is_null",
        crate::model::CompiledQueryFilterOperator::IsNotNull => "is_not_null",
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
            .map(|grant| grant.readable_fields.clone())
            .unwrap_or_default();
    }
    spec.entity
        .access_profiles
        .get(profile_id)
        .map(|profile| profile.readable_fields.clone())
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
        CompiledQueryKind::AsOf => "as_of",
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
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
    }
}

fn is_request_action(operation: Operation) -> bool {
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
        "artifact.canonicalization_failed",
        "artifacts",
        "the generated artifact could not be canonicalized",
    )
}
