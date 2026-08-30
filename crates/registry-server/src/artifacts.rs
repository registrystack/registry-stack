// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

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
    CompiledAccessInventory, CompiledEntity, CompiledEventDeliveryInventory,
    CompiledMetadataInventory, CompiledModuleIdentity, CompiledQueryInventory, CompiledQueryKind,
    CompiledRevisionKind, CompiledRouteInventory, HttpMethod,
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
        let schema = entity_schema(entity);
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
    let openapi = openapi_document(registry_id, version, entities, routes, &schemas);
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
    };
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "entity": {"const": entity.id},
            "recordId": {"type": "string", "format": "uuid"},
            "revision": {"type": "integer", "format": "int64", "minimum": 1},
            "trigger": {"const": trigger},
            "packageRevision": {"type": "string"},
            "values": {
                "type": "object",
                "additionalProperties": false,
                "properties": value_properties,
                "required": event.projection,
            }
        },
        "required": ["entity", "recordId", "revision", "trigger", "packageRevision", "values"]
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

fn entity_schema(entity: &CompiledEntity) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        properties.insert(
            field.logical.api_name.clone(),
            field_schema(&field.logical.field_type),
        );
        if field.required {
            required.push(Value::String(field.logical.api_name.clone()));
        }
    }
    for field in entity.derived_fields.values() {
        let mut schema = field_schema(&field.logical.field_type);
        schema
            .as_object_mut()
            .expect("field schemas are objects")
            .insert("readOnly".to_owned(), Value::Bool(true));
        properties.insert(field.logical.id.clone(), schema);
    }
    json!({
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
    })
}

fn field_schema(field_type: &FieldTypeSource) -> Value {
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
    schemas: &BTreeMap<String, Value>,
) -> Value {
    let mut paths = Map::new();
    for route in &routes.routes {
        let method = match route.method {
            HttpMethod::Delete => "delete",
            HttpMethod::Get => "get",
            HttpMethod::Patch => "patch",
            HttpMethod::Post => "post",
        };
        let path_entry = paths
            .entry(route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(operations) = path_entry else {
            unreachable!("OpenAPI path entries are objects")
        };
        let (status, description) = if route.operation == Operation::Create {
            ("201", "Record created")
        } else {
            ("200", "Operation completed")
        };
        let mut responses = Map::new();
        responses.insert(status.to_owned(), json!({"description": description}));
        let mut operation = Map::from_iter([
            ("operationId".to_owned(), json!(route.id)),
            ("x-registry-entity".to_owned(), json!(route.entity_id)),
            (
                "x-registry-operation".to_owned(),
                json!(operation_name(route.operation)),
            ),
            (
                "x-registry-accessProfiles".to_owned(),
                json!(route.access_profiles),
            ),
            ("responses".to_owned(), Value::Object(responses)),
        ]);
        if let Some(kind) = route.query_kind {
            operation.insert(
                "x-registry-queryKind".to_owned(),
                Value::String(query_kind_name(kind).to_owned()),
            );
            operation.insert("parameters".to_owned(), query_parameters(kind));
        } else if let Some(kind) = route.revision_kind {
            operation.insert("parameters".to_owned(), revision_parameters(kind));
            operation.insert(
                "x-registry-maximumRecords".to_owned(),
                json!(route.maximum_records),
            );
        } else if route.operation == Operation::Batch {
            let batch = entities
                .get(&route.entity_id)
                .and_then(|entity| entity.batch.as_ref())
                .expect("batch routes require compiled bounds");
            let allow_create = route.access_profiles.iter().any(|profile_id| {
                entities[&route.entity_id].access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Create)
            });
            let allow_patch = route.access_profiles.iter().any(|profile_id| {
                entities[&route.entity_id].access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Patch)
            });
            operation.insert("parameters".to_owned(), access_profile_parameters());
            operation.insert(
                "x-registry-maximumItems".to_owned(),
                json!(batch.maximum_items),
            );
            operation.insert(
                "x-registry-maximumBytes".to_owned(),
                json!(batch.maximum_bytes),
            );
            operation.insert(
                "requestBody".to_owned(),
                batch_request_body(
                    &route.entity_id,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            );
            operation.insert(
                "responses".to_owned(),
                batch_response(
                    &route.entity_id,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            );
        }
        operations.insert(method.to_owned(), Value::Object(operation));
    }
    let component_schemas: Map<String, Value> = schemas
        .iter()
        .map(|(id, schema)| (id.clone(), schema.clone()))
        .collect();
    json!({
        "openapi": "3.1.0",
        "info": {"title": registry_id, "version": version},
        "paths": paths,
        "components": {"schemas": component_schemas}
    })
}

fn access_profile_parameters() -> Value {
    Value::Array(vec![query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string"}),
        "Select one compiled access profile.",
    )])
}

fn batch_request_body(
    entity_id: &str,
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
                "data": {"$ref": format!("#/components/schemas/{entity_id}")},
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
                "ifMatch": {"type": "string"},
                "patch": {"type": "array", "minItems": 1, "maxItems": 128},
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

fn batch_response(
    entity_id: &str,
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
        "200": {
            "description": "Atomic batch committed",
            "content": {
                "application/json": {
                    "schema": {
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
                                        "etag": {"type": "string"},
                                        "data": {"$ref": format!("#/components/schemas/{entity_id}")},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

fn revision_parameters(kind: CompiledRevisionKind) -> Value {
    let mut parameters = vec![query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string"}),
        "Select one compiled access profile.",
    )];
    parameters.push(path_parameter(
        "record_id",
        json!({"type": "string", "format": "uuid"}),
        "Canonical record UUID.",
    ));
    if kind == CompiledRevisionKind::Detail {
        parameters.push(path_parameter(
            "revision",
            json!({"type": "integer", "format": "int64", "minimum": 1}),
            "Exact positive record revision.",
        ));
    }
    Value::Array(parameters)
}

fn query_parameters(kind: CompiledQueryKind) -> Value {
    let mut parameters = vec![
        query_parameter(
            "accessProfile",
            false,
            false,
            json!({"type": "string"}),
            "Select one compiled access profile.",
        ),
        query_parameter(
            "$select",
            false,
            false,
            json!({"type": "string"}),
            "Comma-separated subset of readable API property names.",
        ),
        query_parameter(
            "$filter",
            false,
            false,
            json!({"type": "string"}),
            "Strict Registry read filter expression over compiled filterable properties.",
        ),
        query_parameter(
            "$orderby",
            false,
            false,
            json!({"type": "string"}),
            "One compiled sortable property, ascending only.",
        ),
        query_parameter(
            "$top",
            false,
            false,
            json!({"type": "integer", "minimum": 1, "maximum": 100}),
            "Bounded page size.",
        ),
        query_parameter(
            "$count",
            false,
            false,
            json!({"type": "boolean"}),
            "Request a total count when the compiled operation allows it.",
        ),
        query_parameter(
            "$skiptoken",
            false,
            false,
            json!({"type": "string"}),
            "Opaque continuation cursor for the next page.",
        ),
    ];
    if kind == CompiledQueryKind::AsOf {
        parameters.push(query_parameter(
            "asOf",
            true,
            false,
            json!({"type": "string", "format": "date-time"}),
            "Strict UTC RFC3339 instant for the as-of temporal query.",
        ));
    }
    Value::Array(parameters)
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

fn path_parameter(name: &str, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": schema,
    })
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
        "artifact.canonicalization_failed",
        "artifacts",
        "the generated artifact could not be canonicalized",
    )
}
