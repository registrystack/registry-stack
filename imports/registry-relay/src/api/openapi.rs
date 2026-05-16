// SPDX-License-Identifier: Apache-2.0
//! Best-effort OpenAPI route.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde_json::{json, Map, Value};

use crate::audit::ErrorCodeExt;
use crate::auth::Principal;
use crate::config::{Config, EntityConfig, FilterOp};
use crate::entity::EntityRegistry;
use crate::error::{AuthError, Error};
use crate::metadata::catalog::{
    catalog_document_for_entity_ids, entity_class_uri, field_property_uri, CatalogDocument,
    DatasetMetadata, EntityMetadata, FieldMetadata, RelationshipMetadata,
};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const OPENAPI_UNAVAILABLE_CODE: &str = "openapi.generation_unavailable";

/// Sub-router for the best-effort OpenAPI document.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/openapi.json", get(openapi))
}

async fn openapi(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = openapi_state(config, registry) else {
        return openapi_unavailable("OpenAPI route matched, but metadata state is not installed");
    };
    let visible_entity_ids = match visible_metadata_entity_ids(&config, principal) {
        Ok(entity_ids) => entity_ids,
        Err(error) => return error.into_response(),
    };
    let catalog = catalog_document_for_entity_ids(&config, &registry, &visible_entity_ids);

    Json(openapi_document(&catalog, &config)).into_response()
}

fn openapi_state(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn visible_metadata_entity_ids(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<BTreeSet<(String, String)>, Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    let entity_ids = config
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset
                .entities
                .iter()
                .filter(|entity| principal.scopes.contains(&entity.access.metadata_scope))
                .map(|entity| (dataset.id.to_string(), entity.name.clone()))
        })
        .collect::<BTreeSet<_>>();
    if entity_ids.is_empty() {
        Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity".to_string(),
        }
        .into())
    } else {
        Ok(entity_ids)
    }
}

fn openapi_document(catalog: &CatalogDocument, config: &Config) -> Value {
    let mut paths = Map::new();
    insert_json_path(&mut paths, "/health", "get", "Health", "HealthResponse");
    insert_json_path(
        &mut paths,
        "/ready",
        "get",
        "Readiness",
        "ReadinessResponse",
    );
    insert_json_path(&mut paths, "/catalog", "get", "Catalog", "CatalogDocument");
    paths.insert(
        "/catalog/dcat-ap.jsonld".to_string(),
        json!({
            "get": {
                "summary": "DCAT-AP catalog",
                "responses": {
                    "200": {
                        "description": "DCAT-AP JSON-LD catalog",
                        "content": {
                            "application/ld+json": {
                                "schema": { "type": "object" }
                            }
                        }
                    }
                }
            }
        }),
    );
    insert_json_path(&mut paths, "/datasets", "get", "Datasets", "DatasetList");

    for dataset in &catalog.datasets {
        paths.insert(
            format!("/datasets/{}", dataset.dataset_id),
            json_path_item("get", "Dataset metadata", "DatasetSummary"),
        );
        for entity in &dataset.entities {
            let Some(entity_config) = entity_config(config, &dataset.dataset_id, &entity.name)
            else {
                continue;
            };
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            let collection_component = entity_collection_component_name(&component);
            paths.insert(
                format!("/datasets/{}/{}", dataset.dataset_id, entity.name),
                entity_collection_path_item(
                    "Entity collection",
                    &collection_component,
                    entity_config,
                ),
            );
            paths.insert(
                format!("/datasets/{}/{}/{{id}}", dataset.dataset_id, entity.name),
                entity_record_path_item("Entity record", &component, entity_config),
            );
            paths.insert(
                format!("/datasets/{}/{}/schema", dataset.dataset_id, entity.name),
                json_path_item("get", "Entity schema", &format!("{component}Schema")),
            );
            paths.insert(
                format!("/datasets/{}/{}/verify", dataset.dataset_id, entity.name),
                entity_verify_path_item(entity, entity_config),
            );
            paths.insert(
                format!(
                    "/datasets/{}/{}/aggregates",
                    dataset.dataset_id, entity.name
                ),
                json_path_item("get", "Entity aggregates", "AggregateListResponse"),
            );
            paths.insert(
                format!(
                    "/datasets/{}/{}/aggregates/{{aggregate_id}}",
                    dataset.dataset_id, entity.name
                ),
                path_item_with_params(
                    "get",
                    "Entity aggregate result",
                    "AggregateResult",
                    vec![path_parameter("aggregate_id", "Aggregate identifier")],
                ),
            );
            for relationship in &entity.relationships {
                paths.insert(
                    format!(
                        "/datasets/{}/{}/{{id}}/{}",
                        dataset.dataset_id, entity.name, relationship.name
                    ),
                    entity_relationship_path_item(config, dataset, entity_config, relationship),
                );
            }
            paths.insert(
                format!(
                    "/catalog/datasets/{}/{}/schema.jsonld",
                    dataset.dataset_id, entity.name
                ),
                json!({
                    "get": {
                        "summary": "Entity SHACL schema",
                        "responses": {
                            "200": {
                                "description": "Entity JSON-LD schema and SHACL shape",
                                "content": {
                                    "application/ld+json": {
                                        "schema": { "type": "object" }
                                    }
                                }
                            }
                        }
                    }
                }),
            );
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": catalog.title,
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Best-effort data_gate API document generated from visible metadata.",
        },
        "servers": [{ "url": catalog.base_url }],
        "paths": paths,
        "components": {
            "schemas": schemas(catalog),
        },
    })
}

fn schemas(catalog: &CatalogDocument) -> Value {
    let mut schemas = Map::new();
    schemas.insert("HealthResponse".to_string(), json!({ "type": "object" }));
    schemas.insert("ReadinessResponse".to_string(), json!({ "type": "object" }));
    schemas.insert("CatalogDocument".to_string(), json!({ "type": "object" }));
    schemas.insert("DatasetList".to_string(), json!({ "type": "object" }));
    schemas.insert("DatasetSummary".to_string(), json!({ "type": "object" }));
    schemas.insert("Pagination".to_string(), pagination_schema());
    schemas.insert("ProblemDetails".to_string(), problem_details_schema());
    schemas.insert("VerifyResponse".to_string(), verify_response_schema());
    schemas.insert("AggregateListResponse".to_string(), aggregate_list_schema());
    schemas.insert("AggregateResult".to_string(), aggregate_result_schema());

    for dataset in &catalog.datasets {
        for entity in &dataset.entities {
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            schemas.insert(
                component.clone(),
                entity_response_schema(catalog, dataset, entity),
            );
            schemas.insert(
                entity_collection_component_name(&component),
                entity_collection_schema(&component),
            );
            schemas.insert(
                format!("{component}Schema"),
                entity_metadata_schema(dataset, entity),
            );
        }
    }

    Value::Object(schemas)
}

fn pagination_schema() -> Value {
    json!({
        "type": "object",
        "required": ["has_more"],
        "properties": {
            "has_more": { "type": "boolean" },
            "next_cursor": { "type": "string" },
        },
    })
}

fn problem_details_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "title", "status", "detail", "code"],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
        },
        "additionalProperties": true,
    })
}

fn verify_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["exists"],
        "properties": {
            "exists": { "type": "boolean" },
            "ingest_version": { "type": "string", "nullable": true },
        },
    })
}

fn aggregate_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["data"],
        "properties": {
            "data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["aggregate_id", "description", "group_by", "measures", "min_group_size"],
                    "properties": {
                        "aggregate_id": { "type": "string" },
                        "description": { "type": "string" },
                        "group_by": { "type": "array", "items": { "type": "string" } },
                        "measures": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name", "function", "column"],
                                "properties": {
                                    "name": { "type": "string" },
                                    "function": {
                                        "type": "string",
                                        "enum": ["count", "sum", "avg", "min", "max", "median", "count_distinct", "stddev"]
                                    },
                                    "column": { "type": "string" },
                                },
                            },
                        },
                        "min_group_size": { "type": "integer", "format": "int32", "minimum": 1 },
                    },
                },
            },
        },
    })
}

fn aggregate_result_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "dataset_id",
            "entity",
            "aggregate_id",
            "computed_at",
            "min_group_size",
            "suppressed_groups",
            "rows"
        ],
        "properties": {
            "dataset_id": { "type": "string" },
            "entity": { "type": "string" },
            "aggregate_id": { "type": "string" },
            "computed_at": { "type": "string", "format": "date-time" },
            "min_group_size": { "type": "integer", "format": "int32", "minimum": 1 },
            "suppressed_groups": { "type": "integer", "format": "int64", "minimum": 0 },
            "rows": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
        },
    })
}

fn entity_collection_schema(component: &str) -> Value {
    json!({
        "type": "object",
        "required": ["data", "pagination"],
        "properties": {
            "data": {
                "type": "array",
                "items": { "$ref": format!("#/components/schemas/{component}") },
            },
            "pagination": { "$ref": "#/components/schemas/Pagination" },
        },
    })
}

fn entity_response_schema(
    catalog: &CatalogDocument,
    dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.fields {
        if !field.nullable {
            required.push(Value::String(field.name.clone()));
        }
        properties.insert(
            field.name.clone(),
            field_response_schema(&catalog.base_url, &dataset.dataset_id, &entity.name, field),
        );
    }
    for relationship in &entity.relationships {
        properties.insert(
            relationship.name.clone(),
            relationship_response_schema(dataset, relationship),
        );
    }

    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert(
        "x-concept-uri".to_string(),
        json!(entity_class_uri(
            &catalog.base_url,
            &dataset.dataset_id,
            entity
        )),
    );
    schema.insert("x-dataset-id".to_string(), json!(dataset.dataset_id));
    schema.insert("x-entity-name".to_string(), json!(entity.name));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    Value::Object(schema)
}

fn field_response_schema(
    base_url: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &FieldMetadata,
) -> Value {
    let mut schema = match field.r#type {
        "integer" => json!({ "type": "integer", "format": "int64" }),
        "number" => json!({ "type": "number", "format": "double" }),
        "boolean" => json!({ "type": "boolean" }),
        "date" => json!({ "type": "string", "format": "date" }),
        "timestamp" => json!({ "type": "string", "format": "date-time" }),
        _ => json!({ "type": "string" }),
    };
    schema["nullable"] = json!(field.nullable);
    schema["x-concept-uri"] = json!(field_property_uri(base_url, dataset_id, entity_name, field));
    if let Some(codelist) = &field.codelist {
        schema["x-codelist"] = json!(codelist);
    }
    if let Some(unit) = &field.unit {
        schema["x-unit"] = json!(unit);
    }
    if let Some(language) = &field.language {
        schema["x-language"] = json!(language);
    }
    schema
}

fn relationship_response_schema(
    dataset: &DatasetMetadata,
    relationship: &RelationshipMetadata,
) -> Value {
    let target_ref = dataset
        .entities
        .iter()
        .find(|entity| entity.name == relationship.target)
        .map(|entity| {
            json!({
                "$ref": format!(
                    "#/components/schemas/{}",
                    entity_component_name(&dataset.dataset_id, &entity.name)
                )
            })
        })
        .unwrap_or_else(|| json!({ "type": "object" }));
    let mut schema = if relationship.kind == "has_many" {
        json!({ "type": "array", "items": target_ref })
    } else {
        target_ref
    };
    if let Some(concept_uri) = &relationship.concept_uri {
        schema["x-concept-uri"] = json!(concept_uri);
    }
    schema["x-relationship-kind"] = json!(relationship.kind);
    schema["x-target-entity"] = json!(relationship.target);
    schema["x-foreign-key"] = json!(relationship.foreign_key);
    schema["x-target-schema"] = json!(relationship.links.target_schema);
    schema
}

fn entity_metadata_schema(dataset: &DatasetMetadata, entity: &EntityMetadata) -> Value {
    json!({
        "type": "object",
        "x-concept-uri": entity.concept_uri,
        "x-dataset-id": dataset.dataset_id,
        "x-entity-name": entity.name,
        "properties": {
            "dataset_id": { "type": "string" },
            "entity": { "type": "string" },
            "primary_key": { "type": "string" },
            "fields": { "type": "array", "items": { "type": "object" } },
            "relationships": { "type": "array", "items": { "type": "object" } },
        },
    })
}

fn entity_config<'a>(
    config: &'a Config,
    dataset_id: &str,
    entity_name: &str,
) -> Option<&'a EntityConfig> {
    config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == dataset_id)?
        .entities
        .iter()
        .find(|entity| entity.name == entity_name)
}

fn insert_json_path(
    paths: &mut Map<String, Value>,
    path: &str,
    method: &str,
    summary: &str,
    schema: &str,
) {
    paths.insert(path.to_string(), json_path_item(method, summary, schema));
}

fn json_path_item(method: &str, summary: &str, schema: &str) -> Value {
    path_item_with_params(method, summary, schema, Vec::new())
}

fn path_item_with_params(
    method: &str,
    summary: &str,
    schema: &str,
    parameters: Vec<Value>,
) -> Value {
    json!({
        method: {
            "summary": summary,
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                },
                "default": {
                    "description": "Problem Details error response",
                    "content": {
                        "application/problem+json": {
                            "schema": { "$ref": "#/components/schemas/ProblemDetails" }
                        }
                    }
                }
            }
        }
    })
}

fn entity_collection_path_item(summary: &str, schema: &str, entity: &EntityConfig) -> Value {
    let mut parameters = purpose_parameters(entity.api.require_purpose_header);
    parameters.extend(pagination_parameters());
    parameters.push(query_parameter(
        "fields",
        "Comma-separated entity field projection",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationship expansion list",
            entity
                .api
                .allowed_expansions
                .iter()
                .map(String::as_str)
                .collect(),
        ));
    }
    parameters.extend(filter_parameters(entity));
    path_item_with_params("get", summary, schema, parameters)
}

fn entity_record_path_item(summary: &str, schema: &str, entity: &EntityConfig) -> Value {
    let mut parameters = purpose_parameters(entity.api.require_purpose_header);
    parameters.push(path_parameter("id", "Entity primary key"));
    parameters.push(query_parameter(
        "fields",
        "Comma-separated entity field projection",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationship expansion list",
            entity
                .api
                .allowed_expansions
                .iter()
                .map(String::as_str)
                .collect(),
        ));
    }
    path_item_with_params("get", summary, schema, parameters)
}

fn entity_verify_path_item(entity: &EntityMetadata, entity_config: &EntityConfig) -> Value {
    let mut parameters = purpose_parameters(entity_config.api.require_purpose_header);
    parameters.push(query_parameter(
        &entity.primary_key,
        "Entity primary key value to verify",
    ));
    path_item_with_params(
        "get",
        "Entity record existence check",
        "VerifyResponse",
        parameters,
    )
}

fn entity_relationship_path_item(
    config: &Config,
    dataset: &DatasetMetadata,
    current_entity_config: &EntityConfig,
    relationship: &RelationshipMetadata,
) -> Value {
    let target_component = dataset
        .entities
        .iter()
        .find(|entity| entity.name == relationship.target)
        .map(|entity| entity_component_name(&dataset.dataset_id, &entity.name));
    let schema = match relationship.kind {
        "has_many" => {
            let items = target_component
                .as_deref()
                .map(|component| json!({ "$ref": format!("#/components/schemas/{component}") }))
                .unwrap_or_else(|| json!({ "type": "object", "additionalProperties": true }));
            json!({
            "type": "object",
            "required": ["data", "pagination"],
            "properties": {
                "data": {
                    "type": "array",
                    "items": items,
                },
                "pagination": { "$ref": "#/components/schemas/Pagination" },
            },
            })
        }
        _ if target_component.is_some() => {
            let component = target_component.expect("checked is_some");
            json!({ "$ref": format!("#/components/schemas/{component}") })
        }
        _ => json!({ "type": "object", "additionalProperties": true }),
    };
    let target_requires_purpose = entity_config(config, &dataset.dataset_id, &relationship.target)
        .is_some_and(|target| target.api.require_purpose_header);
    let mut parameters = purpose_parameters(
        current_entity_config.api.require_purpose_header || target_requires_purpose,
    );
    parameters.extend(relationship_parameters(relationship.kind));

    json!({
        "get": {
            "summary": "Entity relationship",
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": schema
                        }
                    }
                },
                "default": {
                    "description": "Problem Details error response",
                    "content": {
                        "application/problem+json": {
                            "schema": { "$ref": "#/components/schemas/ProblemDetails" }
                        }
                    }
                }
            }
        }
    })
}

fn purpose_parameters(required: bool) -> Vec<Value> {
    if required {
        vec![purpose_header_parameter()]
    } else {
        Vec::new()
    }
}

fn pagination_parameters() -> Vec<Value> {
    vec![
        json!({
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": { "type": "integer", "format": "int32", "minimum": 1 },
            "description": "Maximum records to return",
        }),
        query_parameter("cursor", "Opaque pagination cursor"),
    ]
}

fn relationship_parameters(kind: &str) -> Vec<Value> {
    let mut parameters = vec![path_parameter("id", "Entity primary key")];
    if kind == "has_many" {
        parameters.extend(pagination_parameters());
    }
    parameters
}

fn filter_parameters(entity: &EntityConfig) -> Vec<Value> {
    entity
        .api
        .allowed_filters
        .iter()
        .flat_map(|filter| {
            filter.ops.iter().map(|op| {
                let name = filter_parameter_name(&filter.field, *op);
                query_parameter(&name, "Allowed entity filter")
            })
        })
        .collect()
}

fn filter_parameter_name(field: &str, op: FilterOp) -> String {
    match op {
        FilterOp::Eq => field.to_string(),
        FilterOp::In => format!("{field}.in"),
        FilterOp::Gte => format!("{field}.gte"),
        FilterOp::Lte => format!("{field}.lte"),
        FilterOp::Between => format!("{field}.between"),
    }
}

fn path_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": { "type": "string" },
    })
}

fn query_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": { "type": "string" },
    })
}

fn purpose_header_parameter() -> Value {
    json!({
        "name": "Data-Purpose",
        "in": "header",
        "required": true,
        "description": "Free-form purpose-of-use label recorded in the audit trail. Required by this entity's policy; any non-empty value is accepted.",
        "schema": { "type": "string", "minLength": 1 },
        "example": "demo-review",
    })
}

fn enum_query_parameter(name: &str, description: &str, values: Vec<&str>) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": { "type": "string", "enum": values },
    })
}

fn entity_component_name(dataset_id: &str, entity_name: &str) -> String {
    format!(
        "Entity_{}_{}",
        sanitize_component_part(dataset_id),
        sanitize_component_part(entity_name)
    )
}

fn entity_collection_component_name(entity_component: &str) -> String {
    format!("{entity_component}Collection")
}

fn sanitize_component_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn openapi_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/openapi/generation_unavailable",
            "title": "OpenAPI generation unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": OPENAPI_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(OPENAPI_UNAVAILABLE_CODE.to_string()));
    response
}
