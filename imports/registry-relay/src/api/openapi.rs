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
use crate::config::Config;
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

    Json(openapi_document(&catalog)).into_response()
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

fn openapi_document(catalog: &CatalogDocument) -> Value {
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
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            paths.insert(
                format!("/datasets/{}/{}", dataset.dataset_id, entity.name),
                json_path_item("get", "Entity collection", &component),
            );
            paths.insert(
                format!("/datasets/{}/{}/schema", dataset.dataset_id, entity.name),
                json_path_item("get", "Entity schema", &format!("{component}Schema")),
            );
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
            "version": "0.1.0",
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

    for dataset in &catalog.datasets {
        for entity in &dataset.entities {
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            schemas.insert(
                component.clone(),
                entity_response_schema(catalog, dataset, entity),
            );
            schemas.insert(
                format!("{component}Schema"),
                entity_metadata_schema(dataset, entity),
            );
        }
    }

    Value::Object(schemas)
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
    json!({
        method: {
            "summary": summary,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                }
            }
        }
    })
}

fn entity_component_name(dataset_id: &str, entity_name: &str) -> String {
    format!(
        "Entity_{}_{}",
        sanitize_component_part(dataset_id),
        sanitize_component_part(entity_name)
    )
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
