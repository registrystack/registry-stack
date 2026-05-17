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

const TAG_SERVICE: &str = "Service";
const TAG_CATALOG: &str = "Catalog";
#[cfg(feature = "ogcapi-features")]
const TAG_OGC: &str = "OGC API Features";

const INFO_SUMMARY: &str = "Read-only data gateway exposing entity records, \
    catalog metadata, and SHACL/DCAT-AP shapes for governed datasets.";

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

    // ---- Service ----
    insert_json_path(
        &mut paths,
        "/health",
        "get",
        "Liveness probe",
        "HealthResponse",
    );
    set_op_id(&mut paths, "/health", "get", "get_health");
    set_description(
        &mut paths,
        "/health",
        "get",
        "Returns 200 once the gateway process has started. Unauthenticated.",
    );
    mark_public(&mut paths, "/health", "get");
    tag(&mut paths, "/health", "get", TAG_SERVICE);

    insert_json_path(
        &mut paths,
        "/ready",
        "get",
        "Readiness probe",
        "ReadinessResponse",
    );
    set_op_id(&mut paths, "/ready", "get", "get_ready");
    set_description(
        &mut paths,
        "/ready",
        "get",
        "Returns 200 once dependent state (entity registry, audit sink) is initialised. \
         Unauthenticated.",
    );
    mark_public(&mut paths, "/ready", "get");
    tag(&mut paths, "/ready", "get", TAG_SERVICE);

    // ---- Catalog ----
    insert_json_path(
        &mut paths,
        "/catalog",
        "get",
        "Catalog overview",
        "CatalogDocument",
    );
    set_op_id(&mut paths, "/catalog", "get", "get_catalog");
    set_description(
        &mut paths,
        "/catalog",
        "get",
        "Returns the gateway's catalog overview: datasets and entities visible to the \
         calling principal, with links to dataset-level metadata and SHACL/DCAT-AP artifacts.",
    );
    tag(&mut paths, "/catalog", "get", TAG_CATALOG);

    paths.insert(
        "/catalog/dcat-ap.jsonld".to_string(),
        jsonld_path_item(
            "get_catalog_dcat_ap",
            "DCAT-AP catalog (JSON-LD)",
            "Returns the catalog as a DCAT-AP 3 JSON-LD document. Useful for federating \
             with dataspace catalogs (IDS, EDC) or generic DCAT consumers.",
            "DCAT-AP JSON-LD catalog",
        ),
    );
    tag(&mut paths, "/catalog/dcat-ap.jsonld", "get", TAG_CATALOG);

    #[cfg(feature = "ogcapi-features")]
    insert_ogc_paths(&mut paths);

    insert_json_path(
        &mut paths,
        "/datasets",
        "get",
        "List datasets",
        "DatasetList",
    );
    set_op_id(&mut paths, "/datasets", "get", "list_datasets");
    set_description(
        &mut paths,
        "/datasets",
        "get",
        "Lists every dataset visible to the calling principal.",
    );
    tag(&mut paths, "/datasets", "get", TAG_CATALOG);

    for dataset in &catalog.datasets {
        let dataset_slug = op_id_slug(&dataset.dataset_id);

        let dataset_path = format!("/datasets/{}", dataset.dataset_id);
        paths.insert(
            dataset_path.clone(),
            json_path_item("get", "Dataset metadata", "DatasetSummary"),
        );
        set_op_id(
            &mut paths,
            &dataset_path,
            "get",
            &format!("get_{dataset_slug}_metadata"),
        );
        set_description(
            &mut paths,
            &dataset_path,
            "get",
            &format!(
                "Returns metadata for the `{}` dataset: entities, publishers, sensitivity, \
                 update frequency, and links to JSON, JSON-LD, and SHACL artifacts.\n\n{}",
                dataset.dataset_id, dataset.description
            ),
        );
        add_response_404(
            &mut paths,
            &dataset_path,
            "get",
            "Dataset not found or not visible to the caller.",
        );
        tag(&mut paths, &dataset_path, "get", TAG_CATALOG);

        for entity in &dataset.entities {
            let Some(entity_config) = entity_config(config, &dataset.dataset_id, &entity.name)
            else {
                continue;
            };
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            let collection_component = entity_collection_component_name(&component);
            let entity_tag = entity_tag_name(&dataset.dataset_id, &entity.name);
            let entity_slug = op_id_slug(&entity.name);
            let stem = format!("{dataset_slug}_{entity_slug}");
            let entity_desc = entity.description.as_deref().unwrap_or("");

            // List records
            let collection_path = format!("/datasets/{}/{}", dataset.dataset_id, entity.name);
            paths.insert(
                collection_path.clone(),
                entity_collection_path_item("List records", &collection_component, entity_config),
            );
            set_op_id(
                &mut paths,
                &collection_path,
                "get",
                &format!("list_{stem}_records"),
            );
            set_description(
                &mut paths,
                &collection_path,
                "get",
                &format!(
                    "List `{}` records from dataset `{}`.{}\n\n\
                     Supports pagination via `limit`+`cursor`, projection via `fields`, \
                     relationship expansion via `expand`, and configured filters.",
                    entity.name,
                    dataset.dataset_id,
                    if entity_desc.is_empty() {
                        String::new()
                    } else {
                        format!(" {entity_desc}")
                    },
                ),
            );
            set_code_samples(
                &mut paths,
                &collection_path,
                "get",
                code_samples_for_collection(&dataset.dataset_id, &entity.name),
            );
            if entity_config.api.require_purpose_header {
                add_purpose_header_parameter(&mut paths, &collection_path, "get");
            }
            tag(&mut paths, &collection_path, "get", &entity_tag);

            // Get record by id
            let record_path = format!("/datasets/{}/{}/{{id}}", dataset.dataset_id, entity.name);
            paths.insert(
                record_path.clone(),
                entity_record_path_item("Get record by id", &component, entity_config),
            );
            set_op_id(
                &mut paths,
                &record_path,
                "get",
                &format!("get_{stem}_record"),
            );
            set_description(
                &mut paths,
                &record_path,
                "get",
                &format!(
                    "Return a single `{}` record from `{}` by primary key.{}",
                    entity.name,
                    dataset.dataset_id,
                    if entity_desc.is_empty() {
                        String::new()
                    } else {
                        format!(" {entity_desc}")
                    },
                ),
            );
            add_response_404(
                &mut paths,
                &record_path,
                "get",
                &format!(
                    "`{}` record with the given primary key not found.",
                    entity.name
                ),
            );
            set_code_samples(
                &mut paths,
                &record_path,
                "get",
                code_samples_for_record(&dataset.dataset_id, &entity.name),
            );
            if entity_config.api.require_purpose_header {
                add_purpose_header_parameter(&mut paths, &record_path, "get");
            }
            tag(&mut paths, &record_path, "get", &entity_tag);

            // Field schema (JSON Schema view)
            let field_schema_path =
                format!("/datasets/{}/{}/schema", dataset.dataset_id, entity.name);
            paths.insert(
                field_schema_path.clone(),
                json_path_item("get", "Field schema", &format!("{component}Schema")),
            );
            set_op_id(
                &mut paths,
                &field_schema_path,
                "get",
                &format!("get_{stem}_field_schema"),
            );
            set_description(
                &mut paths,
                &field_schema_path,
                "get",
                &format!(
                    "Returns the `{}` field schema in a JSON-friendly form: field names, \
                     types, concept URIs, codelists, units, and language tags. Useful for \
                     codegen and validation.",
                    entity.name,
                ),
            );
            tag(&mut paths, &field_schema_path, "get", &entity_tag);

            // Verify
            let verify_path = format!("/datasets/{}/{}/verify", dataset.dataset_id, entity.name);
            paths.insert(verify_path.clone(), entity_verify_path_item(entity));
            set_op_id(
                &mut paths,
                &verify_path,
                "get",
                &format!("verify_{stem}_record"),
            );
            set_description(
                &mut paths,
                &verify_path,
                "get",
                &format!(
                    "Verifies that a `{}` record with the given primary key exists, without \
                     returning its content. Useful when the caller has `verify` scope only.",
                    entity.name,
                ),
            );
            if entity_config.api.require_purpose_header {
                add_purpose_header_parameter(&mut paths, &verify_path, "get");
            }
            tag(&mut paths, &verify_path, "get", &entity_tag);

            // List aggregates
            let aggregates_path = format!(
                "/datasets/{}/{}/aggregates",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                aggregates_path.clone(),
                json_path_item("get", "List aggregates", "AggregateListResponse"),
            );
            set_op_id(
                &mut paths,
                &aggregates_path,
                "get",
                &format!("list_{stem}_aggregates"),
            );
            set_description(
                &mut paths,
                &aggregates_path,
                "get",
                &format!(
                    "Lists the named aggregate queries defined for `{}` in `{}`. Each entry \
                     declares its group-by columns, measures, and minimum group size used for \
                     disclosure control.",
                    entity.name, dataset.dataset_id,
                ),
            );
            tag(&mut paths, &aggregates_path, "get", &entity_tag);

            // Run aggregate
            let aggregate_run_path = format!(
                "/datasets/{}/{}/aggregates/{{aggregate_id}}",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                aggregate_run_path.clone(),
                path_item_with_params(
                    "get",
                    "Run aggregate",
                    "AggregateResult",
                    vec![path_parameter("aggregate_id", "Aggregate identifier")],
                ),
            );
            set_op_id(
                &mut paths,
                &aggregate_run_path,
                "get",
                &format!("run_{stem}_aggregate"),
            );
            set_description(
                &mut paths,
                &aggregate_run_path,
                "get",
                &format!(
                    "Runs the named aggregate against `{}`. Returns the configured group-by \
                     and measures, with sub-threshold groups suppressed per disclosure control.",
                    entity.name,
                ),
            );
            add_response_404(
                &mut paths,
                &aggregate_run_path,
                "get",
                "Aggregate definition not found for this entity.",
            );
            tag(&mut paths, &aggregate_run_path, "get", &entity_tag);

            // Relationships
            for relationship in &entity.relationships {
                let relationship_path = format!(
                    "/datasets/{}/{}/{{id}}/{}",
                    dataset.dataset_id, entity.name, relationship.name
                );
                paths.insert(
                    relationship_path.clone(),
                    entity_relationship_path_item(dataset, relationship),
                );
                let rel_slug = op_id_slug(&relationship.name);
                set_op_id(
                    &mut paths,
                    &relationship_path,
                    "get",
                    &format!("get_{stem}_{rel_slug}"),
                );
                set_description(
                    &mut paths,
                    &relationship_path,
                    "get",
                    &format!(
                        "Returns the `{}` ({}) target(s) for one `{}` record. Foreign key: `{}`.",
                        relationship.name, relationship.kind, entity.name, relationship.foreign_key,
                    ),
                );
                add_response_404(
                    &mut paths,
                    &relationship_path,
                    "get",
                    "Parent record not found, or relationship target unavailable.",
                );
                let target_requires_purpose = config
                    .datasets
                    .iter()
                    .find(|d| d.id.as_str() == dataset.dataset_id)
                    .and_then(|d| d.entities.iter().find(|e| e.name == relationship.target))
                    .is_some_and(|target| target.api.require_purpose_header);
                if entity_config.api.require_purpose_header || target_requires_purpose {
                    add_purpose_header_parameter(&mut paths, &relationship_path, "get");
                }
                tag(&mut paths, &relationship_path, "get", &entity_tag);
            }

            // SHACL shape (JSON-LD)
            let shacl_path = format!(
                "/catalog/datasets/{}/{}/schema.jsonld",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                shacl_path.clone(),
                jsonld_path_item(
                    &format!("get_{stem}_shacl_shape"),
                    "SHACL shape (JSON-LD)",
                    &format!(
                        "Returns the JSON-LD schema and SHACL shape for `{}` in `{}`. \
                         Useful for shape validators and semantic catalog consumers.",
                        entity.name, dataset.dataset_id,
                    ),
                    "Entity JSON-LD schema and SHACL shape",
                ),
            );
            tag(&mut paths, &shacl_path, "get", &entity_tag);
        }
    }

    let server_url = catalog.base_url.trim_end_matches('/').to_string();

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": catalog.title,
            "summary": INFO_SUMMARY,
            "description": "Best-effort Registry Relay API document generated from visible metadata.",
            "version": env!("CARGO_PKG_VERSION"),
            "contact": { "name": catalog.publisher },
            "license": {
                "name": "Apache-2.0",
                "identifier": "Apache-2.0",
            },
        },
        "servers": [{
            "url": server_url,
            "description": "Configured base URL for this gateway instance.",
        }],
        "security": [{ "bearerAuth": [] }],
        "tags": tag_definitions(catalog),
        "x-tagGroups": tag_groups(catalog),
        "paths": paths,
        "components": {
            "schemas": schemas(catalog),
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "V1 API key carried as `Authorization: Bearer <key>`. The gateway hashes the bearer with SHA-256 and matches the fingerprint against `config.auth.api_keys[*].hash_env`.",
                },
            },
        },
    })
}

fn entity_tag_name(dataset_id: &str, entity_name: &str) -> String {
    format!("{dataset_id} / {entity_name}")
}

/// Build the document-level `tags` array. Tag order drives the sidebar
/// order in Scalar: `Service` and `Catalog` first, then one tag per
/// `(dataset, entity)` pair in catalog iteration order (the catalog
/// document is already sorted). Entity tags carry `x-displayName` so
/// Scalar can render a short label while the tag key (used by every
/// per-operation `tags` reference) stays stable.
fn tag_definitions(catalog: &CatalogDocument) -> Value {
    let mut tags = vec![
        json!({
            "name": TAG_SERVICE,
            "description": "Liveness and readiness probes. Unauthenticated.",
        }),
        json!({
            "name": TAG_CATALOG,
            "description": "Catalog discovery: dataset listing, dataset metadata, DCAT-AP export.",
        }),
    ];
    #[cfg(feature = "ogcapi-features")]
    tags.push(json!({
        "name": TAG_OGC,
        "description": "OGC API Features discovery and dataset-scoped feature collections.",
    }));
    for dataset in &catalog.datasets {
        for entity in &dataset.entities {
            let display = entity.title.as_deref().unwrap_or(&entity.name);
            let mut tag_obj = json!({
                "name": entity_tag_name(&dataset.dataset_id, &entity.name),
                "x-displayName": display,
                "description": format!(
                    "Operations on the `{}` entity in dataset `{}`.",
                    entity.name, dataset.dataset_id,
                ),
            });
            if let Some(desc) = entity.description.as_deref() {
                if !desc.is_empty() {
                    tag_obj["description"] = json!(format!(
                        "Operations on the `{}` entity in dataset `{}`. {desc}",
                        entity.name, dataset.dataset_id,
                    ));
                }
            }
            tags.push(tag_obj);
        }
    }
    Value::Array(tags)
}

/// Build the Scalar-specific `x-tagGroups` array. Groups every entity
/// tag under its dataset, with `Service` and `Catalog` as their own
/// groups. Scalar renders each group as a collapsible sidebar section.
fn tag_groups(catalog: &CatalogDocument) -> Value {
    let mut groups = vec![
        json!({ "name": "Service", "tags": [TAG_SERVICE] }),
        json!({ "name": "Catalog", "tags": [TAG_CATALOG] }),
    ];
    #[cfg(feature = "ogcapi-features")]
    groups.push(json!({ "name": "OGC", "tags": [TAG_OGC] }));
    for dataset in &catalog.datasets {
        let entity_tags: Vec<String> = dataset
            .entities
            .iter()
            .map(|entity| entity_tag_name(&dataset.dataset_id, &entity.name))
            .collect();
        if entity_tags.is_empty() {
            continue;
        }
        groups.push(json!({
            "name": dataset.title,
            "tags": entity_tags,
        }));
    }
    Value::Array(groups)
}

// --- post-construction mutators ------------------------------------
// All mutators follow the same shape as `tag()`/`mark_public()`:
// resolve `(path, method)` to an operation object, then mutate. Each
// is a no-op if the operation is absent, which keeps the openapi_document
// body declarative.

fn op_at<'a>(
    paths: &'a mut Map<String, Value>,
    path: &str,
    method: &str,
) -> Option<&'a mut Map<String, Value>> {
    paths
        .get_mut(path)?
        .get_mut(method)
        .and_then(Value::as_object_mut)
}

fn set_op_id(paths: &mut Map<String, Value>, path: &str, method: &str, op_id: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("operationId".to_string(), json!(op_id));
    }
}

fn set_description(paths: &mut Map<String, Value>, path: &str, method: &str, description: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("description".to_string(), json!(description));
    }
}

fn set_code_samples(paths: &mut Map<String, Value>, path: &str, method: &str, samples: Vec<Value>) {
    if samples.is_empty() {
        return;
    }
    if let Some(op) = op_at(paths, path, method) {
        op.insert("x-codeSamples".to_string(), Value::Array(samples));
    }
}

/// Append the `Data-Purpose` header parameter to the operation at
/// `(path, method)`. No-op if the operation does not exist or already
/// declares the header. The parameter is required by the gateway when
/// the entity has `api.require_purpose_header: true`.
fn add_purpose_header_parameter(paths: &mut Map<String, Value>, path: &str, method: &str) {
    let Some(op) = op_at(paths, path, method) else {
        return;
    };
    let parameters = op
        .entry("parameters".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut();
    let Some(parameters) = parameters else {
        return;
    };
    let already_declared = parameters.iter().any(|p| {
        p.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case("Data-Purpose"))
            && p.get("in").and_then(Value::as_str) == Some("header")
    });
    if !already_declared {
        parameters.push(purpose_header_parameter());
    }
}

fn add_response_404(paths: &mut Map<String, Value>, path: &str, method: &str, description: &str) {
    if let Some(op) = op_at(paths, path, method) {
        if let Some(responses) = op.get_mut("responses").and_then(Value::as_object_mut) {
            responses.insert("404".to_string(), problem_response(description));
        }
    }
}

/// Single tag on the operation at `(path, method)`. No-op if the
/// operation does not exist.
fn tag(paths: &mut Map<String, Value>, path: &str, method: &str, tag: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("tags".to_string(), json!([tag]));
    }
}

/// Override the document-level security requirement on a single
/// operation so it advertises as unauthenticated. Used for `/health`
/// and `/ready`, which are merged onto the public sub-router in
/// `crate::server::build_app_with_provenance`.
fn mark_public(paths: &mut Map<String, Value>, path: &str, method: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("security".to_string(), json!([]));
    }
}

// --- Scalar code samples -------------------------------------------

fn code_samples_for_collection(dataset_id: &str, entity_name: &str) -> Vec<Value> {
    let curl = format!(
        "curl -sS \\\n  -H 'Authorization: Bearer $REGISTRY_RELAY_TOKEN' \\\n  'http://localhost:4242/datasets/{dataset_id}/{entity_name}?limit=10'"
    );
    let python = format!(
        "import os, httpx\n\n\
         token = os.environ['REGISTRY_RELAY_TOKEN']\n\
         resp = httpx.get(\n    \
         'http://localhost:4242/datasets/{dataset_id}/{entity_name}',\n    \
         params={{'limit': 10}},\n    \
         headers={{'Authorization': f'Bearer {{token}}'}}\n\
         )\n\
         resp.raise_for_status()\n\
         page = resp.json()\n\
         for row in page['data']:\n    \
         print(row)\n\
         next_cursor = page['pagination'].get('next_cursor')"
    );
    vec![
        json!({ "lang": "Shell", "label": "curl", "source": curl }),
        json!({ "lang": "Python", "label": "httpx", "source": python }),
    ]
}

fn code_samples_for_record(dataset_id: &str, entity_name: &str) -> Vec<Value> {
    let curl = format!(
        "curl -sS \\\n  -H 'Authorization: Bearer $REGISTRY_RELAY_TOKEN' \\\n  'http://localhost:4242/datasets/{dataset_id}/{entity_name}/$ID'"
    );
    let python = format!(
        "import os, httpx\n\n\
         token = os.environ['REGISTRY_RELAY_TOKEN']\n\
         record_id = '...'\n\
         resp = httpx.get(\n    \
         f'http://localhost:4242/datasets/{dataset_id}/{entity_name}/{{record_id}}',\n    \
         headers={{'Authorization': f'Bearer {{token}}'}}\n\
         )\n\
         resp.raise_for_status()\n\
         print(resp.json())"
    );
    vec![
        json!({ "lang": "Shell", "label": "curl", "source": curl }),
        json!({ "lang": "Python", "label": "httpx", "source": python }),
    ]
}

// --- schemas --------------------------------------------------------

fn schemas(catalog: &CatalogDocument) -> Value {
    let mut schemas = Map::new();
    schemas.insert("HealthResponse".to_string(), health_schema());
    schemas.insert("ReadinessResponse".to_string(), readiness_schema());
    schemas.insert("CatalogDocument".to_string(), catalog_document_schema());
    schemas.insert("DatasetList".to_string(), dataset_list_schema());
    schemas.insert("DatasetSummary".to_string(), dataset_summary_schema());
    schemas.insert("Pagination".to_string(), pagination_schema());
    schemas.insert("ProblemDetails".to_string(), problem_details_schema());
    schemas.insert("VerifyResponse".to_string(), verify_response_schema());
    schemas.insert("AggregateListResponse".to_string(), aggregate_list_schema());
    schemas.insert("AggregateResult".to_string(), aggregate_result_schema());
    #[cfg(feature = "ogcapi-features")]
    insert_ogc_schemas(&mut schemas);

    for dataset in &catalog.datasets {
        for entity in &dataset.entities {
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            schemas.insert(
                component.clone(),
                entity_response_schema(catalog, dataset, entity),
            );
            schemas.insert(
                entity_collection_component_name(&component),
                entity_collection_schema(&component, catalog, dataset, entity),
            );
            schemas.insert(
                format!("{component}Schema"),
                entity_metadata_schema(dataset, entity),
            );
        }
    }

    Value::Object(schemas)
}

fn health_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "examples": ["ok"] }
        },
        "examples": [{ "status": "ok" }],
    })
}

fn readiness_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "examples": ["ready"] }
        },
        "examples": [{ "status": "ready" }],
    })
}

fn catalog_document_schema() -> Value {
    json!({
        "type": "object",
        "description": "Catalog overview. See `/catalog` for the live document.",
    })
}

fn dataset_list_schema() -> Value {
    json!({
        "type": "object",
        "description": "Listing of datasets visible to the calling principal.",
    })
}

fn dataset_summary_schema() -> Value {
    json!({
        "type": "object",
        "description": "Per-dataset metadata. See `/datasets/{id}` for the live shape.",
    })
}

fn pagination_schema() -> Value {
    json!({
        "type": "object",
        "required": ["has_more"],
        "properties": {
            "has_more": { "type": "boolean", "description": "True when more pages remain after this one." },
            "next_cursor": {
                "type": ["string", "null"],
                "description": "Opaque cursor for the next page; null when `has_more` is false.",
            },
        },
        "examples": [{ "has_more": true, "next_cursor": "eyJvIjoyMH0=" }],
    })
}

fn problem_details_schema() -> Value {
    json!({
        "type": "object",
        "description": "RFC 7807 Problem Details, returned for every non-2xx response.",
        "required": ["type", "title", "status", "detail", "code"],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
        },
        "additionalProperties": true,
        "examples": [{
            "type": "https://data.example.gov/problems/auth/missing_credential",
            "title": "Missing credential",
            "status": 401,
            "detail": "no credential provided in Authorization or X-Api-Key header",
            "code": "auth.missing_credential",
        }],
    })
}

#[cfg(feature = "ogcapi-features")]
fn insert_ogc_schemas(schemas: &mut Map<String, Value>) {
    schemas.insert("OgcLink".to_string(), ogc_link_schema());
    schemas.insert("OgcLandingPage".to_string(), ogc_landing_page_schema());
    schemas.insert("OgcConformance".to_string(), ogc_conformance_schema());
    schemas.insert("OgcCollections".to_string(), ogc_collections_schema());
    schemas.insert("OgcCollection".to_string(), ogc_collection_schema());
    schemas.insert(
        "GeoJsonFeatureCollection".to_string(),
        geojson_feature_collection_schema(),
    );
    schemas.insert("GeoJsonFeature".to_string(), geojson_feature_schema());
}

#[cfg(feature = "ogcapi-features")]
fn ogc_link_schema() -> Value {
    json!({
        "type": "object",
        "required": ["href", "rel"],
        "properties": {
            "href": { "type": "string" },
            "rel": { "type": "string" },
            "type": { "type": "string" },
            "title": { "type": "string" },
        },
        "additionalProperties": true,
    })
}

#[cfg(feature = "ogcapi-features")]
fn ogc_landing_page_schema() -> Value {
    json!({
        "type": "object",
        "required": ["title", "links"],
        "properties": {
            "title": { "type": "string" },
            "description": { "type": "string" },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn ogc_conformance_schema() -> Value {
    json!({
        "type": "object",
        "required": ["conformsTo"],
        "properties": {
            "conformsTo": { "type": "array", "items": { "type": "string", "format": "uri" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn ogc_collections_schema() -> Value {
    json!({
        "type": "object",
        "required": ["links", "collections"],
        "properties": {
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
            "collections": { "type": "array", "items": { "$ref": "#/components/schemas/OgcCollection" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn ogc_collection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "itemType", "links"],
        "properties": {
            "id": { "type": "string" },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "itemType": { "type": "string", "enum": ["feature"] },
            "crs": { "type": "array", "items": { "type": "string", "format": "uri" } },
            "storageCrs": { "type": "string", "format": "uri" },
            "extent": { "type": "object", "additionalProperties": true },
            "properties": { "type": "object", "additionalProperties": true },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn geojson_feature_collection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "features"],
        "properties": {
            "type": { "type": "string", "enum": ["FeatureCollection"] },
            "timeStamp": { "type": "string", "format": "date-time" },
            "numberReturned": { "type": "integer", "minimum": 0 },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
            "features": { "type": "array", "items": { "$ref": "#/components/schemas/GeoJsonFeature" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn geojson_feature_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "id", "geometry", "properties"],
        "properties": {
            "type": { "type": "string", "enum": ["Feature"] },
            "id": { "type": "string" },
            "geometry": { "type": ["object", "null"], "additionalProperties": true },
            "properties": { "type": "object", "additionalProperties": true },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

fn verify_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["exists"],
        "properties": {
            "exists": {
                "type": "boolean",
                "description": "Whether a record with the supplied primary key is present.",
            },
            "ingest_version": {
                "type": ["string", "null"],
                "description": "Ingest version that introduced the record. Null when unknown.",
            },
        },
        "examples": [{ "exists": true, "ingest_version": "2026-05-01" }],
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
        "examples": [{
            "data": [{
                "aggregate_id": "households_by_region",
                "description": "Household count by region",
                "group_by": ["region"],
                "measures": [{ "name": "household_count", "function": "count", "column": "id" }],
                "min_group_size": 2,
            }]
        }],
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
        "examples": [{
            "dataset_id": "social_registry",
            "entity": "household",
            "aggregate_id": "households_by_region",
            "computed_at": "2026-05-16T08:00:00Z",
            "min_group_size": 2,
            "suppressed_groups": 1,
            "rows": [{ "region": "north", "household_count": 42 }],
        }],
    })
}

fn entity_collection_schema(
    component: &str,
    catalog: &CatalogDocument,
    dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let item_example = entity_example(catalog, dataset, entity);
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
        "examples": [{
            "data": [item_example],
            "pagination": { "has_more": false, "next_cursor": null },
        }],
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
    if let Some(desc) = entity.description.as_deref() {
        if !desc.is_empty() {
            schema.insert("description".to_string(), json!(desc));
        }
    }
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
    schema.insert(
        "examples".to_string(),
        Value::Array(vec![entity_example(catalog, dataset, entity)]),
    );
    Value::Object(schema)
}

/// Build a representative JSON example for an entity using each field's
/// declared type. Relationship properties are omitted from the example.
fn entity_example(
    _catalog: &CatalogDocument,
    _dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let mut obj = Map::new();
    for field in &entity.fields {
        obj.insert(field.name.clone(), field_example_value(field));
    }
    Value::Object(obj)
}

fn field_example_value(field: &FieldMetadata) -> Value {
    match field.r#type {
        "integer" => json!(42),
        "number" => json!(12.34),
        "boolean" => json!(true),
        "date" => json!("2026-01-15"),
        "timestamp" => json!("2026-01-15T08:30:00Z"),
        _ => json!(example_string_for(field)),
    }
}

fn example_string_for(field: &FieldMetadata) -> String {
    // Conservative defaults that read naturally in Scalar's preview.
    let name = field.name.as_str();
    if name.ends_with("_id") || name == "id" {
        return "01HZX9...".to_string();
    }
    if name.contains("code") {
        return "REG-001".to_string();
    }
    if name.contains("region") || name.contains("country") {
        return "north".to_string();
    }
    if name.contains("email") {
        return "alex@example.test".to_string();
    }
    if name.contains("name") {
        return "Alex Example".to_string();
    }
    format!("<{}>", name)
}

fn field_response_schema(
    base_url: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &FieldMetadata,
) -> Value {
    let (type_value, format) = match field.r#type {
        "integer" => (json!("integer"), Some("int64")),
        "number" => (json!("number"), Some("double")),
        "boolean" => (json!("boolean"), None),
        "date" => (json!("string"), Some("date")),
        "timestamp" => (json!("string"), Some("date-time")),
        _ => (json!("string"), None),
    };

    let mut schema = Map::new();
    // OAS 3.1 nullability is expressed via a type array; the `nullable`
    // keyword from 3.0 is silently ignored by 3.1 tooling.
    let type_field = if field.nullable {
        let base = type_value.as_str().expect("scalar type tag");
        Value::Array(vec![json!(base), json!("null")])
    } else {
        type_value
    };
    schema.insert("type".to_string(), type_field);
    if let Some(fmt) = format {
        schema.insert("format".to_string(), json!(fmt));
    }
    schema.insert(
        "description".to_string(),
        json!(synth_field_description(field)),
    );
    schema.insert(
        "x-concept-uri".to_string(),
        json!(field_property_uri(base_url, dataset_id, entity_name, field)),
    );
    if let Some(codelist) = &field.codelist {
        schema.insert("x-codelist".to_string(), json!(codelist));
    }
    if let Some(unit) = &field.unit {
        schema.insert("x-unit".to_string(), json!(unit));
    }
    if let Some(language) = &field.language {
        schema.insert("x-language".to_string(), json!(language));
    }
    schema.insert(
        "examples".to_string(),
        Value::Array(vec![field_example_value(field)]),
    );
    Value::Object(schema)
}

/// Build a short markdown description from field metadata. There is no
/// human-authored description in the catalog, so we surface what we do
/// know: nullability, codelist URI, unit, language tag.
fn synth_field_description(field: &FieldMetadata) -> String {
    let nullability = if field.nullable {
        "Optional"
    } else {
        "Required"
    };
    let mut parts = vec![format!("{nullability} `{}` field.", field.r#type)];
    if let Some(codelist) = &field.codelist {
        parts.push(format!("Codelist: `{codelist}`."));
    }
    if let Some(unit) = &field.unit {
        parts.push(format!("Unit: `{unit}`."));
    }
    if let Some(language) = &field.language {
        parts.push(format!("Language: `{language}`."));
    }
    parts.join(" ")
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

// --- path-item builders --------------------------------------------

#[cfg(feature = "ogcapi-features")]
fn insert_ogc_paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/ogc/v1".to_string(),
        ogc_json_path_item("get_ogc_landing_page", "OGC landing page", "OgcLandingPage"),
    );
    tag(paths, "/ogc/v1", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/conformance".to_string(),
        ogc_json_path_item("get_ogc_conformance", "OGC conformance", "OgcConformance"),
    );
    tag(paths, "/ogc/v1/conformance", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/collections".to_string(),
        ogc_json_path_item(
            "list_ogc_collections",
            "List OGC collections",
            "OgcCollections",
        ),
    );
    tag(paths, "/ogc/v1/collections", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections".to_string(),
        ogc_path_item_with_params(
            "get",
            "List dataset OGC collections",
            "OgcCollections",
            "application/json",
            vec![path_parameter("dataset_id", "Dataset identifier")],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections",
        "get",
        "list_dataset_ogc_collections",
    );

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC collection",
            "OgcCollection",
            "application/json",
            vec![
                path_parameter("dataset_id", "Dataset identifier"),
                path_parameter("collection_id", "OGC collection identifier"),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
        "get",
        "get_dataset_ogc_collection",
    );

    let item_query_parameters = vec![
        path_parameter("dataset_id", "Dataset identifier"),
        path_parameter("collection_id", "OGC collection identifier"),
        query_parameter("limit", "Maximum features to return."),
        query_parameter("after", "Opaque signed pagination cursor."),
        query_parameter("bbox", "CRS84 bbox in minx,miny,maxx,maxy order."),
        query_parameter("bbox-crs", "Bbox CRS. Phase 1 accepts CRS84 only."),
        query_parameter("datetime", "Instant or closed/half-open datetime interval."),
    ];
    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items".to_string(),
        ogc_path_item_with_params(
            "get",
            "List OGC features",
            "GeoJsonFeatureCollection",
            "application/geo+json",
            item_query_parameters,
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
        "get",
        "list_dataset_ogc_features",
    );

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC feature",
            "GeoJsonFeature",
            "application/geo+json",
            vec![
                path_parameter("dataset_id", "Dataset identifier"),
                path_parameter("collection_id", "OGC collection identifier"),
                path_parameter("feature_id", "Feature identifier"),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
        "get",
        "get_dataset_ogc_feature",
    );
}

#[cfg(feature = "ogcapi-features")]
fn ogc_json_path_item(op_id: &str, summary: &str, schema: &str) -> Value {
    let mut item =
        ogc_path_item_with_params("get", summary, schema, "application/json", Vec::new());
    if let Some(op) = item.get_mut("get").and_then(Value::as_object_mut) {
        op.insert("operationId".to_string(), json!(op_id));
    }
    item
}

#[cfg(feature = "ogcapi-features")]
fn ogc_path_item_with_params(
    method: &str,
    summary: &str,
    schema: &str,
    media_type: &str,
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
                        media_type: {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                },
                "400": problem_response("Invalid OGC or spatial query parameter."),
                "401": problem_response("Missing or invalid bearer credential."),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "404": problem_response("OGC collection or feature not found."),
                "default": problem_response("Problem Details error response."),
            }
        }
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
                "401": problem_response(
                    "Missing or invalid bearer credential."
                ),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

/// Path item for routes that return JSON-LD (DCAT-AP, SHACL). These
/// share the 401/403/default error envelope but emit an inline object
/// schema for their JSON-LD body rather than a `$ref`.
fn jsonld_path_item(
    op_id: &str,
    summary: &str,
    description: &str,
    response_description: &str,
) -> Value {
    json!({
        "get": {
            "operationId": op_id,
            "summary": summary,
            "description": description,
            "responses": {
                "200": {
                    "description": response_description,
                    "content": {
                        "application/ld+json": {
                            "schema": { "type": "object" }
                        }
                    }
                },
                "401": problem_response(
                    "Missing or invalid bearer credential."
                ),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": { "$ref": "#/components/schemas/ProblemDetails" }
            }
        }
    })
}

fn entity_collection_path_item(summary: &str, schema: &str, entity: &EntityConfig) -> Value {
    let mut parameters = pagination_parameters();
    parameters.push(query_parameter(
        "fields",
        "Comma-separated list of entity fields to project. Unknown fields are rejected.",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationships to expand inline. Limited to the entity's \
             configured `allowed_expansions`.",
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
    let mut parameters = vec![path_parameter("id", "Entity primary key")];
    parameters.push(query_parameter(
        "fields",
        "Comma-separated list of entity fields to project. Unknown fields are rejected.",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationships to expand inline. Limited to the entity's \
             configured `allowed_expansions`.",
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

fn entity_verify_path_item(entity: &EntityMetadata) -> Value {
    path_item_with_params(
        "get",
        "Verify record exists",
        "VerifyResponse",
        vec![query_parameter(
            &entity.primary_key,
            "Primary key value to verify.",
        )],
    )
}

fn entity_relationship_path_item(
    dataset: &DatasetMetadata,
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
    json!({
        "get": {
            "summary": format!("Relationship: {}", relationship.name),
            "parameters": relationship_parameters(relationship.kind),
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": schema
                        }
                    }
                },
                "401": problem_response("Missing or invalid bearer credential."),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn pagination_parameters() -> Vec<Value> {
    vec![
        json!({
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": { "type": "integer", "format": "int32", "minimum": 1 },
            "description": "Maximum records to return. Capped by the entity's `api.max_limit`.",
            "examples": { "default": { "value": 10 } },
        }),
        query_parameter(
            "cursor",
            "Opaque pagination cursor returned in a prior response's `pagination.next_cursor`.",
        ),
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
                let description = filter_parameter_description(&filter.field, *op);
                query_parameter(&name, &description)
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

fn filter_parameter_description(field: &str, op: FilterOp) -> String {
    match op {
        FilterOp::Eq => format!("Filter by exact match on `{field}`."),
        FilterOp::In => {
            format!("Filter by inclusion in a comma-separated list of `{field}` values.")
        }
        FilterOp::Gte => format!("Filter where `{field}` is greater than or equal to the value."),
        FilterOp::Lte => format!("Filter where `{field}` is less than or equal to the value."),
        FilterOp::Between => {
            format!("Filter where `{field}` is within an inclusive `min,max` range.")
        }
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

/// Header parameter declaring the `Data-Purpose` requirement. Entities
/// with `api.require_purpose_header: true` reject row-data requests that
/// omit this header with `auth.purpose_required`. Surfacing it in the
/// OpenAPI document lets Scalar render a fillable field in the Try-it
/// panel and lets generated clients carry it through.
fn purpose_header_parameter() -> Value {
    json!({
        "name": "Data-Purpose",
        "in": "header",
        "required": true,
        "description": "Free-form purpose-of-use label recorded in the audit trail. \
                        Required by this entity's policy; any non-empty value is accepted.",
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

fn op_id_slug(value: &str) -> String {
    sanitize_component_part(value).to_lowercase()
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
