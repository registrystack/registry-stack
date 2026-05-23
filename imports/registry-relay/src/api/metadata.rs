// SPDX-License-Identifier: Apache-2.0
//! Standard-facing metadata routes backed by `registry-manifest-core`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use registry_manifest_core as metadata_core;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::Config;
use crate::entity::EntityRegistry;
use crate::error::{AuthError, Error, SchemaError};
use crate::metadata::scoped_compiled_from_runtime;

const JSON_LD: HeaderValue = HeaderValue::from_static("application/ld+json");
const JSON_SCHEMA: HeaderValue = HeaderValue::from_static("application/schema+json");
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const METADATA_UNAVAILABLE_CODE: &str = "metadata.core_unavailable";

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/metadata", get(metadata_landing))
        .route("/metadata/catalog", get(catalog))
        .route("/metadata/evidence-offerings", get(evidence_offerings))
        .route(
            "/metadata/evidence-offerings/{offering_id}",
            get(evidence_offering),
        )
        .route("/metadata/dcat", get(dcat))
        .route("/metadata/dcat/{profile}", get(dcat_profile))
        .route("/metadata/shacl", get(shacl))
        .route("/metadata/policies", get(policies))
        .route("/metadata/profiles", get(profiles))
        .route("/metadata/profiles/{profile}", get(profile))
        .route("/metadata/datasets", get(datasets))
        .route("/metadata/datasets/{dataset_id}", get(dataset))
        .route(
            "/metadata/datasets/{dataset_id}/policy",
            get(dataset_policy),
        )
        .route(
            "/metadata/datasets/{dataset_id}/entities",
            get(dataset_entities),
        )
        .route(
            "/metadata/datasets/{dataset_id}/entities/{entity}",
            get(dataset_entity),
        )
        .route(
            "/metadata/schema/{dataset_id}/{entity}/schema.json",
            get(entity_schema),
        )
        .route(
            "/metadata/datasets/{dataset_id}/entities/{entity}/schema",
            get(entity_schema),
        )
        .route(
            "/metadata/datasets/{dataset_id}/entities/{entity}/shacl",
            get(entity_shacl),
        )
        .route("/metadata/ogc/records", get(ogc_records))
        .route("/metadata/ogc/records/{record_id}", get(ogc_record_item))
}

#[derive(Debug, serde::Deserialize)]
struct EntityPath {
    dataset_id: String,
    entity: String,
}

#[derive(Debug, serde::Deserialize)]
struct DatasetPath {
    dataset_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct EvidenceOfferingPath {
    offering_id: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct EvidenceOfferingFilters {
    evidence_type: Option<String>,
    country: Option<String>,
    procedure_context: Option<String>,
}

impl EvidenceOfferingFilters {
    fn matches(&self, offering: &metadata_core::CompiledEvidenceOffering) -> bool {
        if self.evidence_type.as_deref().is_some_and(|expected| {
            expected != offering.evidence_type && expected != offering.evidence_type_iri
        }) {
            return false;
        }
        if self.country.as_deref().is_some_and(|expected| {
            offering.issuing_authority.country.as_deref() != Some(expected)
                && offering
                    .jurisdiction
                    .as_ref()
                    .and_then(|jurisdiction| jurisdiction.country.as_deref())
                    != Some(expected)
        }) {
            return false;
        }
        if self.procedure_context.as_deref().is_some_and(|expected| {
            !offering
                .procedure_contexts
                .iter()
                .any(|iri| iri == expected)
        }) {
            return false;
        }
        true
    }
}

async fn metadata_landing(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(
        json!({
            "links": [
                { "rel": "self", "href": "/metadata" },
                { "rel": "describedby", "href": "/metadata/catalog", "type": "application/json" },
                { "rel": "alternate", "href": "/metadata/dcat", "type": "application/ld+json" },
                { "rel": "alternate", "href": "/metadata/dcat/bregdcat-ap", "type": "application/ld+json" },
                { "rel": "describedby", "href": "/metadata/shacl", "type": "application/ld+json" },
                { "rel": "describedby", "href": "/metadata/policies", "type": "application/ld+json" },
            ],
            "catalog": metadata_core::render_catalog(&compiled),
        }),
        &headers,
    )
}

async fn catalog(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(metadata_core::render_catalog(&compiled), &headers)
}

async fn evidence_offerings(
    Query(filters): Query<EvidenceOfferingFilters>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let evidence_offerings = compiled
        .evidence_offerings()
        .filter(|offering| filters.matches(offering))
        .collect::<Vec<_>>();
    private_metadata_response(
        json!({ "evidence_offerings": evidence_offerings }),
        &headers,
    )
}

async fn evidence_offering(
    Path(path): Path<EvidenceOfferingPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) if response.status() == StatusCode::FORBIDDEN => return offering_not_found(),
        Err(response) => return *response,
    };
    let Some(document) = metadata_core::render_evidence_offering(&compiled, &path.offering_id)
    else {
        return offering_not_found();
    };
    private_metadata_response(document, &headers)
}

async fn dcat(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_ld_response(metadata_core::render_base_dcat(&compiled), &headers)
}

async fn dcat_profile(
    Path(profile): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(document) = metadata_core::render_dcat_profile(&compiled, &profile) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_ld_response(document, &headers)
}

async fn shacl(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_ld_response(metadata_core::render_shacl(&compiled), &headers)
}

async fn policies(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_ld_response(metadata_core::render_policy_collection(&compiled), &headers)
}

async fn entity_schema(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(document) = metadata_core::render_entity_schema_draft_2020_12(
        &compiled,
        &path.dataset_id,
        &path.entity,
    ) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    typed_json_response(document, &headers, JSON_SCHEMA)
}

async fn entity_shacl(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(document) =
        metadata_core::render_entity_shacl(&compiled, &path.dataset_id, &path.entity)
    else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_ld_response(document, &headers)
}

async fn profiles(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(
        json!({
            "application_profiles": compiled.catalog().application_profiles,
            "profiles": compiled.profiles(),
        }),
        &headers,
    )
}

async fn profile(
    Path(profile): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(profile) = compiled
        .catalog()
        .application_profiles
        .iter()
        .find(|candidate| candidate.id == profile)
    else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_response(profile, &headers)
}

async fn datasets(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(
        json!({
            "datasets": compiled.datasets().collect::<Vec<_>>(),
        }),
        &headers,
    )
}

async fn dataset(
    Path(path): Path<DatasetPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(dataset) = compiled.dataset(&path.dataset_id) else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };
    json_response(dataset, &headers)
}

async fn dataset_policy(
    Path(path): Path<DatasetPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(document) = metadata_core::render_dataset_policy_document(&compiled, &path.dataset_id)
    else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };
    json_ld_response(document, &headers)
}

async fn dataset_entities(
    Path(path): Path<DatasetPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(dataset) = compiled.dataset(&path.dataset_id) else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };
    json_response(
        json!({
            "dataset_id": dataset.dataset_id,
            "entities": dataset.entities.values().collect::<Vec<_>>(),
        }),
        &headers,
    )
}

async fn dataset_entity(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(dataset) = compiled.dataset(&path.dataset_id) else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };
    let Some(entity) = dataset.entities.get(&path.entity) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_response(entity, &headers)
}

async fn ogc_records(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(metadata_core::render_ogc_records_items(&compiled), &headers)
}

async fn ogc_record_item(
    Path(record_id): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(config, registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(record) = metadata_core::render_ogc_records_item(&compiled, &record_id) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_response(record, &headers)
}

fn scoped_metadata(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Result<metadata_core::CompiledMetadata, Box<Response>> {
    let Some(Extension(config)) = config else {
        return Err(Box::new(metadata_unavailable(
            "metadata route matched, but config state is not installed",
        )));
    };
    let Some(Extension(registry)) = registry else {
        return Err(Box::new(metadata_unavailable(
            "metadata route matched, but entity registry state is not installed",
        )));
    };
    let visible_entity_ids = visible_metadata_entity_ids(&config, principal)
        .map_err(|error| Box::new(error.into_response()))?;
    if let Some(Extension(compiled)) = compiled_metadata {
        return Ok(compiled.filter(|dataset, entity| {
            visible_entity_ids.contains(&(dataset.dataset_id.clone(), entity.name.clone()))
        }));
    }
    scoped_compiled_from_runtime(&config, &registry, &visible_entity_ids).map_err(|_error| {
        Box::new(metadata_unavailable(
            "metadata manifest could not be compiled",
        ))
    })
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

#[allow(dead_code)]
fn require_principal_scope(
    principal: Option<Extension<Principal>>,
    required: &str,
) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, required)
}

fn json_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    typed_json_response(value, headers, HeaderValue::from_static("application/json"))
}

fn private_metadata_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    let mut response = json_response(value, headers);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("private"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Authorization"));
    response
}

fn json_ld_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    typed_json_response(value, headers, JSON_LD)
}

fn typed_json_response<T>(value: T, headers: &HeaderMap, content_type: HeaderValue) -> Response
where
    T: Serialize,
{
    let etag = metadata_etag(&value);
    if if_none_match_matches(headers, &etag) {
        return not_modified_response(&etag);
    }
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    with_etag(response, &etag)
}

fn metadata_etag<T>(value: &T) -> String
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).expect("metadata serializes");
    let mut hasher = Sha256::new();
    hasher.update(b"metadata:");
    hasher.update(bytes);
    format!(r#""sha256:{}""#, hex_lower(&hasher.finalize()))
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("metadata_etag returns a valid header value"),
    );
    response
}

fn not_modified_response(etag: &str) -> Response {
    with_etag(StatusCode::NOT_MODIFIED.into_response(), etag)
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*"
                || candidate == etag
                || candidate
                    .strip_prefix("W/")
                    .is_some_and(|weak_candidate| weak_candidate == etag)
        })
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

fn metadata_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/metadata/core_unavailable",
            "title": "Metadata unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": METADATA_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
}

fn offering_not_found() -> Response {
    let mut response = (
        StatusCode::NOT_FOUND,
        Json(json!({
            "type": "https://data.example.gov/problems/offering/not_found",
            "title": "Evidence offering not found",
            "status": StatusCode::NOT_FOUND.as_u16(),
            "detail": "Evidence offering not found or not visible to the caller.",
            "code": "offering.not_found",
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
}
