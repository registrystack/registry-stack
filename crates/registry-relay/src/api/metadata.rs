// SPDX-License-Identifier: Apache-2.0
//! Standard-facing metadata routes backed by `registry-manifest-core`.

use std::collections::BTreeSet;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use registry_manifest_core as metadata_core;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::Principal;
use crate::config::Config;
use crate::error::{AuthError, Error, SchemaError};
use crate::metadata::scoped_compiled_from_runtime;
use crate::metadata::shacl::dcat_ap_document_for_metadata_scopes;
use crate::runtime_config::RuntimeSnapshot;

const JSON_LD: HeaderValue = HeaderValue::from_static("application/ld+json");
const LINKSET_JSON: HeaderValue = HeaderValue::from_static(
    "application/linkset+json; profile=\"https://www.rfc-editor.org/info/rfc9727\"",
);
const API_CATALOG_LINK: HeaderValue = HeaderValue::from_static(
    "</.well-known/api-catalog>; rel=\"api-catalog\"; type=\"application/linkset+json\"; profile=\"https://www.rfc-editor.org/info/rfc9727\"",
);
const JSON_SCHEMA: HeaderValue = HeaderValue::from_static("application/schema+json");
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const METADATA_UNAVAILABLE_CODE: &str = "metadata.core_unavailable";

/// Public RFC 9727 API catalog discovery route.
///
/// `GET`/`HEAD /.well-known/api-catalog` returns a fixed linkset of
/// relative hrefs. The handlers are fully static: they take no
/// [`Principal`], read no runtime state, and reveal nothing scoped to a
/// caller, so the route is mounted on the public (auth-exempt)
/// sub-router in [`crate::server::build_app`]. If either
/// handler ever becomes dynamic (per-principal links, runtime state), its
/// route placement must move back behind auth.
pub fn well_known_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        "/.well-known/api-catalog",
        get(api_catalog).head(api_catalog_head),
    )
}

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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(
        json!({
            "links": [
                { "rel": "self", "href": "/metadata" },
                { "rel": "api-catalog", "href": "/.well-known/api-catalog", "type": "application/linkset+json" },
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

/// RFC 9727 API catalog linkset.
///
/// The body is a fixed linkset of relative hrefs with no principal input
/// and no runtime state, which is why it is served publicly (see
/// [`well_known_router`]). Keep it static: if it ever needs a
/// [`Principal`] or runtime snapshot, move the route back behind auth.
async fn api_catalog(headers: HeaderMap) -> Response {
    let mut response = typed_json_response(
        json!({
            "linkset": [
                {
                    "anchor": "/.well-known/api-catalog",
                    "describedby": [
                        {
                            "href": "/metadata",
                            "type": "application/json",
                            "title": "Registry Relay metadata landing document"
                        }
                    ],
                    "item": [
                        {
                            "href": "/openapi.json",
                            "type": "application/vnd.oai.openapi+json;version=3.1",
                            "title": "Registry Relay OpenAPI description"
                        },
                        {
                            "href": "/metadata/catalog",
                            "type": "application/json",
                            "title": "Registry metadata catalog"
                        },
                        {
                            "href": "/metadata/dcat",
                            "type": "application/ld+json",
                            "profile": "http://www.w3.org/ns/dcat#",
                            "title": "Base DCAT catalog"
                        },
                        {
                            "href": "/metadata/dcat/bregdcat-ap",
                            "type": "application/ld+json",
                            "profile": "https://semiceu.github.io/BRegDCAT-AP/",
                            "title": "BRegDCAT-AP catalog"
                        },
                        {
                            "href": "/metadata/evidence-offerings",
                            "type": "application/json",
                            "title": "Evidence offerings"
                        },
                        {
                            "href": "/metadata/policies",
                            "type": "application/ld+json",
                            "title": "Policy metadata"
                        },
                        {
                            "href": "/metadata/shacl",
                            "type": "application/ld+json",
                            "title": "SHACL shapes"
                        }
                    ]
                }
            ]
        }),
        &headers,
        LINKSET_JSON,
    );
    response
        .headers_mut()
        .insert(header::LINK, API_CATALOG_LINK);
    response
}

async fn api_catalog_head() -> Response {
    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, LINKSET_JSON);
    response
        .headers_mut()
        .insert(header::LINK, API_CATALOG_LINK);
    response
}

async fn catalog(
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(metadata_core::render_catalog(&compiled), &headers)
}

async fn evidence_offerings(
    Query(filters): Query<EvidenceOfferingFilters>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if runtime.compiled_metadata().is_some() {
        let compiled = match scoped_metadata(runtime, principal) {
            Ok(compiled) => compiled,
            Err(response) => return *response,
        };
        let Some(document) = metadata_core::render_dcat_profile(&compiled, "dcat") else {
            return Error::from(SchemaError::UnknownResource).into_response();
        };
        return json_ld_response(document, &headers);
    }

    let Some(config) = runtime.config() else {
        return metadata_unavailable("metadata route matched, but config state is not installed");
    };
    let Some(registry) = runtime.entity_registry() else {
        return metadata_unavailable(
            "metadata route matched, but entity registry state is not installed",
        );
    };
    let scopes = match visible_metadata_scopes(&config, principal) {
        Ok(scopes) => scopes,
        Err(error) => return error.into_response(),
    };
    json_ld_response(
        dcat_ap_document_for_metadata_scopes(&config, &registry, &scopes),
        &headers,
    )
}

async fn dcat_profile(
    Path(profile): Path<String>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_ld_response(metadata_core::render_shacl(&compiled), &headers)
}

async fn policies(
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_ld_response(metadata_core::render_policy_collection(&compiled), &headers)
}

async fn entity_schema(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    private_typed_json_response(document, &headers, JSON_SCHEMA)
}

async fn entity_shacl(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    json_response(metadata_core::render_ogc_records_items(&compiled), &headers)
}

async fn ogc_record_item(
    Path(record_id): Path<String>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let compiled = match scoped_metadata(runtime, principal) {
        Ok(compiled) => compiled,
        Err(response) => return *response,
    };
    let Some(record) = metadata_core::render_ogc_records_item(&compiled, &record_id) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    json_response(record, &headers)
}

fn scoped_metadata(
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Result<metadata_core::CompiledMetadata, Box<Response>> {
    let Some(config) = runtime.config() else {
        return Err(Box::new(metadata_unavailable(
            "metadata route matched, but config state is not installed",
        )));
    };
    let Some(registry) = runtime.entity_registry() else {
        return Err(Box::new(metadata_unavailable(
            "metadata route matched, but entity registry state is not installed",
        )));
    };
    let visible_entity_ids = visible_metadata_entity_ids(&config, principal)
        .map_err(|error| Box::new(error.into_response()))?;
    if let Some(compiled) = runtime.compiled_metadata() {
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

fn visible_metadata_scopes(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<BTreeSet<String>, Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    let has_visible_metadata = config.datasets.iter().any(|dataset| {
        let has_visible_entity = dataset
            .entities
            .iter()
            .any(|entity| principal.scopes.contains(&entity.access.metadata_scope));
        let default_metadata_scope = format!("{}:metadata", dataset.id);
        let has_visible_aggregate = dataset.aggregates.iter().any(|aggregate| {
            let scope = aggregate
                .access
                .as_ref()
                .and_then(|access| access.metadata_scope.as_deref())
                .unwrap_or(default_metadata_scope.as_str());
            principal.scopes.contains(scope)
        });
        has_visible_entity || has_visible_aggregate
    });
    if !has_visible_metadata {
        return Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity or aggregate".to_string(),
        }
        .into());
    }
    Ok(principal
        .scopes
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>())
}

fn json_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    private_typed_json_response(value, headers, HeaderValue::from_static("application/json"))
}

fn private_metadata_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    json_response(value, headers)
}

fn json_ld_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    private_typed_json_response(value, headers, JSON_LD)
}

fn private_typed_json_response<T>(
    value: T,
    headers: &HeaderMap,
    content_type: HeaderValue,
) -> Response
where
    T: Serialize,
{
    let response = typed_json_response(value, headers, content_type);
    with_private_metadata_headers(response)
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
    with_private_metadata_headers(with_etag(StatusCode::NOT_MODIFIED.into_response(), etag))
}

fn with_private_metadata_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Authorization"));
    response
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
            "type": format!("{}metadata/core_unavailable", crate::error::PROBLEM_TYPE_BASE),
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
            "type": format!("{}offering/not_found", crate::error::PROBLEM_TYPE_BASE),
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
