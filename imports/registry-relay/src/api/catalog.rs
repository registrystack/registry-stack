// SPDX-License-Identifier: Apache-2.0
//! Catalog and entity-grain metadata routes.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::audit::ErrorCodeExt;
use crate::auth::Principal;
use crate::config::Config;
use crate::entity::EntityRegistry;
use crate::error::{AuthError, Error};
use crate::metadata;

const JSON_LD: HeaderValue = HeaderValue::from_static("application/ld+json");
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const METADATA_UNAVAILABLE_CODE: &str = "catalog.metadata_unavailable";

/// Sub-router for catalog metadata routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/catalog", get(catalog))
        .route("/catalog/dcat-ap.jsonld", get(dcat_ap))
}

async fn catalog(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = metadata_state(config, registry) else {
        return metadata_unavailable("catalog route matched, but metadata state is not installed");
    };
    let visible_entity_ids = match visible_metadata_entity_ids(&config, principal) {
        Ok(entity_ids) => entity_ids,
        Err(error) => return error.into_response(),
    };

    json_response(
        metadata::catalog::catalog_document_for_entity_ids(&config, &registry, &visible_entity_ids),
        &headers,
    )
}

async fn dcat_ap(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = metadata_state(config, registry) else {
        return metadata_unavailable(
            "DCAT-AP catalog route matched, but metadata state is not installed",
        );
    };
    let visible_entity_ids = match visible_metadata_entity_ids(&config, principal) {
        Ok(entity_ids) => entity_ids,
        Err(error) => return error.into_response(),
    };

    json_ld_response(
        metadata::dcat_ap_document_for_entity_ids(&config, &registry, &visible_entity_ids),
        &headers,
    )
}

fn metadata_state(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn json_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    let etag = catalog_etag(&value);
    if if_none_match_matches(headers, &etag) {
        return not_modified_response(&etag);
    }
    with_etag(Json(value).into_response(), &etag)
}

fn json_ld_response<T>(value: T, headers: &HeaderMap) -> Response
where
    T: Serialize,
{
    let etag = catalog_etag(&value);
    if if_none_match_matches(headers, &etag) {
        return not_modified_response(&etag);
    }
    let mut response = Json(value).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, JSON_LD);
    with_etag(response, &etag)
}

fn catalog_etag<T>(value: &T) -> String
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).expect("catalog metadata serializes");
    let mut hasher = Sha256::new();
    hasher.update(b"catalog:");
    hasher.update(bytes);
    format!(r#""sha256:{}""#, hex_lower(&hasher.finalize()))
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("catalog_etag returns a valid header value"),
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

fn metadata_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/catalog/metadata_unavailable",
            "title": "Catalog metadata unavailable",
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
        .extensions_mut()
        .insert(ErrorCodeExt(METADATA_UNAVAILABLE_CODE.to_string()));
    response
}
