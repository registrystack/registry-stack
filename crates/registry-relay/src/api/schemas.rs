// SPDX-License-Identifier: Apache-2.0
//! Public, unauthenticated `/schemas/{type}/{version}` route.
//!
//! Returns the JSON Schema bytes for a provenance claim type. The wire
//! contract is stable: once a schema is published it never mutates;
//! adding a v2 means a new path and a new in-tree file. The byte
//! source is `crate::provenance::resources`.
//!
//! Caching headers (`Cache-Control: public, max-age=86400`) are set so
//! consumers can cache the document. Schema URLs are stable for a given
//! version.
//!
//! These resources are public verification artefacts, so the handler
//! emits `Access-Control-Allow-Origin: *` directly rather than relying
//! on the gateway's default-deny application CORS policy.

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::error::{Error, ProvenanceError};
use crate::provenance::resources;

const APPLICATION_SCHEMA_JSON: HeaderValue = HeaderValue::from_static("application/schema+json");
const CACHE_CONTROL_24H: HeaderValue = HeaderValue::from_static("public, max-age=86400");

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/schemas/{claim_type}/{version}", get(serve_schema))
}

#[derive(Debug, Deserialize)]
struct SchemaPath {
    claim_type: String,
    version: String,
}

async fn serve_schema(Path(path): Path<SchemaPath>) -> Response {
    match resources::lookup_schema(&path.claim_type, &path.version) {
        Some(bytes) => build_resource_response(bytes, APPLICATION_SCHEMA_JSON),
        None => Error::from(ProvenanceError::UnknownResource).into_response(),
    }
}

fn build_resource_response(bytes: &'static [u8], content_type: HeaderValue) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(header::CACHE_CONTROL, CACHE_CONTROL_24H);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    (StatusCode::OK, headers, bytes).into_response()
}
