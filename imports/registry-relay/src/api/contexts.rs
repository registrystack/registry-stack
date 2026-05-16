// SPDX-License-Identifier: Apache-2.0
//! Public, unauthenticated `/contexts/{vocab}/{version}` route.
//!
//! Serves the JSON-LD 1.1 context documents for the Wave 3 vocabulary
//! and the vendored W3C VC 2.0 context. Bytes are pulled from
//! `crate::provenance::resources` and hash-pinned in
//! `resources/MANIFEST.toml`.
//!
//! Once published, contexts never mutate; a v2 context lands at a new
//! URL. The W3C VC v2 context is vendored alongside our own so a
//! verifier offline from the W3C host still has the required @context
//! entries.

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::error::{Error, ProvenanceError};
use crate::provenance::resources;

const APPLICATION_LD_JSON: HeaderValue = HeaderValue::from_static("application/ld+json");
const CACHE_CONTROL_24H: HeaderValue = HeaderValue::from_static("public, max-age=86400");

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/contexts/{vocab}/{version}", get(serve_context))
}

#[derive(Debug, Deserialize)]
struct ContextPath {
    vocab: String,
    version: String,
}

async fn serve_context(Path(path): Path<ContextPath>) -> Response {
    match resources::lookup_context(&path.vocab, &path.version) {
        Some(bytes) => build_context_response(bytes),
        None => Error::from(ProvenanceError::UnknownResource).into_response(),
    }
}

fn build_context_response(bytes: &'static [u8]) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, APPLICATION_LD_JSON);
    headers.insert(header::CACHE_CONTROL, CACHE_CONTROL_24H);
    (StatusCode::OK, headers, bytes).into_response()
}
