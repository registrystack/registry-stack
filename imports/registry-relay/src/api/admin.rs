// SPDX-License-Identifier: Apache-2.0
//! Admin HTTP routes.
//!
//! This module owns the route surface only. Server/auth integration can
//! install the router and `IngestRegistry` extension from the admin
//! listener when that wiring lands.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::json;

use crate::audit::ErrorCodeExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{DatasetId, ResourceId};
use crate::error::{AdminError, AuthError, Error, IngestError};
use crate::ingest::IngestRegistry;

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RELOAD_UNAVAILABLE_CODE: &str = "admin.reload_unavailable";

/// Sub-router for admin reload routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/reload", post(reload_all))
        .route(
            "/admin/datasets/{dataset_id}/tables/{table_id}/reload",
            post(reload_table),
        )
}

#[derive(Debug, Deserialize)]
struct ReloadTablePath {
    dataset_id: DatasetId,
    table_id: ResourceId,
}

async fn reload_table(
    Path(path): Path<ReloadTablePath>,
    registry: Option<Extension<Arc<IngestRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(registry)) = registry else {
        return reload_unavailable(
            "admin table reload route matched, but ingest registry is not installed",
        );
    };
    if let Err(error) = require_admin_scope(principal) {
        return error.into_response();
    }

    match registry.reload(&path.dataset_id, &path.table_id).await {
        Ok(()) => Json(json!({
            "status": "ok",
            "dataset_id": path.dataset_id.as_str(),
            "table_id": path.table_id.as_str(),
        }))
        .into_response(),
        Err(IngestError::SourceNotFound) => {
            Error::from(AdminError::UnknownResource).into_response()
        }
        Err(_) => Error::from(AdminError::ReloadFailed).into_response(),
    }
}

async fn reload_all() -> Response {
    reload_unavailable("admin reload-all route matched, but registry-wide reload is not available")
}

fn require_admin_scope(principal: Option<Extension<Principal>>) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, "admin")
}

fn reload_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/admin/reload_unavailable",
            "title": "Admin reload unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": RELOAD_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(RELOAD_UNAVAILABLE_CODE.to_string()));
    response
}
