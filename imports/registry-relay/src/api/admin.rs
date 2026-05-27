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
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::watch;

use crate::audit::ErrorCodeExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{DatasetId, ResourceId};
use crate::error::{AdminError, AuthError, Error, IngestError};
use crate::ingest::{IngestRegistry, ReadinessSnapshot};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RELOAD_FAILED_CODE: &str = "admin.reload_failed";
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
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
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

    let result = registry.reload(&path.dataset_id, &path.table_id).await;
    publish_readiness(readiness_tx, &registry);

    match result {
        Ok(()) => Json(json!({
            "status": "ok",
            "counts": {
                "reloaded": 1,
            },
        }))
        .into_response(),
        Err(IngestError::SourceNotFound) => {
            Error::from(AdminError::UnknownResource).into_response()
        }
        Err(_) => Error::from(AdminError::ReloadFailed).into_response(),
    }
}

async fn reload_all(
    registry: Option<Extension<Arc<IngestRegistry>>>,
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_admin_scope(principal) {
        return error.into_response();
    }
    let Some(Extension(registry)) = registry else {
        return reload_unavailable(
            "admin reload-all route matched, but ingest registry is not installed",
        );
    };

    let report = registry.reload_all().await;
    publish_readiness(readiness_tx, &registry);
    let status = if report.failed == 0 { "ok" } else { "failed" };
    let http_status = if report.failed == 0 {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mut response = (
        http_status,
        Json(ReloadAllResponse {
            status,
            counts: ReloadAllCounts {
                total: report.total,
                succeeded: report.succeeded,
                failed: report.failed,
            },
        }),
    )
        .into_response();
    if http_status.is_server_error() {
        response
            .extensions_mut()
            .insert(ErrorCodeExt(RELOAD_FAILED_CODE.to_string()));
    }
    response
}

fn publish_readiness(
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
    registry: &IngestRegistry,
) {
    if let Some(Extension(readiness_tx)) = readiness_tx {
        let _ = readiness_tx.send(registry.snapshot());
    }
}

fn require_admin_scope(principal: Option<Extension<Principal>>) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, "admin")
}

#[derive(Debug, Serialize)]
struct ReloadAllResponse {
    status: &'static str,
    counts: ReloadAllCounts,
}

#[derive(Debug, Serialize)]
struct ReloadAllCounts {
    total: usize,
    succeeded: usize,
    failed: usize,
}

fn reload_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": format!("{}admin/reload_unavailable", crate::error::PROBLEM_TYPE_BASE),
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
