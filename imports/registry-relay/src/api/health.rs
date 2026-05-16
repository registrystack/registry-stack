// SPDX-License-Identifier: Apache-2.0
//! `/health` and `/ready` handlers.
//!
//! Both endpoints are unauthenticated; load balancers, container
//! orchestrators, and uptime probes hit them without credentials. The
//! paths match Spec.md Section 7.
//!
//! ## Semantics
//!
//! * `/health` reports process liveness only. It does not consult any
//!   dependency state and always returns 200. This matches Spec.md
//!   Section 7: "`/health` checks process liveness only".
//! * `/ready` reports ingest readiness when a readiness watch receiver
//!   is installed. Without that extension, it returns a trivial 200 for
//!   tests that only exercise the HTTP shell.

use axum::http::{header, StatusCode};
use axum::response::Json;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::ingest::ReadinessSnapshot;

/// Sub-router carrying both `/health` and `/ready`. Returned to
/// `server::build_app` so it can mount this set on the main router
/// *outside* the auth layer.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// Liveness probe. Always 200 with a small JSON body once the process
/// is up enough to accept connections.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness probe. With a readiness receiver installed,
/// returns 200 only when every configured resource has ingested. When
/// no receiver is installed, it returns a trivial ready response.
async fn ready(readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>) -> Response {
    let Some(Extension(readiness)) = readiness else {
        return Json(json!({ "status": "ok" })).into_response();
    };

    let snapshot = readiness.borrow().clone();
    if snapshot.fully_ready() {
        return Json(json!({
            "status": "ok",
            "resources": snapshot
                .ready
                .iter()
                .map(|((dataset_id, resource_id), entry)| json!({
                    "dataset_id": dataset_id.as_str(),
                    "resource_id": resource_id.as_str(),
                    "ingest_ulid": entry.ingest_ulid.to_string(),
                }))
                .collect::<Vec<_>>()
        }))
        .into_response();
    }

    let failed_count = snapshot.failed.len();
    let not_ready_count = snapshot.not_ready.len();
    let unresolved_count = snapshot.unresolved_entities.len();

    let body = Json(json!({
        "type": "https://data.example.gov/problems/schema/resource_unavailable",
        "title": "Resource unavailable",
        "status": 503,
        "detail": "one or more configured resources failed ingest, are not ready, or have unresolved entity mappings",
        "code": "schema.resource_unavailable",
        "failed_count": failed_count,
        "not_ready_count": not_ready_count,
        "unresolved_count": unresolved_count,
    }));
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json"
            .parse()
            .expect("static content type is valid"),
    );
    response
}
