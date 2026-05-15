// SPDX-License-Identifier: Apache-2.0
//! `/health` and `/ready` handlers.
//!
//! Both endpoints are unauthenticated; load balancers, container
//! orchestrators, and uptime probes hit them without credentials. The
//! paths match Spec.md Section 7 and `decisions/wave-0.md` Section 8.
//!
//! ## Semantics
//!
//! * `/health` reports process liveness only. It does not consult any
//!   dependency state and always returns 200. This matches Spec.md
//!   Section 7: "`/health` checks process liveness only".
//! * `/ready` reports ingest readiness when a Wave 1 readiness watch
//!   receiver is installed. Without that extension, it keeps Wave 0's
//!   trivial 200 behavior for tests that only exercise the HTTP shell.

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

/// Readiness probe. With a Wave 1 readiness receiver installed,
/// returns 200 only when every configured resource has ingested. When
/// no receiver is installed, it keeps Wave 0's trivial ready response.
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
                .map(|((dataset_id, resource_id), ingest_ulid)| json!({
                    "dataset_id": dataset_id.as_str(),
                    "resource_id": resource_id.as_str(),
                    "ingest_ulid": ingest_ulid.to_string(),
                }))
                .collect::<Vec<_>>()
        }))
        .into_response();
    }

    let failed_resources = snapshot
        .failed
        .iter()
        .map(|((dataset_id, resource_id), code)| {
            json!({
                "dataset_id": dataset_id.as_str(),
                "resource_id": resource_id.as_str(),
                "code": code,
            })
        })
        .collect::<Vec<_>>();
    let not_ready_resources = snapshot
        .not_ready
        .iter()
        .map(|(dataset_id, resource_id)| {
            json!({
                "dataset_id": dataset_id.as_str(),
                "resource_id": resource_id.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let unresolved_entities = snapshot
        .unresolved_entities
        .iter()
        .map(|(dataset_id, entity_name)| {
            json!({
                "dataset_id": dataset_id.as_str(),
                "entity": entity_name,
            })
        })
        .collect::<Vec<_>>();

    let body = Json(json!({
        "type": "https://data.example.gov/problems/schema/resource_unavailable",
        "title": "Resource unavailable",
        "status": 503,
        "detail": "one or more configured resources failed ingest, are not ready, or have unresolved entity mappings",
        "code": "schema.resource_unavailable",
        "failed_resources": failed_resources,
        "not_ready_resources": not_ready_resources,
        "unresolved_entities": unresolved_entities,
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
