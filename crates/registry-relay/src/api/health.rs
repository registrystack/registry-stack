// SPDX-License-Identifier: Apache-2.0
//! `/healthz` and `/ready` handlers.
//!
//! Both endpoints are unauthenticated; load balancers, container
//! orchestrators, and uptime probes hit them without credentials. The
//! paths match the public API shape documented in the README.
//!
//! ## Semantics
//!
//! * `/healthz` reports process liveness only. It does not consult any
//!   dependency state and always returns 200.
//! * `/ready` reports ingest readiness when a readiness watch receiver
//!   is installed. Without that extension, it returns a trivial 200 for
//!   tests that only exercise the HTTP shell.

use axum::http::{header, StatusCode};
use axum::response::Json;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};

use crate::runtime_config::RuntimeSnapshot;

/// Sub-router carrying both `/healthz` and `/ready`. Returned to
/// `server::build_app` so it can mount this set on the main router
/// *outside* the auth layer.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/healthz", get(health))
        .route("/ready", get(ready))
}

/// Liveness probe. Always 200 with a small JSON body once the process
/// is up enough to accept connections.
async fn health() -> Json<Value> {
    Json(ok_health_body(1, 1, 0))
}

/// Readiness probe. With a runtime readiness receiver installed,
/// returns 200 only when every configured resource has ingested and no
/// declared deployment gate demands `readiness_fail`. When no runtime is
/// installed, it returns a trivial ready response.
async fn ready(runtime: RuntimeSnapshot) -> Response {
    // Deployment gates evaluated at `readiness_fail` keep the process running
    // but report not-ready. This is checked first so that adopting a profile
    // surfaces a posture problem even before ingest state is consulted.
    if let Some(config) = runtime.config() {
        let source = runtime
            .config_provenance()
            .map(|provenance| provenance.source)
            .unwrap_or(registry_platform_ops::ConfigSource::LocalFile);
        let facts = crate::deployment::facts_from_config(&config, source);
        let waivers = crate::deployment::waivers_from_config(&config);
        let evaluation = crate::deployment::evaluate(
            config.deployment.profile,
            &facts,
            &waivers,
            &crate::deployment::today_utc(),
        );
        if evaluation.has_readiness_failure() {
            return deployment_not_ready_response();
        }
    }

    // A retained audit chain that failed startup verification means every
    // audited request fails closed; report not-ready so the brick is visible on
    // /ready rather than only as per-request 503s behind a green healthcheck
    // (#196). Recover with `registry-relay audit quarantine`.
    if let Some(audit) = runtime.audit_sink() {
        if !audit.chain_healthy() {
            return audit_chain_not_ready_response();
        }
    }

    let Some(readiness) = runtime.readiness_rx() else {
        return Json(ok_health_body(1, 1, 0)).into_response();
    };

    let snapshot = readiness.borrow().clone();
    if snapshot.fully_ready() {
        let ready_count = snapshot.ready.len();
        return Json(ok_health_body(ready_count, ready_count, 0)).into_response();
    }

    let failed_count = snapshot.failed.len();
    let not_ready_count = snapshot.not_ready.len();
    let unresolved_count = snapshot.unresolved_entities.len();

    let body = Json(json!({
        "type": format!("{}schema/resource_unavailable", crate::error::PROBLEM_TYPE_BASE),
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

/// 503 problem response raised when the retained audit chain failed startup
/// verification and requires operator recovery (#196). The recovery path is
/// `registry-relay audit quarantine`.
fn audit_chain_not_ready_response() -> Response {
    let body = Json(json!({
        "type": format!("{}audit/chain_inconsistent", crate::error::PROBLEM_TYPE_BASE),
        "title": "Audit chain inconsistent",
        "status": 503,
        "detail": "the retained audit chain failed startup verification and requires operator recovery",
        "code": crate::audit::AUDIT_CHAIN_INCONSISTENT_CODE,
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

/// 503 problem response raised when one or more declared deployment gates
/// evaluate to `readiness_fail`. Detailed gate findings stay on authenticated
/// admin posture surfaces; this public probe only reports aggregate status.
fn deployment_not_ready_response() -> Response {
    let body = Json(json!({
        "type": format!("{}deployment/not_ready", crate::error::PROBLEM_TYPE_BASE),
        "title": "Deployment not ready",
        "status": 503,
        "detail": "one or more declared deployment profile gates report not-ready",
        "code": "deployment.not_ready",
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

fn ok_health_body(total: usize, ok: usize, failed: usize) -> Value {
    json!({
        "status": "ok",
        "checks": {
            "total": total,
            "ok": ok,
            "failed": failed,
        },
    })
}
