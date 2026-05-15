// SPDX-License-Identifier: Apache-2.0
//! `/health` and `/ready` handlers.
//!
//! Both endpoints are unauthenticated; load balancers, container
//! orchestrators, and uptime probes hit them without credentials. The
//! paths match Spec.md Section 7 and `decisions/wave-0.md` Section 8.
//!
//! ## Semantics (Wave 0)
//!
//! * `/health` reports process liveness only. It does not consult any
//!   dependency state and always returns 200. This matches Spec.md
//!   Section 7: "`/health` checks process liveness only".
//! * `/ready` reports startup completion. Wave 0's readiness check is
//!   trivial: once `server::build_app` returns, the process is ready
//!   to serve. The dataset-gated readiness handle described in
//!   Spec.md Section 7 lands in Wave 1 when ingestion comes online.

use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};

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

/// Readiness probe. Wave 0 returns 200 once `build_app` is wired,
/// matching the architect's exit-criteria checklist for the wave (see
/// `decisions/wave-0.md` Section 8: "`/ready` returns 200 in Wave 0"
/// pending dataset registration in Wave 1).
async fn ready() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
