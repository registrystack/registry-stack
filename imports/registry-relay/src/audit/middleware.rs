// SPDX-License-Identifier: Apache-2.0
//! Axum middleware for emitting one audit record per request.
//!
//! The hot path lives in `audit/mod.rs::audit_layer` so the test suite
//! and the server scaffold can both import it as `audit::audit_layer`.
//! This submodule provides the installation helper that wires the
//! shared `Arc<AuditPipeline>` into the request extensions before the
//! layer runs.

use std::sync::Arc;

use axum::middleware::from_fn;
use axum::Extension;
use axum::Router;

use super::{audit_layer, AuditPipeline, AuditSettings};

/// Install the audit middleware on a router. The caller supplies the
/// pipeline so test code can substitute an in-memory platform sink
/// while production uses [`super::StdoutSink`].
///
/// The sink is provided to the layer via an `Extension`, which lets us
/// keep the router's user-facing state generic.
pub fn install<S>(router: Router<S>, sink: Arc<AuditPipeline>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    install_with_settings(router, sink, AuditSettings::default())
}

/// Install the audit middleware with explicit runtime settings from
/// config.
pub fn install_with_settings<S>(
    router: Router<S>,
    sink: Arc<AuditPipeline>,
    settings: AuditSettings,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(sink))
}
