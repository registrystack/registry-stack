// SPDX-License-Identifier: Apache-2.0
//! HTTP server composition.
//!
//! [`build_app`] composes the public data-plane router from parsed
//! [`Config`], [`crate::auth::AuthProvider`], and [`AuditPipeline`] state. The production
//! path installs ingest readiness plus entity/query state through
//! [`build_app_with_entity_query`]. Layering order follows the V1
//! operational requirements for request ids, audit records, bounded
//! metrics, CORS, body limits, timeouts, and scoped API-key
//! authentication.
//!
//! ## Layer order (outer to inner)
//!
//! 1. `SetRequestIdLayer` + `PropagateRequestIdLayer` (ULID-shaped
//!    `x-request-id` header). The propagate layer copies the request
//!    id onto the response so clients can correlate without parsing
//!    the audit log.
//! 2. Baseline security headers: browser hardening headers applied to
//!    every response.
//! 3. Audit middleware: emits one record per request to the configured
//!    sink, with health/ready gated by `audit.include_health`.
//! 4. Metrics middleware: records low-cardinality request counters and
//!    duration buckets for the admin-only Prometheus exposition route.
//! 5. `TraceLayer`: structured request/response spans for operational
//!    logs. The audit log is the load-bearing observability surface;
//!    this layer adds debugging context.
//! 6. `CorsLayer`: built from `config.server.cors.allowed_origins`.
//!    Empty allowlist (the default) means no `Access-Control-Allow-*`
//!    headers go out, matching the default-deny CORS policy.
//! 7. Internal error normalizer: maps timeout/body-limit responses into
//!    RFC 9457 Problem Details before audit records them.
//! 8. `RequestBodyLimitLayer` at 1 MiB as a defensive backstop.
//! 9. `RequestBodyTimeoutLayer`: built from
//!    `config.server.request_body_timeout`.
//! 10. `TimeoutLayer`: built from `config.server.request_timeout`.
//! 11. Auth middleware on a *sub-router* that mounts data-plane routes
//!     only. The health sub-router is merged separately so `/healthz`
//!     and `/ready` stay unauthenticated.
//!
//! ## Admin listener
//!
//! [`build_admin_app`] mirrors [`build_app`] for the optional admin
//! listener (`config.server.admin_bind`). Admin routes are intentionally
//! kept off the public data-plane listener. The admin listener carries
//! `/healthz`, admin-listener-only `/metrics`, table reload, and
//! registry-wide reload.
//!
//! ## What lives elsewhere
//!
//! * Middleware *factories* (auth, audit) live in their owning modules.
//!   This file composes; it does not author middleware.
//! * Route handlers live in `crate::api`; this module only wires those
//!   routers together with shared state and cross-cutting middleware.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Router;
use registry_manifest_core::CompiledMetadata;
use registry_platform_audit::AuditKeyHasher;
use registry_platform_httpsec::{apply_conditional_corp, request_body_limit, CorsPolicy};
use tower_http::cors::CorsLayer;
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use ulid::Ulid;

use crate::api::{self, CursorSigner};
use crate::audit::{self, AuditPipeline, AuditSettings, OperationalAuditEvent};
use crate::auth::middleware::{auth_layer, AuthProviderRef};
use crate::config::{Config, CorsConfig};
use crate::entity::EntityRegistry;
use crate::error::{ConfigError, Error, InternalError};
use crate::ingest::{IngestRegistry, ReadinessSnapshot};
use crate::observability::RequestMetrics;
use crate::query::{AggregateQueryEngine, EntityQueryEngine};

/// Defensive cap on request body size (1 MiB). V1 endpoints are GET only;
/// the limit exists so a misbehaving client cannot exhaust memory by
/// streaming a body the server will discard anyway.
const REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Defensive cap on request URI length (path + query, 8 KiB). The 1 MiB
/// body limit does not apply to GET query strings, so a separate cap is
/// installed at the transport layer. Requests exceeding the cap are
/// rejected with `414 URI Too Long` before any handler runs.
const MAX_URI_BYTES: usize = 8192;

const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
#[cfg(test)]
const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// `MakeRequestId` impl that mints fresh ULIDs. Generic over header
/// name so the same shape is reusable if we ever change `x-request-id`
/// to something else.
#[derive(Debug, Clone, Default)]
struct UlidMakeRequestId;

impl MakeRequestId for UlidMakeRequestId {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        // ULIDs are 26 ASCII chars from Crockford Base32; always a
        // valid HTTP header value. Fall back to `None` only if parsing
        // ever fails so the request continues without an id rather
        // than panicking.
        Ulid::new().to_string().parse().ok().map(RequestId::new)
    }
}

/// Assemble the full HTTP application for the main listener.
///
/// The auth provider and audit sink are both passed as `Arc<dyn _>`:
/// startup branches on `config::AuthMode` and `config::AuditSinkConfig`
/// once and the rest of the wiring is provider-agnostic. The per-request
/// virtual call cost is negligible against SHA-256 hashing (API-key) or
/// JWT signature verification (OIDC).
pub fn build_app(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
) -> Result<Router, ConfigError> {
    build_app_with_provenance(config, auth, audit_sink, None)
}

/// Same as [`build_app`] but lets a caller install a pre-built
/// [`crate::provenance::ProvenanceState`]. Tests that don't exercise provenance keep the
/// smaller [`build_app`] entry.
pub fn build_app_with_provenance(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
) -> Result<Router, ConfigError> {
    build_app_with_provenance_and_metrics(
        config,
        auth,
        audit_sink,
        provenance,
        RequestMetrics::shared(),
    )
}

/// Same as [`build_app_with_provenance`] but lets callers supply the
/// request metrics collector installed in the cross-cutting stack.
pub fn build_app_with_provenance_and_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    build_app_with_provenance_metadata_and_metrics(
        config, auth, audit_sink, provenance, None, metrics,
    )
}

fn build_app_with_provenance_metadata_and_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metadata: Option<Arc<CompiledMetadata>>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    // Health/ready routes: unauthenticated sub-router. Merged onto the
    // top-level router *outside* the auth layer. The Scalar viewer
    // (`/docs` + `/docs/scalar.js`) is a static HTML+JS shell with no
    // secrets in it, so it sits on the public surface and a browser
    // can load it directly. The OpenAPI document it renders
    // (`/openapi.json`) stays auth-gated below; the user pastes their
    // API key into Scalar to fetch it.
    let mut public = api::health_router().merge(api::docs_router());

    // When provenance is configured and enabled, the gateway exposes
    // JSON Schemas, JSON-LD contexts, and (gateway mode only) the
    // `/.well-known/did.json` document on the public unauthenticated
    // surface. These routes share the same audit and tracing pipeline
    // as `/health` and `/ready`.
    //
    // A `ProvenanceState` whose `is_enabled()` returns `false` is
    // still installed as an extension below so internal wiring stays
    // identical; the public surface, however, must stay invisible for
    // deployments that load a config with `provenance.enabled: false`.
    if provenance.as_ref().is_some_and(|state| state.is_enabled()) {
        public = public
            .merge(api::schemas_router())
            .merge(api::contexts_router())
            .merge(api::did_router());
    }

    // Data-plane sub-router. All protected public API routes are merged
    // here so the auth layer gates them as one surface.
    let protected: Router<()> = Router::new()
        .merge(api::datasets_router())
        .merge(api::aggregates_router())
        .merge(api::entity_router())
        .merge(api::metadata_router())
        .merge(api::openapi_router());
    #[cfg(feature = "ogcapi-features")]
    let protected = protected.merge(api::ogc_router());
    #[cfg(feature = "ogcapi-edr")]
    let protected = protected.merge(api::edr_router());
    #[cfg(feature = "ogcapi-records")]
    let protected = protected.merge(api::records_router());
    let protected = merge_spdci_routes(protected);
    let protected = auth_layer(protected, auth);

    // Merge public + protected; everything above this point is inside
    // the audit, tracing, request-id, CORS, body-limit, and timeout
    // layers installed below.
    let merged: Router<()> = Router::new().merge(public).merge(protected);

    // Ephemeral per-process signing key for opaque cursors. Claim
    // verification uses a configured stable HMAC key so audit hashes
    // survive process restarts.
    let cursor_signer = Arc::new(CursorSigner::new_random());
    let mut router = apply_cross_cutting_layers_with_metrics(merged, &config, audit_sink, metrics)?
        .layer(Extension(cursor_signer))
        .layer(Extension(config));
    if let Some(state) = provenance {
        router = router.layer(Extension(state));
    }
    if let Some(metadata) = metadata {
        router = router.layer(Extension(metadata));
    }
    Ok(router)
}

#[cfg(feature = "spdci-api-standards")]
fn merge_spdci_routes(router: Router) -> Router {
    router.merge(api::spdci_router())
}

#[cfg(not(feature = "spdci-api-standards"))]
fn merge_spdci_routes(router: Router) -> Router {
    router
}

/// Assemble the main application with an ingest readiness watch.
///
/// [`build_app`] remains as a tiny compatibility wrapper for tests that
/// only need the HTTP shell without live readiness state.
pub fn build_app_with_readiness(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
) -> Result<Router, ConfigError> {
    Ok(build_app(config, auth, audit_sink)?.layer(Extension(readiness)))
}

/// Assemble the main app with readiness plus entity/query state installed
/// for entity-shaped API routes.
pub fn build_app_with_entity_query(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
) -> Result<Router, ConfigError> {
    Ok(
        build_app_with_readiness(config, auth, audit_sink, readiness)?
            .layer(Extension(aggregate_query))
            .layer(Extension(query))
            .layer(Extension(entity_registry)),
    )
}

/// Production assembly: readiness, entity/query state, and optional
/// [`crate::provenance::ProvenanceState`]. Used by `main.rs` once runtime state has been
/// built from the parsed config; tests that need provenance plus query
/// call this directly with their own handles.
#[allow(clippy::too_many_arguments)]
pub fn build_app_with_entity_query_and_provenance(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
) -> Result<Router, ConfigError> {
    build_app_with_entity_query_and_provenance_and_metrics(
        config,
        auth,
        audit_sink,
        readiness,
        entity_registry,
        query,
        aggregate_query,
        provenance,
        RequestMetrics::shared(),
    )
}

/// Same as [`build_app_with_entity_query_and_provenance`] but lets the
/// caller share one request metrics collector across multiple listeners.
/// The binary uses this to expose data-plane and admin traffic through
/// the admin-only `/metrics` route.
#[allow(clippy::too_many_arguments)]
pub fn build_app_with_entity_query_and_provenance_and_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    Ok(
        build_app_with_provenance_and_metrics(config, auth, audit_sink, provenance, metrics)?
            .layer(Extension(readiness))
            .layer(Extension(aggregate_query))
            .layer(Extension(query))
            .layer(Extension(entity_registry)),
    )
}

/// Production assembly with split metadata compiled from `metadata.yaml`.
#[allow(clippy::too_many_arguments)]
pub fn build_app_with_entity_query_metadata_provenance_and_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
    metadata: Option<Arc<CompiledMetadata>>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    Ok(build_app_with_provenance_metadata_and_metrics(
        config, auth, audit_sink, provenance, metadata, metrics,
    )?
    .layer(Extension(readiness))
    .layer(Extension(aggregate_query))
    .layer(Extension(query))
    .layer(Extension(entity_registry)))
}

/// Assemble the admin HTTP application for `config.server.admin_bind`.
///
/// Mounts the same `/healthz` route as the main listener so operators
/// can probe the second port without authentication. Admin reload
/// routes are mounted behind authentication and their handlers enforce
/// the `admin` scope.
pub fn build_admin_app(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    readiness_tx: tokio::sync::watch::Sender<ReadinessSnapshot>,
    ingest: Arc<IngestRegistry>,
) -> Result<Router, ConfigError> {
    build_admin_app_with_metadata_and_metrics(
        config,
        auth,
        audit_sink,
        readiness,
        readiness_tx,
        ingest,
        None,
        RequestMetrics::shared(),
    )
}

/// Same as [`build_admin_app`] but shares a request metrics collector
/// with another listener.
pub fn build_admin_app_with_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    readiness_tx: tokio::sync::watch::Sender<ReadinessSnapshot>,
    ingest: Arc<IngestRegistry>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    build_admin_app_with_metadata_and_metrics(
        config,
        auth,
        audit_sink,
        readiness,
        readiness_tx,
        ingest,
        None,
        metrics,
    )
}

/// Same as [`build_admin_app_with_metrics`] but installs compiled split
/// metadata for operations posture artifact and evidence summaries.
#[allow(clippy::too_many_arguments)]
pub fn build_admin_app_with_metadata_and_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<AuditPipeline>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    readiness_tx: tokio::sync::watch::Sender<ReadinessSnapshot>,
    ingest: Arc<IngestRegistry>,
    metadata: Option<Arc<CompiledMetadata>>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    let public = api::health_router()
        .merge(crate::observability::router())
        .layer(Extension(metrics.clone()));
    let protected = api::admin_router().layer(Extension(ingest));
    let protected = auth_layer(protected, auth);
    let merged: Router<()> = Router::new().merge(public).merge(protected);
    let mut router = apply_cross_cutting_layers_with_metrics(merged, &config, audit_sink, metrics)?
        .layer(Extension(readiness))
        .layer(Extension(readiness_tx))
        .layer(Extension(config));
    if let Some(metadata) = metadata {
        router = router.layer(Extension(metadata));
    }
    Ok(router)
}

fn apply_cross_cutting_layers_with_metrics(
    router: Router,
    config: &Config,
    audit_sink: Arc<AuditPipeline>,
    metrics: Arc<RequestMetrics>,
) -> Result<Router, ConfigError> {
    let x_request_id: HeaderName = HeaderName::from_static("x-request-id");
    let (cors, cors_fell_back) = build_cors_layer_with_status(&config.server.cors);
    if cors_fell_back {
        spawn_operational_audit_event(
            Arc::clone(&audit_sink),
            OperationalAuditEvent::new("cors.policy_invalid", "cors.policy_invalid"),
        );
    }
    let audit_settings = AuditSettings {
        include_health: config.audit.include_health,
        trust_proxy_enabled: config.server.trust_proxy.enabled,
        trusted_proxies: config.server.trust_proxy.trusted_proxies.clone(),
        sensitive_fields: audit_sensitive_fields(config),
        hash_hasher: load_audit_hash_secret(config.audit.hash_secret_env.as_deref())?,
    };

    let with_operational_layers = router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.server.request_timeout,
        ))
        .layer(request_body_limit(REQUEST_BODY_LIMIT_BYTES))
        .layer(RequestBodyTimeoutLayer::new(
            config.server.request_body_timeout,
        ))
        .layer(from_fn(reject_overlong_uri))
        .layer(from_fn(normalize_internal_error_response))
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::info_span!(
                        "http.request",
                        method = %request.method(),
                        route = operational_route(request),
                        request_id = operational_request_id(request),
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );
    let with_operational_layers = crate::observability::install(with_operational_layers, metrics);

    let with_audit = audit::middleware::install_with_settings(
        with_operational_layers,
        audit_sink,
        audit_settings,
    );

    Ok(with_audit
        // Strip client-supplied request ids, then mint and propagate a
        // server-owned `x-request-id` value.
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, UlidMakeRequestId))
        .layer(from_fn(strip_untrusted_request_id))
        .layer(from_fn(add_security_headers)))
}

fn operational_route(request: &Request<Body>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("<unmatched>")
}

fn operational_request_id(request: &Request<Body>) -> &str {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

async fn strip_untrusted_request_id(mut request: Request<Body>, next: Next) -> Response {
    request.headers_mut().remove("x-request-id");
    request.extensions_mut().remove::<RequestId>();
    next.run(request).await
}

async fn add_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        PERMISSIONS_POLICY,
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
        ),
    );
    headers.insert(
        CROSS_ORIGIN_OPENER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    apply_conditional_corp(&mut response);
    // HSTS is intentionally omitted at the application layer. Production
    // deployments terminate TLS upstream (load balancer / ingress) and
    // own the HSTS policy there; local development runs plain HTTP on
    // loopback. Emitting HSTS from the relay would either be no-op text
    // on dev or duplicate (and potentially conflict with) the edge
    // value. If the relay ever serves TLS directly, set it here.
    response
}

/// Resolve the audit hash secret from the env var named by config.
///
/// Production startup fails closed when `audit.hash_secret_env` is
/// missing, empty, unset, or resolves to a weak secret. Direct
/// middleware tests can still opt into `AuditKeyHasher::unkeyed_dev_only`
/// through `AuditSettings::default()`.
fn load_audit_hash_secret(env_var: Option<&str>) -> Result<AuditKeyHasher, ConfigError> {
    let Some(var_name) = env_var.filter(|name| !name.trim().is_empty()) else {
        tracing::error!("audit.hash_secret_env is required");
        return Err(ConfigError::MissingSecret);
    };
    AuditKeyHasher::from_env(var_name).map_err(|err| {
        tracing::error!(
            env_var = %var_name,
            error = %err,
            "audit hash secret failed validation"
        );
        ConfigError::MissingSecret
    })
}

fn audit_sensitive_fields(config: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    for dataset in &config.datasets {
        for entity in &dataset.entities {
            let table = dataset
                .table_configs()
                .find(|table| table.id.as_str() == entity.table.as_str());
            let Some(table) = table else {
                continue;
            };
            if entity.fields.is_empty() {
                for field in table.schema.fields.iter().filter(|field| field.sensitive) {
                    fields.push(format!("{}:{}:{}", dataset.id, entity.name, field.name));
                }
                continue;
            }
            for field in &entity.fields {
                let table_column = field.from.as_deref().unwrap_or(field.name.as_str());
                let table_sensitive = table
                    .schema
                    .fields
                    .iter()
                    .find(|candidate| candidate.name == table_column)
                    .map(|candidate| candidate.sensitive)
                    .unwrap_or(false);
                if field.sensitive || table_sensitive {
                    fields.push(format!("{}:{}:{}", dataset.id, entity.name, field.name));
                }
            }
        }
    }
    fields
}

/// Reject requests whose URI (path + query string) exceeds
/// [`MAX_URI_BYTES`]. Installed inside the audit layer so rejections
/// produce an audit record with the `internal.uri_too_long` code, and
/// outside the body-limit layer so the GET-only query string is bound
/// independently of any request body. Returns a Problem Details
/// response shaped identically to the body-limit and timeout layers.
async fn reject_overlong_uri(request: Request<Body>, next: Next) -> Response {
    if request.uri().to_string().len() > MAX_URI_BYTES {
        return Error::from(InternalError::UriTooLong).into_response();
    }
    next.run(request).await
}

async fn normalize_internal_error_response(request: Request<Body>, next: Next) -> Response {
    let response = next.run(request).await;
    if response
        .extensions()
        .get::<crate::audit::ErrorCodeExt>()
        .is_some()
    {
        return response;
    }
    match response.status() {
        StatusCode::REQUEST_TIMEOUT => Error::from(InternalError::Timeout).into_response(),
        StatusCode::PAYLOAD_TOO_LARGE => {
            Error::from(InternalError::PayloadTooLarge).into_response()
        }
        _ => response,
    }
}

/// Build a `CorsLayer` from configuration.
///
/// V1 uses default-deny CORS. When `allowed_origins` is empty,
/// `CorsLayer::new()` is returned (no origin gets
/// `Access-Control-Allow-Origin`, which is the deny case).
/// When non-empty, the shared Registry Platform CORS policy validates
/// and builds the concrete Tower layer.
#[cfg(test)]
fn build_cors_layer(cors: &CorsConfig) -> CorsLayer {
    build_cors_layer_with_status(cors).0
}

fn build_cors_layer_with_status(cors: &CorsConfig) -> (CorsLayer, bool) {
    let policy = platform_cors_policy(cors);
    if let Err(err) = policy.validate() {
        tracing::error!(
            code = %Error::from(ConfigError::ValidationError).code(),
            error = %err,
            "cors policy failed platform validation; falling back to deny-all"
        );
        return (CorsLayer::new(), true);
    }
    (policy.layer(), false)
}

fn spawn_operational_audit_event(audit_sink: Arc<AuditPipeline>, event: OperationalAuditEvent) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                if let Err(err) = audit_sink.write_operational_event(event).await {
                    tracing::error!(error = %err, "audit.operational_event_write_failed");
                }
            });
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                event = event.event,
                "audit operational event skipped because no Tokio runtime is active",
            );
        }
    }
}

fn platform_cors_policy(cors: &CorsConfig) -> CorsPolicy {
    CorsPolicy {
        allowed_origins: cors.allowed_origins.clone(),
        allowed_methods: vec![Method::GET, Method::POST, Method::OPTIONS],
        allowed_headers: Vec::new(),
        allow_credentials: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::audit::{AuditPipeline, InMemorySink};
    use axum::body::Body;
    use axum::routing::get;
    use bytes::Bytes;
    use futures::stream;
    use serde_json::Value;
    use tower::ServiceExt;

    fn load_example_config() -> Config {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
        let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
            std::env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
            std::env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
            std::env::set_var(
                "REGISTRY_RELAY_AUDIT_HASH_SECRET",
                "relay-audit-test-secret-32-bytes-minimum",
            );
        }
        crate::config::load(&path).expect("example config loads")
    }

    fn captured_audit_record(line: &str) -> Value {
        let envelope: Value =
            serde_json::from_str(line.trim_end()).expect("platform audit envelope JSON");
        assert_platform_audit_envelope(&envelope);
        envelope["record"].clone()
    }

    fn assert_platform_audit_envelope(envelope: &Value) {
        let object = envelope
            .as_object()
            .expect("platform audit envelope object");
        assert_eq!(
            object.len(),
            5,
            "platform audit envelope must only expose envelope metadata plus record"
        );
        for key in [
            "envelope_id",
            "timestamp_unix_ms",
            "prev_hash",
            "record",
            "record_hash",
        ] {
            assert!(object.contains_key(key), "missing envelope field {key}");
        }
        assert!(envelope["envelope_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
        assert!(envelope["timestamp_unix_ms"].as_i64().is_some());
        assert!(
            envelope["prev_hash"].is_null() || is_lower_hex_hash(&envelope["prev_hash"]),
            "prev_hash must be null or lowercase hex: {}",
            envelope["prev_hash"]
        );
        assert!(
            is_lower_hex_hash(&envelope["record_hash"]),
            "record_hash must be lowercase hex: {}",
            envelope["record_hash"]
        );
        assert!(envelope["record"].is_object());
    }

    fn is_lower_hex_hash(value: &Value) -> bool {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    }

    use crate::config::CorsConfig;

    #[test]
    fn build_cors_layer_empty_returns_deny_default() {
        // We cannot inspect the layer's internal state directly, but
        // we can prove the empty-config path does not panic and
        // returns a real layer. The behaviour test lives in
        // `tests/e2e_health.rs`.
        let _ = build_cors_layer(&CorsConfig::default());
    }

    #[test]
    fn build_cors_layer_with_valid_origin_constructs() {
        let cors = CorsConfig {
            allowed_origins: vec!["https://allowed.example.gov".to_string()],
        };
        let _ = build_cors_layer(&cors);
    }

    #[test]
    fn build_cors_layer_drops_malformed_origins() {
        // A header value cannot contain control characters. We expect
        // the layer to be constructed (degraded to deny-all) without
        // panicking.
        let cors = CorsConfig {
            allowed_origins: vec!["https://bad\norigin".to_string()],
        };
        let _ = build_cors_layer(&cors);
    }

    #[tokio::test]
    async fn invalid_cors_policy_writes_operational_audit_event() {
        let mut config = load_example_config();
        config.server.cors.allowed_origins = vec!["https://bad\norigin".to_string()];
        let config = Arc::new(config);
        let inmem = InMemorySink::new();
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
        let router = Router::new().route("/ok", get(|| async { StatusCode::OK }));
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let records = inmem.snapshot();
                if records.iter().any(|line| {
                    let record = captured_audit_record(line);
                    record["path"] == "/__events/cors.policy_invalid"
                        && record["method"] == "BACKGROUND"
                        && record["error_code"] == "cors.policy_invalid"
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cors operational audit event");
    }

    #[tokio::test]
    async fn cross_cutting_layers_add_baseline_security_headers() {
        let config = Arc::new(load_example_config());
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
        let router = Router::new().route("/ok", get(|| async { StatusCode::OK }));
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(X_CONTENT_TYPE_OPTIONS)
                .expect("x-content-type-options"),
            "nosniff"
        );
        assert_eq!(
            headers.get(REFERRER_POLICY).expect("referrer-policy"),
            "no-referrer"
        );
        assert_eq!(
            headers.get(X_FRAME_OPTIONS).expect("x-frame-options"),
            "DENY"
        );
        assert_eq!(
            headers.get(PERMISSIONS_POLICY).expect("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()"
        );
        assert_eq!(
            headers
                .get(CROSS_ORIGIN_OPENER_POLICY)
                .expect("cross-origin-opener-policy"),
            "same-origin"
        );
        assert_eq!(
            headers
                .get(CROSS_ORIGIN_RESOURCE_POLICY)
                .expect("cross-origin-resource-policy"),
            "same-origin"
        );
    }

    #[tokio::test]
    async fn corp_relaxes_to_cross_origin_when_cors_allows_request() {
        // When the CORS layer approves a cross-origin request, CORP must
        // not block it under COEP. The middleware reads the
        // `Access-Control-Allow-Origin` echo and downgrades CORP to
        // `cross-origin` for that specific response.
        let mut config = load_example_config();
        config.server.cors.allowed_origins = vec!["https://allowed.example.gov".to_string()];
        let config = Arc::new(config);
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
        let router = Router::new().route("/ok", get(|| async { StatusCode::OK }));
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .header("origin", "https://allowed.example.gov")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .expect("cors layer echoes allowed origin"),
            "https://allowed.example.gov"
        );
        assert_eq!(
            headers
                .get(CROSS_ORIGIN_RESOURCE_POLICY)
                .expect("cross-origin-resource-policy"),
            "cross-origin"
        );
    }

    #[tokio::test]
    async fn timeout_layer_returns_problem_details_and_audit_code() {
        let mut config = load_example_config();
        config.server.request_timeout = Duration::from_millis(1);
        let config = Arc::new(config);
        let inmem = InMemorySink::new();
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
        let router = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                StatusCode::OK
            }),
        );
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/slow")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem JSON");
        assert_eq!(body["code"], "internal.timeout");

        let records = inmem.snapshot();
        assert_eq!(records.len(), 1);
        let record = captured_audit_record(&records[0]);
        assert_eq!(record["error_code"], "internal.timeout");
        assert_eq!(record["status_code"], 504);
    }

    #[tokio::test]
    async fn body_limit_layer_returns_problem_details_and_audit_code() {
        let config = Arc::new(load_example_config());
        let inmem = InMemorySink::new();
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|_body: String| async { StatusCode::OK }),
        );
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");
        let body = vec![b'x'; REQUEST_BODY_LIMIT_BYTES + 1];

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem JSON");
        assert_eq!(body["code"], "internal.payload_too_large");

        let records = inmem.snapshot();
        assert_eq!(records.len(), 1);
        let record = captured_audit_record(&records[0]);
        assert_eq!(record["error_code"], "internal.payload_too_large");
        assert_eq!(record["status_code"], 413);
    }

    #[tokio::test]
    async fn request_body_timeout_layer_bounds_slow_body_reads() {
        let mut config = load_example_config();
        config.server.request_body_timeout = Duration::from_millis(25);
        let config = Arc::new(config);
        let inmem = InMemorySink::new();
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|_body: String| async { StatusCode::OK }),
        );
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");
        let slow_body = Body::from_stream(stream::unfold(false, |sent_first| async move {
            if sent_first {
                tokio::time::sleep(Duration::from_millis(200)).await;
                None
            } else {
                Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b"x")), true))
            }
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .body(slow_body)
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let records = inmem.snapshot();
        assert_eq!(records.len(), 1);
        let record = captured_audit_record(&records[0]);
        assert_eq!(record["status_code"], 400);
    }

    #[tokio::test]
    async fn uri_length_layer_returns_problem_details_and_audit_code() {
        let config = Arc::new(load_example_config());
        let inmem = InMemorySink::new();
        let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
        let router = Router::new().route("/", get(|| async { StatusCode::OK }));
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        )
        .expect("audit hash secret configured");
        let uri = format!("/{}", "x".repeat(MAX_URI_BYTES));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem JSON");
        assert_eq!(body["code"], "internal.uri_too_long");
        assert_eq!(body["status"], 414);

        let records = inmem.snapshot();
        assert_eq!(records.len(), 1);
        let record = captured_audit_record(&records[0]);
        assert_eq!(record["error_code"], "internal.uri_too_long");
        assert_eq!(record["status_code"], 414);
    }
}
