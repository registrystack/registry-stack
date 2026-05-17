// SPDX-License-Identifier: Apache-2.0
//! HTTP server composition.
//!
//! [`build_app`] composes the public data-plane router from parsed
//! [`Config`], [`AuthProvider`], and [`AuditSink`] state. The production
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
//! 2. Audit middleware: emits one record per request to the configured
//!    sink, with health/ready gated by `audit.include_health`.
//! 3. Metrics middleware: records low-cardinality request counters and
//!    duration buckets for the admin-only Prometheus exposition route.
//! 4. `TraceLayer`: structured request/response spans for operational
//!    logs. The audit log is the load-bearing observability surface;
//!    this layer adds debugging context.
//! 5. `CorsLayer`: built from `config.server.cors.allowed_origins`.
//!    Empty allowlist (the default) means no `Access-Control-Allow-*`
//!    headers go out, matching the default-deny CORS policy.
//! 6. Internal error normalizer: maps timeout/body-limit responses into
//!    RFC 7807 Problem Details before audit records them.
//! 7. `RequestBodyLimitLayer` at 1 MiB as a defensive backstop.
//! 8. `TimeoutLayer`: built from `config.server.request_timeout`.
//! 9. Auth middleware on a *sub-router* that mounts data-plane routes
//!    only. The health sub-router is merged separately so `/health`
//!    and `/ready` stay unauthenticated.
//!
//! ## Admin listener
//!
//! [`build_admin_app`] mirrors [`build_app`] for the optional admin
//! listener (`config.server.admin_bind`). Admin routes are intentionally
//! kept off the public data-plane listener. The admin listener carries
//! `/health`, admin-listener-only `/metrics`, table reload, and the
//! registry-wide reload placeholder; `POST /admin/reload` remains a
//! reserved V1.x surface that returns `501 admin.reload_unavailable`.
//!
//! ## What lives elsewhere
//!
//! * Middleware *factories* (auth, audit) live in their owning modules.
//!   This file composes; it does not author middleware.
//! * Route handlers live in `crate::api`; this module only wires those
//!   routers together with shared state and cross-cutting middleware.

use std::env;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{
    MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use ulid::Ulid;

use crate::api::{self, CursorSigner};
use crate::audit::{self, AuditSettings, AuditSink};
use crate::auth::middleware::{auth_layer, AuthProviderRef};
use crate::claim_verification::{decode_binding_key, ClaimVerificationHasher};
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
    audit_sink: Arc<dyn AuditSink>,
) -> Router {
    build_app_with_provenance(config, auth, audit_sink, None)
}

/// Same as [`build_app`] but lets a caller install a pre-built
/// [`ProvenanceState`]. Tests that don't exercise provenance keep the
/// smaller [`build_app`] entry.
pub fn build_app_with_provenance(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<dyn AuditSink>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
) -> Router {
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
    audit_sink: Arc<dyn AuditSink>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metrics: Arc<RequestMetrics>,
) -> Router {
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
        .merge(api::entity_router())
        .merge(api::aggregates_router())
        .merge(api::catalog_router())
        .merge(api::openapi_router());
    #[cfg(feature = "ogcapi-features")]
    let protected = protected.merge(api::ogc_router());
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
    let claim_verification_hasher = claim_verification_hasher_from_config(&config).map(Arc::new);

    let mut router = apply_cross_cutting_layers_with_metrics(merged, &config, audit_sink, metrics)
        .layer(Extension(cursor_signer))
        .layer(Extension(config));
    if let Some(hasher) = claim_verification_hasher {
        router = router.layer(Extension(hasher));
    }
    if let Some(state) = provenance {
        router = router.layer(Extension(state));
    }
    router
}

fn claim_verification_hasher_from_config(config: &Config) -> Option<ClaimVerificationHasher> {
    let Some(binding) = &config.claim_verification else {
        return None;
    };
    let key = env::var(&binding.binding_key_env)
        .expect("config validation ensures claim_verification.binding_key_env is set");
    let key = decode_binding_key(&key).expect("config validation ensures HMAC key format is valid");
    Some(ClaimVerificationHasher::new(
        binding.binding_key_id.clone(),
        key,
    ))
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
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
) -> Router {
    build_app(config, auth, audit_sink).layer(Extension(readiness))
}

/// Assemble the main app with readiness plus entity/query state installed
/// for entity-shaped API routes.
pub fn build_app_with_entity_query(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
) -> Router {
    build_app_with_readiness(config, auth, audit_sink, readiness)
        .layer(Extension(aggregate_query))
        .layer(Extension(query))
        .layer(Extension(entity_registry))
}

/// Production assembly: readiness, entity/query state, and optional
/// [`ProvenanceState`]. Used by `main.rs` once runtime state has been
/// built from the parsed config; tests that need provenance plus query
/// call this directly with their own handles.
#[allow(clippy::too_many_arguments)]
pub fn build_app_with_entity_query_and_provenance(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
) -> Router {
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
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    entity_registry: Arc<EntityRegistry>,
    query: Arc<EntityQueryEngine>,
    aggregate_query: Arc<AggregateQueryEngine>,
    provenance: Option<Arc<crate::provenance::ProvenanceState>>,
    metrics: Arc<RequestMetrics>,
) -> Router {
    build_app_with_provenance_and_metrics(config, auth, audit_sink, provenance, metrics)
        .layer(Extension(readiness))
        .layer(Extension(aggregate_query))
        .layer(Extension(query))
        .layer(Extension(entity_registry))
}

/// Assemble the admin HTTP application for `config.server.admin_bind`.
///
/// Mounts the same `/health` route as the main listener so operators
/// can probe the second port without authentication. Admin reload
/// routes are mounted behind authentication and their handlers enforce
/// the `admin` scope.
pub fn build_admin_app(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    ingest: Arc<IngestRegistry>,
) -> Router {
    build_admin_app_with_metrics(
        config,
        auth,
        audit_sink,
        readiness,
        ingest,
        RequestMetrics::shared(),
    )
}

/// Same as [`build_admin_app`] but shares a request metrics collector
/// with another listener.
pub fn build_admin_app_with_metrics(
    config: Arc<Config>,
    auth: AuthProviderRef,
    audit_sink: Arc<dyn AuditSink>,
    readiness: tokio::sync::watch::Receiver<ReadinessSnapshot>,
    ingest: Arc<IngestRegistry>,
    metrics: Arc<RequestMetrics>,
) -> Router {
    let public = api::health_router()
        .merge(crate::observability::router())
        .layer(Extension(metrics.clone()));
    let protected = api::admin_router().layer(Extension(ingest));
    let protected = auth_layer(protected, auth);
    let merged: Router<()> = Router::new().merge(public).merge(protected);
    apply_cross_cutting_layers_with_metrics(merged, &config, audit_sink, metrics)
        .layer(Extension(readiness))
        .layer(Extension(config))
}

fn apply_cross_cutting_layers_with_metrics(
    router: Router,
    config: &Config,
    audit_sink: Arc<dyn AuditSink>,
    metrics: Arc<RequestMetrics>,
) -> Router {
    let x_request_id: HeaderName = HeaderName::from_static("x-request-id");
    let cors = build_cors_layer(&config.server.cors);
    let audit_settings = AuditSettings {
        include_health: config.audit.include_health,
        trust_proxy_enabled: config.server.trust_proxy.enabled,
        trusted_proxies: config.server.trust_proxy.trusted_proxies.clone(),
        sensitive_fields: audit_sensitive_fields(config),
    };

    let with_operational_layers = router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.server.request_timeout,
        ))
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT_BYTES))
        .layer(from_fn(reject_overlong_uri))
        .layer(from_fn(normalize_internal_error_response))
        .layer(cors)
        .layer(TraceLayer::new_for_http());
    let with_operational_layers = crate::observability::install(with_operational_layers, metrics);

    let with_audit = audit::middleware::install_with_settings(
        with_operational_layers,
        audit_sink,
        audit_settings,
    );

    with_audit
        // Strip client-supplied request ids, then mint and propagate a
        // server-owned `x-request-id` value.
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, UlidMakeRequestId))
        .layer(from_fn(strip_untrusted_request_id))
}

async fn strip_untrusted_request_id(mut request: Request<Body>, next: Next) -> Response {
    request.headers_mut().remove("x-request-id");
    request.extensions_mut().remove::<RequestId>();
    next.run(request).await
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
/// When non-empty, each origin is parsed as a [`HeaderValue`] and the
/// list installed via [`AllowOrigin::list`]. A malformed origin is
/// treated as a startup-time mis-config; the parse failure is logged
/// and the layer falls back to deny-all so the gateway still starts.
fn build_cors_layer(cors: &CorsConfig) -> CorsLayer {
    if cors.allowed_origins.is_empty() {
        return CorsLayer::new();
    }
    let mut parsed = Vec::with_capacity(cors.allowed_origins.len());
    for origin in &cors.allowed_origins {
        match HeaderValue::from_str(origin) {
            Ok(value) => parsed.push(value),
            Err(_) => {
                // The config validator does not currently re-check
                // origin syntax (it is parsed as a plain `String`), so
                // we degrade gracefully here
                // rather than panic at startup.
                tracing::error!(
                    code = %Error::from(ConfigError::ValidationError).code(),
                    origin = %origin,
                    "cors allowed_origins entry is not a valid header value; dropping it"
                );
            }
        }
    }
    if parsed.is_empty() {
        return CorsLayer::new();
    }
    CorsLayer::new().allow_origin(AllowOrigin::list(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::audit::{AuditSink, InMemorySink};
    use axum::body::Body;
    use axum::routing::get;
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
                "CLAIM_VERIFICATION_BINDING_KEY",
                "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
        }
        crate::config::load(&path).expect("example config loads")
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
    async fn timeout_layer_returns_problem_details_and_audit_code() {
        let mut config = load_example_config();
        config.server.request_timeout = Duration::from_millis(1);
        let config = Arc::new(config);
        let inmem = InMemorySink::new();
        let sink: Arc<dyn AuditSink> = Arc::new(inmem.clone());
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
        );

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
        let record: Value = serde_json::from_str(records[0].trim_end()).expect("audit JSON");
        assert_eq!(record["error_code"], "internal.timeout");
        assert_eq!(record["status_code"], 504);
    }

    #[tokio::test]
    async fn body_limit_layer_returns_problem_details_and_audit_code() {
        let config = Arc::new(load_example_config());
        let inmem = InMemorySink::new();
        let sink: Arc<dyn AuditSink> = Arc::new(inmem.clone());
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|_body: String| async { StatusCode::OK }),
        );
        let app = apply_cross_cutting_layers_with_metrics(
            router,
            &config,
            sink,
            RequestMetrics::shared(),
        );
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
        let record: Value = serde_json::from_str(records[0].trim_end()).expect("audit JSON");
        assert_eq!(record["error_code"], "internal.payload_too_large");
        assert_eq!(record["status_code"], 413);
    }
}
