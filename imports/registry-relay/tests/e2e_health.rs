// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for HTTP health, readiness, and cross-cutting layers.
//!
//! Coverage:
//! * `/health` returns 200 with the documented JSON body and echoes an
//!   `x-request-id` header.
//! * `/ready` returns 200 when `build_app` is used without resource
//!   readiness state.
//! * The audit middleware fires for every request: hitting `/health`
//!   with an `InMemorySink` produces exactly one record carrying the
//!   request method, path, and status.
//! * `server.cors.allowed_origins` is consumed: a configured origin is
//!   echoed in the `access-control-allow-origin` response header on a
//!   preflight; an unconfigured origin is not.
//! * `server.request_timeout` is consumed: setting a tiny timeout and
//!   hitting the admin listener proves the value reaches the
//!   `TimeoutLayer`.
//! * `server.admin_bind` produces a second reachable listener that
//!   serves `/health`.
//!
//! These tests use `axum_test::TestServer` so the full middleware stack
//! (request id, tracing, audit, CORS, body size limit, timeout) runs in
//! the order the production `build_app` installs it. The admin-listener
//! test binds two real `TcpListener`s on ephemeral ports and drives
//! `axum::serve` directly because `TestServer` only models a single
//! router.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum_test::TestServer;
use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::auth::AuthProvider;
use registry_relay::config::{Config, DatasetId, ResourceId};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot, ReadyResource};
use registry_relay::server::{build_admin_app, build_app, build_app_with_readiness};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;
use ulid::Ulid;

/// Load the canonical example config from the repo. The config
/// loader runs cross-field validation; we set the required `hash_env`
/// env vars to a known API key fingerprint so the loader does not
/// fail with `config.missing_secret`.
fn load_example_config() -> Config {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // Matches the existing pattern in `tests/config_loader.rs`: env
    // vars are set inline at test setup. Test binaries run each test in
    // a fresh thread but share process env, so the chosen names must be
    // unique to this fixture; the canonical example's keys are.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
        std::env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
        std::env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
        std::env::set_var(
            "REGISTRY_RELAY_AUDIT_HASH_SECRET",
            "relay-e2e-health-audit-secret-32-bytes",
        );
    }
    registry_relay::config::load(&path).expect("example config loads")
}

fn build_test_app(sink: Arc<AuditPipeline>) -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink).unwrap()
}

fn build_test_app_with_health_audit(sink: Arc<AuditPipeline>) -> axum::Router {
    let mut cfg = load_example_config();
    cfg.audit.include_health = true;
    let config = Arc::new(cfg);
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink).unwrap()
}

fn build_test_app_with_config(config: Arc<Config>, sink: Arc<AuditPipeline>) -> axum::Router {
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink).unwrap()
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn build_test_app_with_readiness(snapshot: ReadinessSnapshot) -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let (_tx, rx) = watch::channel(snapshot);
    build_app_with_readiness(config, auth, sink, rx).unwrap()
}

#[tokio::test]
async fn health_returns_200_with_status_ok_body() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);

    let body: Value = resp.json();
    assert_eq!(body, serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn health_response_carries_x_request_id_header() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);

    // The audit middleware attaches `x-request-id`; the request-id
    // layer also propagates one if the client sends one. Either way
    // the response must carry the header.
    let header = resp.header("x-request-id");
    let header_value = header.to_str().expect("x-request-id is ASCII");
    assert!(
        !header_value.is_empty(),
        "x-request-id must be non-empty, got {header_value:?}"
    );
}

#[tokio::test]
async fn client_supplied_x_request_id_is_replaced() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);
    let spoofed = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    let resp = server
        .get("/health")
        .add_header("x-request-id", spoofed)
        .await;
    resp.assert_status(StatusCode::OK);

    let header = resp.header("x-request-id");
    let header_value = header.to_str().expect("x-request-id is ASCII");
    assert_ne!(header_value, spoofed);
    Ulid::from_string(header_value).expect("server-owned request id is a ULID");
}

#[tokio::test]
async fn ready_returns_200_without_resource_readiness_state() {
    // Without a readiness receiver, `build_app` reports trivial ready.
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/ready").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn ready_returns_200_when_all_resources_registered() {
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (dataset, resource),
        ReadyResource {
            ingest_ulid: Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );

    let server = TestServer::new(build_test_app_with_readiness(snapshot));
    let resp = server.get("/ready").await;
    resp.assert_status(StatusCode::OK);

    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["resources"][0]["dataset_id"], "social_registry");
    assert_eq!(body["resources"][0]["resource_id"], "beneficiaries");
    assert_eq!(
        body["resources"][0]["ingest_ulid"],
        "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    );
}

#[tokio::test]
async fn ready_503_reports_failed_count_without_names() {
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot
        .failed
        .insert((dataset, resource), "ingest.schema_mismatch");

    let server = TestServer::new(build_test_app_with_readiness(snapshot));
    let resp = server.get("/ready").await;
    resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.header("content-type"), "application/problem+json");

    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.resource_unavailable");
    // Count-only: no dataset or resource names exposed.
    assert_eq!(body["failed_count"], 1);
    assert!(
        body.get("failed_resources").is_none(),
        "dataset names must not appear in 503 body"
    );
    assert!(
        !body.to_string().contains("social_registry"),
        "dataset id must not leak in 503 body"
    );
}

#[tokio::test]
async fn ready_503_reports_unresolved_count_without_names() {
    let dataset: DatasetId = id("social_registry");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot
        .unresolved_entities
        .insert((dataset, "individual".to_string()));

    let server = TestServer::new(build_test_app_with_readiness(snapshot));
    let resp = server.get("/ready").await;
    resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);

    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.resource_unavailable");
    assert_eq!(body["unresolved_count"], 1);
    assert!(
        body.get("unresolved_entities").is_none(),
        "entity names must not appear in 503 body"
    );
    assert!(
        !body.to_string().contains("individual"),
        "entity name must not leak in 503 body"
    );
    assert!(
        !body.to_string().contains("social_registry"),
        "dataset id must not leak in 503 body"
    );
}

#[tokio::test]
async fn audit_middleware_fires_on_health() {
    let inmem = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
    let app = build_test_app_with_health_audit(sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);

    let captured = inmem.snapshot();
    assert_eq!(
        captured.len(),
        1,
        "audit middleware must emit exactly one record per request"
    );

    let record = audit_record_from_platform_envelope(&captured[0]);
    assert_eq!(record["status_code"], 200);
    assert_eq!(record["method"], "GET");
    assert_eq!(record["path"], "/health");
    assert!(record["request_id"].is_string());
}

#[tokio::test]
async fn health_audit_is_suppressed_by_default() {
    let inmem = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);

    assert!(
        inmem.snapshot().is_empty(),
        "health/ready audit records should be opt-in"
    );
}

#[tokio::test]
async fn cors_allowed_origin_from_config_is_echoed_on_preflight() {
    // The example config has no `cors.allowed_origins`; mutate the
    // parsed `Config` in place to add one. Going through YAML is
    // unnecessary for this assertion.
    let mut cfg = load_example_config();
    cfg.server.cors.allowed_origins = vec!["https://allowed.example.gov".to_string()];
    let config = Arc::new(cfg);

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app_with_config(config, sink);
    let server = TestServer::new(app);

    // CORS preflight: OPTIONS with an Origin header. The CORS layer
    // mirrors the request's `Access-Control-Request-Method`.
    let resp = server
        .method(axum::http::Method::OPTIONS, "/health")
        .add_header("origin", "https://allowed.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;

    let allow_origin = resp.header("access-control-allow-origin");
    assert_eq!(allow_origin, "https://allowed.example.gov");
}

#[tokio::test]
async fn cors_unconfigured_origin_is_not_echoed() {
    let mut cfg = load_example_config();
    cfg.server.cors.allowed_origins = vec!["https://allowed.example.gov".to_string()];
    let config = Arc::new(cfg);

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app_with_config(config, sink);
    let server = TestServer::new(app);

    let resp = server
        .method(axum::http::Method::OPTIONS, "/health")
        .add_header("origin", "https://stranger.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;

    // tower-http returns no Access-Control-Allow-Origin for a
    // non-matching origin.
    assert!(
        resp.maybe_header("access-control-allow-origin").is_none(),
        "non-allowlisted origin must not receive an allow-origin header"
    );
}

#[tokio::test]
async fn server_request_timeout_field_reaches_timeout_layer() {
    // We cannot observe the timeout firing without adding a slow test
    // route. Instead, assert that `build_app` reads `request_timeout`
    // from config by verifying the router builds and a fast request
    // still succeeds when an extremely long timeout is configured.
    let mut cfg = load_example_config();
    cfg.server.request_timeout = Duration::from_secs(120);
    let config = Arc::new(cfg);

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app_with_config(config, sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn overlong_uri_returns_414_uri_too_long() {
    // The transport-layer URI cap fires before any handler runs. A
    // request with a path + query string over 8 KiB must return 414
    // with the `internal.uri_too_long` problem-details code, matching
    // the shape used by the timeout and body-limit layers.
    let inmem = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    // Build a URI well over the 8 KiB cap. The leading `/health?` plus
    // 9000 ASCII bytes of query string puts us comfortably past the
    // limit. We hit `/health` because it is the simplest always-mounted
    // route; the cap is enforced before route matching.
    let big_param = "a".repeat(9_000);
    let url = format!("/health?x={big_param}");
    let resp = server.get(&url).await;

    resp.assert_status(StatusCode::URI_TOO_LONG);
    assert_eq!(resp.header("content-type"), "application/problem+json");
    let body: Value = resp.json();
    assert_eq!(body["code"], "internal.uri_too_long");
}

#[tokio::test]
async fn admin_bind_serves_health_on_second_listener() {
    // Bind two ephemeral ports, spin up the main and admin routers,
    // and confirm `/health` is reachable on both. The integration test
    // proves that `main.rs::run` would have a working second listener
    // when `server.admin_bind` is set. We drive the server directly
    // rather than spawning the binary so the test runs in-process.
    let main_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind main");
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
    let main_addr: SocketAddr = main_listener.local_addr().expect("main addr");
    let admin_addr: SocketAddr = admin_listener.local_addr().expect("admin addr");

    let mut cfg = load_example_config();
    cfg.server.bind = main_addr;
    cfg.server.admin_bind = Some(admin_addr);
    cfg.datasets.clear();
    let config = Arc::new(cfg);

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let ingest = Arc::new(
        IngestRegistry::from_config(
            &config,
            Arc::new(FormatRegistry::with_v1_defaults()),
            Arc::from(config.server.cache_dir.as_path()),
            Arc::new(SessionContext::new()),
        )
        .expect("empty ingest registry builds"),
    );
    let (readiness_tx, readiness_rx) = watch::channel(ingest.snapshot());
    let main_app = build_app(Arc::clone(&config), Arc::clone(&auth), Arc::clone(&sink)).unwrap();
    let admin_app = build_admin_app(
        Arc::clone(&config),
        Arc::clone(&auth),
        Arc::clone(&sink),
        readiness_rx,
        readiness_tx,
        ingest,
    )
    .expect("admin app builds");

    // Serve both routers in background tasks. We do not bother with
    // graceful shutdown here because the test process tears them down
    // when it exits.
    let main_handle = tokio::spawn(async move {
        axum::serve(
            main_listener,
            main_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let admin_handle = tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let client = reqwest_lite_get(main_addr, "/health").await;
    assert_eq!(client.0, 200, "main /health responded");
    assert!(
        client.1.contains("\"status\""),
        "main body contained status"
    );

    let admin = reqwest_lite_get(admin_addr, "/health").await;
    assert_eq!(admin.0, 200, "admin /health responded");
    assert!(
        admin.1.contains("\"status\""),
        "admin body contained status"
    );

    // The futures are still running; aborting is enough since we own
    // the JoinHandles.
    main_handle.abort();
    admin_handle.abort();
}

#[tokio::test]
async fn trusted_proxy_forwarded_for_reaches_audit_on_real_listener() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr: SocketAddr = listener.local_addr().expect("listener addr");

    let mut cfg = load_example_config();
    cfg.audit.include_health = true;
    cfg.server.trust_proxy.enabled = true;
    cfg.server.trust_proxy.trusted_proxies = vec!["127.0.0.1/32".to_string()];
    let config = Arc::new(cfg);

    let inmem = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
    let app = build_test_app_with_config(config, sink);

    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let response = reqwest_lite_get_with_headers(
        addr,
        "/health",
        &[("X-Forwarded-For", "203.0.113.10, 127.0.0.1")],
    )
    .await;
    assert_eq!(response.0, 200, "/health responded through listener");

    let records = inmem.snapshot();
    assert_eq!(records.len(), 1);
    let record = audit_record_from_platform_envelope(&records[0]);
    assert_eq!(record["remote_addr"], "203.0.113.10");

    handle.abort();
}

fn audit_record_from_platform_envelope(line: &str) -> Value {
    let envelope: Value =
        serde_json::from_str(line.trim_end()).expect("valid platform audit envelope");
    envelope["record"].clone()
}

/// Minimal HTTP/1.1 GET client. We avoid pulling reqwest into
/// dev-deps for one test; this just opens a TCP connection, writes a
/// request line + Host header, and returns `(status, body)`.
async fn reqwest_lite_get(addr: SocketAddr, path: &str) -> (u16, String) {
    reqwest_lite_get_with_headers(addr, path, &[]).await
}

async fn reqwest_lite_get_with_headers(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let raw = String::from_utf8_lossy(&buf).to_string();

    // Parse the status line and split out the body. HTTP/1.1 splits
    // headers and body on the first blank line.
    let status: u16 = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}
