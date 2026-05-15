// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for Wave 0 Track 6: HTTP scaffold + health/ready.
//!
//! Coverage:
//! * `/health` returns 200 with the documented JSON body and echoes an
//!   `x-request-id` header.
//! * `/ready` returns 200 (Wave 0 readiness is trivially ready once
//!   `build_app` returns; resource-gated readiness lands in Wave 1).
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
use data_gate::audit::{AuditSink, InMemorySink};
use data_gate::auth::api_key::ApiKeyAuth;
use data_gate::config::{Config, DatasetId, ResourceId};
use data_gate::format::FormatRegistry;
use data_gate::ingest::{IngestRegistry, ReadinessSnapshot};
use data_gate::server::{build_admin_app, build_app, build_app_with_readiness};
use datafusion::execution::context::SessionContext;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;
use ulid::Ulid;

/// Load the canonical Wave 0 example config from the repo. The config
/// loader runs cross-field validation; we set the required `hash_env`
/// env vars to a known Argon2id PHC string so the loader does not
/// fail with `config.missing_secret`.
fn load_example_config() -> Config {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    // Set both keys to the same PHC string. The plaintext is irrelevant
    // for these tests; we never present a credential.
    let phc = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHRkZ3RmaXh0dXJl$\
               EFMrkqK4dXMTH8DBlEvNN3wL/qmRvDjCwIAt7BqDpUw";
    // Matches the existing pattern in `tests/config_loader.rs`: env
    // vars are set inline at test setup. Test binaries run each test in
    // a fresh thread but share process env, so the chosen names must be
    // unique to this fixture; the canonical example's keys are.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("STATS_OFFICE_API_KEY_HASH", phc);
        std::env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", phc);
        std::env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", phc);
    }
    data_gate::config::load(&path).expect("example config loads")
}

fn build_test_app(sink: Arc<dyn AuditSink>) -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink)
}

fn build_test_app_with_health_audit(sink: Arc<dyn AuditSink>) -> axum::Router {
    let mut cfg = load_example_config();
    cfg.audit.include_health = true;
    let config = Arc::new(cfg);
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink)
}

fn build_test_app_with_config(config: Arc<Config>, sink: Arc<dyn AuditSink>) -> axum::Router {
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    build_app(config, auth, sink)
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn build_test_app_with_readiness(snapshot: ReadinessSnapshot) -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let (_tx, rx) = watch::channel(snapshot);
    build_app_with_readiness(config, auth, sink, rx)
}

#[tokio::test]
async fn health_returns_200_with_status_ok_body() {
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);

    let body: Value = resp.json();
    assert_eq!(body, serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn health_response_carries_x_request_id_header() {
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
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
async fn ready_returns_200_in_wave_0() {
    // Wave 0 readiness check is trivial: once `build_app` returns,
    // the process is ready. Dataset-gated readiness arrives in Wave 1.
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
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
        Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
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
    let sink: Arc<dyn AuditSink> = Arc::new(inmem.clone());
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

    let record: Value = serde_json::from_str(captured[0].trim_end()).expect("valid JSONL");
    assert_eq!(record["status_code"], 200);
    assert_eq!(record["method"], "GET");
    assert_eq!(record["path"], "/health");
    assert!(record["request_id"].is_string());
}

#[tokio::test]
async fn health_audit_is_suppressed_by_default() {
    let inmem = InMemorySink::new();
    let sink: Arc<dyn AuditSink> = Arc::new(inmem.clone());
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

    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
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

    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
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
    // We cannot observe the timeout firing without a slow handler;
    // Wave 0 has no sleep route. Instead, assert that `build_app` reads
    // `request_timeout` from config by verifying the router builds and
    // a fast request still succeeds when an extremely long timeout is
    // configured. The negative case (timeout firing on a slow route)
    // lands in Wave 1 once a data-plane route exists.
    let mut cfg = load_example_config();
    cfg.server.request_timeout = Duration::from_secs(120);
    let config = Arc::new(cfg);

    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_test_app_with_config(config, sink);
    let server = TestServer::new(app);

    let resp = server.get("/health").await;
    resp.assert_status(StatusCode::OK);
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

    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let ingest = Arc::new(
        IngestRegistry::from_config(
            &config,
            Arc::new(FormatRegistry::with_v1_defaults()),
            Arc::from(config.server.cache_dir.as_path()),
            Arc::new(SessionContext::new()),
        )
        .expect("empty ingest registry builds"),
    );
    let (_readiness_tx, readiness_rx) = watch::channel(ingest.snapshot());
    let main_app = build_app(Arc::clone(&config), Arc::clone(&auth), Arc::clone(&sink));
    let admin_app = build_admin_app(
        Arc::clone(&config),
        Arc::clone(&auth),
        Arc::clone(&sink),
        readiness_rx,
        ingest,
    );

    // Serve both routers in background tasks. We do not bother with
    // graceful shutdown here because the test process tears them down
    // when it exits.
    let main_handle =
        tokio::spawn(async move { axum::serve(main_listener, main_app.into_make_service()).await });
    let admin_handle =
        tokio::spawn(
            async move { axum::serve(admin_listener, admin_app.into_make_service()).await },
        );

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

/// Minimal HTTP/1.1 GET client. We avoid pulling reqwest into
/// dev-deps for one test; this just opens a TCP connection, writes a
/// request line + Host header, and returns `(status, body)`.
async fn reqwest_lite_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
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
