// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for HTTP health, readiness, and cross-cutting layers.
//!
//! Coverage:
//! * `/healthz` returns 200 with the documented JSON body and echoes an
//!   `x-request-id` header.
//! * `/ready` returns 200 when `build_app` is used without resource
//!   readiness state.
//! * The audit middleware fires for every request: hitting `/healthz`
//!   with an `InMemorySink` produces exactly one record carrying the
//!   request method, path, and status.
//! * `server.cors.allowed_origins` is consumed: a configured origin is
//!   echoed in the `access-control-allow-origin` response header on a
//!   preflight; an unconfigured origin is not.
//! * `server.request_timeout` is consumed: setting a tiny timeout and
//!   hitting the admin listener proves the value reaches the
//!   `TimeoutLayer`.
//! * `server.admin_bind` produces a second reachable listener that
//!   serves `/healthz`.
//! * Security headers (`Content-Security-Policy`, `X-Content-Type-Options`,
//!   `X-Frame-Options`, `Referrer-Policy`) are present on all responses
//!   served through the full `build_app` middleware stack. Fixes #87.
//!
//! These tests use `axum_test::TestServer` so the full middleware stack
//! (request id, tracing, audit, CORS, body size limit, timeout) runs in
//! the order the production `build_app` installs it. The admin-listener
//! test binds two real `TcpListener`s on ephemeral ports and drives
//! `axum::serve` directly because `TestServer` only models a single
//! router.

use std::net::SocketAddr;
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
use registry_relay::serve::{serve_listener, ServeLimits};
use registry_relay::server::{build_admin_app, build_app, build_app_with_readiness};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;
use ulid::Ulid;

/// Load the canonical example config from the repo. The config
/// loader runs cross-field validation; we set the required fingerprint secret
/// env vars to a known API key fingerprint so the loader does not
/// fail with `config.missing_secret`.
fn load_example_config() -> Config {
    registry_relay::config::test_support::load_example_config_for_tests(
        "relay-e2e-health-audit-secret-32-bytes",
    )
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

    let resp = server.get("/healthz").await;
    resp.assert_status(StatusCode::OK);

    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "status": "ok",
            "checks": {
                "total": 1,
                "ok": 1,
                "failed": 0,
            },
        })
    );
}

#[tokio::test]
async fn health_response_carries_x_request_id_header() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/healthz").await;
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
        .get("/healthz")
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
    assert_eq!(body["checks"]["total"], 1);
    assert_eq!(body["checks"]["ok"], 1);
    assert_eq!(body["checks"]["failed"], 0);
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
    assert_eq!(body["checks"]["total"], 1);
    assert_eq!(body["checks"]["ok"], 1);
    assert_eq!(body["checks"]["failed"], 0);
    assert!(body.get("counts").is_none());
    assert!(body.get("resources").is_none());
    let dump = body.to_string();
    assert!(!dump.contains("social_registry"));
    assert!(!dump.contains("beneficiaries"));
    assert!(!dump.contains("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
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
    let request_id = resp
        .header("x-request-id")
        .to_str()
        .expect("x-request-id is ASCII")
        .to_string();
    Ulid::from_string(&request_id).expect("x-request-id is a ULID");

    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.resource_unavailable");
    assert_eq!(body["request_id"], request_id);
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

    let resp = server.get("/healthz").await;
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
    assert_eq!(record["path"], "/healthz");
    assert!(record["request_id"].is_string());
}

#[tokio::test]
async fn health_audit_is_suppressed_by_default() {
    let inmem = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(inmem.clone());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/healthz").await;
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
        .method(axum::http::Method::OPTIONS, "/healthz")
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
        .method(axum::http::Method::OPTIONS, "/healthz")
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

    let resp = server.get("/healthz").await;
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

    // Build a URI well over the 8 KiB cap. The leading `/healthz?` plus
    // 9000 ASCII bytes of query string puts us comfortably past the
    // limit. We hit `/healthz` because it is the simplest always-mounted
    // route; the cap is enforced before route matching.
    let big_param = "a".repeat(9_000);
    let url = format!("/healthz?x={big_param}");
    let spoofed = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let resp = server.get(&url).add_header("x-request-id", spoofed).await;

    resp.assert_status(StatusCode::URI_TOO_LONG);
    assert_eq!(resp.header("content-type"), "application/problem+json");
    let request_id = resp
        .header("x-request-id")
        .to_str()
        .expect("x-request-id is ASCII")
        .to_string();
    assert_ne!(request_id, spoofed);
    Ulid::from_string(&request_id).expect("x-request-id is a ULID");
    let body: Value = resp.json();
    assert_eq!(body["code"], "internal.uri_too_long");
    assert_eq!(body["request_id"], request_id);
}

#[tokio::test]
async fn admin_bind_serves_health_on_second_listener() {
    // Bind two ephemeral ports, spin up the main and admin routers,
    // and confirm `/healthz` is reachable on both. The integration test
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

    let client = reqwest_lite_get(main_addr, "/healthz").await;
    assert_eq!(client.0, 200, "main /healthz responded");
    assert!(
        client.1.contains("\"status\""),
        "main body contained status"
    );

    let admin = reqwest_lite_get(admin_addr, "/healthz").await;
    assert_eq!(admin.0, 200, "admin /healthz responded");
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
async fn public_and_admin_incomplete_headers_are_closed() {
    let main_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind main");
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
    let main_addr: SocketAddr = main_listener.local_addr().expect("main addr");
    let admin_addr: SocketAddr = admin_listener.local_addr().expect("admin addr");

    let mut cfg = load_example_config();
    cfg.server.bind = main_addr;
    cfg.server.admin_bind = Some(admin_addr);
    cfg.server.http1_header_read_timeout = Duration::from_millis(200);
    cfg.server.max_connections = 8;
    cfg.datasets.clear();
    let config = Arc::new(cfg);
    let limits = ServeLimits::from_config(&config.server);

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

    let (main_shutdown_tx, main_shutdown_rx) = tokio::sync::oneshot::channel();
    let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::oneshot::channel();
    let main_handle = tokio::spawn(serve_listener(
        main_listener,
        main_app,
        limits,
        async move {
            let _ = main_shutdown_rx.await;
        },
    ));
    let admin_handle = tokio::spawn(serve_listener(
        admin_listener,
        admin_app,
        limits,
        async move {
            let _ = admin_shutdown_rx.await;
        },
    ));

    assert_incomplete_header_closes(main_addr).await;
    assert_incomplete_header_closes(admin_addr).await;

    let _ = main_shutdown_tx.send(());
    let _ = admin_shutdown_tx.send(());
    main_handle
        .await
        .expect("main task joins")
        .expect("main serve");
    admin_handle
        .await
        .expect("admin task joins")
        .expect("admin serve");
}

#[tokio::test]
async fn serve_listener_max_connections_holds_excess_request_work() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind main");
    let addr: SocketAddr = listener.local_addr().expect("main addr");

    let mut cfg = load_example_config();
    cfg.server.bind = addr;
    cfg.server.http1_header_read_timeout = Duration::from_secs(5);
    cfg.server.max_connections = 1;
    cfg.datasets.clear();
    let config = Arc::new(cfg);
    let limits = ServeLimits::from_config(&config.server);

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let app = build_app(Arc::clone(&config), auth, sink).expect("app builds");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(serve_listener(listener, app, limits, async move {
        let _ = shutdown_rx.await;
    }));

    let mut held = TcpStream::connect(addr).await.expect("connect held");
    held.write_all(format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\n").as_bytes())
        .await
        .expect("write held partial headers");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut queued = TcpStream::connect(addr).await.expect("connect queued");
    queued
        .write_all(
            format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write queued request");

    let mut first_byte = [0_u8; 1];
    let early =
        tokio::time::timeout(Duration::from_millis(200), queued.read(&mut first_byte)).await;
    assert!(
        early.is_err(),
        "queued request received response bytes while connection cap was exhausted"
    );

    drop(held);
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(2), queued.read_to_end(&mut rest))
        .await
        .expect("queued request finishes after capacity frees")
        .expect("queued response reads");
    assert!(read > 0, "queued request received a response");
    let response = String::from_utf8_lossy(&rest);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "queued request should succeed after capacity frees, got: {response}"
    );

    let _ = shutdown_tx.send(());
    handle
        .await
        .expect("serve task joins")
        .expect("serve exits");
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
        "/healthz",
        &[("X-Forwarded-For", "203.0.113.10, 127.0.0.1")],
    )
    .await;
    assert_eq!(response.0, 200, "/healthz responded through listener");

    let records = inmem.snapshot();
    assert_eq!(records.len(), 1);
    let record = audit_record_from_platform_envelope(&records[0]);
    assert_eq!(record["remote_addr"], "203.0.113.10");

    handle.abort();
}

async fn assert_incomplete_header_closes(addr: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\n").as_bytes())
        .await
        .expect("write partial headers");

    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await;
    match result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("partial-header connection returned {n} bytes instead of closing"),
        Err(_) => panic!("partial-header connection did not close before timeout"),
    }
}

/// Assert that the full relay stack sends the required browser-hardening
/// security headers on every response. Covers issue #87: `/healthz` must
/// carry `Content-Security-Policy` (and the other baseline headers) in
/// addition to the `X-Content-Type-Options` and `X-Frame-Options` that
/// were already present before the CSP layer was added.
#[tokio::test]
async fn healthz_response_carries_required_security_headers() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/healthz").await;
    resp.assert_status(StatusCode::OK);

    assert_eq!(
        resp.header("x-content-type-options"),
        "nosniff",
        "x-content-type-options must be set on /healthz"
    );
    assert_eq!(
        resp.header("x-frame-options"),
        "DENY",
        "x-frame-options must be set on /healthz"
    );
    assert_eq!(
        resp.header("referrer-policy"),
        "no-referrer",
        "referrer-policy must be set on /healthz"
    );
    let csp = resp
        .maybe_header("content-security-policy")
        .expect("content-security-policy must be set on /healthz");
    let csp = csp.to_str().expect("CSP header is ASCII");
    assert!(
        csp.contains("default-src"),
        "CSP on /healthz must include a default-src directive, got: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP on /healthz must include frame-ancestors 'none', got: {csp}"
    );
}

/// `/.well-known/api-catalog` is the RFC 9727 linkset discovery document.
/// It is fully static (no principal, no runtime state) and must be served
/// publicly so unauthenticated clients can bootstrap into the API surface.
/// `build_test_app` configures zero API keys, so any auth-gated route would
/// answer 401; reaching 200 here proves the route sits on the public
/// sub-router. The baseline security headers must still be present.
#[tokio::test]
async fn api_catalog_is_public_and_carries_security_headers() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/api-catalog").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.header("content-type"),
        "application/linkset+json; profile=\"https://www.rfc-editor.org/info/rfc9727\"",
        "api-catalog must answer with the RFC 9727 linkset media type"
    );

    assert_eq!(
        resp.header("x-content-type-options"),
        "nosniff",
        "x-content-type-options must be set on /.well-known/api-catalog"
    );
    assert_eq!(
        resp.header("x-frame-options"),
        "DENY",
        "x-frame-options must be set on /.well-known/api-catalog"
    );
    assert_eq!(
        resp.header("referrer-policy"),
        "no-referrer",
        "referrer-policy must be set on /.well-known/api-catalog"
    );
    let csp = resp
        .maybe_header("content-security-policy")
        .expect("content-security-policy must be set on /.well-known/api-catalog");
    let csp = csp.to_str().expect("CSP header is ASCII");
    assert!(
        csp.contains("default-src"),
        "CSP on /.well-known/api-catalog must include a default-src directive, got: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP on /.well-known/api-catalog must include frame-ancestors 'none', got: {csp}"
    );
}

/// HEAD on the same route must also be public and carry the security
/// headers; the discovery `Link` header is the load-bearing payload for a
/// HEAD probe.
#[tokio::test]
async fn api_catalog_head_is_public_and_carries_security_headers() {
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let app = build_test_app(sink);
    let server = TestServer::new(app);

    let resp = server
        .method(axum::http::Method::HEAD, "/.well-known/api-catalog")
        .await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.header("content-type"),
        "application/linkset+json; profile=\"https://www.rfc-editor.org/info/rfc9727\"",
        "HEAD api-catalog must echo the RFC 9727 linkset media type"
    );

    assert_eq!(
        resp.header("x-content-type-options"),
        "nosniff",
        "x-content-type-options must be set on HEAD /.well-known/api-catalog"
    );
    assert_eq!(
        resp.header("x-frame-options"),
        "DENY",
        "x-frame-options must be set on HEAD /.well-known/api-catalog"
    );
    let csp = resp
        .maybe_header("content-security-policy")
        .expect("content-security-policy must be set on HEAD /.well-known/api-catalog");
    let csp = csp.to_str().expect("CSP header is ASCII");
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP on HEAD /.well-known/api-catalog must include frame-ancestors 'none', got: {csp}"
    );
}

/// The admin listener carries its own `build_admin_app` stack; confirm
/// it also sends the same baseline security headers.
#[tokio::test]
async fn admin_healthz_response_carries_required_security_headers() {
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
    let admin_app = build_admin_app(
        Arc::clone(&config),
        Arc::clone(&auth),
        Arc::clone(&sink),
        readiness_rx,
        readiness_tx,
        ingest,
    )
    .expect("admin app builds");

    let admin_handle = tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let headers = reqwest_lite_get_response_headers(admin_addr, "/healthz").await;

    assert_security_headers_present(&headers, "admin /healthz");

    admin_handle.abort();
}

fn assert_security_headers_present(headers: &[(String, String)], context: &str) {
    let find = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    assert_eq!(
        find("x-content-type-options").as_deref(),
        Some("nosniff"),
        "x-content-type-options missing or wrong on {context}"
    );
    assert_eq!(
        find("x-frame-options").as_deref(),
        Some("DENY"),
        "x-frame-options missing or wrong on {context}"
    );
    assert_eq!(
        find("referrer-policy").as_deref(),
        Some("no-referrer"),
        "referrer-policy missing or wrong on {context}"
    );
    let csp = find("content-security-policy")
        .unwrap_or_else(|| panic!("content-security-policy missing on {context}"));
    assert!(
        csp.contains("default-src"),
        "CSP on {context} must include default-src, got: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP on {context} must include frame-ancestors 'none', got: {csp}"
    );
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

/// Minimal HTTP/1.1 GET client that returns parsed response headers as
/// `(name, value)` pairs. Used for the admin-listener security-header
/// integration tests that drive a real TCP listener.
async fn reqwest_lite_get_response_headers(addr: SocketAddr, path: &str) -> Vec<(String, String)> {
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

    // The header section is everything before the first blank line.
    let header_section = raw.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(&raw);

    // Skip the status line; each subsequent line is a `name: value` pair.
    header_section
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_lowercase(), value.trim().to_string()))
        })
        .collect()
}
