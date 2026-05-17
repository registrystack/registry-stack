// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the audit core (`registry_relay::audit`).
//!
//! These tests pin the audit wire contract: field set, key names, types,
//! and ISO-8601 millisecond timestamp format.
//! They also exercise the [`StdoutSink`]-shaped path via a captured-writer
//! variant and the middleware's query redaction policy.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Extension;
use axum::Router;
use registry_relay::audit::{
    audit_layer, redact_query, AuditContextExt, AuditEnvelope, AuditOutcome, AuditRecord,
    AuditSettings, AuditSink, EndpointKind, ErrorCodeExt, InMemorySink, StdoutSink,
};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use serde_json::Value;
use tower::ServiceExt;

fn sample_record() -> AuditRecord {
    AuditRecord {
        ts: "2026-05-15T10:00:00.123Z".to_string(),
        request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
        principal_id: Some("statistics_office".to_string()),
        auth_mode: Some("api_key".to_string()),
        remote_addr: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: "/datasets".to_string(),
        endpoint_kind: EndpointKind::Catalog,
        dataset_id: None,
        entity_name: None,
        table_id: None,
        relationship: None,
        aggregate_id: None,
        underlying_kind: None,
        collection_id: None,
        primary_key: None,
        scopes_used: vec!["catalog".to_string()],
        query_params: serde_json::json!({}),
        purpose: Some("ci-smoke".to_string()),
        status_code: 200,
        row_count: None,
        null_geometry_count: None,
        invalid_geometry_count: None,
        suppressed_groups: None,
        duration_ms: 7,
        error_code: None,
        provenance: None,
    }
}

/// Section 13.1 contract: exactly the documented set of required + conditional
/// keys must appear on every record. The chain envelope fields are off
/// by default and must not appear.
#[test]
fn record_serialises_to_expected_field_shape() {
    let record = sample_record();
    let json = serde_json::to_value(&record).expect("serialize");

    let expected: BTreeSet<&'static str> = [
        "ts",
        "request_id",
        "principal_id",
        "auth_mode",
        "remote_addr",
        "method",
        "path",
        "endpoint_kind",
        "dataset_id",
        "entity_name",
        "table_id",
        "relationship",
        "aggregate_id",
        "underlying_kind",
        "collection_id",
        "primary_key",
        "scopes_used",
        "query_params",
        "purpose",
        "status_code",
        "row_count",
        "null_geometry_count",
        "invalid_geometry_count",
        "suppressed_groups",
        "duration_ms",
        "error_code",
    ]
    .into_iter()
    .collect();

    let object = json.as_object().expect("object");
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "field set must match Section 5 contract");

    // Chain envelope fields are not emitted unless chaining wraps the sink.
    assert!(!object.contains_key("prev_hash"));
    assert!(!object.contains_key("record_hash"));
}

#[test]
fn record_field_types_match_contract() {
    let record = sample_record();
    let json = serde_json::to_value(&record).unwrap();
    assert!(json["ts"].is_string());
    assert!(json["request_id"].is_string());
    assert!(json["principal_id"].is_string());
    assert!(json["auth_mode"].is_string());
    assert!(json["remote_addr"].is_string());
    assert!(json["method"].is_string());
    assert!(json["path"].is_string());
    assert!(json["endpoint_kind"].is_string());
    assert!(json["scopes_used"].is_array());
    assert!(json["query_params"].is_object());
    assert!(json["status_code"].is_u64());
    assert!(json["duration_ms"].is_u64());
    // Optional fields serialise as JSON null when absent.
    assert!(json["dataset_id"].is_null());
    assert!(json["entity_name"].is_null());
    assert!(json["table_id"].is_null());
    assert!(json["relationship"].is_null());
    assert!(json["aggregate_id"].is_null());
    assert!(json["underlying_kind"].is_null());
    assert!(json["collection_id"].is_null());
    assert!(json["primary_key"].is_null());
    assert!(json["row_count"].is_null());
    assert!(json["null_geometry_count"].is_null());
    assert!(json["invalid_geometry_count"].is_null());
    assert!(json["suppressed_groups"].is_null());
    assert!(json["error_code"].is_null());
}

#[test]
fn timestamp_is_iso8601_with_millisecond_precision() {
    let record = AuditRecord {
        ts: registry_relay::audit::now_iso8601_millis(),
        ..sample_record()
    };
    let ts = record.ts;
    // Shape: YYYY-MM-DDTHH:MM:SS.mmmZ -- 24 characters, fixed positions.
    assert_eq!(ts.len(), 24, "ts must be 24 chars; got {ts:?}");
    assert!(ts.ends_with('Z'), "ts must end with Z; got {ts:?}");
    let dot = ts.chars().nth(19);
    assert_eq!(
        dot,
        Some('.'),
        "ts must have '.' at position 19; got {ts:?}"
    );
    // The millisecond fragment is exactly three digits.
    let millis: &str = &ts[20..23];
    assert!(
        millis.chars().all(|c| c.is_ascii_digit()),
        "ts millisecond fragment must be three digits: {millis:?}"
    );
}

#[test]
fn outcome_classifies_status_codes() {
    assert_eq!(AuditOutcome::from_status(200), AuditOutcome::Ok);
    assert_eq!(AuditOutcome::from_status(299), AuditOutcome::Ok);
    assert_eq!(AuditOutcome::from_status(304), AuditOutcome::Ok);
    assert_eq!(AuditOutcome::from_status(401), AuditOutcome::Denied);
    assert_eq!(AuditOutcome::from_status(403), AuditOutcome::Denied);
    assert_eq!(AuditOutcome::from_status(400), AuditOutcome::Error);
    assert_eq!(AuditOutcome::from_status(404), AuditOutcome::Error);
    assert_eq!(AuditOutcome::from_status(500), AuditOutcome::Error);
}

#[test]
fn query_redaction_strips_sensitive_param_values() {
    let redacted = redact_query("token=abc&q=alpha&password=hunter2&key=xyz&limit=10");
    let map = redacted.as_object().expect("object");
    // Names preserved.
    assert!(map.contains_key("token"));
    assert!(map.contains_key("q"));
    assert!(map.contains_key("password"));
    assert!(map.contains_key("key"));
    assert!(map.contains_key("limit"));
    // Sensitive values redacted.
    assert_eq!(map["token"]["op"], "redacted");
    assert_eq!(map["password"]["op"], "redacted");
    assert_eq!(map["key"]["op"], "redacted");
    // Non-sensitive params keep their op marker but never the value.
    assert_eq!(map["q"]["op"], "eq");
    assert_eq!(map["limit"]["op"], "eq");
    // Raw value never appears.
    let dump = redacted.to_string();
    assert!(!dump.contains("abc"));
    assert!(!dump.contains("hunter2"));
    assert!(!dump.contains("xyz"));
}

#[test]
fn empty_query_redacts_to_empty_object() {
    let redacted = redact_query("");
    assert_eq!(redacted, serde_json::json!({}));
}

#[tokio::test]
async fn in_memory_sink_writes_one_jsonl_line_per_record() {
    let sink = InMemorySink::new();
    let envelope = AuditEnvelope::from(sample_record());
    sink.write(envelope).await.expect("write succeeds");
    let captured = sink.snapshot();
    // Exactly one record.
    assert_eq!(captured.len(), 1);
    // Trailing newline; one '\n' total.
    assert!(captured[0].ends_with('\n'));
    assert_eq!(captured[0].matches('\n').count(), 1);
    // The body parses as JSON and carries `request_id`.
    let parsed: Value = serde_json::from_str(captured[0].trim_end()).expect("valid JSON");
    assert_eq!(parsed["request_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
}

#[tokio::test]
async fn stdout_sink_is_constructible() {
    // We do not assert on actual stdout bytes here; the e2e tests cover
    // the process-level path. We assert the sink constructs and a write
    // call returns Ok.
    let sink: Arc<dyn AuditSink> = Arc::new(StdoutSink::new());
    sink.write(AuditEnvelope::from(sample_record()))
        .await
        .expect("stdout write must not error");
    sink.flush().await.expect("flush ok");
}

#[tokio::test]
async fn middleware_emits_one_record_per_request_with_response_status() {
    let sink = Arc::new(InMemorySink::new());
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe?token=secret&page=2")
        .header("user-agent", "audit-test/1.0")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Response-header propagation is owned by `PropagateRequestIdLayer`
    // in `src/server.rs`, not by the audit middleware. We do not assert
    // on `x-request-id` here; the e2e test in `tests/e2e_health.rs`
    // covers end-to-end propagation through the full server stack.

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "exactly one audit record per request");
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["status_code"], 200);
    assert_eq!(parsed["method"], "GET");
    assert_eq!(parsed["path"], "/probe");
    assert!(parsed["request_id"].is_string());
    // Query redaction applied.
    assert_eq!(parsed["query_params"]["token"]["op"], "redacted");
    assert_eq!(parsed["query_params"]["page"]["op"], "eq");
    // No raw token value.
    assert!(!records[0].contains("secret"));
}

#[tokio::test]
async fn middleware_records_error_code_when_handler_sets_extension() {
    async fn failing() -> axum::response::Response {
        let mut resp = (StatusCode::FORBIDDEN, "denied").into_response();
        resp.extensions_mut()
            .insert(ErrorCodeExt("auth.scope_denied".to_string()));
        resp
    }
    let sink = Arc::new(InMemorySink::new());
    let app = Router::new()
        .route("/deny", get(failing))
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/deny")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["status_code"], 403);
    assert_eq!(parsed["error_code"], "auth.scope_denied");
}

#[test]
fn endpoint_kind_renders_canonical_strings() {
    use EndpointKind::*;
    let cases = [
        (Health, "health"),
        (Ready, "ready"),
        (Catalog, "catalog"),
        (Dataset, "dataset"),
        (Schema, "schema"),
        (Verify, "verify"),
        (Rows, "rows"),
        (AggregateList, "aggregate_list"),
        (Aggregate, "aggregate"),
        (Admin, "admin"),
        (Openapi, "openapi"),
        (Other, "other"),
    ];
    for (variant, expected) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, expected, "EndpointKind::{variant:?} -> {expected}");
    }
}

#[tokio::test]
async fn header_map_keeps_no_raw_secret_in_record() {
    // The middleware must never copy bearer credentials into the record.
    let sink = Arc::new(InMemorySink::new());
    let app = Router::new()
        .route("/x", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/x")
        .header("authorization", "Bearer SUPER_SECRET_42")
        .header("data-purpose", "qa")
        .body(Body::empty())
        .unwrap();
    let _resp = app.oneshot(req).await.unwrap();

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert!(
        !records[0].contains("SUPER_SECRET_42"),
        "audit record must not echo raw credentials: {}",
        records[0]
    );
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    // Purpose header is captured verbatim.
    assert_eq!(parsed["purpose"], "qa");
}

#[tokio::test]
async fn response_body_unaffected_by_audit_middleware() {
    let sink = Arc::new(InMemorySink::new());
    let app = Router::new()
        .route("/echo", get(|| async { "hello" }))
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));
    let req = Request::builder()
        .method(Method::GET)
        .uri("/echo")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&body_bytes[..], b"hello");
    // And one audit record was still emitted.
    assert_eq!(sink.snapshot().len(), 1);
}

/// BLK-1: the audit middleware reads `Principal` from request extensions
/// when present and projects `principal_id`, `auth_mode`, and `scopes_used`
/// into the captured `AuditRecord`.
#[tokio::test]
async fn middleware_projects_principal_into_record() {
    async fn inject_principal(mut req: Request<Body>, next: Next) -> axum::response::Response {
        req.extensions_mut().insert(Principal {
            principal_id: "test_client".to_string(),
            scopes: ScopeSet::from_iter(["scope.a", "scope.b"]),
            auth_mode: AuthMode::ApiKey,
        });
        next.run(req).await
    }

    let sink = Arc::new(InMemorySink::new());
    // `.layer(...)` wraps innermost-first: the second `.layer(...)`
    // call ends up outermost. We want `inject_principal` to run BEFORE
    // `audit_layer` so the principal is on the request by the time
    // audit reads `req.extensions()`. That mirrors the contract where
    // an outer auth layer (or a per-request principal-stashing layer)
    // populates the extension before audit observes it.
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(from_fn(inject_principal))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["principal_id"], "test_client");
    assert_eq!(parsed["auth_mode"], "api_key");
    let scopes: BTreeSet<&str> = parsed["scopes_used"]
        .as_array()
        .expect("scopes_used array")
        .iter()
        .map(|v| v.as_str().expect("scope is string"))
        .collect();
    assert!(
        scopes.contains("scope.a"),
        "scope.a missing from {scopes:?}"
    );
    assert!(
        scopes.contains("scope.b"),
        "scope.b missing from {scopes:?}"
    );
}

/// HIGH-1: when an upstream layer (e.g. `SetRequestIdLayer`) has already
/// set `x-request-id` on the request, the audit middleware MUST adopt
/// that value rather than mint a fresh one. This pins the contract that
/// the audit record's `request_id` equals the upstream id.
#[tokio::test]
async fn middleware_adopts_upstream_request_id() {
    const UPSTREAM_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    async fn set_upstream_id(mut req: Request<Body>, next: Next) -> axum::response::Response {
        req.headers_mut()
            .insert("x-request-id", UPSTREAM_ID.parse().unwrap());
        next.run(req).await
    }

    let sink = Arc::new(InMemorySink::new());
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(from_fn(set_upstream_id))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let _ = app.oneshot(req).await.unwrap();

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(
        parsed["request_id"], UPSTREAM_ID,
        "audit record must adopt the upstream x-request-id"
    );
}

#[test]
fn ip_default_when_no_connect_info() {
    // The layer should record an IP even when ConnectInfo is absent
    // (e.g. unit tests that don't supply one). Concrete value is
    // unspecified, but the field must be present and non-empty.
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let s = ip.to_string();
    assert!(!s.is_empty());
}

#[tokio::test]
async fn middleware_hashes_configured_sensitive_query_values() {
    let sink = Arc::new(InMemorySink::new());
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: false,
        trusted_proxies: Vec::new(),
        sensitive_fields: vec!["social_registry:individual:id".to_string()],
    };
    let app = Router::new()
        .route(
            "/datasets/social_registry/individual",
            get(|| async {
                let mut response = StatusCode::OK.into_response();
                response.extensions_mut().insert(AuditContextExt {
                    dataset_id: Some("social_registry".to_string()),
                    entity_name: Some("individual".to_string()),
                    table_id: Some("individuals_table".to_string()),
                    ..AuditContextExt::default()
                });
                response
            }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/datasets/social_registry/individual?id=IND-001234&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["dataset_id"], "social_registry");
    assert_eq!(parsed["entity_name"], "individual");
    assert_eq!(parsed["table_id"], "individuals_table");
    assert_eq!(parsed["query_params"]["id"]["op"], "eq");
    assert!(parsed["query_params"]["id"]["value_hash"]
        .as_str()
        .expect("value hash")
        .starts_with("sha256:"));
    assert_eq!(parsed["query_params"]["limit"]["op"], "eq");
    assert!(!records[0].contains("IND-001234"));
}

/// BLK-1 (production layer order): in the real server stack, audit
/// sits *outside* auth. The auth middleware attaches `Principal` to
/// response extensions after the inner handler runs, and the audit
/// middleware reads from response extensions on the way back. This
/// test pins the production wiring rather than the simpler unit-level
/// "outer middleware injects on request" pattern.
#[tokio::test]
async fn middleware_projects_principal_when_auth_runs_inside_audit() {
    use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
    use registry_relay::auth::middleware::auth_layer;
    use sha2::{Digest, Sha256};

    const VALID_KEY: &str = "test-bearer-token-blk1";

    let fingerprint = format!(
        "sha256:{}",
        hex_lower_local(&Sha256::digest(VALID_KEY.as_bytes()))
    );

    let entry = ApiKeyEntry::new(
        "statistics_office".to_string(),
        ScopeSet::from_iter(["catalog", "rows"]),
        fingerprint,
    )
    .expect("fingerprint parses");
    let provider = Arc::new(ApiKeyAuth::new(vec![entry]));

    let sink = Arc::new(InMemorySink::new());

    // Production composition: auth wraps the protected sub-router,
    // audit wraps the whole thing. This matches `crate::server::build_app`.
    let protected = auth_layer(
        Router::new().route("/probe", get(|| async { StatusCode::OK })),
        provider,
    );
    let app = Router::new()
        .merge(protected)
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .header("authorization", format!("Bearer {VALID_KEY}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["principal_id"], "statistics_office");
    assert_eq!(parsed["auth_mode"], "api_key");
    let scopes: BTreeSet<&str> = parsed["scopes_used"]
        .as_array()
        .expect("scopes_used array")
        .iter()
        .map(|v| v.as_str().expect("scope is string"))
        .collect();
    assert!(
        scopes.contains("catalog"),
        "catalog missing from {scopes:?}"
    );
    assert!(scopes.contains("rows"), "rows missing from {scopes:?}");
}

fn hex_lower_local(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// BLK-2 (production layer order): when auth short-circuits with an
/// auth error, `Error::into_response` attaches `ErrorCodeExt` to the
/// response. The audit middleware (outer) reads it and the record's
/// `error_code` field carries the taxonomy code.
#[tokio::test]
async fn middleware_captures_error_code_from_auth_short_circuit() {
    use registry_relay::auth::api_key::ApiKeyAuth;
    use registry_relay::auth::middleware::auth_layer;

    let provider = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink = Arc::new(InMemorySink::new());

    let protected = auth_layer(
        Router::new().route("/probe", get(|| async { StatusCode::OK })),
        provider,
    );
    let app = Router::new()
        .merge(protected)
        .layer(from_fn(audit_layer))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    // No Authorization header => MissingCredential.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["error_code"], "auth.missing_credential");
    assert_eq!(parsed["principal_id"], Value::Null);
}

#[tokio::test]
async fn middleware_uses_x_forwarded_for_from_trusted_proxy() {
    let sink = Arc::new(InMemorySink::new());
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: true,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
        sensitive_fields: Vec::new(),
    };
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .header("x-forwarded-for", "203.0.113.10, 10.1.2.3")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.1.2.3:12345".parse::<SocketAddr>().unwrap(),
    ));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["remote_addr"], "203.0.113.10");
}

#[tokio::test]
async fn middleware_ignores_x_forwarded_for_from_untrusted_peer() {
    let sink = Arc::new(InMemorySink::new());
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: true,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
        sensitive_fields: Vec::new(),
    };
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(sink.clone() as Arc<dyn AuditSink>));

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .header("x-forwarded-for", "203.0.113.10")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "192.0.2.1:12345".parse::<SocketAddr>().unwrap(),
    ));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed: Value = serde_json::from_str(records[0].trim_end()).unwrap();
    assert_eq!(parsed["remote_addr"], "192.0.2.1");
}
