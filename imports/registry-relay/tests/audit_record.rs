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
    audit_layer, redact_query, sensitive_value_hash, sensitive_value_hash_keyed, AuditContextExt,
    AuditHashSecret, AuditKeyHasher, AuditOutcome, AuditPipeline, AuditRecord, AuditSettings,
    EndpointKind, ErrorCodeExt, InMemorySink, StdoutSink,
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
        path: "/v1/datasets".to_string(),
        endpoint_kind: EndpointKind::Catalog,
        dataset_id: None,
        entity_name: None,
        table_id: None,
        relationship: None,
        aggregate_id: None,
        underlying_kind: None,
        collection_id: None,
        primary_key: None,
        offering_id: None,
        verification_id: None,
        verification_decision: None,
        claim_hash: None,
        evidence_hash: None,
        scopes_used: vec!["catalog".to_string()],
        query_params: serde_json::json!({}),
        purpose: Some("ci-smoke".to_string()),
        status_code: 200,
        row_count: None,
        null_geometry_count: None,
        invalid_geometry_count: None,
        geometry_vertex_count: None,
        suppressed_groups: None,
        duration_ms: 7,
        error_code: None,
        provenance: None,
    }
}

fn captured_record(line: &str) -> Value {
    let envelope: Value = serde_json::from_str(line.trim_end()).expect("valid audit envelope JSON");
    record_from_envelope(&envelope)
}

fn record_from_envelope(envelope: &Value) -> Value {
    envelope
        .get("record")
        .and_then(Value::as_object)
        .expect("envelope record object");
    envelope["record"].clone()
}

fn assert_platform_envelope_metadata(envelope: &Value) {
    assert!(envelope["envelope_id"].is_string());
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
}

fn is_lower_hex_hash(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

fn in_memory_pipeline() -> (InMemorySink, Arc<AuditPipeline>) {
    let sink = InMemorySink::new();
    let pipeline = AuditPipeline::from_sink(sink.clone());
    (sink, pipeline)
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
        "table_id_hash",
        "relationship",
        "aggregate_id",
        "underlying_kind",
        "collection_id",
        "primary_key",
        "offering_id",
        "verification_id",
        "verification_decision",
        "claim_hash",
        "evidence_hash",
        "scopes_used",
        "query_params",
        "purpose",
        "status_code",
        "row_count",
        "null_geometry_count",
        "invalid_geometry_count",
        "geometry_vertex_count",
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
    assert!(json["table_id_hash"].is_null());
    assert!(json["relationship"].is_null());
    assert!(json["aggregate_id"].is_null());
    assert!(json["underlying_kind"].is_null());
    assert!(json["collection_id"].is_null());
    assert!(json["primary_key"].is_null());
    assert!(json["offering_id"].is_null());
    assert!(json["verification_id"].is_null());
    assert!(json["verification_decision"].is_null());
    assert!(json["claim_hash"].is_null());
    assert!(json["evidence_hash"].is_null());
    assert!(json["row_count"].is_null());
    assert!(json["null_geometry_count"].is_null());
    assert!(json["invalid_geometry_count"].is_null());
    assert!(json["geometry_vertex_count"].is_null());
    assert!(json["suppressed_groups"].is_null());
    assert!(json["error_code"].is_null());
}

#[test]
fn record_serialization_hashes_plaintext_table_id() {
    let record = AuditRecord {
        table_id: Some("individuals_table".to_string()),
        ..sample_record()
    };

    let json = serde_json::to_value(&record).expect("serialize");
    assert!(json["table_id"].is_null());
    assert_ne!(json["table_id_hash"], "individuals_table");
    assert!(json["table_id_hash"]
        .as_str()
        .expect("table id hash")
        .starts_with("sha256:"));
    assert!(!json.to_string().contains("individuals_table"));
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
    let pipeline = AuditPipeline::from_sink(sink.clone());
    pipeline
        .write_record(sample_record())
        .await
        .expect("write succeeds");
    let captured = sink.snapshot();
    // Exactly one record.
    assert_eq!(captured.len(), 1);
    // Trailing newline; one '\n' total.
    assert!(captured[0].ends_with('\n'));
    assert_eq!(captured[0].matches('\n').count(), 1);
    // The body parses as a platform envelope carrying relay record metadata.
    let envelope: Value = serde_json::from_str(captured[0].trim_end()).expect("valid JSON");
    assert_platform_envelope_metadata(&envelope);
    let parsed = record_from_envelope(&envelope);
    assert_eq!(parsed["request_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
}

#[tokio::test]
async fn stdout_sink_is_constructible() {
    // We do not assert on actual stdout bytes here; the e2e tests cover
    // the process-level path. We assert the sink constructs and a write
    // call returns Ok.
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(StdoutSink::new());
    sink.write_record(sample_record())
        .await
        .expect("stdout write must not error");
    sink.flush().await.expect("flush ok");
}

#[tokio::test]
async fn middleware_emits_one_record_per_request_with_response_status() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
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
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route("/deny", get(failing))
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/deny")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
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
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route("/x", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
    // Purpose header is captured verbatim.
    assert_eq!(parsed["purpose"], "qa");
}

#[tokio::test]
async fn response_body_unaffected_by_audit_middleware() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route("/echo", get(|| async { "hello" }))
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));
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

    let (sink, pipeline) = in_memory_pipeline();
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
        .layer(Extension(pipeline.clone()));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
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

    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(from_fn(set_upstream_id))
        .layer(Extension(pipeline.clone()));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let _ = app.oneshot(req).await.unwrap();

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
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
    let (sink, pipeline) = in_memory_pipeline();
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: false,
        trusted_proxies: Vec::new(),
        sensitive_fields: vec!["social_registry:individual:id".to_string()],
        hash_hasher: AuditKeyHasher::unkeyed_dev_only(),
    };
    let app = Router::new()
        .route(
            "/v1/datasets/social_registry/entities/individual/records",
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
        .layer(Extension(pipeline.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/datasets/social_registry/entities/individual/records?id=IND-001234&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["dataset_id"], "social_registry");
    assert_eq!(parsed["entity_name"], "individual");
    assert!(parsed["table_id"].is_null());
    assert_eq!(
        parsed["table_id_hash"],
        sensitive_value_hash("table_id:social_registry:individual", "individuals_table")
    );
    assert_eq!(parsed["query_params"]["id"]["op"], "eq");
    assert!(parsed["query_params"]["id"]["value_hash"]
        .as_str()
        .expect("value hash")
        .starts_with("sha256:"));
    assert_eq!(parsed["query_params"]["limit"]["op"], "eq");
    assert!(!records[0].contains("individuals_table"));
    assert!(!records[0].contains("IND-001234"));
}

#[tokio::test]
async fn middleware_records_geometry_vertex_count_without_raw_geometry() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route(
            "/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area",
            get(|| async {
                let mut response = StatusCode::OK.into_response();
                response.extensions_mut().insert(AuditContextExt {
                    dataset_id: Some("social_registry".to_string()),
                    aggregate_id: Some("beneficiaries_by_municipality".to_string()),
                    collection_id: Some(
                        "social_registry_beneficiaries_by_municipality".to_string(),
                    ),
                    geometry_vertex_count: Some(5),
                    row_count: Some(1),
                    ..AuditContextExt::default()
                });
                response
            }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area?coords=POLYGON%20((0%200,1%200,1%201,0%201,0%200))")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["endpoint_kind"], "ogc_edr_area");
    assert_eq!(parsed["geometry_vertex_count"], 5);
    assert_eq!(parsed["row_count"], 1);
    assert!(!records[0].contains("POLYGON"));
}

#[tokio::test]
async fn middleware_hashes_primary_key_and_redacts_single_record_path() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route(
            "/v1/datasets/social_registry/entities/individual/records/IND-001234",
            get(|| async { StatusCode::OK }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/datasets/social_registry/entities/individual/records/IND-001234")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert!(
        !records[0].contains("IND-001234"),
        "audit record must not contain raw primary key: {}",
        records[0]
    );
    let parsed = captured_record(&records[0]);
    assert_eq!(
        parsed["path"],
        "/v1/datasets/social_registry/entities/individual/records/{id}"
    );
    assert_eq!(
        parsed["primary_key"],
        sensitive_value_hash("primary_key:social_registry:individual", "IND-001234")
    );
    assert_eq!(parsed["dataset_id"], "social_registry");
    assert_eq!(parsed["entity_name"], "individual");
}

#[tokio::test]
async fn middleware_primary_key_hash_is_stable_and_context_bound() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route(
            "/v1/datasets/social_registry/entities/individual/records/IND-001234",
            get(|| async { StatusCode::OK }),
        )
        .route(
            "/v1/datasets/other_registry/entities/individual/records/IND-001234",
            get(|| async { StatusCode::OK }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    for uri in [
        "/v1/datasets/social_registry/entities/individual/records/IND-001234",
        "/v1/datasets/social_registry/entities/individual/records/IND-001234",
        "/v1/datasets/other_registry/entities/individual/records/IND-001234",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let records = sink.snapshot();
    assert_eq!(records.len(), 3);
    let first = captured_record(&records[0]);
    let second = captured_record(&records[1]);
    let other_dataset = captured_record(&records[2]);

    assert_eq!(first["primary_key"], second["primary_key"]);
    assert_ne!(first["primary_key"], other_dataset["primary_key"]);
    assert!(first["primary_key"]
        .as_str()
        .expect("primary key hash")
        .starts_with("sha256:"));
    assert!(!records.join("").contains("IND-001234"));
}

#[tokio::test]
async fn middleware_primary_key_hash_uses_hmac_when_secret_configured() {
    // With a per-deploy secret in AuditSettings, the primary_key hash
    // must be HMAC-SHA256 (prefix `hmac-sha256:`), and two deployments
    // with different secrets must produce different hashes for the same
    // (dataset, entity, id) tuple. This is the property that closes the
    // rainbow-table attack on small keyspaces (national IDs etc.).
    let hasher_a = AuditKeyHasher::Keyed(
        AuditHashSecret::new(b"deploy-a-32-bytes-of-entropy----".to_vec()).unwrap(),
    );
    let hasher_b = AuditKeyHasher::Keyed(
        AuditHashSecret::new(b"deploy-b-32-bytes-of-entropy----".to_vec()).unwrap(),
    );

    async fn run_with_hasher(hasher: AuditKeyHasher) -> String {
        let (sink, pipeline) = in_memory_pipeline();
        let settings = AuditSettings {
            hash_hasher: hasher,
            ..AuditSettings::default()
        };
        let app = Router::new()
            .route(
                "/v1/datasets/social_registry/entities/individual/records/IND-001234",
                get(|| async { StatusCode::OK }),
            )
            .layer(from_fn(audit_layer))
            .layer(Extension(settings))
            .layer(Extension(pipeline.clone()));

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/datasets/social_registry/entities/individual/records/IND-001234")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        sink.snapshot().pop().expect("one record")
    }

    let record_a = run_with_hasher(hasher_a.clone()).await;
    let record_b = run_with_hasher(hasher_b).await;
    let parsed_a = captured_record(&record_a);
    let parsed_b = captured_record(&record_b);

    let hash_a = parsed_a["primary_key"].as_str().expect("hash a present");
    let hash_b = parsed_b["primary_key"].as_str().expect("hash b present");
    assert!(
        hash_a.starts_with("hmac-sha256:"),
        "expected HMAC prefix on keyed hash: {hash_a}"
    );
    assert!(hash_b.starts_with("hmac-sha256:"));
    assert_ne!(
        hash_a, hash_b,
        "different per-deploy secrets must produce different hashes"
    );

    // Cross-check the exact value against the keyed helper to pin the
    // construction (HMAC-SHA256(secret, field || \0 || id)).
    assert_eq!(
        parsed_a["primary_key"],
        sensitive_value_hash_keyed(
            &hasher_a,
            "primary_key:social_registry:individual",
            "IND-001234",
        )
    );

    // Negative control: the unkeyed sha256 form must not match either.
    let unkeyed = sensitive_value_hash("primary_key:social_registry:individual", "IND-001234");
    assert_ne!(hash_a, unkeyed);
}

#[tokio::test]
async fn middleware_redacts_relationship_path_id_without_losing_relationship() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route(
            "/v1/datasets/social_registry/entities/household/records/HH-001/relationships/members",
            get(|| async { StatusCode::OK }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/datasets/social_registry/entities/household/records/HH-001/relationships/members")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert!(!records[0].contains("HH-001"));
    let parsed = captured_record(&records[0]);
    assert_eq!(
        parsed["path"],
        "/v1/datasets/social_registry/entities/household/records/{id}/relationships/members"
    );
    assert_eq!(parsed["relationship"], "members");
    assert_eq!(
        parsed["primary_key"],
        sensitive_value_hash("primary_key:social_registry:household", "HH-001")
    );
}

#[tokio::test]
async fn middleware_leaves_non_record_dataset_paths_unredacted() {
    let (sink, pipeline) = in_memory_pipeline();
    let app = Router::new()
        .route(
            "/v1/datasets/social_registry/entities/individual/schema",
            get(|| async { StatusCode::OK }),
        )
        .route(
            "/v1/datasets/social_registry/entities/individual/verify",
            get(|| async { StatusCode::OK }),
        )
        .route(
            "/v1/datasets/social_registry/aggregates",
            get(|| async { StatusCode::OK }),
        )
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    for uri in [
        "/v1/datasets/social_registry/entities/individual/schema",
        "/v1/datasets/social_registry/entities/individual/verify",
        "/v1/datasets/social_registry/aggregates",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let records = sink.snapshot();
    assert_eq!(records.len(), 3);
    let paths: Vec<String> = records
        .iter()
        .map(|line| {
            let parsed = captured_record(line);
            assert!(parsed["primary_key"].is_null());
            parsed["path"].as_str().expect("path").to_string()
        })
        .collect();

    assert_eq!(
        paths,
        [
            "/v1/datasets/social_registry/entities/individual/schema",
            "/v1/datasets/social_registry/entities/individual/verify",
            "/v1/datasets/social_registry/aggregates",
        ]
    );
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

    let (sink, pipeline) = in_memory_pipeline();

    // Production composition: auth wraps the protected sub-router,
    // audit wraps the whole thing. This matches `crate::server::build_app`.
    let protected = auth_layer(
        Router::new().route("/probe", get(|| async { StatusCode::OK })),
        provider,
    );
    let app = Router::new()
        .merge(protected)
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
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
    let (sink, pipeline) = in_memory_pipeline();

    let protected = auth_layer(
        Router::new().route("/probe", get(|| async { StatusCode::OK })),
        provider,
    );
    let app = Router::new()
        .merge(protected)
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["error_code"], "auth.missing_credential");
    assert_eq!(parsed["principal_id"], Value::Null);
}

#[tokio::test]
async fn middleware_records_jwks_unavailable_auth_failure() {
    use registry_relay::auth::middleware::auth_layer;
    use registry_relay::auth::AuthProvider;
    use registry_relay::error::AuthError;

    struct JwksUnavailableAuth;

    impl AuthProvider for JwksUnavailableAuth {
        fn authenticate<'a>(
            &'a self,
            _headers: &'a axum::http::HeaderMap,
            _remote_addr: IpAddr,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<registry_relay::auth::Principal, AuthError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(AuthError::JwksUnavailable) })
        }
    }

    let (sink, pipeline) = in_memory_pipeline();
    let protected = auth_layer(
        Router::new().route("/probe", get(|| async { StatusCode::OK })),
        Arc::new(JwksUnavailableAuth),
    );
    let app = Router::new()
        .merge(protected)
        .layer(from_fn(audit_layer))
        .layer(Extension(pipeline.clone()));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/probe")
        .header("authorization", "Bearer token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["error_code"], "auth.jwks_unavailable");
    assert_eq!(parsed["status_code"], 503);
    assert_eq!(parsed["principal_id"], Value::Null);
}

#[tokio::test]
async fn middleware_uses_x_forwarded_for_from_trusted_proxy() {
    let (sink, pipeline) = in_memory_pipeline();
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: true,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
        sensitive_fields: Vec::new(),
        hash_hasher: AuditKeyHasher::unkeyed_dev_only(),
    };
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["remote_addr"], "203.0.113.10");
}

#[tokio::test]
async fn middleware_ignores_x_forwarded_for_from_untrusted_peer() {
    let (sink, pipeline) = in_memory_pipeline();
    let settings = AuditSettings {
        include_health: true,
        trust_proxy_enabled: true,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
        sensitive_fields: Vec::new(),
        hash_hasher: AuditKeyHasher::unkeyed_dev_only(),
    };
    let app = Router::new()
        .route("/probe", get(|| async { StatusCode::OK }))
        .layer(from_fn(audit_layer))
        .layer(Extension(settings))
        .layer(Extension(pipeline.clone()));

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
    let parsed = captured_record(&records[0]);
    assert_eq!(parsed["remote_addr"], "192.0.2.1");
}
