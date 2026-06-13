// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::{to_bytes, Body},
    extract::Query,
    http::header,
    http::Request,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_test::TestServer;
use registry_notary_openfn_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const TOKEN: &str = "http-json-sidecar-token";
const TOKEN_HASH_ENV: &str = "HTTP_JSON_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "HTTP_JSON_ADAPTER_CREDENTIAL_JSON";
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

struct HttpJsonHarness {
    sidecar: TestServer,
    upstream_state: UpstreamState,
    _upstream: TestServer,
}

#[derive(Clone, Default)]
struct UpstreamState {
    seen: Arc<Mutex<Vec<Value>>>,
    in_flight: Arc<Mutex<usize>>,
    max_in_flight: Arc<Mutex<usize>>,
}

async fn person_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(json!({
        "id": id,
        "authorization": headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        "client_id": headers
            .get("x-client-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    }));

    let results = match id.as_str() {
        "person-123" | "smoke-person" => json!([
            {
                "national_id": id,
                "birth_date": "1990-01-01",
                "ignored_extra": "not-requested"
            }
        ]),
        "ambiguous-person" => json!([
            { "national_id": id, "birth_date": "1990-01-01" },
            { "national_id": id, "birth_date": "1992-02-02" }
        ]),
        _ => json!([]),
    };
    (StatusCode::OK, Json(json!({ "results": results })))
}

async fn person_post_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> (StatusCode, Json<Value>) {
    let bytes = to_bytes(request.into_body(), 8192)
        .await
        .expect("request body is captured");
    let body: Value = serde_json::from_slice(&bytes).expect("request body is JSON");
    let id = body
        .get("lookup")
        .and_then(|lookup| lookup.get("value"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    state.seen.lock().await.push(json!({
        "id": id,
        "body": body,
        "authorization": headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    }));
    (
        StatusCode::OK,
        Json(json!({
            "results": [{
                "national_id": id,
                "birth_date": "1990-01-01"
            }]
        })),
    )
}

async fn oversized_lookup(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    if query.get("id").map(String::as_str) == Some("smoke-person") {
        return Json(json!({
            "results": [{
                "national_id": "smoke-person",
                "birth_date": "1990-01-01"
            }]
        }));
    }
    Json(json!({ "results": ["x".repeat(4096)] }))
}

async fn status_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(json!({ "id": id }));
    match id.as_str() {
        "smoke-person" => (
            StatusCode::OK,
            Json(json!({
                "results": [{
                    "national_id": "smoke-person",
                    "birth_date": "1990-01-01"
                }]
            })),
        )
            .into_response(),
        "unauthorized-person" => (StatusCode::UNAUTHORIZED, Json(json!({}))).into_response(),
        "forbidden-person" => (StatusCode::FORBIDDEN, Json(json!({}))).into_response(),
        "rate-limited-person" => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "17")],
            Json(json!({})),
        )
            .into_response(),
        "rate-limited-no-header-person" => {
            (StatusCode::TOO_MANY_REQUESTS, Json(json!({}))).into_response()
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response(),
    }
}

async fn slow_lookup(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    if query.get("id").map(String::as_str) == Some("smoke-person") {
        return Json(json!({
            "results": [{
                "national_id": "smoke-person",
                "birth_date": "1990-01-01"
            }]
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    Json(json!({
        "results": [{
            "national_id": query.get("id").cloned().unwrap_or_default(),
            "birth_date": "1990-01-01"
        }]
    }))
}

async fn concurrent_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    if id == "smoke-person" {
        return Json(json!({
            "results": [{
                "national_id": "smoke-person",
                "birth_date": "1990-01-01"
            }]
        }));
    }
    {
        let mut in_flight = state.in_flight.lock().await;
        *in_flight += 1;
        let current = *in_flight;
        drop(in_flight);
        let mut max_in_flight = state.max_in_flight.lock().await;
        *max_in_flight = (*max_in_flight).max(current);
    }
    state.seen.lock().await.push(json!({ "id": id }));
    tokio::time::sleep(Duration::from_millis(50)).await;
    *state.in_flight.lock().await -= 1;
    Json(json!({
        "results": [{
            "national_id": id,
            "birth_date": "1990-01-01"
        }]
    }))
}

async fn native_batch_lookup(request: Request<Body>) -> (StatusCode, Json<Value>) {
    let bytes = to_bytes(request.into_body(), 8192)
        .await
        .expect("request body is captured");
    let body: Value = serde_json::from_slice(&bytes).expect("request body is JSON");
    native_batch_response(&body)
}

async fn tracked_native_batch_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    request: Request<Body>,
) -> (StatusCode, Json<Value>) {
    let bytes = to_bytes(request.into_body(), 8192)
        .await
        .expect("request body is captured");
    let body: Value = serde_json::from_slice(&bytes).expect("request body is JSON");
    state.seen.lock().await.push(json!({
        "items": body.get("items").cloned().unwrap_or(Value::Null),
    }));
    native_batch_response(&body)
}

fn native_batch_response(body: &Value) -> (StatusCode, Json<Value>) {
    assert!(body.get("configuration").is_none());
    assert!(!body.to_string().contains("target-secret"));
    let mut results = Vec::new();
    let mut emitted_person_123 = false;
    for item in body
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = item
            .get("values")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .unwrap_or_default();
        match id {
            "person-123" if !emitted_person_123 => {
                emitted_person_123 = true;
                results.push(json!({
                    "national_id": "person-123",
                    "birth_date": "1990-01-01",
                    "ignored_extra": "not-requested"
                }));
            }
            "person-123" => {}
            "ambiguous-person" => {
                results
                    .push(json!({ "national_id": "ambiguous-person", "birth_date": "1990-01-01" }));
                results
                    .push(json!({ "national_id": "ambiguous-person", "birth_date": "1992-02-02" }));
            }
            _ => {}
        }
    }
    results.push(json!({ "national_id": "unknown-person", "birth_date": "1999-09-09" }));
    (StatusCode::OK, Json(json!({ "results": results })))
}

async fn redirect_lookup(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(json!({ "id": id }));
    if id == "smoke-person" {
        return (
            StatusCode::OK,
            Json(json!({
                "results": [{
                    "national_id": "smoke-person",
                    "birth_date": "1990-01-01"
                }]
            })),
        )
            .into_response();
    }
    (
        StatusCode::FOUND,
        [(header::LOCATION, "/people?id=redirected-person")],
        Json(json!({})),
    )
        .into_response()
}

fn set_sidecar_env(base_url: &str) {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    std::env::set_var(
        CREDENTIAL_ENV,
        json!({
            "baseUrl": base_url,
            "clientId": "public-client",
            "apiToken": "target-secret",
            "username": "admin",
            "password": "district"
        })
        .to_string(),
    );
}

fn http_json_manifest(_base_url: &str, allowlist_url: &str) -> String {
    http_json_manifest_with_method(allowlist_url, "GET", "/people", 4096)
}

fn http_json_manifest_with_method(
    allowlist_url: &str,
    method: &str,
    path: &str,
    max_output_bytes: usize,
) -> String {
    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: {max_output_bytes}
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  http_people:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
      - baseUrl
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    http_json:
      method: {method}
      base_url:
        cel: credential_public.baseUrl
      path: {path}
      query:
        id:
          cel: lookup.value
      headers:
        x-client-id:
          cel: credential_public.clientId
      auth:
        type: bearer
        token:
          secret: apiToken
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        method = method,
        path = serde_json::to_string(path).expect("path serializes"),
        max_output_bytes = max_output_bytes,
    )
}

fn http_json_basic_auth_manifest(allowlist_url: &str) -> String {
    http_json_manifest(allowlist_url, allowlist_url).replace(
        r#"      auth:
        type: bearer
        token:
          secret: apiToken"#,
        r#"      auth:
        type: basic
        username:
          secret: username
        password:
          secret: password"#,
    )
}

fn http_json_manifest_with_source_limits(allowlist_url: &str) -> String {
    http_json_manifest(allowlist_url, allowlist_url).replace(
        "    allow_insecure_localhost: true",
        r#"    allow_insecure_localhost: true
    limits:
      requests_per_second: 1
      burst: 2"#,
    )
}

fn http_json_manifest_with_cache(allowlist_url: &str) -> String {
    http_json_manifest(allowlist_url, allowlist_url).replace(
        "    allow_insecure_localhost: true",
        r#"    allow_insecure_localhost: true
    cache:
      exact_match_ttl_ms: 60000
      not_found_ttl_ms: 60000"#,
    )
}

fn http_json_manifest_with_parallel_batch(allowlist_url: &str) -> String {
    http_json_manifest_with_method(allowlist_url, "GET", "/concurrent", 4096).replace(
        "    allow_insecure_localhost: true",
        r#"    allow_insecure_localhost: true
    batch:
      mode: parallel_lookup
      max_parallel: 2"#,
    )
}

fn http_json_manifest_with_native_batch(allowlist_url: &str) -> String {
    http_json_manifest_with_method(allowlist_url, "GET", "/people", 4096)
        .replace(
            "    allow_insecure_localhost: true",
            r#"    allow_insecure_localhost: true
    batch:
      mode: native_batch"#,
        )
        .replace(
            r#"      response:
        records:
          cel: body.results"#,
            r#"      response:
        records:
          cel: body.results
      batch:
        method: POST
        path: "/native"
        response:
          records:
            cel: body.results
          record_key:
            cel: record.national_id
          item_key:
            cel: item.values[0]"#,
        )
}

fn server_base_url(server: &TestServer) -> String {
    server
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string()
        .trim_end_matches('/')
        .to_string()
}

async fn http_json_harness() -> HttpJsonHarness {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .route("/people-post", post(person_post_lookup))
            .route("/oversized", get(oversized_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_manifest(&upstream_url, &upstream_url))
            .expect("http_json manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts and passes smoke lookup");
    let sidecar = TestServer::builder().http_transport().build(app);
    HttpJsonHarness {
        sidecar,
        upstream_state,
        _upstream: upstream,
    }
}

#[tokio::test]
async fn http_json_lookup_returns_projected_rda_data_without_worker() {
    let harness = http_json_harness().await;

    let response = harness
        .sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .add_query_param("limit", "2")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "birth_date": "1990-01-01"
            }]
        })
    );
    assert!(!response.text().contains("ignored_extra"));

    let seen = harness.upstream_state.seen.lock().await;
    let lookup = seen
        .iter()
        .find(|request| request["id"] == json!("person-123"))
        .expect("lookup reached upstream");
    assert_eq!(lookup["authorization"], json!("Bearer target-secret"));
    assert_eq!(lookup["client_id"], json!("public-client"));
}

#[tokio::test]
async fn http_json_reuses_clients_per_source_without_leaking_targets_in_metrics() {
    let harness = http_json_harness().await;

    for id in ["person-123", "missing-person"] {
        harness
            .sidecar
            .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
            .add_header("authorization", format!("Bearer {TOKEN}"))
            .add_header("data-purpose", "eligibility")
            .add_query_param("national_id", id)
            .add_query_param("fields", "national_id")
            .await
            .assert_status_ok();
    }

    let metrics = harness.sidecar.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics = metrics.text();
    assert!(metrics
        .contains("registry_notary_openfn_sidecar_http_json_clients{source_id=\"http_people\"} 1"));
    assert!(!metrics.contains("target-secret"));
    assert!(!metrics.contains("person-123"));
}

#[tokio::test]
async fn http_json_basic_auth_uses_username_and_password_secret_refs() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_basic_auth_manifest(&upstream_url))
            .expect("basic-auth http_json manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("basic-auth http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await;

    response.assert_status_ok();
    let seen = upstream_state.seen.lock().await;
    let lookup = seen
        .iter()
        .find(|request| request["id"] == json!("person-123"))
        .expect("basic-auth lookup reached upstream");
    assert_eq!(lookup["authorization"], json!("Basic YWRtaW46ZGlzdHJpY3Q="));
    assert_eq!(lookup["client_id"], json!("public-client"));
}

#[tokio::test]
async fn http_json_source_rate_limit_blocks_before_upstream_dispatch() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_manifest_with_source_limits(&upstream_url))
            .expect("rate-limited manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("rate-limited sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);
    upstream_state.seen.lock().await.clear();

    sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await
        .assert_status_ok();

    let limited = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-456")
        .add_query_param("fields", "national_id")
        .await;

    limited.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(limited.json::<Value>()["code"], "source.target_rate_limit");
    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.iter()
            .filter(|request| request["id"] != json!("smoke-person"))
            .count(),
        1,
        "rate limit must block before upstream dispatch"
    );
}

#[tokio::test]
async fn http_json_rejects_bad_sidecar_bearer_tokens_before_upstream_dispatch() {
    let harness = http_json_harness().await;
    harness.upstream_state.seen.lock().await.clear();
    let path = format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records");

    let missing = harness
        .sidecar
        .get(&path)
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;
    missing.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );

    let malformed = harness
        .sidecar
        .get(&path)
        .add_header("authorization", "Token not-bearer")
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;
    malformed.assert_status(StatusCode::UNAUTHORIZED);

    let wrong = harness
        .sidecar
        .get(&path)
        .add_header("authorization", "Bearer wrong-token")
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;
    wrong.assert_status(StatusCode::FORBIDDEN);

    assert!(
        harness.upstream_state.seen.lock().await.is_empty(),
        "bad sidecar bearer tokens must not reach the upstream adapter"
    );
}

#[tokio::test]
async fn http_json_batch_match_runs_sequential_lookups_and_preserves_item_order() {
    let harness = http_json_harness().await;

    let response = harness
        .sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-123"] },
                { "id": "1", "values": ["missing-person"] },
                { "id": "2", "values": ["ambiguous-person"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                {
                    "id": "0",
                    "data": [{
                        "national_id": "person-123",
                        "birth_date": "1990-01-01"
                    }]
                },
                { "id": "1", "data": [] },
                {
                    "id": "2",
                    "data": [
                        {
                            "national_id": "ambiguous-person",
                            "birth_date": "1990-01-01"
                        },
                        {
                            "national_id": "ambiguous-person",
                            "birth_date": "1992-02-02"
                        }
                    ]
                }
            ]
        })
    );

    let seen = harness.upstream_state.seen.lock().await;
    assert!(seen
        .iter()
        .any(|request| request["id"] == json!("person-123")));
    assert!(seen
        .iter()
        .any(|request| request["id"] == json!("missing-person")));
    assert!(seen
        .iter()
        .any(|request| request["id"] == json!("ambiguous-person")));
}

#[tokio::test]
async fn http_json_parallel_batch_is_bounded_and_preserves_order() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/concurrent", get(concurrent_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_manifest_with_parallel_batch(&upstream_url))
            .expect("parallel batch manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("parallel batch sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-0"] },
                { "id": "1", "values": ["person-1"] },
                { "id": "2", "values": ["person-2"] },
                { "id": "3", "values": ["person-3"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-0", "birth_date": "1990-01-01" }] },
                { "id": "1", "data": [{ "national_id": "person-1", "birth_date": "1990-01-01" }] },
                { "id": "2", "data": [{ "national_id": "person-2", "birth_date": "1990-01-01" }] },
                { "id": "3", "data": [{ "national_id": "person-3", "birth_date": "1990-01-01" }] }
            ]
        })
    );
    assert_eq!(*upstream_state.max_in_flight.lock().await, 2);
}

#[tokio::test]
async fn http_json_native_batch_fans_out_records_by_configured_keys() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .route("/native", post(native_batch_lookup))
            .with_state(UpstreamState::default()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_manifest_with_native_batch(&upstream_url))
            .expect("native batch manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("native batch sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-123"] },
                { "id": "1", "values": ["missing-person"] },
                { "id": "2", "values": ["ambiguous-person"] },
                { "id": "3", "values": ["person-123"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }] },
                { "id": "1", "data": [] },
                {
                    "id": "2",
                    "data": [
                        { "national_id": "ambiguous-person", "birth_date": "1990-01-01" },
                        { "national_id": "ambiguous-person", "birth_date": "1992-02-02" }
                    ]
                },
                { "id": "3", "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }] }
            ]
        })
    );
}

#[tokio::test]
async fn http_json_native_batch_spends_one_rate_token_per_dispatch() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .route("/native", post(tracked_native_batch_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest_with_native_batch(&upstream_url).replace(
        "    allow_insecure_localhost: true",
        r#"    allow_insecure_localhost: true
    limits:
      requests_per_second: 1
      burst: 1"#,
    );
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("rate-limited native batch manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("rate-limited native batch sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);
    upstream_state.seen.lock().await.clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;

    sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [{ "id": "0", "values": ["person-123"] }]
        }))
        .await
        .assert_status_ok();

    let limited = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [{ "id": "1", "values": ["person-456"] }]
        }))
        .await;

    limited.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(limited.json::<Value>()["code"], "source.target_rate_limit");
    assert_eq!(
        upstream_state.seen.lock().await.len(),
        1,
        "native batch rate limiting must spend one token per upstream dispatch"
    );
}

#[tokio::test]
async fn http_json_cache_is_explicit_and_scoped_to_lookup_shape() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig =
        serde_norway::from_str(&http_json_manifest_with_cache(&upstream_url))
            .expect("cache manifest parses");
    let app = sidecar_router(config).await.expect("cache sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);
    upstream_state.seen.lock().await.clear();

    for id in [
        "person-123",
        "person-123",
        "missing-person",
        "missing-person",
    ] {
        sidecar
            .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
            .add_header("authorization", format!("Bearer {TOKEN}"))
            .add_header("data-purpose", "eligibility")
            .add_query_param("national_id", id)
            .add_query_param("fields", "national_id,birth_date")
            .await
            .assert_status_ok();
    }

    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.iter()
            .filter(|request| request["id"] == json!("person-123"))
            .count(),
        1
    );
    assert_eq!(
        seen.iter()
            .filter(|request| request["id"] == json!("missing-person"))
            .count(),
        1
    );
    drop(seen);

    let metrics = sidecar.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics = metrics.text();
    assert!(metrics.contains(
        "registry_notary_openfn_sidecar_lookup_total{source_id=\"http_people\",outcome=\"source_cache_hit\"} 2"
    ));
    assert!(!metrics.contains("person-123"));
    assert!(!metrics.contains("target-secret"));
}

#[tokio::test]
async fn http_json_post_sends_minimized_body_without_configuration_or_secrets() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people-post", post(person_post_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "POST",
        "/people-post",
        4096,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await;

    response.assert_status_ok();
    let seen = upstream_state.seen.lock().await;
    let body = seen
        .iter()
        .find(|request| request["id"] == json!("person-123"))
        .and_then(|request| request.get("body"))
        .expect("POST body captured");
    assert!(body.get("lookup").is_some());
    assert!(body.get("fields").is_some());
    assert!(body.get("configuration").is_none());
    assert!(
        !body.to_string().contains("target-secret"),
        "POST body must not contain credential secrets: {body}"
    );
}

#[tokio::test]
async fn http_json_oversized_upstream_response_maps_to_502() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/oversized", get(oversized_lookup)));
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/oversized",
        256,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;

    response.assert_status(StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn http_json_batch_rejects_multiple_predicates_before_fetch() {
    let harness = http_json_harness().await;

    let response = harness
        .sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [
                { "field": "national_id", "op": "eq" },
                { "field": "birth_date", "op": "eq" }
            ],
            "items": [
                { "id": "0", "values": ["person-123", "1990-01-01"] }
            ]
        }))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let seen = harness.upstream_state.seen.lock().await;
    assert_eq!(
        seen.iter()
            .filter(|request| request["id"] == json!("person-123"))
            .count(),
        0,
        "multi-predicate batch must be rejected before upstream fetch"
    );
}

#[tokio::test]
async fn http_json_rejects_base_url_outside_allowlist_before_fetch() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/people", get(|| async { Json(json!({})) })));
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest(&upstream_url, "https://allowed.example.test");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    let error = sidecar_router(config)
        .await
        .expect_err("disallowed http_json base_url must fail startup");

    assert!(
        error.to_string().contains("allowed_base_urls"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn http_json_rejects_loopback_base_url_unless_explicitly_allowed() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest(&upstream_url, &upstream_url)
        .replace("  liveness_window_ms: 30000", "  liveness_window_ms: 1")
        .replace("    allow_insecure_localhost: true\n", "");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    let error = sidecar_router(config)
        .await
        .expect_err("loopback base URL must fail without explicit localhost allowance");

    assert!(
        error.to_string().contains("smoke lookup"),
        "unexpected error: {error}"
    );
    assert!(
        upstream_state.seen.lock().await.is_empty(),
        "loopback denial must happen before upstream dispatch"
    );
}

#[tokio::test]
async fn http_json_rejects_path_that_escapes_allowed_origin_before_fetch() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest =
        http_json_manifest_with_method(&upstream_url, "GET", "//evil.example.test/people", 4096)
            .replace("  liveness_window_ms: 30000", "  liveness_window_ms: 1");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    let error = sidecar_router(config)
        .await
        .expect_err("protocol-relative path must not escape allowed origin");

    assert!(
        error.to_string().contains("http_json.path"),
        "unexpected error: {error}"
    );
    assert!(
        upstream_state.seen.lock().await.is_empty(),
        "same-origin denial must happen before upstream dispatch"
    );
}

#[tokio::test]
async fn http_json_preserves_base_url_path_prefix_before_adapter_path() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/stable-2-43-0/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = format!("{}/stable-2-43-0", server_base_url(&upstream));
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/people",
        4096,
    ))
    .expect("manifest with base path prefix parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts with base path prefix");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "birth_date": "1990-01-01"
            }]
        })
    );
}

#[tokio::test]
async fn http_json_bearer_auth_uses_secret_without_exposing_secret_to_cel() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(UpstreamState::default()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest(&upstream_url, &upstream_url).replace(
        "          cel: body.results",
        "          cel: '[credential_public]'",
    );
    let manifest = manifest
        .replace("      field: national_id", "      field: baseUrl")
        .replace(
            "      value: smoke-person",
            &format!("      value: {upstream_url}"),
        )
        .replace("        - national_id", "        - baseUrl");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "baseUrl,clientId,apiToken")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "baseUrl": upstream_url,
                "clientId": "public-client"
            }]
        })
    );
}

#[tokio::test]
async fn http_json_does_not_follow_upstream_redirects() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/redirect", get(redirect_lookup))
            .route("/people", get(person_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/redirect",
        4096,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;

    response.assert_status(StatusCode::BAD_GATEWAY);
    let seen = upstream_state.seen.lock().await;
    assert!(seen.iter().any(|request| request["id"] == "person-123"));
    assert!(
        !seen
            .iter()
            .any(|request| request["id"] == "redirected-person"),
        "sidecar must not follow upstream redirects"
    );
}

#[tokio::test]
async fn http_json_upstream_statuses_map_to_controlled_errors() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/status", get(status_lookup))
            .with_state(upstream_state),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/status",
        4096,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let unauthorized = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "unauthorized-person")
        .add_query_param("fields", "national_id")
        .await;
    unauthorized.assert_status(StatusCode::BAD_GATEWAY);
    assert_eq!(unauthorized.json::<Value>()["code"], "source.target_auth");

    let forbidden = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "forbidden-person")
        .add_query_param("fields", "national_id")
        .await;
    forbidden.assert_status(StatusCode::BAD_GATEWAY);
    assert_eq!(forbidden.json::<Value>()["code"], "source.target_auth");

    let unavailable = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "broken-person")
        .add_query_param("fields", "national_id")
        .await;
    unavailable.assert_status(StatusCode::BAD_GATEWAY);
    let unavailable_body = unavailable.json::<Value>();
    assert_eq!(unavailable_body["code"], "source.unavailable");
    assert_eq!(unavailable_body["title"], "source unavailable");

    let rate_limited_without_header = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "rate-limited-no-header-person")
        .add_query_param("fields", "national_id")
        .await;
    rate_limited_without_header.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rate_limited_without_header.json::<Value>()["code"],
        "source.target_rate_limit"
    );
    assert_eq!(
        rate_limited_without_header
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let rate_limited = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "rate-limited-person")
        .add_query_param("fields", "national_id")
        .await;
    rate_limited.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rate_limited.json::<Value>()["code"],
        "source.target_rate_limit"
    );
    assert_eq!(
        rate_limited
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("17")
    );
}

#[tokio::test]
async fn http_json_retry_after_backoff_fails_fast_before_dispatch() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/status", get(status_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/status",
        4096,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);
    upstream_state.seen.lock().await.clear();

    let rate_limited = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "rate-limited-person")
        .add_query_param("fields", "national_id")
        .await;
    rate_limited.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rate_limited
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("17")
    );

    let blocked = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;
    blocked.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(blocked.json::<Value>()["code"], "source.target_rate_limit");
    let retry_after = blocked
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("backoff response carries Retry-After");
    assert!((1..=17).contains(&retry_after));

    let seen = upstream_state.seen.lock().await;
    assert_eq!(seen.len(), 1, "backoff must fail before dispatch");
    assert_eq!(seen[0]["id"], json!("rate-limited-person"));
}

#[tokio::test]
async fn http_json_batch_shared_credential_failures_are_top_level_errors() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/status", get(status_lookup))
            .with_state(upstream_state),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let config: SidecarConfig = serde_norway::from_str(&http_json_manifest_with_method(
        &upstream_url,
        "GET",
        "/status",
        4096,
    ))
    .expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let unauthorized = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["unauthorized-person"] },
                { "id": "1", "values": ["person-123"] }
            ]
        }))
        .await;
    unauthorized.assert_status(StatusCode::BAD_GATEWAY);
    assert_eq!(unauthorized.json::<Value>()["code"], "source.target_auth");

    let rate_limited = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["rate-limited-person"] },
                { "id": "1", "values": ["person-123"] }
            ]
        }))
        .await;
    rate_limited.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rate_limited.json::<Value>()["code"],
        "source.target_rate_limit"
    );
    assert_eq!(
        rate_limited
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("17")
    );
}

#[tokio::test]
async fn http_json_batch_timeout_is_a_whole_operation_deadline() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/slow", get(slow_lookup)));
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest_with_method(&upstream_url, "GET", "/slow", 4096).replace(
        "  max_batch_items: 100",
        "  max_batch_items: 100\n  batch_timeout_ms: 25",
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("http_json sidecar starts");
    let sidecar = TestServer::builder().http_transport().build(app);

    let response = sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&json!({
            "fields": ["national_id"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-123"] },
                { "id": "1", "values": ["person-456"] }
            ]
        }))
        .await;

    response.assert_status(StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.json::<Value>()["code"], "source.timeout");
}

#[tokio::test]
async fn http_json_invalid_cel_fails_startup_smoke_lookup() {
    let _env_guard = ENV_LOCK.lock().await;
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/people", get(person_lookup))
            .with_state(UpstreamState::default()),
    );
    let upstream_url = server_base_url(&upstream);
    set_sidecar_env(&upstream_url);
    let manifest = http_json_manifest(&upstream_url, &upstream_url)
        .replace("  liveness_window_ms: 30000", "  liveness_window_ms: 1")
        .replace("          cel: lookup.value", "          cel: lookup.");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    let error = sidecar_router(config)
        .await
        .expect_err("invalid http_json CEL must fail during smoke lookup");

    assert!(
        error.to_string().contains("smoke lookup"),
        "unexpected error: {error}"
    );
}
