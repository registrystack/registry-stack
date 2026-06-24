// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for the `script_rhai` source engine.
//!
//! These drive the public sidecar entrypoint against an `axum_test` mock
//! upstream, exactly mirroring the `http_json` integration harness. The engine
//! itself is unit-tested in the rhai crate; here we prove the sidecar wiring:
//! the script reaches the configured upstream, its records surface as
//! `{ "data": [...] }`, and the per-target `visible_statuses` gate behaves.

use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::Mutex;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const TOKEN: &str = "http-json-sidecar-token";
const TOKEN_HASH_ENV: &str = "RHAI_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_ADAPTER_CREDENTIAL_JSON";

// Serialize env mutation across tests (the credential/token hashes are read at
// `sidecar_router` time from process env, like the http_json harness).
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Default)]
struct UpstreamState {
    seen: std::sync::Arc<Mutex<Vec<String>>>,
    last_post_body: std::sync::Arc<Mutex<Option<Value>>>,
}

/// `/lookup?id=...` — echoes the id back as one record. Used by the happy-path
/// test and as the smoke-lookup endpoint.
async fn lookup_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
}

/// `/a?id=...` — 404 for ordinary ids, but returns the smoke record for the
/// startup smoke id so readiness passes via the primary path (the fallback to
/// `/b` is only exercised by the real, non-smoke request). Used by the
/// visibility-gate tests.
async fn path_a(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/a:{id}"));
    if id == "smoke-person" {
        return (
            StatusCode::OK,
            Json(json!([{ "national_id": "smoke-person", "birth_date": "1990-01-01" }])),
        )
            .into_response();
    }
    (StatusCode::NOT_FOUND, Json(json!({ "error": "missing" }))).into_response()
}

async fn path_a_empty_404(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/a:{id}"));
    if id == "smoke-person" {
        return (
            StatusCode::OK,
            Json(json!([{ "national_id": "smoke-person", "birth_date": "1990-01-01" }])),
        )
            .into_response();
    }
    (StatusCode::NOT_FOUND, "").into_response()
}

async fn path_b(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
) -> impl IntoResponse {
    state.seen.lock().await.push("/b".to_string());
    (
        StatusCode::OK,
        Json(json!([{ "national_id": "from-b", "birth_date": "1980-12-31" }])),
    )
}

async fn post_search_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/search:{id}"));
    *state.last_post_body.lock().await = Some(body);
    Json(json!([{ "national_id": id }]))
}

async fn post_empty_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/empty:{id}"));
    *state.last_post_body.lock().await = Some(body);
    (StatusCode::NO_CONTENT, "")
}

async fn post_conflict_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/conflict:{id}"));
    *state.last_post_body.lock().await = Some(body);
    if id == "smoke-person" {
        return (
            StatusCode::OK,
            Json(json!([{ "national_id": "smoke-person", "birth_date": "1990-01-01" }])),
        )
            .into_response();
    }
    (
        StatusCode::CONFLICT,
        Json(json!({ "error": "duplicate", "id": id })),
    )
        .into_response()
}

fn set_env() {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    std::env::set_var(
        CREDENTIAL_ENV,
        json!({
            "clientId": "public-client",
            "apiToken": "target-secret"
        })
        .to_string(),
    );
}

fn server_base_url(server: &TestServer) -> String {
    server
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string()
        .trim_end_matches('/')
        .to_string()
}

/// A `script_rhai` manifest whose `lookup` script fetches `/lookup?id=<value>`
/// from the single `primary` target and returns the body verbatim.
fn rhai_lookup_manifest(allowlist_url: &str) -> String {
    rhai_lookup_manifest_with_batch(allowlist_url, "")
}

fn rhai_lookup_manifest_with_batch(allowlist_url: &str, batch_block: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true{batch_block}
    rhai:
      script: |
        fn lookup(ctx) {{
          source.get("primary", "/lookup", #{{ id: ctx.lookup.value }}).body
        }}
      targets:
        primary:
          base_url: {allowlist_url}
          auth:
            type: bearer
            token:
              secret: apiToken
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
        batch_block = batch_block,
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// A `script_rhai` manifest that tries `/a` first; if it observes a 404 it falls
/// back to `/b`. `visible_statuses` is injected by the caller so both the
/// "observable 404" and "terminal 404" cases share one manifest body.
fn rhai_fallback_manifest(allowlist_url: &str, visible_statuses_block: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      limits:
        max_http_calls: 3
      script: |
        fn lookup(ctx) {{
          let r = source.get("primary", "/a", #{{ id: ctx.lookup.value }});
          if r.status == 404 {{ source.get("primary", "/b", #{{}}).body }} else {{ r.body }}
        }}
      targets:
        primary:
          base_url: {allowlist_url}{visible_statuses_block}
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
        visible_statuses_block = visible_statuses_block,
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// A `script_rhai` manifest that POSTs a search body, then GETs the concrete
/// record using the id returned by the search endpoint.
fn rhai_post_then_get_manifest(allowlist_url: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      limits:
        max_http_calls: 3
      script: |
        fn lookup(ctx) {{
          let search = source.post_json(
            "primary",
            "/search",
            #{{ id: ctx.lookup.value }},
            #{{ value: ctx.lookup.value, fields: ctx.fields }}
          );
          source.get("primary", "/lookup", #{{ id: search.body[0].national_id }}).body
        }}
      targets:
        primary:
          base_url: {allowlist_url}
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
        dataset = DATASET,
        entity = ENTITY,
    )
}

fn rhai_post_empty_manifest(allowlist_url: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      limits:
        max_http_calls: 1
      script: |
        fn lookup(ctx) {{
          let posted = source.post_json(
            "primary",
            "/empty",
            #{{ id: ctx.lookup.value }},
            #{{ value: ctx.lookup.value }}
          );
          [#{{ national_id: ctx.lookup.value, post_status: posted.status, post_body: posted.body }}]
        }}
      targets:
        primary:
          base_url: {allowlist_url}
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
        dataset = DATASET,
        entity = ENTITY,
    )
}

fn rhai_post_conflict_manifest(allowlist_url: &str, visible_statuses_block: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      limits:
        max_http_calls: 1
      script: |
        fn lookup(ctx) {{
          let posted = source.post_json(
            "primary",
            "/conflict",
            #{{ id: ctx.lookup.value }},
            #{{ value: ctx.lookup.value }}
          );
          if posted.status == 409 {{
            [#{{ national_id: ctx.lookup.value, birth_date: "conflict" }}]
          }} else {{
            posted.body
          }}
        }}
      targets:
        primary:
          base_url: {allowlist_url}{visible_statuses_block}
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
        visible_statuses_block = visible_statuses_block,
        dataset = DATASET,
        entity = ENTITY,
    )
}

fn rhai_post_oversized_manifest(allowlist_url: &str) -> String {
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
  worker_timeout_ms: 500
  max_output_bytes: 4096
  max_request_bytes: 256
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
  max_worker_memory_mb: 256
sources:
  rhai_people:
    engine: script_rhai
    dataset: {dataset}
    entity: {entity}
    credential_env: {credential_env}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      limits:
        max_http_calls: 1
      script: |
        fn lookup(ctx) {{
          let payload = if ctx.lookup.value == "smoke-person" {{
            "ok"
          }} else {{
            "this-value-is-intentionally-too-large-for-the-request-limit-this-value-is-intentionally-too-large-for-the-request-limit-this-value-is-intentionally-too-large-for-the-request-limit-this-value-is-intentionally-too-large-for-the-request-limit-this-value-is-intentionally-too-large-for-the-request-limit-this-value-is-intentionally-too-large-for-the-request-limit"
          }};
          source.post_json(
            "primary",
            "/search",
            #{{ id: ctx.lookup.value }},
            #{{ value: payload }}
          ).body
        }}
      targets:
        primary:
          base_url: {allowlist_url}
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
        dataset = DATASET,
        entity = ENTITY,
    )
}

async fn spawn_sidecar(manifest: String, upstream_state: UpstreamState) -> TestServer {
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("script_rhai manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("script_rhai sidecar starts and passes smoke lookup");
    let _ = upstream_state; // kept alive by the caller's TestServer
    TestServer::builder().http_transport().build(app)
}

#[tokio::test]
async fn rhai_lookup_returns_data_from_upstream() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(rhai_lookup_manifest(&upstream_url), upstream_state.clone()).await;

    let response = sidecar
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

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/lookup:person-123"),
        "the script's lookup must reach the upstream; saw {seen:?}"
    );
}

#[tokio::test]
async fn rhai_post_json_then_get_uses_json_body_and_shared_call_budget() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/search", post(post_search_endpoint))
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(
        rhai_post_then_get_manifest(&upstream_url),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();
    *upstream_state.last_post_body.lock().await = None;

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

    let post_body = upstream_state
        .last_post_body
        .lock()
        .await
        .clone()
        .expect("POST body captured");
    assert_eq!(
        post_body,
        json!({ "value": "person-123", "fields": ["national_id", "birth_date"] })
    );
    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.as_slice(),
        ["/search:person-123", "/lookup:person-123"],
        "the script should POST once, then GET once under the shared call budget"
    );
}

#[tokio::test]
async fn rhai_post_json_empty_2xx_body_is_returned_as_null() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/empty", post(post_empty_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(
        rhai_post_empty_manifest(&upstream_url),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();
    *upstream_state.last_post_body.lock().await = None;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,post_status,post_body")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "post_status": 204,
                "post_body": null
            }]
        })
    );
    assert_eq!(
        *upstream_state.last_post_body.lock().await,
        Some(json!({ "value": "person-123" }))
    );
}

#[tokio::test]
async fn rhai_post_json_visible_status_lets_script_observe_409() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/conflict", post(post_conflict_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let visible = r#"
          visible_statuses:
            - 409"#;
    let sidecar = spawn_sidecar(
        rhai_post_conflict_manifest(&upstream_url, visible),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();

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
                "birth_date": "conflict"
            }]
        })
    );
    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.as_slice(),
        ["/conflict:person-123"],
        "the visible POST 409 should be returned to the script once; saw {seen:?}"
    );
}

#[tokio::test]
async fn rhai_post_json_without_visible_status_terminates_on_409() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/conflict", post(post_conflict_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(
        rhai_post_conflict_manifest(&upstream_url, ""),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_GATEWAY);
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.unavailable"),
        "expected POST 409 to terminate as source.unavailable, got {body}"
    );
    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.as_slice(),
        ["/conflict:person-123"],
        "the run should stop after the non-visible POST 409; saw {seen:?}"
    );
}

#[tokio::test]
async fn rhai_post_json_oversized_body_fails_before_sending_request() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/search", post(post_search_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(
        rhai_post_oversized_manifest(&upstream_url),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();
    *upstream_state.last_post_body.lock().await = None;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_GATEWAY);
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.unavailable"),
        "expected oversized POST body to fail as source.unavailable, got {body}"
    );
    assert!(
        upstream_state.seen.lock().await.is_empty(),
        "oversized POST body must be rejected before reaching the upstream"
    );
    assert_eq!(*upstream_state.last_post_body.lock().await, None);
}

#[tokio::test]
async fn rhai_batch_match_runs_sequential_lookups_and_preserves_item_order() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(rhai_lookup_manifest(&upstream_url), upstream_state.clone()).await;
    upstream_state.seen.lock().await.clear();

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
                { "id": "first", "values": ["person-123"] },
                { "id": "second", "values": ["person-456"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                {
                    "id": "first",
                    "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }]
                },
                {
                    "id": "second",
                    "data": [{ "national_id": "person-456", "birth_date": "1990-01-01" }]
                }
            ]
        })
    );

    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.as_slice(),
        ["/lookup:person-123", "/lookup:person-456"],
        "sequential Rhai batch should run one lookup per item in order"
    );
}

#[tokio::test]
async fn rhai_batch_match_supports_parallel_lookup_mode() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let batch = r#"
    batch:
      mode: parallel_lookup
      max_parallel: 2"#;
    let sidecar = spawn_sidecar(
        rhai_lookup_manifest_with_batch(&upstream_url, batch),
        upstream_state.clone(),
    )
    .await;
    upstream_state.seen.lock().await.clear();

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
                { "id": "first", "values": ["person-123"] },
                { "id": "second", "values": ["person-456"] }
            ]
        }))
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                {
                    "id": "first",
                    "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }]
                },
                {
                    "id": "second",
                    "data": [{ "national_id": "person-456", "birth_date": "1990-01-01" }]
                }
            ]
        })
    );
}

#[tokio::test]
async fn rhai_visible_status_lets_script_observe_404_and_fall_back() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            // `/a` 404s for the real id and falls back to `/b`; it serves the
            // smoke record directly for the startup smoke id.
            .route("/a", get(path_a))
            .route("/b", get(path_b))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    // 404 is observable for this target, so the script branches to `/b`.
    let visible = r#"
          visible_statuses:
            - 404"#;
    let sidecar = spawn_sidecar(
        rhai_fallback_manifest(&upstream_url, visible),
        upstream_state.clone(),
    )
    .await;

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
                "national_id": "from-b",
                "birth_date": "1980-12-31"
            }]
        })
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/a:person-123"),
        "saw {seen:?}"
    );
    assert!(seen.iter().any(|hit| hit == "/b"), "saw {seen:?}");
}

#[tokio::test]
async fn rhai_visible_empty_404_body_is_observable_as_null() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/a", get(path_a_empty_404))
            .route("/b", get(path_b))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let visible = r#"
          visible_statuses:
            - 404"#;
    let sidecar = spawn_sidecar(
        rhai_fallback_manifest(&upstream_url, visible),
        upstream_state.clone(),
    )
    .await;

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
                "national_id": "from-b",
                "birth_date": "1980-12-31"
            }]
        })
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/a:person-123"),
        "saw {seen:?}"
    );
    assert!(seen.iter().any(|hit| hit == "/b"), "saw {seen:?}");
}

#[tokio::test]
async fn rhai_without_visible_status_terminates_on_404() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/a", get(path_a))
            .route("/b", get(path_b))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    // No `visible_statuses`: the 404 on `/a` is a terminal upstream-status error,
    // so the run never reaches `/b` and the sidecar reports source.unavailable.
    let sidecar = spawn_sidecar(
        rhai_fallback_manifest(&upstream_url, ""),
        upstream_state.clone(),
    )
    .await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await;

    // The sidecar maps source.unavailable to a 502-class problem response whose
    // top-level `code` is the public problem code.
    assert_eq!(response.status_code(), StatusCode::BAD_GATEWAY);
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.unavailable"),
        "expected a terminal source.unavailable error, got {body}"
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/a:person-123"),
        "saw {seen:?}"
    );
    assert!(
        !seen.iter().any(|hit| hit == "/b"),
        "the run must terminate at the non-visible 404 and never hit /b; saw {seen:?}"
    );
}
