// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for the `script_rhai` source engine.
//!
//! These drive the public sidecar entrypoint against an `axum_test` mock
//! upstream, exactly mirroring the `http_json` integration harness. The engine
//! itself is unit-tested in the rhai crate; here we prove the sidecar wiring:
//! the script reaches the configured upstream, its records surface as
//! `{ "data": [...] }`, and the per-target `visible_statuses` gate behaves.

use axum::{extract::Query, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
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

async fn path_b(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
) -> impl IntoResponse {
    state.seen.lock().await.push("/b".to_string());
    (
        StatusCode::OK,
        Json(json!([{ "national_id": "from-b", "birth_date": "1980-12-31" }])),
    )
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
