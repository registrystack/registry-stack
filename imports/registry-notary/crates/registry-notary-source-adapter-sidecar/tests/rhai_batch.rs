// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for `script_rhai` batch-match. The engine accepts
//! batch-capable config (`sequential_lookup` / `parallel_lookup`); these drive
//! the `:batchMatch` route end-to-end and prove each item runs one governed
//! single-item script lookup, results preserve request order, and a per-item
//! failure is isolated rather than failing the whole batch.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
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
const TOKEN_HASH_ENV: &str = "RHAI_BATCH_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_BATCH_CREDENTIAL_JSON";

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Default)]
struct UpstreamState {
    seen: std::sync::Arc<Mutex<Vec<String>>>,
}

/// `/lookup?id=...`: a record for ordinary ids, an empty array for `missing`, a
/// terminal (non-visible) 404 for `boom`, and the smoke record for the startup
/// smoke id.
async fn batch_lookup(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(id.clone());
    if id == "boom" {
        // No `visible_statuses` on the target, so this terminates the run.
        return StatusCode::NOT_FOUND.into_response();
    }
    if id == "denied" {
        // A shared credential error (target_auth) must fail the whole batch.
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if id == "missing" {
        return Json(json!([])).into_response();
    }
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }])).into_response()
}

fn set_env() {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    std::env::set_var(
        CREDENTIAL_ENV,
        json!({ "clientId": "public-client", "apiToken": "target-secret" }).to_string(),
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

/// `script_rhai` manifest with an injectable top-level `batch_block` (empty for
/// the default sequential mode). The script fetches `/lookup?id=<value>` and
/// returns the body, so each batch item resolves one governed lookup.
fn rhai_batch_manifest(allowlist_url: &str, batch_block: &str) -> String {
    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 4
  worker_timeout_ms: 1000
  max_output_bytes: 4096
  max_request_bytes: 4096
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

async fn spawn(manifest: String, upstream_state: UpstreamState) -> TestServer {
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("script_rhai manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("script_rhai sidecar starts and passes smoke lookup");
    let _ = upstream_state;
    TestServer::builder().http_transport().build(app)
}

fn upstream(state: UpstreamState) -> TestServer {
    TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(batch_lookup))
            .with_state(state),
    )
}

async fn post_batch(sidecar: &TestServer, body: Value) -> axum_test::TestResponse {
    sidecar
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .json(&body)
        .await
}

#[tokio::test]
async fn rhai_sequential_batch_resolves_items_in_order() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = upstream(upstream_state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();
    // No batch block -> the default sequential_lookup mode.
    let sidecar = spawn(
        rhai_batch_manifest(&upstream_url, ""),
        upstream_state.clone(),
    )
    .await;

    let response = post_batch(
        &sidecar,
        json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-1"] },
                { "id": "1", "values": ["missing"] },
                { "id": "2", "values": ["person-2"] }
            ]
        }),
    )
    .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-1", "birth_date": "1990-01-01" }] },
                { "id": "1", "data": [] },
                { "id": "2", "data": [{ "national_id": "person-2", "birth_date": "1990-01-01" }] }
            ]
        })
    );
}

#[tokio::test]
async fn rhai_parallel_batch_resolves_all_items() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = upstream(upstream_state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();
    let batch_block = r#"
    batch:
      mode: parallel_lookup
      max_parallel: 3"#;
    let sidecar = spawn(
        rhai_batch_manifest(&upstream_url, batch_block),
        upstream_state.clone(),
    )
    .await;

    let response = post_batch(
        &sidecar,
        json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-1"] },
                { "id": "1", "values": ["person-2"] },
                { "id": "2", "values": ["person-3"] }
            ]
        }),
    )
    .await;

    response.assert_status_ok();
    // Order is preserved by item index regardless of completion order.
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-1", "birth_date": "1990-01-01" }] },
                { "id": "1", "data": [{ "national_id": "person-2", "birth_date": "1990-01-01" }] },
                { "id": "2", "data": [{ "national_id": "person-3", "birth_date": "1990-01-01" }] }
            ]
        })
    );

    let seen = upstream_state.seen.lock().await;
    for id in ["person-1", "person-2", "person-3"] {
        assert!(seen.iter().any(|hit| hit == id), "saw {seen:?}");
    }
}

#[tokio::test]
async fn rhai_batch_isolates_a_per_item_failure() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = upstream(upstream_state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn(
        rhai_batch_manifest(&upstream_url, ""),
        upstream_state.clone(),
    )
    .await;

    let response = post_batch(
        &sidecar,
        json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-1"] },
                { "id": "1", "values": ["boom"] }
            ]
        }),
    )
    .await;

    // The `boom` lookup hits a terminal 404; that item carries an error while
    // its sibling still resolves. A per-item failure must not fail the batch.
    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "items": [
                { "id": "0", "data": [{ "national_id": "person-1", "birth_date": "1990-01-01" }] },
                { "id": "1", "error": { "code": "source_unavailable" } }
            ]
        })
    );
}

#[tokio::test]
async fn rhai_batch_shared_credential_error_fails_whole_batch() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = upstream(upstream_state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn(
        rhai_batch_manifest(&upstream_url, ""),
        upstream_state.clone(),
    )
    .await;

    let response = post_batch(
        &sidecar,
        json!({
            "fields": ["national_id", "birth_date"],
            "query_signature": [{ "field": "national_id", "op": "eq" }],
            "items": [
                { "id": "0", "values": ["person-1"] },
                { "id": "1", "values": ["denied"] }
            ]
        }),
    )
    .await;

    // A 401 is a shared credential error: unlike a per-item not-found it aborts
    // the entire batch with a single top-level problem rather than a per-item
    // entry, so a leaked/expired credential can't be probed item by item.
    assert_eq!(response.status_code(), StatusCode::BAD_GATEWAY);
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.target_auth"),
        "expected a whole-batch target_auth failure, got {body}"
    );
}
