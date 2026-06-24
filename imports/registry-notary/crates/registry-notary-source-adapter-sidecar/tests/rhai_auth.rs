// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for the `script_rhai` messy-API auth package:
//! `api_key_header` / `api_key_query` auth kinds and per-target static request
//! headers. The positive tests assert the secret/headers reach the upstream on
//! the wire (and the script-visible public credential never does); the negative
//! tests assert misconfigurations are rejected at startup.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const TOKEN: &str = "http-json-sidecar-token";
const TOKEN_HASH_ENV: &str = "RHAI_AUTH_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_AUTH_CREDENTIAL_JSON";

// Distinct env-var names from the sibling test binaries so parallel runs do not
// race on process env.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Mock upstream that records the headers and query of the most recent request.
/// The smoke lookup runs first at startup, then the single test request, so the
/// captured "last" state reflects the test request.
#[derive(Clone, Default)]
struct CapturingUpstream {
    last_headers: Arc<Mutex<HashMap<String, String>>>,
    last_query: Arc<Mutex<HashMap<String, String>>>,
}

async fn capturing_lookup(
    State(state): State<CapturingUpstream>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut recorded = state.last_headers.lock().await;
    recorded.clear();
    for (name, value) in headers.iter() {
        recorded.insert(
            name.as_str().to_string(),
            value.to_str().unwrap_or_default().to_string(),
        );
    }
    drop(recorded);
    *state.last_query.lock().await = query.clone();

    let id = query.get("id").cloned().unwrap_or_default();
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
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

/// Build a `script_rhai` manifest whose single `primary` target gets the
/// caller-supplied `target_extra` block (auth and/or headers) appended under its
/// `base_url`. The script fetches `/lookup?id=<value>` and returns the body.
fn rhai_auth_manifest(allowlist_url: &str, target_extra: &str) -> String {
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
          base_url: {allowlist_url}{target_extra}
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

async fn spawn_sidecar(manifest: String) -> TestServer {
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("script_rhai manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("script_rhai sidecar starts and passes smoke lookup");
    TestServer::builder().http_transport().build(app)
}

async fn run_single_lookup(sidecar: &TestServer) -> axum_test::TestResponse {
    sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await
}

#[tokio::test]
async fn api_key_header_sends_secret_in_configured_header() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = CapturingUpstream::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(capturing_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let target_extra = r#"
          auth:
            type: api_key_header
            header: X-API-Key
            token:
              secret: apiToken"#;
    let sidecar = spawn_sidecar(rhai_auth_manifest(&upstream_url, target_extra)).await;

    let response = run_single_lookup(&sidecar).await;
    response.assert_status_ok();

    let headers = upstream_state.last_headers.lock().await;
    assert_eq!(
        headers.get("x-api-key").map(String::as_str),
        Some("target-secret"),
        "the resolved secret must be sent in the configured header; saw {headers:?}"
    );
    assert!(
        !headers.values().any(|v| v.contains("public-client")),
        "the script-visible public credential must never reach the wire; saw {headers:?}"
    );
}

#[tokio::test]
async fn api_key_query_sends_secret_in_configured_param() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = CapturingUpstream::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(capturing_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let target_extra = r#"
          auth:
            type: api_key_query
            query_param: api_key
            token:
              secret: apiToken"#;
    let sidecar = spawn_sidecar(rhai_auth_manifest(&upstream_url, target_extra)).await;

    let response = run_single_lookup(&sidecar).await;
    response.assert_status_ok();

    let query = upstream_state.last_query.lock().await;
    assert_eq!(
        query.get("api_key").map(String::as_str),
        Some("target-secret"),
        "the resolved secret must be appended as the configured query param; saw {query:?}"
    );
    // The script's own `id` param is still present alongside the host-appended key.
    assert_eq!(query.get("id").map(String::as_str), Some("person-123"));
}

#[tokio::test]
async fn static_target_headers_are_sent_to_upstream() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = CapturingUpstream::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(capturing_lookup))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let target_extra = r#"
          headers:
            Accept: application/fhir+json
            X-Vendor-Version: v2-2024"#;
    let sidecar = spawn_sidecar(rhai_auth_manifest(&upstream_url, target_extra)).await;

    let response = run_single_lookup(&sidecar).await;
    response.assert_status_ok();

    let headers = upstream_state.last_headers.lock().await;
    assert_eq!(
        headers.get("accept").map(String::as_str),
        Some("application/fhir+json"),
        "saw {headers:?}"
    );
    assert_eq!(
        headers.get("x-vendor-version").map(String::as_str),
        Some("v2-2024"),
        "saw {headers:?}"
    );
}

/// Validation negatives share a dummy in-allowlist URL; they fail before the
/// startup smoke lookup ever connects, so no live upstream is needed.
async fn expect_startup_rejection(target_extra: &str) -> String {
    set_env();
    let manifest = rhai_auth_manifest("http://127.0.0.1:9/", target_extra);
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("manifest parses; the rejection is at validation");
    sidecar_router(config)
        .await
        .expect_err("startup must reject the misconfigured target")
        .to_string()
}

#[tokio::test]
async fn api_key_header_without_header_name_is_rejected() {
    let _guard = ENV_LOCK.lock().await;
    let target_extra = r#"
          auth:
            type: api_key_header
            token:
              secret: apiToken"#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(
        message.contains("header is required when type is api_key_header"),
        "got: {message}"
    );
}

#[tokio::test]
async fn api_key_query_without_param_is_rejected() {
    let _guard = ENV_LOCK.lock().await;
    let target_extra = r#"
          auth:
            type: api_key_query
            token:
              secret: apiToken"#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(
        message.contains("query_param is required when type is api_key_query"),
        "got: {message}"
    );
}

#[tokio::test]
async fn restricted_static_authorization_header_is_rejected() {
    let _guard = ENV_LOCK.lock().await;
    let target_extra = r#"
          headers:
            Authorization: "Bearer nope""#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(message.contains("restricted header"), "got: {message}");
}

#[tokio::test]
async fn restricted_static_proxy_header_is_rejected() {
    let _guard = ENV_LOCK.lock().await;
    let target_extra = r#"
          headers:
            Proxy-Authorization: "nope""#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(message.contains("restricted header"), "got: {message}");
}

#[tokio::test]
async fn malformed_static_header_name_is_rejected_at_startup() {
    let _guard = ENV_LOCK.lock().await;
    // `/` is not a legal HTTP header-name token. The check must fail at config
    // validation, not later when reqwest builds the request (which would only
    // surface at smoke or first use).
    let target_extra = r#"
          headers:
            "Bad/Header": "x""#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(
        message.contains("is not a valid HTTP header name"),
        "got: {message}"
    );
}

#[tokio::test]
async fn api_key_header_with_malformed_header_name_is_rejected() {
    let _guard = ENV_LOCK.lock().await;
    // `:` is the header name/value separator and is not a legal token character.
    let target_extra = r#"
          auth:
            type: api_key_header
            header: "Bad:Header"
            token:
              secret: apiToken"#;
    let message = expect_startup_rejection(target_extra).await;
    assert!(
        message.contains("is not a valid HTTP header name"),
        "got: {message}"
    );
}
