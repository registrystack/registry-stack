// SPDX-License-Identifier: Apache-2.0
//! Additional sidecar integration tests for the `script_rhai` engine, each
//! closing a verification gap left by the happy-path harness in the sibling
//! `rhai_adapter.rs`. Like that file, these drive the public `sidecar_router`
//! entrypoint against an `axum_test` mock upstream.
//!
//! Each `tests/*.rs` file compiles as its own test BINARY and they run in
//! PARALLEL while mutating process env, so this file uses env-var NAMES that are
//! disjoint from every sibling (`RHAI_RUNTIME_*`, never `RHAI_SIDECAR_*` /
//! `RHAI_ADAPTER_*`) and serializes its own tests with a private `ENV_LOCK`. The
//! bearer TOKEN and its sha256 TOKEN_HASH are the same matching pair the other
//! harnesses reuse; only the env-var name they are bound to differs.
//!
//! The four gaps proven here:
//!  1. The configured bearer SECRET (not the public credential) reaches the
//!     upstream on the wire as `Authorization: Bearer target-secret`.
//!  2. The per-source token-bucket rate limit trips before dispatch, mapping to
//!     `source.target_rate_limit` (503).
//!  3. A registered `xw.*` pure helper runs end-to-end through the sidecar.
//!  4. A failing startup smoke lookup makes `sidecar_router` return `Err`.

use axum::{
    extract::Query, http::HeaderMap, http::StatusCode, response::IntoResponse, routing::get, Json,
    Router,
};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::Mutex;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const TOKEN: &str = "http-json-sidecar-token";
const TOKEN_HASH_ENV: &str = "RHAI_RUNTIME_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_RUNTIME_CREDENTIAL_JSON";

// Serialize env mutation across the tests in THIS binary (the credential/token
// hashes are read at `sidecar_router` time from process env). A distinct lock
// per binary is sufficient because the env-var names are disjoint from every
// sibling test file.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Default)]
struct UpstreamState {
    /// Ids the upstream was asked for, as `"/lookup:<id>"`, for dispatch counting.
    seen: std::sync::Arc<Mutex<Vec<String>>>,
    /// Every inbound `Authorization` header value the upstream observed, so a
    /// test can assert the SECRET (not the public credential) crossed the wire.
    auth: std::sync::Arc<Mutex<Vec<String>>>,
}

fn captured_auth(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `/lookup?id=...` — echoes the id back as one record, recording the inbound
/// `Authorization` header. Answers the smoke id with a valid record so readiness
/// passes. Used by the auth-on-the-wire, rate-limit, and xw-helper tests.
async fn lookup_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    state.auth.lock().await.push(captured_auth(&headers));
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
}

/// `/lookup?id=...` that answers the startup smoke id with a valid record but
/// returns a non-visible **500** for any other id, so the real lookup's script
/// terminates with an upstream-status error. Used by the smoke-failure test,
/// where the smoke id is the one that 500s (so smoke fails and startup is
/// rejected).
async fn lookup_endpoint_smoke_500(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    if id == "smoke-person" {
        // No `visible_statuses` on the target, so this terminates the run.
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "boom" })))
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }])),
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

/// Shared YAML preamble (server/auth/limits) parameterized by the liveness
/// window so the smoke-failure test can fail fast instead of retrying for 30s.
fn manifest_preamble(liveness_window_ms: u64) -> String {
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
  liveness_window_ms: {liveness_window_ms}
  max_batch_items: 100
  max_worker_memory_mb: 256"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        liveness_window_ms = liveness_window_ms,
    )
}

/// A `script_rhai` manifest whose `lookup` fetches `/lookup?id=<value>` from the
/// single `primary` target — authenticated with `bearer { secret: apiToken }` —
/// and returns the body verbatim. Used by the auth-on-the-wire test.
fn rhai_bearer_manifest(allowlist_url: &str) -> String {
    format!(
        r#"{preamble}
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
        preamble = manifest_preamble(30_000),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// A `script_rhai` manifest identical in shape to `rhai_bearer_manifest` but with
/// a very low per-source token-bucket rate limit, so the second lookup in quick
/// succession is rejected before dispatch. `burst: 2` matches the http_json rate
/// test: the startup smoke consumes one token, the first real request the
/// second, and the next real request finds the bucket empty.
fn rhai_rate_limited_manifest(allowlist_url: &str) -> String {
    format!(
        r#"{preamble}
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
    limits:
      requests_per_second: 1
      burst: 2
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
        preamble = manifest_preamble(30_000),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// A `script_rhai` manifest that fetches the record and runs the registered pure
/// helper `xw.text.upper_ascii` on the id, surfacing the result in a NEW field
/// (`national_id_upper`) while leaving `national_id` raw — the smoke lookup
/// matches on the raw `national_id`, so uppercasing it would break readiness.
fn rhai_xw_helper_manifest(allowlist_url: &str) -> String {
    format!(
        r#"{preamble}
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
          let r = source.get("primary", "/lookup", #{{ id: ctx.lookup.value }});
          let rec = r.body[0];
          [#{{
            national_id: rec.national_id,
            national_id_upper: xw.text.upper_ascii(rec.national_id),
          }}]
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
        preamble = manifest_preamble(30_000),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// A `script_rhai` manifest whose target has NO `visible_statuses`, so a non-2xx
/// upstream status terminates the run. Paired with `lookup_endpoint_smoke_500`,
/// the startup smoke id 500s and readiness must fail. Uses a short liveness
/// window so the smoke retry loop gives up quickly.
fn rhai_smoke_fail_manifest(allowlist_url: &str) -> String {
    format!(
        r#"{preamble}
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
        preamble = manifest_preamble(100),
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

/// 1. The bearer SECRET reaches the upstream on the wire. The script only ever
///    sees the public credential (`clientId`); the host must inject the real
///    `apiToken` secret as `Authorization: Bearer target-secret`.
#[tokio::test]
async fn rhai_bearer_secret_reaches_upstream_on_the_wire() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(rhai_bearer_manifest(&upstream_url)).await;
    // Drop the startup smoke's captured Authorization so we assert on the real
    // request only (the smoke uses the same secret, but we want a clean window).
    upstream_state.auth.lock().await.clear();
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
        json!({ "data": [{ "national_id": "person-123", "birth_date": "1990-01-01" }] })
    );

    let auth = upstream_state.auth.lock().await;
    assert!(
        auth.iter().any(|value| value == "Bearer target-secret"),
        "the host must inject the real apiToken secret on the wire, never the \
         public credential; upstream saw Authorization headers {auth:?}"
    );
    assert!(
        !auth.iter().any(|value| value.contains("public-client")),
        "the public credential must never appear in the upstream Authorization \
         header; saw {auth:?}"
    );
}

/// 2. The per-source token-bucket rate limit trips before dispatch: the second
///    lookup in quick succession is rejected with `source.target_rate_limit`
///    (503) and never reaches the upstream.
#[tokio::test]
async fn rhai_per_source_rate_limit_trips_before_dispatch() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(rhai_rate_limited_manifest(&upstream_url)).await;
    // Ignore the startup smoke's dispatch in the upstream-hit count below.
    upstream_state.seen.lock().await.clear();

    let first = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id")
        .await;
    first.assert_status_ok();

    let limited = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-456")
        .add_query_param("fields", "national_id")
        .await;

    // The rhai host reports a limiter rejection to the script as a 429, which
    // maps to `source.target_rate_limit` and a 503 problem response (matching
    // `target_error_response` / the http_json rate test).
    assert_eq!(limited.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = limited.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.target_rate_limit"),
        "expected the per-source rate limit to surface, got {body}"
    );

    let seen = upstream_state.seen.lock().await;
    assert_eq!(
        seen.iter().filter(|hit| hit.as_str() != "/lookup:smoke-person").count(),
        1,
        "only the first real lookup may reach the upstream; the rate-limited \
         second must be rejected before dispatch; saw {seen:?}"
    );
}

/// 3. A registered `xw.*` pure helper runs end-to-end through the sidecar:
///    `xw.text.upper_ascii` upper-cases the fetched id, proving the sidecar
///    wiring registers the helper namespace inside the script engine.
#[tokio::test]
async fn rhai_xw_text_helper_runs_through_sidecar() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(rhai_xw_helper_manifest(&upstream_url)).await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,national_id_upper")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({
            "data": [{
                "national_id": "person-123",
                "national_id_upper": "PERSON-123"
            }]
        }),
        "xw.text.upper_ascii must run inside the script and upper-case the id"
    );
}

/// 4. A failing startup smoke lookup blocks readiness: the upstream 500s for the
///    smoke id (and the target has no `visible_statuses`, so the run terminates),
///    so `sidecar_router(config).await` rejects startup with `Err`.
#[tokio::test]
async fn rhai_failing_smoke_lookup_blocks_readiness() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint_smoke_500))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();

    let config: SidecarConfig = serde_norway::from_str(&rhai_smoke_fail_manifest(&upstream_url))
        .expect("script_rhai manifest parses");
    // Not wrapped in a TestServer: we are asserting startup REJECTION, not
    // serving requests. The smoke id 500s, the script terminates, and the smoke
    // retry loop gives up at the (short) liveness window.
    let result = sidecar_router(config).await;
    assert!(
        result.is_err(),
        "a failing smoke lookup must make sidecar_router return Err and block readiness"
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/lookup:smoke-person"),
        "the smoke lookup must have attempted the upstream; saw {seen:?}"
    );
}
