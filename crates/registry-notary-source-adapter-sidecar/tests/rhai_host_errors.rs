// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for `script_rhai` *host error* mapping.
//!
//! These drive the public sidecar entrypoint against an `axum_test` mock
//! upstream and assert that each `source.get` failure mode surfaces the correct
//! top-level problem `/code` and HTTP status. The pipeline under test is
//! `RhaiHttpHost::source_get` -> `SourceScriptError` -> `execute_rhai` building
//! `{ "error": { "code": ... } }` -> the sidecar flattening that to a top-level
//! `/code` plus a 502/503/504 status.
//!
//! Each integration-test file compiles as its own crate, so this file is fully
//! self-contained (its own imports, constants, helpers, `set_env`, mock
//! handlers, manifest builder, and `ENV_LOCK`). Every test acquires `ENV_LOCK`
//! first because cargo runs the `#[tokio::test]`s on parallel threads and the
//! credential/token hashes are read from process env at `sidecar_router` time.
//!
//! The startup smoke is the recurring hazard: `sidecar_router(config).await`
//! runs the script's primary path with `smoke_lookup.value` ("smoke-person")
//! against the upstream BEFORE returning. It MUST succeed or the router will not
//! build. So upstream-driven failures are gated to the real id ("person-123")
//! while "smoke-person" gets a clean 200 JSON array, and script-driven failures
//! branch on `ctx.lookup.value` so the smoke takes the clean primary path.

use axum::{
    extract::Query, extract::State, http::StatusCode, response::IntoResponse, response::Response,
    routing::get, Json, Router,
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
const TOKEN_HASH_ENV: &str = "RHAI_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_ADAPTER_CREDENTIAL_JSON";

const SMOKE_ID: &str = "smoke-person";
const TEST_ID: &str = "person-123";

// Serialize env mutation across this file's tests (the credential/token hashes
// are read at `sidecar_router` time from process env).
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Default)]
struct UpstreamState {
    seen: Arc<Mutex<Vec<String>>>,
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

/// A small, valid record for the given id (well under any tightened
/// `max_output_bytes`). Used to satisfy the startup smoke.
fn small_record(id: &str) -> Value {
    json!([{ "national_id": id, "birth_date": "1990-01-01" }])
}

// -------------------------------------------------------------------------
// Mock upstream handlers. Each records the id it observed in `seen` so tests
// can assert exactly which calls reached the upstream.
// -------------------------------------------------------------------------

/// Records the `authorization` header verbatim and echoes the id back as one
/// record. Used by the auth-reaches-upstream happy path.
async fn auth_recording_endpoint(
    State(state): State<UpstreamState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    state.seen.lock().await.push(format!("auth={auth}"));
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    Json(small_record(&id))
}

/// Clean 200 for the smoke id, 401 for the test id (one thin wrapper per status
/// so each handler is a plain `fn` axum can route directly).
async fn status_endpoint_401(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    status_endpoint(state, query, StatusCode::UNAUTHORIZED).await
}

async fn status_endpoint_403(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    status_endpoint(state, query, StatusCode::FORBIDDEN).await
}

async fn status_endpoint_429(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    status_endpoint(state, query, StatusCode::TOO_MANY_REQUESTS).await
}

/// Shared body: clean 200 for the smoke id, `error_status` for the test id.
async fn status_endpoint(
    state: UpstreamState,
    query: HashMap<String, String>,
    error_status: StatusCode,
) -> Response {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    if id == SMOKE_ID {
        return (StatusCode::OK, Json(small_record(SMOKE_ID))).into_response();
    }
    (error_status, Json(json!({ "error": "denied" }))).into_response()
}

/// Responds fast with a clean 200 for the smoke id, but sleeps past the worker
/// timeout for the test id so the reqwest client's `send()` times out.
async fn slow_endpoint(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    if id != SMOKE_ID {
        // Longer than `limits.worker_timeout_ms` (300ms) so the client times out.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    }
    (StatusCode::OK, Json(small_record(&id)))
}

/// Returns a clean JSON 200 for the smoke id but a plain-text (non-JSON) 200 for
/// the test id, so the response-body JSON parse fails.
async fn non_json_endpoint(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    if id == SMOKE_ID {
        return (StatusCode::OK, Json(small_record(SMOKE_ID))).into_response();
    }
    (StatusCode::OK, "this is not json at all, plainly text").into_response()
}

/// Returns a small JSON array for the smoke id but a large JSON array (well over
/// a tightened `max_output_bytes`) for the test id.
async fn oversized_endpoint(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    if id == SMOKE_ID {
        return (StatusCode::OK, Json(small_record(SMOKE_ID))).into_response();
    }
    // Build an array whose serialized size comfortably exceeds 256 bytes.
    let big: Vec<Value> = (0..50)
        .map(|i| json!({ "national_id": format!("padding-value-number-{i:04}"), "birth_date": "1990-01-01" }))
        .collect();
    (StatusCode::OK, Json(Value::Array(big))).into_response()
}

/// Plain echo endpoint: returns one record for whatever id it is asked for.
/// Used where the smoke and the (failing-for-other-reasons) test id both want a
/// clean 200 (e.g. the max-http-calls and unknown-target cases, where the
/// failure is script/host driven rather than upstream driven).
async fn echo_endpoint(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    Json(small_record(&id))
}

// -------------------------------------------------------------------------
// Manifest builders. The base manifest fetches `/lookup?id=<value>` from the
// single `primary` target. Callers inject the top-level `limits` block, the
// optional `rhai.limits` block, and the script body so one shape serves every
// failure mode.
// -------------------------------------------------------------------------

#[derive(Default)]
struct ManifestParts<'a> {
    /// Top-level `limits.worker_timeout_ms` (defaults to 500 when None).
    worker_timeout_ms: Option<u64>,
    /// Top-level `limits.max_output_bytes` (defaults to 4096 when None).
    max_output_bytes: Option<usize>,
    /// An optional `rhai.limits:` YAML block (already indented to sit under
    /// `rhai:`), e.g. "      limits:\n        max_http_calls: 1\n".
    rhai_limits_block: &'a str,
    /// The Rhai `script: |` body lines, already indented 8 spaces under
    /// `script:`. Must define `fn lookup(ctx) { ... }`.
    script_body: &'a str,
}

fn manifest(allowlist_url: &str, parts: &ManifestParts<'_>) -> String {
    let worker_timeout_ms = parts.worker_timeout_ms.unwrap_or(500);
    let max_output_bytes = parts.max_output_bytes.unwrap_or(4096);
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
  worker_timeout_ms: {worker_timeout_ms}
  max_output_bytes: {max_output_bytes}
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
{rhai_limits_block}      script: |
{script_body}
      targets:
        primary:
          base_url: {allowlist_url}
          auth:
            type: bearer
            token:
              secret: apiToken
    smoke_lookup:
      field: national_id
      value: {smoke_id}
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        dataset = DATASET,
        entity = ENTITY,
        smoke_id = SMOKE_ID,
        worker_timeout_ms = worker_timeout_ms,
        max_output_bytes = max_output_bytes,
        rhai_limits_block = parts.rhai_limits_block,
        script_body = parts.script_body,
    )
}

/// The plain primary-path script: one `source.get("primary", "/lookup", ...)`.
const SCRIPT_PLAIN: &str = r#"        fn lookup(ctx) {
          source.get("primary", "/lookup", #{ id: ctx.lookup.value }).body
        }"#;

async fn spawn_sidecar(manifest: String) -> TestServer {
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("script_rhai manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("script_rhai sidecar starts and passes smoke lookup");
    TestServer::builder().http_transport().build(app)
}

/// Drive the real (non-smoke) lookup for `person-123`.
async fn drive_lookup(sidecar: &TestServer) -> axum_test::TestResponse {
    sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", TEST_ID)
        .add_query_param("fields", "national_id,birth_date")
        .await
}

/// Assert the response carries the expected top-level `/code` and HTTP status.
fn assert_problem(response: &axum_test::TestResponse, status: StatusCode, code: &str) {
    let observed_status = response.status_code();
    let body = response.json::<Value>();
    assert_eq!(
        observed_status, status,
        "expected HTTP {status} got {observed_status}; body {body}"
    );
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some(code),
        "expected problem code {code:?}, got body {body}"
    );
}

// =========================================================================
// 1. Happy path: the configured bearer token reaches the upstream.
// =========================================================================
#[tokio::test]
async fn auth_bearer_reaches_upstream() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(auth_recording_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({ "data": [{ "national_id": TEST_ID, "birth_date": "1990-01-01" }] })
    );

    let seen = state.seen.lock().await;
    // The token is the credential field named by auth.token.secret = apiToken,
    // whose value is "target-secret".
    assert!(
        seen.iter().any(|hit| hit == "auth=Bearer target-secret"),
        "the upstream must see the configured bearer token; saw {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|hit| hit.as_str() == format!("/lookup:{TEST_ID}")),
        "the real lookup must reach the upstream; saw {seen:?}"
    );
}

// =========================================================================
// 2. Upstream 401 -> source.target_auth (502).
// =========================================================================
#[tokio::test]
async fn upstream_401_maps_target_auth() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(status_endpoint_401))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.target_auth");
}

// =========================================================================
// 3. Upstream 403 -> source.target_auth (502).
// =========================================================================
#[tokio::test]
async fn upstream_403_maps_target_auth() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(status_endpoint_403))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.target_auth");
}

// =========================================================================
// 4. Upstream 429 (target has NO visible_statuses) -> source.target_rate_limit
//    (503).
// =========================================================================
#[tokio::test]
async fn upstream_429_maps_target_rate_limit() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(status_endpoint_429))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.target_rate_limit",
    );
}

// =========================================================================
// 5. Upstream slower than the worker timeout -> source.timeout (504).
//    The outbound reqwest client is built with `.timeout(worker_timeout_ms)`,
//    so a `send()` that outlasts it is classified as a deadline. We set the
//    worker timeout to 300ms and sleep 600ms for the test id (the smoke id
//    still responds immediately).
// =========================================================================
#[tokio::test]
async fn upstream_timeout_maps_source_timeout() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(slow_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            worker_timeout_ms: Some(300),
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::GATEWAY_TIMEOUT, "source.timeout");
}

// =========================================================================
// 6. Non-JSON 200 body -> source.unavailable (502).
// =========================================================================
#[tokio::test]
async fn non_json_body_maps_unavailable() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(non_json_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.unavailable");
}

// =========================================================================
// 7. Oversized 200 body (> max_output_bytes) -> source.unavailable (502).
//    The host reads the response bounded by the top-level
//    `limits.max_output_bytes`; we tighten it to 256 and return a large array
//    for the test id (the smoke record stays tiny).
// =========================================================================
#[tokio::test]
async fn oversized_body_maps_unavailable() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(oversized_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            max_output_bytes: Some(256),
            script_body: SCRIPT_PLAIN,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.unavailable");
}

// =========================================================================
// 8. max_http_calls exceeded -> source.unavailable (502).
//    `rhai.limits.max_http_calls: 1`. The script makes ONE call for the smoke
//    id (which passes), but TWO calls for the test id; the second trips the
//    HTTP-call budget before dispatch.
// =========================================================================
#[tokio::test]
async fn max_http_calls_exceeded_unavailable() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(echo_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let script = r#"        fn lookup(ctx) {
          if ctx.lookup.value == "smoke-person" {
            source.get("primary", "/lookup", #{ id: ctx.lookup.value }).body
          } else {
            source.get("primary", "/lookup", #{ id: ctx.lookup.value });
            source.get("primary", "/lookup", #{ id: ctx.lookup.value }).body
          }
        }"#;
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            rhai_limits_block: "      limits:\n        max_http_calls: 1\n",
            script_body: script,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.unavailable");
}

// =========================================================================
// 9. Unknown target -> source.unavailable (502), and the upstream is never hit
//    for that call. The script branches: the smoke takes the valid primary
//    path; the real id calls an undeclared target.
// =========================================================================
#[tokio::test]
async fn unknown_target_unavailable() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(echo_endpoint))
            // `/x` exists on the mock but should never be reached: the unknown
            // target is rejected by the host before any request is built.
            .route("/x", get(echo_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    let script = r#"        fn lookup(ctx) {
          if ctx.lookup.value == "smoke-person" {
            source.get("primary", "/lookup", #{ id: ctx.lookup.value }).body
          } else {
            source.get("does_not_exist", "/x", #{}).body
          }
        }"#;
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: script,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.unavailable");

    let seen = state.seen.lock().await;
    // The unknown-target call must never reach the upstream.
    assert!(
        !seen
            .iter()
            .any(|hit| hit == "/lookup:does_not_exist" || hit.starts_with("/x")),
        "the unknown-target call must not reach the upstream; saw {seen:?}"
    );
    // And specifically the test-id lookup must not have hit the real endpoint.
    assert!(
        !seen
            .iter()
            .any(|hit| hit.as_str() == format!("/lookup:{TEST_ID}")),
        "the real id must not reach the primary endpoint via an unknown target; saw {seen:?}"
    );
}

// =========================================================================
// 10. Invalid query-parameter name (F1 guard) -> source.unavailable (502), and
//     the upstream never receives that request. The script else-branch passes a
//     parameter name containing a newline; the host validates names and fails
//     the call closed before `send()`.
// =========================================================================
#[tokio::test]
async fn invalid_query_param_name_rejected() {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(echo_endpoint))
            .with_state(state.clone()),
    );
    let url = server_base_url(&upstream);
    set_env();
    // `"bad\nname"` is a double-quoted Rhai string literal; Rhai interprets the
    // `\n` as a newline, producing a control character in the param name. The
    // smoke branch uses a clean param name so readiness passes.
    let script = "        fn lookup(ctx) {\n          if ctx.lookup.value == \"smoke-person\" {\n            source.get(\"primary\", \"/lookup\", #{ id: ctx.lookup.value }).body\n          } else {\n            source.get(\"primary\", \"/lookup\", #{ \"bad\\nname\": ctx.lookup.value }).body\n          }\n        }";
    let sidecar = spawn_sidecar(manifest(
        &url,
        &ManifestParts {
            script_body: script,
            ..Default::default()
        },
    ))
    .await;

    let response = drive_lookup(&sidecar).await;
    assert_problem(&response, StatusCode::BAD_GATEWAY, "source.unavailable");

    let seen = state.seen.lock().await;
    // The rejected call must never reach the upstream: there must be no hit for
    // the test id (only the smoke id should appear, from startup readiness).
    assert!(
        !seen
            .iter()
            .any(|hit| hit.as_str() == format!("/lookup:{TEST_ID}")),
        "the invalid-param call must be failed closed before reaching the upstream; saw {seen:?}"
    );
}
