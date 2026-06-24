// SPDX-License-Identifier: Apache-2.0
//! Sidecar-level security proofs for the `script_rhai` source engine.
//!
//! The rhai crate already unit-tests the path canonicalizer (`path.rs`) and
//! proves, at the library seam, that a rejected path never reaches the host
//! (`crates/registry-notary-source-adapter-rhai/tests/path_traversal_e2e.rs`).
//! This file is the *integration* counterpart: it drives the public sidecar
//! entrypoint (`sidecar_router`) against an `axum_test` mock upstream and proves
//! that an SSRF / path-traversal attempt expressed by a script is blocked at the
//! sidecar level, end to end:
//!
//!   (a) the request surfaces as an error problem (NOT 200), whose top-level
//!       `/code` is `source.unavailable` (502 BAD_GATEWAY), and
//!   (b) the malicious path NEVER reaches the mock upstream — the mock's `seen`
//!       log records no hit for it, because the rhai bridge canonicalizes (and
//!       rejects) the path *before* the host dispatches, and the request-time IP
//!       policy rejects the cloud-metadata address *before* any connection.
//!
//! Every script branches on the lookup value so the startup smoke (which runs
//! `sidecar_router` with `smoke-person` against the upstream) succeeds via the
//! benign `/lookup` route, while the *test* request (`person-123`) takes the
//! malicious else-branch.

use axum::{
    extract::{Query, State},
    http::{StatusCode, Uri},
    response::IntoResponse,
    routing::{any, get},
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
const TOKEN_HASH_ENV: &str = "RHAI_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_ADAPTER_CREDENTIAL_JSON";

/// The cloud-metadata service address. The request-time IP policy
/// (`ensure_ip_allowed`/`is_cloud_metadata_ip`) rejects this literal before any
/// socket is opened, so a target pointed at it can never connect.
const METADATA_BASE_URL: &str = "http://169.254.169.254";

// Each integration-test file compiles as its own crate; cargo runs the
// `#[tokio::test]`s on parallel threads, and `set_env` mutates process env that
// `sidecar_router` reads. Serialize the whole body of every test behind this
// file-local lock so the env is stable for each `sidecar_router` build.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Records every upstream request path the mock actually received. If any
/// malicious path reaches the mock, it shows up here and the test fails.
#[derive(Clone, Default)]
struct UpstreamState {
    seen: Arc<Mutex<Vec<String>>>,
}

/// `/lookup?id=...` — the benign route. Echoes the id back as one record. This
/// is what the script's smoke branch hits (`id == "smoke-person"`), so the
/// startup smoke passes; it is also the only route a non-malicious request would
/// ever take.
async fn lookup_endpoint(
    State(state): State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
}

/// Catch-all route: records the requested path (and 200s with an array). It
/// exists ONLY so that, if a traversal/encoded path somehow slipped past the
/// canonicalizer and reached this upstream, the request would be served (not
/// 404'd) AND recorded in `seen` — turning a silent bypass into a loud test
/// failure rather than letting the malicious branch error for the "wrong"
/// reason. In the expected (secure) world this handler is never invoked.
async fn catch_all(State(state): State<UpstreamState>, uri: Uri) -> impl IntoResponse {
    state.seen.lock().await.push(format!(
        "CATCHALL:{}",
        uri.path_and_query()
            .map(|p| p.as_str())
            .unwrap_or(uri.path())
    ));
    (
        StatusCode::OK,
        Json(json!([{ "national_id": "leaked", "birth_date": "2000-01-01" }])),
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

/// Build a `script_rhai` manifest whose entrypoint branches on the lookup value:
/// the smoke id takes the benign `/lookup` call (so startup smoke passes), and
/// every other id runs `malicious_call` — a raw Rhai expression the test injects
/// (e.g. `source.get("primary", "/../secrets", #{})`).
///
/// `extra_targets` lets a test add a second target (used only by the
/// cloud-metadata case); it must be a YAML fragment indented to sit under
/// `rhai.targets`. `extra_allowed` adds entries under `allowed_base_urls` so the
/// metadata target passes config validation.
fn malicious_manifest(
    primary_url: &str,
    malicious_call: &str,
    extra_targets: &str,
    extra_allowed: &str,
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
      - {primary_url}{extra_allowed}
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {{
          if ctx.lookup.value == "smoke-person" {{
            source.get("primary", "/lookup", #{{ id: ctx.lookup.value }}).body
          }} else {{
            {malicious_call}.body
          }}
        }}
      targets:
        primary:
          base_url: {primary_url}
          auth:
            type: bearer
            token:
              secret: apiToken{extra_targets}
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        primary_url = serde_json::to_string(primary_url).expect("URL serializes"),
        extra_allowed = extra_allowed,
        extra_targets = extra_targets,
        malicious_call = malicious_call,
        dataset = DATASET,
        entity = ENTITY,
    )
}

/// Build the mock upstream: the benign `/lookup` route plus a catch-all that
/// records any other path it is (unexpectedly) asked for.
fn build_upstream(state: UpstreamState) -> TestServer {
    TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .fallback(any(catch_all))
            .with_state(state),
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

/// Drive the sidecar with the real (non-smoke) id so the malicious else-branch
/// runs. Returns the raw response for the caller to assert on.
async fn drive_malicious(sidecar: &TestServer) -> axum_test::TestResponse {
    sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "national_id,birth_date")
        .await
}

/// Assert the standard "blocked" outcome: a 502 problem whose top-level `/code`
/// is `source.unavailable`, and NOT a 200.
fn assert_blocked(response: &axum_test::TestResponse) {
    assert_ne!(
        response.status_code(),
        StatusCode::OK,
        "malicious request must NOT succeed with 200"
    );
    assert_eq!(
        response.status_code(),
        StatusCode::BAD_GATEWAY,
        "blocked malicious request should map to 502 BAD_GATEWAY"
    );
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.unavailable"),
        "expected top-level /code = source.unavailable, got body {body}"
    );
    // Defense in depth: a leaked record would carry national_id == "leaked".
    assert!(
        body.pointer("/data").is_none(),
        "a blocked request must not return a data array, got {body}"
    );
}

/// Assert the mock upstream never saw anything beyond the benign smoke lookup —
/// in particular, no catch-all hit and no request mentioning `needle`.
async fn assert_upstream_clean(state: &UpstreamState, needle: &str) {
    let seen = state.seen.lock().await;
    assert!(
        !seen.iter().any(|hit| hit.starts_with("CATCHALL:")),
        "the malicious path must be blocked BEFORE reaching the upstream; \
         upstream catch-all was hit: {seen:?}"
    );
    assert!(
        !seen.iter().any(|hit| hit.contains(needle)),
        "the upstream must never see {needle:?}; saw {seen:?}"
    );
    // Sanity: the only thing the upstream should ever have seen is the smoke.
    assert!(
        seen.iter().all(|hit| hit == "/lookup:smoke-person"),
        "the upstream should only have served the startup smoke; saw {seen:?}"
    );
}

/// Shared driver for the single-target traversal/SSRF cases: build the upstream,
/// spawn the sidecar with the injected malicious call, drive the real id, and
/// assert (a) blocked with `source.unavailable` and (b) upstream never saw the
/// needle.
async fn run_blocked_case(malicious_call: &str, needle: &str) {
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = build_upstream(state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();
    let sidecar = spawn_sidecar(malicious_manifest(&upstream_url, malicious_call, "", "")).await;

    let response = drive_malicious(&sidecar).await;

    assert_blocked(&response);
    assert_upstream_clean(&state, needle).await;
}

#[tokio::test]
async fn dotdot_path_blocked() {
    // `/../secrets` — a literal parent-directory traversal. The canonicalizer
    // rejects the `..` segment in the bridge, before the host dispatches.
    run_blocked_case(r#"source.get("primary", "/../secrets", #{})"#, "secrets").await;
}

#[tokio::test]
async fn encoded_dotdot_blocked() {
    // `/%2e%2e/secrets` — percent-encoded `..`. Decoded once to `..`, then
    // rejected as a traversal segment (encoding does not smuggle it past).
    run_blocked_case(
        r#"source.get("primary", "/%2e%2e/secrets", #{})"#,
        "secrets",
    )
    .await;
}

#[tokio::test]
async fn encoded_separator_blocked() {
    // `/foo%2fbar` — an encoded forward slash, rejected outright (it would
    // otherwise silently address the different resource `foo/bar`).
    run_blocked_case(r#"source.get("primary", "/foo%2fbar", #{})"#, "foo").await;
}

#[tokio::test]
async fn encoded_backslash_separator_blocked() {
    // `/foo%5cbar` — an encoded backslash, a common traversal/normalization
    // vector, rejected after decode. (Companion to the `%2f` case above.)
    run_blocked_case(r#"source.get("primary", "/foo%5cbar", #{})"#, "foo").await;
}

#[tokio::test]
async fn query_in_path_blocked() {
    // `/lookup?evil=1` — a query component embedded in the path. The
    // canonicalizer rejects `?` outright, so the script cannot append arbitrary
    // query state to a path (it must use the typed query map). Note this is
    // blocked in the bridge BEFORE the host, even though `/lookup` is a real
    // upstream route.
    run_blocked_case(r#"source.get("primary", "/lookup?evil=1", #{})"#, "evil").await;
}

#[tokio::test]
async fn protocol_relative_blocked() {
    // `//evil.example.com/x` — a protocol-relative path that, if joined naively,
    // could re-target the request at an attacker host. Rejected as multiple
    // leading slashes.
    run_blocked_case(
        r#"source.get("primary", "//evil.example.com/x", #{})"#,
        "evil.example.com",
    )
    .await;
}

#[tokio::test]
async fn cloud_metadata_ip_blocked() {
    // Request-time IP policy: a SECOND target `meta` points at the cloud-metadata
    // address. It is added to `allowed_base_urls` so config validation passes,
    // but `ensure_ip_allowed`/`is_cloud_metadata_ip` rejects 169.254.169.254 at
    // request time — the host parses it as an IP literal and fails closed BEFORE
    // opening any socket, so the run cannot hang and nothing connects.
    let _guard = ENV_LOCK.lock().await;
    let state = UpstreamState::default();
    let upstream = build_upstream(state.clone());
    let upstream_url = server_base_url(&upstream);
    set_env();

    // `primary` stays the smoke target (real upstream); `meta` is the SSRF
    // target the malicious branch calls.
    let extra_targets = format!(
        "\n        meta:\n          base_url: {}",
        serde_json::to_string(METADATA_BASE_URL).expect("URL serializes")
    );
    let extra_allowed = format!(
        "\n      - {}",
        serde_json::to_string(METADATA_BASE_URL).expect("URL serializes")
    );
    let manifest = malicious_manifest(
        &upstream_url,
        r#"source.get("meta", "/latest/meta-data/", #{})"#,
        &extra_targets,
        &extra_allowed,
    );
    let sidecar = spawn_sidecar(manifest).await;

    let response = drive_malicious(&sidecar).await;

    // The metadata fetch is rejected pre-connect and surfaces as a 502
    // source.unavailable problem (transport failure class), never a 200.
    assert_blocked(&response);

    // Nothing should have reached our mock upstream beyond the smoke (the
    // metadata address is a different host entirely), and the run must have
    // returned promptly — if it had hung, the test would time out instead.
    let seen = state.seen.lock().await;
    assert!(
        seen.iter().all(|hit| hit == "/lookup:smoke-person"),
        "only the startup smoke should have reached the mock upstream; saw {seen:?}"
    );
}
