// SPDX-License-Identifier: Apache-2.0
//! Sidecar integration tests for the `script_rhai` engine covering two
//! security-relevant contracts:
//!
//! A. **Credential-public exposure** — a script only ever sees the whitelisted
//!    `credential_public_fields` via `ctx.credential_public`; raw secrets
//!    (here `apiToken`) are never projected, and an empty whitelist hides
//!    everything (including the otherwise-public `clientId`).
//!
//! B. **Per-target `visible_statuses` gating vs the engine union** — the engine
//!    is compiled with the *union* of every target's observable statuses as the
//!    ceiling, but the host gates *per target*. A target that lists `404` can
//!    observe it (the script branches on `r.status`); a sibling target that does
//!    NOT list `404` terminates the run at the 404 before the script ever sees
//!    it, even though `404` is in the engine union. This proves the union is a
//!    ceiling only and the per-target list is authoritative.
//!
//! This file is fully self-contained (own `ENV_LOCK`, constants, `set_env`,
//! handlers, manifest builders), mirroring `tests/rhai_adapter.rs`.

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
// A dedicated credential env var name for this file (each integration-test file
// is its own process, so env does not race across files; within this file every
// test still serialises on ENV_LOCK before mutating process env).
const CREDENTIAL_ENV: &str = "RHAI_CREDENTIAL_UNION_CREDENTIAL_JSON";

const SMOKE_VALUE: &str = "smoke-person";

// Serialize env mutation across this file's tests (cargo runs `#[tokio::test]`s
// on parallel threads; the credential/token hashes are read from process env at
// `sidecar_router` time).
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Default)]
struct UpstreamState {
    seen: std::sync::Arc<Mutex<Vec<String>>>,
}

/// `/lookup?id=...` — echoes the id back as one record. Only needed to give the
/// credential-echo manifests a valid in-allowlist target with a reachable
/// `base_url`; the echo script itself never calls it.
async fn lookup_endpoint(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/lookup:{id}"));
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
}

/// `/a?id=...` — returns the smoke record (200) for the startup smoke id so the
/// primary path passes readiness, but 404s for every other id. The Part B tests
/// use this as target `a`'s endpoint; the 404 is observable only when target `a`
/// lists 404 in its `visible_statuses`.
async fn path_a(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let id = query.get("id").cloned().unwrap_or_default();
    state.seen.lock().await.push(format!("/a:{id}"));
    if id == SMOKE_VALUE {
        return (
            StatusCode::OK,
            Json(json!([{ "national_id": SMOKE_VALUE, "birth_date": "1990-01-01" }])),
        )
            .into_response();
    }
    (StatusCode::NOT_FOUND, Json(json!({ "error": "missing" }))).into_response()
}

/// `/b` — always 404. Target `b` does NOT list 404, so the host terminates the
/// run here before the script can branch on the status.
async fn path_b(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
) -> impl IntoResponse {
    state.seen.lock().await.push("/b".to_string());
    (StatusCode::NOT_FOUND, Json(json!({ "error": "missing-b" }))).into_response()
}

/// `/fallback` — a clean record, available to the Part B targets if a script
/// chooses to fall back to it (kept for parity with the briefing's upstream
/// shape; the asserted scripts use in-script literal fallbacks instead).
async fn path_fallback(
    axum::extract::State(state): axum::extract::State<UpstreamState>,
) -> impl IntoResponse {
    state.seen.lock().await.push("/fallback".to_string());
    (
        StatusCode::OK,
        Json(json!([{ "national_id": "from-fallback", "birth_date": "1970-01-01" }])),
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

async fn spawn_sidecar(manifest: String, upstream_state: UpstreamState) -> TestServer {
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("script_rhai manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("script_rhai sidecar starts and passes smoke lookup");
    let _ = upstream_state; // kept alive by the caller's TestServer
    TestServer::builder().http_transport().build(app)
}

// ---------------------------------------------------------------------------
// PART A — credential_public exposure
// ---------------------------------------------------------------------------

/// A `script_rhai` manifest whose `lookup` echoes what the script can see of the
/// credential. `credential_public_fields` is injected by the caller so the
/// whitelisted-vs-empty cases share one manifest body.
///
/// For the startup smoke id the script emits a record carrying `national_id ==
/// smoke-person` so readiness passes (the smoke checks the returned `data` array
/// contains a record whose lookup field equals the smoke value). For any other
/// id it emits the credential-echo record. The script makes NO `source.get`
/// call, so no upstream is contacted by the echo itself; the `primary` target
/// only exists to satisfy config validation (non-empty targets, in-allowlist
/// base_url).
fn rhai_credential_echo_manifest(allowlist_url: &str, public_fields_block: &str) -> String {
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
{public_fields_block}
    allowed_base_urls:
      - {allowlist_url}
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {{
          if ctx.lookup.value == "{smoke_value}" {{
            return [#{{ national_id: "{smoke_value}", birth_date: "1990-01-01" }}];
          }}
          let seen = if "apiToken" in ctx.credential_public {{ "LEAKED" }} else {{ "absent" }};
          [#{{ client_id: ctx.credential_public.clientId, api_token_seen: seen }}]
        }}
      targets:
        primary:
          base_url: {allowlist_url}
    smoke_lookup:
      field: national_id
      value: {smoke_value}
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        public_fields_block = public_fields_block,
        smoke_value = SMOKE_VALUE,
        dataset = DATASET,
        entity = ENTITY,
    )
}

#[tokio::test]
async fn script_sees_only_whitelisted_public_credential() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();

    // Whitelist exactly `clientId`. The secret `apiToken` is present in the
    // credential JSON but must NOT be projected into `ctx.credential_public`.
    let public_fields = "    credential_public_fields:\n      - clientId";
    let sidecar = spawn_sidecar(
        rhai_credential_echo_manifest(&upstream_url, public_fields),
        upstream_state.clone(),
    )
    .await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        // `fields` is REQUIRED by the sidecar; list the echo keys so the
        // projection preserves them (an omitted `fields` is a 400).
        .add_query_param("fields", "client_id,api_token_seen")
        .await;

    response.assert_status_ok();
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/data/0/client_id").and_then(Value::as_str),
        Some("public-client"),
        "the whitelisted clientId must be visible to the script, got {body}"
    );
    assert_eq!(
        body.pointer("/data/0/api_token_seen")
            .and_then(Value::as_str),
        Some("absent"),
        "the secret apiToken must NOT appear in ctx.credential_public, got {body}"
    );

    // The echo script never calls the upstream.
    let seen = upstream_state.seen.lock().await;
    assert!(
        !seen.iter().any(|hit| hit.starts_with("/lookup:person-123")),
        "the credential-echo script must not contact the upstream; saw {seen:?}"
    );
}

#[tokio::test]
async fn empty_public_fields_hides_all_credential() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/lookup", get(lookup_endpoint))
            .with_state(upstream_state.clone()),
    );
    let upstream_url = server_base_url(&upstream);
    set_env();

    // Empty whitelist: NOTHING is exposed, not even the otherwise-public
    // clientId. `credential_public_fields` defaults to empty when omitted.
    let public_fields = "    credential_public_fields: []";
    let sidecar = spawn_sidecar(
        rhai_credential_echo_manifest(&upstream_url, public_fields),
        upstream_state.clone(),
    )
    .await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "client_id,api_token_seen")
        .await;

    response.assert_status_ok();
    let body = response.json::<Value>();
    // The secret stays hidden.
    assert_eq!(
        body.pointer("/data/0/api_token_seen")
            .and_then(Value::as_str),
        Some("absent"),
        "the secret apiToken must stay hidden under an empty whitelist, got {body}"
    );
    // And clientId is now ALSO hidden: the script reads
    // `ctx.credential_public.clientId` which is missing -> Rhai unit `()`, which
    // serialises to JSON null. Assert the projected value is absent or null
    // (i.e. NOT the public-client string).
    let client_id = body.pointer("/data/0/client_id");
    assert!(
        client_id.is_none() || client_id == Some(&Value::Null),
        "clientId must be hidden under an empty whitelist (absent or null), got {body}"
    );
}

// ---------------------------------------------------------------------------
// PART B — per-target visible_statuses union vs per-target gate
// ---------------------------------------------------------------------------

/// A two-target `script_rhai` manifest. Target `a` lists `visible_statuses: [404]`
/// and target `b` lists `visible_statuses: []` (empty). The engine union is
/// therefore `{404}` (the compile ceiling), but the host gates per target. The
/// `lookup` body is injected by the caller so both Part B cases share one
/// manifest body; the smoke id always goes through target `a`'s `/a`, which
/// answers the smoke id with a clean 200.
fn rhai_two_target_manifest(allowlist_url: &str, else_branch: &str) -> String {
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
          if ctx.lookup.value == "{smoke_value}" {{
            return source.get("a", "/a", #{{ id: ctx.lookup.value }}).body;
          }}
          {else_branch}
        }}
      targets:
        a:
          base_url: {allowlist_url}
          visible_statuses:
            - 404
        b:
          base_url: {allowlist_url}
          visible_statuses: []
    smoke_lookup:
      field: national_id
      value: {smoke_value}
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = serde_json::to_string(TOKEN_HASH_ENV).expect("env serializes"),
        credential_env = serde_json::to_string(CREDENTIAL_ENV).expect("env serializes"),
        allowlist_url = serde_json::to_string(allowlist_url).expect("URL serializes"),
        else_branch = else_branch,
        smoke_value = SMOKE_VALUE,
        dataset = DATASET,
        entity = ENTITY,
    )
}

fn part_b_upstream(upstream_state: &UpstreamState) -> TestServer {
    TestServer::builder().http_transport().build(
        Router::new()
            .route("/a", get(path_a))
            .route("/b", get(path_b))
            .route("/fallback", get(path_fallback))
            .with_state(upstream_state.clone()),
    )
}

#[tokio::test]
async fn target_a_can_observe_listed_404() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = part_b_upstream(&upstream_state);
    let upstream_url = server_base_url(&upstream);
    set_env();

    // Target `a` lists 404, so the host returns `#{status:404, body}` to the
    // script and the else-branch observes `r.status == 404` and falls back.
    let else_branch = r#"let r = source.get("a", "/a", #{ id: ctx.lookup.value });
          if r.status == 404 { [#{ source: "fallback-a" }] } else { r.body }"#;
    let sidecar = spawn_sidecar(
        rhai_two_target_manifest(&upstream_url, else_branch),
        upstream_state.clone(),
    )
    .await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "source")
        .await;

    response.assert_status_ok();
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/data/0/source").and_then(Value::as_str),
        Some("fallback-a"),
        "target `a` lists 404, so the script must observe it and fall back, got {body}"
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/a:person-123"),
        "target `a` must have been hit with the real id; saw {seen:?}"
    );
}

#[tokio::test]
async fn target_b_cannot_observe_unlisted_404() {
    let _guard = ENV_LOCK.lock().await;
    let upstream_state = UpstreamState::default();
    let upstream = part_b_upstream(&upstream_state);
    let upstream_url = server_base_url(&upstream);
    set_env();

    // Target `b` does NOT list 404 (even though 404 is in the engine union via
    // target `a`). The host therefore terminates the run at the 404 BEFORE the
    // script can read `r.status`, so the literal `should-not-happen` fallback is
    // never produced.
    let else_branch = r#"let r = source.get("b", "/b", #{});
          if r.status == 404 { [#{ source: "should-not-happen" }] } else { r.body }"#;
    let sidecar = spawn_sidecar(
        rhai_two_target_manifest(&upstream_url, else_branch),
        upstream_state.clone(),
    )
    .await;

    let response = sidecar
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", "eligibility")
        .add_query_param("national_id", "person-123")
        .add_query_param("fields", "source")
        .await;

    // The non-visible 404 is a terminal upstream-status error -> source.unavailable
    // at the top-level `/code` with a 502.
    assert_eq!(
        response.status_code(),
        StatusCode::BAD_GATEWAY,
        "an unlisted 404 must terminate the run as a 502, got {}",
        response.status_code()
    );
    let body = response.json::<Value>();
    assert_eq!(
        body.pointer("/code").and_then(Value::as_str),
        Some("source.unavailable"),
        "expected source.unavailable for the unlisted 404, got {body}"
    );
    // The script never saw `r.status`, so its fallback record is absent.
    assert!(
        !body.to_string().contains("should-not-happen"),
        "the run must terminate before the script branches; `should-not-happen` leaked: {body}"
    );

    let seen = upstream_state.seen.lock().await;
    assert!(
        seen.iter().any(|hit| hit == "/b"),
        "target `b` must have been hit (the gate runs in the host, after the request); saw {seen:?}"
    );
}
