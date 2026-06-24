// SPDX-License-Identifier: Apache-2.0
//! Negative-path integration tests for `validate_rhai_source` and one positive control.
//!
//! Each test builds a manifest that passes ALL earlier validation checks and trips
//! exactly one rejection branch. Config errors are returned from `sidecar_router`
//! as `SidecarError::Config(msg)` before any network activity.

use axum::{extract::Query, routing::get, Json, Router};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig, SidecarError};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::Mutex;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
#[allow(dead_code)]
const TOKEN: &str = "http-json-sidecar-token";
const TOKEN_HASH_ENV: &str = "RHAI_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:569f528c8a6aaa329fb4ba077327b7cd6f44ceb931f0e45483b558f26eb6299c";
const CREDENTIAL_ENV: &str = "RHAI_ADAPTER_CREDENTIAL_JSON";

// Serialize env mutation across tests within this process.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

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

async fn lookup_endpoint(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let id = q.get("id").cloned().unwrap_or_default();
    Json(json!([{ "national_id": id, "birth_date": "1990-01-01" }]))
}

/// Baseline valid manifest (used for positive control and as the template to mutate).
/// All negative tests start from this shape and perturb exactly one field.
fn base_manifest(url: &str) -> String {
    let url_json = serde_json::to_string(url).expect("URL serializes");
    let token_hash_env_json =
        serde_json::to_string(TOKEN_HASH_ENV).expect("token hash env serializes");
    let credential_env_json =
        serde_json::to_string(CREDENTIAL_ENV).expect("credential env serializes");
    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env_json}
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
    dataset: {DATASET}
    entity: {ENTITY}
    credential_env: {credential_env_json}
    credential_public_fields:
      - clientId
    allowed_base_urls:
      - {url_json}
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {{
          source.get("primary", "/lookup", #{{ id: ctx.lookup.value }}).body
        }}
      targets:
        primary:
          base_url: {url_json}
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
        token_hash_env_json = token_hash_env_json,
        credential_env_json = credential_env_json,
        url_json = url_json,
        DATASET = DATASET,
        ENTITY = ENTITY,
    )
}

/// Helper: assert that parsing + routing the manifest produces a Config error
/// containing the given substring.
async fn assert_config_error(manifest: &str, expected_substring: &str) {
    let config: SidecarConfig = serde_norway::from_str(manifest)
        .unwrap_or_else(|e| panic!("manifest YAML failed to parse: {e}\n---\n{manifest}"));
    let err = sidecar_router(config)
        .await
        .expect_err("must be rejected by validate_rhai_source");
    assert!(
        matches!(&err, SidecarError::Config(msg) if msg.contains(expected_substring)),
        "expected SidecarError::Config containing {expected_substring:?}, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 1 – http_json block present alongside script_rhai engine
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn http_json_block_rejected_for_rhai_engine() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    http_json:
      base_url:
        cel: '"http://127.0.0.1:9999"'
      path: "/lookup"
      response:
        records:
          cel: "result"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "http_json config is not valid when engine is script_rhai",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 2 – http_flow block present
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn http_flow_block_rejected_for_rhai_engine() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    http_flow:
      steps: []
      output:
        records:
          cel: "result"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "http_flow config is not valid when engine is script_rhai",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 3 – fhir block present
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn fhir_block_rejected_for_rhai_engine() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    fhir:
      base_url: "http://127.0.0.1:9999"
      anchor:
        id: "anchor-node"
        resource_type: "Patient"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "fhir config is not valid when engine is script_rhai",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 4 – batch.mode = workflow_batch (unsupported)
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn workflow_batch_mode_rejected_for_rhai_engine() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    batch:
      mode: workflow_batch
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "batch.mode is not supported for script_rhai sources",
    )
    .await;
}

// Branch 4b – batch.mode = native_batch (also unsupported)
#[tokio::test]
async fn native_batch_mode_rejected_for_rhai_engine() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    batch:
      mode: native_batch
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "batch.mode is not supported for script_rhai sources",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 5 – batch.max_parallel set without batch.mode parallel_lookup
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn batch_max_parallel_without_parallel_lookup_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    batch:
      max_parallel: 4
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "batch.max_parallel requires batch.mode parallel_lookup",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 6 – allowed_base_urls empty
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn empty_allowed_base_urls_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls: []
    allow_insecure_localhost: true
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "allowed_base_urls is required for script_rhai").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 7 – rhai block missing
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn missing_rhai_block_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "engine script_rhai requires a rhai config").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 8 – rhai.targets empty
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn empty_rhai_targets_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets: {}
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "rhai.targets must not be empty").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 9 – target base_url not a parseable URL
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn invalid_target_base_url_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "not a url at all !!!"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "base_url must be a URL").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 10 – target base_url not within allowed_base_urls
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn target_base_url_not_in_allowlist_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://allowed.example.com"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://different.example.com"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "base_url is not in allowed_base_urls").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 11 – bearer auth with invalid (dotted) token secret ref
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn bearer_auth_dotted_secret_ref_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
          auth:
            type: bearer
            token:
              secret: "a.b"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "auth.token.secret must name one top-level credential field",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 12a – basic auth with invalid username secret ref
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn basic_auth_invalid_username_secret_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
          auth:
            type: basic
            username:
              secret: "nested.field"
            password:
              secret: "apiToken"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "auth.username.secret must name one top-level credential field",
    )
    .await;
}

// Branch 12b – basic auth with invalid password secret ref
#[tokio::test]
async fn basic_auth_invalid_password_secret_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
          auth:
            type: basic
            username:
              secret: "clientId"
            password:
              secret: "nested.pwd"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(
        manifest,
        "auth.password.secret must name one top-level credential field",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 13 – target has auth but credential_env is empty/omitted
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn auth_without_credential_env_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: ""
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
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
"#;
    assert_config_error(
        manifest,
        "credential_env is required when a rhai target configures auth",
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 14a – script with a syntax error fails to compile
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn bad_script_syntax_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: ""
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) {
          THIS IS NOT VALID RHAI SYNTAX !!!@#$%
        }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "rhai script failed to compile:").await;
}

// Branch 14b – valid syntax but missing entrypoint function → compile failure
// This is the "sidecar startup fails on a bad script" guarantee.
#[tokio::test]
async fn bad_script_fails_router_startup() {
    // A script with valid syntax but no `lookup` function (the required entrypoint).
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: ""
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn not_the_lookup_entrypoint(ctx) {
          []
        }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "rhai script failed to compile:").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch 15 – visible_statuses entry outside 100..=599
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn visible_statuses_out_of_range_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
          visible_statuses:
            - 999
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "visible_statuses contains an invalid HTTP status").await;
}

// Branch 15b – zero is also out of range
#[tokio::test]
async fn visible_statuses_zero_rejected() {
    let manifest = r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: "RHAI_SIDECAR_TOKEN_HASH"
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
    dataset: civil_registry
    entity: civil_person
    credential_env: "RHAI_ADAPTER_CREDENTIAL_JSON"
    allowed_base_urls:
      - "http://127.0.0.1:9999"
    allow_insecure_localhost: true
    rhai:
      script: |
        fn lookup(ctx) { [] }
      targets:
        primary:
          base_url: "http://127.0.0.1:9999"
          visible_statuses:
            - 0
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#;
    assert_config_error(manifest, "visible_statuses contains an invalid HTTP status").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Positive control – a fully-valid manifest builds the router successfully
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn valid_manifest_builds_router() {
    let _guard = ENV_LOCK.lock().await;
    set_env();

    // Spin up a mock upstream that echoes any id (satisfies the startup smoke).
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/lookup", get(lookup_endpoint)));
    let url = server_base_url(&upstream);

    let manifest = base_manifest(&url);
    let config: SidecarConfig =
        serde_norway::from_str(&manifest).expect("valid manifest YAML parses");
    // sidecar_router runs the smoke lookup; it must succeed.
    let _ = sidecar_router(config)
        .await
        .expect("valid script_rhai manifest must build the router");
}
