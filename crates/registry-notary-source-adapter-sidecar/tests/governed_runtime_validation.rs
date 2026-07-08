// SPDX-License-Identifier: Apache-2.0

//! Source-adapter sidecar startup coverage after the TUF governed-config
//! loader was retired. The sidecar now accepts a local manifest directly and
//! keeps the release-helper target rendering/validation path for bundle
//! authoring workflows.

use axum::{extract::Query, routing::get, Json, Router};
use axum_test::TestServer;
use registry_notary_source_adapter_sidecar::{
    load_startup_config, load_startup_config_with_options, render_governed_runtime_target_json,
    verify_governed_bundle_report_json,
};
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::Mutex;

const TOKEN_HASH_ENV: &str = "GOVERNED_RUNTIME_VALIDATION_TOKEN_HASH";
const CREDENTIAL_ENV: &str = "GOVERNED_RUNTIME_VALIDATION_CREDENTIAL_JSON";
const SOURCE_ID: &str = "http_people";

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

async fn person_lookup(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    let results = match id.as_str() {
        "smoke-person" => json!([
            {
                "national_id": "smoke-person",
                "birth_date": "1990-01-01"
            }
        ]),
        _ => json!([]),
    };
    Json(json!({ "results": results }))
}

fn server_base_url(server: &TestServer) -> String {
    server
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string()
        .trim_end_matches('/')
        .to_string()
}

struct Harness {
    _env_guard: tokio::sync::MutexGuard<'static, ()>,
    _upstream: TestServer,
    upstream_url: String,
}

impl Harness {
    async fn new() -> Self {
        let env_guard = ENV_LOCK.lock().await;
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/people", get(person_lookup)));
        let upstream_url = server_base_url(&upstream);
        Self {
            _env_guard: env_guard,
            _upstream: upstream,
            upstream_url,
        }
    }

    fn manifest(&self) -> String {
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 1
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
sources:
  {source_id}:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: {credential_env}
    credential_public_fields:
      - baseUrl
    allowed_base_urls:
      - {base_url}
    allow_insecure_localhost: true
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/people"
      query:
        id:
          cel: lookup.value
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
            token_hash_env = yaml_string(TOKEN_HASH_ENV),
            source_id = SOURCE_ID,
            credential_env = yaml_string(CREDENTIAL_ENV),
            base_url = yaml_string(&self.upstream_url),
        )
    }

    fn target_bytes(&self) -> Vec<u8> {
        render_governed_runtime_target_json(&self.manifest())
            .expect("governed http_json runtime target renders")
    }

    fn manifest_with_assurance(&self) -> String {
        format!(
            r#"{}
assurance:
  status: accepted
  product: registry-notary-source-adapter-sidecar
  instance_id: source-adapter-test
  environment: test
  stream_id: sidecar-runtime
  bundle_id: sidecar-runtime-bundle
  sequence: 7
  config_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  signer_kids: []
  expression_hashes_verified: true
  runtime_verified: true
  smoke_verified: true
"#,
            self.manifest()
        )
    }
}

#[tokio::test]
async fn governed_target_renders_http_json_runtime_and_verifies_locally() {
    let harness = Harness::new().await;
    let target_bytes = harness.target_bytes();
    let target: Value = serde_json::from_slice(&target_bytes).expect("target is JSON");

    assert_eq!(
        target["schema"],
        "registry.notary.source_adapter_sidecar.runtime.v1"
    );
    assert_eq!(target["sources"][SOURCE_ID]["engine"], "http_json");

    let verify_report = verify_governed_bundle_report_json(&target_bytes)
        .expect("plain http_json-only target verifies");
    assert_eq!(verify_report["verified"], true);
    assert_eq!(verify_report["target_name"], "<local-target-json>");
    assert_eq!(verify_report["config_hash"], sha256_uri(&target_bytes));
}

#[tokio::test]
async fn startup_loader_accepts_local_manifest_without_dev_escape_hatch() {
    let harness = Harness::new().await;
    let config = load_startup_config(&harness.manifest())
        .await
        .expect("local manifest parses");

    assert!(config.config_trust.is_none());
    assert!(config.assurance.is_none());
}

#[tokio::test]
async fn startup_loader_populates_local_manifest_assurance() {
    let harness = Harness::new().await;
    let config = load_startup_config(&harness.manifest_with_assurance())
        .await
        .expect("local manifest with assurance parses");

    let assurance = config.assurance.expect("assurance is populated");
    assert_eq!(assurance.status, "accepted");
    assert_eq!(assurance.instance_id, "source-adapter-test");
    assert_eq!(
        assurance.config_hash,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(assurance.expression_hashes_verified);
    assert!(assurance.runtime_verified);
    assert!(assurance.smoke_verified);
}

#[tokio::test]
async fn startup_loader_rejects_legacy_config_trust_tuf_startup() {
    let harness = Harness::new().await;
    let raw = format!(
        r#"{}
config_trust:
  accepted_roots: []
"#,
        harness.manifest()
    );

    let error = load_startup_config_with_options(&raw, true)
        .await
        .expect_err("legacy sidecar TUF bootstrap is rejected");

    assert!(error
        .to_string()
        .contains("config_trust TUF startup is no longer supported"));
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

#[tokio::test]
async fn release_helper_verify_rejects_wrong_runtime_target_schema() {
    let target = serde_json::to_vec(&json!({
        "schema": "registry.notary.source_adapter_sidecar.runtime.v2",
        "limits": {
            "max_workers": 1,
            "worker_timeout_ms": 250,
            "max_output_bytes": 4096,
            "max_request_bytes": 2048,
            "max_query_parameter_bytes": 128,
            "liveness_window_ms": 30000,
            "max_batch_items": 100
        },
        "sources": {}
    }))
    .expect("target serializes");

    let error = verify_governed_bundle_report_json(&target).expect_err("wrong schema is rejected");

    assert!(error
        .to_string()
        .contains("governed runtime target schema is unsupported"));
}
