// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use registry_witness_openfn_sidecar::{sidecar_router, SidecarConfig};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const LOOKUP_FIELD: &str = "national_id";
const PURPOSE: &str = "https://purpose.example.test/eligibility";
const TOKEN: &str = "contract-sidecar-token";
const TOKEN_HASH_ENV: &str = "OPENFN_CONTRACT_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:98808b694f3b431dcc2459db07bbfb61b8e3287ad0ab7364a2ff510d35e21418";
const CREDENTIAL_ENV: &str = "OPENCRVS_READER_CREDENTIAL_JSON";

struct ContractHarness {
    server: TestServer,
    attempt_log: PathBuf,
    _tmp: TempDir,
}

#[derive(Clone, Copy)]
struct HarnessOptions {
    max_workers: usize,
    worker_timeout_ms: u64,
    max_output_bytes: usize,
    liveness_window_ms: u64,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            max_workers: 2,
            worker_timeout_ms: 250,
            max_output_bytes: 4096,
            liveness_window_ms: 30_000,
        }
    }
}

async fn contract_harness(options: HarnessOptions) -> ContractHarness {
    set_sidecar_token_hash();
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let manifest = manifest_yaml(&options, &attempt_log);
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("sidecar router builds from contract manifest");
    let server = TestServer::builder().http_transport().build(app);

    ContractHarness {
        server,
        attempt_log,
        _tmp: tmp,
    }
}

fn manifest_yaml(options: &HarnessOptions, attempt_log: &Path) -> String {
    set_sidecar_token_hash();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let worker = fixtures.join("contract_worker.sh");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");

    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: witness-contract
      hash_env: {token_hash_env}
limits:
  max_workers: {max_workers}
  worker_timeout_ms: {worker_timeout_ms}
  max_output_bytes: {max_output_bytes}
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: {liveness_window_ms}
  max_worker_memory_mb: 256
openfn:
  cli_build_tool: "1.36.0"
  runtime: "1.36.0"
worker:
  command: "/bin/sh"
  args:
    - {worker}
    - {attempt_log}
sources:
  openfn_crvs:
    dataset: civil_registry
    entity: civil_person
    job: {job}
    adaptor: "@openfn/language-http@7.2.0"
    credential_env: {credential_env}
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = yaml_string(TOKEN_HASH_ENV),
        max_workers = options.max_workers,
        worker_timeout_ms = options.worker_timeout_ms,
        max_output_bytes = options.max_output_bytes,
        liveness_window_ms = options.liveness_window_ms,
        worker = yaml_path(&worker),
        attempt_log = yaml_path(attempt_log),
        job = yaml_path(&job),
        credential_env = yaml_string(CREDENTIAL_ENV),
    )
}

fn set_sidecar_token_hash() {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
}

fn yaml_path(path: &Path) -> String {
    yaml_string(path.to_str().expect("fixture path is UTF-8"))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

async fn authorized_lookup(server: &TestServer, lookup_value: &str) -> TestResponse {
    lookup_request(server, lookup_value)
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_header("x-correlation-id", "contract-correlation")
        .await
}

fn lookup_request(server: &TestServer, lookup_value: &str) -> axum_test::TestRequest {
    server
        .get(&format!("/datasets/{DATASET}/{ENTITY}"))
        .add_query_param(LOOKUP_FIELD, lookup_value)
        .add_query_param("fields", "national_id,birth_date")
        .add_query_param("limit", "2")
}

fn assert_rda_data(response: &TestResponse, expected: Value) {
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body, json!({ "data": expected }));
}

fn assert_problem_details(response: &TestResponse, status: StatusCode) -> Value {
    response.assert_status(status);
    let body: Value = response.json();
    assert!(
        body["type"].is_string(),
        "problem details must include type"
    );
    assert!(
        body["title"].is_string(),
        "problem details must include title"
    );
    assert_eq!(body["status"], json!(status.as_u16()));
    body
}

fn attempt_count(harness: &ContractHarness) -> usize {
    std::fs::read_to_string(&harness.attempt_log)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.contains("smoke-person"))
        .count()
}

#[tokio::test]
async fn exact_match_returns_single_projected_record() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "person-123").await;

    assert_rda_data(
        &response,
        json!([{
            "national_id": "person-123",
            "birth_date": "1990-01-01"
        }]),
    );
    assert_eq!(
        attempt_count(&harness),
        1,
        "exact lookup dispatches exactly one worker execution"
    );
    assert!(
        !response.text().contains("ignored_extra"),
        "sidecar trims fields outside the requested projection"
    );
}

#[tokio::test]
async fn not_found_returns_empty_rda_data_array() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "missing-person").await;

    assert_rda_data(&response, json!([]));
    assert_eq!(attempt_count(&harness), 1);
}

#[tokio::test]
async fn ambiguous_result_returns_two_records() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "ambiguous-person").await;

    assert_rda_data(
        &response,
        json!([
            {
                "national_id": "ambiguous-person",
                "birth_date": "1990-01-01"
            },
            {
                "national_id": "ambiguous-person",
                "birth_date": "1992-02-02"
            }
        ]),
    );
    assert_eq!(attempt_count(&harness), 1);
}

#[tokio::test]
async fn missing_purpose_is_rejected_before_worker_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = lookup_request(&harness.server, "person-123")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .await;

    assert_problem_details(&response, StatusCode::BAD_REQUEST);
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn missing_or_malformed_token_returns_401_with_challenge() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = lookup_request(&harness.server, "person-123")
        .add_header("data-purpose", PURPOSE)
        .await;

    assert_problem_details(&response, StatusCode::UNAUTHORIZED);
    assert!(
        response.headers().contains_key("www-authenticate"),
        "401 responses include a WWW-Authenticate challenge"
    );
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn well_formed_but_rejected_token_returns_403() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = lookup_request(&harness.server, "person-123")
        .add_header("authorization", "Bearer wrong-token")
        .add_header("data-purpose", PURPOSE)
        .await;

    assert_problem_details(&response, StatusCode::FORBIDDEN);
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn saturated_worker_pool_returns_503_with_retry_after() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 1,
        worker_timeout_ms: 1_000,
        max_output_bytes: 4096,
        ..HarnessOptions::default()
    })
    .await;

    let first = authorized_lookup(&harness.server, "slow-person");
    let second = authorized_lookup(&harness.server, "person-123");
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.status_code(), second.status_code()];

    assert!(
        statuses.contains(&StatusCode::OK),
        "one request should acquire the only worker"
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "overflow request should fail fast instead of queueing"
    );
    let saturated = if first.status_code() == StatusCode::SERVICE_UNAVAILABLE {
        first
    } else {
        second
    };
    assert_problem_details(&saturated, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        saturated.headers().contains_key("retry-after"),
        "saturation responses include Retry-After"
    );
}

#[tokio::test]
async fn invalid_worker_output_maps_to_502_problem_details() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "invalid-output").await;

    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
    assert_eq!(attempt_count(&harness), 1);
}

#[tokio::test]
async fn worker_timeout_maps_to_504_and_releases_capacity() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 1,
        worker_timeout_ms: 25,
        max_output_bytes: 4096,
        ..HarnessOptions::default()
    })
    .await;

    let timeout = authorized_lookup(&harness.server, "timeout-person").await;
    assert_problem_details(&timeout, StatusCode::GATEWAY_TIMEOUT);

    let recovery = authorized_lookup(&harness.server, "person-123").await;
    assert_rda_data(
        &recovery,
        json!([{
            "national_id": "person-123",
            "birth_date": "1990-01-01"
        }]),
    );
}

#[tokio::test]
async fn oversized_worker_output_maps_to_502_problem_details() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 2,
        worker_timeout_ms: 250,
        max_output_bytes: 64,
        ..HarnessOptions::default()
    })
    .await;

    let response = authorized_lookup(&harness.server, "oversized-output").await;

    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
    assert_eq!(attempt_count(&harness), 1);
}

#[tokio::test]
async fn concurrent_requests_within_capacity_complete_independently() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 4,
        worker_timeout_ms: 500,
        max_output_bytes: 4096,
        ..HarnessOptions::default()
    })
    .await;

    let one = authorized_lookup(&harness.server, "person-123");
    let two = authorized_lookup(&harness.server, "person-456");
    let three = authorized_lookup(&harness.server, "missing-person");
    let four = authorized_lookup(&harness.server, "ambiguous-person");
    let (one, two, three, four) = tokio::join!(one, two, three, four);

    assert_rda_data(
        &one,
        json!([{
            "national_id": "person-123",
            "birth_date": "1990-01-01"
        }]),
    );
    assert_rda_data(
        &two,
        json!([{
            "national_id": "person-456",
            "birth_date": "1985-05-05"
        }]),
    );
    assert_rda_data(&three, json!([]));
    assert_eq!(four.status_code(), StatusCode::OK);
    assert_eq!(attempt_count(&harness), 4);
}

#[tokio::test]
async fn openfn_execution_failure_is_not_retried() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "worker-failure").await;

    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
    assert_eq!(
        attempt_count(&harness),
        1,
        "OpenFn execution failures are reported without retrying the worker"
    );
}

#[tokio::test]
async fn health_ready_and_metrics_are_available_without_secret_disclosure() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let lookup = authorized_lookup(&harness.server, "person-123").await;
    lookup.assert_status_ok();

    let health = harness.server.get("/healthz").await;
    health.assert_status_ok();
    let ready = harness.server.get("/ready").await;
    ready.assert_status_ok();
    let metrics = harness.server.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();

    assert!(metrics_body.contains("registry_witness_openfn_sidecar_workers"));
    assert!(metrics_body.contains("source_id=\"openfn_crvs\",outcome=\"success\""));
    assert!(!metrics_body.contains("fixture-token"));
    assert!(!metrics_body.contains("opencrvs.example.test"));
    assert!(!metrics_body.contains(TOKEN));
}

#[tokio::test]
async fn liveness_does_not_fail_a_new_request_after_idle_time() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 1,
        worker_timeout_ms: 1_000,
        max_output_bytes: 4096,
        liveness_window_ms: 10,
    })
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let slow = authorized_lookup(&harness.server, "slow-person");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    harness.server.get("/healthz").await.assert_status_ok();
    slow.await.assert_status_ok();
}

#[tokio::test]
async fn truncated_worker_stdout_maps_to_502_problem_details() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "truncated-output").await;

    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
    assert_eq!(attempt_count(&harness), 1);
}

#[tokio::test]
async fn target_auth_and_rate_limit_have_distinct_status_codes() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let auth = authorized_lookup(&harness.server, "target-auth").await;
    let auth_body = assert_problem_details(&auth, StatusCode::BAD_GATEWAY);
    assert_eq!(auth_body["code"], json!("target_auth"));

    let rate_limit = authorized_lookup(&harness.server, "target-rate-limit").await;
    let rate_limit_body = assert_problem_details(&rate_limit, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rate_limit_body["code"], json!("target_rate_limit"));
    assert_eq!(
        rate_limit
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
}

#[tokio::test]
async fn credential_material_is_not_disclosed_on_worker_error_path() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_lookup(&harness.server, "stderr-leak").await;

    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
    let body = response.text();
    assert!(!body.contains("fixture-token"));
    assert!(!body.contains("opencrvs.example.test"));
    assert!(!body.contains(CREDENTIAL_ENV));
}

#[tokio::test]
async fn startup_rejects_missing_adaptor_pin_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace(
        "@openfn/language-http@7.2.0",
        "@openfn/language-missing@0.0.1",
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a manifest with a missing adaptor pin"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("@openfn/language-missing@0.0.1"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_missing_sidecar_token_hash_env() {
    let missing_hash_env = "OPENFN_CONTRACT_MISSING_SIDECAR_TOKEN_HASH";
    std::env::remove_var(missing_hash_env);
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    );
    let manifest = manifest.replace(TOKEN_HASH_ENV, missing_hash_env);
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a missing sidecar token hash env"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains(missing_hash_env));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_plaintext_sidecar_token_config() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace(
        &format!("      hash_env: {}\n", yaml_string(TOKEN_HASH_ENV)),
        "      token: contract-sidecar-token\n",
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject plaintext sidecar token config"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("plaintext token is not supported"));
    assert!(!error.contains("contract-sidecar-token"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_adaptor_installed_version_mismatch() {
    set_sidecar_token_hash();
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("attempts.jsonl");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let worker = fixtures.join("contract_worker.sh");
    let wrapper = tmp.path().join("version-mismatch-worker.sh");
    fs::write(
        &wrapper,
        format!(
            r#"if [ "${{1:-}}" = "--version" ] || [ "${{2:-}}" = "--version" ]; then
  printf '%s\n' 'cli_build_tool=1.36.0 runtime=1.36.0 @openfn/language-http@7.2.0:7.3.0=/fixture'
  exit 0
fi
exec /bin/sh {} "$@"
"#,
            worker.display()
        ),
    )
    .expect("write wrapper worker");
    let manifest = manifest_yaml(&HarnessOptions::default(), &attempt_log)
        .replace(&yaml_path(&worker), &yaml_path(&wrapper));
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject adaptor installed version mismatch"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("resolved to version 7.3.0, expected 7.2.0"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_credential_base_url_outside_allowlist() {
    let credential_env = "OPENFN_CONTRACT_DISALLOWED_CREDENTIAL_JSON";
    std::env::set_var(
        credential_env,
        r#"{"baseUrl":"https://unexpected.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(&HarnessOptions::default(), &tmp.path().join("attempts.jsonl"))
        .replace(
            &format!("    credential_env: {}\n", yaml_string(CREDENTIAL_ENV)),
            &format!(
                "    credential_env: {}\n    allowed_base_urls:\n      - https://opencrvs.example.test\n",
                yaml_string(credential_env)
            ),
        );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a credential baseUrl outside allowlist"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("baseUrl"));
    assert!(!error.contains("fixture-token"));
    assert!(!error.contains("unexpected.example.test"));
}

#[tokio::test]
async fn configured_smoke_lookup_runs_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let manifest = manifest_yaml(&HarnessOptions::default(), &attempt_log);
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let app = sidecar_router(config).await.expect("smoke lookup succeeds");
    let server = TestServer::builder().http_transport().build(app);

    server.get("/ready").await.assert_status_ok();
    assert_eq!(
        std::fs::read_to_string(&attempt_log)
            .unwrap_or_default()
            .lines()
            .count(),
        1,
        "startup smoke executes the configured job before readiness"
    );
}

#[tokio::test]
async fn startup_rejects_missing_smoke_lookup_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace(
        r#"    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        "",
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a manifest without smoke_lookup"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("smoke_lookup"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_smoke_lookup_that_does_not_return_expected_record() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace("value: smoke-person", "value: missing-person");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a smoke lookup that returns no matching record"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("smoke lookup"));
    assert!(error.contains("expected smoke record"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_smoke_lookup_projection_without_lookup_field() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace("        - national_id", "        - birth_date");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a smoke projection without the lookup field"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("smoke_lookup.fields"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_manifest_without_worker_memory_limit() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace("  max_worker_memory_mb: 256\n", "");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a manifest without max_worker_memory_mb"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("max_worker_memory_mb"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn invalid_query_size_and_parameter_limits_are_rejected_before_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let too_many_predicates = harness
        .server
        .get(&format!("/datasets/{DATASET}/{ENTITY}"))
        .add_query_param(LOOKUP_FIELD, "person-123")
        .add_query_param("other_id", "person-123")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .await;
    assert_problem_details(&too_many_predicates, StatusCode::BAD_REQUEST);

    let too_large_param = lookup_request(&harness.server, &"x".repeat(129))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .await;
    assert_problem_details(&too_large_param, StatusCode::BAD_REQUEST);
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn missing_fields_projection_is_rejected_before_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = harness
        .server
        .get(&format!("/datasets/{DATASET}/{ENTITY}"))
        .add_query_param(LOOKUP_FIELD, "person-123")
        .add_query_param("limit", "2")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .await;

    assert_problem_details(&response, StatusCode::BAD_REQUEST);
    assert_eq!(attempt_count(&harness), 0);
}
