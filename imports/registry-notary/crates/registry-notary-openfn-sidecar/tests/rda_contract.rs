// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use registry_notary_openfn_sidecar::{sidecar_router, SidecarConfig};
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
    max_batch_items: usize,
    batch_mode: Option<&'static str>,
    source_max_in_flight: Option<usize>,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            max_workers: 2,
            worker_timeout_ms: 250,
            max_output_bytes: 4096,
            liveness_window_ms: 30_000,
            max_batch_items: 100,
            batch_mode: None,
            source_max_in_flight: None,
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
    let batch_config = options
        .batch_mode
        .map(|mode| format!("    batch:\n      mode: {mode}\n"))
        .unwrap_or_default();
    let source_limits_config = options
        .source_max_in_flight
        .map(|limit| format!("    limits:\n      max_in_flight: {limit}\n"))
        .unwrap_or_default();

    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: {max_workers}
  worker_timeout_ms: {worker_timeout_ms}
  max_output_bytes: {max_output_bytes}
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: {liveness_window_ms}
  max_batch_items: {max_batch_items}
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
{batch_config}{source_limits_config}
    workflow:
      steps:
        - id: lookup
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
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
        max_batch_items = options.max_batch_items,
        batch_config = batch_config,
        source_limits_config = source_limits_config,
        worker = yaml_path(&worker),
        attempt_log = yaml_path(attempt_log),
        job = yaml_path(&job),
        credential_env = yaml_string(CREDENTIAL_ENV),
    )
}

#[test]
fn manifest_defaults_server_boundary_limits() {
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("worker-attempts.jsonl"),
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    assert_eq!(config.server.request_timeout_ms, 30_000);
    assert_eq!(config.server.request_body_timeout_ms, 10_000);
    assert_eq!(config.server.http1_header_read_timeout_ms, 10_000);
    assert_eq!(config.server.max_connections, 1024);
    let source = config
        .sources
        .get("openfn_crvs")
        .expect("source config parses");
    assert_eq!(
        serde_json::to_value(&source.batch).expect("batch config serializes"),
        json!({ "mode": "sequential_lookup" })
    );
    assert_eq!(source.limits.max_in_flight, None);
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

fn single_step_workflow_yaml(job: &Path) -> String {
    format!(
        r#"    workflow:
      steps:
        - id: lookup
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
"#,
        job = yaml_path(job)
    )
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
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
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

async fn authorized_batch_match(server: &TestServer) -> TestResponse {
    batch_match_request(server)
        .json(&valid_batch_match_body())
        .await
}

fn batch_match_request(server: &TestServer) -> axum_test::TestRequest {
    server
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_header("x-correlation-id", "contract-correlation")
}

fn valid_batch_match_body() -> Value {
    batch_match_body_with_values(["person-123", "missing-person", "ambiguous-person"])
}

fn batch_match_body_with_values(values: [&str; 3]) -> Value {
    json!({
        "fields": ["national_id", "birth_date"],
        "query_signature": [
            { "field": "national_id", "op": "eq" }
        ],
        "items": [
            { "id": "0", "values": [values[0]] },
            { "id": "1", "values": [values[1]] },
            { "id": "2", "values": [values[2]] }
        ]
    })
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
async fn batch_match_returns_per_item_projected_rda_data_and_sends_minimized_worker_request() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = authorized_batch_match(&harness.server).await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body,
        json!({
            "items": [
                {
                    "id": "0",
                    "data": [{
                        "national_id": "person-123",
                        "birth_date": "1990-01-01"
                    }]
                },
                {
                    "id": "1",
                    "data": []
                },
                {
                    "id": "2",
                    "data": [
                        {
                            "national_id": "ambiguous-person",
                            "birth_date": "1990-01-01"
                        },
                        {
                            "national_id": "ambiguous-person",
                            "birth_date": "1992-02-02"
                        }
                    ]
                }
            ]
        })
    );

    let attempts = fs::read_to_string(&harness.attempt_log).expect("attempt log is written");
    let batch_request = attempts
        .lines()
        .find(|line| line.contains(r#""mode":"batch_match""#))
        .expect("batch worker request is logged");
    let request: Value = serde_json::from_str(batch_request).expect("worker request is JSON");
    assert_eq!(request["mode"], json!("batch_match"));
    assert_eq!(request["batch"], json!({ "mode": "sequential_lookup" }));
    assert_eq!(
        request["query_signature"],
        json!([{ "field": "national_id", "op": "eq" }])
    );
    assert!(request.get("target").is_none());
    assert!(request.get("requester").is_none());
    assert!(request.get("relationship").is_none());
    assert!(
        !response.text().contains("ignored_extra"),
        "sidecar trims fields outside the requested projection"
    );
    assert_eq!(
        attempt_count(&harness),
        1,
        "batch dispatches exactly one non-smoke worker execution"
    );
}

#[tokio::test]
async fn batch_match_forwards_workflow_batch_mode_to_worker() {
    let harness = contract_harness(HarnessOptions {
        batch_mode: Some("workflow_batch"),
        ..HarnessOptions::default()
    })
    .await;

    let response = authorized_batch_match(&harness.server).await;

    response.assert_status_ok();
    let attempts = fs::read_to_string(&harness.attempt_log).expect("attempt log is written");
    let batch_request = attempts
        .lines()
        .find(|line| line.contains(r#""mode":"batch_match""#))
        .expect("batch worker request is logged");
    let request: Value = serde_json::from_str(batch_request).expect("worker request is JSON");
    assert_eq!(request["batch"], json!({ "mode": "workflow_batch" }));
    assert_eq!(request["items"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        attempt_count(&harness),
        1,
        "true batch mode still dispatches a single worker execution"
    );
}

#[tokio::test]
async fn batch_match_rejects_unknown_request_fields_before_worker_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let mut top_level = valid_batch_match_body();
    top_level["target"] = json!({ "must": "not be accepted" });
    let response = batch_match_request(&harness.server).json(&top_level).await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut term = valid_batch_match_body();
    term["query_signature"][0]["ignored"] = json!(true);
    let response = batch_match_request(&harness.server).json(&term).await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut item = valid_batch_match_body();
    item["items"][0]["ignored"] = json!(true);
    let response = batch_match_request(&harness.server).json(&item).await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn batch_match_enforces_raw_request_body_limit_before_worker_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;
    let body = json!({
        "fields": ["national_id"],
        "query_signature": [{ "field": "national_id", "op": "eq" }],
        "items": [{ "id": "0", "values": ["x".repeat(4096)] }]
    })
    .to_string();

    let response = batch_match_request(&harness.server)
        .content_type("application/json")
        .text(body)
        .await;

    assert_problem_details(&response, StatusCode::BAD_REQUEST);
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn batch_match_request_validation_rejects_limits_and_signature_errors_before_dispatch() {
    let harness = contract_harness(HarnessOptions {
        max_batch_items: 2,
        ..HarnessOptions::default()
    })
    .await;

    let too_many_items = valid_batch_match_body();
    let response = batch_match_request(&harness.server)
        .json(&too_many_items)
        .await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut unsupported_op = valid_batch_match_body();
    unsupported_op["query_signature"][0]["op"] = json!("contains");
    let response = batch_match_request(&harness.server)
        .json(&unsupported_op)
        .await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut value_length_mismatch = valid_batch_match_body();
    value_length_mismatch["items"][0]["values"] = json!(["person-123", "extra"]);
    let response = batch_match_request(&harness.server)
        .json(&value_length_mismatch)
        .await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut overlong_field = valid_batch_match_body();
    overlong_field["fields"][0] = json!("x".repeat(129));
    let response = batch_match_request(&harness.server)
        .json(&overlong_field)
        .await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    let mut overlong_value = valid_batch_match_body();
    overlong_value["items"][0]["values"][0] = json!("x".repeat(129));
    let response = batch_match_request(&harness.server)
        .json(&overlong_value)
        .await;
    assert_problem_details(&response, StatusCode::BAD_REQUEST);

    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn batch_match_requires_auth_and_purpose_before_worker_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let missing_token = harness
        .server
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("data-purpose", PURPOSE)
        .json(&valid_batch_match_body())
        .await;
    assert_problem_details(&missing_token, StatusCode::UNAUTHORIZED);
    assert!(
        missing_token.headers().contains_key("www-authenticate"),
        "401 responses include a WWW-Authenticate challenge"
    );

    let malformed_token = harness
        .server
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", "Basic not-bearer")
        .add_header("data-purpose", PURPOSE)
        .json(&valid_batch_match_body())
        .await;
    assert_problem_details(&malformed_token, StatusCode::UNAUTHORIZED);

    let rejected_token = harness
        .server
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", "Bearer wrong-token")
        .add_header("data-purpose", PURPOSE)
        .json(&valid_batch_match_body())
        .await;
    assert_problem_details(&rejected_token, StatusCode::FORBIDDEN);

    let missing_purpose = harness
        .server
        .post(&format!(
            "/v1/datasets/{DATASET}/entities/{ENTITY}/records:batchMatch"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .json(&valid_batch_match_body())
        .await;
    assert_problem_details(&missing_purpose, StatusCode::BAD_REQUEST);

    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn batch_match_worker_response_item_ids_are_normalized_or_rejected_per_contract() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let missing = batch_match_body_with_values([
        "batch-missing-response",
        "missing-person",
        "ambiguous-person",
    ]);
    let response = batch_match_request(&harness.server).json(&missing).await;
    let attempts = fs::read_to_string(&harness.attempt_log).expect("attempt log is written");
    assert!(
        attempts.contains("batch-missing-response"),
        "worker request must include the batch marker; attempts: {attempts}"
    );
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body["items"][1],
        json!({ "id": "1", "error": { "code": "source_unavailable" } })
    );

    let duplicate = batch_match_body_with_values([
        "batch-duplicate-response",
        "missing-person",
        "ambiguous-person",
    ]);
    let response = batch_match_request(&harness.server).json(&duplicate).await;
    assert_problem_details(&response, StatusCode::BAD_GATEWAY);

    let extra = batch_match_body_with_values([
        "batch-extra-response",
        "missing-person",
        "ambiguous-person",
    ]);
    let response = batch_match_request(&harness.server).json(&extra).await;
    assert_problem_details(&response, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn batch_match_worker_per_item_errors_are_documented_and_sanitized() {
    let harness = contract_harness(HarnessOptions::default()).await;
    let request =
        batch_match_body_with_values(["batch-item-errors", "missing-person", "ambiguous-person"]);

    let response = batch_match_request(&harness.server).json(&request).await;
    let attempts = fs::read_to_string(&harness.attempt_log).expect("attempt log is written");
    assert!(
        attempts.contains("batch-item-errors"),
        "worker request must include the batch marker; attempts: {attempts}"
    );

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body,
        json!({
            "items": [
                { "id": "0", "error": { "code": "target_auth" } },
                {
                    "id": "1",
                    "error": {
                        "code": "target_rate_limit",
                        "retry_after_seconds": 7
                    }
                },
                { "id": "2", "error": { "code": "source_unavailable" } }
            ]
        })
    );
    assert!(!response.text().contains("batch-item-errors"));
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
        source_max_in_flight: Some(2),
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
async fn source_concurrency_limit_returns_503_before_worker_dispatch() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 2,
        worker_timeout_ms: 1_000,
        max_output_bytes: 4096,
        source_max_in_flight: Some(1),
        ..HarnessOptions::default()
    })
    .await;

    let first = authorized_lookup(&harness.server, "slow-person");
    let second = authorized_lookup(&harness.server, "person-123");
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.status_code(), second.status_code()];

    assert!(
        statuses.contains(&StatusCode::OK),
        "one request should acquire the source permit"
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "overflow request should fail fast at the source limiter"
    );
    let saturated = if first.status_code() == StatusCode::SERVICE_UNAVAILABLE {
        first
    } else {
        second
    };
    let body = assert_problem_details(&saturated, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["title"], json!("source concurrency limit reached"));
    assert!(
        saturated.headers().contains_key("retry-after"),
        "source saturation responses include Retry-After"
    );
    assert_eq!(
        attempt_count(&harness),
        1,
        "source saturation is rejected before a second worker request is dispatched"
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
    let batch = authorized_batch_match(&harness.server).await;
    batch.assert_status_ok();

    let health = harness.server.get("/healthz").await;
    health.assert_status_ok();
    let ready = harness.server.get("/ready").await;
    ready.assert_status_ok();
    let metrics = harness.server.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();

    assert!(metrics_body.contains("registry_notary_openfn_sidecar_workers"));
    assert!(metrics_body.contains("registry_notary_openfn_sidecar_source_permits"));
    assert!(metrics_body.contains(
        "registry_notary_openfn_sidecar_source_permits{source_id=\"openfn_crvs\",state=\"max\"} 2"
    ));
    assert!(metrics_body.contains("source_id=\"openfn_crvs\",outcome=\"success\""));
    assert!(metrics_body.contains("source_id=\"openfn_crvs\",outcome=\"batch_success\""));
    assert!(metrics_body.contains("registry_notary_openfn_sidecar_lookup_items_total"));
    assert!(metrics_body.contains(
        "registry_notary_openfn_sidecar_lookup_items_total{source_id=\"openfn_crvs\",outcome=\"batch_success\"} 3"
    ));
    assert!(!metrics_body.contains("fixture-token"));
    assert!(!metrics_body.contains("opencrvs.example.test"));
    assert!(!metrics_body.contains("person-123"));
    assert!(!metrics_body.contains("missing-person"));
    assert!(!metrics_body.contains("ambiguous-person"));
    assert!(!metrics_body.contains("contract-correlation"));
    assert!(!metrics_body.contains(TOKEN));
}

#[tokio::test]
async fn liveness_does_not_fail_a_new_request_after_idle_time() {
    let harness = contract_harness(HarnessOptions {
        max_workers: 1,
        worker_timeout_ms: 1_000,
        max_output_bytes: 4096,
        liveness_window_ms: 10,
        ..HarnessOptions::default()
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
    assert_eq!(auth_body["code"], json!("source.target_auth"));

    let rate_limit = authorized_lookup(&harness.server, "target-rate-limit").await;
    let rate_limit_body = assert_problem_details(&rate_limit, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rate_limit_body["code"], json!("source.target_rate_limit"));
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
async fn startup_rejects_missing_adaptor_version_pin_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace("@openfn/language-http@7.2.0", "@openfn/language-http");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a manifest with an unpinned adaptor"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("must include a version pin"));
    assert!(error.contains("@openfn/language-http"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_missing_expression_file_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");
    let missing_job = tmp.path().join("missing-expression.js");
    let manifest = manifest_yaml(
        &HarnessOptions::default(),
        &tmp.path().join("attempts.jsonl"),
    )
    .replace(&yaml_path(&job), &yaml_path(&missing_job));
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a missing expression file"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("expression"));
    assert!(error.contains("is missing"));
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
        "startup smoke executes the configured workflow before readiness"
    );
}

#[tokio::test]
async fn workflow_source_config_sends_multi_step_execution_plan() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");
    let manifest = manifest_yaml(&HarnessOptions::default(), &attempt_log).replace(
        &single_step_workflow_yaml(&job),
        &format!(
            r#"    workflow:
      start: prepare_lookup
      steps:
        - id: prepare_lookup
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            return_rda: true
        - id: return_rda
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
"#,
            job = yaml_path(&job)
        ),
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let app = sidecar_router(config)
        .await
        .expect("sidecar router builds from workflow manifest");
    let server = TestServer::builder().http_transport().build(app);

    assert_rda_data(
        &authorized_lookup(&server, "person-123").await,
        json!([{ "national_id": "person-123", "birth_date": "1990-01-01" }]),
    );

    let attempts = fs::read_to_string(&attempt_log).expect("attempt log is written");
    let lookup_request = attempts
        .lines()
        .find(|line| line.contains("person-123"))
        .expect("lookup request is logged");
    let request: Value = serde_json::from_str(lookup_request).expect("request is JSON");
    assert!(request.get("job").is_none());
    assert!(request.get("adaptor").is_none());
    assert_eq!(request["workflow"]["start"], json!("prepare_lookup"));
    assert_eq!(
        request["workflow"]["steps"][0]["next"],
        json!({ "return_rda": true })
    );
    assert_eq!(
        request["workflow"]["steps"]
            .as_array()
            .expect("workflow steps array")
            .len(),
        2
    );
}

#[tokio::test]
async fn startup_rejects_workflow_cycle_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");
    let manifest = manifest_yaml(&HarnessOptions::default(), &attempt_log).replace(
        &single_step_workflow_yaml(&job),
        &format!(
            r#"    workflow:
      start: prepare_lookup
      steps:
        - id: prepare_lookup
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            return_rda: true
        - id: return_rda
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            prepare_lookup: true
"#,
            job = yaml_path(&job)
        ),
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a workflow cycle before readiness"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("workflow contains a cycle"));
    assert!(!error.contains("fixture-token"));
}

#[tokio::test]
async fn startup_rejects_workflow_merge_before_readiness() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");
    let manifest = manifest_yaml(&HarnessOptions::default(), &attempt_log).replace(
        &single_step_workflow_yaml(&job),
        &format!(
            r#"    workflow:
      start: choose_path
      steps:
        - id: choose_path
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            path_a: true
            path_b: true
        - id: path_a
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            return_rda: true
        - id: path_b
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            return_rda: true
        - id: return_rda
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
"#,
            job = yaml_path(&job)
        ),
    );
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");
    let error = match sidecar_router(config).await {
        Ok(_) => panic!("router should reject a workflow merge before readiness"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("multiple input steps"));
    assert!(error.contains("is not a join"));
    assert!(!error.contains("fixture-token"));
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
        &HarnessOptions {
            liveness_window_ms: 5,
            ..HarnessOptions::default()
        },
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
async fn startup_retries_smoke_lookup_within_liveness_window() {
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let attempt_log = tmp.path().join("attempts.jsonl");
    let manifest = manifest_yaml(
        &HarnessOptions {
            liveness_window_ms: 1_100,
            ..HarnessOptions::default()
        },
        &attempt_log,
    )
    .replace("value: smoke-person", "value: flaky-smoke");
    let config: SidecarConfig = serde_norway::from_str(&manifest).expect("manifest parses");

    let _ = sidecar_router(config)
        .await
        .expect("router should retry a transient smoke lookup response");

    let attempts = fs::read_to_string(attempt_log).expect("attempt log exists");
    assert_eq!(attempts.matches("flaky-smoke").count(), 2);
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
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
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
async fn request_uri_limit_returns_414_problem_details_before_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;
    let oversized_dataset = "x".repeat(9 * 1024);

    let response = harness
        .server
        .get(&format!(
            "/v1/datasets/{oversized_dataset}/entities/{ENTITY}/records"
        ))
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .await;

    assert_problem_details(&response, StatusCode::URI_TOO_LONG);
    assert_eq!(attempt_count(&harness), 0);
}

#[tokio::test]
async fn missing_fields_projection_is_rejected_before_dispatch() {
    let harness = contract_harness(HarnessOptions::default()).await;

    let response = harness
        .server
        .get(&format!("/v1/datasets/{DATASET}/entities/{ENTITY}/records"))
        .add_query_param(LOOKUP_FIELD, "person-123")
        .add_query_param("limit", "2")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .await;

    assert_problem_details(&response, StatusCode::BAD_REQUEST);
    assert_eq!(attempt_count(&harness), 0);
}
