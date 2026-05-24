// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for the per-connection outbound semaphore and the
//! single-retry policy in `standalone::send_request_with_retry`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::standalone_router;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn set_audit_secret() {
    std::env::set_var("REGISTRY_WITNESS_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
}

#[derive(Clone, Default)]
struct UpstreamMetrics {
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
    total_requests: Arc<AtomicUsize>,
    fail_first_n: Arc<AtomicUsize>,
}

impl UpstreamMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn peak(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }

    fn total(&self) -> usize {
        self.total_requests.load(Ordering::SeqCst)
    }
}

async fn slow_registry_data_api(
    State(metrics): State<UpstreamMetrics>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    metrics.total_requests.fetch_add(1, Ordering::SeqCst);
    let current = metrics.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    metrics.peak_in_flight.fetch_max(current, Ordering::SeqCst);
    // 80ms is comfortably longer than tokio scheduler jitter so concurrent
    // requests overlap if the client allows it.
    tokio::time::sleep(Duration::from_millis(80)).await;
    metrics.in_flight.fetch_sub(1, Ordering::SeqCst);
    let id = query.get("id").cloned().unwrap_or_default();
    Json(json!({
        "data": [{
            "id": id,
            "total_farmed_area": 1.0,
        }]
    }))
    .into_response()
}

async fn flaky_registry_data_api(
    State(metrics): State<UpstreamMetrics>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let attempt = metrics.total_requests.fetch_add(1, Ordering::SeqCst) + 1;
    let fail_first = metrics.fail_first_n.load(Ordering::SeqCst);
    if attempt <= fail_first {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let id = query.get("id").cloned().unwrap_or_default();
    Json(json!({
        "data": [{
            "id": id,
            "total_farmed_area": 2.5,
        }]
    }))
    .into_response()
}

fn config_with_max_in_flight(
    base_url: &str,
    audit_path: &str,
    max_in_flight: usize,
) -> StandaloneRegistryWitnessConfig {
    set_audit_secret();
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      hash_env: TEST_EVIDENCE_API_KEY_HASH
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_WITNESS_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
      max_in_flight: {max_in_flight}
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 64
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: subject_id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: extract
        source: farmer
        field: total_farmed_area
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-witness.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("config deserializes")
}

#[tokio::test]
async fn outbound_semaphore_caps_upstream_in_flight_at_max() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let metrics = UpstreamMetrics::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/datasets/farmer_registry/farmer",
                get(slow_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    // `max_in_flight = 2` even though the client side allows up to 16
    // bindings and 32 subjects; only the per-connection semaphore should
    // restrict upstream parallelism.
    let app = standalone_router(config_with_max_in_flight(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        2,
    ))
    .expect("standalone router builds");
    let server = Arc::new(TestServer::builder().http_transport().build(app));

    // Fire 8 batch_evaluate requests concurrently, each with 4 subjects, to
    // give the runtime plenty of headroom to overlap.
    let subjects: Vec<Value> = (0..4)
        .map(|i| json!({ "id": format!("person-{i}") }))
        .collect();
    let body = json!({
        "claims": ["farmed-land-size"],
        "subjects": subjects,
        "disclosure": "value",
    });

    let mut handles = Vec::new();
    for _ in 0..8 {
        let server = Arc::clone(&server);
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            server
                .post("/claims/batch-evaluate")
                .add_header("x-api-key", "api-token")
                .add_header("data-purpose", "https://purpose.example.test/eligibility")
                .json(&body)
                .await
        }));
    }
    for handle in handles {
        let response = handle.await.expect("task joined");
        response.assert_status_ok();
    }

    // The upstream's observed peak must respect the per-connection cap. With
    // 32 inflight requests across the client and `max_in_flight=2`, we expect
    // peak == 2 (allowing a tiny race where a permit is held but the upstream
    // request hasn't quite been counted, hence <= 2).
    let peak = metrics.peak();
    assert!(
        peak <= 2,
        "upstream peak in_flight {peak} exceeds max_in_flight=2",
    );
    // Sanity: we did make at least one upstream request per subject (32 total).
    assert!(
        metrics.total() >= 32,
        "expected >=32 upstream calls, got {}",
        metrics.total(),
    );
}

#[tokio::test]
async fn outbound_retries_once_on_http_500_and_returns_success() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let metrics = UpstreamMetrics::new();
    // Fail the very first request with 500, then succeed.
    metrics.fail_first_n.store(1, Ordering::SeqCst);

    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/datasets/farmer_registry/farmer",
                get(flaky_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_max_in_flight(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        8,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(2.5));
    // Exactly two upstream attempts: one 500, one 200.
    assert_eq!(metrics.total(), 2, "expected exactly one retry");
}

#[tokio::test]
async fn outbound_gives_up_after_one_retry_when_upstream_keeps_failing() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let metrics = UpstreamMetrics::new();
    // Fail effectively forever so both attempts return 500.
    metrics.fail_first_n.store(usize::MAX, Ordering::SeqCst);

    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/datasets/farmer_registry/farmer",
                get(flaky_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_max_in_flight(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        8,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;
    // The runtime maps source unavailability to a 5xx-style error response;
    // we only need to assert it is non-success and the request used the
    // single-retry budget (i.e. exactly 2 upstream calls).
    assert!(
        !response.status_code().is_success(),
        "expected non-success when upstream keeps failing, got {}",
        response.status_code(),
    );
    assert_eq!(
        metrics.total(),
        2,
        "expected exactly two upstream calls (initial + one retry)",
    );
}
