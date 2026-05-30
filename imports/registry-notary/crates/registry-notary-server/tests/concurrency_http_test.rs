// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for the per-connection outbound semaphore and the
//! single-retry policy in `standalone::send_request_with_retry`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
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

#[derive(Clone, Default)]
struct OauthUpstreamMetrics {
    token_requests: Arc<AtomicUsize>,
    token_in_flight: Arc<AtomicUsize>,
    peak_token_in_flight: Arc<AtomicUsize>,
    source_requests: Arc<AtomicUsize>,
    token_expires_in: Arc<AtomicUsize>,
    reject_first_source_token: bool,
}

impl OauthUpstreamMetrics {
    fn token_requests(&self) -> usize {
        self.token_requests.load(Ordering::SeqCst)
    }

    fn source_requests(&self) -> usize {
        self.source_requests.load(Ordering::SeqCst)
    }

    fn peak_token_in_flight(&self) -> usize {
        self.peak_token_in_flight.load(Ordering::SeqCst)
    }
}

async fn oauth_token_form(
    State(metrics): State<OauthUpstreamMetrics>,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    oauth_token_response(metrics, |metrics| validate_oauth_params(&form, metrics)).await
}

async fn oauth_token_json(
    State(metrics): State<OauthUpstreamMetrics>,
    Json(body): Json<Value>,
) -> Response {
    let params = body
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect::<BTreeMap<String, String>>()
        })
        .unwrap_or_default();
    oauth_token_response(metrics, |metrics| validate_oauth_params(&params, metrics)).await
}

async fn oauth_token_response(
    metrics: OauthUpstreamMetrics,
    validate: impl FnOnce(&OauthUpstreamMetrics) -> bool,
) -> Response {
    let current = metrics.token_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    metrics
        .peak_token_in_flight
        .fetch_max(current, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(25)).await;
    metrics.token_in_flight.fetch_sub(1, Ordering::SeqCst);
    if !validate(&metrics) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let token_number = metrics.token_requests.fetch_add(1, Ordering::SeqCst) + 1;
    let configured_expires = metrics.token_expires_in.load(Ordering::SeqCst);
    let expires_in = if configured_expires == 0 {
        3600
    } else {
        configured_expires
    };
    Json(json!({
        "access_token": format!("oauth-token-{token_number}"),
        "expires_in": expires_in,
    }))
    .into_response()
}

fn validate_oauth_params(form: &BTreeMap<String, String>, _metrics: &OauthUpstreamMetrics) -> bool {
    if form.get("grant_type").map(String::as_str) != Some("client_credentials")
        || form.get("client_id").map(String::as_str) != Some("oauth-client")
        || form.get("client_secret").map(String::as_str) != Some("oauth-secret")
        || form.get("scope").map(String::as_str) != Some("registry.read")
    {
        return false;
    }
    true
}

async fn oauth_registry_data_api(
    State(metrics): State<OauthUpstreamMetrics>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let request_number = metrics.source_requests.fetch_add(1, Ordering::SeqCst) + 1;
    let auth = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if metrics.reject_first_source_token && request_number == 1 && auth == "Bearer oauth-token-1" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !metrics.reject_first_source_token && !auth.starts_with("Bearer oauth-token-") {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if metrics.reject_first_source_token && auth != "Bearer oauth-token-2" {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let id = query.get("id").cloned().unwrap_or_default();
    Json(json!({
        "data": [{
            "id": id,
            "total_farmed_area": 3.25,
        }]
    }))
    .into_response()
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
) -> StandaloneRegistryNotaryConfig {
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
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
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
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("config deserializes")
}

fn config_with_oauth_source(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    config_with_oauth_source_options(
        base_url,
        audit_path,
        "form",
        &format!("{base_url}/oauth/token"),
    )
}

fn config_with_oauth_source_options(
    base_url: &str,
    audit_path: &str,
    request_format: &str,
    token_url: &str,
) -> StandaloneRegistryNotaryConfig {
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
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      source_auth:
        type: oauth2_client_credentials
        token_url: "{token_url}"
        client_id_env: TEST_OAUTH_CLIENT_ID
        client_secret_env: TEST_OAUTH_CLIENT_SECRET
        request_format: {request_format}
        scope: registry.read
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
        - application/vnd.registry-notary.claim-result+json
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
                "/v1/datasets/farmer_registry/entities/farmer/records",
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
                .post("/v1/batch-evaluations")
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
async fn oauth_source_auth_fetches_form_token_once_and_reads_source() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/oauth/token", post(oauth_token_form))
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for id in ["person-1", "person-2"] {
        let response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "subject": { "id": id },
                "claims": ["farmed-land-size"],
                "disclosure": "value",
            }))
            .await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["results"][0]["value"], json!(3.25));
    }

    assert_eq!(
        metrics.token_requests(),
        1,
        "OAuth token should be cached across source reads",
    );
    assert_eq!(metrics.source_requests(), 2);
}

#[tokio::test]
async fn oauth_source_auth_supports_json_token_requests() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/oauth/token", post(oauth_token_json))
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source_options(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        "json",
        &format!("{}/oauth/token", base_url.trim_end_matches('/')),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();
    assert_eq!(metrics.token_requests(), 1);
    assert_eq!(metrics.source_requests(), 1);
}

#[tokio::test]
async fn oauth_source_auth_refreshes_before_expiry_when_token_ttl_is_short() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics::default();
    metrics.token_expires_in.store(1, Ordering::SeqCst);
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/oauth/token", post(oauth_token_form))
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for id in ["person-1", "person-2"] {
        let response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "subject": { "id": id },
                "claims": ["farmed-land-size"],
                "disclosure": "value",
            }))
            .await;
        response.assert_status_ok();
    }

    assert_eq!(
        metrics.token_requests(),
        2,
        "short token TTL should refresh before the second source read",
    );
}

#[tokio::test]
async fn oauth_source_auth_coalesces_concurrent_initial_token_fetch() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/oauth/token", post(oauth_token_form))
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects: Vec<Value> = (0..8)
        .map(|i| json!({ "id": format!("person-{i}") }))
        .collect();
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subjects": subjects,
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();

    assert_eq!(
        metrics.token_requests(),
        1,
        "concurrent first use should share one token endpoint call",
    );
    assert_eq!(metrics.peak_token_in_flight(), 1);
    assert_eq!(metrics.source_requests(), 8);
}

#[tokio::test]
async fn oauth_source_auth_applies_fetch_url_policy_to_token_url() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source_options(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        "form",
        "http://169.254.169.254/latest/meta-data/token",
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;

    assert!(
        !response.status_code().is_success(),
        "blocked token URL should make the source unavailable",
    );
    assert_eq!(
        metrics.source_requests(),
        0,
        "source should not be called when token URL is rejected",
    );
}

#[tokio::test]
async fn oauth_source_auth_refreshes_once_after_unauthorized_source_response() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_OAUTH_CLIENT_ID", "oauth-client");
    std::env::set_var("TEST_OAUTH_CLIENT_SECRET", "oauth-secret");

    let metrics = OauthUpstreamMetrics {
        reject_first_source_token: true,
        ..OauthUpstreamMetrics::default()
    };
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/oauth/token", post(oauth_token_form))
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(oauth_registry_data_api),
            )
            .with_state(metrics.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(config_with_oauth_source(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
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
    assert_eq!(body["results"][0]["value"], json!(3.25));

    assert_eq!(
        metrics.token_requests(),
        2,
        "401 from the source should force one token refresh",
    );
    assert_eq!(
        metrics.source_requests(),
        2,
        "source should be called once with the stale token and once after refresh",
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
                "/v1/datasets/farmer_registry/entities/farmer/records",
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
        .post("/v1/evaluations")
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
                "/v1/datasets/farmer_registry/entities/farmer/records",
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
        .post("/v1/evaluations")
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
