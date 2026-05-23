// SPDX-License-Identifier: Apache-2.0
//! Standalone Evidence Server tests that do not link Registry Relay.

use axum::extract::Query;
#[cfg(feature = "evidence-server-cel")]
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
#[cfg(feature = "evidence-server-cel")]
use axum::routing::post;
use axum::{Json, Router};
use axum_test::TestServer;
use evidence_core::StandaloneEvidenceServerConfig;
use evidence_server::{standalone_router, StandaloneServerError};
use serde_json::{json, Value};
use std::collections::BTreeMap;
#[cfg(feature = "evidence-server-cel")]
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

async fn registry_data_api(
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer source-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        != Some("https://purpose.example.test/eligibility")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query.get("id").map(String::as_str) != Some("person-1") {
        return Json(json!({ "data": [] })).into_response();
    }
    Json(json!({
        "data": [{
            "id": "person-1",
            "total_farmed_area": 3.5
        }]
    }))
    .into_response()
}

#[cfg(feature = "evidence-server-cel")]
async fn dci_source(
    State(observed): State<Arc<Mutex<Option<Value>>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer source-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        != Some("https://purpose.example.test/eligibility")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    *observed.lock().expect("observed request lock") = Some(body.clone());
    if body["message"]["search_request"][0]["search_criteria"]["query"]["value"] != "person-1" {
        return Json(json!({
            "message": {
                "search_response": [{
                    "data": { "reg_records": [] }
                }]
            }
        }))
        .into_response();
    }
    Json(json!({
        "message": {
            "search_response": [{
                "data": {
                    "reg_records": [{
                        "farmed_land_size_hectares": 3.5
                    }]
                }
            }]
        }
    }))
    .into_response()
}

fn config(
    base_url: &str,
    audit_path: &str,
    connector: &str,
    source_path: &str,
) -> StandaloneEvidenceServerConfig {
    let source_connection = if connector == "dci" {
        r#"
      dci:
        search_path: /dci/fr/registry/sync/search
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          farmed_land_size_hectares: /farmed_land_size_hectares"#
    } else {
        ""
    };
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: caseworker
      token_env: TEST_EVIDENCE_API_KEY
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
{source_connection}
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
      source_bindings:
        farmer:
          connector: {connector}
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
              field: {source_path}
              type: number
              unit: hectare
              required: true
      rule:
        type: extract
        source: farmer
        field: {source_path}
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-under-4ha
      title: Farmer under four hectares
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      depends_on:
        - farmed-land-size
      rule:
        type: cel
        expression: "claims.farmed_land_size.value < 4.0"
        bindings:
          claims:
            farmed_land_size:
              claim: farmed-land-size
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.evidence-server.claim-result+json
"#
    );
    serde_yml::from_str(&raw).expect("config deserializes")
}

fn registry_data_api_config(base_url: &str, audit_path: &str) -> StandaloneEvidenceServerConfig {
    config(
        base_url,
        audit_path,
        "registry_data_api",
        "total_farmed_area",
    )
}

#[cfg(feature = "evidence-server-cel")]
fn dci_config(base_url: &str, audit_path: &str) -> StandaloneEvidenceServerConfig {
    config(base_url, audit_path, "dci", "farmed_land_size_hectares")
}

fn no_cel_config(base_url: &str, audit_path: &str) -> StandaloneEvidenceServerConfig {
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: caseworker
      token_env: TEST_EVIDENCE_API_KEY
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
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
        - application/vnd.evidence-server.claim-result+json
"#
    );
    serde_yml::from_str(&raw).expect("config deserializes")
}

#[tokio::test]
async fn standalone_server_authenticates_evaluates_over_http_and_writes_redacted_audit() {
    std::env::set_var("TEST_EVIDENCE_API_KEY", "api-token");
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let denied = server.get("/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let openapi = server
        .get("/openapi.json")
        .add_header("x-api-key", "api-token")
        .await;
    openapi.assert_status_ok();
    let openapi_body: Value = openapi.json();
    assert_eq!(openapi_body["openapi"], json!("3.1.0"));
    assert!(openapi_body["paths"]["/claims/evaluate"].is_object());

    let discovery = server
        .get("/.well-known/evidence-service")
        .add_header("x-api-key", "api-token")
        .await;
    discovery.assert_status_ok();
    let discovery_body: Value = discovery.json();
    assert_eq!(
        discovery_body["base_url"],
        json!("https://evidence.example.test")
    );

    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    assert_eq!(body["results"][0]["provenance"]["source_count"], json!(1));

    #[cfg(feature = "evidence-server-cel")]
    {
        let cel_response = server
            .post("/claims/evaluate")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "subject": { "id": "person-1" },
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate"
            }))
            .await;
        cel_response.assert_status_ok();
        let cel_body: Value = cel_response.json();
        assert_eq!(cel_body["results"][0]["value"], json!(true));
        assert_eq!(
            cel_body["results"][0]["provenance"]["source_count"],
            json!(1)
        );
    }

    let audit = std::fs::read_to_string(audit_path).expect("audit was written");
    assert!(audit.contains("\"principal_id\":\"caseworker\""));
    assert!(audit.contains("\"decision\":\"evaluate\""));
    assert!(audit.contains("\"claim_hash\":\"sha256:"));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("source-token"));
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("3.5"));
}

#[tokio::test]
#[cfg(feature = "evidence-server-cel")]
async fn standalone_server_reads_dci_source_and_evaluates_cel_claim() {
    std::env::set_var("TEST_EVIDENCE_API_KEY", "api-token");
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let observed = Arc::new(Mutex::new(None));
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/dci/fr/registry/sync/search", post(dci_source))
            .with_state(Arc::clone(&observed)),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(body["results"][0]["provenance"]["source_count"], json!(1));

    let observed = observed
        .lock()
        .expect("observed request lock")
        .clone()
        .expect("DCI request captured");
    assert_eq!(observed["header"]["action"], "search");
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query_type"],
        "idtype-value"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query"]["type"],
        "id"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query"]["value"],
        "person-1"
    );
}

#[tokio::test]
async fn standalone_server_extract_claim_works_without_default_features() {
    std::env::set_var("TEST_EVIDENCE_API_KEY", "api-token");
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(no_cel_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
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
            "disclosure": "value"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
}

#[test]
fn standalone_router_rejects_unknown_audit_sink() {
    std::env::set_var("TEST_EVIDENCE_API_KEY", "api-token");
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.sink = "syslog".to_string();

    let error = standalone_router(config).expect_err("unknown audit sink is rejected");
    assert!(matches!(
        error,
        StandaloneServerError::InvalidAuditSink(sink) if sink == "syslog"
    ));
}
