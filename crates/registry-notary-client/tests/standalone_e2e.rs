// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_client::RegistryNotaryClient;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::{json, Value};
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const PURPOSE: &str = "https://purpose.example.test/eligibility";

#[tokio::test]
async fn client_evaluates_against_real_standalone_server() {
    set_env();

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let upstream_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        upstream_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let server_url = server
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string();

    let client = RegistryNotaryClient::builder(server_url)
        .api_key("api-token")
        .default_purpose(PURPOSE)
        .build()
        .expect("client builds for loopback test server");

    let health = client.health().await.expect("health succeeds");
    assert_eq!(health.body.status, "ok");

    let claims = client
        .list_claims(Default::default())
        .await
        .expect("claims list succeeds");
    assert_eq!(claims.body.data[0]["id"], json!("farmed-land-size"));

    let evaluation = client
        .evaluate("person-1")
        .claim("farmed-land-size")
        .disclosure("value")
        .send()
        .await
        .expect("evaluation succeeds");
    let result = evaluation.body.first_result().expect("one result");
    assert_eq!(result.claim_id, "farmed-land-size");
    assert_eq!(result.value, Some(json!(3.5)));
    assert_eq!(result.provenance.used.source_count, 1);

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(audit.contains("\"decision\":\"evaluate\""));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("source-token"));
    assert!(!audit.contains("person-1"));
    assert!(!audit_contains_json_number(&audit, 3.5));
    assert!(!audit.contains("total_farmed_area"));
}

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
        != Some(PURPOSE)
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

fn set_env() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
}

fn registry_data_api_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    let raw = format!(
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      fingerprint:
        provider: env
        name: TEST_EVIDENCE_API_KEY_HASH
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
  allowed_purposes:
    - {PURPOSE}
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
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
            input: target.id
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

fn audit_contains_json_number(audit: &str, expected: f64) -> bool {
    audit
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .any(|value| json_contains_number(&value, expected))
}

fn json_contains_number(value: &Value, expected: f64) -> bool {
    match value {
        Value::Number(number) => number
            .as_f64()
            .is_some_and(|actual| (actual - expected).abs() < f64::EPSILON),
        Value::Array(items) => items
            .iter()
            .any(|item| json_contains_number(item, expected)),
        Value::Object(fields) => fields
            .values()
            .any(|field| json_contains_number(field, expected)),
        Value::Null | Value::Bool(_) | Value::String(_) => false,
    }
}
