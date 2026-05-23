// SPDX-License-Identifier: Apache-2.0
//! Decentralized demo config and cross-source CEL coverage.

#![cfg(feature = "registry-witness-cel")]

mod common;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::standalone_router;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

const DEMO_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

async fn civil_source(
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    source_response(
        headers,
        query,
        "civil-source-token",
        "deceased,national_id",
        json!({
            "national_id": "NID-1",
            "birth_date": "1990-01-02",
            "civil_status": "single",
            "deceased": false
        }),
    )
}

async fn social_source(
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    source_response(
        headers,
        query,
        "social-source-token",
        "enrollment_status,national_id",
        json!({
            "national_id": "NID-1",
            "enrollment_status": "active"
        }),
    )
}

fn source_response(
    headers: HeaderMap,
    query: BTreeMap<String, String>,
    token: &str,
    expected_fields: &str,
    row: Value,
) -> Response {
    let expected_auth = format!("Bearer {token}");
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(expected_auth.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        != Some("https://purpose.example.test/combined-support")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query.get("national_id").map(String::as_str) != Some("NID-1") {
        return Json(json!({ "data": [] })).into_response();
    }
    if query.get("fields").map(String::as_str) != Some(expected_fields) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({ "data": [row] })).into_response()
}

fn shared_config(civil_base_url: &str, social_base_url: &str) -> StandaloneRegistryWitnessConfig {
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: shared_caseworker
      token_env: TEST_SHARED_EVIDENCE_CLIENT_TOKEN
      scopes:
        - civil_registry:evidence_verification
        - social_protection_registry:evidence_verification
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: shared-eligibility-registry-witness
  source_connections:
    civil:
      base_url: "{civil_base_url}"
      token_env: TEST_SHARED_CIVIL_EVIDENCE_SOURCE_RAW
    social_protection:
      base_url: "{social_base_url}"
      token_env: TEST_SHARED_SOCIAL_EVIDENCE_SOURCE_RAW
  claims:
    - id: civil-record-present
      title: Civil record present
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        civil:
          connector: registry_data_api
          connection: civil
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: subject_id
            field: national_id
          fields:
            deceased:
              field: deceased
              type: boolean
              required: true
      rule:
        type: cel
        expression: "source.civil.deceased == false"
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-witness.claim-result+json
    - id: social-program-active
      title: Social program active
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        enrollment:
          connector: registry_data_api
          connection: social_protection
          required_scope: social_protection_registry:evidence_verification
          dataset: social_protection_registry
          entity: program_enrollment
          lookup:
            input: subject_id
            field: national_id
          fields:
            enrollment_status:
              field: enrollment_status
              type: string
              required: true
      rule:
        type: cel
        expression: "source.enrollment.enrollment_status == 'active'"
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-witness.claim-result+json
    - id: eligible-for-combined-support
      title: Eligible for combined support
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      depends_on:
        - civil-record-present
        - social-program-active
      rule:
        type: cel
        expression: "claims.civil_record_present.satisfied && claims.social_program_active.satisfied"
        bindings:
          claims:
            civil_record_present:
              claim: civil-record-present
            social_program_active:
              claim: social-program-active
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-witness.claim-result+json
"#
    );
    serde_yml::from_str(&raw).expect("shared config deserializes")
}

#[tokio::test]
async fn cross_source_cel_claim_reads_dependencies_with_distinct_tokens() {
    unsafe {
        std::env::set_var("TEST_SHARED_EVIDENCE_CLIENT_TOKEN", "shared-client-token");
        std::env::set_var(
            "TEST_SHARED_CIVIL_EVIDENCE_SOURCE_RAW",
            "civil-source-token",
        );
        std::env::set_var(
            "TEST_SHARED_SOCIAL_EVIDENCE_SOURCE_RAW",
            "social-source-token",
        );
    }

    let civil = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/civil_registry/civil_person", get(civil_source)));
    let social = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/datasets/social_protection_registry/program_enrollment",
            get(social_source),
        ));
    let config = shared_config(
        civil
            .server_address()
            .expect("civil source exposes address")
            .to_string()
            .trim_end_matches('/'),
        social
            .server_address()
            .expect("social source exposes address")
            .to_string()
            .trim_end_matches('/'),
    );
    config.validate().expect("shared config validates");
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "shared-client-token")
        .add_header(
            "data-purpose",
            "https://purpose.example.test/combined-support",
        )
        .json(&json!({
            "subject": { "id": "NID-1" },
            "claims": ["eligible-for-combined-support"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(body["results"][0]["provenance"]["source_count"], json!(2));
}

#[test]
fn decentralized_demo_evidence_configs_load_validate_and_build_router() {
    // Hold the shared lock for the duration of this test to prevent a race
    // with demo_config, which sets the same REGISTRY_WITNESS_ISSUER_JWK env var.
    let _guard = common::issuer_jwk_guard();

    set_demo_env();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("apps directory");
    for config_path in [
        "registry_relay/demo/decentralized/config/evidence/civil-evidence-server.yaml",
        "registry_relay/demo/decentralized/config/evidence/social-protection-evidence-server.yaml",
        "registry_relay/demo/decentralized/config/evidence/shared-eligibility-evidence-server.yaml",
    ] {
        let raw = std::fs::read_to_string(root.join(config_path)).expect("config is readable");
        let config: StandaloneRegistryWitnessConfig =
            serde_yml::from_str(&raw).expect("config deserializes");
        config.validate().expect("config validates");
        let _ = standalone_router(config).expect("config builds standalone router");
    }
}

fn set_demo_env() {
    unsafe {
        for key in [
            "CIVIL_EVIDENCE_CLIENT_TOKEN",
            "CIVIL_EVIDENCE_CLIENT_BEARER",
            "CIVIL_EVIDENCE_SOURCE_RAW",
            "SOCIAL_EVIDENCE_CLIENT_TOKEN",
            "SOCIAL_EVIDENCE_CLIENT_BEARER",
            "SOCIAL_EVIDENCE_SOURCE_RAW",
            "SHARED_EVIDENCE_CLIENT_TOKEN",
            "SHARED_EVIDENCE_CLIENT_BEARER",
            "SHARED_CIVIL_EVIDENCE_SOURCE_RAW",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_RAW",
            "SHARED_HEALTH_EVIDENCE_SOURCE_RAW",
        ] {
            std::env::set_var(key, "demo-token");
        }
        std::env::set_var("REGISTRY_WITNESS_ISSUER_JWK", DEMO_ISSUER_JWK);
        // The external registry_relay demo configs (loaded by
        // decentralized_demo_evidence_configs_load_validate_and_build_router)
        // still reference EVIDENCE_SERVER_ISSUER_JWK. Set it here until
        // Phase 4 updates those files to the new name.
        std::env::set_var("EVIDENCE_SERVER_ISSUER_JWK", DEMO_ISSUER_JWK);
    }
}
