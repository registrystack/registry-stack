// SPDX-License-Identifier: Apache-2.0
//! Decentralized demo config and cross-source CEL coverage.

#![cfg(feature = "registry-notary-cel")]

mod common;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DEMO_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_SHARED_EVIDENCE_CLIENT_TOKEN_HASH: &str =
    "sha256:3adbe152ab16e34838a5ce68872b2f315e5efbcb91a1f795af0632fd9e0d5ada";

fn cel_worker_bin() -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-cel-worker"));
    if env_path
        .parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|file_name| file_name == "deps")
    {
        let candidate = env_path
            .parent()
            .and_then(|parent| parent.parent())
            .expect("target debug dir")
            .join("registry-notary-cel-worker");
        if candidate.is_file() {
            return candidate;
        }
    }
    env_path
}

fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    std::env::set_var("REGISTRY_NOTARY_CEL_WORKER_COMMAND", cel_worker_bin());
}

fn test_api_key_fingerprint_ref_yaml(_id: &str, env_name: &str, _fingerprint: &str) -> String {
    format!("fingerprint:\n        provider: env\n        name: {env_name}")
}

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

fn shared_config(civil_base_url: &str, social_base_url: &str) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "shared_caseworker",
        "TEST_SHARED_EVIDENCE_CLIENT_TOKEN_HASH",
        TEST_SHARED_EVIDENCE_CLIENT_TOKEN_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: shared_caseworker
      {api_key_fingerprint}
      scopes:
        - civil_registry:evidence_verification
        - social_protection_registry:evidence_verification
audit:
  sink: stdout
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
cel:
  worker_count: 4
  eval_timeout_ms: 10000
evidence:
  enabled: true
  service_id: shared-eligibility-registry-notary
  allowed_purposes:
    - https://purpose.example.test/combined-support
  source_connections:
    civil:
      base_url: "{civil_base_url}"
      allow_insecure_localhost: true
      token_env: TEST_SHARED_CIVIL_EVIDENCE_SOURCE_RAW
    social_protection:
      base_url: "{social_base_url}"
      allow_insecure_localhost: true
      token_env: TEST_SHARED_SOCIAL_EVIDENCE_SOURCE_RAW
  claims:
    - id: civil-record-present
      title: Civil record present
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
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
            input: target.identifiers.national_id
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
        - application/vnd.registry-notary.claim-result+json
    - id: social-program-active
      title: Social program active
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
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
            input: target.identifiers.national_id
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
        - application/vnd.registry-notary.claim-result+json
    - id: eligible-for-combined-support
      title: Eligible for combined support
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
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
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("shared config deserializes")
}

#[tokio::test]
async fn cross_source_cel_claim_reads_dependencies_with_distinct_tokens() {
    unsafe {
        std::env::set_var(
            "TEST_SHARED_EVIDENCE_CLIENT_TOKEN_HASH",
            TEST_SHARED_EVIDENCE_CLIENT_TOKEN_HASH,
        );
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
        .build(Router::new().route(
            "/v1/datasets/civil_registry/entities/civil_person/records",
            get(civil_source),
        ));
    let social = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/social_protection_registry/entities/program_enrollment/records",
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
        .post("/v1/evaluations")
        .add_header("x-api-key", "shared-client-token")
        .add_header(
            "data-purpose",
            "https://purpose.example.test/combined-support",
        )
        .json(&json!({
            "target": {
                "type": "Person",
                "identifiers": [{ "scheme": "national_id", "value": "NID-1" }]
            },
            "claims": ["eligible-for-combined-support"],
            "disclosure": "predicate"
        }))
        .await;

    let status = response.status_code();
    let response_text = response.text();
    assert_eq!(status, StatusCode::OK, "{response_text}");
    let body: Value = serde_json::from_str(&response_text).expect("response is JSON");
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(2)
    );
}

#[test]
fn decentralized_demo_evidence_configs_load_validate_and_build_router() {
    // Hold the shared lock for the duration of this test to prevent a race
    // with demo_config, which sets the same REGISTRY_NOTARY_ISSUER_JWK env var.
    let _guard = common::issuer_jwk_guard();

    set_demo_env();
    let Some(root) = registry_relay_source_dir() else {
        eprintln!(
            "skipping registry-relay decentralized demo config check; set REGISTRY_RELAY_SOURCE_DIR or check out registry-relay as a sibling"
        );
        return;
    };
    for config_paths in [
        [
            "demo/decentralized/config/evidence/civil-registry-notary.yaml",
            "demo/decentralized/config/evidence/civil-evidence-server.yaml",
        ],
        [
            "demo/decentralized/config/evidence/social-protection-registry-notary.yaml",
            "demo/decentralized/config/evidence/social-protection-evidence-server.yaml",
        ],
        [
            "demo/decentralized/config/evidence/shared-eligibility-registry-notary.yaml",
            "demo/decentralized/config/evidence/shared-eligibility-evidence-server.yaml",
        ],
    ] {
        let config_path = config_paths
            .iter()
            .map(|config_path| root.join(config_path))
            .find(|config_path| config_path.is_file())
            .expect("config is readable");
        let raw = std::fs::read_to_string(&config_path).expect("config is readable");
        let auth_block = raw
            .split_once("\naudit:")
            .map(|(before_audit, _)| before_audit)
            .unwrap_or(&raw);
        if auth_block.contains("token_env:") {
            eprintln!(
                "skipping stale registry-relay decentralized demo config with pre-hash auth schema: {}",
                config_path.display()
            );
            continue;
        }
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&raw).expect("config deserializes");
        config.validate().expect("config validates");
        let _ = standalone_router(config).expect("config builds standalone router");
    }
}

fn registry_relay_source_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("REGISTRY_RELAY_SOURCE_DIR") {
        let path = PathBuf::from(path);
        if path.join("demo/decentralized/config/evidence").is_dir() {
            return Some(path);
        }
    }

    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|apps| apps.join("registry-relay"))?;

    sibling
        .join("demo/decentralized/config/evidence")
        .is_dir()
        .then_some(sibling)
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
            std::env::set_var(
                format!("{key}_HASH"),
                "sha256:7c43ef5ae21d43ce2743f770c68e24def1a43ee2f416d2438410c8af7af2ff2c",
            );
        }
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
    }
}
