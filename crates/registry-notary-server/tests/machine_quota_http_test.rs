// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for the per-principal machine evaluation quota
//! (`evidence.machine_quota`): a fixed-window, subjects-counted budget for
//! non-self-attestation `evaluate`/`batch_evaluate` traffic. A single
//! `/v1/evaluations` call consumes 1 subject; a `/v1/batch-evaluations` call
//! consumes `items.len()`.

use axum::extract::Query;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use registry_platform_testing::MockIdp;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tempfile::TempDir;
use time::OffsetDateTime;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_EVIDENCE_API_KEY_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";
const TEST_EVIDENCE_API_KEY_HASH_2: &str =
    "sha256:b767149b99a04301759a833b9602d685fbd33c7336cc4420fdb9aab9b1591d8a";

fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
}

fn set_api_key_envs() {
    std::env::set_var("TEST_EVIDENCE_API_KEY_HASH", TEST_EVIDENCE_API_KEY_HASH);
    std::env::set_var("TEST_EVIDENCE_API_KEY_HASH_2", TEST_EVIDENCE_API_KEY_HASH_2);
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
}

fn api_key_fingerprint_ref_yaml(env_name: &str) -> String {
    format!("fingerprint:\n        provider: env\n        name: {env_name}")
}

fn person_target(id: &str) -> Value {
    json!({
        "type": "Person",
        "id": id,
    })
}

async fn registry_data_api(Query(query): Query<BTreeMap<String, String>>) -> Response {
    let id = query.get("id").cloned().unwrap_or_default();
    Json(json!({
        "data": [{
            "id": id,
            "total_farmed_area": 1.0,
        }]
    }))
    .into_response()
}

/// Builds a standalone config with two API-key machine credentials
/// (`machine-a` / api-token, `machine-b` / api-token-2) and one claim that
/// supports both single-evaluate and batch-evaluate. `machine_quota_yaml`,
/// when non-empty, must be valid YAML indented two spaces under `evidence:`
/// (e.g. `"  machine_quota:\n    enabled: true\n    subjects_per_minute: 10\n"`);
/// pass `""` to omit the block entirely and exercise the disabled-by-default
/// posture.
fn config_with_machine_quota(
    base_url: &str,
    audit_path: &str,
    machine_quota_yaml: &str,
    max_batch_subjects: u32,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let fingerprint_a = api_key_fingerprint_ref_yaml("TEST_EVIDENCE_API_KEY_HASH");
    let fingerprint_b = api_key_fingerprint_ref_yaml("TEST_EVIDENCE_API_KEY_HASH_2");
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: machine-a
      {fingerprint_a}
      scopes: [farmer_registry:evidence_verification]
    - id: machine-b
      {fingerprint_b}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
deployment:
  profile: local
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
{machine_quota_yaml}  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
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
          max_subjects: {max_batch_subjects}
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

/// Starts the app server plus its mock upstream. The returned upstream
/// `TestServer` must be kept alive (bound, not `_`-discarded) for as long as
/// the app server is used: `axum_test`'s `http_transport()` listener shuts
/// down when its `TestServer` is dropped, and a dropped upstream fails every
/// source fetch with `source.unavailable` instead of ever reaching the mock
/// handler.
async fn start_server(
    machine_quota_yaml: &str,
    max_batch_subjects: u32,
) -> (TestServer, TestServer, TempDir) {
    set_api_key_envs();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(config_with_machine_quota(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        machine_quota_yaml,
        max_batch_subjects,
    ))
    .expect("standalone router builds");
    (
        TestServer::builder().http_transport().build(app),
        upstream,
        tmp,
    )
}

fn batch_body(prefix: &str, count: usize) -> Value {
    let subjects: Vec<Value> = (0..count)
        .map(|i| person_target(&format!("{prefix}-{i}")))
        .collect();
    json!({
        "claims": ["farmed-land-size"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    })
}

fn evaluate_body(id: &str) -> Value {
    json!({
        "target": person_target(id),
        "claims": ["farmed-land-size"],
        "disclosure": "value",
    })
}

fn audit_records(tmp: &TempDir) -> Vec<Value> {
    std::fs::read_to_string(tmp.path().join("audit.jsonl"))
        .expect("audit jsonl was written")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .map(|envelope| envelope["record"].clone())
        .collect()
}

#[tokio::test]
async fn disabled_by_default_allows_repeated_max_size_batches() {
    let (server, _upstream, _tmp) = start_server("", 10).await;

    // machine_quota is omitted from the config entirely, so it must default
    // to disabled: five repeated max-size batches from the same credential
    // must all succeed with no quota interference.
    for _ in 0..5 {
        let response = server
            .post("/v1/batch-evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&batch_body("disabled", 10))
            .await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["summary"]["succeeded"], json!(10));
        assert_eq!(body["summary"]["failed"], json!(0));
    }
}

#[tokio::test]
async fn enabled_quota_returns_429_deterministically_with_stable_code() {
    let (server, _upstream, tmp) = start_server(
        "  machine_quota:\n    enabled: true\n    subjects_per_minute: 25\n",
        10,
    )
    .await;

    // subjects_per_minute=25, max batch size=10: two full batches consume
    // exactly 20, leaving 5 remaining. A third batch of 10 exceeds the
    // remaining budget and must be rejected whole and deterministically.
    for i in 0..2 {
        let response = server
            .post("/v1/batch-evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&batch_body(&format!("batch-{i}"), 10))
            .await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["summary"]["succeeded"], json!(10));
    }

    let exhausted = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("batch-2", 10))
        .await;
    exhausted.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: Value = exhausted.json();
    assert_eq!(body["code"], json!("evaluation.quota_exceeded"));
    assert_eq!(body["status"], json!(429));
    let retry_after = exhausted
        .header(header::RETRY_AFTER.as_str())
        .to_str()
        .expect("retry-after is ASCII")
        .parse::<u64>()
        .expect("retry-after is a positive integer");
    assert!(retry_after > 0 && retry_after <= 60);

    let quota_audit = audit_records(&tmp)
        .into_iter()
        .find(|record| record["decision"] == json!("batch_evaluate_denied"))
        .expect("machine quota denial audit record exists");
    assert_eq!(
        quota_audit["error_code"],
        json!("evaluation.quota_exceeded")
    );
    assert!(quota_audit["claim_hash"].is_string());
    let purposes = quota_audit["purposes"]
        .as_array()
        .expect("batch quota audit carries purpose per requested subject");
    assert_eq!(purposes.len(), 10);
    assert!(purposes
        .iter()
        .all(|purpose| purpose == "https://purpose.example.test/eligibility"));
    assert_eq!(quota_audit["source_read_count"], json!(0));
    assert_eq!(quota_audit["forwarded"], json!(false));
}

#[tokio::test]
async fn idempotent_batch_replay_does_not_consume_machine_quota() {
    let (server, _upstream, _tmp) = start_server(
        "  machine_quota:\n    enabled: true\n    subjects_per_minute: 2\n",
        2,
    )
    .await;
    let request = batch_body("retry", 2);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .add_header("idempotency-key", "same-batch")
        .json(&request)
        .await;
    response.assert_status_ok();
    let first: Value = response.json();
    assert_eq!(first["summary"]["succeeded"], json!(2));

    let replay = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .add_header("idempotency-key", "same-batch")
        .json(&request)
        .await;
    replay.assert_status_ok();
    let second: Value = replay.json();
    assert_eq!(second, first);

    let exhausted = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("new-work", 1))
        .await;
    exhausted.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: Value = exhausted.json();
    assert_eq!(body["code"], json!("evaluation.quota_exceeded"));
}

#[tokio::test]
async fn oversized_batch_does_not_consume_machine_quota() {
    let (server, _upstream, _tmp) = start_server(
        "  machine_quota:\n    enabled: true\n    subjects_per_minute: 1\n",
        1,
    )
    .await;

    let oversized = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("oversized", 2))
        .await;
    oversized.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = oversized.json();
    assert_eq!(body["code"], json!("batch.too_large"));

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&evaluate_body("still-has-budget"))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(1.0));
}

#[tokio::test]
async fn second_machine_credential_has_independent_budget() {
    let (server, _upstream, _tmp) = start_server(
        "  machine_quota:\n    enabled: true\n    subjects_per_minute: 5\n",
        10,
    )
    .await;

    // Exhaust machine-a's budget entirely with one batch of 5.
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("a", 5))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["summary"]["succeeded"], json!(5));

    let exhausted = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&evaluate_body("a-extra"))
        .await;
    exhausted.assert_status(StatusCode::TOO_MANY_REQUESTS);

    // machine-b has never made a request, so its budget is untouched even
    // though machine-a (a distinct principal) is fully exhausted.
    let unaffected = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token-2")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("b", 5))
        .await;
    unaffected.assert_status_ok();
    let unaffected_body: Value = unaffected.json();
    assert_eq!(unaffected_body["summary"]["succeeded"], json!(5));
}

#[tokio::test]
async fn single_evaluate_calls_share_budget_with_batch_calls() {
    let (server, _upstream, tmp) = start_server(
        "  machine_quota:\n    enabled: true\n    subjects_per_minute: 3\n",
        10,
    )
    .await;

    // Two single-evaluate calls consume 1 each (2 total).
    for i in 0..2 {
        let response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&evaluate_body(&format!("single-{i}")))
            .await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["results"][0]["value"], json!(1.0));
    }

    // A batch of 1 consumes the third and final subject in the budget.
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&batch_body("batch", 1))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["summary"]["succeeded"], json!(1));

    // The budget is now fully spent: single-evaluate and batch-evaluate draw
    // from the same pool, so the next single-evaluate call must be denied.
    let exhausted = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&evaluate_body("single-3"))
        .await;
    exhausted.assert_status(StatusCode::TOO_MANY_REQUESTS);

    let quota_audit = audit_records(&tmp)
        .into_iter()
        .find(|record| record["decision"] == json!("evaluate_denied"))
        .expect("machine quota denial audit record exists");
    assert_eq!(
        quota_audit["error_code"],
        json!("evaluation.quota_exceeded")
    );
    assert!(quota_audit["claim_hash"].is_string());
    assert_eq!(
        quota_audit["purposes"],
        json!(["https://purpose.example.test/eligibility"])
    );
    assert_eq!(quota_audit["source_read_count"], json!(0));
    assert_eq!(quota_audit["forwarded"], json!(false));
}

fn self_attestation_and_machine_oidc_config(
    base_url: &str,
    audit_path: &str,
    issuer: &str,
    jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: oidc
  oidc:
    issuer: "{issuer}"
    jwks_url: "{jwks_uri}"
    audiences:
      - registry-notary-citizen
      - registry-notary-service
    allowed_clients:
      - citizen-portal
      - service-client
    allowed_algorithms:
      - EdDSA
    allowed_token_types:
      - JWT
    scope_claim: scope
    scope_separator: " "
    principal_claim: sub
    leeway: 60s
    allow_insecure_localhost: true
    scope_map:
      self_attestation:
        - self_attestation
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
deployment:
  profile: local
evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
  machine_quota:
    enabled: true
    subjects_per_minute: 1
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: TEST_SELF_ATTESTATION_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer-key
      vct: http://127.0.0.1:4325/credentials/civil-status
      validity_seconds: 600
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods:
          - did:jwk
      allowed_claims:
        - person-is-alive
      disclosure:
        allowed:
          - value
  source_connections:
    people:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
  claims:
    - id: person-is-alive
      title: Person is alive
      version: 2026-05
      subject_type: person
      purpose: citizen_self_attestation
      value:
        type: boolean
      source_bindings:
        person:
          connector: registry_data_api
          connection: people
          required_scope: people:evidence_verification
          dataset: people
          entity: person
          lookup:
            input: target.identifiers.national_id
            field: id
            op: eq
            cardinality: one
          fields:
            alive:
              field: alive
              type: boolean
              required: true
      rule:
        type: extract
        source: person
        field: alive
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
      credential_profiles:
        - civil_status_sd_jwt
self_attestation:
  enabled: true
  subject_binding:
    token_claim: national_id
    id_type: national_id
  citizen_clients:
    allowed_client_ids:
      - citizen-portal
    allowed_audiences:
      - registry-notary-citizen
  token_policy:
    max_auth_age_seconds: 900
    max_access_token_lifetime_seconds: 900
    max_evaluation_age_seconds: 600
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: true
    issue_credential: false
    batch_evaluate: false
  allowed_purposes:
    - citizen_self_attestation
  allowed_claims:
    - person-is-alive
  allowed_formats:
    - application/vnd.registry-notary.claim-result+json
    - application/dc+sd-jwt
  allowed_disclosures:
    - value
    - redacted
  required_scopes:
    - self_attestation
  credential_profiles:
    - civil_status_sd_jwt
  allowed_wallet_origins:
    - https://wallet.example.gov
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
"#
    );
    serde_norway::from_str(&raw).expect("self-attestation + machine config deserializes")
}

async fn people_registry_data_api(Query(query): Query<BTreeMap<String, String>>) -> Response {
    if query.get("id").map(String::as_str) != Some("person-1") {
        return Json(json!({ "data": [] })).into_response();
    }
    Json(json!({
        "data": [{
            "id": "person-1",
            "alive": true,
        }]
    }))
    .into_response()
}

#[tokio::test]
async fn self_attestation_evaluate_succeeds_while_machine_quota_is_exhausted_for_same_principal_id()
{
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw\",\"x\":\"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc\",\"alg\":\"EdDSA\"}");

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(people_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_and_machine_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // A machine-classified OIDC principal (distinct audience/client, no
    // self-attestation scope) that happens to carry the *same* `sub` as the
    // citizen below. subjects_per_minute=1, so this single call exhausts the
    // machine quota for principal_id "citizen-subject".
    let machine_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-service",
        "azp": "service-client",
        "scope": "people:evidence_verification",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let machine_evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", format!("Bearer {machine_token}"))
        .json(&json!({
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "purpose": "citizen_self_attestation",
            "target": {
                "type": "Person",
                "identifiers": [{ "scheme": "national_id", "value": "person-1" }],
            },
        }))
        .await;
    machine_evaluate.assert_status_ok();

    let machine_exhausted = server
        .post("/v1/evaluations")
        .add_header("authorization", format!("Bearer {machine_token}"))
        .json(&json!({
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "purpose": "citizen_self_attestation",
            "target": {
                "type": "Person",
                "identifiers": [{ "scheme": "national_id", "value": "person-1" }],
            },
        }))
        .await;
    machine_exhausted.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: Value = machine_exhausted.json();
    assert_eq!(body["code"], json!("evaluation.quota_exceeded"));

    // A self-attestation citizen JWT with the *same* `sub` ("citizen-subject")
    // must still succeed: self-attestation principals never reach the
    // machine quota limiter, regardless of the (shared) principal_id's
    // machine-quota state.
    let citizen_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let citizen_evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", format!("Bearer {citizen_token}"))
        .json(&json!({
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    citizen_evaluate.assert_status_ok();
    let citizen_body: Value = citizen_evaluate.json();
    assert_eq!(citizen_body["results"][0]["value"], json!(true));

    idp.stop().await;
}
