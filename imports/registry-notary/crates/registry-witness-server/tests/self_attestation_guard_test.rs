// SPDX-License-Identifier: Apache-2.0
//! Integration coverage for self-attestation stored-evaluation guards.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use registry_platform_audit::AuditKeyHasher;
use registry_witness_core::sd_jwt::EvidenceIssuer;
use registry_witness_core::{
    AccessMode, BoundedVerifiedClaims, EvidenceConfig, EvidenceError, EvidencePrincipal,
    SelfAttestationConfig, SourceBindingConfig, SubjectRequest, VerifiedClaimName,
    VerifiedClaimValue, FORMAT_CLAIM_RESULT_JSON,
};
use registry_witness_server::{
    EvidenceIssuerResolver, EvidenceStore, RegistryWitnessApiState, SourceReader,
};
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

const RAW_PRINCIPAL_ID: &str = "citizen-raw-principal";
const SUBJECT_ID: &str = "person-1";

#[derive(Debug, Deserialize)]
struct TestRuntimeConfig {
    evidence: EvidenceConfig,
    self_attestation: SelfAttestationConfig,
}

#[derive(Debug)]
struct StaticSource;

impl SourceReader for StaticSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(subject.id, SUBJECT_ID);
            assert_eq!(purpose, "citizen_self_attestation");
            Ok(json!({ "id": SUBJECT_ID, "alive": true }))
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(vec!["people:evidence_verification".to_string()])
    }
}

#[derive(Debug)]
struct NoopIssuers;

impl EvidenceIssuerResolver for NoopIssuers {
    fn issuer(&self, _profile_id: &str) -> Result<EvidenceIssuer, EvidenceError> {
        Err(EvidenceError::CredentialIssuerNotConfigured)
    }
}

fn bounded(value: &str) -> VerifiedClaimValue {
    VerifiedClaimValue::new(value).expect("test verified claim value is bounded")
}

fn self_attestation_principal() -> EvidencePrincipal {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    EvidencePrincipal {
        principal_id: RAW_PRINCIPAL_ID.to_string(),
        scopes: vec!["self_attestation".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: Some(BoundedVerifiedClaims {
            issuer: bounded("https://idp.example.test"),
            audiences: vec![bounded("registry-witness-citizen")],
            client_id: Some(bounded("azp:citizen-portal")),
            token_type: Some(bounded("JWT")),
            scopes: vec![bounded("self_attestation")],
            subject: Some(bounded(RAW_PRINCIPAL_ID)),
            subject_binding_claim: Some(
                VerifiedClaimName::new("national_id")
                    .expect("test subject binding claim is bounded"),
            ),
            subject_binding_value: Some(bounded(SUBJECT_ID)),
            acr: None,
            auth_time: Some(now),
            exp: Some(now + 300),
            iat: Some(now),
            nbf: Some(now),
        }),
    }
}

fn machine_principal() -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: "caseworker".to_string(),
        scopes: vec!["people:evidence_verification".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
    }
}

fn config_with_allowed_disclosures(allowed_disclosures: &[&str]) -> TestRuntimeConfig {
    let allowed_disclosures_yaml = allowed_disclosures
        .iter()
        .map(|disclosure| format!("    - {disclosure}"))
        .collect::<Vec<_>>()
        .join("\n");
    let raw = format!(
        r#"
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    people:
      base_url: http://127.0.0.1:1
      allow_insecure_localhost: true
      token_env: TEST_SOURCE_TOKEN
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
            input: subject_id
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
        - {FORMAT_CLAIM_RESULT_JSON}
self_attestation:
  enabled: true
  subject_binding:
    token_claim: national_id
    id_type: national_id
  citizen_clients:
    allowed_client_ids:
      - citizen-portal
    allowed_audiences:
      - registry-witness-citizen
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
    - {FORMAT_CLAIM_RESULT_JSON}
  allowed_disclosures:
{allowed_disclosures_yaml}
  required_scopes:
    - self_attestation
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
    serde_norway::from_str(&raw).expect("test config deserializes")
}

fn build_server(
    config: TestRuntimeConfig,
    store: Arc<EvidenceStore>,
    principal: EvidencePrincipal,
) -> TestServer {
    let state = Arc::new(RegistryWitnessApiState::new_with_self_attestation_hasher(
        Arc::new(config.evidence),
        Arc::new(config.self_attestation),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(StaticSource),
        store,
        Arc::new(NoopIssuers),
    ));
    TestServer::builder().http_transport().build(
        registry_witness_server::router::<()>()
            .layer(Extension(state))
            .layer(Extension(principal)),
    )
}

#[tokio::test]
async fn self_attestation_discovery_details_require_self_attestation_principal() {
    let store = Arc::new(EvidenceStore::default());
    let machine_server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        Arc::clone(&store),
        machine_principal(),
    );

    let machine_response = machine_server.get("/.well-known/evidence-service").await;
    machine_response.assert_status_ok();
    let machine_body: Value = machine_response.json();
    assert_eq!(machine_body["self_attestation"]["enabled"], json!(true));
    assert!(machine_body["self_attestation"]["subject_id_type"].is_null());
    assert!(machine_body["self_attestation"]["token_claim_name"].is_null());
    assert!(machine_body["self_attestation"]["allowed_claim_ids"].is_null());

    let self_attestation_server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        store,
        self_attestation_principal(),
    );
    let self_attestation_response = self_attestation_server
        .get("/.well-known/evidence-service")
        .await;
    self_attestation_response.assert_status_ok();
    let self_attestation_body: Value = self_attestation_response.json();
    assert_eq!(
        self_attestation_body["self_attestation"]["subject_id_type"],
        json!("national_id")
    );
    assert_eq!(
        self_attestation_body["self_attestation"]["token_claim_name"],
        json!("national_id")
    );
    assert_eq!(
        self_attestation_body["self_attestation"]["allowed_claim_ids"],
        json!(["person-is-alive"])
    );
}

#[tokio::test]
async fn self_attestation_stores_hashed_principal_and_render_policy_changes_fail_closed() {
    let store = Arc::new(EvidenceStore::default());
    let principal = self_attestation_principal();
    let server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        Arc::clone(&store),
        principal.clone(),
    );

    let evaluate = server
        .post("/claims/evaluate")
        .json(&json!({
            "subject": {
                "id": SUBJECT_ID,
                "id_type": "national_id"
            },
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": FORMAT_CLAIM_RESULT_JSON
        }))
        .await;

    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id is returned")
        .to_string();
    assert_eq!(evaluate_body["results"][0]["value"], json!(true));

    let stored = store
        .get(&evaluation_id)
        .expect("self-attestation evaluation was stored");
    let metadata = stored
        .self_attestation
        .as_ref()
        .expect("self-attestation metadata was stored");
    assert_ne!(stored.client_id, RAW_PRINCIPAL_ID);
    assert_eq!(stored.client_id, metadata.principal_hash.as_str());
    assert_ne!(metadata.principal_hash.as_str(), RAW_PRINCIPAL_ID);

    let changed_policy_server = build_server(
        config_with_allowed_disclosures(&["redacted"]),
        Arc::clone(&store),
        principal,
    );
    let render = changed_policy_server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "format": FORMAT_CLAIM_RESULT_JSON,
            "disclosure": "value"
        }))
        .await;

    render.assert_status(StatusCode::FORBIDDEN);
    let render_body: Value = render.json();
    assert_eq!(render_body["code"], json!("evaluation.binding_mismatch"));
}
