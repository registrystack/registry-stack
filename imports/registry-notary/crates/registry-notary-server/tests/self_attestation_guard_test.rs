// SPDX-License-Identifier: Apache-2.0
//! Integration coverage for self-attestation stored-evaluation guards.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::sd_jwt::EvidenceIssuer;
use registry_notary_core::{
    AccessMode, BoundedVerifiedClaims, EvidenceConfig, EvidenceError, EvidencePrincipal,
    SelfAttestationConfig, SourceBindingConfig, SubjectRequest, VerifiedClaimName,
    VerifiedClaimValue, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
};
use registry_notary_server::{
    EvidenceIssuerResolver, EvidenceStore, RegistryNotaryApiState, SourceReader,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_crypto::{sign, PrivateJwk};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const RAW_PRINCIPAL_ID: &str = "citizen-raw-principal";
const SUBJECT_ID: &str = "person-1";
const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const HOLDER_PRIV_D_B64: &str = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw";
const HOLDER_PUB_X_B64: &str = "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc";

fn self_attestation_target() -> Value {
    json!({
        "type": "Person",
        "identifiers": [
            { "scheme": "national_id", "value": SUBJECT_ID }
        ],
    })
}

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

#[derive(Debug)]
struct StaticIssuers;

impl EvidenceIssuerResolver for StaticIssuers {
    fn issuer(&self, profile_id: &str) -> Result<EvidenceIssuer, EvidenceError> {
        if profile_id != "civil_status_sd_jwt" {
            return Err(EvidenceError::CredentialIssuerNotConfigured);
        }
        EvidenceIssuer::from_jwk_str(ISSUER_JWK, "did:web:issuer.example#key-1".to_string())
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
            audiences: vec![bounded("registry-notary-citizen")],
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

fn self_attestation_principal_with_id(raw_id: &str) -> EvidencePrincipal {
    let mut principal = self_attestation_principal();
    principal.principal_id = raw_id.to_string();
    if let Some(claims) = principal.verified_claims.as_mut() {
        claims.subject = Some(bounded(raw_id));
    }
    principal
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

fn credential_issuance_config() -> TestRuntimeConfig {
    let raw = format!(
        r#"
evidence:
  enabled: true
  service_id: evidence.test
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: TEST_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil_status_sd_jwt:
      format: {FORMAT_SD_JWT_VC}
      issuer: did:web:issuer.example
      signing_key: issuer-key
      vct: https://issuer.example/credentials/civil-status
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
          - redacted
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
        default: redacted
        allowed: [redacted]
      formats:
        - {FORMAT_CLAIM_RESULT_JSON}
        - {FORMAT_SD_JWT_VC}
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
    issue_credential: true
    batch_evaluate: false
  allowed_purposes:
    - citizen_self_attestation
  allowed_claims:
    - person-is-alive
  allowed_formats:
    - {FORMAT_CLAIM_RESULT_JSON}
    - {FORMAT_SD_JWT_VC}
  allowed_disclosures:
    - redacted
  required_scopes:
    - self_attestation
  allowed_wallet_origins:
    - https://wallet.example.gov
  credential_profiles:
    - civil_status_sd_jwt
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
"#
    );
    serde_norway::from_str(&raw).expect("credential issuance config deserializes")
}

fn build_server(
    config: TestRuntimeConfig,
    store: Arc<EvidenceStore>,
    principal: EvidencePrincipal,
) -> TestServer {
    let state = Arc::new(RegistryNotaryApiState::new_with_self_attestation_hasher(
        Arc::new(config.evidence),
        Arc::new(config.self_attestation),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(StaticSource),
        store,
        Arc::new(NoopIssuers),
    ));
    TestServer::builder().http_transport().build(
        registry_notary_server::router::<()>()
            .layer(Extension(state))
            .layer(Extension(principal)),
    )
}

fn build_issuance_server(
    config: TestRuntimeConfig,
    store: Arc<EvidenceStore>,
    principal: EvidencePrincipal,
) -> TestServer {
    let state = Arc::new(RegistryNotaryApiState::new_with_self_attestation_hasher(
        Arc::new(config.evidence),
        Arc::new(config.self_attestation),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(StaticSource),
        store,
        Arc::new(StaticIssuers),
    ));
    TestServer::builder().http_transport().build(
        registry_notary_server::router::<()>()
            .layer(Extension(state))
            .layer(Extension(principal)),
    )
}

fn holder_did_jwk() -> String {
    let public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": HOLDER_PUB_X_B64,
    });
    let encoded =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public_jwk).expect("holder JWK serializes"));
    format!("did:jwk:{encoded}")
}

fn sign_holder_proof(holder_id: &str, evaluation_id: &str) -> String {
    let holder = PrivateJwk::parse(
        &json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": HOLDER_PRIV_D_B64,
            "x": HOLDER_PUB_X_B64,
            "alg": "EdDSA",
            "kid": holder_id,
        })
        .to_string(),
    )
    .expect("holder JWK parses");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let payload = json!({
        "sub": holder_id,
        "aud": "evidence.test",
        "iat": now,
        "exp": now + 60,
        "jti": "self-attestation-jti-1",
        "evaluation_id": evaluation_id,
        "credential_profile": "civil_status_sd_jwt",
        "disclosure": URL_SAFE_NO_PAD.encode(Sha256::digest("redacted".as_bytes())),
        "claims": ["person-is-alive"],
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "kb+jwt",
            "kid": holder_id,
        }))
        .expect("header serializes"),
    );
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).expect("holder proof payload serializes"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), &holder).expect("holder proof signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn jwt_payload(jwt: &str) -> Value {
    let payload = jwt
        .split('.')
        .nth(1)
        .expect("compact JWT has a payload segment");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload decodes as base64url"),
    )
    .expect("payload decodes as JSON")
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
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
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
        .post(&format!("/v1/evaluations/{evaluation_id}/render"))
        .json(&json!({
            "format": FORMAT_CLAIM_RESULT_JSON,
            "disclosure": "value"
        }))
        .await;

    render.assert_status(StatusCode::FORBIDDEN);
    let render_body: Value = render.json();
    assert_eq!(render_body["code"], json!("evaluation.binding_mismatch"));
}

#[tokio::test]
async fn self_attestation_render_rejects_same_evaluation_for_different_principal() {
    let store = Arc::new(EvidenceStore::default());
    let server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        Arc::clone(&store),
        self_attestation_principal_with_id("citizen-raw-principal-a"),
    );

    let evaluate = server
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
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

    let different_principal_server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        Arc::clone(&store),
        self_attestation_principal_with_id("citizen-raw-principal-b"),
    );
    let render = different_principal_server
        .post(&format!("/v1/evaluations/{evaluation_id}/render"))
        .json(&json!({
            "format": FORMAT_CLAIM_RESULT_JSON,
            "disclosure": "value"
        }))
        .await;

    render.assert_status(StatusCode::NOT_FOUND);
    let render_body: Value = render.json();
    assert_eq!(render_body["code"], json!("evaluation.not_found"));
}

#[tokio::test]
async fn self_attestation_credential_issuance_hides_other_principal_evaluation_ids() {
    let store = Arc::new(EvidenceStore::default());
    let server = build_issuance_server(
        credential_issuance_config(),
        Arc::clone(&store),
        self_attestation_principal_with_id("citizen-raw-principal-a"),
    );

    let evaluate = server
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
            "claims": ["person-is-alive"],
            "disclosure": "redacted",
            "format": FORMAT_SD_JWT_VC
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id is returned")
        .to_string();

    let different_principal_server = build_issuance_server(
        credential_issuance_config(),
        Arc::clone(&store),
        self_attestation_principal_with_id("citizen-raw-principal-b"),
    );
    let denied = different_principal_server
        .post("/v1/credentials")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": FORMAT_SD_JWT_VC,
            "claims": ["person-is-alive"],
            "disclosure": "redacted"
        }))
        .await;

    denied.assert_status(StatusCode::NOT_FOUND);
    let denied_body: Value = denied.json();
    assert_eq!(denied_body["code"], json!("evaluation.not_found"));
}

#[tokio::test]
async fn self_attestation_render_rejects_expired_metadata_via_http() {
    let store = Arc::new(EvidenceStore::default());
    let principal = self_attestation_principal();
    let server = build_server(
        config_with_allowed_disclosures(&["value", "redacted"]),
        Arc::clone(&store),
        principal,
    );

    let evaluate = server
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
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

    let mut stored = store
        .get(&evaluation_id)
        .expect("self-attestation evaluation was stored");
    stored.expires_at = "2999-01-01T00:00:00Z".to_string();
    stored
        .self_attestation
        .as_mut()
        .expect("self-attestation metadata was stored")
        .evaluation_expires_at = Some("1970-01-01T00:00:00Z".to_string());
    store.insert(stored);

    let render = server
        .post(&format!("/v1/evaluations/{evaluation_id}/render"))
        .json(&json!({
            "format": FORMAT_CLAIM_RESULT_JSON,
            "disclosure": "value"
        }))
        .await;

    render.assert_status(StatusCode::NOT_FOUND);
    let render_body: Value = render.json();
    assert_eq!(render_body["code"], json!("evaluation.not_found"));
}

#[tokio::test]
async fn self_attestation_credential_issuance_requires_holder_proof_and_hides_civil_id() {
    let store = Arc::new(EvidenceStore::default());
    let server = build_issuance_server(
        credential_issuance_config(),
        Arc::clone(&store),
        self_attestation_principal(),
    );

    let evaluate = server
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
            "claims": ["person-is-alive"],
            "disclosure": "redacted",
            "format": FORMAT_SD_JWT_VC
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id is returned")
        .to_string();

    let missing_holder = server
        .post("/v1/credentials")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": FORMAT_SD_JWT_VC,
            "claims": ["person-is-alive"],
            "disclosure": "redacted"
        }))
        .await;
    missing_holder.assert_status(StatusCode::BAD_REQUEST);
    let missing_holder_body: Value = missing_holder.json();
    assert_eq!(
        missing_holder_body["code"],
        json!("credential.holder_proof_required")
    );

    let holder_id = holder_did_jwk();
    let proof = sign_holder_proof(&holder_id, &evaluation_id);
    let issued = server
        .post("/v1/credentials")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": FORMAT_SD_JWT_VC,
            "claims": ["person-is-alive"],
            "disclosure": "redacted",
            "holder": {
                "binding": "did",
                "id": holder_id.clone(),
                "proof": proof.clone()
            }
        }))
        .await;
    issued.assert_status_ok();
    let issued_body: Value = issued.json();
    let payload = jwt_payload(
        issued_body["issuer_signed_jwt"]
            .as_str()
            .expect("issuer-signed JWT is returned"),
    );

    assert_eq!(payload["sub"], json!(holder_id));
    assert!(
        !payload.to_string().contains(SUBJECT_ID),
        "issuer-signed payload must not expose the raw civil id"
    );
    let iat = payload["iat"].as_i64().expect("iat is an integer");
    let exp = payload["exp"].as_i64().expect("exp is an integer");
    assert!(
        exp - iat <= 600,
        "self-attestation credential validity must not exceed 600 seconds"
    );

    let replay = server
        .post("/v1/credentials")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": FORMAT_SD_JWT_VC,
            "claims": ["person-is-alive"],
            "disclosure": "redacted",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": proof
            }
        }))
        .await;
    replay.assert_status(StatusCode::CONFLICT);
    let replay_body: Value = replay.json();
    assert_eq!(replay_body["code"], json!("credential.holder_proof_replay"));
}

#[tokio::test]
async fn self_attestation_credential_issuance_rejects_disallowed_profile() {
    let mut config = credential_issuance_config();
    let machine_profile = config
        .evidence
        .credential_profiles
        .get("civil_status_sd_jwt")
        .expect("civil status profile exists")
        .clone();
    config
        .evidence
        .credential_profiles
        .insert("machine_only_sd_jwt".to_string(), machine_profile);
    config.evidence.claims[0]
        .credential_profiles
        .push("machine_only_sd_jwt".to_string());

    let store = Arc::new(EvidenceStore::default());
    let server = build_issuance_server(config, Arc::clone(&store), self_attestation_principal());

    let evaluate = server
        .post("/v1/evaluations")
        .json(&json!({
            "target": self_attestation_target(),
            "claims": ["person-is-alive"],
            "disclosure": "redacted",
            "format": FORMAT_SD_JWT_VC
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id is returned")
        .to_string();

    let denied = server
        .post("/v1/credentials")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "machine_only_sd_jwt",
            "format": FORMAT_SD_JWT_VC,
            "claims": ["person-is-alive"],
            "disclosure": "redacted"
        }))
        .await;

    denied.assert_status(StatusCode::FORBIDDEN);
    let denied_body: Value = denied.json();
    assert_eq!(denied_body["code"], json!("self_attestation.denied"));
}
