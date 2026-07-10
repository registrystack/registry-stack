// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary tests that do not link Registry Relay.

use axum::body::Bytes;
use axum::extract::Query;
#[cfg(feature = "registry-notary-cel")]
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
#[cfg(feature = "registry-notary-cel")]
use axum::routing::post;
use axum::{Json, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP;
#[cfg(feature = "registry-notary-cel")]
use registry_notary_core::FEDERATION_RESPONSE_JWT_TYP;
use registry_notary_core::{
    BulkMode, ConfigTrustConfig, CredentialProfileConfig, EvidenceAuthMode,
    EvidenceCredentialConfig, EvidenceOidcAuthConfig, Oid4vciConfig, Oid4vciCredentialClaimConfig,
    RegistryNotaryAdminListenerMode, RuleConfig, SelfAttestationClaimSource, SigningKeyConfig,
    SigningKeyProviderConfig, SigningKeyStatus, SourceFieldConfig, StandaloneRegistryNotaryConfig,
    SD_JWT_VC_SIGNING_ALG,
};
#[cfg(feature = "registry-notary-cel")]
use registry_notary_server::cel_worker::{CelWorker, CelWorkerConfig};
use registry_notary_server::{
    compile_notary_runtime, notary_routers_from_runtime, openapi_document, standalone_router,
    StandaloneServerError,
};
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope};
use registry_platform_authcommon::{CredentialFingerprintProvider, CredentialFingerprintRef};
#[cfg(feature = "registry-notary-cel")]
use registry_platform_crypto::verify;
use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
use registry_platform_ops::internal_config_hash;
use registry_platform_testing::{
    fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, sign_openid4vci_proof_jwt,
    MockHttpUpstream, MockIdp, FEDERATION_PROTOCOL, FEDERATION_REQUEST_JWT_TYPE,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
#[cfg(feature = "registry-notary-cel")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(feature = "registry-notary-cel")]
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;
#[cfg(feature = "registry-notary-cel")]
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_HOLDER_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA"}"#;
#[derive(Debug, Deserialize)]
struct ExposureManifest {
    endpoints: Vec<ExposureEndpoint>,
}

#[derive(Debug, Deserialize)]
struct ExposureEndpoint {
    listener: String,
    method: String,
    path: String,
    feature: Option<String>,
    auth: String,
}

fn person_target(id: &str) -> Value {
    json!({
        "type": "Person",
        "id": id,
    })
}

fn person_identifier_target(scheme: &str, value: &str) -> Value {
    json!({
        "type": "Person",
        "identifiers": [
            { "scheme": scheme, "value": value }
        ],
    })
}

#[cfg(feature = "registry-notary-cel")]
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
    #[cfg(feature = "registry-notary-cel")]
    std::env::set_var("REGISTRY_NOTARY_CEL_WORKER_COMMAND", cel_worker_bin());
}

fn sign_oid4vci_proof(audience: &str, nonce: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    sign_openid4vci_proof_jwt(TEST_HOLDER_JWK, audience, Some(nonce), now)
}

fn sign_oid4vci_proof_without_iss(audience: &str, nonce: &str) -> String {
    let holder = PrivateJwk::parse(TEST_HOLDER_JWK).expect("holder JWK parses");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": holder.public(),
        }))
        .expect("header serializes"),
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "aud": audience,
            "iat": now,
            "exp": now + 60,
            "nonce": nonce,
        }))
        .expect("payload serializes"),
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), &holder).expect("holder signs proof");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn sign_direct_holder_proof(holder_id: &str, evaluation_id: &str, jti: &str) -> String {
    let holder = PrivateJwk::parse(TEST_HOLDER_JWK).expect("holder JWK parses");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let payload = json!({
        "sub": holder_id,
        "aud": "evidence.test",
        "iat": now,
        "exp": now + 60,
        "jti": jti,
        "evaluation_id": evaluation_id,
        "credential_profile": "civil_status_sd_jwt",
        "disclosure": URL_SAFE_NO_PAD.encode(Sha256::digest("value".as_bytes())),
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
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload serializes"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), &holder).expect("holder proof signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn holder_did_jwk() -> String {
    let holder = PrivateJwk::parse(TEST_HOLDER_JWK).expect("holder JWK parses");
    did_jwk_from_public_jwk(&holder.public()).expect("holder did:jwk encodes")
}

fn enable_credential_status(config: &mut StandaloneRegistryNotaryConfig) {
    config.credential_status = serde_norway::from_str(
        r#"
enabled: true
base_url: http://127.0.0.1:4325
storage: in_memory
retention_seconds: 3600
"#,
    )
    .expect("credential status config parses");
}

fn env_fingerprint_ref(env_name: &str) -> CredentialFingerprintRef {
    CredentialFingerprintRef {
        provider: CredentialFingerprintProvider::Env,
        name: Some(env_name.to_string()),
        path: None,
    }
}

fn add_admin_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a";
    std::env::set_var("TEST_EVIDENCE_ADMIN_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });
}

fn add_ops_read_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:d9310c002af91822beb0b3487d8b04f85bf6bf1f8a5496bff7d35fc7c5a29def";
    std::env::set_var("TEST_EVIDENCE_OPS_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "ops".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_OPS_KEY_HASH"),
        scopes: vec!["registry_notary:ops_read".to_string()],
        authorization_details: None,
    });
}

fn add_metrics_read_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:eb5a63e42b6b498364b3f10d5c3bb71cd8c7a7a9ad16524875557fa2e52f5d41";
    std::env::set_var("TEST_EVIDENCE_METRICS_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "metrics".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_METRICS_KEY_HASH"),
        scopes: vec!["registry_notary:metrics_read".to_string()],
        authorization_details: None,
    });
}

fn enable_shared_admin_listener(config: &mut StandaloneRegistryNotaryConfig) {
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
}

fn assert_matches_posture_schema(body: &Value) {
    let schema: Value = serde_json::from_str(registry_platform_ops::POSTURE_SCHEMA_V1)
        .expect("posture schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("posture schema compiles");
    let errors = compiled
        .validate(body)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        errors.is_empty(),
        "posture response did not match registry.ops.posture.v1: {errors:?}\n{body:#}"
    );
}

fn assert_standards_artifacts_omit_sha256(body: &Value, label: &str) {
    let artifacts = body["standards_artifacts"]
        .as_object()
        .expect("posture standards_artifacts is object");
    for (name, artifact) in artifacts {
        assert!(
            artifact.get("sha256").is_none(),
            "{label} standards_artifacts.{name} includes sha256, but live Notary posture no longer emits it"
        );
    }
}

fn assert_matches_admin_capabilities_schema(body: &Value) {
    let schema: Value = serde_json::from_str(registry_platform_ops::ADMIN_CAPABILITIES_SCHEMA_V1)
        .expect("admin capabilities schema parses");
    let compiled =
        jsonschema::JSONSchema::compile(&schema).expect("admin capabilities schema compiles");
    let errors = compiled
        .validate(body)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        errors.is_empty(),
        "capabilities response did not match registry.admin.capabilities.v1: {errors:?}\n{body:#}"
    );
}

fn sample_manifest_path(path: &str) -> String {
    path.replace("{claim_id}", "farmed-land-size")
        .replace("{evaluation_id}", "eval-1")
        .replace("{credential_id}", "urn:ulid:01HX0000000000000000000000")
        .replace("{*vct_path}", "civil-status")
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

async fn self_attestation_registry_data_api(
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
        != Some("citizen_self_attestation")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query.get("id").map(String::as_str) != Some("person-1") {
        return Json(json!({ "data": [] })).into_response();
    }
    Json(json!({
        "data": [{
            "id": "person-1",
            "alive": true,
            "given_name": "Miguel",
            "birth_date": "2016-01-15"
        }]
    }))
    .into_response()
}

#[cfg(feature = "registry-notary-cel")]
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
    if body["message"]["search_request"][0]["search_criteria"]["query"]["value"]
        == "openspp-missing"
    {
        return Json(json!({
            "message": {
                "search_response": [{
                    "status": "rjct",
                    "status_reason_code": "REG-ERR-001",
                    "status_reason_message": "REGISTER_NOT_FOUND: No registrant found for identifier 'openspp-missing'"
                }]
            }
        }))
        .into_response();
    }
    let query_value = body["message"]["search_request"][0]["search_criteria"]["query"]["value"]
        .as_str()
        .unwrap_or_default();
    if !matches!(
        query_value,
        "person-1" | "stale-person" | "missing-timestamp"
    ) {
        return Json(json!({
            "message": {
                "search_response": [{
                    "data": { "reg_records": [] }
                }]
            }
        }))
        .into_response();
    }
    let mut response = json!({
        "message": {
            "search_response": [{
                "data": {
                    "reg_records": [{
                        "farmed_land_size_hectares": 3.5
                    }]
                }
            }]
        }
    });
    if query_value != "missing-timestamp" {
        let observed_at = if query_value == "stale-person" {
            OffsetDateTime::now_utc() - time::Duration::days(2)
        } else {
            OffsetDateTime::now_utc()
        };
        response["message"]["search_response"][0]["timestamp"] =
            json!(observed_at.format(&Rfc3339).expect("timestamp formats"));
    }
    Json(json!({
        "message": response["message"].clone()
    }))
    .into_response()
}

#[cfg(feature = "registry-notary-cel")]
async fn civil_demographic_dci_source(
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
    Json(json!({
        "message": {
            "search_response": [{
                "data": {
                    "reg_records": [{
                        "person": {
                            "given_name": "Miguel",
                            "surname": "Santos",
                            "birth_date": "2016-01-15",
                            "deceased": false
                        }
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
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let source_connection = if connector == "dci" {
        r#"
      dci:
        search_path: /dci/fr/registry/sync/search
        query_type: idtype-value
        registry_event_type: birth
        receiver_id: upstream-registry
        signature: ""
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          farmed_land_size_hectares: /farmed_land_size_hectares"#
    } else {
        ""
    };
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
    - https://purpose.example.test/eligibility
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
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
          matching:
            allowed_purposes:
              - https://purpose.example.test/eligibility
          lookup:
            input: target.id
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
        allowed: [value, predicate, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
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
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("config deserializes")
}

fn registry_data_api_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    config(
        base_url,
        audit_path,
        "registry_data_api",
        "total_farmed_area",
    )
}

#[test]
fn compile_notary_runtime_is_named_fail_closed_boundary() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::remove_var("TEST_COMPILE_BOUNDARY_MISSING_SOURCE_TOKEN");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_COMPILE_BOUNDARY_MISSING_SOURCE_TOKEN".to_string();

    let error = match compile_notary_runtime(config) {
        Ok(_) => panic!("compile boundary must reject unresolved local env secrets"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        StandaloneServerError::MissingSourceTokenEnv(_)
    ));
    assert!(error
        .to_string()
        .contains("TEST_COMPILE_BOUNDARY_MISSING_SOURCE_TOKEN"));
}

fn registry_data_api_target_identifier_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    let mut config = registry_data_api_config(base_url, audit_path);
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists");
    claim.operations.batch_evaluate.enabled = true;
    let binding = claim
        .source_bindings
        .get_mut("farmer")
        .expect("farmer source binding exists");
    binding.lookup.input = "target.identifiers.national_id".to_string();
    binding.matching.policy_id = Some("http-target-identifier-v1".to_string());
    binding.matching.method = Some("exact_identifier".to_string());
    binding.matching.target_type = Some("Person".to_string());
    binding.matching.allowed_purposes =
        vec!["https://purpose.example.test/eligibility".to_string()];
    binding.matching.sufficient_target_inputs =
        vec![vec!["target.identifiers.national_id".to_string()]];
    binding.matching.allowed_target_inputs = vec!["target.identifiers.national_id".to_string()];
    config
}

fn set_federation_env() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_FEDERATION_SIGNING_KEY", TEST_ISSUER_JWK);
    std::env::set_var(
        "TEST_FEDERATION_PAIRWISE_SECRET",
        "federation-pairwise-secret",
    );
}

fn federation_config(
    base_url: &str,
    audit_path: &str,
    peer_jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    federation_config_for(
        base_url,
        audit_path,
        "did:web:agency-a.example.gov",
        "https://agency-a.example.gov",
        "did:web:agency-b.example.gov",
        "https://agency-b.example.gov",
        peer_jwks_uri,
    )
}

#[allow(clippy::too_many_arguments)]
fn federation_config_for(
    base_url: &str,
    audit_path: &str,
    node_id: &str,
    issuer: &str,
    peer_node_id: &str,
    peer_issuer: &str,
    peer_jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    let mut config = registry_data_api_config(base_url, audit_path);
    config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists")
        .source_bindings
        .get_mut("farmer")
        .expect("farmer binding exists")
        .lookup
        .input = "target.identifiers.national_id".to_string();
    config.evidence.signing_keys.insert(
        "federation-key".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: SD_JWT_VC_SIGNING_ALG.to_string(),
            kid: "agency-a-fed-1".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "TEST_FEDERATION_SIGNING_KEY".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    config.federation = serde_norway::from_str(&format!(
        r#"
enabled: true
node_id: {node_id}
issuer: {issuer}
jwks_uri: {issuer}/federation/jwks.json
federation_api: {issuer}/federation/v1
supported_protocol_versions:
  - registry-notary-federation/v0.1
signing:
  signing_key: federation-key
pairwise_subject_hash:
  secret_env: TEST_FEDERATION_PAIRWISE_SECRET
replay:
  storage: in_process_single_instance_only
  max_entries: 100
  eviction: expire_oldest
response_shaping:
  minimum_denial_latency_ms: 1
peers:
  - node_id: {peer_node_id}
    issuer: {peer_issuer}
    jwks_uri: "{peer_jwks_uri}"
    allow_insecure_localhost: true
    allowed_protocol_versions:
      - registry-notary-federation/v0.1
    allowed_purposes:
      - https://purpose.example.test/eligibility
    allowed_profiles:
      - farmer_under_4ha
    source_scopes:
      - farmer_registry:evidence_verification
evaluation_profiles:
  - id: farmer_under_4ha
    ruleset: farmer-under-4ha-v1
    claim_id: farmer-under-4ha
    subject_id_type: national_id
"#
    ))
    .expect("federation config deserializes");
    config
}

#[cfg(feature = "registry-notary-cel")]
fn add_governed_federation_policy_context(
    config: &mut StandaloneRegistryNotaryConfig,
    profile_jurisdiction: &str,
) {
    let binding = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists")
        .source_bindings
        .get_mut("farmer")
        .expect("farmer binding exists");
    binding.matching.allowed_assurance = vec!["substantial".to_string()];
    binding.matching.permitted_jurisdictions = vec!["ZZ".to_string()];
    binding.matching.require_legal_basis = true;
    binding.matching.require_consent = true;

    let profile = config
        .federation
        .evaluation_profiles
        .first_mut()
        .expect("federation profile exists");
    profile.disclosure = Some("predicate".to_string());
    profile.legal_basis_ref = Some("demo:benefits-eligibility".to_string());
    profile.consent_ref = Some("demo:benefits-consent".to_string());
    profile.jurisdiction = Some(profile_jurisdiction.to_string());
    profile.assurance_level = Some("substantial".to_string());
}

fn federation_request_jwt(jti: &str, purpose: &str) -> String {
    federation_request_jwt_with_claims(jti, purpose, json!(["farmer-under-4ha"]))
}

fn federation_request_jwt_with_claims(jti: &str, purpose: &str, claims: Value) -> String {
    let mut payload = federation_request_payload(jti);
    payload["purpose"] = json!(purpose);
    payload["request"]["claims"] = claims;
    federation_request_jwt_from_payload(payload)
}

fn federation_request_jwt_with_audience(jti: &str, audience: &str) -> String {
    let mut payload = federation_request_payload(jti);
    payload["aud"] = json!(audience);
    federation_request_jwt_from_payload(payload)
}

fn federation_request_jwt_with_kid(jti: &str, kid: &str) -> String {
    sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        FEDERATION_REQUEST_JWT_TYPE,
        kid,
        federation_request_payload(jti),
    )
}

fn federation_request_jwt_with_times(jti: &str, iat: i64, nbf: i64, exp: i64) -> String {
    let mut payload = federation_request_payload(jti);
    payload["iat"] = json!(iat);
    payload["nbf"] = json!(nbf);
    payload["exp"] = json!(exp);
    federation_request_jwt_from_payload(payload)
}

fn federation_request_jwt_with_subject(jti: &str, subject: &str) -> String {
    let mut payload = federation_request_payload(jti);
    payload["sub"] = json!(subject);
    federation_request_jwt_from_payload(payload)
}

fn federation_request_payload(jti: &str) -> Value {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    json!({
        "iss": "https://agency-b.example.gov",
        "sub": "did:web:agency-b.example.gov",
        "aud": "did:web:agency-a.example.gov",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": jti,
        "protocol": FEDERATION_PROTOCOL,
        "action": "evaluate",
        "profile": "farmer_under_4ha",
        "purpose": "https://purpose.example.test/eligibility",
        "request": {
            "subject": {
                "id": "person-1",
                "id_type": "national_id"
            },
            "claims": ["farmer-under-4ha"]
        }
    })
}

fn federation_request_jwt_from_payload(payload: Value) -> String {
    sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        FEDERATION_REQUEST_JWT_TYPE,
        "registry-platform-testing-ed25519-1",
        payload,
    )
}

fn federation_jwt_with_header(header: Value, payload: Value) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header encodes")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload encodes")),
        URL_SAFE_NO_PAD.encode(b"invalid-signature")
    )
}

fn tamper_jwt_signature(jwt: &str) -> String {
    let mut parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "compact jwt has three parts");
    parts[2] = "AA";
    parts.join(".")
}

#[cfg(feature = "registry-notary-cel")]
fn verified_federation_response_claims(jwt: &str) -> Value {
    verified_federation_response_claims_with_key(jwt, "agency-a-fed-1", TEST_ISSUER_JWK)
}

#[cfg(feature = "registry-notary-cel")]
fn verified_federation_response_claims_with_key(
    jwt: &str,
    expected_kid: &str,
    private_jwk: &str,
) -> Value {
    let parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "compact JWT response has three segments");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("response header is base64url"),
    )
    .expect("response header is JSON");
    assert_eq!(header["alg"], json!("EdDSA"));
    assert_eq!(header["typ"], json!(FEDERATION_RESPONSE_JWT_TYP));
    assert_eq!(header["kid"], json!(expected_kid));
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("response signature is base64url");
    let public = PrivateJwk::parse(private_jwk)
        .expect("private JWK parses")
        .public();
    verify(signing_input.as_bytes(), &signature, &public).expect("response signature verifies");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("response payload is base64url");
    serde_json::from_slice(&payload).expect("response payload is JSON")
}

fn audit_records(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("audit was written")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .map(|envelope| envelope["record"].clone())
        .collect()
}

fn self_attestation_oidc_config(
    base_url: &str,
    audit_path: &str,
    issuer: &str,
    jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: oidc
  oidc:
    issuer: "{issuer}"
    jwks_url: "{jwks_uri}"
    audiences:
      - registry-notary-citizen
    allowed_clients:
      - citizen-portal
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
evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
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
    serde_norway::from_str(&raw).expect("self-attestation config deserializes")
}

fn self_attestation_oid4vci_config(
    base_url: &str,
    audit_path: &str,
    issuer: &str,
    jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    let mut config = self_attestation_oidc_config(base_url, audit_path, issuer, jwks_uri);
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .vct = "http://127.0.0.1:4325/credentials/civil-status".to_string();
    config.oid4vci = serde_norway::from_str::<Oid4vciConfig>(
        r#"
enabled: true
credential_issuer: http://127.0.0.1:4325
authorization_servers:
  - http://127.0.0.1:4325
accepted_token_audiences:
  - registry-notary-citizen
credential_endpoint: http://127.0.0.1:4325/oid4vci/credential
offer_endpoint: http://127.0.0.1:4325/oid4vci/credential-offer
nonce_endpoint: http://127.0.0.1:4325/oid4vci/nonce
nonce:
  enabled: true
  ttl_seconds: 300
authorization:
  require_pkce_method: S256
proof:
  max_age_seconds: 300
  max_clock_skew_seconds: 30
credential_configurations:
  person_is_alive_sd_jwt:
    claim_id: person-is-alive
    credential_profile: civil_status_sd_jwt
    format: dc+sd-jwt
    scope: person-is-alive
    vct: http://127.0.0.1:4325/credentials/civil-status
    display_name: Person is alive
"#,
    )
    .expect("oid4vci config deserializes");
    config
}

fn add_self_attestation_projection_claim(
    config: &mut StandaloneRegistryNotaryConfig,
    claim_id: &str,
    title: &str,
    source_field: &str,
    value_type: &str,
) {
    let mut claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "person-is-alive")
        .expect("base self-attestation claim exists")
        .clone();
    claim.id = claim_id.to_string();
    claim.title = title.to_string();
    claim.value.value_type = value_type.to_string();
    claim.rule = RuleConfig::Extract {
        source: "person".to_string(),
        field: source_field.to_string(),
    };
    claim.formats = vec![
        "application/vnd.registry-notary.claim-result+json".to_string(),
        "application/dc+sd-jwt".to_string(),
    ];
    claim.credential_profiles = vec!["civil_status_sd_jwt".to_string()];
    let binding = claim
        .source_bindings
        .get_mut("person")
        .expect("person source binding exists");
    binding.fields.insert(
        source_field.to_string(),
        SourceFieldConfig {
            field: source_field.to_string(),
            field_type: Some(value_type.to_string()),
            unit: None,
            required: true,
            semantic_term: None,
        },
    );
    config.evidence.claims.push(claim);
    config
        .self_attestation
        .allowed_claims
        .push(claim_id.to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status profile exists")
        .allowed_claims
        .push(claim_id.to_string());
}

fn enable_oid4vci_field_projection(config: &mut StandaloneRegistryNotaryConfig) {
    add_self_attestation_projection_claim(
        config,
        "person-given-name",
        "Given name",
        "given_name",
        "string",
    );
    add_self_attestation_projection_claim(
        config,
        "person-birth-date",
        "Birth date",
        "birth_date",
        "date",
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("OID4VCI credential configuration exists");
    credential.claim_id = None;
    credential.display_name = "Civil identity fields".to_string();
    credential.claims = vec![
        Oid4vciCredentialClaimConfig {
            id: "person-given-name".to_string(),
            output_path: vec!["given_name".to_string()],
            display_name: "Given name".to_string(),
            sd: "always".to_string(),
        },
        Oid4vciCredentialClaimConfig {
            id: "person-birth-date".to_string(),
            output_path: vec!["birth_date".to_string()],
            display_name: "Birth date".to_string(),
            sd: "always".to_string(),
        },
    ];
}

#[cfg(feature = "registry-notary-cel")]
fn dci_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    config(base_url, audit_path, "dci", "farmed_land_size_hectares")
}

#[cfg(feature = "registry-notary-cel")]
fn civil_demographic_dci_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
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
      scopes: [civil_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
  source_connections:
    civil_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_EVIDENCE_SOURCE_TOKEN
      dci:
        search_path: /dci/fr/registry/sync/search
        query_type: predicate
        registry_event_type: birth
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          given_name: /person/given_name
          surname: /person/surname
          birth_date: /person/birth_date
          deceased: /person/deceased
  claims:
    - id: civil-person-is-alive-by-demographics
      title: Civil person is alive by demographics
      version: 2026-06
      subject_type: person
      value:
        type: boolean
      source_bindings:
        birth_record:
          connector: dci
          connection: civil_registry
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: birth_record
          lookup:
            input: target.attributes.given_name
            field: given_name
            op: eq
            cardinality: one
          query_fields:
            - input: target.attributes.given_name
              field: given_name
              op: eq
            - input: target.attributes.surname
              field: surname
              op: eq
            - input: target.attributes.birth_date
              field: birth_date
              op: eq
          fields:
            given_name:
              field: given_name
              type: string
              required: true
            surname:
              field: surname
              type: string
              required: true
            birth_date:
              field: birth_date
              type: date
              required: true
            deceased:
              field: deceased
              type: boolean
              required: true
          matching:
            target_type: Person
            method: configured_demographic_lookup
            allowed_purposes:
              - https://purpose.example.test/eligibility
            sufficient_target_inputs:
              - - target.attributes.given_name
                - target.attributes.surname
                - target.attributes.birth_date
            allowed_target_inputs:
              - target.attributes.given_name
              - target.attributes.surname
              - target.attributes.birth_date
      rule:
        type: cel
        expression: source.birth_record.deceased == false
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("Civil demographic DCI config deserializes")
}

fn no_cel_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
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
  allowed_purposes:
    - https://purpose.example.test/eligibility
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

fn audit_envelopes(path: &std::path::Path) -> Vec<AuditEnvelope> {
    std::fs::read_to_string(path)
        .expect("audit jsonl is readable")
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is an envelope"))
        .collect()
}

fn audit_record_contains_text(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Number(value) => value.to_string().contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| audit_record_contains_text(value, needle)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key != "occurred_at" && audit_record_contains_text(value, needle)),
        Value::Bool(_) | Value::Null => false,
    }
}

fn audit_records_from_envelopes(path: &std::path::Path) -> Vec<Value> {
    audit_envelopes(path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect()
}

fn audit_record_with<'a>(
    records: &'a [Value],
    path: &str,
    decision: &str,
    status: StatusCode,
    error_code: &str,
) -> &'a Value {
    records
        .iter()
        .find(|record| {
            record["path"] == json!(path)
                && record["decision"] == json!(decision)
                && record["status"] == json!(status.as_u16())
                && record["error_code"] == json!(error_code)
        })
        .unwrap_or_else(|| {
            panic!(
                "audit record missing path={path} decision={decision} status={} error_code={error_code}",
                status.as_u16()
            )
        })
}

fn assert_problem_identity(body: &Value, status: StatusCode, code: &str) {
    assert_eq!(body["status"], json!(status.as_u16()));
    assert_eq!(body["code"], json!(code));
    assert_eq!(
        body["type"],
        json!(format!(
            "https://id.registrystack.org/problems/registry-notary/{}",
            code.replace('.', "/")
        ))
    );
}

fn assert_audit_records_do_not_contain(records: &[Value], forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !records
                .iter()
                .any(|record| audit_record_contains_text(record, needle)),
            "audit records leaked forbidden text: {needle}"
        );
    }
}

fn assert_hmac_audit_field(record: &Value, field: &str) {
    assert!(
        record[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is a string"))
            .starts_with("hmac-sha256:"),
        "{field} is a keyed HMAC handle"
    );
}

fn assert_verified_federation_audit_context(
    record: &Value,
    profile: &str,
    purpose: &str,
    includes_subject_hash: bool,
) {
    assert_eq!(
        record["scopes_used"],
        json!(["farmer_registry:evidence_verification"])
    );
    assert_hmac_audit_field(record, "federation_peer_id_hash");
    assert_eq!(
        record["federation_issuer"],
        json!("https://agency-b.example.gov")
    );
    assert_eq!(record["federation_profile"], json!(profile));
    assert_eq!(record["federation_purpose"], json!(purpose));
    assert_hmac_audit_field(record, "federation_request_jti_hash");
    if includes_subject_hash {
        assert_hmac_audit_field(record, "federation_subject_ref_hash");
    } else {
        assert!(record.get("federation_subject_ref_hash").is_none());
    }
}

fn assert_federation_request_context_is_absent(record: &Value) {
    assert_eq!(record["scopes_used"], json!([]));
    for field in [
        "federation_peer_id_hash",
        "federation_issuer",
        "federation_profile",
        "federation_purpose",
        "federation_request_jti_hash",
        "federation_subject_ref_hash",
    ] {
        assert!(
            record.get(field).is_none(),
            "pre-verification denial unexpectedly recorded {field}"
        );
    }
}

#[tokio::test]
async fn healthz_ready_opaque_counters_in_503_body() {
    let server = TestServer::builder()
        .http_transport()
        .build(registry_notary_server::router::<()>());

    let healthz = server.get("/healthz").await;
    healthz.assert_status_ok();
    let healthz_body: Value = healthz.json();
    assert_eq!(healthz_body["status"], json!("ok"));
    assert_eq!(healthz_body["checks"]["total"], json!(1));
    assert_eq!(healthz_body["checks"]["failed"], json!(0));

    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let ready_content_type = ready
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .expect("ready content-type is present");
    assert!(ready_content_type.starts_with("application/problem+json"));
    let ready_body: Value = ready.json();
    assert_eq!(ready_body["code"], json!("readiness.not_ready"));
    assert_eq!(ready_body["readiness_status"], json!("not_ready"));
    assert_eq!(ready_body["checks"]["total"], json!(1));
    assert_eq!(ready_body["checks"]["ok"], json!(0));
    assert_eq!(ready_body["checks"]["failed"], json!(1));
    let ready_text = ready.text();
    assert!(!ready_text.contains("farmer_registry"));
    assert!(!ready_text.contains("source_connections"));
    assert!(!ready_text.contains("evaluations"));
}

#[tokio::test]
async fn federation_route_is_not_mounted_until_enabled() {
    set_federation_env();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/federation/v1/evaluations")
        .bytes(Bytes::from_static(b"not-mounted"))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_evaluation_returns_signed_response_and_rejects_replay() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);
    enable_shared_admin_listener(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6",
        "https://purpose.example.test/eligibility",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token.clone()))
        .await;
    response.assert_status_ok();
    let claims = verified_federation_response_claims(&response.text());
    assert_eq!(claims["iss"], json!("https://agency-a.example.gov"));
    assert_eq!(claims["sub"], json!("did:web:agency-a.example.gov"));
    assert_eq!(claims["aud"], json!("did:web:agency-b.example.gov"));
    assert_eq!(
        claims["result"]["subject_ref"]["id_type"],
        json!("national_id")
    );
    assert!(claims["result"]["subject_ref"]["hash"]
        .as_str()
        .expect("subject hash is string")
        .starts_with("hmac-sha256:"));
    assert_eq!(
        claims["result"]["claims"]["farmer-under-4ha"]["disclosure"],
        json!("redacted")
    );
    assert!(claims["result"]["claims"]["farmer-under-4ha"]["satisfied"].is_null());
    assert!(claims["result"]["evaluation_id"]
        .as_str()
        .expect("evaluation id is string")
        .starts_with("eval_"));

    let replay = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;
    replay.assert_status(StatusCode::CONFLICT);

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let records = audit_records(&audit_path);
    let allowed = records
        .iter()
        .find(|record| record["decision"] == json!("federated_evaluate"))
        .expect("allowed federation audit record exists");
    assert_eq!(
        allowed["federation_issuer"],
        json!("https://agency-b.example.gov")
    );
    assert_eq!(allowed["federation_profile"], json!("farmer_under_4ha"));
    assert_eq!(
        allowed["scopes_used"],
        json!(["farmer_registry:evidence_verification"])
    );
    assert_eq!(
        allowed["federation_purpose"],
        json!("https://purpose.example.test/eligibility")
    );
    assert!(allowed.get("federation_request_jti").is_none());
    assert!(allowed["federation_request_jti_hash"]
        .as_str()
        .expect("request jti hash is string")
        .starts_with("hmac-sha256:"));
    assert!(allowed["federation_subject_ref_hash"]
        .as_str()
        .expect("subject ref hash is string")
        .starts_with("hmac-sha256:"));
    assert!(allowed["federation_peer_id_hash"]
        .as_str()
        .expect("peer id hash is string")
        .starts_with("hmac-sha256:"));
    assert!(records
        .iter()
        .any(|record| record["decision"] == json!("federated_evaluate_denied")));
    let replay_denied = audit_record_with(
        &records,
        "/federation/v1/evaluations",
        "federated_evaluate_denied",
        StatusCode::CONFLICT,
        "federation.replay",
    );
    assert_verified_federation_audit_context(
        replay_denied,
        "farmer_under_4ha",
        "https://purpose.example.test/eligibility",
        true,
    );
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6"));
    assert!(!audit.contains("source-token"));

    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains(
        "registry_notary_replay_events_total{flow=\"federation_request\",outcome=\"accepted\"} 1"
    ));
    assert!(metrics_body.contains(
        "registry_notary_replay_events_total{flow=\"federation_request\",outcome=\"replayed\"} 1"
    ));
    assert!(!metrics_body.contains("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6"));
    assert!(!metrics_body.contains("person-1"));
    assert!(!metrics_body.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_policy_context_satisfies_governed_source_matching() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    add_governed_federation_policy_context(&mut config, "ZZ");
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6G0V1",
        "https://purpose.example.test/eligibility",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status_ok();
    let claims = verified_federation_response_claims(&response.text());
    assert_eq!(
        claims["result"]["claims"]["farmer-under-4ha"]["disclosure"],
        json!("predicate")
    );
    assert_eq!(
        claims["result"]["claims"]["farmer-under-4ha"]["satisfied"],
        json!(true)
    );
    let records = audit_records(&audit_path);
    assert!(records
        .iter()
        .any(|record| record["decision"] == json!("federated_evaluate")));

    let denied_peer_jwks = MockHttpUpstream::start().await;
    let (denied_peer_private, _) = fixtures::ed25519_pair();
    denied_peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&denied_peer_private))
        .await;
    let denied_audit_path = tmp.path().join("denied-audit.jsonl");
    let mut denied_config = federation_config(
        base_url.trim_end_matches('/'),
        denied_audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", denied_peer_jwks.url()),
    );
    add_governed_federation_policy_context(&mut denied_config, "XY");
    let denied_app = standalone_router(denied_config).expect("standalone router builds");
    let denied_server = TestServer::builder().http_transport().build(denied_app);
    let denied_token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6G0W1",
        "https://purpose.example.test/eligibility",
    );

    let denied = denied_server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(denied_token))
        .await;

    denied.assert_status(StatusCode::FORBIDDEN);
    let body: Value = denied.json();
    assert_eq!(body["code"], json!("pdp.jurisdiction_not_permitted"));
    let denied_records = audit_records(&denied_audit_path);
    let denied_audit = audit_record_with(
        &denied_records,
        "/federation/v1/evaluations",
        "federated_evaluate_denied",
        StatusCode::FORBIDDEN,
        "pdp.jurisdiction_not_permitted",
    );
    assert_verified_federation_audit_context(
        denied_audit,
        "farmer_under_4ha",
        "https://purpose.example.test/eligibility",
        true,
    );
    assert_audit_records_do_not_contain(
        &denied_records,
        &["person-1", "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6G0W1"],
    );
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_auth_exempt_route_still_requires_valid_jws() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from_static(b"not.a.valid-jws"))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("federation.invalid_token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_two_standalone_notaries_smoke() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let agency_b_jwks = MockHttpUpstream::start().await;
    let (agency_b_private, _) = fixtures::ed25519_pair();
    agency_b_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&agency_b_private))
        .await;
    let agency_a_jwks = MockHttpUpstream::start().await;
    let (agency_a_private, _) = fixtures::ed25519_pair();
    agency_a_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&agency_a_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let agency_a_audit = tmp.path().join("agency-a-audit.jsonl");
    let agency_b_audit = tmp.path().join("agency-b-audit.jsonl");
    let agency_a = TestServer::builder().http_transport().build(
        standalone_router(federation_config_for(
            base_url.trim_end_matches('/'),
            agency_a_audit.to_str().expect("audit path is UTF-8"),
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
            "did:web:agency-b.example.gov",
            "https://agency-b.example.gov",
            &format!("{}/jwks", agency_b_jwks.url()),
        ))
        .expect("agency A standalone router builds"),
    );
    let agency_b = TestServer::builder().http_transport().build(
        standalone_router(federation_config_for(
            base_url.trim_end_matches('/'),
            agency_b_audit.to_str().expect("audit path is UTF-8"),
            "did:web:agency-b.example.gov",
            "https://agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
            &format!("{}/jwks", agency_a_jwks.url()),
        ))
        .expect("agency B standalone router builds"),
    );
    agency_b.get("/healthz").await.assert_status_ok();

    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6S0",
        "https://purpose.example.test/eligibility",
    );
    let response = agency_a
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status_ok();
    let claims = verified_federation_response_claims(&response.text());
    assert_eq!(claims["iss"], json!("https://agency-a.example.gov"));
    assert_eq!(claims["aud"], json!("did:web:agency-b.example.gov"));
    assert_eq!(
        claims["result"]["claims"]["farmer-under-4ha"]["disclosure"],
        json!("redacted")
    );
    assert!(claims["result"]["claims"]["farmer-under-4ha"]["satisfied"].is_null());
    let records = audit_records(&agency_a_audit);
    assert!(records
        .iter()
        .any(|record| record["decision"] == json!("federated_evaluate")));
}

#[tokio::test]
async fn federation_denial_happens_before_source_read() {
    set_federation_env();
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(move || {
                let source_hits = Arc::clone(&source_hits_for_route);
                async move {
                    source_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q7",
        "https://purpose.example.test/not-allowed",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let records = audit_records(&audit_path);
    let denied = audit_record_with(
        &records,
        "/federation/v1/evaluations",
        "federated_evaluate_denied",
        StatusCode::FORBIDDEN,
        "federation.forbidden",
    );
    assert_verified_federation_audit_context(
        denied,
        "farmer_under_4ha",
        "https://purpose.example.test/not-allowed",
        true,
    );
    assert_audit_records_do_not_contain(&records, &["person-1", "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q7"]);

    let unsupported_media_type = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/json")
        .bytes(Bytes::from("{}"))
        .await;
    unsupported_media_type.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let oversized_body = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(vec![b'a'; 16 * 1024 + 1]))
        .await;
    oversized_body.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let bad_audience = federation_request_jwt_with_audience(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q1",
        "did:web:other-agency.example.gov",
    );
    let bad_audience_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(bad_audience))
        .await;
    bad_audience_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let expired = federation_request_jwt_with_times(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q2",
        now - 600,
        now - 600,
        now - 300,
    );
    let expired_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(expired))
        .await;
    expired_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let future_nbf =
        federation_request_jwt_with_times("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q3", now, now + 600, now + 900);
    let future_nbf_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(future_nbf))
        .await;
    future_nbf_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let long_lived =
        federation_request_jwt_with_times("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q4", now, now, now + 301);
    let long_lived_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(long_lived))
        .await;
    long_lived_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let bad_subject = federation_request_jwt_with_subject(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q5",
        "did:web:other-peer.example.gov",
    );
    let bad_subject_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(bad_subject))
        .await;
    bad_subject_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let unknown_kid = federation_request_jwt_with_kid("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q6", "unknown-key");
    let unknown_kid_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(unknown_kid))
        .await;
    unknown_kid_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let records = audit_records(&audit_path);
    let unknown_key_audit = records.last().expect("unknown-key audit record exists");
    assert_eq!(
        unknown_key_audit["error_code"],
        json!("federation.invalid_token")
    );
    assert_federation_request_context_is_absent(unknown_key_audit);
    assert!(!audit_record_contains_text(
        unknown_key_audit,
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q6"
    ));
    assert!(!audit_record_contains_text(unknown_key_audit, "person-1"));

    let audit_count_before_bad_signature = records.len();
    let bad_signature = tamper_jwt_signature(&federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q7",
        "https://purpose.example.test/eligibility",
    ));
    let bad_signature_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(bad_signature))
        .await;
    bad_signature_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let records = audit_records(&audit_path);
    assert_eq!(records.len(), audit_count_before_bad_signature + 1);
    let bad_signature_audit = &records[audit_count_before_bad_signature];
    assert_eq!(
        bad_signature_audit["error_code"],
        json!("federation.invalid_token")
    );
    assert_federation_request_context_is_absent(bad_signature_audit);
    assert!(!audit_record_contains_text(
        bad_signature_audit,
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q7"
    ));
    assert!(!audit_record_contains_text(bad_signature_audit, "person-1"));

    let bad_alg = federation_jwt_with_header(
        json!({
            "alg": "HS256",
            "typ": FEDERATION_REQUEST_JWT_TYPE,
            "kid": "registry-platform-testing-ed25519-1"
        }),
        federation_request_payload("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q8"),
    );
    let bad_alg_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(bad_alg))
        .await;
    bad_alg_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let bad_typ = federation_jwt_with_header(
        json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "registry-platform-testing-ed25519-1"
        }),
        federation_request_payload("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q9"),
    );
    let bad_typ_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(bad_typ))
        .await;
    bad_typ_response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn federation_emergency_kid_denylist_blocks_before_source_read() {
    assert_federation_emergency_denylist_blocks_before_source_read(true).await;
}

#[tokio::test]
async fn federation_emergency_node_id_denylist_blocks_before_source_read() {
    assert_federation_emergency_denylist_blocks_before_source_read(false).await;
}

async fn assert_federation_emergency_denylist_blocks_before_source_read(deny_kid: bool) {
    set_federation_env();
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(move || {
                let source_hits = Arc::clone(&source_hits_for_route);
                async move {
                    source_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    if deny_kid {
        config
            .federation
            .emergency_denylist
            .kids
            .push("registry-platform-testing-ed25519-1".to_string());
    } else {
        config
            .federation
            .emergency_denylist
            .node_ids
            .push("did:web:agency-b.example.gov".to_string());
    }
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let request_jti = if deny_kid {
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7R0"
    } else {
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7R1"
    };
    let token = federation_request_jwt(request_jti, "https://purpose.example.test/eligibility");

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let records = audit_records(&audit_path);
    let denied = audit_record_with(
        &records,
        "/federation/v1/evaluations",
        "federated_evaluate_denied",
        StatusCode::FORBIDDEN,
        "federation.forbidden",
    );
    assert_federation_request_context_is_absent(denied);
    assert_audit_records_do_not_contain(&records, &["person-1", request_jti]);
}

#[tokio::test]
async fn federation_request_claims_must_match_profile_before_source_read() {
    set_federation_env();
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(move || {
                let source_hits = Arc::clone(&source_hits_for_route);
                async move {
                    source_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt_with_claims(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q9",
        "https://purpose.example.test/eligibility",
        json!(["farmed-land-size"]),
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let records = audit_records(&audit_path);
    let denied = audit_record_with(
        &records,
        "/federation/v1/evaluations",
        "federated_evaluate_denied",
        StatusCode::FORBIDDEN,
        "federation.forbidden",
    );
    assert_verified_federation_audit_context(
        denied,
        "farmer_under_4ha",
        "https://purpose.example.test/eligibility",
        true,
    );
    assert!(denied["claim_hash"].is_string());
    assert_audit_records_do_not_contain(&records, &["person-1", "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q9"]);
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_stale_source_observation_returns_signed_evaluation_error() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    config.cel.eval_timeout_ms = 10_000;
    config.federation.evaluation_profiles[0].max_source_observed_age_seconds = Some(0);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q8",
        "https://purpose.example.test/eligibility",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status_ok();
    let claims = verified_federation_response_claims(&response.text());
    assert_eq!(
        claims["error"]["type"],
        json!("urn:registry-notary:problem:federation:stale-source-observation")
    );
    assert!(claims.get("result").is_none());
    let records = audit_records(&audit_path);
    let error = records
        .iter()
        .find(|record| record["decision"] == json!("federated_evaluate_error"))
        .expect("stale-source audit record exists");
    assert_eq!(
        error["error_code"],
        json!("federation.stale_source_observation")
    );
    assert!(error["federation_subject_ref_hash"]
        .as_str()
        .expect("subject ref hash is string")
        .starts_with("hmac-sha256:"));
    assert_verified_federation_audit_context(
        error,
        "farmer_under_4ha",
        "https://purpose.example.test/eligibility",
        true,
    );
    assert_audit_records_do_not_contain(&records, &["person-1", "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q8"]);
}

#[tokio::test]
async fn federation_audit_write_failure_replaces_signed_success() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    // Make the audit target itself a directory: the single-writer sink still
    // constructs (its `.lock` sentinel is a sibling in the real tmp dir), but
    // every audit WRITE fails, which is exactly what this test exercises (#211).
    let audit_path = tmp.path().join("audit.jsonl");
    std::fs::create_dir(&audit_path).expect("audit target is a directory");
    let app = standalone_router(federation_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q0",
        "https://purpose.example.test/eligibility",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("audit.write_failed"));
}

#[tokio::test]
async fn admin_reload_401_unauth_403_wrong_scope_501_admin() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH",
        "sha256:ac3dced2bcf7d2cb4166747790d67437b5cc5314ed33e01d06b274a7fe0c3b3c",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "wrong-scope".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH"),
        scopes: vec!["farmer_registry:evidence_verification".to_string()],
        authorization_details: None,
    });
    add_admin_api_key(&mut config);
    enable_shared_admin_listener(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let unauthenticated = server.post("/admin/v1/reload").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);

    let wrong_scope = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "wrong-scope-token")
        .await;
    wrong_scope.assert_status(StatusCode::FORBIDDEN);

    let admin = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await;
    admin.assert_status(StatusCode::NOT_IMPLEMENTED);
    let admin_body: Value = admin.json();
    assert_eq!(admin_body["schema"], json!("registry.admin.error.v1"));
    assert_eq!(
        admin_body["code"],
        json!("registry.admin.capability.not_supported")
    );
    assert_eq!(admin_body["capability"], json!("reload.config_reload"));
}

#[test]
fn admin_reload_openapi_says_runtime_config_reload_is_not_supported() {
    let document = serde_json::to_value(openapi_document()).expect("OpenAPI serializes");
    let operation = &document["paths"]["/admin/v1/reload"]["post"];
    let rendered = serde_json::to_string(operation).expect("operation serializes");

    assert!(rendered.contains("unsupported"));
    assert!(rendered.contains("does not support runtime configuration reload"));
    assert!(operation["responses"].get("501").is_some());
    assert!(operation["responses"].get("200").is_none());
    assert!(!rendered.contains("Request a standalone config reload"));

    let capabilities = &document["paths"]["/admin/v1/capabilities"]["get"];
    assert_eq!(
        capabilities["responses"]["403"]["description"],
        "Caller lacks registry_notary:ops_read scope"
    );

    assert!(
        document["paths"].get("/admin/v1/config/verify").is_none(),
        "admin config verify route is removed"
    );
    assert!(
        document["paths"].get("/admin/v1/config/dry-run").is_none(),
        "admin config dry-run route is removed"
    );
    assert!(
        document["paths"].get("/admin/v1/config/apply").is_none(),
        "admin config apply route is removed"
    );
}

#[tokio::test]
async fn admin_posture_requires_ops_read_not_admin_and_ops_cannot_reload() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_admin_api_key(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/admin/v1/posture")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let unsupported_reload = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await;
    unsupported_reload.assert_status(StatusCode::NOT_IMPLEMENTED);
    let unsupported_reload_body: Value = unsupported_reload.json();
    assert_eq!(
        unsupported_reload_body["code"],
        json!("registry.admin.capability.not_supported")
    );
    server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "ops-token")
        .json(&json!({ "status": "revoked" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["schema"], json!("registry.ops.posture.v1"));
    assert_eq!(body["component"], json!("registry-notary"));
    assert_eq!(body["instance"]["id"], json!("registry-notary-standalone"));
    assert_eq!(body["instance"]["environment"], json!("development"));
    assert_eq!(body["build"]["package"], json!("registry-notary"));
    assert_eq!(body["build"]["version"], json!(env!("CARGO_PKG_VERSION")));
    assert!(body["build"].get("git_sha").is_none());
    assert!(body["build"].get("features").is_none());
}

#[tokio::test]
async fn admin_capabilities_requires_ops_read_and_reports_notary_surface() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    add_admin_api_key(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/admin/v1/capabilities")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let response = server
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .header("cache-control")
            .to_str()
            .expect("cache-control is ASCII"),
        "no-store"
    );
    let body: Value = response.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(body["schema"], json!("registry.admin.capabilities.v1"));
    assert_eq!(body["product"], json!("registry-notary"));
    assert_eq!(
        body["supported_posture_tiers"],
        json!(["default", "restricted"])
    );
    assert_eq!(body.get("scopes"), None);
    assert_eq!(
        body["config"]["verify"],
        json!({
            "supported": false,
            "currently_available": false
        })
    );
    assert_eq!(
        body["config"]["dry_run"],
        json!({
            "supported": false,
            "currently_available": false
        })
    );
    assert_eq!(
        body["config"]["apply"],
        json!({
            "supported": false,
            "currently_available": false,
            "requires_signed_input": true,
            "supported_sources": []
        })
    );
    assert_eq!(
        body["break_glass"],
        json!({
            "supported": false,
            "currently_available": false,
            "rate_limit_scope": "none"
        })
    );
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "shared_with_public",
                "public_admin_routes": true
            },
            "metrics": {
                "mode": "shared_with_public",
                "requires_admin_scope": false,
                "required_scope": "registry_notary:metrics_read"
            }
        })
    );
    assert!(!serde_json::to_string(&body["listeners"])
        .expect("listeners serialize")
        .contains("127.0.0.1"));
    assert_eq!(body["root_transition"]["supported"], json!(false));
    assert_eq!(
        body["hot_swap"],
        json!({
            "supported": false,
            "currently_available": false,
            "components": []
        })
    );
    assert_eq!(body["reload"]["resource_reload"]["supported"], json!(false));
    assert_eq!(body["reload"]["table_reload"]["supported"], json!(false));
    assert_eq!(body["reload"]["config_reload"]["supported"], json!(false));
}

#[tokio::test]
async fn dedicated_topology_splits_admin_routes_and_reports_capabilities() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    add_ops_read_api_key(&mut config);

    let routers = notary_routers_from_runtime(
        compile_notary_runtime(config).expect("runtime compiles for dedicated topology"),
    );
    let public = TestServer::builder().http_transport().build(routers.public);
    let admin = TestServer::builder().http_transport().build(routers.admin);

    public.get("/healthz").await.assert_status_ok();
    public
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    public
        .get("/metrics")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    let response = admin
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "dedicated",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "admin",
                "requires_admin_scope": false,
                "required_scope": "registry_notary:metrics_read"
            }
        })
    );
    assert!(!serde_json::to_string(&body["listeners"])
        .expect("listeners serialize")
        .contains("127.0.0.1"));
}

#[tokio::test]
async fn governed_config_rejects_shared_admin_listener_topology() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.config_trust = Some(ConfigTrustConfig {
        trust_anchor_path: tmp.path().join("config-anchor.json"),
        bundle_path: tmp.path().join("config-bundle"),
        antirollback_state_path: tmp.path().join("config-antirollback.json"),
        break_glass_override_path: None,
    });

    let error = match compile_notary_runtime(config) {
        Ok(_) => panic!("shared governed topology is rejected"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("server.admin_listener.mode = dedicated"),
        "unexpected error: {message}"
    );
}

#[test]
fn governed_config_docs_do_not_ship_unresolved_config_trust_placeholders() {
    let doc = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/notary/docs/operator-config-reference.md"),
    )
    .expect("operator config reference reads");

    assert!(
        doc.contains("syntactically valid but illustrative"),
        "governed config example must be explicitly labeled as illustrative"
    );
    assert!(
        !doc.contains("REPLACE_WITH_FINAL"),
        "governed config example must not contain replacement placeholders"
    );
    assert!(
        !doc.contains("TUF_TARGETS_ROLE_KEY_ID"),
        "governed config example must not mention retired TUF key placeholders"
    );
}

#[tokio::test]
async fn admin_posture_rejects_unknown_tier_with_shared_error_code() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/admin/v1/posture?tier=complete")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["schema"], json!("registry.admin.error.v1"));
    assert_eq!(body["code"], json!("registry.admin.posture.invalid_tier"));
    assert_eq!(
        body["detail"],
        json!("posture tier must be default or restricted")
    );
}

#[tokio::test]
async fn admin_posture_reports_configured_instance_override() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.instance.id = "notary-prod-a".to_string();
    config.instance.environment = "production".to_string();
    config.instance.owner = Some("trust-ops".to_string());
    config.instance.jurisdiction = Some("TH".to_string());
    config.instance.public_base_url = Some("https://notary.example.test".to_string());
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["instance"]["id"], json!("notary-prod-a"));
    assert_eq!(body["instance"]["environment"], json!("production"));
    assert_eq!(body["instance"]["owner"], json!("trust-ops"));
    assert_eq!(body["instance"]["jurisdiction"], json!("TH"));
    assert!(body["instance"].get("public_base_url").is_none());
}

#[tokio::test]
async fn admin_posture_top_level_keys_match_documented_example() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let default_posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    default_posture.assert_status_ok();
    let default_body: Value = default_posture.json();
    assert_matches_posture_schema(&default_body);

    let default_live_keys = default_body
        .as_object()
        .expect("posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let default_example: Value =
        serde_json::from_str(registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1)
            .expect("notary posture example parses");
    assert_standards_artifacts_omit_sha256(&default_body, "live default posture");
    assert_standards_artifacts_omit_sha256(&default_example, "NOTARY_POSTURE_EXAMPLE_V1");
    let default_example_keys = default_example
        .as_object()
        .expect("example posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        default_example_keys, default_live_keys,
        "NOTARY_POSTURE_EXAMPLE_V1 top-level keys drifted from the live default-tier posture document \
         (missing from example: {:?}, extra in example: {:?})",
        default_live_keys.difference(&default_example_keys).collect::<Vec<_>>(),
        default_example_keys.difference(&default_live_keys).collect::<Vec<_>>(),
    );

    let restricted_posture = server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", "ops-token")
        .await;
    restricted_posture.assert_status_ok();
    let restricted_body: Value = restricted_posture.json();
    assert_matches_posture_schema(&restricted_body);

    let restricted_live_keys = restricted_body
        .as_object()
        .expect("posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let restricted_fixture: Value =
        serde_json::from_str(registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1)
            .expect("restricted posture fixture parses");
    let restricted_fixture_keys = restricted_fixture
        .as_object()
        .expect("restricted fixture posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        restricted_fixture_keys, restricted_live_keys,
        "RESTRICTED_POSTURE_FIXTURE_V1 top-level keys drifted from the live restricted-tier posture document \
         (missing from fixture: {:?}, extra in fixture: {:?})",
        restricted_live_keys.difference(&restricted_fixture_keys).collect::<Vec<_>>(),
        restricted_fixture_keys.difference(&restricted_live_keys).collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn admin_posture_reports_self_attestation_summary_and_redacts_signing_key_ids() {
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let issuer = MockIdp::start().await;
    let issuer_url = issuer.issuer();
    let jwks_uri = issuer.jwks_uri();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &issuer_url,
        &jwks_uri,
    );
    enable_shared_admin_listener(&mut config);
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .scope_map
        .insert(
            "ops_read".to_string(),
            vec!["registry_notary:ops_read".to_string()],
        );
    let ops_token = issuer.mint_token(json!({
        "sub": "trust-ops",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "ops_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("authorization", format!("Bearer {ops_token}"))
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["self_attestation"]["enabled"], json!(true));
    assert_eq!(
        body["notary"]["self_attestation"]["allowed_claim_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["allowed_purpose_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["credential_profile_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["wallet_origin_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["rate_limit_mode"],
        json!("in_process")
    );
    assert!(body["notary"].get("signing_keys").is_none());

    let rendered = serde_json::to_string(&body).expect("posture serializes");
    assert!(!rendered.contains("issuer-key"));
    assert!(!rendered.contains("did:web:issuer.example#key-1"));
}

#[tokio::test]
async fn admin_posture_reports_oid4vci_bearer_offer_mode() {
    set_preauth_env();
    let issuer = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &issuer.issuer(),
        &issuer.jwks_uri(),
        &format!("{}/authorize", issuer.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    enable_shared_admin_listener(&mut config);
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .scope_map
        .insert(
            "ops_read".to_string(),
            vec!["registry_notary:ops_read".to_string()],
        );
    let ops_token = issuer.mint_token(json!({
        "sub": "trust-ops",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "ops_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("authorization", format!("Bearer {ops_token}"))
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert!(body["posture"]["warnings"]
        .as_array()
        .expect("warnings is an array")
        .iter()
        .any(|warning| warning == "notary.oid4vci.bearer_offer"));
    let finding = body["posture"]["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .find(|finding| finding["id"] == "notary.oid4vci.bearer_offer")
        .expect("bearer-offer finding is reported");
    assert!(finding["evidence"]
        .as_array()
        .expect("finding evidence is an array")
        .iter()
        .any(|entry| entry["value"] == json!("bearer_offer")));

    issuer.stop().await;
}

#[tokio::test]
async fn admin_posture_redacts_runtime_config_secrets_and_private_topology() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "very-secret-source-token");
    std::env::set_var("TEST_UNUSED_SOURCE_TOKEN", "unused-secret-source-token");
    std::env::set_var("TEST_POSTURE_PRIVATE_JWK", TEST_ISSUER_JWK);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1/private-source?token=source-url-secret",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    let mut unused_connection = config.evidence.source_connections["farmer_registry"].clone();
    unused_connection.base_url =
        "http://10.24.0.9/internal/source-adapter?token=unused-url-secret".to_string();
    unused_connection.token_env = "TEST_UNUSED_SOURCE_TOKEN".to_string();
    unused_connection.bulk_mode = BulkMode::SourceAdapterSidecarBatch;
    config.evidence.source_connections.insert(
        "private_unused_source_adapter".to_string(),
        unused_connection,
    );
    config.evidence.signing_keys.insert(
        "issuer".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: SD_JWT_VC_SIGNING_ALG.to_string(),
            kid: "did:web:evidence.example.test#issuer".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "TEST_POSTURE_PRIVATE_JWK".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists");
    claim
        .source_bindings
        .get_mut("farmer")
        .expect("farmer source binding exists")
        .matching
        .policy_id = Some("civil-id-policy-1234567890123".to_string());
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let text = posture.text();

    assert!(!text.contains("very-secret-source-token"));
    assert!(!text.contains("unused-secret-source-token"));
    assert!(!text.contains("source-url-secret"));
    assert!(!text.contains("unused-url-secret"));
    assert!(!text.contains("http://127.0.0.1:1/private-source"));
    assert!(!text.contains("http://10.24.0.9/internal/source-adapter"));
    assert!(!text.contains("TEST_EVIDENCE_SOURCE_TOKEN"));
    assert!(!text.contains("TEST_UNUSED_SOURCE_TOKEN"));
    assert!(!text.contains("TEST_EVIDENCE_API_KEY_HASH"));
    assert!(!text.contains("TEST_POSTURE_PRIVATE_JWK"));
    assert!(
        !text.contains("sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51")
    );
    assert!(!text.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    assert!(!text.contains("private_jwk"));
    assert!(!text.contains("\"d\""));
    assert!(!text.contains("token_env"));
    assert!(!text.contains("civil-id-policy-1234567890123"));
    assert!(!text.contains("disclosure"));
    assert!(!text.contains("predicate"));
    // The disclosure config must not leak. `audit.redaction_mode: "redacted"` is
    // a legitimate posture vocabulary value, so guard against the disclosure
    // list shape rather than the bare word.
    assert!(!text.contains("[value, redacted]"));
    assert!(!text.contains("\"value\",\"redacted\""));
}

#[tokio::test]
async fn admin_posture_hash_ignores_secret_only_config_changes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_ROTATED_SOURCE_TOKEN", "rotated-source-token");

    let tmp = TempDir::new().expect("tempdir");
    let first_audit_path = tmp.path().join("first-audit.jsonl");
    let second_audit_path = tmp.path().join("second-audit.jsonl");
    let mut first = registry_data_api_config(
        "http://127.0.0.1:1",
        first_audit_path.to_str().expect("audit path is UTF-8"),
    );
    let mut second = registry_data_api_config(
        "http://127.0.0.1:1",
        second_audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut first);
    enable_shared_admin_listener(&mut second);
    first
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_ROTATED_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .base_url = "http://127.0.0.1:2/private-source".to_string();
    add_ops_read_api_key(&mut first);
    add_ops_read_api_key(&mut second);
    let first_internal_hash = internal_config_hash(
        serde_json::to_string(&first)
            .expect("config serializes")
            .as_bytes(),
    );

    let first_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(first).expect("first router builds"));
    let second_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(second).expect("second router builds"));

    let first_posture = first_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    first_posture.assert_status_ok();
    let second_posture = second_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    second_posture.assert_status_ok();
    let first_body: Value = first_posture.json();
    let second_body: Value = second_posture.json();
    assert_matches_posture_schema(&first_body);
    assert_matches_posture_schema(&second_body);

    assert_eq!(
        first_body["configuration"]["last_config_hash"],
        second_body["configuration"]["last_config_hash"]
    );
    assert_ne!(
        first_body["configuration"]["last_config_hash"],
        json!(first_internal_hash)
    );
}

#[tokio::test]
async fn admin_posture_hash_tracks_public_instance_config_changes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let first_audit_path = tmp.path().join("first-audit.jsonl");
    let second_audit_path = tmp.path().join("second-audit.jsonl");
    let mut first = registry_data_api_config(
        "http://127.0.0.1:1",
        first_audit_path.to_str().expect("audit path is UTF-8"),
    );
    let mut second = registry_data_api_config(
        "http://127.0.0.1:1",
        second_audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut first);
    enable_shared_admin_listener(&mut second);
    first.instance.owner = Some("operations".to_string());
    second.instance.owner = Some("data-office".to_string());
    first
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    add_ops_read_api_key(&mut first);
    add_ops_read_api_key(&mut second);

    let first_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(first).expect("first router builds"));
    let second_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(second).expect("second router builds"));

    let first_posture = first_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    first_posture.assert_status_ok();
    let second_posture = second_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    second_posture.assert_status_ok();
    let first_body: Value = first_posture.json();
    let second_body: Value = second_posture.json();

    assert_ne!(
        first_body["configuration"]["last_config_hash"],
        second_body["configuration"]["last_config_hash"]
    );
}

#[tokio::test]
async fn admin_posture_counts_configured_but_unused_source_connections_by_safe_kind() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_UNUSED_DCI_SOURCE_TOKEN", "unused-dci-source-token");
    std::env::set_var(
        "TEST_UNUSED_GENERIC_SOURCE_TOKEN",
        "unused-generic-source-token",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    let mut unused_dci = config.evidence.source_connections["farmer_registry"].clone();
    unused_dci.base_url = "http://127.0.0.1:2/private-dci".to_string();
    unused_dci.token_env = "TEST_UNUSED_DCI_SOURCE_TOKEN".to_string();
    unused_dci.bulk_mode = BulkMode::DciBatchedSearch;
    config
        .evidence
        .source_connections
        .insert("unused_dci".to_string(), unused_dci);
    let mut unused_generic = config.evidence.source_connections["farmer_registry"].clone();
    unused_generic.base_url = "http://127.0.0.1:3/private-generic".to_string();
    unused_generic.token_env = "TEST_UNUSED_GENERIC_SOURCE_TOKEN".to_string();
    config
        .evidence
        .source_connections
        .insert("unused_generic".to_string(), unused_generic);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(
        body["notary"]["source_connection_counts"]["registry_data_api"],
        json!(1)
    );
    assert_eq!(body["notary"]["source_connection_counts"]["dci"], json!(1));
    assert_eq!(
        body["notary"]["source_connection_counts"]["unknown"],
        json!(1)
    );
}

#[tokio::test]
async fn admin_posture_classifies_replay_storage() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL", "redis://127.0.0.1:6379/0");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.replay.storage = "redis".to_string();
    config.replay.redis.url_env = "TEST_REPLAY_REDIS_URL".to_string();
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["replay"]["storage"], json!("redis"));
}

#[tokio::test]
async fn admin_posture_warns_for_production_like_in_memory_replay() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.instance.environment = "production".to_string();
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(
        body["posture"]["warnings"][0],
        json!("notary.replay.in_memory.production")
    );
    assert_eq!(
        body["posture"]["findings"][0]["id"],
        json!("notary.replay.in_memory.production")
    );
    assert_eq!(body["runtime"]["readiness"], json!("degraded"));
}

#[tokio::test]
async fn admin_posture_federation_summary_omits_peer_private_data() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks/private", peer_jwks.url()),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["federation"]["enabled"], json!(true));
    assert!(body["notary"]["federation"].get("node_id").is_none());
    assert_eq!(body["notary"]["federation"]["peer_count"], json!(1));
    assert!(body["notary"]["federation"].get("peers").is_none());

    let text = serde_json::to_string(&body).expect("posture serializes");
    assert!(!text.contains("agency-b.example.gov"));
    assert!(!text.contains("/jwks/private"));
}

#[tokio::test]
async fn metrics_requires_metrics_scope_and_keeps_health_public() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let health = server.get("/healthz").await;
    health.assert_status_ok();

    let unauthenticated = server.get("/metrics").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);
    assert!(!unauthenticated
        .text()
        .contains("registry_notary_http_requests_total"));

    let non_metrics = server
        .get("/metrics")
        .add_header("x-api-key", "api-token")
        .await;
    non_metrics.assert_status(StatusCode::FORBIDDEN);
    assert!(!non_metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    let admin = server
        .get("/metrics")
        .add_header("x-api-key", "admin-token")
        .await;
    admin.assert_status(StatusCode::FORBIDDEN);
    assert!(!admin.text().contains("registry_notary_http_requests_total"));

    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let content_type = metrics
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("text/plain; version=0.0.4"));
    assert!(metrics
        .text()
        .contains("registry_notary_http_requests_total"));
}

#[tokio::test]
async fn oidc_mode_verifies_token_from_fixture_idp() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.bearer_tokens.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: idp.issuer(),
        jwks_url: idp.jwks_uri(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: true,
    });
    let token = idp.mint_token(json!({
        "sub": "caseworker",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "farmer_registry:evidence_verification",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let denied = server.get("/v1/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let response = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["data"][0]["id"], json!("farmed-land-size"));

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let id_token_typ = sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        "id_token",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": idp.issuer(),
            "sub": "caseworker",
            "aud": "registry-notary",
            "azp": "registry-client",
            "scope": "farmer_registry:evidence_verification",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        }),
    );
    let wrong_typ = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {id_token_typ}"))
        .await;
    wrong_typ.assert_status(StatusCode::UNAUTHORIZED);

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    let claims_audit = envelopes
        .iter()
        .map(|envelope| &envelope.record)
        .find(|record| record["path"] == json!("/v1/claims") && record["status"] == json!(200))
        .expect("claims audit record exists");
    assert_eq!(
        claims_audit["scopes_used"],
        json!(["farmer_registry:evidence_verification"])
    );
    assert!(!audit.contains(&token));

    idp.stop().await;
}

#[tokio::test]
async fn oidc_metrics_scope_can_scrape_metrics_but_non_metrics_cannot() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.bearer_tokens.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: idp.issuer(),
        jwks_url: idp.jwks_uri(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: [(
            "metrics_read".to_string(),
            vec!["registry_notary:metrics_read".to_string()],
        )]
        .into_iter()
        .collect(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: true,
    });
    let non_admin_token = idp.mint_token(json!({
        "sub": "caseworker",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "farmer_registry:evidence_verification",
    }));
    let metrics_token = idp.mint_token(json!({
        "sub": "metrics-reader",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "metrics_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let non_metrics = server
        .get("/metrics")
        .add_header("authorization", format!("Bearer {non_admin_token}"))
        .await;
    non_metrics.assert_status(StatusCode::FORBIDDEN);
    assert!(!non_metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    let metrics = server
        .get("/metrics")
        .add_header("authorization", format!("Bearer {metrics_token}"))
        .await;
    metrics.assert_status_ok();
    assert!(metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    idp.stop().await;
}

#[tokio::test]
async fn jwks_is_public_and_contains_no_private_members() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let jwks = server.get("/.well-known/evidence/jwks.json").await;

    jwks.assert_status_ok();
    let jwks_body: Value = jwks.json();
    let keys = jwks_body["keys"].as_array().expect("JWKS keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], json!("did:web:issuer.example#key-1"));
    assert!(keys[0].get("d").is_none());

    idp.stop().await;
}

#[tokio::test]
async fn oidc_self_attestation_evaluates_renders_and_audits_access_mode() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let jwks = server.get("/.well-known/evidence/jwks.json").await;
    jwks.assert_status_ok();
    let jwks_body: Value = jwks.json();
    assert_eq!(jwks_body["keys"].as_array().expect("JWKS keys").len(), 1);
    assert_eq!(
        jwks_body["keys"][0]["kid"],
        json!("did:web:issuer.example#key-1")
    );
    assert!(jwks_body["keys"][0].get("d").is_none());

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    assert_eq!(evaluate_body["results"][0]["value"], json!(true));
    // Self-attestation flows produce results under the canonical evaluation
    // policy, so generated_by carries the policy triple.
    let generated_by = &evaluate_body["results"][0]["provenance"]["generated_by"];
    assert_eq!(generated_by["policy_id"], json!("self-attestation"));
    assert!(
        generated_by["policy_hash"]
            .as_str()
            .expect("self-attestation provenance carries policy_hash")
            .starts_with("sha256:"),
        "policy_hash must use the sha256:<hex> prefixed format"
    );
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();

    let render = server
        .post(&format!("/v1/evaluations/{evaluation_id}/render"))
        .add_header("authorization", authorization)
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    render.assert_status_ok();
    let render_body: Value = render.json();
    assert_eq!(render_body["results"][0]["value"], json!(true));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains(&token));
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("citizen-subject"));
    assert!(!audit.contains("source-token"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let evaluate_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations")
                && record["decision"] == json!("evaluate")
                && record["status"] == json!(200)
        })
        .expect("evaluate audit record exists");
    assert_eq!(
        evaluate_audit["access_mode"],
        json!("self_attestation"),
        "{evaluate_audit}"
    );
    assert!(evaluate_audit["policy_hash"].is_string());
    assert!(evaluate_audit.get("correlation_id").is_none());
    assert!(evaluate_audit["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is string")
        .starts_with("hmac-sha256:"));
    assert!(evaluate_audit.get("principal_id").is_none());
    assert!(evaluate_audit.get("principal_id_hash").is_some());
    assert_eq!(evaluate_audit["scopes_used"], json!(["self_attestation"]));

    let render_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations/{evaluation_id}/render")
                && record["decision"] == json!("render")
                && record["status"] == json!(200)
        })
        .expect("render audit record exists");
    assert_eq!(render_audit["access_mode"], json!("self_attestation"));
    assert_eq!(render_audit["scopes_used"], json!(["self_attestation"]));
    assert_eq!(
        render_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    assert!(render_audit["policy_hash"].is_string());
    assert!(render_audit.get("correlation_id").is_none());
    assert!(render_audit["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is string")
        .starts_with("hmac-sha256:"));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_metadata_offer_and_nonce_are_public() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(
        metadata_body["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"]
            [0]["name"],
        json!("Person is alive")
    );
    let metadata_text = metadata_body.to_string();
    assert!(!metadata_text.contains("source_connections"));
    assert!(!metadata_text.contains("source-token"));

    let offer = server.get("/oid4vci/credential-offer").await;
    offer.assert_status_ok();
    let offer_body: Value = offer.json();
    assert_eq!(
        offer_body["credential_configuration_ids"][0],
        json!("person_is_alive_sd_jwt")
    );
    let filtered_offer = server
        .get("/oid4vci/credential-offer?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    filtered_offer.assert_status_ok();
    let filtered_offer_body: Value = filtered_offer.json();
    assert_eq!(
        filtered_offer_body["credential_configuration_ids"],
        json!(["person_is_alive_sd_jwt"])
    );
    let unknown_offer = server
        .get("/oid4vci/credential-offer?credential_configuration_id=unknown")
        .await;
    unknown_offer.assert_status(StatusCode::BAD_REQUEST);
    let unknown_offer_body: Value = unknown_offer.json();
    assert_eq!(unknown_offer_body["error"], json!("invalid_request"));

    let nonce = server.post("/oid4vci/nonce").json(&json!({})).await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    assert!(nonce_body["c_nonce"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(nonce_body["c_nonce_expires_in"], json!(300));

    let bad_nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"subject": "person-2"}))
        .await;
    bad_nonce.assert_status(StatusCode::BAD_REQUEST);
    let bad_nonce_body: Value = bad_nonce.json();
    assert_eq!(bad_nonce_body["error"], json!("invalid_request"));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_nonce_is_rate_limited_before_reservation() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config
        .self_attestation
        .rate_limits
        .invalid_token_per_client_address_per_minute = 2;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.10")
        .json(&json!({}))
        .await
        .assert_status_ok();
    server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.11")
        .json(&json!({}))
        .await
        .assert_status_ok();

    let limited = server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.12")
        .json(&json!({}))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.json::<Value>()["error"],
        json!("temporarily_unavailable")
    );

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_is_public_and_matches_configured_vct() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = response.json();
    assert_eq!(
        body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(body["name"], json!("Person is alive"));
    assert_eq!(body["display"][0]["locale"], json!("en-US"));
    assert_eq!(body["display"][0]["name"], json!("Person is alive"));
    assert_eq!(body["claims"][0]["path"], json!(["person-is-alive"]));
    assert_eq!(body["claims"][0]["display"][0]["locale"], json!("en-US"));
    assert_eq!(
        body["claims"][0]["display"][0]["label"],
        json!("Person is alive")
    );
    assert_eq!(body["claims"][0]["sd"], json!("always"));
    assert_eq!(body["claims"][0]["mandatory"], json!(true));

    let query_response = server
        .get("/credentials/civil-status?cache_bust=1")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    query_response.assert_status_ok();
    let query_body: Value = query_response.json();
    assert_eq!(
        query_body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );

    let head = server
        .method(Method::HEAD, "/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    head.assert_status_ok();
    assert_eq!(
        head.headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_normalizes_forwarded_scheme_and_host_case() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let vct = "https://issuer.example.test/credentials/civil-status";
    config.oid4vci.credential_issuer = "https://issuer.example.test".to_string();
    config.oid4vci.credential_endpoint =
        "https://issuer.example.test/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "https://issuer.example.test/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("https://issuer.example.test/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = vct.to_string();
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "ISSUER.EXAMPLE.TEST")
        .add_header("x-forwarded-proto", "HTTPS")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["vct"], json!(vct));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_supports_nested_paths_and_public_404s() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let nested_vct = "http://127.0.0.1:4325/credentials/dhis2/health-status/v1";
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = nested_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = nested_vct.to_string();
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nested = server
        .get("/credentials/dhis2/health-status/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    nested.assert_status_ok();
    let body: Value = nested.json();
    assert_eq!(body["vct"], json!(nested_vct));

    let unknown = server
        .get("/credentials/dhis2/unknown/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    unknown.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_supports_path_prefixed_issuer_behind_stripping_proxy() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let prefixed_vct = "http://127.0.0.1:4325/notary/credentials/civil-status";
    config.oid4vci.credential_issuer = "http://127.0.0.1:4325/notary".to_string();
    config.oid4vci.credential_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("http://127.0.0.1:4325/notary/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = prefixed_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = prefixed_vct.to_string();
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["vct"], json!(prefixed_vct));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_is_not_served_when_oid4vci_is_disabled() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.oid4vci.enabled = false;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_well_known_is_public_and_matches_configured_vct() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = response.json();
    assert_eq!(
        body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(body["name"], json!("Person is alive"));
    assert_eq!(body["display"][0]["locale"], json!("en-US"));
    assert_eq!(body["display"][0]["name"], json!("Person is alive"));
    assert_eq!(body["claims"][0]["path"], json!(["person-is-alive"]));
    assert_eq!(body["claims"][0]["display"][0]["locale"], json!("en-US"));
    assert_eq!(
        body["claims"][0]["display"][0]["label"],
        json!("Person is alive")
    );
    assert_eq!(body["claims"][0]["sd"], json!("always"));
    assert_eq!(body["claims"][0]["mandatory"], json!(true));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_well_known_supports_nested_paths_and_public_404s() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let nested_vct = "http://127.0.0.1:4325/credentials/dhis2/health-status/v1";
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = nested_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = nested_vct.to_string();
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nested = server
        .get("/.well-known/vct/credentials/dhis2/health-status/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    nested.assert_status_ok();
    let body: Value = nested.json();
    assert_eq!(body["vct"], json!(nested_vct));

    let unknown = server
        .get("/.well-known/vct/credentials/dhis2/unknown/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    unknown.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_well_known_is_not_served_when_oid4vci_is_disabled() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.oid4vci.enabled = false;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_well_known_keeps_protected_routes_authenticated() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status_ok();
    server
        .post("/v1/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_type_metadata_well_known_serves_wallet_cors() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let type_metadata = server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .add_header("origin", "https://wallet.example.gov")
        .await;
    type_metadata.assert_status_ok();
    assert_eq!(
        type_metadata
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );

    let preflight = server
        .method(Method::OPTIONS, "/.well-known/vct/credentials/civil-status")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;
    preflight.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert!(
        preflight
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|methods| methods.split(',').any(|method| method.trim() == "GET")),
        "preflight response should allow GET"
    );

    idp.stop().await;
}

#[tokio::test]
async fn public_probe_routes_remain_public_except_metrics() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server.get("/healthz").await.assert_status_ok();
    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let ready_body: Value = ready.json();
    assert_eq!(ready_body["status"], json!(503));
    assert_eq!(ready_body["code"], json!("readiness.not_ready"));
    assert_eq!(ready_body["readiness_status"], json!("degraded"));
    assert_eq!(ready_body["checks"]["degraded"], json!(1));
    server
        .get("/.well-known/openid-credential-issuer")
        .await
        .assert_status_ok();
    server
        .get("/oid4vci/credential-offer")
        .await
        .assert_status_ok();
    server
        .post("/oid4vci/nonce")
        .json(&json!({}))
        .await
        .assert_status_ok();
    server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/history")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/federation/v1/evaluations")
        .bytes(Bytes::from_static(b"not-mounted"))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    server
        .get("/metrics")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/v1/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    idp.stop().await;
}

#[tokio::test]
async fn manifest_public_protected_routes_are_mounted_behind_auth() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let manifest: ExposureManifest = serde_json::from_str(include_str!(
        "../../../products/notary/security/exposure-manifest.json"
    ))
    .expect("security exposure manifest parses");
    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for endpoint in manifest.endpoints.iter().filter(|endpoint| {
        endpoint.listener == "public" && endpoint.auth != "none" && endpoint.feature.is_none()
    }) {
        let method = Method::from_bytes(endpoint.method.as_bytes()).expect("method parses");
        let path = sample_manifest_path(&endpoint.path);
        let request = server.method(method, &path);
        let response = if endpoint.auth == "bearer" && endpoint.path == "/oid4vci/credential" {
            request
                .json(&json!({
                    "format": "dc+sd-jwt",
                    "credential_configuration_id": "person_is_alive_sd_jwt",
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": sign_oid4vci_proof("http://127.0.0.1:4325", "nonce-1")
                    }
                }))
                .await
        } else {
            request.await
        };
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "{} {} must be mounted behind auth on the public listener",
            endpoint.method,
            endpoint.path
        );
    }

    idp.stop().await;
}

#[tokio::test]
async fn service_document_advertises_credential_status_when_enabled() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/.well-known/evidence-service")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["status_methods"],
        json!(["status_list"])
    );
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["credential_status_url"],
        json!("/v1/credentials/{credential_id}/status")
    );
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["credential_status_media_type"],
        json!("application/statuslist+jwt")
    );
    assert!(!body["credential_capabilities"]["unsupported_features"]
        .as_array()
        .expect("unsupported features is an array")
        .iter()
        .any(|feature| feature.as_str() == Some("credential_status")));
}

#[tokio::test]
async fn credential_status_admin_edges_return_expected_http_statuses() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let enabled_audit_path = tmp.path().join("enabled-audit.jsonl");
    let mut enabled_config = registry_data_api_config(
        "http://127.0.0.1:1",
        enabled_audit_path
            .to_str()
            .expect("enabled audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut enabled_config);
    enable_credential_status(&mut enabled_config);
    enabled_config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });
    let enabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(enabled_config).expect("enabled router builds"));

    let invalid_status = enabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "admin-token")
        .json(&json!({ "status": "deleted" }))
        .await;
    invalid_status.assert_status(StatusCode::BAD_REQUEST);
    let invalid_body: Value = invalid_status.json();
    assert_eq!(
        invalid_body["code"],
        json!("credential_status.invalid_status")
    );

    let missing_admin_scope = enabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "api-token")
        .json(&json!({ "status": "revoked" }))
        .await;
    missing_admin_scope.assert_status(StatusCode::FORBIDDEN);

    let disabled_audit_path = tmp.path().join("disabled-audit.jsonl");
    let mut disabled_config = registry_data_api_config(
        "http://127.0.0.1:1",
        disabled_audit_path
            .to_str()
            .expect("disabled audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut disabled_config);
    disabled_config
        .auth
        .api_keys
        .push(EvidenceCredentialConfig {
            id: "admin".to_string(),
            fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
            scopes: vec!["registry_notary:admin".to_string()],
            authorization_details: None,
        });
    let disabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(disabled_config).expect("disabled router builds"));

    let disabled = disabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "admin-token")
        .json(&json!({ "status": "revoked" }))
        .await;
    disabled.assert_status(StatusCode::NOT_FOUND);
    let disabled_body: Value = disabled.json();
    assert_eq!(disabled_body["code"], json!("credential_status.disabled"));

    let disabled_public = disabled_server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await;
    disabled_public.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_scope_is_instance_global_across_credential_profiles() {
    // Pins the documented instance-global admin model (issue #58): the same
    // registry_notary:admin-scoped credential authorizes admin operations
    // against every credential profile hosted by this instance. Registry
    // Notary does not partition admin authority per credential profile /
    // issuer; the supported isolation boundary for separate administrative
    // domains is one Registry Notary instance per issuing authority.
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK_2", TEST_HOLDER_JWK);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    enable_credential_status(&mut config);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });

    // Two credential profiles standing in for two distinct issuing
    // authorities hosted by this single instance.
    config.evidence.signing_keys.insert(
        "issuer-one-key".to_string(),
        local_jwk_signing_key(
            "TEST_SELF_ATTESTATION_ISSUER_JWK",
            "did:web:issuer-one.example#key-1",
        ),
    );
    config.evidence.signing_keys.insert(
        "issuer-two-key".to_string(),
        local_jwk_signing_key(
            "TEST_SELF_ATTESTATION_ISSUER_JWK_2",
            "did:web:issuer-two.example#key-1",
        ),
    );
    config.evidence.credential_profiles.insert(
        "issuer_one_sd_jwt".to_string(),
        CredentialProfileConfig {
            format: "application/dc+sd-jwt".to_string(),
            issuer: "did:web:issuer-one.example".to_string(),
            signing_key: "issuer-one-key".to_string(),
            vct: "http://127.0.0.1:4325/credentials/issuer-one".to_string(),
            validity_seconds: 600,
            holder_binding: Default::default(),
            allowed_claims: vec!["farmed-land-size".to_string()],
            disclosure: Default::default(),
        },
    );
    config.evidence.credential_profiles.insert(
        "issuer_two_sd_jwt".to_string(),
        CredentialProfileConfig {
            format: "application/dc+sd-jwt".to_string(),
            issuer: "did:web:issuer-two.example".to_string(),
            signing_key: "issuer-two-key".to_string(),
            vct: "http://127.0.0.1:4325/credentials/issuer-two".to_string(),
            validity_seconds: 600,
            holder_binding: Default::default(),
            allowed_claims: vec!["farmed-land-size".to_string()],
            disclosure: Default::default(),
        },
    );

    let server = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("standalone router builds"));

    // Credential ids standing in for credentials issued under each profile.
    // The admin credential-status route takes no profile parameter, so this
    // exercises the same route and token pair against resources nominally
    // tied to two different issuers hosted by the instance.
    let issuer_one_credential_id = "urn:ulid:01HX0000000000000000000AA1";
    let issuer_two_credential_id = "urn:ulid:01HX0000000000000000000AA2";

    for credential_id in [issuer_one_credential_id, issuer_two_credential_id] {
        let path = format!("/admin/v1/credentials/{credential_id}/status");

        // The non-admin caseworker key is denied for both profiles' credentials.
        let missing_admin_scope = server
            .post(&path)
            .add_header("x-api-key", "api-token")
            .json(&json!({ "status": "revoked" }))
            .await;
        missing_admin_scope.assert_status(StatusCode::FORBIDDEN);

        // The single admin-scoped key clears the scope check for both
        // profiles' credentials; the deliberately invalid status value below
        // proves the request reached past authorization (400, not 403).
        let admin_authorized = server
            .post(&path)
            .add_header("x-api-key", "admin-token")
            .json(&json!({ "status": "deleted" }))
            .await;
        admin_authorized.assert_status(StatusCode::BAD_REQUEST);
        let admin_authorized_body: Value = admin_authorized.json();
        assert_eq!(
            admin_authorized_body["code"],
            json!("credential_status.invalid_status")
        );
    }
}

#[tokio::test]
async fn disabled_oid4vci_credential_route_stays_hidden_for_malformed_body() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/oid4vci/credential")
        .add_header("content-type", "application/json")
        .text("{")
        .await;
    response.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_credential_route_issues_holder_bound_sd_jwt() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_shared_admin_listener(&mut config);
    enable_credential_status(&mut config);
    config
        .auth
        .oidc
        .as_mut()
        .expect("OIDC auth is configured")
        .scope_map
        .insert(
            "status_admin".to_string(),
            vec!["registry_notary:admin".to_string()],
        );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let missing_status = server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await;
    missing_status.assert_status(StatusCode::NOT_FOUND);
    let missing_status_body: Value = missing_status.json();
    assert_eq!(
        missing_status_body["code"],
        json!("credential_status.not_found")
    );

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    let nonce = nonce_body["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "authorization_details": [{
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "legal_basis_ref": "wallet-compat-context",
            "consent_ref": "wallet-compat-consent",
            "jurisdiction": "ZZ",
            "assurance_level": "substantial"
        }],
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": proof
            }
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["format"], json!("dc+sd-jwt"));
    let credential = body["credential"].as_str().expect("credential is a string");
    assert!(credential.contains('~'));
    let issuer_jws = credential
        .split('~')
        .next()
        .expect("SD-JWT contains an issuer JWS");
    let payload_segment = issuer_jws
        .split('.')
        .nth(1)
        .expect("issuer JWS contains a payload segment");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("issuer JWS payload is base64url"),
    )
    .expect("issuer JWS payload is JSON");
    assert_eq!(
        payload["exp"].as_i64().expect("credential has exp")
            - payload["iat"].as_i64().expect("credential has iat"),
        600
    );
    let credential_id = payload["jti"]
        .as_str()
        .expect("credential has jti")
        .to_string();
    assert_eq!(payload["id"], json!(credential_id));
    assert_eq!(
        payload["status"],
        json!({
            "status_list": {
                "idx": 0,
                "uri": format!("http://127.0.0.1:4325/v1/credentials/{credential_id}/status")
            }
        })
    );
    assert!(body["c_nonce"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let status = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status.assert_status_ok();
    let status_body: Value = status.json();
    assert_eq!(status_body["credential_id"], json!(credential_id));
    assert_eq!(status_body["status"], json!("valid"));
    assert_eq!(
        status_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    let status_list = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .add_header(header::ACCEPT, "application/statuslist+jwt")
        .await;
    status_list.assert_status_ok();
    assert_eq!(
        status_list
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/statuslist+jwt")
    );
    let status_list_jwt = status_list.text();
    assert_eq!(jwt_header(&status_list_jwt)["typ"], json!("statuslist+jwt"));
    let status_list_payload = jwt_payload(&status_list_jwt);
    assert_eq!(
        status_list_payload["sub"],
        json!(format!(
            "http://127.0.0.1:4325/v1/credentials/{credential_id}/status"
        ))
    );
    assert_eq!(status_list_payload["ttl"], json!(300));
    assert_eq!(status_list_payload["status_list"]["bits"], json!(8));
    assert_eq!(
        status_list_payload["status_list"]["lst"],
        json!("eJxjAAAAAQAB")
    );

    let admin_token = idp.mint_token(json!({
        "sub": "status-admin",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "status_admin",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let revoked = server
        .post(&format!("/admin/v1/credentials/{credential_id}/status"))
        .add_header("authorization", format!("Bearer {admin_token}"))
        .json(&json!({ "status": "revoked" }))
        .await;
    revoked.assert_status_ok();
    let revoked_body: Value = revoked.json();
    assert_eq!(revoked_body["status"], json!("revoked"));

    let status_after_revoke = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status_after_revoke.assert_status_ok();
    let status_after_revoke_body: Value = status_after_revoke.json();
    assert_eq!(status_after_revoke_body["status"], json!("revoked"));
    let revoked_status_list = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .add_header(header::ACCEPT, "application/statuslist+jwt")
        .await;
    revoked_status_list.assert_status_ok();
    let revoked_status_list_payload = jwt_payload(&revoked_status_list.text());
    assert_eq!(
        revoked_status_list_payload["status_list"]["lst"],
        json!("eJxjBAAAAgAC")
    );

    for attempted_status in ["valid", "suspended"] {
        let rejected = server
            .post(&format!("/admin/v1/credentials/{credential_id}/status"))
            .add_header("authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "status": attempted_status }))
            .await;
        rejected.assert_status(StatusCode::CONFLICT);
        let rejected_body: Value = rejected.json();
        assert_eq!(
            rejected_body["code"],
            json!("credential_status.invalid_transition")
        );
    }

    let status_after_rejected_mutations = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status_after_rejected_mutations.assert_status_ok();
    let status_after_rejected_mutations_body: Value = status_after_rejected_mutations.json();
    assert_eq!(
        status_after_rejected_mutations_body["status"],
        json!("revoked")
    );

    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let credential_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/credential")
                && record["decision"] == json!("credential_issued")
                && record["status"] == json!(200)
        })
        .expect("OID4VCI credential audit record exists");
    assert_eq!(credential_audit["access_mode"], json!("self_attestation"));
    assert_eq!(
        credential_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    assert_eq!(credential_audit["protocol"], json!("openid4vci"));
    assert_eq!(
        credential_audit["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    assert_eq!(
        credential_audit["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    assert_eq!(credential_audit["target_type"], json!("Person"));
    assert!(credential_audit["target_ref_hash"].as_str().is_some());
    assert_eq!(credential_audit["requester_type"], json!("Person"));
    assert!(credential_audit["requester_ref_hash"].as_str().is_some());

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_field_projection_issues_separate_disclosures() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_oid4vci_field_projection(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let metadata = server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(metadata_body["claims"][0]["path"], json!(["given_name"]));
    assert_eq!(
        metadata_body["claims"][0]["display"][0]["label"],
        json!("Given name")
    );
    assert_eq!(metadata_body["claims"][0]["sd"], json!("always"));
    assert_eq!(metadata_body["claims"][0]["mandatory"], json!(true));
    assert_eq!(metadata_body["claims"][1]["path"], json!(["birth_date"]));
    assert_eq!(
        metadata_body["claims"][1]["display"][0]["label"],
        json!("Birth date")
    );
    assert_eq!(metadata_body["claims"][1]["mandatory"], json!(true));

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce = nonce.json::<Value>()["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": proof
            }
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    let credential = body["credential"].as_str().expect("credential issued");
    let payload = decode_sd_jwt_payload(credential);
    assert_eq!(
        payload["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(
        payload["_sd"]
            .as_array()
            .expect("_sd digests are present")
            .len(),
        2
    );
    let payload_text = payload.to_string();
    assert!(!payload_text.contains("Miguel"));
    assert!(!payload_text.contains("2016-01-15"));

    assert_eq!(
        decode_disclosed_claim(credential, "given_name"),
        json!("Miguel")
    );
    assert_eq!(
        decode_disclosed_claim(credential, "birth_date"),
        json!("2016-01-15")
    );

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_credential_route_rejects_replayed_nonce() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    let nonce = nonce_body["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let credential_request = json!({
        "format": "dc+sd-jwt",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "proof": {
            "proof_type": "jwt",
            "jwt": proof
        }
    });

    let first = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_request)
        .await;
    first.assert_status_ok();

    let replay = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_request)
        .await;
    replay.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = replay.json();
    assert_eq!(body["error"], json!("invalid_proof"));

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_pre_evaluation_denials_are_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");
    let invalid_classification_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "openid",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let invalid_classification_authorization = format!("Bearer {invalid_classification_token}");
    const UNKNOWN_EVALUATION_ID: &str = "attacker-controlled-unknown-evaluation";
    const IDEMPOTENCY_EVALUATION_ID: &str = "idempotency-evaluation-not-read";
    const CLASSIFICATION_EVALUATION_ID: &str = "classification-evaluation-not-read";
    let cases = vec![
        (
            "malformed JSON",
            authorization.clone(),
            None,
            false,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "missing evaluation id",
            authorization.clone(),
            Some(json!({})),
            false,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "unsupported idempotency key",
            authorization.clone(),
            Some(json!({"evaluation_id": IDEMPOTENCY_EVALUATION_ID})),
            true,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "unknown evaluation id",
            authorization.clone(),
            Some(json!({"evaluation_id": UNKNOWN_EVALUATION_ID})),
            false,
            StatusCode::NOT_FOUND,
            "evaluation.not_found",
            "evaluation.not_found",
            None,
            None,
        ),
        (
            "self-attestation classification denial",
            invalid_classification_authorization.clone(),
            Some(json!({"evaluation_id": CLASSIFICATION_EVALUATION_ID})),
            false,
            StatusCode::FORBIDDEN,
            "self_attestation.denied",
            "self_attestation.invalid_token",
            Some("self_attestation.invalid_token"),
            Some(("self_attestation", "national_id")),
        ),
    ];

    for (
        index,
        (
            name,
            case_authorization,
            payload,
            idempotency_key,
            status,
            code,
            audit_code,
            denial_code,
            attestation_context,
        ),
    ) in cases.into_iter().enumerate()
    {
        let request = server
            .post("/v1/credentials")
            .add_header("authorization", case_authorization);
        let request = if idempotency_key {
            request.add_header("idempotency-key", "unsupported-idempotency-key")
        } else {
            request
        };
        let response = match payload {
            Some(payload) => request.json(&payload).await,
            None => {
                request
                    .add_header(header::CONTENT_TYPE, "application/json")
                    .text("{")
                    .await
            }
        };
        response.assert_status(status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json"),
            "{name} returns problem+json"
        );
        let body: Value = response.json();
        assert_problem_identity(&body, status, code);
        for field in [
            "credential",
            "credential_id",
            "issuer_signed_jwt",
            "disclosures",
        ] {
            assert!(body.get(field).is_none(), "{name} has no {field}");
        }
        let body_text = serde_json::to_string(&body).expect("problem body serializes");
        assert!(!body_text.contains(&token), "{name} does not echo token");
        for evaluation_id in [
            UNKNOWN_EVALUATION_ID,
            IDEMPOTENCY_EVALUATION_ID,
            CLASSIFICATION_EVALUATION_ID,
        ] {
            assert!(
                !body_text.contains(evaluation_id),
                "{name} does not echo an untrusted evaluation id"
            );
        }

        let records = audit_records_from_envelopes(&audit_path);
        let credential_records = records
            .iter()
            .filter(|record| record["path"] == json!("/v1/credentials"))
            .collect::<Vec<_>>();
        assert_eq!(
            credential_records.len(),
            index + 1,
            "{name} writes one credential audit record"
        );
        let denied = credential_records
            .last()
            .expect("new credential denial audit record exists");
        assert_eq!(denied["decision"], json!("credential_denied"), "{name}");
        assert_eq!(denied["status"], json!(status.as_u16()), "{name}");
        assert_eq!(denied["error_code"], json!(audit_code), "{name}");
        assert_eq!(denied["source_read_count"], json!(0), "{name}");
        assert_eq!(denied["forwarded"], json!(false), "{name}");
        match denial_code {
            Some(denial_code) => assert_eq!(denied["denial_code"], json!(denial_code), "{name}"),
            None => assert!(denied.get("denial_code").is_none(), "{name}"),
        }
        if let Some((access_mode, token_claim_name)) = attestation_context {
            assert_eq!(denied["access_mode"], json!(access_mode), "{name}");
            assert_eq!(
                denied["token_claim_name"],
                json!(token_claim_name),
                "{name}"
            );
        }
        assert!(
            denied.get("verification_id").is_none(),
            "{name} has no untrusted verification id"
        );
        for field in [
            "credential",
            "credential_id",
            "issuer_signed_jwt",
            "disclosures",
        ] {
            assert!(denied.get(field).is_none(), "{name} audit has no {field}");
        }
        assert!(
            !audit_record_contains_text(denied, &token),
            "{name} audit does not contain the token"
        );
        assert!(
            !audit_record_contains_text(denied, UNKNOWN_EVALUATION_ID),
            "{name} audit does not contain the unknown evaluation id"
        );
        assert!(!records.iter().any(|record| {
            record["path"] == json!("/v1/credentials")
                && record["decision"] == json!("credential_issued")
        }));
    }
    let records = audit_records_from_envelopes(&audit_path);
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &invalid_classification_token,
            &invalid_classification_authorization,
            UNKNOWN_EVALUATION_ID,
            IDEMPOTENCY_EVALUATION_ID,
            CLASSIFICATION_EVALUATION_ID,
            "unsupported-idempotency-key",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
async fn direct_credentials_issue_creates_retrievable_status_record() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    let holder_id = holder_did_jwk();
    let proof =
        sign_direct_holder_proof(&holder_id, &evaluation_id, "direct-credential-status-jti-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization)
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": proof
            }
        }))
        .await;
    issue.assert_status_ok();
    let issue_body: Value = issue.json();
    assert_eq!(
        issue_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    let issuer_signed_jwt = issue_body["issuer_signed_jwt"]
        .as_str()
        .expect("issuer signed JWT returned");
    let header_segment = issuer_signed_jwt
        .split('.')
        .next()
        .expect("issuer signed JWT has protected header");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_segment)
            .expect("issuer signed JWT header is base64url"),
    )
    .expect("issuer signed JWT header is JSON");
    assert_eq!(header["alg"], json!("EdDSA"));
    assert_eq!(header["typ"], json!("dc+sd-jwt"));
    assert_eq!(header["kid"], json!("did:web:issuer.example#key-1"));
    let credential_id = issue_body["credential_id"]
        .as_str()
        .expect("credential id returned");

    let status = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status.assert_status_ok();
    let status_body: Value = status.json();
    assert_eq!(status_body["credential_id"], json!(credential_id));
    assert_eq!(status_body["status"], json!("valid"));
    assert_eq!(
        status_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_operation_denial_is_audited_and_preserves_denial_code() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    assert!(config.self_attestation.allowed_operations.evaluate);
    assert!(!config.self_attestation.allowed_operations.issue_credential);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    assert_eq!(source_hits.load(Ordering::SeqCst), 1);
    let holder_id = holder_did_jwk();
    let proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "operation-denied-jti-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": proof
            }
        }))
        .await;
    issue.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(&body, StatusCode::FORBIDDEN, "self_attestation.denied");
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(body.get(field).is_none(), "denial has no {field}");
    }
    assert_eq!(
        source_hits.load(Ordering::SeqCst),
        1,
        "credential denial does not read the source again"
    );

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "self_attestation.operation_denied",
    );
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.operation_denied")
    );
    assert_eq!(denied["verification_id"], json!(evaluation_id));
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(denied.get(field).is_none(), "audit has no {field}");
    }
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            &holder_id,
            "operation-denied-jti-1",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_rate_limit_is_audited_with_stored_context() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .self_attestation
        .rate_limits
        .credential_issuance_per_principal_per_hour = 1;
    config.self_attestation.token_policy.max_auth_age_seconds = 60;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");
    let stale_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now - 3600,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let stale_authorization = format!("Bearer {stale_token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    assert_eq!(source_hits.load(Ordering::SeqCst), 1);
    let holder_id = holder_did_jwk();
    let first_proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "rate-limit-first-jti");
    let second_proof =
        sign_direct_holder_proof(&holder_id, &evaluation_id, "rate-limit-second-jti");

    let stale = server
        .post("/v1/credentials")
        .add_header("authorization", stale_authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": first_proof.clone()
            }
        }))
        .await;
    stale.assert_status(StatusCode::FORBIDDEN);
    let stale_body: Value = stale.json();
    assert_problem_identity(
        &stale_body,
        StatusCode::FORBIDDEN,
        "self_attestation.denied",
    );
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(
            stale_body.get(field).is_none(),
            "stale token has no {field}"
        );
    }
    let records = audit_records_from_envelopes(&audit_path);
    let assurance_denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "self_attestation.assurance_denied",
    );
    assert_eq!(
        assurance_denied["denial_code"],
        json!("self_attestation.assurance_denied")
    );
    assert_eq!(assurance_denied["source_read_count"], json!(0));
    assert_eq!(assurance_denied["forwarded"], json!(false));
    assert_eq!(source_hits.load(Ordering::SeqCst), 1);
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    let first = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": first_proof
            }
        }))
        .await;
    first.assert_status_ok();
    let first_body: Value = first.json();
    let issued_credential = first_body["credential"]
        .as_str()
        .expect("first credential is returned")
        .to_string();

    let limited = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": second_proof
            }
        }))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let limited_body: Value = limited.json();
    assert_problem_identity(
        &limited_body,
        StatusCode::TOO_MANY_REQUESTS,
        "self_attestation.rate_limited",
    );
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(
            limited_body.get(field).is_none(),
            "rate limit has no {field}"
        );
    }
    assert_eq!(
        source_hits.load(Ordering::SeqCst),
        1,
        "credential requests do not read the source again"
    );

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_issue_rate_limited",
        StatusCode::TOO_MANY_REQUESTS,
        "self_attestation.rate_limited",
    );
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.rate_limited")
    );
    assert_eq!(
        denied["rate_limit_bucket"],
        json!("credential_issuance_per_principal")
    );
    assert_eq!(denied["verification_id"], json!(evaluation_id));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["purposes"], json!(["citizen_self_attestation"]));
    assert!(denied["claim_hash"].as_str().is_some());
    assert_eq!(denied["target_type"], json!("Person"));
    assert!(denied["target_ref_hash"].as_str().is_some());
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(denied.get(field).is_none(), "audit has no {field}");
    }
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record["path"] == json!("/v1/credentials")
                    && record["decision"] == json!("credential_issued")
            })
            .count(),
        1,
        "only the first request issues a credential"
    );
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &stale_token,
            &stale_authorization,
            &first_proof,
            &second_proof,
            &holder_id,
            &issued_credential,
            "rate-limit-first-jti",
            "rate-limit-second-jti",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_holder_proof_replay_is_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    let holder_id = holder_did_jwk();
    let proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "direct-replay-jti-1");
    let credential_request = json!({
        "evaluation_id": evaluation_id,
        "credential_profile": "civil_status_sd_jwt",
        "format": "application/dc+sd-jwt",
        "claims": ["person-is-alive"],
        "disclosure": "value",
        "holder": {
            "binding": "did",
            "id": holder_id,
            "proof": proof
        }
    });

    let first = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&credential_request)
        .await;
    first.assert_status_ok();
    let first_body: Value = first.json();
    assert!(first_body["credential"].is_string());

    let replay = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&credential_request)
        .await;
    replay.assert_status(StatusCode::CONFLICT);
    assert_eq!(
        replay
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let replay_body: Value = replay.json();
    assert_problem_identity(
        &replay_body,
        StatusCode::CONFLICT,
        "credential.holder_proof_replay",
    );
    assert!(replay_body.get("credential").is_none());
    assert!(replay_body.get("credential_id").is_none());
    assert!(replay_body.get("issuer_signed_jwt").is_none());
    assert!(replay_body.get("disclosures").is_none());
    let replay_body_text = serde_json::to_string(&replay_body).expect("problem body serializes");
    assert!(!replay_body_text.contains(&token));
    assert!(!replay_body_text.contains("person-1"));
    assert!(!replay_body_text.contains("direct-replay-jti-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::CONFLICT,
        "credential.holder_proof_replay",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record["path"] == json!("/v1/credentials")
                    && record["decision"] == json!("credential_issued")
            })
            .count(),
        1,
        "first use should issue exactly one credential"
    );
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            "direct-replay-jti-1",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
async fn strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");
    let proof = sign_oid4vci_proof("registry-notary", "nonce-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_did_jwk(),
                "proof": proof.clone()
            }
        }))
        .await;
    issue.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(
        &body,
        StatusCode::BAD_REQUEST,
        "credential.holder_proof_required",
    );
    assert!(body.get("credential").is_none());
    assert!(body.get("issuer_signed_jwt").is_none());
    assert!(body.get("disclosures").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains(&proof));
    assert!(!body_text.contains(&token));
    assert!(!body_text.contains("person-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::BAD_REQUEST,
        "credential.holder_proof_required",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_purpose_mismatch_denial_is_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "purpose": "appeals"
        }))
        .await;
    issue.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(&body, StatusCode::FORBIDDEN, "evaluation.binding_mismatch");
    assert!(body.get("credential").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("issuer_signed_jwt").is_none());
    assert!(body.get("disclosures").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains(&token));
    assert!(!body_text.contains("person-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "evaluation.binding_mismatch",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
async fn direct_credential_binding_denials_are_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");

    let cases = [
        (
            "unsupported format",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/json",
                "claims": ["person-is-alive"],
                "disclosure": "value"
            }),
            StatusCode::NOT_ACCEPTABLE,
            "claim.format_not_supported",
        ),
        (
            "disclosure mismatch",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/dc+sd-jwt",
                "claims": ["person-is-alive"],
                "disclosure": "predicate"
            }),
            StatusCode::FORBIDDEN,
            "evaluation.binding_mismatch",
        ),
        (
            "claim-set mismatch",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/dc+sd-jwt",
                "claims": ["person-is-dead"],
                "disclosure": "value"
            }),
            StatusCode::FORBIDDEN,
            "evaluation.binding_mismatch",
        ),
    ];

    for (name, payload, status, code) in &cases {
        let issue = server
            .post("/v1/credentials")
            .add_header("authorization", authorization.clone())
            .json(&payload)
            .await;
        issue.assert_status(*status);
        assert_eq!(
            issue
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json"),
            "{name} returns problem+json"
        );
        let body: Value = issue.json();
        assert_problem_identity(&body, *status, code);
        assert!(body.get("credential").is_none(), "{name} has no credential");
        assert!(
            body.get("credential_id").is_none(),
            "{name} has no credential id"
        );
        assert!(
            body.get("issuer_signed_jwt").is_none(),
            "{name} has no issuer JWT"
        );
        assert!(
            body.get("disclosures").is_none(),
            "{name} has no disclosures"
        );
        let body_text = serde_json::to_string(&body).expect("problem body serializes");
        assert!(!body_text.contains(&token), "{name} does not echo token");
        assert!(
            !body_text.contains("person-1"),
            "{name} does not echo subject"
        );
    }

    let records = audit_records_from_envelopes(&audit_path);
    let denied_records = records
        .iter()
        .filter(|record| {
            record["path"] == json!("/v1/credentials")
                && record["decision"] == json!("credential_denied")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        denied_records.len(),
        cases.len(),
        "every binding denial should emit credential_denied audit"
    );
    for ((name, _, status, code), denied) in cases.iter().zip(denied_records.iter()) {
        assert_eq!(
            denied["status"],
            json!(status.as_u16()),
            "{name} audit status"
        );
        assert_eq!(
            denied["error_code"],
            json!(*code),
            "{name} audit error code"
        );
        assert_eq!(denied["access_mode"], json!("self_attestation"));
        assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
        assert_eq!(denied["source_read_count"], json!(0));
        assert_eq!(denied["forwarded"], json!(false));
        assert!(denied.get("principal_id").is_none());
        assert!(denied["principal_id_hash"]
            .as_str()
            .expect("principal id hash is present")
            .starts_with("hmac-sha256:"));
        assert!(denied.get("correlation_id").is_none());
        assert!(denied["correlation_id_hash"]
            .as_str()
            .expect("correlation id hash is present")
            .starts_with("hmac-sha256:"));
    }
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
async fn oid4vci_malformed_proof_is_rejected_before_oidc_auth() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let userinfo_hits = Arc::new(AtomicUsize::new(0));
    let userinfo_hits_for_route = Arc::clone(&userinfo_hits);
    let userinfo_app = Router::new().route(
        "/userinfo",
        get(move || {
            let userinfo_hits = Arc::clone(&userinfo_hits_for_route);
            async move {
                userinfo_hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::NO_CONTENT
            }
        }),
    );
    let userinfo_server = TestServer::builder().http_transport().build(userinfo_app);
    let userinfo_endpoint = userinfo_server
        .server_url("/userinfo")
        .expect("userinfo URL builds")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(userinfo_endpoint);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": "not-a-compact-jwt"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_proof"));
    assert!(body.get("code").is_none());
    assert_eq!(
        userinfo_hits.load(Ordering::SeqCst),
        0,
        "malformed proof must be rejected before the live UserInfo fetch"
    );

    let response = server
        .post("/oid4vci/credential")
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "target": person_target("person-2"),
            "proof": {
                "proof_type": "jwt",
                "jwt": "not-a-compact-jwt"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_proof"));

    idp.stop().await;
}

#[tokio::test]
async fn self_attestation_subject_mismatch_audit_names_token_claim_not_value() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
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

    let response = server
        .post("/v1/evaluations")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("x-request-id", "bad value")
        .json(&json!({
            "target": person_identifier_target("national_id", "person-2"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("self_attestation.denied"));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-notary/self_attestation/denied")
    );

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("person-2"));
    assert!(!audit.contains("citizen-subject"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let denied = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations")
                && record["decision"] == json!("evaluate_denied")
                && record["status"] == json!(403)
        })
        .expect("denial audit record exists");
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.subject_mismatch")
    );
    assert_eq!(
        denied["error_code"],
        json!("self_attestation.subject_mismatch")
    );
    assert_eq!(denied["token_claim_name"], json!("national_id"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"].is_string());
    assert_ne!(denied["correlation_id_hash"], json!("bad value"));

    idp.stop().await;
}

#[tokio::test]
async fn request_body_limit_returns_413_above_threshold() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::new(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .add_header(header::CONTENT_LENGTH, "1048577")
        .await;

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(413));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-platform/request/body-too-large")
    );
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(
        !body_text.contains("api-token"),
        "oversized-body problem response must not echo credential material"
    );
    assert!(
        !body_text.contains("1048577"),
        "oversized-body problem response must not echo the supplied content length"
    );
}

#[tokio::test]
async fn request_uri_limit_returns_414_problem_details() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let long_path = format!("/{}", "a".repeat(8 * 1024 + 1));

    let response = server
        .get(&long_path)
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::URI_TOO_LONG);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(414));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-notary/request/uri-too-long")
    );
    assert_eq!(body["code"], json!("request.uri_too_long"));
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(
        !body_text.contains(&long_path),
        "overlong-URI problem response must not echo the submitted URI"
    );
}

#[tokio::test]
async fn error_responses_match_rfc_9457_problem_details_shape() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/v1/claims")
        .add_header("x-request-id", "req-auth-1")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "req-auth-1");
    assert_eq!(body["status"], json!(401));
    assert_eq!(body["title"], json!("Missing credential"));
    assert_eq!(body["code"], json!("auth.missing_credential"));
    assert!(body["type"].as_str().is_some_and(
        |value| value.starts_with("https://id.registrystack.org/problems/registry-notary/")
    ));
    assert!(body["detail"].as_str().is_some());
}

#[tokio::test]
async fn evaluation_json_rejections_and_unsupported_idempotency_are_problem_details() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let old_shape = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("x-request-id", "req-problem-1")
        .add_header("content-type", "application/json")
        .bytes(Bytes::from_static(
            br#"{"subject":{"id":"person-1","id_type":"national_id"},"claims":["farmed-land-size"]}"#,
        ))
        .await;
    let old_shape_body: Value = old_shape.json();
    assert_server_owned_request_id(&old_shape, &old_shape_body, "req-problem-1");
    assert_eq!(old_shape_body["code"], json!("request.invalid"));

    let old_shape = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .bytes(Bytes::from_static(
            br#"{"subject":{"id":"person-1","id_type":"national_id"},"claims":["farmed-land-size"]}"#,
        ))
        .await;
    assert_request_invalid_problem(old_shape);

    let malformed_json = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .text("{")
        .await;
    assert_request_invalid_problem(malformed_json);

    let wrong_content_type = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "text/plain")
        .text("{}")
        .await;
    assert_request_invalid_problem(wrong_content_type);

    for route in [
        "/v1/evaluations",
        "/v1/evaluations/eval-1/render",
        "/v1/credentials",
    ] {
        let response = server
            .post(route)
            .add_header("x-api-key", "api-token")
            .add_header("idempotency-key", "unsupported-key")
            .add_header("content-type", "application/json")
            .text("{}")
            .await;
        assert_request_invalid_problem(response);
    }
}

fn assert_server_owned_request_id(
    response: &axum_test::TestResponse,
    body: &Value,
    inbound_request_id: &str,
) {
    let header_request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("x-request-id response header is present");
    let body_request_id = body["request_id"]
        .as_str()
        .expect("ProblemDetails request_id is present");

    assert_eq!(header_request_id, body_request_id);
    assert_ne!(body_request_id, inbound_request_id);
    Ulid::from_string(body_request_id).expect("request_id is a server-minted ULID");
}

fn assert_request_invalid_problem(response: axum_test::TestResponse) {
    response.assert_status(StatusCode::BAD_REQUEST);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(400));
    assert_eq!(body["code"], json!("request.invalid"));
    assert!(body["type"]
        .as_str()
        .is_some_and(|value| value.ends_with("/request/invalid")));
}

#[tokio::test]
async fn cors_csp_corp_headers_present_and_corp_conditional() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.cors.allowed_origins = vec!["https://client.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/healthz")
        .add_header("origin", "https://client.example.test")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://client.example.test")
    );
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("permissions-policy")
            .and_then(|value| value.to_str().ok()),
        Some("camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|value| value.to_str().ok()),
        Some("same-origin")
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-resource-policy")
            .and_then(|value| value.to_str().ok()),
        Some("cross-origin")
    );
}

#[tokio::test]
async fn self_attestation_cors_uses_wallet_origins_on_browser_paths() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let wallet = server
        .get("/.well-known/evidence-service")
        .add_header("origin", "https://wallet.example.gov")
        .await;
    wallet.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );

    let type_metadata = server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .add_header("origin", "https://wallet.example.gov")
        .await;
    type_metadata.assert_status_ok();
    assert_eq!(
        type_metadata
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );

    let ops = server
        .get("/.well-known/evidence-service")
        .add_header("origin", "https://ops.example.test")
        .await;
    ops.assert_status(StatusCode::UNAUTHORIZED);
    assert!(ops.headers().get("access-control-allow-origin").is_none());

    let healthz = server
        .get("/healthz")
        .add_header("origin", "https://ops.example.test")
        .await;
    healthz.assert_status_ok();
    assert_eq!(
        healthz
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://ops.example.test")
    );
}

#[tokio::test]
async fn self_attestation_preflight_uses_wallet_origin_allow_list() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let wallet = server
        .method(Method::OPTIONS, "/v1/evaluations")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "POST")
        .add_header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .await;
    wallet.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-headers")
            .and_then(|value| value.to_str().ok()),
        Some("authorization, content-type")
    );

    let type_metadata = server
        .method(Method::OPTIONS, "/credentials/civil-status")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;
    type_metadata.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        type_metadata
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert!(
        type_metadata
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|methods| methods.split(',').any(|method| method.trim() == "GET")),
        "preflight response should allow GET"
    );

    let ops = server
        .method(Method::OPTIONS, "/v1/evaluations")
        .add_header("origin", "https://ops.example.test")
        .add_header("access-control-request-method", "POST")
        .await;
    ops.assert_status(StatusCode::NO_CONTENT);
    assert!(ops.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn evaluate_policy_denial_records_zero_source_and_redacted_audit() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let binding = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists")
        .source_bindings
        .get_mut("farmer")
        .expect("farmer binding exists");
    binding.matching.permitted_jurisdictions = vec!["RW".to_string()];

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = response.json();
    assert_eq!(body["code"], json!("pdp.jurisdiction_not_permitted"));
    assert!(body.get("results").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains("api-token"));
    assert!(!body_text.contains("source-token"));
    assert!(!body_text.contains("person-1"));
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/evaluations",
        "evaluate_denied",
        StatusCode::FORBIDDEN,
        "pdp.jurisdiction_not_permitted",
    );
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied["claim_hash"]
        .as_str()
        .expect("claim hash is present")
        .starts_with("sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            "api-token",
            "source-token",
            "person-1",
            base_url.trim_end_matches('/'),
        ],
    );
}

#[tokio::test]
async fn standalone_server_authenticates_evaluates_over_http_and_writes_redacted_audit() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let denied = server.get("/v1/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let denied_openapi = server.get("/openapi.json").await;
    denied_openapi.assert_status(StatusCode::UNAUTHORIZED);

    let openapi = server
        .get("/openapi.json")
        .add_header("x-api-key", "api-token")
        .await;
    openapi.assert_status_ok();
    let openapi_body: Value = openapi.json();
    assert_eq!(openapi_body["openapi"], json!("3.1.0"));
    assert!(openapi_body["paths"]["/v1/evaluations"].is_object());

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
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    let provenance = &body["results"][0]["provenance"];
    assert_eq!(
        provenance["schema_version"],
        json!("registry-notary-claim-provenance/v1")
    );
    assert_eq!(
        provenance["generated_by"]["type"],
        json!("claim_evaluation")
    );
    assert_eq!(
        provenance["generated_by"]["service_id"],
        body["results"][0]["provenance"]["generated_by"]["service_id"]
    );
    assert!(provenance["generated_by"]["service_id"].is_string());
    assert_eq!(
        provenance["generated_by"]["claim_id"],
        json!("farmed-land-size")
    );
    assert_eq!(provenance["used"]["source_count"], json!(1));
    assert_eq!(provenance["derived_from"], json!([]));
    // computed_by must be gone from the wire entirely.
    assert!(
        !provenance.to_string().contains("computed_by"),
        "computed_by must not appear in claim provenance on the wire"
    );
    // Machine-client flow evaluates under no named policy: policy_* omitted.
    assert!(provenance["generated_by"].get("policy_id").is_none());
    // Requester-side identity must never appear in claim provenance.
    for forbidden in ["client", "actor", "subject"] {
        assert!(
            provenance.get(forbidden).is_none()
                && provenance["generated_by"].get(forbidden).is_none()
                && provenance["used"].get(forbidden).is_none(),
            "requester-side field {forbidden} must not appear in claim provenance"
        );
    }

    #[cfg(feature = "registry-notary-cel")]
    {
        let cel_response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "target": person_target("person-1"),
                "claims": ["farmer-under-4ha"],
                "disclosure": "predicate"
            }))
            .await;
        cel_response.assert_status_ok();
        let cel_body: Value = cel_response.json();
        assert_eq!(cel_body["results"][0]["value"], json!(true));
        assert_eq!(
            cel_body["results"][0]["provenance"]["used"]["source_count"],
            json!(1)
        );
    }

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    assert!(audit.contains("\"decision\":\"evaluate\""));
    assert!(audit.contains("\"claim_hash\":\"sha256:"));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("source-token"));
    assert!(!audit.contains("person-1"));
    assert!(!envelopes
        .iter()
        .any(|envelope| audit_record_contains_text(&envelope.record, "3.5")));

    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains("registry_notary_http_requests_total"));
    assert!(metrics_body.contains(
        "registry_notary_http_requests_total{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(metrics_body.contains("# TYPE registry_notary_http_request_duration_seconds histogram"));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_bucket{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\",le=\"+Inf\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_sum{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(metrics_body.contains(
        "registry_notary_http_request_duration_seconds_count{method=\"POST\",endpoint_kind=\"evaluation\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"}"
    ));
    assert!(!metrics_body.contains("registry_notary_http_request_duration_ms_total"));
    assert!(!metrics_body.contains("route="));
    assert!(metrics_body
        .contains("registry_notary_source_requests_total{connector=\"rda\",outcome=\"success\"}"));
    assert!(metrics_body.contains("registry_notary_audit_events_total{outcome=\"success\"}"));
    #[cfg(feature = "registry-notary-cel")]
    {
        assert!(
            metrics_body.contains("registry_notary_cel_evaluations_total{outcome=\"success\"} 1")
        );
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"max\"}"));
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"idle\"}"));
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"in_flight\"}"));
        assert!(
            metrics_body.contains("registry_notary_cel_worker_pool{state=\"replacements_total\"}")
        );
        assert!(metrics_body.contains("registry_notary_cel_worker_pool{state=\"circuit_open\"}"));
    }
    assert!(!metrics_body.contains("api-token"));
    assert!(!metrics_body.contains("source-token"));
    assert!(!metrics_body.contains("person-1"));
    assert!(!metrics_body.contains("3.5"));
    assert!(!metrics_body.contains("farmed-land-size"));
    assert!(!metrics_body.contains("farmer-under-4ha"));
    assert!(!metrics_body.contains("purpose.example.test"));
    assert!(!metrics_body.contains(base_url.trim_end_matches('/')));
}

#[tokio::test]
async fn standalone_router_hides_admin_and_metrics_when_admin_listener_is_not_shared() {
    for mode in [
        RegistryNotaryAdminListenerMode::Dedicated,
        RegistryNotaryAdminListenerMode::Disabled,
    ] {
        set_audit_secret();
        std::env::set_var(
            "TEST_EVIDENCE_API_KEY_HASH",
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
        );
        std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

        let tmp = TempDir::new().expect("tempdir");
        let audit_path = tmp.path().join("audit.jsonl");
        let mut config = registry_data_api_config(
            "http://127.0.0.1:1",
            audit_path.to_str().expect("audit path is UTF-8"),
        );
        add_admin_api_key(&mut config);
        config.server.admin_listener.mode = mode;
        config.server.admin_listener.bind = "127.0.0.1:19091".parse().expect("valid admin bind");

        let app = standalone_router(config).expect("standalone router builds");
        let server = TestServer::builder().http_transport().build(app);

        server.get("/healthz").await.assert_status_ok();
        server
            .post("/admin/v1/reload")
            .add_header("x-api-key", "admin-token")
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .get("/metrics")
            .add_header("x-api-key", "admin-token")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn standalone_router_default_config_hides_admin_and_metrics() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    add_admin_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server.get("/healthz").await.assert_status_ok();
    server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/metrics")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn standalone_server_can_serve_openapi_without_auth_when_configured() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.openapi_requires_auth = false;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let openapi = server.get("/openapi.json").await;
    openapi.assert_status_ok();
    let openapi_body: Value = openapi.json();
    assert_eq!(openapi_body["openapi"], json!("3.1.0"));
    assert!(openapi_body["paths"]["/v1/evaluations"].is_object());
}

#[tokio::test]
async fn openapi_json_handler_denies_without_runtime_state_by_default() {
    let server = TestServer::new(registry_notary_server::api::public_router());

    server
        .get("/openapi.json")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn standalone_server_serves_docs_shell_without_auth() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let docs = server.get("/docs").await;
    docs.assert_status_ok();
    let docs_body = docs.text();
    assert!(docs_body.contains("Registry Notary API"));
    assert!(docs_body.contains("/openapi.json"));
    assert!(docs_body.contains("/docs/scalar.js"));
    assert!(docs_body.contains("X-Api-Key"));

    let bundle = server.get("/docs/scalar.js").await;
    bundle.assert_status_ok();
    let content_type = bundle
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("bundle content type");
    assert!(content_type.starts_with("application/javascript"));

    let denied_openapi = server.get("/openapi.json").await;
    denied_openapi.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn batch_evaluation_audit_records_per_item_target_model_context() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(registry_data_api_target_identifier_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "items": [
                { "target": person_identifier_target("national_id", "person-1") },
                { "target": person_identifier_target("national_id", "person-404") }
            ],
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["summary"]["succeeded"], json!(1));
    assert_eq!(body["summary"]["failed"], json!(1));
    assert_eq!(
        body["items"][1]["errors"][0]["code"],
        json!("evidence.not_available")
    );

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("person-404"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let batch_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/batch-evaluations")
                && record["decision"] == json!("batch_evaluate")
                && record["status"] == json!(200)
        })
        .expect("batch evaluation audit record exists");
    let items = batch_audit["batch_items"]
        .as_array()
        .expect("batch audit includes per-item metadata");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["input_index"], json!(0));
    assert_eq!(items[0]["target_type"], json!("Person"));
    assert!(items[0]["target_ref_hash"].as_str().is_some());
    assert_eq!(items[0]["matching_outcome"], json!("matched"));
    assert_eq!(
        items[0]["matching_policy_id"],
        json!("http-target-identifier-v1")
    );
    assert_eq!(items[0]["matching_method"], json!("exact_identifier"));
    assert_eq!(items[1]["input_index"], json!(1));
    assert_eq!(items[1]["matching_outcome"], json!("error"));
    assert_eq!(items[1]["matching_error_code"], json!("target.not_found"));
    assert!(items[1].get("target_ref_hash").is_none());
}

#[tokio::test]
async fn audit_chain_bootstraps_from_sink_tail() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );

    let first = TestServer::builder()
        .http_transport()
        .build(standalone_router(config.clone()).expect("first router builds"));
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A restart releases the single-writer audit lock: the first instance must
    // be fully torn down before the replacement acquires the lock (#211).
    drop(first);
    tokio::task::yield_now().await;

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
    second
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(
        verify_jsonl_lines_with_hasher(contents.lines(), &AuditChainHasher::unkeyed_dev_only())
            .is_err(),
        "runtime audit chain must not verify with the dev-only unkeyed hasher"
    );
    let hasher = AuditChainHasher::from_env_derived("REGISTRY_NOTARY_AUDIT_HASH_SECRET")
        .expect("configured audit chain secret loads");
    verify_jsonl_lines_with_hasher(contents.lines(), &hasher).expect("audit chain verifies");
    let envelopes = audit_envelopes(&audit_path);
    assert_eq!(envelopes.len(), 2);
    assert_eq!(envelopes[1].prev_hash, Some(envelopes[0].record_hash));
}

#[tokio::test]
async fn audit_chain_detects_inserted_envelope() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let first = TestServer::builder()
        .http_transport()
        .build(standalone_router(config.clone()).expect("first router builds"));
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    first
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A restart releases the single-writer audit lock before the replacement
    // instance acquires it (#211).
    drop(first);
    tokio::task::yield_now().await;

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    let mut lines = contents.lines().collect::<Vec<_>>();
    lines.insert(1, lines[0]);
    std::fs::write(&audit_path, format!("{}\n", lines.join("\n"))).expect("tampered audit write");

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
    let response = second
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("audit.write_failed"));
}

#[test]
#[cfg(feature = "registry-notary-cel")]
fn cel_worker_config_rejects_missing_command_without_path_leak() {
    let worker = CelWorker::lazy(CelWorkerConfig {
        command: "/registry-notary-test/missing-cel-worker".into(),
        ..CelWorkerConfig::for_current_exe_subcommand()
    });
    let error = worker
        .validate_config()
        .expect_err("worker rejects missing command path");

    let text = error.to_string();
    assert!(!text.contains("missing-cel-worker"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_startup_rejects_cel_expression_compile_error() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let bad_expression = "claims.farmed_land_size.value <";
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = bad_expression.to_string();

    let error = standalone_router(config).expect_err("router rejects invalid CEL expression");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains(bad_expression));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_startup_rejects_cel_unknown_root_reference() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = "credential.level == 'gold'".to_string();

    let error = standalone_router(config).expect_err("router rejects unsupported CEL root");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains("credential.level"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_startup_rejects_disabled_cel_mode_when_claims_use_cel() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.cel.mode = "disabled".to_string();

    let error = standalone_router(config).expect_err("router rejects disabled CEL mode");
    let text = error.to_string();
    assert!(text.contains("CEL claims require cel.mode = worker"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_startup_rejects_cel_regex_helpers_by_default() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let bad_expression = "text.regex_replace(source.farmer.total_farmed_area, '^3', '4') == '4.5'";
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = bad_expression.to_string();

    let error = standalone_router(config).expect_err("router rejects regex helper");
    let text = error.to_string();
    assert!(text.contains("invalid CEL"));
    assert!(!text.contains("text.regex_replace"));
    assert!(!text.contains("source-token"));
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_server_reads_dci_source_and_evaluates_cel_claim() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
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
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    let observed = observed
        .lock()
        .expect("observed request lock")
        .clone()
        .expect("DCI request captured");
    assert_eq!(observed["header"]["action"], "search");
    assert_eq!(observed["header"]["receiver_id"], "upstream-registry");
    assert_eq!(observed["signature"], "");
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["query_type"],
        "idtype-value"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["reg_event_type"],
        "birth"
    );
    assert_eq!(
        observed["message"]["search_request"][0]["search_criteria"]["pagination"]["page_number"],
        1
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
#[cfg(feature = "registry-notary-cel")]
async fn standalone_server_uses_dci_response_timestamp_for_source_freshness() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
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

    let mut config = dci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let connection = config
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer registry source exists");
    connection.dci.field_paths.insert(
        "observed_at".to_string(),
        "$response:/message/search_response/0/timestamp".to_string(),
    );
    let binding = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists")
        .source_bindings
        .get_mut("farmer")
        .expect("farmer binding exists");
    binding.matching.max_source_age_seconds = Some(60);
    binding.matching.source_observed_at_field = Some("observed_at".to_string());

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    for target_id in ["stale-person", "missing-timestamp"] {
        let response = server
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "target": person_target(target_id),
                "claims": ["farmed-land-size"],
                "disclosure": "value"
            }))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("pdp.evidence_stale"));
    }
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_server_reads_dci_source_by_demographic_target_attributes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let observed = Arc::new(Mutex::new(None));
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/dci/fr/registry/sync/search",
                post(civil_demographic_dci_source),
            )
            .with_state(Arc::clone(&observed)),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(civil_demographic_dci_config(
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
            "target": {
                "type": "Person",
                "attributes": {
                    "given_name": "Miguel",
                    "surname": "Santos",
                    "birth_date": "2016-01-15"
                }
            },
            "claims": ["civil-person-is-alive-by-demographics"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(true));
    assert_eq!(
        body["results"][0]["provenance"]["used"]["source_count"],
        json!(1)
    );

    let observed = observed
        .lock()
        .expect("observed request lock")
        .clone()
        .expect("DCI request captured");
    let criteria = &observed["message"]["search_request"][0]["search_criteria"];
    assert_eq!(criteria["query_type"], json!("predicate"));
    assert_eq!(criteria["reg_event_type"], json!("birth"));
    let query = criteria["query"]
        .as_array()
        .expect("predicate query is an array of expressions");
    assert_eq!(
        query[0]["expression1"]["attribute_name"],
        json!("given_name")
    );
    assert_eq!(query[0]["expression1"]["operator"], json!("eq"));
    assert_eq!(query[0]["expression1"]["attribute_value"], json!("Miguel"));
    assert_eq!(query[1]["expression2"]["attribute_name"], json!("surname"));
    assert_eq!(query[1]["expression2"]["attribute_value"], json!("Santos"));
    assert_eq!(
        query[2]["expression3"]["attribute_name"],
        json!("birth_date")
    );
    assert_eq!(
        query[2]["expression3"]["attribute_value"],
        json!("2016-01-15")
    );
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_server_rejects_cel_result_type_mismatch() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmer-under-4ha")
        .expect("CEL claim exists");
    let registry_notary_core::RuleConfig::Cel { expression, .. } = &mut claim.rule else {
        panic!("expected CEL claim");
    };
    *expression = "claims.farmed_land_size.value > 3.0 ? 'bad-type' : true".to_string();

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("claim.rule_evaluation_failed"));
    assert!(body["results"].is_null());
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn standalone_server_maps_dci_register_not_found_to_source_not_found() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/dci/fr/registry/sync/search", post(dci_source))
            .with_state(Arc::new(Mutex::new(None))),
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
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("openspp-missing"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("evidence.not_available"));
}

#[tokio::test]
async fn standalone_server_extract_claim_works_without_default_features() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
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
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
}

#[cfg(not(feature = "registry-notary-cel"))]
#[tokio::test]
async fn standalone_server_rejects_cel_claim_without_cel_feature() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/farmer_registry/entities/farmer/records",
            get(registry_data_api),
        ));
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

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-1"),
            "claims": ["farmer-under-4ha"],
            "disclosure": "redacted"
        }))
        .await;

    response.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("claim.operation_unsupported"));
}

#[test]
fn standalone_router_rejects_unknown_audit_sink() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.sink = "bogus".to_string();

    let error = standalone_router(config).expect_err("unknown audit sink is rejected");
    assert!(matches!(
        error,
        StandaloneServerError::InvalidAuditSink(sink) if sink == "bogus"
    ));
}

#[test]
fn standalone_router_rejects_missing_redis_replay_url_env() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::remove_var("TEST_REPLAY_REDIS_URL_MISSING");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_MISSING
  key_prefix: registry-notary-test
  connect_timeout_ms: 1
  operation_timeout_ms: 1
"#,
    )
    .expect("redis replay config parses");

    let error = standalone_router(config).expect_err("missing redis URL env is rejected");
    assert!(
        error.to_string().contains("TEST_REPLAY_REDIS_URL_MISSING"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn ready_fails_closed_when_redis_replay_store_is_unavailable() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL_UNAVAILABLE", "redis://127.0.0.1:1/");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_UNAVAILABLE
  key_prefix: registry-notary-test
  connect_timeout_ms: 10
  operation_timeout_ms: 10
"#,
    )
    .expect("redis replay config parses");

    let app = standalone_router(config).expect("router builds without opening Redis eagerly");
    let server = TestServer::builder().http_transport().build(app);

    let ready = server.get("/ready").await;

    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn ready_accepts_available_redis_replay_store_when_env_is_set() {
    let Ok(redis_url) = std::env::var("REGISTRY_NOTARY_REDIS_TEST_URL") else {
        return;
    };
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL_AVAILABLE", redis_url);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: TEST_REPLAY_REDIS_URL_AVAILABLE
  key_prefix: registry-notary-live-test
  connect_timeout_ms: 500
  operation_timeout_ms: 500
"#,
    )
    .expect("redis replay config parses");

    let app = standalone_router(config).expect("router builds without opening Redis eagerly");
    let server = TestServer::builder().http_transport().build(app);

    let ready = server.get("/ready").await;

    ready.assert_status_ok();
}

#[test]
fn audit_hasher_from_env_returns_err_when_unset() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::remove_var("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.hash_secret_env = Some("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET".to_string());

    let error = standalone_router(config).expect_err("unset audit hash secret fails closed");

    assert!(matches!(error, StandaloneServerError::Audit(_)));
    assert!(error
        .to_string()
        .contains("TEST_UNSET_REGISTRY_NOTARY_AUDIT_HASH_SECRET"));
}

#[test]
fn audit_hash_secret_env_is_required_for_runtime_config() {
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.audit.hash_secret_env = None;

    let error = standalone_router(config).expect_err("missing audit hash secret fails closed");

    assert!(matches!(
        error,
        StandaloneServerError::MissingAuditHashSecretEnv
    ));
}

// ---------------------------------------------------------------------------
// Pre-authorized-code flow (PR3): offer/start, offer/callback, token endpoint,
// the second trust anchor, abuse controls, and audit redaction.
// ---------------------------------------------------------------------------

// Dedicated access-token signing key, distinct from the credential key
// (TEST_ISSUER_JWK). Config validation rejects reusing a credential key.
const TEST_ACCESS_TOKEN_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
// eSignet RP client signing key (signs the private_key_jwt client assertion).
const TEST_ESIGNET_RP_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"EOLPz23yGd5Ju5e-PYybLE-YyvjgXLhGzS6XgmszzXs","x":"3v5jZ5rAf7KGvcC3zuKh6-ujgtA0ABa4jqmAWXq-S_c","alg":"EdDSA"}"#;
// Test-only 2048-bit RSA private JWK (kty=RSA, alg=RS256) for the eSignet RP
// client when the lab registers the Notary's RP client with an RSA key.
// Generated once with openssl and converted to a JWK; not a production key.
#[cfg(feature = "registry-notary-cel")]
const TEST_ESIGNET_RP_RSA_JWK: &str = r#"{"kty":"RSA","kid":"did:web:rp.example#esignet-rp-rsa-key","alg":"RS256","n":"uujuLM_PhTFXueBzTafeFW7O4kJgQnLIzuoHJQgaYDkCBbUYAznt-IZvGkyTTkg4mfolJj47HDlBsSNzzx7bYcFDKdBMoZQwukVX9bhkXVUPT9-fot1jfW0EPrvdJdDQ-5LjQYfk2a2OpKtV5hmBIxoHm_JRU3QOmKU0h1_vKjwStMO0ntaitIL7pSIE0X7Ht4P3edhBc5Vxf_-Ui7wSaN-jAjHCk6HYRY4BTODI-zo5K8yB5JERBqcawsuAIDPTjQ1eIOHxIQsTlsdbmSgqnMldoyZAkjxCyOm9Ad_rpbJ04WDaIhFxyaqHTVUD32cufcZFYxkSJ35zuIlJYgoebw","e":"AQAB","d":"EEvSyFFuFHzS2z_4jaK_ODsrCosi_WgonfHFobLtKcqOpJS_fTiFyQ9fjHl0tnSRistGhekTGkjbs2gV5s8X7ZP-GR0yMTxMa1E0dBYZmhGafipPLtICpKLmpdmXVH66WdTav5HroBcDwtO1b5R1r-vLEgu0j4Qk6aYtyEfTAGmKRzH9fk7crZwaM2MiklIWLaK6Gfior5KDrQhIMGfKZzu78naJ5FyFSHBUW0VvikTg0C8QbRgBuFbQCuOceu4UZhjySJUhugdgzlbnteVRc_VvSvusLL4i7fSeecRIXURSexUjraLifeh1lM_jrD8ZM-o_2Qop2ada12Asll4gkQ","p":"4QhhINnwbq_vuFTQL3Wx980l2eg8yocFS5hsmk7vbqAUbAZVSVOGW_y6ip-uG_c9xpYBvTyZAANUZHpqDyu0frPDdZplJZX2FTMkiHTg4RJQfj8OD0tmL370cGv3RRfO4md4-0E0wxl8Zsv4-PSVrMZCFyIk8TLgLZs1w7bpg0U","q":"1KGH6VP7TkA3hDXTlSL2GPShsGY0Y9P1Kn6mMA8aHIZ690QmeJU2j91oWcCP1AG6LnAp5pvxT0XJJu3OVsQs7OZPiUwAf_RoSdlMtm6xll1FkBKC3AtTLYn0vgHwFPeXa29wZM1khFv_vBdhk47ZgZT0G3f4Y88FHh5EM5EFPCM","dp":"0D332_WyWEu5c4QQ74pjuaP_XgpajzSpgs432ggn6-B5ZYnqzKNdl6xlV7jy3vBKG4Zfb6YvE-MA6saZdRaFviZOP3s0FLcUdYPRT_GQ1Nck498n_KFSm6tJOuu-dBLXIY6NVz19PPpNs7cX3BJCnBMPv-aZ9xaUe7_A3i9bIl0","dq":"gDDudp5aGSAgGEY3TGdqhTsfK_FCTpkf6sG2Qa0pKd9tzRs6MmKLJYrveYTdcYylCZA3wr9raUaCckTWrHrTNvPXKcg3WO0p3rPySt5LlIKhCK4QVMdDG2Zbth4G9y0aDfx-f1dQ7Xdlo6lY-5QYz8XUsabPiqTpyfGnXotk448","qi":"XlLiaiQDLYZXtyR1ixq3dJ1EqnBtHtx75VjpQydmb4yQMtzsQ1JS5xyRgv1gws8u5KVaF3h3CUo6wBrtKBFGIhL9WFnym_8DEECgVF7eLHZ6WNtnIv6Vs7vjO3CAPKG3TrIuaHhY5KXQf0za7criZ9Euai41_ky9_iU6j0Lw5CY"}"#;

const NOTARY_ISSUER: &str = "http://127.0.0.1:4325";
const NOTARY_AUDIENCE: &str = "registry-notary-citizen";
const ESIGNET_RP_CLIENT_ID: &str = "registry-lab-live-client";

fn set_preauth_env() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_ACCESS_TOKEN_JWK", TEST_ACCESS_TOKEN_JWK);
    std::env::set_var("TEST_ESIGNET_RP_JWK", TEST_ESIGNET_RP_JWK);
}

fn local_jwk_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    SigningKeyConfig {
        provider: SigningKeyProviderConfig::LocalJwkEnv,
        alg: SD_JWT_VC_SIGNING_ALG.to_string(),
        kid: kid.to_string(),
        status: SigningKeyStatus::Active,
        publish_until_unix_seconds: None,
        private_jwk_env: private_jwk_env.to_string(),
        public_jwk_env: String::new(),
        module_path: String::new(),
        token_label: String::new(),
        pin_env: String::new(),
        key_label: String::new(),
        key_id_hex: String::new(),
        path: String::new(),
        password_env: String::new(),
    }
}

/// A pre-auth-enabled config. eSignet `issuer`/`jwks_uri` point at the MockIdp;
/// the token endpoint points at `token_url` (a wiremock upstream). The
/// access-token signing key is dedicated (distinct from the credential key).
fn self_attestation_preauth_config(
    base_url: &str,
    audit_path: &str,
    esignet_issuer: &str,
    esignet_jwks_uri: &str,
    esignet_authorize_url: &str,
    esignet_token_url: &str,
) -> StandaloneRegistryNotaryConfig {
    // Reuse the eSignet issuer/jwks as the primary OIDC auth issuer so the
    // credential endpoint still accepts eSignet tokens on the unchanged path.
    let mut config =
        self_attestation_oid4vci_config(base_url, audit_path, esignet_issuer, esignet_jwks_uri);
    // The credential endpoint must be allowed to issue credentials for the
    // pre-auth happy path.
    config.self_attestation.allowed_operations.issue_credential = true;
    // The person-is-alive claim must support the SD-JWT VC format for OID4VCI
    // issuance (the base config only lists the claim-result format).
    for claim in config.evidence.claims.iter_mut() {
        if claim.id == "person-is-alive" {
            claim
                .formats
                .push(registry_notary_core::FORMAT_SD_JWT_VC.to_string());
        }
    }
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 3;
    config
        .self_attestation
        .rate_limits
        .invalid_token_per_client_address_per_minute = 50;
    // The Notary RP client id must be an accepted citizen client + audience so a
    // Notary-minted token classifies as self-attestation.
    config
        .self_attestation
        .citizen_clients
        .allowed_client_ids
        .push(ESIGNET_RP_CLIENT_ID.to_string());
    config
        .oid4vci
        .accepted_token_audiences
        .push(NOTARY_AUDIENCE.to_string());
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.allowed_clients.push(ESIGNET_RP_CLIENT_ID.to_string());
    }

    // Dedicated access-token signing key.
    config.evidence.signing_keys.insert(
        "access-token-key".to_string(),
        local_jwk_signing_key(
            "TEST_ACCESS_TOKEN_JWK",
            "did:web:issuer.example#access-token-key",
        ),
    );
    // eSignet RP client signing key.
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        local_jwk_signing_key("TEST_ESIGNET_RP_JWK", "did:web:rp.example#esignet-rp-key"),
    );

    config.auth.access_token_signing = serde_norway::from_str(&format!(
        r#"
enabled: true
issuer: {NOTARY_ISSUER}
audiences:
  - {NOTARY_AUDIENCE}
allowed_algorithms:
  - EdDSA
token_typ: registry-notary-access+jwt
signing_key_id: access-token-key
access_token_ttl_seconds: 300
"#
    ))
    .expect("access-token signing config parses");

    config.oid4vci.pre_authorized_code = serde_norway::from_str(&format!(
        r#"
enabled: true
tx_code:
  required: true
  input_mode: numeric
  length: 6
esignet:
  client_id: {ESIGNET_RP_CLIENT_ID}
  client_signing_key_id: esignet-rp-key
  redirect_uri: http://127.0.0.1:4325/oid4vci/offer/callback
  authorize_url: {esignet_authorize_url}
  token_url: {esignet_token_url}
  issuer: {esignet_issuer}
  jwks_uri: {esignet_jwks_uri}
  scopes:
    - openid
  login_state_ttl_seconds: 300
  allow_insecure_localhost: true
pre_authorized_code_ttl_seconds: 300
"#
    ))
    .expect("pre-auth config parses");
    config
}

/// Extract a query parameter from a URL.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Mint an eSignet id_token bound to the login nonce, with the civil-id claim.
fn esignet_id_token(idp: &MockIdp, nonce: &str, national_id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "nonce": nonce,
        "national_id": national_id,
        "scope": "openid self_attestation",
        "acr": "urn:example:loa:substantial",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }))
}

struct PreauthOfferPage {
    code: String,
    pin: Option<String>,
    offer: Value,
    html: String,
}

/// Drive offer/start + offer/callback, returning the rendered offer details.
async fn drive_offer_to_page(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> PreauthOfferPage {
    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");

    let id_token = esignet_id_token(idp, &nonce, national_id);
    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;

    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    callback.assert_status_ok();
    let html = callback.text();
    let offer_uri = extract_between(&html, "href=\"", "\"").expect("offer href present");
    let offer_json =
        query_param(&offer_uri, "credential_offer").expect("offer carries credential_offer");
    let offer: Value = serde_json::from_str(&offer_json).expect("offer is JSON");
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("offer carries pre-authorized_code")
        .to_string();
    let pin = extract_between(&html, "id=\"tx-code\">", "<");
    PreauthOfferPage {
        code,
        pin,
        offer,
        html,
    }
}

/// Drive offer/start + offer/callback, returning (pre_authorized_code, tx_code).
async fn drive_offer_to_code(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> (String, String) {
    let page = drive_offer_to_page(server, token_upstream, idp, national_id).await;
    let pin = page.pin.expect("offer page shows PIN");
    (page.code, pin)
}

fn extract_between(haystack: &str, start: &str, end: &str) -> Option<String> {
    let after = haystack.split_once(start)?.1;
    let value = after.split_once(end)?.0;
    Some(value.to_string())
}

async fn redeem_token(server: &TestServer, code: &str, pin: &str) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}&tx_code={}",
            urlencode(code),
            urlencode(pin),
        ))
        .await
}

async fn redeem_token_without_pin(server: &TestServer, code: &str) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}",
            urlencode(code)
        ))
        .await
}

fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Decode (without verifying) the JSON claims of a compact JWT's payload.
fn jwt_payload(jwt: &str) -> Value {
    let payload_b64 = jwt.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload is base64url");
    serde_json::from_slice(&bytes).expect("payload is JSON")
}

/// Decode (without verifying) the JOSE header of a compact JWT.
fn jwt_header(jwt: &str) -> Value {
    let header_b64 = jwt.split('.').next().expect("jwt has a header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("header is base64url");
    serde_json::from_slice(&bytes).expect("header is JSON")
}

/// Extract a field from an `application/x-www-form-urlencoded` body.
#[cfg(feature = "registry-notary-cel")]
fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

#[tokio::test]
async fn preauth_offer_start_redirects_to_esignet_and_mints_nothing() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("redirect location")
        .to_str()
        .expect("location is valid")
        .to_string();
    assert!(location.starts_with(&format!("{}/authorize", idp.issuer())));
    assert_eq!(
        query_param(&location, "response_type").as_deref(),
        Some("code")
    );
    assert_eq!(
        query_param(&location, "client_id").as_deref(),
        Some(ESIGNET_RP_CLIENT_ID)
    );
    assert_eq!(
        query_param(&location, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(query_param(&location, "state").is_some());
    assert!(query_param(&location, "nonce").is_some());
    assert!(query_param(&location, "claims").is_none());
    // No code or PIN is in the redirect; nothing is minted.
    assert!(!location.contains("pre-authorized_code"));

    // The audit log carries no minted material from a start.
    let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(!audit.contains("pre-authorized_code"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_offer_start_returns_429_when_login_state_store_is_full() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for _ in 0..4096 {
        server
            .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
            .await
            .assert_status(StatusCode::SEE_OTHER);
    }

    let limited = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.json::<Value>()["error"],
        json!("temporarily_unavailable")
    );
    idp.stop().await;
}

#[tokio::test]
async fn preauth_offer_start_requests_userinfo_subject_binding_claim_when_required() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    config.self_attestation.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("redirect location")
        .to_str()
        .expect("location is valid")
        .to_string();
    let claims =
        query_param(&location, "claims").expect("redirect requests required userinfo claim");
    let claims: Value = serde_json::from_str(&claims).expect("claims param is JSON");
    assert_eq!(
        claims,
        json!({
            "userinfo": {
                "individual_id": {
                    "essential": true
                }
            }
        })
    );
    assert!(!location.contains("pre-authorized_code"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_offer_start_rejects_unknown_configuration_id() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=unknown_config")
        .await;
    start.assert_status(StatusCode::BAD_REQUEST);
    idp.stop().await;
}

#[tokio::test]
async fn preauth_callback_mints_pre_authorized_offer_with_tx_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    assert!(!code.is_empty(), "callback mints a pre-authorized_code");
    assert_eq!(pin.len(), 6, "tx_code is a 6-digit PIN");
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_callback_omits_tx_code_when_optional() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let page = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    assert!(
        !page.code.is_empty(),
        "callback mints a pre-authorized_code"
    );
    assert!(page.pin.is_none(), "offer page does not show a PIN");
    assert!(
        !page.html.contains("id=\"tx-code\""),
        "optional tx_code mode omits the PIN block"
    );
    assert!(
        page.offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"]
            .is_null(),
        "credential offer omits the tx_code object"
    );
    idp.stop().await;
}

/// eSignet signs ID Tokens with a JOSE header that omits the optional `typ`
/// member (observed live: `{"alg":"PS256","kid":...}`). The pre-auth callback
/// must accept such an id_token and mint the offer. Regression guard for the
/// Wave 5 hosted blocker where a typ-less id_token was rejected as
/// `invalid_token` before the nonce/userinfo checks ran.
#[tokio::test]
async fn preauth_callback_accepts_esignet_id_token_without_typ_header() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");

    // Mint the eSignet id_token WITHOUT a `typ` header, as eSignet does.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let id_token = idp.mint_token_without_typ(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "nonce": nonce,
        "national_id": "person-1",
        "scope": "openid self_attestation",
        "acr": "urn:example:loa:substantial",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    // The test id_token must genuinely omit `typ` for this to exercise the fix.
    let header_b64 = id_token
        .split('.')
        .next()
        .expect("jwt has a header segment");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("header is base64url"),
    )
    .expect("header is JSON");
    assert!(
        header.get("typ").is_none(),
        "test id_token must omit the typ header"
    );

    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;

    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    callback.assert_status_ok();
    let html = callback.text();
    let offer_uri = extract_between(&html, "href=\"", "\"").expect("offer href present");
    let offer_json =
        query_param(&offer_uri, "credential_offer").expect("offer carries credential_offer");
    let offer: Value = serde_json::from_str(&offer_json).expect("offer is JSON");
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("offer carries pre-authorized_code");
    assert!(
        !code.is_empty(),
        "a typ-less eSignet id_token still mints a pre-authorized_code"
    );
    idp.stop().await;
}

/// When the eSignet RP client signing key is RS256, the `private_key_jwt`
/// client assertion the Notary sends to the eSignet token endpoint must carry
/// header `alg: RS256` and verify against the RP RSA public key. This proves the
/// RS256 RP key path end to end: the callback exchanges the eSignet code, which
/// signs the assertion with the configured RS256 key.
#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn preauth_client_assertion_is_rs256_signed_when_rp_key_is_rsa() {
    set_preauth_env();
    std::env::set_var("TEST_ESIGNET_RP_RSA_JWK", TEST_ESIGNET_RP_RSA_JWK);
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    // Swap the eSignet RP client signing key for an RSA/RS256 key.
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: "RS256".to_string(),
            kid: "did:web:rp.example#esignet-rp-rsa-key".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "TEST_ESIGNET_RP_RSA_JWK".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, _pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    assert!(!code.is_empty(), "callback mints a pre-authorized_code");

    // Capture the token-endpoint POST the Notary sent and pull out the
    // client_assertion form field.
    let requests = token_upstream
        .wiremock_server()
        .received_requests()
        .await
        .expect("wiremock records requests");
    let token_request = requests
        .iter()
        .find(|request| request.url.path() == "/token")
        .expect("the Notary posts to the eSignet token endpoint");
    let body = String::from_utf8(token_request.body.clone()).expect("token request body is UTF-8");
    let client_assertion = form_field(&body, "client_assertion")
        .expect("the token request carries a client_assertion");

    // The JOSE header alg must be RS256 (derived from the RP RSA key).
    let header = jwt_header(&client_assertion);
    assert_eq!(
        header["alg"], "RS256",
        "the client assertion is signed with the RP key's RS256 algorithm"
    );
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "did:web:rp.example#esignet-rp-rsa-key");

    // The signature must verify against the RP RSA public key.
    let rp_private = PrivateJwk::parse(TEST_ESIGNET_RP_RSA_JWK).expect("RP RSA JWK parses");
    let rp_public = rp_private.public();
    let mut segments = client_assertion.split('.');
    let header_b64 = segments.next().expect("assertion has a header segment");
    let payload_b64 = segments.next().expect("assertion has a payload segment");
    let signature_b64 = segments.next().expect("assertion has a signature segment");
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .expect("signature is base64url");
    verify(signing_input.as_bytes(), &signature, &rp_public)
        .expect("the RS256 client assertion verifies against the RP RSA public key");

    idp.stop().await;
}

#[tokio::test]
async fn preauth_token_endpoint_issues_access_token_and_c_nonce() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let body: Value = token.json();
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], json!("Bearer"));
    assert!(body["c_nonce"].is_string());
    assert_eq!(body["expires_in"], json!(300));

    let access_token = body["access_token"].as_str().expect("access token minted");
    let claims = jwt_payload(access_token);
    assert_eq!(
        claims["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    let scopes: BTreeSet<&str> = claims["scope"]
        .as_str()
        .expect("scope claim is present")
        .split(' ')
        .collect();
    assert!(scopes.contains("self_attestation"));
    assert!(scopes.contains("person-is-alive"));
    assert_eq!(
        claims["authorization_details"][0]["type"],
        json!("registry_notary_evidence_transaction")
    );
    assert_eq!(
        claims["authorization_details"][0]["schema_version"],
        json!("registry-notary-authorization-details/v1")
    );
    assert_eq!(
        claims["authorization_details"][0]["actions"],
        json!(["evaluate"])
    );
    assert_eq!(
        claims["authorization_details"][0]["locations"],
        json!(["evidence.test"])
    );
    assert_eq!(
        claims["authorization_details"][0]["claims"][0]["id"],
        json!("person-is-alive")
    );
    assert_eq!(
        claims["authorization_details"][0]["disclosure"],
        json!("value")
    );
    assert_eq!(
        claims["authorization_details"][0]["format"],
        json!("application/dc+sd-jwt")
    );
    assert_eq!(
        claims["authorization_details"][0]["purpose"],
        json!("citizen_self_attestation")
    );
    assert_eq!(
        claims["authorization_details"][0]["access_mode"],
        json!("self_attestation")
    );
    assert_eq!(
        claims["authorization_details"][0]["subject"],
        json!({
            "binding_claim": "national_id",
            "id_type": "national_id"
        })
    );
    idp.stop().await;
}

/// Issue #173: when the access-token signing key and a credential-profile
/// signing key resolve to the same Ed25519 material under distinct ids and
/// kids, server startup must fail through the real build path
/// (`compile_notary_runtime` -> `SigningKeyRegistry::from_config`), not just the
/// in-isolation helper. The eSignet RP client key is excluded from this scope by
/// `admin_config_apply_signed_preauth_signing_rotation_preserves_inflight_tokens`.
#[tokio::test]
async fn compile_rejects_access_token_key_reusing_credential_key_material() {
    set_preauth_env();
    // A dedicated env var bound to the credential issuer's material. The
    // credential `issuer-key` resolves from `TEST_SELF_ATTESTATION_ISSUER_JWK`,
    // which `set_preauth_env` also sets to `TEST_ISSUER_JWK`, so the new
    // access-token key reuses the credential key material under a distinct
    // id/kid.
    std::env::set_var("TEST_ACCESS_TOKEN_REUSES_CREDENTIAL_JWK", TEST_ISSUER_JWK);
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    );
    config.evidence.signing_keys.insert(
        "access-token-key-reuses-credential".to_string(),
        local_jwk_signing_key(
            "TEST_ACCESS_TOKEN_REUSES_CREDENTIAL_JWK",
            "did:web:issuer.example#access-token-key-reuses-credential",
        ),
    );
    config.auth.access_token_signing.signing_key_id =
        "access-token-key-reuses-credential".to_string();

    let error = match compile_notary_runtime(config) {
        Ok(_) => panic!("reused signing key material must fail startup"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("reuses public key material"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("access-token-key-reuses-credential") || message.contains("issuer-key"),
        "error must name the colliding signing key ids: {message}"
    );
    // The error must never leak key material (thumbprint or raw JWK coordinate).
    assert!(
        !message.contains(TEST_ISSUER_JWK),
        "error must not contain raw key material"
    );
    idp.stop().await;
}

/// A userinfo-sourced subject binding (`claim_source = userinfo`) reads the
/// binding claim from the eSignet userinfo JWS, not the `id_token`. This mirrors
/// the hosted lab, where eSignet delivers `individual_id` only via userinfo.
#[tokio::test]
async fn preauth_callback_binds_subject_from_userinfo_when_claim_source_is_userinfo() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    config.self_attestation.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // The id_token (minted by drive_offer_to_code) carries no individual_id;
    // the userinfo JWS supplies it, bound to the same subject.
    let userinfo = idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "individual_id": "civil-id-9001",
    }));
    token_upstream
        .expect("GET", "/userinfo")
        .respond_body(200, userinfo)
        .await;

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let body: Value = token.json();
    let access_token = body["access_token"].as_str().expect("access token minted");
    let claims = jwt_payload(access_token);
    assert_eq!(
        claims["individual_id"],
        json!("civil-id-9001"),
        "subject binding must come from the userinfo JWS, not the id_token"
    );
    idp.stop().await;
}

/// When the subject binding is userinfo-sourced but the userinfo JWS omits the
/// binding claim, the callback denies the login and mints no code.
#[tokio::test]
async fn preauth_callback_denies_when_userinfo_lacks_subject_binding_claim() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    config.self_attestation.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // userinfo JWS bound to the subject but without the binding claim.
    let userinfo = idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
    }));
    token_upstream
        .expect("GET", "/userinfo")
        .respond_body(200, userinfo)
        .await;

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");
    let id_token = esignet_id_token(&idp, &nonce, "person-1");
    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;
    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    assert_ne!(
        callback.status_code(),
        StatusCode::OK,
        "a userinfo response missing the binding claim must deny the callback"
    );
    idp.stop().await;
}

#[tokio::test]
async fn preauth_code_is_single_use() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    redeem_token(&server, &code, &pin).await.assert_status_ok();
    let second = redeem_token(&server, &code, &pin).await;
    second.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = second.json();
    assert_eq!(body["error"], json!("invalid_grant"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_token_rejects_wrong_and_missing_tx_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, _pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;

    let wrong_pin = redeem_token(&server, &code, "000000").await;
    wrong_pin.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        wrong_pin.json::<Value>()["error"],
        json!("invalid_grant"),
        "a wrong tx_code is rejected"
    );

    let missing_pin = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}",
            urlencode(&code)
        ))
        .await;
    missing_pin.assert_status(StatusCode::BAD_REQUEST);
    idp.stop().await;
}

#[tokio::test]
async fn preauth_token_accepts_missing_tx_code_when_optional() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let page = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    assert!(
        page.pin.is_none(),
        "optional tx_code mode does not mint a PIN"
    );
    redeem_token_without_pin(&server, &page.code)
        .await
        .assert_status_ok();

    let second = redeem_token_without_pin(&server, &page.code).await;
    second.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(second.json::<Value>()["error"], json!("invalid_grant"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_repeated_wrong_pins_lock_the_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 2;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;

    // Two wrong attempts are within the cap; the third trips the limiter and the
    // code is locked, so even the correct PIN now fails.
    redeem_token(&server, &code, "111111")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    redeem_token(&server, &code, "222222")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let locked = redeem_token(&server, &code, &pin).await;
    locked.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: Value = locked.json();
    assert_eq!(body["error"], json!("slow_down"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_token_rejects_wrong_and_missing_grant_cleanly() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let other_grant = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("grant_type=authorization_code&code=abc")
        .await;
    other_grant.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        other_grant.json::<Value>()["error"],
        json!("unsupported_grant_type")
    );

    let missing_grant = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("foo=bar")
        .await;
    missing_grant.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_grant.json::<Value>()["error"],
        json!("invalid_request")
    );
    idp.stop().await;
}

#[tokio::test]
async fn preauth_random_code_flood_is_throttled_per_client_address() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config
        .self_attestation
        .rate_limits
        .invalid_token_per_client_address_per_minute = 2;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Random codes from one socket peer: caller-supplied forwarding headers do
    // not create fresh buckets.
    let flood = |code: &str, forwarded_for: &str| {
        server
            .post("/oid4vci/token")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .add_header("x-forwarded-for", forwarded_for)
            .text(format!(
                "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={code}&tx_code=000000"
            ))
    };
    flood("random-a", "203.0.113.50")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    flood("random-b", "203.0.113.51")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let throttled = flood("random-c", "203.0.113.52").await;
    throttled.assert_status(StatusCode::TOO_MANY_REQUESTS);
    idp.stop().await;
}

#[tokio::test]
async fn preauth_disabled_returns_404_and_offer_is_authorization_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    // Default config: pre-auth disabled.
    let app = standalone_router(self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/oid4vci/offer/callback?code=x&state=y")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=x&tx_code=1")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Offers fall back to authorization_code.
    let offer = server.get("/oid4vci/credential-offer").await;
    offer.assert_status_ok();
    let body: Value = offer.json();
    assert!(body["grants"]["authorization_code"].is_object());
    assert!(body["grants"]
        .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        .is_none());

    // Issuer metadata advertises no token endpoint when pre-auth is disabled.
    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert!(
        metadata_body.get("token_endpoint").is_none(),
        "disabled pre-auth must not advertise a token endpoint"
    );
    idp.stop().await;
}

/// Manually mint a Notary access token (header.payload.signature) so trust-anchor
/// tests can sign with the access-token key, the credential key, or a wrong key.
fn mint_notary_access_token(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
) -> String {
    mint_notary_access_token_with_scope_and_authorization_details(
        private_jwk,
        kid,
        typ,
        issuer,
        national_id,
        "self_attestation",
        None,
    )
}

fn mint_notary_access_token_with_scope_and_authorization_details(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
    scope: &str,
    authorization_details: Option<Value>,
) -> String {
    mint_notary_access_token_with_jti_scope_and_authorization_details(
        private_jwk,
        kid,
        typ,
        issuer,
        national_id,
        None,
        scope,
        authorization_details,
    )
}

#[allow(clippy::too_many_arguments)]
fn mint_notary_access_token_with_jti_scope_and_authorization_details(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
    jti: Option<&str>,
    scope: &str,
    authorization_details: Option<Value>,
) -> String {
    let key = PrivateJwk::parse(private_jwk).expect("test JWK parses");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let header = json!({ "alg": "EdDSA", "typ": typ, "kid": kid });
    let mut payload = json!({
        "iss": issuer,
        "aud": NOTARY_AUDIENCE,
        "sub": "esignet-citizen-subject",
        "client_id": ESIGNET_RP_CLIENT_ID,
        "scope": scope,
        "national_id": national_id,
        "token_type": "Bearer",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    });
    if let Some(jti) = jti {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("jti".to_string(), json!(jti));
    }
    if let Some(authorization_details) = authorization_details {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("authorization_details".to_string(), authorization_details);
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), &key).expect("token signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn preauth_test_config(
    base_url: &str,
    audit_path: &str,
    idp: &MockIdp,
    token_upstream: &MockHttpUpstream,
) -> StandaloneRegistryNotaryConfig {
    self_attestation_preauth_config(
        base_url,
        audit_path,
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    )
}

#[tokio::test]
async fn preauth_trust_anchor_rejects_wrong_key_and_credential_key_notary_tokens() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Use a protected route without a proof precheck, so the trust-anchor
    // verification alone decides the outcome.
    // A Notary-issuer token signed by the WRONG key (the holder key) is rejected.
    let wrong_key_token = mint_notary_access_token(
        TEST_HOLDER_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
    );
    server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {wrong_key_token}"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A Notary-issuer token signed by the CREDENTIAL key is rejected (the second
    // anchor verifies only against the dedicated access-token key).
    let credential_key_token = mint_notary_access_token(
        TEST_ISSUER_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
    );
    server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {credential_key_token}"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    idp.stop().await;
}

#[tokio::test]
async fn preauth_transaction_token_jti_denials_are_stable_and_redacted() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    );
    config.auth.access_token_signing.token_typ = NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string();
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let missing_jti_token = mint_notary_access_token(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        NOTARY_ISSUER,
        "person-1",
    );
    let missing_jti = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {missing_jti_token}"))
        .await;
    missing_jti.assert_status(StatusCode::UNAUTHORIZED);
    let missing_jti_body: Value = missing_jti.json();
    assert_eq!(missing_jti_body["code"], json!("auth.missing_credential"));
    assert!(missing_jti_body.get("data").is_none());
    assert!(!missing_jti_body.to_string().contains(&missing_jti_token));

    let replay_token = mint_notary_access_token_with_jti_scope_and_authorization_details(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        NOTARY_ISSUER,
        "person-1",
        Some("txn-jti-http-replay-1"),
        "self_attestation",
        Some(json!([{
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["evidence.test"]
        }])),
    );
    let first_use = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    first_use.assert_status_ok();
    let first_use_body: Value = first_use.json();
    assert!(first_use_body["data"].is_array());

    let replay = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    replay.assert_status(StatusCode::UNAUTHORIZED);
    let replay_body: Value = replay.json();
    assert_eq!(replay_body["code"], json!("auth.missing_credential"));
    assert!(replay_body.get("data").is_none());
    assert!(!replay_body.to_string().contains(&replay_token));
    assert!(!replay_body.to_string().contains("txn-jti-http-replay-1"));

    let multi_auth = server
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    multi_auth.assert_status(StatusCode::BAD_REQUEST);
    let multi_auth_body: Value = multi_auth.json();
    assert_eq!(multi_auth_body["code"], json!("auth.multiple_credentials"));
    assert!(multi_auth_body.get("data").is_none());
    assert!(!multi_auth_body.to_string().contains(&replay_token));
    assert!(!multi_auth_body.to_string().contains("api-token"));
    assert!(!multi_auth_body
        .to_string()
        .contains("txn-jti-http-replay-1"));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains(&missing_jti_token));
    assert!(!audit.contains(&replay_token));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("txn-jti-http-replay-1"));
    assert!(!audit.contains("person-1"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    assert!(records
        .iter()
        .any(|record| record["path"] == json!("/v1/claims") && record["status"] == json!(200)));
    let missing_credential_denials = records
        .iter()
        .filter(|record| {
            record["path"] == json!("/v1/claims")
                && record["status"] == json!(401)
                && record["error_code"] == json!("auth.missing_credential")
        })
        .count();
    assert!(
        missing_credential_denials >= 2,
        "missing-jti and replay denials should both be audited: {records:?}"
    );
    assert!(records.iter().any(|record| {
        record["path"] == json!("/v1/claims")
            && record["status"] == json!(400)
            && record["error_code"] == json!("auth.multiple_credentials")
    }));

    idp.stop().await;
}

#[tokio::test]
async fn preauth_trust_anchor_isolates_esignet_and_notary_paths() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // A token claiming the Notary issuer but actually an eSignet-minted token
    // fails: the Notary anchor verifies it against the access-token key only.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let esignet_token_claiming_notary_iss = idp.mint_token(json!({
        "iss": NOTARY_ISSUER,
        "sub": "esignet-citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": ESIGNET_RP_CLIENT_ID,
        "scope": "self_attestation",
        "national_id": "person-1",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    server
        .get("/v1/claims")
        .add_header(
            "authorization",
            format!("Bearer {esignet_token_claiming_notary_iss}"),
        )
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    idp.stop().await;
}

#[tokio::test]
async fn preauth_existing_esignet_token_still_authenticates_credential_endpoint() {
    // The unchanged eSignet single-issuer path still accepts an eSignet token.
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    // An eSignet-issued token (issuer == eSignet) on the unchanged path.
    let esignet_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    // It passes the protected JWKS route (auth succeeds) on the eSignet path.
    let jwks = server
        .get("/.well-known/evidence/jwks.json")
        .add_header("authorization", format!("Bearer {esignet_token}"))
        .await;
    jwks.assert_status_ok();
    idp.stop().await;
}

#[tokio::test]
async fn preauth_notary_access_token_with_empty_authorization_details_cannot_issue_credential() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let old_shape_token = mint_notary_access_token_with_scope_and_authorization_details(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
        "self_attestation person-is-alive",
        Some(json!([])),
    );
    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let c_nonce = nonce.json::<Value>()["c_nonce"]
        .as_str()
        .expect("nonce returned")
        .to_string();
    let proof = sign_oid4vci_proof(NOTARY_ISSUER, &c_nonce);

    let credential = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {old_shape_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": { "proof_type": "jwt", "jwt": proof }
        }))
        .await;

    credential.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(credential.json::<Value>()["error"], json!("access_denied"));
    idp.stop().await;
}

#[tokio::test]
async fn preauth_end_to_end_issues_sd_jwt_vc_bound_to_holder() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Issuer metadata advertises the Notary token endpoint when pre-auth is
    // enabled, so a wallet discovers it can redeem the pre-authorized_code grant.
    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(
        metadata_body["token_endpoint"],
        json!("http://127.0.0.1:4325/oid4vci/token"),
        "enabled pre-auth advertises the Notary token endpoint"
    );

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let token_body: Value = token.json();
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();
    let c_nonce = token_body["c_nonce"]
        .as_str()
        .expect("c_nonce issued")
        .to_string();

    // The Notary-minted token is accepted at the credential endpoint and issues
    // an SD-JWT VC bound to the holder's did:jwk proof.
    let proof = sign_oid4vci_proof(NOTARY_ISSUER, &c_nonce);
    let credential = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": { "proof_type": "jwt", "jwt": proof }
        }))
        .await;
    credential.assert_status_ok();
    let credential_body: Value = credential.json();
    let sd_jwt = credential_body["credential"]
        .as_str()
        .expect("credential issued");
    assert!(sd_jwt.contains('~'), "an SD-JWT VC carries disclosures");
    let payload = decode_sd_jwt_payload(sd_jwt);
    assert!(
        payload["issuanceDate"].as_str().is_some(),
        "wallet-compatible issuance date alias is present"
    );
    assert!(
        payload["expirationDate"].as_str().is_some(),
        "wallet-compatible expiration date alias is present"
    );
    idp.stop().await;
}

/// Decode the SD-JWT VC issuer JWS payload (the segment before the first `~`).
fn decode_sd_jwt_payload(sd_jwt: &str) -> Value {
    let issuer_jws = sd_jwt
        .split('~')
        .next()
        .expect("SD-JWT contains an issuer JWS");
    let payload_segment = issuer_jws
        .split('.')
        .nth(1)
        .expect("issuer JWS contains a payload segment");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("issuer JWS payload is base64url"),
    )
    .expect("issuer JWS payload is JSON")
}

/// Decode the SD-JWT VC disclosure for `claim_name` and return its value object.
/// A disclosure is `base64url([salt, name, value])`; the value is the evaluated
/// claim result.
fn decode_disclosed_claim(sd_jwt: &str, claim_name: &str) -> Value {
    sd_jwt
        .split('~')
        .skip(1)
        .filter(|part| !part.is_empty())
        .find_map(|part| {
            let decoded = URL_SAFE_NO_PAD.decode(part).ok()?;
            let triple: Value = serde_json::from_slice(&decoded).ok()?;
            (triple.get(1).and_then(Value::as_str) == Some(claim_name))
                .then(|| triple.get(2).cloned())
                .flatten()
        })
        .unwrap_or_else(|| panic!("disclosure for {claim_name} is present"))
}

/// The evaluated-claim fields that must be stable across issuance paths. The
/// `issued_at` timestamp legitimately differs between two evaluations, so it is
/// excluded from the parity comparison.
fn semantic_claim_fields(disclosure_value: &Value) -> Value {
    json!({
        "claim_id": disclosure_value["claim_id"],
        "version": disclosure_value["version"],
        "value": disclosure_value["value"],
        "satisfied": disclosure_value["satisfied"],
        "subject_type": disclosure_value["subject_type"],
    })
}

/// Find the single `credential_issued` audit record for the OID4VCI credential
/// endpoint. Its `target_ref_hash`/`requester_ref_hash` are HMACs over the
/// bound subject reference, deterministic for a fixed audit secret, so two paths
/// that bind the same eSignet subject produce identical hashes.
fn credential_issued_audit(audit_path: &std::path::Path) -> Value {
    audit_envelopes(audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .find(|record| {
            record["path"] == json!("/oid4vci/credential")
                && record["decision"] == json!("credential_issued")
                && record["status"] == json!(200)
        })
        .expect("credential_issued audit record exists")
}

/// The semantic capstone. Drive the full pre-authorized-code path and compare
/// the issued credential to the one the existing eSignet-token path produces for
/// the same eSignet-authenticated subject and the same configuration.
///
/// It asserts two properties that a shape check cannot:
///
/// 1. Subject equality: both paths bind the same eSignet `subject_binding` value
///    (the civil id), proven by identical, secret-keyed `target_ref_hash` /
///    `requester_ref_hash` audit hashes. The raw civil id is never logged, so the
///    hash is the only observable subject handle, and matching it proves the
///    pre-auth credential is bound to the eSignet subject, not the holder key
///    alone.
/// 2. Evaluation parity: the disclosed `person-is-alive` claim result is
///    byte-identical across the two paths (claim_id, version, value, satisfied,
///    subject_type), proving the pre-auth path yields an equivalent credential,
///    not merely a well-shaped one.
#[tokio::test]
async fn preauth_credential_subject_and_evaluation_match_esignet_token_path() {
    set_preauth_env();

    // The eSignet-token (auth-code) baseline: an eSignet token whose
    // subject-binding claim is the same civil id the pre-auth login carries.
    let baseline_idp = MockIdp::start().await;
    let baseline_token_upstream = MockHttpUpstream::start().await;
    let baseline_upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let baseline_base_url = baseline_upstream
        .server_address()
        .expect("baseline upstream address")
        .to_string();
    let baseline_tmp = TempDir::new().expect("tempdir");
    let baseline_audit_path = baseline_tmp.path().join("audit.jsonl");
    let baseline_app = standalone_router(preauth_test_config(
        baseline_base_url.trim_end_matches('/'),
        baseline_audit_path.to_str().expect("audit path is UTF-8"),
        &baseline_idp,
        &baseline_token_upstream,
    ))
    .expect("baseline router builds");
    let baseline_server = TestServer::builder().http_transport().build(baseline_app);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    // An eSignet-issued token bound to civil id "person-1" via national_id.
    let esignet_token = baseline_idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let baseline_nonce = baseline_server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    baseline_nonce.assert_status_ok();
    let baseline_nonce = baseline_nonce.json::<Value>()["c_nonce"]
        .as_str()
        .expect("nonce returned")
        .to_string();
    let baseline_proof = sign_oid4vci_proof(NOTARY_ISSUER, &baseline_nonce);
    let baseline_credential = baseline_server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {esignet_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": { "proof_type": "jwt", "jwt": baseline_proof }
        }))
        .await;
    baseline_credential.assert_status_ok();
    let baseline_sd_jwt = baseline_credential.json::<Value>()["credential"]
        .as_str()
        .expect("baseline credential issued")
        .to_string();
    let baseline_audit = credential_issued_audit(&baseline_audit_path);
    assert_eq!(
        baseline_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    baseline_idp.stop().await;

    // The pre-authorized-code path: the same civil id arrives through the eSignet
    // login leg (the offer/start -> callback -> token chain).
    let preauth_idp = MockIdp::start().await;
    let preauth_token_upstream = MockHttpUpstream::start().await;
    let preauth_upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let preauth_base_url = preauth_upstream
        .server_address()
        .expect("preauth upstream address")
        .to_string();
    let preauth_tmp = TempDir::new().expect("tempdir");
    let preauth_audit_path = preauth_tmp.path().join("audit.jsonl");
    let preauth_app = standalone_router(preauth_test_config(
        preauth_base_url.trim_end_matches('/'),
        preauth_audit_path.to_str().expect("audit path is UTF-8"),
        &preauth_idp,
        &preauth_token_upstream,
    ))
    .expect("preauth router builds");
    let preauth_server = TestServer::builder().http_transport().build(preauth_app);

    let (code, pin) = drive_offer_to_code(
        &preauth_server,
        &preauth_token_upstream,
        &preauth_idp,
        "person-1",
    )
    .await;
    let token = redeem_token(&preauth_server, &code, &pin).await;
    token.assert_status_ok();
    let token_body: Value = token.json();
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();
    let c_nonce = token_body["c_nonce"]
        .as_str()
        .expect("c_nonce issued")
        .to_string();
    let preauth_proof = sign_oid4vci_proof_without_iss(NOTARY_ISSUER, &c_nonce);
    let preauth_credential = preauth_server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "vct": "http://127.0.0.1:4325/credentials/civil-status",
            "display": [{ "name": "Person is alive" }],
            "credential_signing_alg_values_supported": ["EdDSA"],
            "proof": {
                "proof_type": "jwt",
                "jwt": preauth_proof,
                "subject": "person-1"
            }
        }))
        .await;
    preauth_credential.assert_status_ok();
    let preauth_sd_jwt = preauth_credential.json::<Value>()["credential"]
        .as_str()
        .expect("preauth credential issued")
        .to_string();
    let preauth_audit = credential_issued_audit(&preauth_audit_path);
    assert_eq!(
        preauth_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    preauth_idp.stop().await;

    // Subject equality: the pre-auth credential is bound to the eSignet subject,
    // not the holder key alone. The secret-keyed audit hash over the bound
    // subject reference is identical to the eSignet-token path, which it can be
    // only if both bound the same civil id.
    assert!(
        baseline_audit["target_ref_hash"].as_str().is_some(),
        "baseline credential audit hashes the bound subject"
    );
    assert_eq!(
        preauth_audit["target_ref_hash"], baseline_audit["target_ref_hash"],
        "pre-auth credential subject must equal the eSignet subject_binding value"
    );
    assert_eq!(
        preauth_audit["requester_ref_hash"], baseline_audit["requester_ref_hash"],
        "pre-auth requester must equal the eSignet-token path requester"
    );
    assert_eq!(preauth_audit["target_type"], baseline_audit["target_type"]);

    // The holder binding is independent of the access token: both credentials are
    // bound to the same holder did:jwk proof key via `cnf`/`sub`.
    let baseline_payload = decode_sd_jwt_payload(&baseline_sd_jwt);
    let preauth_payload = decode_sd_jwt_payload(&preauth_sd_jwt);
    assert_eq!(
        preauth_payload["cnf"], baseline_payload["cnf"],
        "holder binding comes from the did:jwk proof, identical across paths"
    );
    assert_eq!(preauth_payload["vct"], baseline_payload["vct"]);
    // The registry subject ref is deliberately never exposed in the payload.
    assert!(
        !preauth_payload.to_string().contains("person-1"),
        "the raw civil id must not appear in the credential payload"
    );

    // Evaluation parity: the disclosed person-is-alive result is identical.
    let baseline_claim = decode_disclosed_claim(&baseline_sd_jwt, "person-is-alive");
    let preauth_claim = decode_disclosed_claim(&preauth_sd_jwt, "person-is-alive");
    assert_eq!(
        semantic_claim_fields(&preauth_claim),
        semantic_claim_fields(&baseline_claim),
        "the evaluated claim result must be identical to the eSignet-token path"
    );
    assert_eq!(preauth_claim["claim_id"], json!("person-is-alive"));
    assert_eq!(preauth_claim["value"], json!(true));
    assert_eq!(preauth_claim["satisfied"], json!(true));
}

#[tokio::test]
async fn preauth_callback_and_token_audit_events_carry_only_hashes() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    redeem_token(&server, &code, &pin).await.assert_status_ok();

    let audit = std::fs::read_to_string(&audit_path).expect("audit written");
    // The raw code, PIN, civil id, and eSignet code never appear in the audit.
    assert!(
        !audit.contains(&code),
        "raw pre-authorized_code must not be logged"
    );
    assert!(!audit.contains(&pin), "raw tx_code must not be logged");
    assert!(!audit.contains("person-1"), "civil id must not be logged");
    assert!(
        !audit.contains("esignet-code-123"),
        "eSignet code must not be logged"
    );

    // The callback and token audit events are present, hashed-only.
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let callback = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/offer/callback")
                && record["decision"] == json!("preauth_offer_minted")
        })
        .expect("callback audit event exists");
    assert_eq!(callback["status"], json!(200));
    assert_eq!(
        callback["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    let token_event = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/token")
                && record["decision"] == json!("preauth_token_issued")
        })
        .expect("token audit event exists");
    assert_eq!(token_event["status"], json!(200));
    idp.stop().await;
}

#[tokio::test]
async fn request_uri_limit_414_carries_server_owned_request_id() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let long_path = format!("/{}", "a".repeat(8 * 1024 + 1));

    let response = server
        .get(&long_path)
        .add_header("x-request-id", "client-supplied-id")
        .await;

    response.assert_status(StatusCode::URI_TOO_LONG);
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "client-supplied-id");
}

#[tokio::test]
async fn request_body_limit_413_carries_server_owned_request_id() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .expect("standalone router builds");
    let server = TestServer::new(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .add_header(header::CONTENT_LENGTH, "1048577")
        .add_header("x-request-id", "client-supplied-id")
        .await;

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "client-supplied-id");
}
