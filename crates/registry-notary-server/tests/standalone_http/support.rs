// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary tests that do not link Registry Relay.

pub(super) use axum::body::Bytes;
pub(super) use axum::http::{header, Method, StatusCode};
pub(super) use axum::routing::get;
pub(super) use axum::Router;
pub(super) use axum_test::TestServer;
pub(super) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(super) use base64::Engine;
pub(super) use registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP;
#[cfg(feature = "registry-notary-cel")]
pub(super) use registry_notary_core::FEDERATION_RESPONSE_JWT_TYP;
pub(super) use registry_notary_core::{
    ConfigTrustConfig, CredentialProfileConfig, EvidenceAuthMode, EvidenceCredentialConfig,
    EvidenceOidcAuthConfig, Oid4vciConfig, RegistryNotaryAdminListenerMode,
    SelfAttestationClaimSource, SigningKeyConfig, SigningKeyProviderConfig, SigningKeyStatus,
    StandaloneRegistryNotaryConfig, SD_JWT_VC_SIGNING_ALG,
};
#[cfg(feature = "registry-notary-cel")]
pub(super) use registry_notary_core::{Oid4vciCredentialClaimConfig, RuleConfig};
pub(super) use registry_notary_server::{
    compile_notary_runtime, notary_routers_from_runtime, openapi_document, standalone_router,
};
pub(super) use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditEnvelope,
};
pub(super) use registry_platform_authcommon::{
    CredentialFingerprintProvider, CredentialFingerprintRef,
};
#[cfg(feature = "registry-notary-cel")]
pub(super) use registry_platform_crypto::{did_jwk_from_public_jwk, verify};
pub(super) use registry_platform_crypto::{sign, PrivateJwk};
pub(super) use registry_platform_testing::{
    fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, sign_openid4vci_proof_jwt,
    MockHttpUpstream, MockIdp, FEDERATION_PROTOCOL, FEDERATION_REQUEST_JWT_TYPE,
};
pub(super) use serde::Deserialize;
pub(super) use serde_json::{json, Value};
#[cfg(feature = "registry-notary-cel")]
pub(super) use sha2::{Digest, Sha256};
pub(super) use std::collections::BTreeMap;
pub(super) use std::collections::BTreeSet;
#[cfg(feature = "registry-notary-cel")]
pub(super) use std::path::PathBuf;
pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) use std::sync::Arc;
pub(super) use std::time::Duration;
pub(super) use tempfile::TempDir;
pub(super) use time::OffsetDateTime;
pub(super) use ulid::Ulid;

pub(super) const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
pub(super) const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
pub(super) const TEST_HOLDER_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA"}"#;
#[derive(Debug, Deserialize)]
pub(super) struct ExposureManifest {
    pub(super) endpoints: Vec<ExposureEndpoint>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ExposureEndpoint {
    pub(super) listener: String,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) feature: Option<String>,
    pub(super) auth: String,
}

pub(super) fn person_target(id: &str) -> Value {
    json!({
        "type": "Person",
        "id": id,
    })
}

pub(super) fn person_identifier_target(scheme: &str, value: &str) -> Value {
    json!({
        "type": "Person",
        "identifiers": [
            { "scheme": scheme, "value": value }
        ],
    })
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn cel_worker_bin() -> PathBuf {
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

pub(super) fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    #[cfg(feature = "registry-notary-cel")]
    std::env::set_var("REGISTRY_NOTARY_CEL_WORKER_COMMAND", cel_worker_bin());
}

pub(super) fn sign_oid4vci_proof(audience: &str, nonce: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    sign_openid4vci_proof_jwt(TEST_HOLDER_JWK, audience, Some(nonce), now)
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn sign_oid4vci_proof_without_iss(audience: &str, nonce: &str) -> String {
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

#[cfg(feature = "registry-notary-cel")]
pub(super) fn sign_direct_holder_proof(holder_id: &str, evaluation_id: &str, jti: &str) -> String {
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

#[cfg(feature = "registry-notary-cel")]
pub(super) fn holder_did_jwk() -> String {
    let holder = PrivateJwk::parse(TEST_HOLDER_JWK).expect("holder JWK parses");
    did_jwk_from_public_jwk(&holder.public()).expect("holder did:jwk encodes")
}

pub(super) fn enable_credential_status(config: &mut StandaloneRegistryNotaryConfig) {
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

pub(super) fn env_fingerprint_ref(env_name: &str) -> CredentialFingerprintRef {
    CredentialFingerprintRef {
        provider: CredentialFingerprintProvider::Env,
        name: Some(env_name.to_string()),
        path: None,
    }
}

pub(super) fn add_admin_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a";
    std::env::set_var("TEST_EVIDENCE_ADMIN_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });
}

pub(super) fn add_ops_read_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:d9310c002af91822beb0b3487d8b04f85bf6bf1f8a5496bff7d35fc7c5a29def";
    std::env::set_var("TEST_EVIDENCE_OPS_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "ops".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_OPS_KEY_HASH"),
        scopes: vec!["registry_notary:ops_read".to_string()],
        authorization_details: None,
    });
}

pub(super) fn add_metrics_read_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:eb5a63e42b6b498364b3f10d5c3bb71cd8c7a7a9ad16524875557fa2e52f5d41";
    std::env::set_var("TEST_EVIDENCE_METRICS_KEY_HASH", fingerprint);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "metrics".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_METRICS_KEY_HASH"),
        scopes: vec!["registry_notary:metrics_read".to_string()],
        authorization_details: None,
    });
}

pub(super) fn enable_shared_admin_listener(config: &mut StandaloneRegistryNotaryConfig) {
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
}

pub(super) fn assert_matches_posture_schema(body: &Value) {
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

pub(super) fn assert_standards_artifacts_omit_sha256(body: &Value, label: &str) {
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

pub(super) fn assert_matches_admin_capabilities_schema(body: &Value) {
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

pub(super) fn sample_manifest_path(path: &str) -> String {
    path.replace("{claim_id}", "farmed-land-size")
        .replace("{evaluation_id}", "eval-1")
        .replace("{credential_id}", "urn:ulid:01HX0000000000000000000000")
        .replace("{*vct_path}", "civil-status")
}

pub(super) fn notary_only_config(
    _base_url: &str,
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
  claims:
    - id: farmer-under-4ha
      title: Farmer under four hectares
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: self_attested
      value:
        type: boolean
      purpose: https://purpose.example.test/eligibility
      required_scopes:
        - farmer_registry:evidence_verification
      rule:
        type: cel
        expression: "true"
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("Notary-only config deserializes")
}
