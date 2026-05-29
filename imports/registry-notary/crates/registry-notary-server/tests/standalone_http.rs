// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary tests that do not link Registry Relay.

use axum::body::Bytes;
use axum::extract::Query;
#[cfg(feature = "registry-notary-cel")]
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
#[cfg(feature = "registry-notary-cel")]
use axum::routing::post;
use axum::{Json, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::{
    EvidenceCredentialConfig, EvidenceOidcAuthConfig, Oid4vciConfig, SelfAttestationClaimSource,
    StandaloneRegistryNotaryConfig,
};
use registry_notary_server::{standalone_router, StandaloneServerError};
use registry_platform_audit::{verify_jsonl_lines, AuditEnvelope};
#[cfg(feature = "registry-notary-cel")]
use registry_platform_crypto::verify;
use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
use registry_platform_testing::{
    fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, sign_openid4vci_proof_jwt,
    MockHttpUpstream, MockIdp, FEDERATION_PROTOCOL, FEDERATION_REQUEST_JWT_TYPE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(feature = "registry-notary-cel")]
use std::sync::Mutex;
use tempfile::TempDir;
use time::OffsetDateTime;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_HOLDER_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA"}"#;

fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
}

fn sign_oid4vci_proof(audience: &str, nonce: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    sign_openid4vci_proof_jwt(TEST_HOLDER_JWK, audience, Some(nonce), now)
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
            "alive": true
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
  api_base_url: https://evidence.example.test
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

fn set_federation_env() {
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
  kid: agency-a-fed-1
  key_env: TEST_FEDERATION_SIGNING_KEY
  alg: EdDSA
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
    let parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "compact JWT response has three segments");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("response signature is base64url");
    let public = PrivateJwk::parse(TEST_ISSUER_JWK)
        .expect("issuer JWK parses")
        .public();
    verify(signing_input.as_bytes(), &signature, &public).expect("response signature verifies");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("response payload is base64url");
    serde_json::from_slice(&payload).expect("response payload is JSON")
}

#[cfg(feature = "registry-notary-cel")]
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
server:
  bind: 127.0.0.1:0
auth:
  mode: oidc
  oidc:
    issuer: "{issuer}"
    jwks_uri: "{jwks_uri}"
    audiences:
      - registry-notary-citizen
    allowed_clients:
      - citizen-portal
    allowed_algorithms:
      - EdDSA
    allowed_typ:
      - JWT
    scope_claim: scope
    scope_separator: " "
    principal_claim: sub
    leeway_seconds: 60
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
  credential_profiles:
    civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      issuer_key_env: TEST_SELF_ATTESTATION_ISSUER_JWK
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
    vct: https://issuer.example/credentials/civil-status
    display_name: Person is alive
"#,
    )
    .expect("oid4vci config deserializes");
    config
}

#[cfg(feature = "registry-notary-cel")]
fn dci_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
    config(base_url, audit_path, "dci", "farmed_land_size_hectares")
}

fn no_cel_config(base_url: &str, audit_path: &str) -> StandaloneRegistryNotaryConfig {
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
    let ready_body: Value = ready.json();
    assert_eq!(ready_body["status"], json!("not_ready"));
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
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
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
        allowed["federation_purpose"],
        json!("https://purpose.example.test/eligibility")
    );
    assert_eq!(
        allowed["federation_request_jti"],
        json!("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6")
    );
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
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("source-token"));

    let metrics = server.get("/metrics").await;
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
async fn federation_two_standalone_notaries_smoke() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
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
            "/datasets/farmer_registry/farmer",
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
async fn federation_emergency_denylist_blocks_before_source_read() {
    set_federation_env();
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/datasets/farmer_registry/farmer",
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
    config
        .federation
        .emergency_denylist
        .kids
        .push("registry-platform-testing-ed25519-1".to_string());
    config
        .federation
        .emergency_denylist
        .node_ids
        .push("did:web:agency-b.example.gov".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let token = federation_request_jwt(
        "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7R0",
        "https://purpose.example.test/eligibility",
    );

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(token))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn federation_request_claims_must_match_profile_before_source_read() {
    set_federation_env();
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/datasets/farmer_registry/farmer",
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
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
async fn federation_stale_source_observation_returns_signed_evaluation_error() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
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
}

#[tokio::test]
async fn federation_audit_write_failure_replaces_signed_success() {
    set_federation_env();
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/datasets/farmer_registry/farmer", get(registry_data_api)));
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
    let blocked_parent = tmp.path().join("blocked");
    std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
    let audit_path = blocked_parent.join("audit.jsonl");
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
async fn admin_reload_401_unauth_403_wrong_scope_200_admin() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH",
        "sha256:ac3dced2bcf7d2cb4166747790d67437b5cc5314ed33e01d06b274a7fe0c3b3c",
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
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "wrong-scope".to_string(),
        hash_env: "TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH".to_string(),
        scopes: vec!["farmer_registry:evidence_verification".to_string()],
    });
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        hash_env: "TEST_EVIDENCE_ADMIN_KEY_HASH".to_string(),
        scopes: vec!["registry_notary:admin".to_string()],
    });

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let unauthenticated = server.post("/admin/reload").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);

    let wrong_scope = server
        .post("/admin/reload")
        .add_header("x-api-key", "wrong-scope-token")
        .await;
    wrong_scope.assert_status(StatusCode::FORBIDDEN);

    let admin = server
        .post("/admin/reload")
        .add_header("x-api-key", "admin-token")
        .await;
    admin.assert_status_ok();
    let admin_body: Value = admin.json();
    assert_eq!(admin_body["reloaded"], json!(false));
    assert_eq!(admin_body["status"], json!("noop"));
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
    config.auth.mode = "oidc".to_string();
    config.auth.api_keys.clear();
    config.auth.bearer_tokens.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: idp.issuer(),
        jwks_uri: idp.jwks_uri(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_typ: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway_seconds: 60,
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

    let denied = server.get("/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let response = server
        .get("/claims")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["data"][0]["id"], json!("farmed-land-size"));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    assert!(!audit.contains(&token));

    idp.stop().await;
}

#[tokio::test]
async fn oidc_self_attestation_evaluates_renders_and_audits_access_mode() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/datasets/people/person",
            get(self_attestation_registry_data_api),
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

    let evaluate = server
        .post("/claims/evaluate")
        .add_header("authorization", authorization.clone())
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "subject": {
                "id": "person-1",
                "id_type": "national_id"
            },
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    assert_eq!(evaluate_body["results"][0]["value"], json!(true));
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();

    let render = server
        .post("/evidence/render")
        .add_header("authorization", authorization)
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "evaluation_id": evaluation_id,
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
            record["path"] == json!("/claims/evaluate")
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
    assert_eq!(evaluate_audit["correlation_id"], json!("req-self-attest-1"));
    assert!(evaluate_audit.get("principal_id").is_none());
    assert!(evaluate_audit.get("principal_id_hash").is_some());

    let render_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/evidence/render")
                && record["decision"] == json!("render")
                && record["status"] == json!(200)
        })
        .expect("render audit record exists");
    assert_eq!(render_audit["access_mode"], json!("self_attestation"));
    assert!(render_audit["policy_hash"].is_string());
    assert_eq!(render_audit["correlation_id"], json!("req-self-attest-1"));

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
        json!(["RegistryNotaryCredentialStatus"])
    );
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["credential_status_url"],
        json!("/credentials/status/{credential_id}")
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
    enable_credential_status(&mut enabled_config);
    enabled_config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        hash_env: "TEST_EVIDENCE_ADMIN_KEY_HASH".to_string(),
        scopes: vec!["registry_notary:admin".to_string()],
    });
    let enabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(enabled_config).expect("enabled router builds"));

    let invalid_status = enabled_server
        .post("/admin/credentials/status/urn:ulid:01HX0000000000000000000000")
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
        .post("/admin/credentials/status/urn:ulid:01HX0000000000000000000000")
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
    disabled_config
        .auth
        .api_keys
        .push(EvidenceCredentialConfig {
            id: "admin".to_string(),
            hash_env: "TEST_EVIDENCE_ADMIN_KEY_HASH".to_string(),
            scopes: vec!["registry_notary:admin".to_string()],
        });
    let disabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(disabled_config).expect("disabled router builds"));

    let disabled = disabled_server
        .post("/admin/credentials/status/urn:ulid:01HX0000000000000000000000")
        .add_header("x-api-key", "admin-token")
        .json(&json!({ "status": "revoked" }))
        .await;
    disabled.assert_status(StatusCode::NOT_FOUND);
    let disabled_body: Value = disabled.json();
    assert_eq!(disabled_body["code"], json!("credential_status.disabled"));

    let disabled_public = disabled_server
        .get("/credentials/status/urn:ulid:01HX0000000000000000000000")
        .await;
    disabled_public.assert_status(StatusCode::NOT_FOUND);
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
            "/datasets/people/person",
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
        .get("/credentials/status/urn:ulid:01HX0000000000000000000000")
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
        "scope": "self_attestation",
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
            "type": "RegistryNotaryCredentialStatus",
            "statusUrl": format!("http://127.0.0.1:4325/credentials/status/{credential_id}")
        })
    );
    assert!(body["c_nonce"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let status = server
        .get(&format!("/credentials/status/{credential_id}"))
        .await;
    status.assert_status_ok();
    let status_body: Value = status.json();
    assert_eq!(status_body["credential_id"], json!(credential_id));
    assert_eq!(status_body["status"], json!("valid"));
    assert_eq!(
        status_body["credential_profile"],
        json!("civil_status_sd_jwt")
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
        .post(&format!("/admin/credentials/status/{credential_id}"))
        .add_header("authorization", format!("Bearer {admin_token}"))
        .json(&json!({ "status": "revoked" }))
        .await;
    revoked.assert_status_ok();
    let revoked_body: Value = revoked.json();
    assert_eq!(revoked_body["status"], json!("revoked"));

    let status_after_revoke = server
        .get(&format!("/credentials/status/{credential_id}"))
        .await;
    status_after_revoke.assert_status_ok();
    let status_after_revoke_body: Value = status_after_revoke.json();
    assert_eq!(status_after_revoke_body["status"], json!("revoked"));

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
    assert_eq!(credential_audit["protocol"], json!("openid4vci"));
    assert_eq!(
        credential_audit["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    assert_eq!(
        credential_audit["credential_profile"],
        json!("civil_status_sd_jwt")
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
            "/datasets/people/person",
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
        .post("/claims/evaluate")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "subject": {
                "id": "person-1",
                "id_type": "national_id"
            },
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
        .post("/credentials/issue")
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
    let credential_id = issue_body["credential_id"]
        .as_str()
        .expect("credential id returned");

    let status = server
        .get(&format!("/credentials/status/{credential_id}"))
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
async fn strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/datasets/people/person",
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
        .post("/claims/evaluate")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "subject": {
                "id": "person-1",
                "id_type": "national_id"
            },
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
        .post("/credentials/issue")
        .add_header("authorization", authorization)
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_did_jwk(),
                "proof": sign_oid4vci_proof("registry-notary", "nonce-1")
            }
        }))
        .await;
    issue.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = issue.json();
    assert_eq!(body["code"], json!("credential.holder_proof_required"));

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
            "subject": {"id": "person-2"},
            "proof": {
                "proof_type": "jwt",
                "jwt": "not-a-compact-jwt"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_request"));

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
        .post("/claims/evaluate")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("x-request-id", "bad value")
        .json(&json!({
            "subject": {
                "id": "person-2",
                "id_type": "national_id"
            },
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
        json!("https://docs.registry-notary.dev/problems/self_attestation/denied")
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
            record["path"] == json!("/claims/evaluate")
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
    assert!(denied["correlation_id"].is_string());
    assert_ne!(denied["correlation_id"], json!("bad value"));

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
    let server = TestServer::builder().http_transport().build(app);

    let too_large = Bytes::from(vec![b' '; 1024 * 1024 + 1]);
    let response = server
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .bytes(too_large)
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
        json!("https://registry-platform.dev/problems/request/body-too-large")
    );
}

#[tokio::test]
async fn error_responses_match_rfc_7807_shape() {
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

    let response = server.get("/claims").await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(401));
    assert_eq!(body["title"], json!("Missing credential"));
    assert_eq!(body["code"], json!("auth.missing_credential"));
    assert!(body["type"]
        .as_str()
        .is_some_and(|value| value.starts_with("https://docs.registry-notary.dev/problems/")));
    assert!(body["detail"].as_str().is_some());
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
    assert!(response.headers().contains_key("content-security-policy"));
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
    let mut config = self_attestation_oidc_config(
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
    let mut config = self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let wallet = server
        .method(Method::OPTIONS, "/claims/evaluate")
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

    let ops = server
        .method(Method::OPTIONS, "/claims/evaluate")
        .add_header("origin", "https://ops.example.test")
        .add_header("access-control-request-method", "POST")
        .await;
    ops.assert_status(StatusCode::NO_CONTENT);
    assert!(ops.headers().get("access-control-allow-origin").is_none());
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

    #[cfg(feature = "registry-notary-cel")]
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
    assert!(!audit.contains("3.5"));

    let metrics = server.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains("registry_notary_http_requests_total"));
    assert!(metrics_body.contains(
        "registry_notary_http_requests_total{method=\"POST\",route=\"/claims/evaluate\",status_class=\"2xx\"}"
    ));
    assert!(metrics_body
        .contains("registry_notary_source_requests_total{connector=\"rda\",outcome=\"success\"}"));
    assert!(metrics_body.contains("registry_notary_audit_events_total{outcome=\"success\"}"));
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
        .get("/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
    second
        .get("/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    verify_jsonl_lines(contents.lines()).expect("audit chain verifies");
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
        .get("/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    first
        .get("/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let contents = std::fs::read_to_string(&audit_path).expect("audit was written");
    let mut lines = contents.lines().collect::<Vec<_>>();
    lines.insert(1, lines[0]);
    std::fs::write(&audit_path, format!("{}\n", lines.join("\n"))).expect("tampered audit write");

    let second = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("second router builds"));
    let response = second
        .get("/claims")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("audit.write_failed"));
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
        .post("/claims/evaluate")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "subject": { "id": "openspp-missing" },
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("source.not_found"));
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
