// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, auth::*, credentials::*, http_contracts::*, oid4vci::*, preauth::*,
};

pub(super) fn set_federation_env() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_FEDERATION_SIGNING_KEY", TEST_ISSUER_JWK);
    std::env::set_var(
        "TEST_FEDERATION_PAIRWISE_SECRET",
        "federation-pairwise-secret",
    );
}

pub(super) fn federation_config(
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
pub(super) fn federation_config_for(
    base_url: &str,
    audit_path: &str,
    node_id: &str,
    issuer: &str,
    peer_node_id: &str,
    peer_issuer: &str,
    peer_jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    let mut config = notary_only_config(base_url, audit_path);
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
    evaluation_scopes:
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

pub(super) fn federation_request_jwt(jti: &str, purpose: &str) -> String {
    federation_request_jwt_with_claims(jti, purpose, json!(["farmer-under-4ha"]))
}

pub(super) fn federation_request_jwt_with_claims(
    jti: &str,
    purpose: &str,
    claims: Value,
) -> String {
    let mut payload = federation_request_payload(jti);
    payload["purpose"] = json!(purpose);
    payload["request"]["claims"] = claims;
    federation_request_jwt_from_payload(payload)
}

pub(super) fn federation_request_jwt_with_audience(jti: &str, audience: &str) -> String {
    let mut payload = federation_request_payload(jti);
    payload["aud"] = json!(audience);
    federation_request_jwt_from_payload(payload)
}

pub(super) fn federation_request_jwt_with_kid(jti: &str, kid: &str) -> String {
    sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        FEDERATION_REQUEST_JWT_TYPE,
        kid,
        federation_request_payload(jti),
    )
}

pub(super) fn federation_request_jwt_with_times(jti: &str, iat: i64, nbf: i64, exp: i64) -> String {
    let mut payload = federation_request_payload(jti);
    payload["iat"] = json!(iat);
    payload["nbf"] = json!(nbf);
    payload["exp"] = json!(exp);
    federation_request_jwt_from_payload(payload)
}

pub(super) fn federation_request_jwt_with_subject(jti: &str, subject: &str) -> String {
    let mut payload = federation_request_payload(jti);
    payload["sub"] = json!(subject);
    federation_request_jwt_from_payload(payload)
}

pub(super) fn federation_request_payload(jti: &str) -> Value {
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

pub(super) fn federation_request_jwt_from_payload(payload: Value) -> String {
    sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        FEDERATION_REQUEST_JWT_TYPE,
        "registry-platform-testing-ed25519-1",
        payload,
    )
}

pub(super) fn federation_jwt_with_header(header: Value, payload: Value) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header encodes")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload encodes")),
        URL_SAFE_NO_PAD.encode(b"invalid-signature")
    )
}

pub(super) fn tamper_jwt_signature(jwt: &str) -> String {
    let mut parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "compact jwt has three parts");
    parts[2] = "AA";
    parts.join(".")
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn verified_federation_response_claims(jwt: &str) -> Value {
    verified_federation_response_claims_with_key(jwt, "agency-a-fed-1", TEST_ISSUER_JWK)
}

#[cfg(feature = "registry-notary-cel")]
pub(super) fn verified_federation_response_claims_with_key(
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

pub(super) fn audit_records(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("audit was written")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .map(|envelope| envelope["record"].clone())
        .collect()
}

pub(super) fn subject_access_oidc_config(
    _base_url: &str,
    audit_path: &str,
    issuer: &str,
    jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let raw = format!(
        r#"
deployment:
  profile: local
state:
  storage: in_memory

server:
  bind: 127.0.0.1:0
auth:
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
      subject_access:
        - subject_access
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
  claims:
    - id: person-is-alive
      title: Person is alive
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: self_attested
      purpose: citizen_subject_access
      value:
        type: boolean
      rule:
        type: cel
        expression: "true"
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
      credential_profiles:
        - civil_status_sd_jwt
subject_access:
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
    - citizen_subject_access
  allowed_claims:
    - person-is-alive
  allowed_formats:
    - application/vnd.registry-notary.claim-result+json
  allowed_disclosures:
    - value
    - redacted
  required_scopes:
    - subject_access
  credential_profiles:
    - civil_status_sd_jwt
  allowed_wallet_origins:
    - https://wallet.example.gov
  rate_limits:
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
"#
    );
    serde_norway::from_str(&raw).expect("subject-access config deserializes")
}

pub(super) fn subject_access_oid4vci_config(
    base_url: &str,
    audit_path: &str,
    issuer: &str,
    jwks_uri: &str,
) -> StandaloneRegistryNotaryConfig {
    let mut config = subject_access_oidc_config(base_url, audit_path, issuer, jwks_uri);
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

#[cfg(feature = "registry-notary-cel")]
pub(super) fn add_subject_access_projection_claim(
    config: &mut StandaloneRegistryNotaryConfig,
    claim_id: &str,
    title: &str,
    output_name: &str,
    value_type: &str,
) {
    let mut claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "person-is-alive")
        .expect("base subject-access claim exists")
        .clone();
    claim.id = claim_id.to_string();
    claim.title = title.to_string();
    claim.value.value_type = value_type.to_string();
    claim.rule = RuleConfig::Cel {
        expression: match output_name {
            "given_name" => "'Miguel'",
            "birth_date" => "'2016-01-15'",
            _ => panic!("unsupported self-attested projection output: {output_name}"),
        }
        .to_string(),
        bindings: Default::default(),
    };
    claim.formats = vec!["application/vnd.registry-notary.claim-result+json".to_string()];
    claim.credential_profiles = vec!["civil_status_sd_jwt".to_string()];
    config.evidence.claims.push(claim);
    config
        .subject_access
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

#[cfg(feature = "registry-notary-cel")]
pub(super) fn enable_oid4vci_field_projection(config: &mut StandaloneRegistryNotaryConfig) {
    add_subject_access_projection_claim(
        config,
        "person-given-name",
        "Given name",
        "given_name",
        "string",
    );
    add_subject_access_projection_claim(
        config,
        "person-birth-date",
        "Birth date",
        "birth_date",
        "date",
    );
    config.subject_access.allowed_operations.issue_credential = true;
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

pub(super) fn audit_envelopes(path: &std::path::Path) -> Vec<AuditEnvelope> {
    std::fs::read_to_string(path)
        .expect("audit jsonl is readable")
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is an envelope"))
        .collect()
}

pub(super) fn audit_record_contains_text(value: &Value, needle: &str) -> bool {
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

pub(super) fn audit_records_from_envelopes(path: &std::path::Path) -> Vec<Value> {
    audit_envelopes(path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect()
}

pub(super) fn audit_record_with<'a>(
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

pub(super) fn assert_problem_identity(body: &Value, status: StatusCode, code: &str) {
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

pub(super) fn assert_audit_records_do_not_contain(records: &[Value], forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !records
                .iter()
                .any(|record| audit_record_contains_text(record, needle)),
            "audit records leaked forbidden text: {needle}"
        );
    }
}

pub(super) fn assert_hmac_audit_field(record: &Value, field: &str) {
    assert!(
        record[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is a string"))
            .starts_with("hmac-sha256:"),
        "{field} is a keyed HMAC handle"
    );
}

pub(super) fn assert_verified_federation_audit_context(
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

pub(super) fn assert_federation_request_context_is_absent(record: &Value) {
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
pub(super) async fn healthz_ready_opaque_counters_in_503_body() {
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
pub(super) async fn federation_route_is_not_mounted_until_enabled() {
    set_federation_env();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
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
pub(super) async fn federation_evaluation_returns_signed_response_and_rejects_replay() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);
    enable_shared_admin_listener(&mut config);
    let app = standalone_router(config)
        .await
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
    assert!(claims["result"]["claim_result_issued_at"].is_string());
    assert!(claims["result"].get("source_observed_at").is_none());

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
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn federation_stale_claim_result_returns_signed_evaluation_error() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    config.federation.evaluation_profiles[0].max_claim_result_age_seconds = Some(0);
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(federation_request_jwt(
            "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6R0",
            "https://purpose.example.test/eligibility",
        )))
        .await;

    response.assert_status_ok();
    let claims = verified_federation_response_claims(&response.text());
    assert_eq!(
        claims["error"]["type"],
        json!("urn:registry-notary:problem:federation:stale-claim-result")
    );
    assert_eq!(claims["error"]["title"], json!("Claim result is stale"));
    assert_eq!(
        claims["error"]["code"],
        json!("federation.stale_claim_result")
    );
    let records = audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["decision"] == json!("federated_evaluate_error")
            && record["error_code"] == json!("federation.stale_claim_result")
    }));
    assert_audit_records_do_not_contain(&records, &["person-1"]);
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn federation_auth_exempt_route_still_requires_valid_jws() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config = federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    );
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
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
pub(super) async fn federation_two_standalone_notaries_smoke() {
    set_federation_env();
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
            "http://127.0.0.1:1",
            agency_a_audit.to_str().expect("audit path is UTF-8"),
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
            "did:web:agency-b.example.gov",
            "https://agency-b.example.gov",
            &format!("{}/jwks", agency_b_jwks.url()),
        ))
        .await
        .expect("agency A standalone router builds"),
    );
    let agency_b = TestServer::builder().http_transport().build(
        standalone_router(federation_config_for(
            "http://127.0.0.1:1",
            agency_b_audit.to_str().expect("audit path is UTF-8"),
            "did:web:agency-b.example.gov",
            "https://agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
            &format!("{}/jwks", agency_a_jwks.url()),
        ))
        .await
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
pub(super) async fn federation_denial_happens_before_claim_evaluation() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .await
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

    let oversized_body = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(vec![b'a'; 16 * 1024 + 1]))
        .await;
    oversized_body.assert_status(StatusCode::PAYLOAD_TOO_LARGE);

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

    let future_nbf =
        federation_request_jwt_with_times("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q3", now, now + 600, now + 900);
    let future_nbf_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(future_nbf))
        .await;
    future_nbf_response.assert_status(StatusCode::UNAUTHORIZED);

    let long_lived =
        federation_request_jwt_with_times("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q4", now, now, now + 301);
    let long_lived_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(long_lived))
        .await;
    long_lived_response.assert_status(StatusCode::UNAUTHORIZED);

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

    let unknown_kid = federation_request_jwt_with_kid("01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q7Q6", "unknown-key");
    let unknown_kid_response = server
        .post("/federation/v1/evaluations")
        .add_header("content-type", "application/jwt")
        .bytes(Bytes::from(unknown_kid))
        .await;
    unknown_kid_response.assert_status(StatusCode::UNAUTHORIZED);
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
}

#[tokio::test]
pub(super) async fn federation_emergency_kid_denylist_blocks_before_claim_evaluation() {
    assert_federation_emergency_denylist_blocks_before_claim_evaluation(true).await;
}

#[tokio::test]
pub(super) async fn federation_emergency_node_id_denylist_blocks_before_claim_evaluation() {
    assert_federation_emergency_denylist_blocks_before_claim_evaluation(false).await;
}

pub(super) async fn assert_federation_emergency_denylist_blocks_before_claim_evaluation(
    deny_kid: bool,
) {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        "http://127.0.0.1:1",
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
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
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
pub(super) async fn federation_request_claims_must_match_profile_before_claim_evaluation() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let (peer_private, _) = fixtures::ed25519_pair();
    peer_jwks
        .expect("GET", "/jwks")
        .respond_json(200, jwks_from_private_jwk(&peer_private))
        .await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .await
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
pub(super) async fn federation_audit_write_failure_replaces_signed_success() {
    set_federation_env();
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
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks", peer_jwks.url()),
    ))
    .await
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
