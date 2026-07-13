// SPDX-License-Identifier: Apache-2.0

use axum_test::TestServer;
use registry_notary_client::RegistryNotaryClient;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::json;
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const PURPOSE: &str = "https://purpose.example.test/eligibility";

#[tokio::test]
async fn client_discovers_real_notary_only_server_and_maps_unsupported_evaluation() {
    set_env();

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
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
    assert_eq!(claims.body.data[0]["id"], json!("farmer-under-4ha"));

    let error = client
        .evaluate("person-1")
        .claim("farmer-under-4ha")
        .disclosure("predicate")
        .send()
        .await
        .expect_err("self-attested claims require an explicit attestation workflow");
    assert_eq!(error.status().map(|status| status.as_u16()), Some(501));
    assert_eq!(error.problem_code(), Some("claim.operation_unsupported"));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(
        audit.contains("\"decision\":\"evaluate_denied\""),
        "unsupported evaluation must be audited as denied: {audit}"
    );
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("farmer-under-4ha"));
}

fn set_env() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
}

fn notary_only_config(audit_path: &str) -> StandaloneRegistryNotaryConfig {
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
  claims:
    - id: farmer-under-4ha
      title: Farmer under four hectares
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: self_attested
      value:
        type: boolean
      purpose: {PURPOSE}
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
    serde_norway::from_str(&raw).expect("config deserializes")
}
