use super::*;
/// Builds a minimal valid config from which individual tests can deviate.
pub(super) fn minimal_config() -> StandaloneRegistryNotaryConfig {
    serde_norway::from_str(
        r#"
evidence:
  enabled: true
  claims:
    - id: test-claim
      title: Test Claim
      version: "1.0"
      subject_type: person
      purpose: test-purpose
      required_scopes:
        - registry:consult:test-source
      evidence_mode:
        type: registry_backed
        consultations:
          test_source:
            profile:
              id: example.test-source.exact
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              subject_id: target.id
            outputs:
              registration_found:
                type: boolean
                nullable: false
      rule:
        type: consultation_matched
        consultation: test_source
      value:
        type: boolean
  relay:
    base_url: https://relay.internal.example
    workload_client_id: registry-notary
    token_file: /run/secrets/registry-notary-relay.jwt
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
auth:
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
"#,
    )
    .expect("minimal config is valid YAML")
}
