use super::*;
/// Builds a minimal valid config from which individual tests can deviate.
pub(super) fn minimal_config() -> StandaloneRegistryNotaryConfig {
    serde_norway::from_str(
        r#"
evidence:
  enabled: true
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
