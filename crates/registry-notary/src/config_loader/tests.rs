// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn config_env_expansion_replaces_required_and_default_values() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("RN_CONFIG_EXPAND_REQUIRED", "https://upstream.example");
    std::env::remove_var("RN_CONFIG_EXPAND_DEFAULT");

    let expanded = expand_config_env_vars(
            "base_url: ${RN_CONFIG_EXPAND_REQUIRED:?missing upstream}\noptional: ${RN_CONFIG_EXPAND_DEFAULT:-fallback}\n",
        )
        .expect("config expands");

    assert!(expanded.contains("base_url: \"https://upstream.example\""));
    assert!(expanded.contains("optional: \"fallback\""));
    std::env::remove_var("RN_CONFIG_EXPAND_REQUIRED");
}

#[test]
fn config_env_expansion_rejects_missing_required_values() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var("RN_CONFIG_EXPAND_MISSING");

    let err = expand_config_env_vars("${RN_CONFIG_EXPAND_MISSING:?missing configured URL}")
        .expect_err("missing env var fails");

    assert!(err.to_string().contains("missing configured URL"));
}

#[test]
fn config_env_expansion_rejects_invalid_variable_names() {
    let err =
        expand_config_env_vars("${NOT-A-VALID-NAME:-fallback}").expect_err("invalid var fails");

    assert!(err.to_string().contains("invalid env var name"));
}

#[test]
fn signed_bundle_server_config_loads_with_pending_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let config_path = tmp.path().join("bootstrap.yaml");
    std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");

    let loaded = load_server_config(&config_path, true).expect("signed bundle config loads");

    assert_eq!(loaded.config_source, ConfigSource::SignedBundleFile);
    let provenance = loaded.config_provenance.expect("provenance");
    assert_eq!(provenance.source, ConfigSource::SignedBundleFile);
    assert_eq!(provenance.internal_config_hash, fixture.config_hash);
    let acceptance = loaded
        .pending_bundle_acceptance
        .expect("pending acceptance");
    assert_eq!(acceptance.source, ConfigSource::SignedBundleFile);
    assert_eq!(
        acceptance.bundle_id.as_deref(),
        Some("notary-loader-bundle")
    );
    assert_eq!(acceptance.sequence, Some(1));
    assert_eq!(acceptance.config_hash, fixture.config_hash);
    assert!(matches!(
        acceptance.state_action,
        BundleStateAction::Initialize
    ));
}

#[test]
fn scalar_admin_listener_shape_names_accepted_modes() {
    let value = parse_config_value(
        r#"
server:
  admin_listener: shared_with_public
"#,
    )
    .expect("config shape parses");
    let err = validate_admin_listener_shape(&value)
        .expect_err("legacy scalar admin listener shape is rejected");

    let message = err.to_string();
    assert!(message.contains("server.admin_listener.mode"));
    assert!(message.contains("disabled"));
    assert!(message.contains("dedicated"));
    assert!(message.contains("shared_with_public"));
}

#[test]
fn deprecated_config_fields_name_replacements_and_removed_cors_credentials() {
    for (raw, expected) in [
        (
            "auth:\n  oidc:\n    jwks_uri: https://id.example.gov/keys\n",
            "auth.oidc.jwks_url",
        ),
        (
            "auth:\n  oidc:\n    leeway_seconds: 60\n",
            "auth.oidc.leeway",
        ),
        (
            "auth:\n  oidc:\n    allowed_typ:\n      - JWT\n",
            "auth.oidc.allowed_token_types",
        ),
        (
            "server:\n  cors:\n    allow_credentials: true\n",
            "always disables credentialed CORS",
        ),
        ("audit:\n  max_size_bytes: 10485760\n", "audit.max_size_mb"),
    ] {
        let value = parse_config_value(raw).expect("deprecated-field fixture parses");
        let err = reject_deprecated_config_fields(&value, &deprecated_config_fields())
            .expect_err("deprecated field is rejected before deserialization");

        assert!(err.to_string().contains(expected), "unexpected: {err}");
    }
}

#[test]
fn absent_admin_listener_block_requests_restore_key_warning() {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_ADMIN_WARNING_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_ADMIN_WARNING_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil-status:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer
      vct: https://issuer.example/credentials/civil-status
"#,
    )
    .expect("config parses");

    assert!(admin_listener_default_warning_needed(&config, false));
    assert!(!admin_listener_default_warning_needed(&config, true));
}
