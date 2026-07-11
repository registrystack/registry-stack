use super::root::valid_self_attestation_config;
use super::support::*;
use super::*;

#[test]
pub(super) fn oidc_auth_mode_requires_oidc_block() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;

    let err = config
        .validate()
        .expect_err("oidc mode requires OIDC settings");

    assert!(matches!(err, EvidenceConfigError::MissingOidcConfig));
}

#[test]
pub(super) fn oidc_auth_mode_validates_required_settings() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "https://issuer.example/jwks.json".to_string(),
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
        allow_insecure_localhost: false,
    });

    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn duplicate_static_credential_api_key_id_rejected() {
    let mut config = minimal_config();
    let duplicate = config.auth.api_keys[0].clone();
    config.auth.api_keys.push(duplicate);

    let reason = match config
        .validate()
        .expect_err("duplicate API key id must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.api_keys") && reason.contains("test-key"),
        "unexpected reason: {reason}"
    );
}

#[test]
pub(super) fn duplicate_static_credential_bearer_token_id_rejected() {
    let mut config = minimal_config();
    let mut token = config.auth.api_keys[0].clone();
    token.id = "shared-bearer-token".to_string();
    config.auth.bearer_tokens.push(token.clone());
    config.auth.bearer_tokens.push(token);

    let reason = match config
        .validate()
        .expect_err("duplicate bearer token id must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.bearer_tokens") && reason.contains("shared-bearer-token"),
        "unexpected reason: {reason}"
    );
}

#[test]
pub(super) fn duplicate_static_credential_id_across_api_key_and_bearer_token_rejected() {
    let mut config = minimal_config();
    config
        .auth
        .bearer_tokens
        .push(config.auth.api_keys[0].clone());

    let reason = match config
        .validate()
        .expect_err("duplicate static credential id across types must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.bearer_tokens") && reason.contains("test-key"),
        "unexpected reason: {reason}"
    );
}

#[test]
pub(super) fn oidc_jwks_url_must_use_https() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "http://issuer.example/jwks.json".to_string(),
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
        allow_insecure_localhost: false,
    });

    let err = config
        .validate()
        .expect_err("remote http jwks_url must fail validation");
    match err {
        EvidenceConfigError::InvalidOidcConfig { reason } => {
            assert!(
                reason.contains("jwks_url must use https"),
                "unexpected: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }

    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .allow_insecure_localhost = true;
    let err = config
        .validate()
        .expect_err("allow_insecure_localhost must not permit remote http");
    assert!(matches!(err, EvidenceConfigError::InvalidOidcConfig { .. }));
}

#[test]
pub(super) fn oidc_jwks_url_allows_insecure_localhost_only_when_enabled() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "http://127.0.0.1:8080/jwks.json".to_string(),
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
        allow_insecure_localhost: false,
    });

    let err = config
        .validate()
        .expect_err("localhost http jwks_url needs explicit opt-in");
    assert!(matches!(err, EvidenceConfigError::InvalidOidcConfig { .. }));

    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .allow_insecure_localhost = true;
    config
        .validate()
        .expect("localhost http jwks_url is allowed only with the opt-in");
}

#[test]
pub(super) fn api_key_plaintext_is_never_loaded_only_fingerprint() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      token_env: TEST_TOKEN
"#,
    )
    .expect_err("plaintext token_env is not part of the credential schema");

    assert!(
        err.to_string().contains("unknown field `token_env`"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn legacy_api_key_fingerprint_commitment_rejected() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
        commitment: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .expect_err("legacy fingerprint commitment must fail deserialization");

    assert!(
        err.to_string()
            .contains("fingerprint.commitment was removed"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn legacy_bearer_token_fingerprint_commitment_rejected() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  bearer_tokens:
    - id: test-bearer
      fingerprint:
        provider: env
        name: TEST_BEARER_HASH
        commitment: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .expect_err("legacy bearer token fingerprint commitment must fail deserialization");

    assert!(
        err.to_string()
            .contains("fingerprint.commitment was removed"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn unsupported_auth_mode_is_rejected_at_parse_time() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oauth2
"#,
    )
    .expect_err("unknown auth mode must fail deserialization");

    let message = err.to_string();
    assert!(
        message.contains("oauth2") || message.contains("unknown variant"),
        "unexpected error: {message}"
    );
}

#[test]
pub(super) fn oidc_auth_rejects_static_credentials() {
    let mut config = valid_self_attestation_config();
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "legacy-api-key".to_string(),
        fingerprint: CredentialFingerprintRef {
            provider: registry_platform_authcommon::CredentialFingerprintProvider::Env,
            name: Some("LEGACY_API_KEY_HASH".to_string()),
            path: None,
        },
        scopes: vec!["self_attestation".to_string()],
        authorization_details: None,
    });

    let reason = match config
        .validate()
        .expect_err("OIDC mode must not accept static credentials")
    {
        EvidenceConfigError::InvalidOidcConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.api_keys"),
        "unexpected error reason: {reason}"
    );
}
