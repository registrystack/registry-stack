use super::infrastructure::valid_federation_config;
use super::issuance::{
    expect_access_token_signing_error, publish_only_access_token_verification_key,
    second_signing_key, test_public_jwk, valid_pre_auth_config,
};
use super::root::expect_oid4vci_error;
use super::support::*;
use super::*;

#[test]
pub(super) fn pre_auth_and_access_token_signing_are_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.oid4vci.pre_authorized_code.enabled);
    assert!(!config.auth.access_token_signing.enabled);
    config
        .validate()
        .expect("a config that omits the pre-auth blocks still validates");
}

#[test]
pub(super) fn omitted_pre_auth_blocks_use_safe_defaults() {
    let config = minimal_config();
    let tx_code = &config.oid4vci.pre_authorized_code.tx_code;
    assert!(tx_code.required, "tx_code is required by default");
    assert_eq!(tx_code.input_mode, "numeric");
    let signing = &config.auth.access_token_signing;
    assert_eq!(signing.allowed_algorithms, vec!["EdDSA".to_string()]);
    assert_eq!(signing.token_typ, "registry-notary-access+jwt");
}

#[test]
pub(super) fn valid_pre_auth_config_validates() {
    valid_pre_auth_config()
        .validate()
        .expect("a fully-configured pre-auth config validates");
}

#[test]
pub(super) fn access_token_signing_enabled_requires_issuer() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.issuer = String::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("issuer"));
}

#[test]
pub(super) fn access_token_signing_enabled_requires_audiences() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.audiences = Vec::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("audiences"));
}

#[test]
pub(super) fn access_token_signing_requires_known_signing_key() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.signing_key_id = "missing-key".to_string();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("evidence.signing_keys"));
}

#[test]
pub(super) fn access_token_signing_key_must_be_distinct_from_credential_key() {
    let mut config = valid_pre_auth_config();
    // Point the access-token key at the credential-signing key.
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("distinct from credential profile"));
}

#[test]
pub(super) fn resolved_signing_key_material_must_not_be_reused_under_distinct_kids() {
    let config = valid_pre_auth_config();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let access_token_public_jwk = test_public_jwk(
        "did:web:issuer.example#access-token-key",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    let err = config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("access-token-key", &access_token_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect_err("same public key material under different kids must fail");

    match err {
        EvidenceConfigError::InvalidSigningKeyConfig { key, reason } => {
            assert_eq!(key, "access-token-key");
            assert!(reason.contains("reuses public key material"));
            assert!(reason.contains("issuer-key"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn resolved_signing_key_material_accepts_distinct_public_keys() {
    let config = valid_pre_auth_config();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let access_token_public_jwk = test_public_jwk(
        "did:web:issuer.example#access-token-key",
        "pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("access-token-key", &access_token_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect("distinct public key material is valid");
}

#[test]
pub(super) fn resolved_signing_key_material_allows_esignet_rp_key_to_reuse_credential_material() {
    // Issue #173 confines reuse detection to the separated EdDSA roles. The
    // eSignet pre-authorized-code RP client key is a relaxed role that is
    // deliberately allowed to share material with the credential issuer key,
    // so it must not appear in the reuse-scoped set and must not trip the
    // detector even when its resolved material matches a credential key.
    let mut config = valid_pre_auth_config();
    let mut esignet_key = second_signing_key();
    esignet_key.kid = "did:web:rp.example#esignet-rp-key".to_string();
    config
        .evidence
        .signing_keys
        .insert("esignet-rp-key".to_string(), esignet_key);
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let esignet_public_jwk = test_public_jwk(
        "did:web:rp.example#esignet-rp-key",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    assert!(
        !reuse_scoped_key_ids.contains("esignet-rp-key"),
        "the eSignet RP client key must be excluded from reuse-scoped roles"
    );

    config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("esignet-rp-key", &esignet_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect("eSignet RP key may reuse credential key material");
}

#[test]
pub(super) fn access_token_signing_key_must_be_active() {
    let mut config = valid_pre_auth_config();
    config
        .evidence
        .signing_keys
        .get_mut("access-token-key")
        .expect("access-token key exists")
        .status = SigningKeyStatus::PublishOnly;
    // PublishOnly requires public_jwk_env and no private_jwk_env.
    let key = config
        .evidence
        .signing_keys
        .get_mut("access-token-key")
        .expect("access-token key exists");
    key.public_jwk_env = "ACCESS_TOKEN_PUBLIC_KEY".to_string();
    key.private_jwk_env = String::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("active signing key"));
}

#[test]
pub(super) fn access_token_signing_rejects_non_eddsa_algorithms() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.allowed_algorithms = vec!["RS256".to_string()];
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("EdDSA"));
}

#[test]
pub(super) fn access_token_verification_key_ids_accept_publish_only_old_keys() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "access-token-key-old".to_string(),
        publish_only_access_token_verification_key("did:web:issuer.example#access-token-key-old"),
    );
    config.auth.access_token_signing.verification_key_ids =
        vec!["access-token-key-old".to_string()];

    config
        .validate()
        .expect("publish-only verification keys are valid during rotation");
}

#[test]
pub(super) fn access_token_verification_key_ids_must_not_repeat_active_key() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.verification_key_ids = vec!["access-token-key".to_string()];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("must not repeat active signing_key_id"));
}

#[test]
pub(super) fn access_token_verification_key_ids_must_be_unique() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "access-token-key-old".to_string(),
        publish_only_access_token_verification_key("did:web:issuer.example#access-token-key-old"),
    );
    config.auth.access_token_signing.verification_key_ids = vec![
        "access-token-key-old".to_string(),
        "access-token-key-old".to_string(),
    ];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("duplicate key"));
}

#[test]
pub(super) fn access_token_verification_key_ids_must_be_publish_only() {
    let mut config = valid_pre_auth_config();
    let mut active_old_key = second_signing_key();
    active_old_key.kid = "did:web:issuer.example#access-token-key-old".to_string();
    config
        .evidence
        .signing_keys
        .insert("access-token-key-old".to_string(), active_old_key);
    config.auth.access_token_signing.verification_key_ids =
        vec!["access-token-key-old".to_string()];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("publish_only"));
}

/// A local JWK signing key entry. Config validation only checks the alg
/// string and the per-provider fields, so a dummy private_jwk_env name
/// suffices; the JWK itself is not decoded at validation time.
pub(super) fn local_jwk_signing_key_with_alg(
    alg: &str,
    private_jwk_env: &str,
    kid: &str,
) -> SigningKeyConfig {
    SigningKeyConfig {
        provider: SigningKeyProviderConfig::LocalJwkEnv,
        alg: alg.to_string(),
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

pub(super) fn rs256_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    local_jwk_signing_key_with_alg(CLIENT_ASSERTION_SIGNING_ALG_RS256, private_jwk_env, kid)
}

pub(super) fn es256_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    local_jwk_signing_key_with_alg(CREDENTIAL_SIGNING_ALG_ES256, private_jwk_env, kid)
}

pub(super) fn expect_signing_key_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("signing-key config must fail validation")
    {
        EvidenceConfigError::InvalidSigningKeyConfig { reason, .. } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn esignet_rp_client_assertion_key_may_be_rs256() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    config
        .validate()
        .expect("an RS256 eSignet RP client-assertion key validates");
}

#[test]
pub(super) fn pre_auth_client_signing_key_must_exist() {
    let mut config = valid_pre_auth_config();
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "missing-rp-key".to_string();
    let reason = match config
        .validate()
        .expect_err("a missing RP client-assertion key must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };
    assert!(reason.contains("client_signing_key_id"));
    assert!(reason.contains("evidence.signing_keys"));
}

#[test]
pub(super) fn pre_auth_client_signing_key_must_be_active() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    // PublishOnly cannot sign; it requires public_jwk_env and no private_jwk_env.
    let key = config
        .evidence
        .signing_keys
        .get_mut("esignet-rp-key")
        .expect("esignet rp key exists");
    key.status = SigningKeyStatus::PublishOnly;
    key.public_jwk_env = "ESIGNET_RP_PUBLIC_KEY".to_string();
    key.private_jwk_env = String::new();
    let reason = match config
        .validate()
        .expect_err("an inactive RP client-assertion key must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };
    assert!(reason.contains("active signing key"));
}

#[test]
pub(super) fn rs256_signing_key_rejected_as_credential_profile_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:issuer.example#esignet-rp-key"),
    );
    // Point a credential profile at the RS256 key.
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .signing_key = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("RS256"));
    assert!(reason.contains("credential profile"));
}

#[test]
pub(super) fn es256_signing_key_may_be_credential_profile_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "issuer-p256-key".to_string(),
        es256_signing_key("ISSUER_P256_KEY", "did:web:issuer.example#p256-key"),
    );
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .signing_key = "issuer-p256-key".to_string();
    config
        .validate()
        .expect("an ES256 credential profile signing key validates");
}

#[test]
pub(super) fn non_eddsa_signing_key_rejected_as_access_token_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        es256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config.auth.access_token_signing.signing_key_id = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("client_signing_key_id"));
}

#[test]
pub(super) fn non_eddsa_signing_key_rejected_as_federation_key() {
    let mut config = valid_federation_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        es256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config.federation.signing.signing_key = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("client_signing_key_id"));
}

#[test]
pub(super) fn signing_key_alg_must_be_eddsa_es256_or_rs256() {
    let mut config = valid_pre_auth_config();
    config
        .evidence
        .signing_keys
        .get_mut("issuer-key")
        .expect("issuer-key exists")
        .alg = "PS256".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains(CREDENTIAL_SIGNING_ALG_EDDSA));
    assert!(reason.contains(CREDENTIAL_SIGNING_ALG_ES256));
    assert!(reason.contains(CLIENT_ASSERTION_SIGNING_ALG_RS256));
}

#[test]
pub(super) fn pre_auth_enabled_requires_oid4vci_enabled() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.enabled = false;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("requires oid4vci.enabled = true"));
}

#[test]
pub(super) fn pre_auth_allows_optional_tx_code() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .validate()
        .expect("operators may explicitly disable tx_code when required for wallet interop");
}

#[test]
pub(super) fn pre_auth_optional_tx_code_caps_bearer_offer_ttl() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS + 1;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("tx_code.required = false"));

    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .validate()
        .expect("bearer-offer mode validates at the explicit cap");
}

#[test]
pub(super) fn pre_auth_requires_esignet_client_id() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.esignet.client_id = String::new();
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("esignet.client_id"));
}

#[test]
pub(super) fn pre_auth_rejects_out_of_range_code_ttl() {
    let mut config = valid_pre_auth_config();
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 0;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("pre_authorized_code_ttl_seconds"));
}

#[test]
pub(super) fn pre_auth_requires_tx_code_rate_limit() {
    let mut config = valid_pre_auth_config();
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("tx_code_attempts_per_code_per_minute"));
}

#[test]
pub(super) fn pre_auth_optional_tx_code_does_not_require_tx_code_rate_limit() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    config
        .validate()
        .expect("tx_code attempt limits are only required when tx_code is required");
}

#[test]
pub(super) fn pre_auth_userinfo_binding_requires_esignet_userinfo_url() {
    let mut config = valid_pre_auth_config();
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    // Satisfy the resource-server userinfo rule so the failure is
    // specifically the missing pre-auth eSignet userinfo endpoint.
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.userinfo_endpoint = Some("https://id.example.gov/userinfo".to_string());
    }
    config.oid4vci.pre_authorized_code.esignet.userinfo_url = String::new();
    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("esignet.userinfo_url"),
        "unexpected reason: {reason}"
    );
}

#[test]
pub(super) fn pre_auth_userinfo_binding_accepts_configured_userinfo_url() {
    let mut config = valid_pre_auth_config();
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.userinfo_endpoint = Some("https://id.example.gov/userinfo".to_string());
    }
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        "https://id.example.gov/userinfo".to_string();
    config
        .validate()
        .expect("userinfo-sourced pre-auth binding validates with a userinfo_url");
}
