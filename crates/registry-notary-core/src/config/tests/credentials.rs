use super::support::*;
use super::*;
#[allow(unused_imports)]
use super::{auth::*, infrastructure::*, issuance::*, preauth::*, root::*};

#[test]
pub(super) fn proof_of_possession_required_with_only_did_jwk_is_valid() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    add_registry_credential_claim(&mut config, "some-claim", "test-profile");
    assert!(
        config.validate().is_ok(),
        "did:jwk only should pass validation"
    );
}

#[test]
pub(super) fn credential_profile_format_must_use_current_sd_jwt_vc_media_type() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: sd_jwt_vc
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("legacy-alias".to_string(), profile);

    let err = config
        .validate()
        .expect_err("legacy profile format alias must fail validation");
    match err {
        EvidenceConfigError::UnsupportedCredentialProfileFormat { profile, format } => {
            assert_eq!(profile, "legacy-alias");
            assert_eq!(format, "sd_jwt_vc");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn credential_profile_default_validity_is_short_lived() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.validity_seconds, 600);
}

#[test]
pub(super) fn credential_profile_default_holder_binding_is_did_jwk() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.holder_binding.mode, "did");
    assert_eq!(
        profile.holder_binding.allowed_did_methods,
        vec!["did:jwk".to_string()]
    );
    assert!(profile.holder_binding.proof_of_possession.is_none());
}

#[test]
pub(super) fn credential_profile_can_explicitly_opt_out_of_holder_binding() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: none
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.holder_binding.mode, "none");
    assert_eq!(
        profile.holder_binding.allowed_did_methods,
        vec!["did:jwk".to_string()]
    );
}

#[test]
pub(super) fn credential_profile_explicit_validity_is_honored() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
validity_seconds: 300
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.validity_seconds, 300);
}

#[test]
pub(super) fn credential_profile_validity_above_general_ceiling_is_rejected() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://vct.example/test
validity_seconds: 601
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("long-lived".to_string(), profile);

    let err = config
        .validate()
        .expect_err("over-ceiling credential validity must fail");
    assert!(matches!(
        err,
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile,
            validity_seconds: 601,
            max_validity_seconds: 600
        } if profile == "long-lived"
    ));
}

#[test]
pub(super) fn credential_profile_non_positive_validity_is_rejected() {
    for invalid in [0, -1] {
        let mut config = minimal_config();
        let mut profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");
        profile.validity_seconds = invalid;
        config
            .evidence
            .credential_profiles
            .insert("invalid-validity".to_string(), profile);

        let err = config
            .validate()
            .expect_err("non-positive credential validity must fail");
        assert!(matches!(
            err,
            EvidenceConfigError::InvalidCredentialProfileValidity { .. }
        ));
    }
}

#[test]
pub(super) fn signing_keys_are_configured_separately_from_credential_profiles() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2026:
  provider: local_jwk_env
  private_jwk_env: ISSUER_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2026
  status: active
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-2026
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    add_registry_credential_claim(&mut config, "some-claim", "test-profile");

    config
        .validate()
        .expect("profile may reference an active signing key");
}

#[test]
pub(super) fn credential_profiles_must_reference_active_signing_keys() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-2025
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("publish-only keys must not be used for new issuance");
    match err {
        EvidenceConfigError::CredentialProfileSigningKeyNotActive { profile, key } => {
            assert_eq!(profile, "test-profile");
            assert_eq!(key, "issuer-2025");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn publish_only_local_jwk_uses_public_jwk_env_only() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  private_jwk_env: OLD_ISSUER_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("publish-only local keys must not require private material");
    assert!(
        err.to_string().contains("public_jwk_env must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn publish_only_signing_key_accepts_bounded_publication_window() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
  publish_until_unix_seconds: 1893456000
"#,
    )
    .expect("signing key YAML is valid");

    let key = config
        .evidence
        .signing_keys
        .get("issuer-2025")
        .expect("publish-only key exists");
    assert_eq!(key.publish_until_unix_seconds, Some(1_893_456_000));
    assert!(key.may_publish_at(1_893_456_000));
    assert!(!key.may_publish_at(1_893_456_001));
    config
        .validate()
        .expect("publish-only key may carry a publication deadline");
}

#[test]
pub(super) fn active_signing_key_rejects_publication_window() {
    let mut config = minimal_config();
    let active = config
        .evidence
        .signing_keys
        .values_mut()
        .find(|key| key.status == SigningKeyStatus::Active)
        .expect("minimal config has an active key");
    active.publish_until_unix_seconds = Some(1_893_456_000);

    let err = config
        .validate()
        .expect_err("active signing keys cannot carry a publication deadline");
    assert!(
        err.to_string()
            .contains("publish_until_unix_seconds is valid only for publish_only signing keys"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn pkcs11_signing_key_shape_validates_without_loading_module() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-hsm
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    add_registry_credential_claim(&mut config, "some-claim", "test-profile");

    config.validate().expect("PKCS#11 key shape validates");
}

#[test]
pub(super) fn file_watch_signing_key_shape_validates_without_secret_material_in_config() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  path: /run/secrets/issuer.jwk
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-file
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    add_registry_credential_claim(&mut config, "some-claim", "test-profile");

    config.validate().expect("file-watch key shape validates");
}

#[test]
pub(super) fn file_watch_signing_key_rejects_secret_fields_and_missing_path() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("file-watch key must use a local path");
    assert!(
        err.to_string().contains("path must not be empty"),
        "unexpected error: {err}"
    );

    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  path: /run/secrets/issuer.jwk
  private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("file-watch key must not carry env-backed private material");
    assert!(
        err.to_string()
            .contains("private_jwk_env is not valid for this signing key provider"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn pkcs11_signing_key_requires_absolute_module_path() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("relative module path must fail validation");
    assert!(
        err.to_string().contains("module_path must be absolute"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn pkcs11_signing_key_rejects_rs256_algorithm() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: RS256
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("PKCS#11 signing only supports EdDSA");
    assert!(
        err.to_string()
            .contains("pkcs11 provider supports only EdDSA"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn publish_only_pkcs11_key_uses_public_jwk_env_only() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm-old:
  provider: pkcs11
  public_jwk_env: REGISTRY_NOTARY_OLD_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm-old
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");

    config
        .validate()
        .expect("publish-only PKCS#11 key needs only public metadata");

    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm-old:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  public_jwk_env: REGISTRY_NOTARY_OLD_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm-old
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("publish-only PKCS#11 key must not require HSM access");
    assert!(
        err.to_string()
            .contains("module_path is not valid for this signing key provider"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn local_pkcs12_file_provider_is_deferred_without_partial_support() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-p12:
  provider: local_pkcs12_file
  path: /run/secrets/issuer.p12
  password_env: REGISTRY_NOTARY_P12_PASSWORD
  alg: EdDSA
  kid: did:web:issuer.example#issuer-p12
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("PKCS#12 support must fail closed until it is implemented");
    assert!(
        err.to_string()
            .contains("local_pkcs12_file provider is intentionally not implemented yet"),
        "unexpected error: {err}"
    );
}

#[test]
pub(super) fn proof_of_possession_required_with_non_jwk_method_is_rejected() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
    - did:key
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("did:key with proof_of_possession required must fail");
    match &err {
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { profile, methods } => {
            assert_eq!(profile, "test-profile");
            assert!(
                methods.contains(&"did:key".to_string()),
                "error must name did:key, got: {methods:?}"
            );
            assert!(
                !methods.contains(&"did:jwk".to_string()),
                "did:jwk must not appear in the unsupported list"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn non_jwk_methods_are_rejected_even_without_proof_of_possession() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  allowed_did_methods:
    - did:jwk
    - did:key
    - did:web
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    let err = config
        .validate()
        .expect_err("non-did:jwk holder methods must fail validation");
    match &err {
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { profile, methods } => {
            assert_eq!(profile, "test-profile");
            assert_eq!(methods, &vec!["did:key".to_string(), "did:web".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Finding 8: depends_on cycle detection
// -----------------------------------------------------------------------

#[test]
pub(super) fn valid_dag_passes_cycle_detection() {
    // A -> B -> C (no cycle)
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-b".to_string()];
    let mut claim_b = minimal_claim("claim-b");
    claim_b.depends_on = vec!["claim-c".to_string()];
    let claim_c = minimal_claim("claim-c");
    config.evidence.claims = vec![claim_a, claim_b, claim_c];
    assert!(config.validate().is_ok(), "A->B->C DAG should pass");
}

#[test]
pub(super) fn two_node_cycle_is_detected() {
    // A -> B -> A
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-b".to_string()];
    let mut claim_b = minimal_claim("claim-b");
    claim_b.depends_on = vec!["claim-a".to_string()];
    config.evidence.claims = vec![claim_a, claim_b];

    let err = config
        .validate()
        .expect_err("A->B->A cycle must fail validation");
    match &err {
        EvidenceConfigError::DependsOnCycle { cycle } => {
            assert!(
                cycle.contains(&"claim-a".to_string()),
                "cycle must mention claim-a, got: {cycle:?}"
            );
            assert!(
                cycle.contains(&"claim-b".to_string()),
                "cycle must mention claim-b, got: {cycle:?}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn self_loop_is_detected() {
    // A -> A
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-a".to_string()];
    config.evidence.claims = vec![claim_a];

    let err = config
        .validate()
        .expect_err("self-loop must fail validation");
    match &err {
        EvidenceConfigError::DependsOnCycle { cycle } => {
            assert!(
                cycle.contains(&"claim-a".to_string()),
                "cycle must mention claim-a, got: {cycle:?}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn unknown_depends_on_is_rejected() {
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-nonexistent".to_string()];
    config.evidence.claims = vec![claim_a];

    let err = config
        .validate()
        .expect_err("depends_on unknown claim must fail validation");
    match &err {
        EvidenceConfigError::DependsOnUnknownClaim { claim, unknown } => {
            assert_eq!(claim, "claim-a");
            assert_eq!(unknown, "claim-nonexistent");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// GH#170 / RS-DM-CLAIM Section 10: load-time validation for invariants
// the loader previously deferred to request/evaluation time.
// -----------------------------------------------------------------------

#[test]
pub(super) fn duplicate_claim_id_is_rejected() {
    // REQ-DM-CLAIM-001: two claims sharing an id previously loaded
    // cleanly; the loader must now reject it.
    let mut config = minimal_config();
    let claim_a = minimal_claim("repeated-id");
    let claim_b = minimal_claim("repeated-id");
    config.evidence.claims = vec![claim_a, claim_b];

    let err = config
        .validate()
        .expect_err("duplicate claim id must fail validation");
    match &err {
        EvidenceConfigError::DuplicateClaimId { claim } => {
            assert_eq!(claim, "repeated-id");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert!(
        err.to_string().contains("repeated-id"),
        "error must name the offending claim id: {err}"
    );
}

#[test]
pub(super) fn disclosure_default_outside_allowed_is_rejected() {
    // REQ-DM-CLAIM-008: a disclosure default outside the allowed set
    // previously surfaced only when a result was rendered. This is the
    // most consequential of the three Section 10 gaps: a
    // privacy-sensitive claim could otherwise ship an internally
    // inconsistent disclosure policy that only fails on first render.
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency-status");
    claim.disclosure = DisclosureConfig {
        default: "value".to_string(),
        allowed: vec!["redacted".to_string()],
        downgrade: "deny".to_string(),
    };
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("disclosure default outside allowed must fail validation");
    match &err {
        EvidenceConfigError::ClaimDisclosureDefaultNotAllowed {
            claim,
            default,
            allowed,
        } => {
            assert_eq!(claim, "residency-status");
            assert_eq!(default, "value");
            assert_eq!(allowed, &vec!["redacted".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("residency-status") && message.contains("disclosure"),
        "error must name the offending claim id and field: {message}"
    );
}

#[test]
pub(super) fn omitted_claim_formats_default_to_claim_result_json() {
    let claim = minimal_claim("default-format");

    assert_eq!(
        claim.formats,
        vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
        "omitted formats must retain the canonical evaluation representation"
    );
}

#[test]
pub(super) fn explicit_empty_claim_formats_are_rejected() {
    let mut config = minimal_config();
    let claim: ClaimDefinition = serde_norway::from_str(
        r#"
id: empty-format
title: Empty format claim
version: "1.0"
subject_type: person
evidence_mode:
  type: self_attested
rule:
  type: cel
  expression: "true"
formats: []
"#,
    )
    .expect("claim YAML is valid");
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("an explicitly empty formats list must fail validation");
    match &err {
        EvidenceConfigError::EmptyClaimFormats { claim } => {
            assert_eq!(claim, "empty-format");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("empty-format") && message.contains("omit formats"),
        "error must name the claim and explain how to use the default: {message}"
    );
}

#[test]
pub(super) fn canonical_claim_format_is_valid() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("canonical-format");
    claim.formats = vec![FORMAT_CLAIM_RESULT_JSON.to_string()];
    config.evidence.claims = vec![claim];

    config
        .validate()
        .expect("the canonical evaluation format must validate");
}

#[test]
pub(super) fn canonical_and_cccev_claim_formats_are_valid() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("canonical-and-cccev");
    claim.formats = vec![
        FORMAT_CLAIM_RESULT_JSON.to_string(),
        FORMAT_CCCEV_JSONLD.to_string(),
    ];
    config.evidence.claims = vec![claim];

    config
        .validate()
        .expect("the canonical and CCCEV evaluation formats must validate");
}

#[test]
pub(super) fn cccev_without_canonical_claim_format_is_rejected() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("cccev-only");
    claim.formats = vec![FORMAT_CCCEV_JSONLD.to_string()];
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("CCCEV-only formats must fail validation");
    match &err {
        EvidenceConfigError::MissingCanonicalClaimFormat { claim } => {
            assert_eq!(claim, "cccev-only");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("cccev-only") && message.contains(FORMAT_CLAIM_RESULT_JSON),
        "error must name the claim and canonical format: {message}"
    );
}

#[test]
pub(super) fn sd_jwt_vc_claim_format_is_rejected_before_canonical_omission() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("sd-jwt-only");
    claim.formats = vec![FORMAT_SD_JWT_VC.to_string()];
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("SD-JWT VC is not an evaluation response format");
    match &err {
        EvidenceConfigError::UnsupportedClaimFormat { claim, format } => {
            assert_eq!(claim, "sd-jwt-only");
            assert_eq!(format, FORMAT_SD_JWT_VC);
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("credential_profiles") && message.contains(FORMAT_SD_JWT_VC),
        "error must identify SD-JWT VC and its configuration home: {message}"
    );
}

#[test]
pub(super) fn mixed_claim_formats_reject_the_first_unsupported_format() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("mixed-formats");
    claim.formats = vec![
        FORMAT_CLAIM_RESULT_JSON.to_string(),
        FORMAT_SD_JWT_VC.to_string(),
        "application/example+json".to_string(),
    ];
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("mixed formats must reject the unsupported SD-JWT VC entry");
    match &err {
        EvidenceConfigError::UnsupportedClaimFormat { claim, format } => {
            assert_eq!(claim, "mixed-formats");
            assert_eq!(format, FORMAT_SD_JWT_VC);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn unknown_claim_format_is_rejected() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("unknown-format");
    claim.formats = vec![
        FORMAT_CLAIM_RESULT_JSON.to_string(),
        "application/example+json".to_string(),
    ];
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("unknown evaluation formats must fail validation");
    match &err {
        EvidenceConfigError::UnsupportedClaimFormat { claim, format } => {
            assert_eq!(claim, "unknown-format");
            assert_eq!(format, "application/example+json");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert!(
        err.to_string().contains("application/example+json"),
        "error must name the offending format: {err}"
    );
}

#[test]
pub(super) fn empty_allowed_claims_is_rejected() {
    // A credential profile with an empty allowed_claims would silently
    // accept every claim at issue time (see api.rs `is_empty()` short
    // circuit). Reject at config-load time so the operator must opt in.
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("the_profile_id".to_string(), profile);

    let err = config
        .validate()
        .expect_err("empty allowed_claims must fail validation");
    match &err {
        EvidenceConfigError::EmptyAllowedClaims { profile } => {
            assert_eq!(profile, "the_profile_id");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Stage 1: concurrency config and the kill-switch
// -----------------------------------------------------------------------

#[test]
pub(super) fn default_concurrency_has_documented_defaults() {
    let cfg = ConcurrencyConfig::default();
    assert_eq!(cfg.subjects, 16);
    assert!(cfg.validate().is_ok());
}

#[test]
pub(super) fn concurrency_zero_subjects_is_rejected() {
    let mut config = minimal_config();
    config.evidence.concurrency = ConcurrencyConfig { subjects: 0 };
    let err = config
        .validate()
        .expect_err("subjects=0 must fail validation");
    assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
}

#[test]
pub(super) fn concurrency_subjects_one_validates() {
    let mut config = minimal_config();
    config.evidence.concurrency = ConcurrencyConfig { subjects: 1 };
    assert!(config.validate().is_ok());
}

// -----------------------------------------------------------------------
// Machine quota config
// -----------------------------------------------------------------------

#[test]
pub(super) fn machine_quota_defaults_to_disabled_with_documented_limit() {
    let cfg = MachineQuotaConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.subjects_per_minute, 6000);
    assert!(cfg.validate().is_ok());
}

#[test]
pub(super) fn machine_quota_disabled_zero_limit_still_validates() {
    // A zero subjects_per_minute is only invalid once the quota is
    // enabled; an operator-provided but unused value must not block
    // deployments that leave the quota off.
    let cfg = MachineQuotaConfig {
        enabled: false,
        subjects_per_minute: 0,
    };
    assert!(cfg.validate().is_ok());
}

#[test]
pub(super) fn machine_quota_enabled_zero_limit_is_rejected() {
    let mut config = minimal_config();
    config.evidence.machine_quota = MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 0,
    };
    let err = config
        .validate()
        .expect_err("enabled machine_quota with subjects_per_minute=0 must fail validation");
    match &err {
        EvidenceConfigError::InvalidMachineQuotaConfig { reason } => {
            assert!(reason.contains("subjects_per_minute"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn machine_quota_enabled_with_positive_limit_validates() {
    let mut config = minimal_config();
    config.evidence.machine_quota = MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 1,
    };
    assert!(config.validate().is_ok());
}
