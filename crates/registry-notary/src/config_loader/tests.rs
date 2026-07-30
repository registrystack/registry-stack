// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

const PATH_SENTINEL: &str = "/private/SENTINEL_COUNTRY_CONFIG_PATH";
const HASH_SENTINEL: &str =
    "sha256:SENTINEL_EXPECTED_COUNTRY_DIGEST_11111111111111111111111111111111";
const OTHER_HASH_SENTINEL: &str =
    "sha256:SENTINEL_ACTUAL_COUNTRY_DIGEST_2222222222222222222222222222222222";
const PARSER_SENTINEL: &str = "SENTINEL_PRIVATE_PARSER_TEXT";
const SECRET_SENTINEL: &str = "SENTINEL_PRIVATE_SECRET";
const COUNTRY_SENTINEL: &str = "SENTINEL_PRIVATE_COUNTRY_VALUE";

fn rewrite_signed_bundle_product(fixture: &SignedBundleFixture, product: &str) {
    let mut manifest: ConfigBundleManifest = serde_json::from_slice(
        &std::fs::read(fixture.bundle_dir.join("manifest.json")).expect("manifest reads"),
    )
    .expect("manifest parses");
    assert_eq!(product, "registry-relay");
    manifest.acceptance_identity.product = ProductAcceptanceProductV1::RegistryRelay;
    manifest.acceptance_identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private JWK parses");
    let kid = private.public().jkt().expect("signer thumbprint");
    write_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);

    let mut anchor: ConfigTrustAnchor =
        serde_json::from_slice(&std::fs::read(&fixture.anchor_path).expect("anchor reads"))
            .expect("anchor parses");
    anchor.acceptance_identity = manifest.acceptance_identity;
    std::fs::write(
        &fixture.anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");
}

fn config_bundle_error_cases() -> Vec<(ConfigBundleError, BundleVerificationCode)> {
    vec![
        (
            ConfigBundleError::Io(PATH_SENTINEL.to_string()),
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBundleError::Json(PARSER_SENTINEL.to_string()),
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBundleError::InvalidManifest(COUNTRY_SENTINEL),
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBundleError::InvalidAcceptanceIdentity(COUNTRY_SENTINEL),
            BundleVerificationCode::REJECTED_BINDING,
        ),
        (
            ConfigBundleError::InvalidTrustAnchor(SECRET_SENTINEL),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::InvalidPermissions(PATH_SENTINEL),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::InvalidBreakGlass(SECRET_SENTINEL),
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBundleError::InvalidSignatureEnvelope(SECRET_SENTINEL),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::InvalidAnchorTransition(SECRET_SENTINEL),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::AnchorTransitionRejected(SECRET_SENTINEL),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::BindingMismatch(COUNTRY_SENTINEL),
            BundleVerificationCode::REJECTED_BINDING,
        ),
        (
            ConfigBundleError::SignatureRejected,
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::FileClosure(PATH_SENTINEL.to_string()),
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
        (
            ConfigBundleError::HashMismatch {
                path: PATH_SENTINEL.to_string(),
                expected: HASH_SENTINEL.to_string(),
                actual: OTHER_HASH_SENTINEL.to_string(),
            },
            BundleVerificationCode::REJECTED_SIGNATURE,
        ),
    ]
}

fn config_boot_error_cases() -> Vec<(ConfigBootError, BundleVerificationCode)> {
    vec![
        (
            ConfigBootError::Store(registry_platform_ops::AntiRollbackStoreError::InvalidState(
                SECRET_SENTINEL.to_string(),
            )),
            BundleVerificationCode::REJECTED_ROLLBACK,
        ),
        (
            ConfigBootError::Bundle(ConfigBundleError::BindingMismatch(COUNTRY_SENTINEL)),
            BundleVerificationCode::REJECTED_BINDING,
        ),
        (
            ConfigBootError::NonMonotonicSequence,
            BundleVerificationCode::REJECTED_ROLLBACK,
        ),
        (
            ConfigBootError::OverrideHashMismatch,
            BundleVerificationCode::REJECTED_ROLLBACK,
        ),
        (
            ConfigBootError::MissingUnsignedConfigPath,
            BundleVerificationCode::REJECTED_ROLLBACK,
        ),
        (
            ConfigBootError::UnsignedConfigHashMismatch {
                expected: HASH_SENTINEL.to_string(),
                actual: OTHER_HASH_SENTINEL.to_string(),
            },
            BundleVerificationCode::REJECTED_ROLLBACK,
        ),
        (
            ConfigBootError::MissingSignedBundleId,
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBootError::MissingSignedBundleManifestHash,
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBootError::MissingSignedBundleSequence,
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBootError::MissingOverridePin,
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
        (
            ConfigBootError::InvalidOverridePath,
            BundleVerificationCode::REJECTED_VALIDATION,
        ),
    ]
}

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
fn bundle_startup_rejections_use_every_exact_static_catalog_definition() {
    for code in BundleVerificationCode::ALL {
        let definition = code.definition();
        let rejection = safe_bundle_rejection("config.bundle_rejected", *code, None);

        assert_eq!(rejection.classification_code, "config.bundle_rejected");
        assert_eq!(rejection.result, code.as_str());
        assert_eq!(rejection.reason, "none");
        assert_eq!(
            rejection.activation_code,
            NotaryActivationCode::CONFIGURATION_INVALID.as_str()
        );
        assert_eq!(rejection.safe_meaning, definition.safe_meaning);
        assert_eq!(rejection.safe_remediation, definition.safe_remediation);
    }
}

#[test]
fn typed_bundle_failures_map_to_exact_value_free_startup_definitions() {
    let forbidden = [
        PATH_SENTINEL,
        HASH_SENTINEL,
        OTHER_HASH_SENTINEL,
        PARSER_SENTINEL,
        SECRET_SENTINEL,
        COUNTRY_SENTINEL,
    ];

    for (error, expected) in config_bundle_error_cases() {
        let code = bundle_verify_rejection_code(&error);
        assert_eq!(code, expected);
        let rejection = safe_bundle_rejection("config.bundle_rejected", code, None);
        assert_eq!(rejection.result, expected.as_str());
        assert_eq!(rejection.safe_meaning, expected.definition().safe_meaning);
        assert_eq!(
            rejection.safe_remediation,
            expected.definition().safe_remediation
        );
        let rendered = format!("{rejection:?}");
        for sentinel in forbidden {
            assert!(
                !rendered.contains(sentinel),
                "safe startup rejection exposed {sentinel:?}: {rendered}"
            );
        }
    }
}

#[test]
fn typed_boot_failures_preserve_binding_rollback_and_validation_definitions() {
    for (error, expected) in config_boot_error_cases() {
        let code = error.bundle_rejection_code();
        assert_eq!(code, expected);
        let rejection = safe_bundle_rejection("config.bundle_rejected", code, None);
        assert_eq!(rejection.result, expected.as_str());
        assert_eq!(rejection.safe_meaning, expected.definition().safe_meaning);
        assert_eq!(
            rejection.safe_remediation,
            expected.definition().safe_remediation
        );
    }
}

#[test]
fn local_configuration_rejection_uses_notary_configuration_definition() {
    let definition = NotaryActivationCode::CONFIGURATION_INVALID.definition();
    let rejection = safe_configuration_rejection(
        NotaryActivationCode::CONFIGURATION_INVALID.as_str(),
        BundleVerificationCode::REJECTED_VALIDATION.as_str(),
        None,
    );

    assert_eq!(rejection.activation_code, definition.code.as_str());
    assert_eq!(rejection.safe_meaning, definition.meaning);
    assert_eq!(rejection.safe_remediation, definition.remediation);
}

#[test]
fn config_boot_error_mapping_preserves_static_bundle_code_and_drops_hash_values() {
    let error = map_config_boot_error(ConfigBootError::UnsignedConfigHashMismatch {
        expected: HASH_SENTINEL.to_string(),
        actual: OTHER_HASH_SENTINEL.to_string(),
    });
    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("config boot errors retain only the typed bundle rejection");

    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_ROLLBACK);
    assert!(std::error::Error::source(failure).is_none());
    let rendered = format!("{failure} {failure:?}");
    assert!(rendered.contains(BundleVerificationCode::REJECTED_ROLLBACK.as_str()));
    assert!(!rendered.contains(HASH_SENTINEL));
    assert!(!rendered.contains(OTHER_HASH_SENTINEL));
}

#[test]
fn verified_bundle_parse_failure_returns_static_validation_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let mut verified =
        verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path).expect("bundle verifies");
    verified.config_bytes = b"SENTINEL_PRIVATE_COUNTRY_VALUE: [invalid parser text".to_vec();
    let bootstrap =
        parse_config_document(&notary_bootstrap_config(&fixture)).expect("bootstrap config parses");
    let config_trust = bootstrap
        .config
        .config_trust
        .expect("bootstrap config has trust settings");

    let error = load_verified_bundle_server_config(&config_trust, true, verified)
        .expect_err("verified bundle parser failure rejects startup");
    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("verified bundle parser failures retain a validation category");

    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_VALIDATION);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains("SENTINEL_PRIVATE_COUNTRY_VALUE"));
    assert!(!rendered.contains("invalid parser text"));
}

#[test]
fn verified_bundle_product_validation_failure_returns_static_validation_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let governed_invalid =
        notary_bundle_runtime_config().replace("mode: dedicated", "mode: shared_with_public");
    let fixture = write_signed_notary_bundle_with_config(&tmp, governed_invalid);
    let verified =
        verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path).expect("bundle verifies");
    let bootstrap =
        parse_config_document(&notary_bootstrap_config(&fixture)).expect("bootstrap config parses");
    let config_trust = bootstrap
        .config
        .config_trust
        .expect("bootstrap config has trust settings");

    let error = load_verified_bundle_server_config(&config_trust, true, verified)
        .expect_err("verified bundle product validation failure rejects startup");
    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("verified bundle validation failures retain a validation category");

    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_VALIDATION);
}

#[test]
fn missing_startup_config_path_returns_value_free_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sentinel = "SENTINEL_PRIVATE_COUNTRY_CONFIG_PATH";
    let config_path = tmp.path().join(sentinel).join("notary.yaml");

    let error = load_server_config(&config_path, false)
        .expect_err("missing startup config must fail closed");
    let failure = error
        .downcast_ref::<NotaryActivationFailure>()
        .expect("missing startup config uses the redacted activation boundary");

    assert_eq!(failure.code(), NotaryActivationCode::CONFIGURATION_INVALID);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains(sentinel));
    assert!(!rendered.contains(config_path.to_string_lossy().as_ref()));
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
fn direct_signed_bundle_server_config_loads_without_bootstrap_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);

    let loaded = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        true,
    )
    .expect("direct signed bundle config loads");

    assert_eq!(loaded.config_source, ConfigSource::SignedBundleFile);
    assert!(
        loaded.config.config_trust.is_none(),
        "direct startup must not inject bootstrap trust configuration into the signed document"
    );
    let provenance = loaded.config_provenance.expect("provenance");
    assert_eq!(provenance.source, ConfigSource::SignedBundleFile);
    assert_eq!(provenance.internal_config_hash, fixture.config_hash);
    let acceptance = loaded
        .pending_bundle_acceptance
        .expect("pending acceptance");
    assert_eq!(acceptance.state_path, fixture.state_path);
    assert_eq!(
        acceptance.bundle_id.as_deref(),
        Some("notary-loader-bundle")
    );
    assert!(matches!(
        acceptance.state_action,
        BundleStateAction::Initialize
    ));
}

#[test]
fn direct_signed_serve_rejects_absent_state_without_initializing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);

    let error = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        false,
    )
    .expect_err("ordinary serve requires existing acceptance state");

    assert_eq!(
        error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("missing-state failure is typed")
            .code(),
        BundleVerificationCode::REJECTED_ROLLBACK
    );
    assert!(
        !fixture.state_path.exists(),
        "ordinary serve must never initialize absent state"
    );
}

#[test]
fn direct_startup_rejects_missing_instance_id_before_state_resolution() {
    const STATE_SENTINEL: &str = "SENTINEL_PRIVATE_ANTIROLLBACK_STATE";

    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    rewrite_signed_bundle_instance_id(&fixture, None);
    std::fs::write(&fixture.state_path, STATE_SENTINEL).expect("malformed state writes");

    let error = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        true,
    )
    .expect_err("instance-unbound bundle must reject before reading direct startup state");

    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("missing instance binding failure is typed");
    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_BINDING);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains(fixture.bundle_dir.to_string_lossy().as_ref()));
    assert!(!rendered.contains(fixture.anchor_path.to_string_lossy().as_ref()));
    assert!(!rendered.contains(fixture.state_path.to_string_lossy().as_ref()));
    assert!(!rendered.contains(STATE_SENTINEL));
    assert_eq!(
        std::fs::read_to_string(&fixture.state_path).expect("state remains readable"),
        STATE_SENTINEL,
        "missing instance binding must reject without consulting or changing anti-rollback state"
    );
}

#[test]
fn direct_startup_missing_instance_id_cannot_share_state_across_instance_anchors() {
    const FIRST_INSTANCE_SENTINEL: &str = "SENTINEL_PRIVATE_NOTARY_INSTANCE_ALPHA";
    const SECOND_INSTANCE_SENTINEL: &str = "SENTINEL_PRIVATE_NOTARY_INSTANCE_BRAVO";

    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    rewrite_signed_bundle_instance_id(&fixture, None);
    let anchor: ConfigTrustAnchor =
        serde_json::from_slice(&std::fs::read(&fixture.anchor_path).expect("anchor reads"))
            .expect("anchor parses");
    let first_anchor_path = tmp.path().join("first-trust-anchor.json");
    let second_anchor_path = tmp.path().join("second-trust-anchor.json");
    for (path, instance_id) in [
        (&first_anchor_path, FIRST_INSTANCE_SENTINEL),
        (&second_anchor_path, SECOND_INSTANCE_SENTINEL),
    ] {
        let mut instance_anchor = anchor.clone();
        instance_anchor.acceptance_identity.instance = instance_id.to_string();
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&instance_anchor).expect("anchor serializes"),
        )
        .expect("anchor writes");
    }

    for anchor_path in [&first_anchor_path, &second_anchor_path] {
        let error = load_direct_signed_bundle_server_config(
            &fixture.bundle_dir,
            anchor_path,
            &fixture.state_path,
            true,
        )
        .expect_err("instance-unbound bundle must reject every direct instance anchor");
        let failure = error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("missing instance binding failure is typed");
        assert_eq!(failure.code(), BundleVerificationCode::REJECTED_BINDING);
        let rendered = format!("{failure} {failure:?}");
        assert!(!rendered.contains(FIRST_INSTANCE_SENTINEL));
        assert!(!rendered.contains(SECOND_INSTANCE_SENTINEL));
    }
    assert!(
        !fixture.state_path.exists(),
        "different anchors must not converge on an empty-instance anti-rollback lane"
    );
}

#[test]
fn direct_startup_rejects_verified_cross_product_bundle_before_state_resolution() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    rewrite_signed_bundle_product(&fixture, "registry-relay");

    let error = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        true,
    )
    .expect_err("verified Relay bundle must not start the Notary");

    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("cross-product failure is typed");
    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_BINDING);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains("registry-relay"));
    assert!(!rendered.contains(fixture.bundle_dir.to_string_lossy().as_ref()));
    assert!(!rendered.contains(fixture.anchor_path.to_string_lossy().as_ref()));
    assert!(
        !fixture.state_path.exists(),
        "product binding must reject before anti-rollback state mutation"
    );
}

#[test]
fn direct_startup_rejects_every_acceptance_identity_mismatch_before_state_access() {
    const STATE_SENTINEL: &str = "SENTINEL_PRIVATE_ACCEPTANCE_STATE";

    for dimension in [
        "trust_domain",
        "project",
        "environment",
        "lane",
        "product",
        "stream",
        "instance",
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);
        let mut manifest: ConfigBundleManifest = serde_json::from_slice(
            &std::fs::read(fixture.bundle_dir.join("manifest.json")).expect("manifest reads"),
        )
        .expect("manifest parses");
        match dimension {
            "trust_domain" => {
                manifest.acceptance_identity.trust_domain = ProductTrustDomainV1::Development;
            }
            "project" => {
                manifest.acceptance_identity.project = "other-project".to_string();
            }
            "environment" => {
                manifest.acceptance_identity.environment = "other-environment".to_string();
            }
            "lane" => {
                manifest.acceptance_identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
            }
            "product" => {
                manifest.acceptance_identity.product = ProductAcceptanceProductV1::RegistryRelay;
            }
            "stream" => {
                manifest.acceptance_identity.stream = "other-stream".to_string();
            }
            "instance" => {
                manifest.acceptance_identity.instance = "other-instance".to_string();
            }
            _ => unreachable!(),
        }
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private JWK parses");
        let kid = private.public().jkt().expect("signer thumbprint");
        write_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
        std::fs::write(&fixture.state_path, STATE_SENTINEL).expect("state sentinel writes");

        let error = load_direct_signed_bundle_server_config(
            &fixture.bundle_dir,
            &fixture.anchor_path,
            &fixture.state_path,
            false,
        )
        .expect_err("identity mismatch rejects direct startup");
        let failure = error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("identity mismatch failure is typed");
        assert!(
            [
                BundleVerificationCode::REJECTED_BINDING,
                BundleVerificationCode::REJECTED_VALIDATION,
            ]
            .contains(&failure.code()),
            "unexpected {dimension} failure: {failure}"
        );
        assert_eq!(
            std::fs::read_to_string(&fixture.state_path).expect("state remains readable"),
            STATE_SENTINEL,
            "{dimension} mismatch accessed or changed state"
        );
    }
}

#[test]
fn direct_startup_rejects_a_valid_relay_lane_swap_before_state_access() {
    const STATE_SENTINEL: &str = "SENTINEL_PRIVATE_LANE_SWAP_STATE";

    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let mut manifest: ConfigBundleManifest = serde_json::from_slice(
        &std::fs::read(fixture.bundle_dir.join("manifest.json")).expect("manifest reads"),
    )
    .expect("manifest parses");
    manifest.acceptance_identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
    manifest.acceptance_identity.product = ProductAcceptanceProductV1::RegistryRelay;
    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private JWK parses");
    let kid = private.public().jkt().expect("signer thumbprint");
    write_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
    let mut anchor: ConfigTrustAnchor =
        serde_json::from_slice(&std::fs::read(&fixture.anchor_path).expect("anchor reads"))
            .expect("anchor parses");
    anchor.acceptance_identity = manifest.acceptance_identity;
    std::fs::write(
        &fixture.anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");
    std::fs::write(&fixture.state_path, STATE_SENTINEL).expect("state sentinel writes");

    let error = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        false,
    )
    .expect_err("Relay lane swap rejects Notary startup");
    assert_eq!(
        error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("lane-swap failure is typed")
            .code(),
        BundleVerificationCode::REJECTED_BINDING
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.state_path).expect("state remains readable"),
        STATE_SENTINEL
    );
}

#[test]
fn bootstrap_startup_rejects_verified_cross_product_bundle_without_fallback() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    rewrite_signed_bundle_product(&fixture, "registry-relay");
    let unsigned_path = tmp.path().join("authorized-unsigned-notary.yaml");
    let unsigned_config = notary_bundle_runtime_config();
    std::fs::write(&unsigned_path, unsigned_config.as_bytes()).expect("unsigned config writes");
    let mut relay_identity = notary_acceptance_identity();
    relay_identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
    relay_identity.product = ProductAcceptanceProductV1::RegistryRelay;
    let key = registry_platform_ops::AntiRollbackKey {
        acceptance_identity: relay_identity,
    };
    let fallback_state = registry_platform_ops::AntiRollbackRecord {
        key: key.clone(),
        last_sequence: 2,
        last_config_hash: sha256_uri(b"newer-cross-product-config"),
        last_bundle_manifest_hash:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        last_bundle_id: "newer-cross-product-bundle".to_string(),
        accepted_anchor: notary_accepted_anchor_pin(),
        override_pin: Some(registry_platform_ops::ConfigOverridePin {
            active: true,
            mode: ConfigOverrideMode::AcceptUnsigned,
            config_hash: sha256_uri(unsigned_config.as_bytes()),
            config_path: Some(unsigned_path.to_string_lossy().into_owned()),
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            used_at: "2026-07-30T00:00:00Z".to_string(),
            operator: "security-review".to_string(),
            reason: "pin fallback regression".to_string(),
        }),
        break_glass: Default::default(),
        local_approvals: Default::default(),
    };
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&fallback_state).expect("fallback state serializes"),
    )
    .expect("pre-existing fallback state writes");
    let config_path = tmp.path().join("bootstrap.yaml");
    std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");

    let error = load_server_config(&config_path, false)
        .expect_err("verified Relay bundle must not select Notary bootstrap fallback");

    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("cross-product failure is typed");
    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_BINDING);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains("registry-relay"));
    let retained = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
        .load(&key)
        .expect("existing fallback state remains readable");
    assert_eq!(
        retained.last_sequence, 2,
        "product binding must reject before bootstrap fallback or state mutation"
    );
}

#[test]
fn server_config_input_debug_is_value_free() {
    let signed = ServerConfigInput::SignedBundle {
        bundle_dir: PathBuf::from("/private/SENTINEL_BUNDLE_PATH"),
        anchor_path: PathBuf::from("/private/SENTINEL_ANCHOR_PATH"),
        state_path: PathBuf::from("/private/SENTINEL_STATE_PATH"),
    };
    let local = ServerConfigInput::LocalFile(PathBuf::from("/private/SENTINEL_LOCAL_PATH"));

    let rendered = format!("{signed:?} {local:?}");

    assert!(rendered.contains("SignedBundle"));
    assert!(rendered.contains("LocalFile"));
    assert!(!rendered.contains("SENTINEL"));
    assert!(!rendered.contains("/private"));
}

#[test]
fn direct_signed_bundle_rejects_signature_and_binding_failures_exactly() {
    let signature_tmp = tempfile::tempdir().expect("tempdir");
    let signature_fixture = write_signed_notary_bundle(&signature_tmp);
    std::fs::write(
        signature_fixture.bundle_dir.join("manifest.sig.json"),
        r#"{"schema":"registry.platform.config_bundle_signatures.v1","signatures":[]}"#,
    )
    .expect("invalid signature envelope writes");

    let signature_error = load_direct_signed_bundle_server_config(
        &signature_fixture.bundle_dir,
        &signature_fixture.anchor_path,
        &signature_fixture.state_path,
        true,
    )
    .expect_err("invalid signature rejects direct startup");
    assert_eq!(
        signature_error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("signature failure is typed")
            .code(),
        BundleVerificationCode::REJECTED_SIGNATURE
    );

    let binding_tmp = tempfile::tempdir().expect("tempdir");
    let binding_fixture = write_signed_notary_bundle(&binding_tmp);
    let mut anchor: ConfigTrustAnchor =
        serde_json::from_slice(&std::fs::read(&binding_fixture.anchor_path).expect("anchor reads"))
            .expect("anchor parses");
    anchor.acceptance_identity.instance = "SENTINEL_WRONG_PRIVATE_INSTANCE".to_string();
    std::fs::write(
        &binding_fixture.anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("mismatched anchor writes");

    let binding_error = load_direct_signed_bundle_server_config(
        &binding_fixture.bundle_dir,
        &binding_fixture.anchor_path,
        &binding_fixture.state_path,
        true,
    )
    .expect_err("binding mismatch rejects direct startup");
    assert_eq!(
        binding_error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("binding failure is typed")
            .code(),
        BundleVerificationCode::REJECTED_BINDING
    );
    assert!(
        !format!("{binding_error} {binding_error:?}").contains("SENTINEL_WRONG_PRIVATE_INSTANCE")
    );
}

#[test]
fn direct_signed_bundle_rejects_stale_antirollback_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let loaded = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        true,
    )
    .expect("first direct load resolves initialization");
    let acceptance = loaded
        .pending_bundle_acceptance
        .expect("pending acceptance");
    let mut newer_record = acceptance.initial_record();
    newer_record.last_sequence += 1;
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&newer_record).expect("newer state serializes"),
    )
    .expect("pre-existing newer state writes");

    let error = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        false,
    )
    .expect_err("stale direct bundle rejects startup");
    assert_eq!(
        error
            .downcast_ref::<BundleVerificationFailure>()
            .expect("rollback failure is typed")
            .code(),
        BundleVerificationCode::REJECTED_ROLLBACK
    );
}

#[test]
fn direct_signed_bundle_diagnostics_do_not_disclose_paths_or_verifier_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sentinel = "SENTINEL_PRIVATE_COUNTRY_BUNDLE_PATH_AND_SECRET";
    let bundle_path = tmp.path().join(sentinel);
    let anchor_path = tmp.path().join("SENTINEL_PRIVATE_TRUST_ANCHOR.json");
    let state_path = tmp.path().join("SENTINEL_PRIVATE_ANTIROLLBACK_STATE.json");

    let error =
        load_direct_signed_bundle_server_config(&bundle_path, &anchor_path, &state_path, false)
            .expect_err("missing direct bundle rejects startup");
    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("direct verification failure is typed");
    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_VALIDATION);
    let rendered = format!("{failure} {failure:?}");
    for forbidden in [
        sentinel,
        bundle_path.to_str().expect("bundle path is UTF-8"),
        anchor_path.to_str().expect("anchor path is UTF-8"),
        state_path.to_str().expect("state path is UTF-8"),
    ] {
        assert!(
            !rendered.contains(forbidden),
            "direct startup diagnostic exposed {forbidden:?}: {rendered}"
        );
    }
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
