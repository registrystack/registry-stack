use std::collections::BTreeSet;

use registry_platform_config::ConfigBundleError;
use registry_platform_ops::{
    bundle_verify_rejection_code, bundle_verify_rejection_result, AntiRollbackStoreError,
    ApplyReportResult, BundleVerificationCode, BundleVerificationCodeLifecycle,
    BundleVerificationEvidencePolicy, BundleVerificationFailure, ConfigBootError,
    BUNDLE_VERIFICATION_CODE_DEFINITIONS,
};

const PATH_SENTINEL: &str = "/Users/redaction-sentinel/private/config.json";
const HASH_SENTINEL: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_HASH_SENTINEL: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const PARSER_SENTINEL: &str = "line 7 column 42 near REDACTION_PARSER_SENTINEL";
const USER_SENTINEL: &str = "redaction-user@example.test";
const SECRET_SENTINEL: &str = "REDACTION_SECRET_SENTINEL";
const COUNTRY_SENTINEL: &str = "REDACTION_COUNTRY_VALUE_SENTINEL";

fn bundle_error_cases() -> Vec<(ConfigBundleError, BundleVerificationCode)> {
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
            ConfigBundleError::InvalidTrustAnchor(USER_SENTINEL),
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

fn boot_error_cases() -> Vec<(ConfigBootError, BundleVerificationCode)> {
    vec![
        (
            ConfigBootError::Store(AntiRollbackStoreError::InvalidState(
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
fn bundle_error_mapping_covers_every_source_variant() {
    for (error, expected) in bundle_error_cases() {
        assert_eq!(bundle_verify_rejection_code(&error), expected);
    }
}

#[test]
fn config_boot_mapping_covers_every_source_variant() {
    for (error, expected) in boot_error_cases() {
        assert_eq!(error.bundle_rejection_code(), expected);
    }
}

#[test]
fn catalog_is_complete_unique_and_sorted() {
    let expected = [
        "rejected_binding",
        "rejected_rollback",
        "rejected_signature",
        "rejected_validation",
    ];
    let actual = BundleVerificationCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert!(
        actual.windows(2).all(|pair| pair[0] < pair[1]),
        "codes must remain in stable lexical order"
    );
    assert_eq!(
        actual.iter().copied().collect::<BTreeSet<_>>().len(),
        actual.len(),
        "codes must be unique"
    );

    let definition_codes = BUNDLE_VERIFICATION_CODE_DEFINITIONS
        .iter()
        .map(|definition| definition.code)
        .collect::<Vec<_>>();
    assert_eq!(definition_codes, BundleVerificationCode::ALL);
    for code in BundleVerificationCode::ALL {
        assert_eq!(code.definition().code, *code);
    }
    assert!(BUNDLE_VERIFICATION_CODE_DEFINITIONS
        .iter()
        .all(|definition| {
            definition.evidence_policy == BundleVerificationEvidencePolicy::NoRuntimeValues
                && !definition.phase.is_empty()
                && !definition.safe_meaning.is_empty()
                && !definition.rule.is_empty()
                && !definition.safe_remediation.is_empty()
                && definition.safe_report_message
                    == format!(
                        "{} {}",
                        definition.safe_meaning, definition.safe_remediation
                    )
                && !definition.evidence_scope.is_empty()
                && !definition.evidence_limitation.is_empty()
                && !definition.docs_slug.is_empty()
                && definition.lifecycle == BundleVerificationCodeLifecycle::Unreleased
                && definition.introduced_in.is_none()
                && definition.lifecycle_metadata_is_valid()
        }));
}

#[test]
fn lifecycle_metadata_requires_versions_only_for_released_codes() {
    let base = BUNDLE_VERIFICATION_CODE_DEFINITIONS[0];
    let cases = [
        (BundleVerificationCodeLifecycle::Unreleased, None, true),
        (
            BundleVerificationCodeLifecycle::Unreleased,
            Some("1.2.3"),
            false,
        ),
        (BundleVerificationCodeLifecycle::Active, None, false),
        (
            BundleVerificationCodeLifecycle::Active,
            Some("unreleased"),
            false,
        ),
        (BundleVerificationCodeLifecycle::Active, Some("1.2"), false),
        (BundleVerificationCodeLifecycle::Active, Some("1.2.3"), true),
        (BundleVerificationCodeLifecycle::Deprecated, None, false),
        (
            BundleVerificationCodeLifecycle::Deprecated,
            Some("1.2.3"),
            true,
        ),
    ];

    for (lifecycle, introduced_in, expected) in cases {
        let definition = registry_platform_ops::BundleVerificationCodeDefinition {
            lifecycle,
            introduced_in,
            ..base
        };
        assert_eq!(
            definition.lifecycle_metadata_is_valid(),
            expected,
            "unexpected lifecycle validity for {lifecycle:?} with {introduced_in:?}"
        );
    }

    let serialized =
        serde_json::to_string(BUNDLE_VERIFICATION_CODE_DEFINITIONS).expect("serialize catalog");
    assert!(serialized.contains(r#""lifecycle":"unreleased""#));
    assert!(serialized.contains(r#""introduced_in":null"#));
    assert!(
        !serialized.contains("0.13.0"),
        "the post-v0.13.0 catalog must not claim that release"
    );
}

#[test]
fn catalog_and_mappings_never_publish_source_values() {
    let sentinels = [
        PATH_SENTINEL,
        HASH_SENTINEL,
        OTHER_HASH_SENTINEL,
        PARSER_SENTINEL,
        USER_SENTINEL,
        SECRET_SENTINEL,
        COUNTRY_SENTINEL,
    ];
    let definitions =
        serde_json::to_string(BUNDLE_VERIFICATION_CODE_DEFINITIONS).expect("serialize definitions");

    for sentinel in sentinels {
        assert!(
            !definitions.contains(sentinel),
            "static definitions leaked sentinel {sentinel:?}"
        );
    }

    for (error, _) in bundle_error_cases() {
        let public_output = serde_json::to_string(&bundle_verify_rejection_code(&error))
            .expect("serialize public code");
        for sentinel in sentinels {
            assert!(
                !public_output.contains(sentinel),
                "public code leaked sentinel {sentinel:?}"
            );
        }
    }

    for (error, _) in boot_error_cases() {
        let public_output = error.bundle_rejection_result();
        for sentinel in sentinels {
            assert!(
                !public_output.contains(sentinel),
                "compatibility result leaked sentinel {sentinel:?}"
            );
        }
    }
}

#[test]
fn compatibility_wrappers_preserve_existing_result_strings() {
    for (error, expected) in bundle_error_cases() {
        assert_eq!(bundle_verify_rejection_result(&error), expected.as_str());
    }
    for (error, expected) in boot_error_cases() {
        assert_eq!(error.bundle_rejection_result(), expected.as_str());
    }
}

#[test]
fn codes_convert_to_the_existing_apply_report_vocabulary() {
    let cases = [
        (
            BundleVerificationCode::REJECTED_BINDING,
            ApplyReportResult::RejectedBinding,
        ),
        (
            BundleVerificationCode::REJECTED_ROLLBACK,
            ApplyReportResult::RejectedRollback,
        ),
        (
            BundleVerificationCode::REJECTED_SIGNATURE,
            ApplyReportResult::RejectedSignature,
        ),
        (
            BundleVerificationCode::REJECTED_VALIDATION,
            ApplyReportResult::RejectedValidation,
        ),
    ];

    for (code, expected) in cases {
        let result = ApplyReportResult::from(code);
        assert_eq!(result, expected);
        assert_eq!(result.as_str(), code.as_str());
        assert_eq!(
            serde_json::to_string(&code).expect("serialize code"),
            format!("\"{}\"", code.as_str())
        );
    }
}

#[test]
fn process_failure_retains_only_static_catalog_evidence() {
    let sentinels = [
        PATH_SENTINEL,
        HASH_SENTINEL,
        OTHER_HASH_SENTINEL,
        PARSER_SENTINEL,
        USER_SENTINEL,
        SECRET_SENTINEL,
        COUNTRY_SENTINEL,
    ];

    for (source, code) in bundle_error_cases() {
        let failure = BundleVerificationFailure::from(bundle_verify_rejection_code(&source));
        assert_eq!(failure.code(), code);
        assert!(
            std::error::Error::source(&failure).is_none(),
            "the process carrier must not retain the source error"
        );
        assert_eq!(
            failure.to_string(),
            format!("{}: {}", code, code.definition().safe_report_message)
        );
        let rendered = format!("{failure:?}\n{failure}");
        for sentinel in sentinels {
            assert!(
                !rendered.contains(sentinel),
                "process failure leaked sentinel {sentinel:?}: {rendered}"
            );
        }
    }
}
