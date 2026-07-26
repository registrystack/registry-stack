// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_platform_ops::BundleVerificationCode;
use registry_relay::process_startup::{
    ProcessStartupCode, ProcessStartupCodeLifecycle, ProcessStartupEvidencePolicy,
    ProcessStartupFailure, PROCESS_STARTUP_CODE_DEFINITIONS,
};

#[test]
fn process_startup_catalog_is_complete_unique_and_lexically_ordered() {
    let codes = ProcessStartupCode::ALL
        .iter()
        .copied()
        .map(ProcessStartupCode::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        [
            "relay.startup.bundle_binding_rejected",
            "relay.startup.bundle_rollback_rejected",
            "relay.startup.bundle_signature_rejected",
            "relay.startup.bundle_validation_rejected",
            "relay.startup.config_document_invalid",
            "relay.startup.config_source_unavailable",
            "relay.startup.config_validation_rejected",
            "relay.startup.consultation_artifacts_rejected",
            "relay.startup.doctor_failed",
            "relay.startup.listener_unavailable",
            "relay.startup.runtime_initialization_failed",
        ]
    );
    assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        codes.iter().copied().collect::<BTreeSet<_>>().len(),
        codes.len()
    );
    assert_eq!(
        PROCESS_STARTUP_CODE_DEFINITIONS
            .iter()
            .map(|definition| definition.code)
            .collect::<Vec<_>>(),
        ProcessStartupCode::ALL
    );
    assert_eq!(
        PROCESS_STARTUP_CODE_DEFINITIONS
            .iter()
            .map(|definition| definition.docs_slug)
            .collect::<BTreeSet<_>>()
            .len(),
        ProcessStartupCode::ALL.len()
    );
}

#[test]
fn process_startup_catalog_metadata_is_static_complete_and_unreleased() {
    for definition in PROCESS_STARTUP_CODE_DEFINITIONS {
        assert_eq!(
            definition.lifecycle,
            ProcessStartupCodeLifecycle::Unreleased
        );
        assert_eq!(definition.introduced_in, None);
        assert!(definition.lifecycle_metadata_is_valid());
        assert_eq!(
            definition.evidence_policy,
            ProcessStartupEvidencePolicy::NoRuntimeValues
        );
        for value in [
            definition.code.as_str(),
            definition.phase,
            definition.safe_meaning,
            definition.rule,
            definition.safe_remediation,
            definition.evidence_scope,
            definition.evidence_limitation,
            definition.docs_slug,
        ] {
            assert!(!value.is_empty());
            assert_eq!(value.trim(), value);
        }

        let rendered =
            serde_json::to_string(definition).expect("catalog definition serializes safely");
        assert_safe_value_free(&rendered);
        let failure = ProcessStartupFailure::new(definition.code).to_string();
        assert!(failure.contains(definition.code.as_str()));
        assert!(failure.contains(definition.safe_meaning));
        assert!(failure.contains(definition.safe_remediation));
        assert_safe_value_free(&failure);
    }
}

#[test]
fn shared_bundle_codes_have_an_exhaustive_relay_process_projection() {
    let expected = [
        ProcessStartupCode::BUNDLE_BINDING_REJECTED,
        ProcessStartupCode::BUNDLE_ROLLBACK_REJECTED,
        ProcessStartupCode::BUNDLE_SIGNATURE_REJECTED,
        ProcessStartupCode::BUNDLE_VALIDATION_REJECTED,
    ];
    assert_eq!(
        BundleVerificationCode::ALL
            .iter()
            .copied()
            .map(ProcessStartupCode::from_bundle_verification)
            .collect::<Vec<_>>(),
        expected
    );
}

fn assert_safe_value_free(value: &str) {
    let lower = value.to_ascii_lowercase();
    for forbidden in [
        "/country/private/source.yaml",
        "/tmp/",
        "/users/",
        "sha256:",
        "://",
        "country_parser_error",
        "country_secret",
        "country@example.test",
        "client_secret",
        "api_key=",
    ] {
        assert!(
            !lower.contains(forbidden),
            "catalog-owned value contains forbidden runtime material {forbidden:?}: {value}"
        );
    }
}
