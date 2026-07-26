// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use registry_relay::consultation::{
    consultation_service_activation_definitions, ConsultationServiceActivationCode,
    ConsultationServiceActivationError, ConsultationServiceActivationLifecycle,
    ConsultationServiceActivationVersion,
};
use serde_json::{json, Value};

const ERROR_MAPPINGS: [(
    ConsultationServiceActivationError,
    ConsultationServiceActivationCode,
); 9] = [
    (
        ConsultationServiceActivationError::MissingConfiguration,
        ConsultationServiceActivationCode::CONFIGURATION_MISSING,
    ),
    (
        ConsultationServiceActivationError::InvalidWorkloadBinding,
        ConsultationServiceActivationCode::WORKLOAD_BINDING_INVALID,
    ),
    (
        ConsultationServiceActivationError::RegistryActivation,
        ConsultationServiceActivationCode::ARTIFACT_REGISTRY_INVALID,
    ),
    (
        ConsultationServiceActivationError::UnsupportedPlan,
        ConsultationServiceActivationCode::UNSUPPORTED_PLAN,
    ),
    (
        ConsultationServiceActivationError::InvalidQuotaLimits,
        ConsultationServiceActivationCode::QUOTA_LIMITS_INVALID,
    ),
    (
        ConsultationServiceActivationError::InvalidMetadata,
        ConsultationServiceActivationCode::PROTECTED_METADATA_INVALID,
    ),
    (
        ConsultationServiceActivationError::SourceCredentials,
        ConsultationServiceActivationCode::SOURCE_CREDENTIALS_UNAVAILABLE,
    ),
    (
        ConsultationServiceActivationError::PseudonymMaterial,
        ConsultationServiceActivationCode::PSEUDONYM_MATERIAL_UNAVAILABLE,
    ),
    (
        ConsultationServiceActivationError::StatePlane,
        ConsultationServiceActivationCode::STATE_PLANE_UNAVAILABLE,
    ),
];

#[test]
fn every_activation_variant_maps_to_one_stable_code_and_definition() {
    for (error, expected_code) in ERROR_MAPPINGS {
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.safe_projection().code, expected_code);
        assert_eq!(expected_code.definition().code, expected_code);
    }
}

#[test]
fn code_and_definition_catalogs_are_unique_complete_and_lexically_ordered() {
    fn assert_typed_version(_: Option<ConsultationServiceActivationVersion>) {}

    let codes =
        ConsultationServiceActivationCode::ALL.map(ConsultationServiceActivationCode::as_str);
    assert_eq!(
        codes,
        [
            "relay.consultation.activation.artifact_registry_invalid",
            "relay.consultation.activation.configuration_missing",
            "relay.consultation.activation.protected_metadata_invalid",
            "relay.consultation.activation.pseudonym_material_unavailable",
            "relay.consultation.activation.quota_limits_invalid",
            "relay.consultation.activation.source_credentials_unavailable",
            "relay.consultation.activation.state_plane_unavailable",
            "relay.consultation.activation.unsupported_plan",
            "relay.consultation.activation.workload_binding_invalid",
        ]
    );
    assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(codes.into_iter().collect::<BTreeSet<_>>().len(), 9);

    let definitions = consultation_service_activation_definitions();
    assert_eq!(
        definitions.len(),
        ConsultationServiceActivationCode::ALL.len()
    );
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.code)
            .collect::<Vec<_>>(),
        ConsultationServiceActivationCode::ALL
    );
    assert!(definitions.iter().all(|definition| {
        assert_typed_version(definition.introduced_in);
        definition.lifecycle == ConsultationServiceActivationLifecycle::Unreleased
            && definition.introduced_in.is_none()
            && definition.lifecycle_metadata_is_valid()
            && definition.catalog_metadata_is_valid()
            && definition.phase == "consultation_activation"
            && !definition.meaning.is_empty()
            && !definition.rule.is_empty()
            && !definition.remediation.is_empty()
            && !definition.evidence_scope.is_empty()
            && !definition.evidence_policy.is_empty()
            && !definition.evidence_limitation.is_empty()
            && !definition.docs_slug.is_empty()
    }));
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.docs_slug)
            .collect::<BTreeSet<_>>()
            .len(),
        definitions.len()
    );
}

#[test]
fn safe_projection_is_static_value_free_and_has_a_closed_boundary_shape() {
    for (error, _) in ERROR_MAPPINGS {
        let projection =
            serde_json::to_value(error.safe_projection()).expect("safe projection serializes");
        assert_eq!(
            projection
                .as_object()
                .expect("projection is an object")
                .len(),
            11
        );
        for field in [
            "code",
            "lifecycle",
            "introduced_in",
            "phase",
            "meaning",
            "rule",
            "remediation",
            "evidence_scope",
            "evidence_policy",
            "evidence_limitation",
            "docs_slug",
        ] {
            assert!(projection.get(field).is_some(), "{field}");
        }
        assert_eq!(
            projection["code"],
            json!(error.code().as_str()),
            "the public boundary renders the stable code string"
        );
        assert_eq!(projection["lifecycle"], json!("unreleased"));
        assert!(projection["introduced_in"].is_null());
        assert_eq!(projection["phase"], json!("consultation_activation"));

        let serialized = projection.to_string();
        assert!(!serialized.contains("0.13.0"));
        assert!(!serialized.contains("0.14.0"));
        for sentinel in [
            "/COUNTRY/private/source.yaml",
            "sha256:COUNTRY_HASH",
            "COUNTRY_PARSER_ERROR",
            "COUNTRY_SOURCE_CREDENTIAL",
            "COUNTRY_IDENTIFIER",
            "COUNTRY_VALUE",
        ] {
            assert!(!serialized.contains(sentinel), "{sentinel}");
        }
        let lower = serialized.to_ascii_lowercase();
        for forbidden in [
            "sha256:",
            "://",
            "/tmp/",
            ".yaml",
            "parser error",
            "client_secret",
            "api_key",
            "registry_id",
            "country_",
        ] {
            assert!(!lower.contains(forbidden), "{forbidden}");
        }
    }
}

#[test]
fn existing_activation_error_display_contract_remains_compatible_and_value_free() {
    let expected = [
        "consultation service configuration is unavailable",
        "consultation service workload binding is invalid",
        "consultation service registry activation failed",
        "consultation service plan is unsupported",
        "consultation service quota limits are invalid",
        "consultation service protected metadata is invalid",
        "consultation service source credentials are unavailable",
        "consultation service pseudonym material is unavailable",
        "consultation service state plane is unavailable",
    ];
    assert_eq!(
        ERROR_MAPPINGS
            .map(|(error, _)| error.to_string())
            .as_slice(),
        expected
    );
}

#[test]
fn catalog_and_projection_render_identically_at_the_public_boundary() {
    for (error, code) in ERROR_MAPPINGS {
        let definition = serde_json::to_value(code.definition()).expect("definition serializes");
        let projection =
            serde_json::to_value(error.safe_projection()).expect("projection serializes");
        assert_eq!(projection, definition);
        assert_eq!(
            serde_json::to_value(code).expect("code serializes"),
            Value::String(code.as_str().to_owned())
        );
        assert_eq!(code.to_string(), code.as_str());
        assert!(format!("{code:?}").contains(code.as_str()));
    }
}
