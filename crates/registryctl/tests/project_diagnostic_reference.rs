// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use registry_platform_ops::BUNDLE_VERIFICATION_CODE_DEFINITIONS;
use registry_relay::consultation::consultation_service_activation_definitions;
use registry_relay::process_startup::PROCESS_STARTUP_CODE_DEFINITIONS;
use registryctl::{
    authoring_error_reference, fixture_error_reference, operator_error_reference,
    validate_authoring_error_reference, validate_fixture_error_reference,
    validate_operator_error_reference, ErrorReferenceEntry, ErrorReferenceFamily,
    ErrorReferenceLifecycle, ErrorReferenceProduct, ErrorReferenceValidationError,
    OperatorErrorOmission, OperatorErrorOmissionFamily, OperatorErrorOmissionReason,
    AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1, FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1,
    OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1,
};
use serde_json::Value;

const AUTHORING_SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.authoring_error_reference.v1.schema.json");
const FIXTURE_SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.fixture_error_reference.v1.schema.json");
const OPERATOR_SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.operator_error_reference.v1.schema.json");

#[test]
fn published_diagnostic_references_are_closed_complete_and_unreleased() {
    let authoring = authoring_error_reference();
    let fixture = fixture_error_reference();
    let operator = operator_error_reference();

    assert_eq!(
        authoring.schema_version,
        AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1
    );
    assert_eq!(
        fixture.schema_version,
        FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1
    );
    assert_eq!(
        operator.schema_version,
        OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1
    );
    validate_authoring_error_reference(&authoring).expect("authoring reference is exact");
    validate_fixture_error_reference(&fixture).expect("fixture reference is exact");
    validate_operator_error_reference(&operator).expect("operator reference is exact");

    assert_eq!(authoring.entries.len(), 17);
    assert_eq!(fixture.entries.len(), 15);
    assert_eq!(operator.entries.len(), 42);
    assert!(
        operator.omissions.is_empty(),
        "all operator catalogs now expose complete product-owned metadata"
    );
    let family_counts =
        operator
            .entries
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, entry| {
                *counts.entry(entry.family.as_str()).or_default() += 1;
                counts
            });
    assert_eq!(
        family_counts,
        BTreeMap::from([
            ("bundle_verification", 4),
            ("operator_preflight", 11),
            ("relay_activation", 9),
            ("relay_process_startup", 18),
        ])
    );

    for entry in authoring
        .entries
        .iter()
        .chain(&fixture.entries)
        .chain(&operator.entries)
    {
        assert_eq!(entry.lifecycle, ErrorReferenceLifecycle::Unreleased);
        assert_eq!(entry.introduced_in, None);
        assert!(!entry.phase.is_empty());
        assert!(!entry.safe_meaning.is_empty());
        assert!(!entry.rule.is_empty());
        assert!(!entry.safe_remediation.is_empty());
        assert!(!entry.evidence_scope.is_empty());
        assert!(!entry.evidence_limitation.is_empty());
        assert!(!entry.docs_anchor.contains("/reference/registryctl/"));
    }
}

#[test]
fn operator_projection_is_exact_to_all_product_owned_metadata() {
    let operator = operator_error_reference();

    for definition in BUNDLE_VERIFICATION_CODE_DEFINITIONS {
        let entry = entry_for(
            &operator.entries,
            ErrorReferenceFamily::BundleVerification,
            ErrorReferenceProduct::RegistryPlatformOps,
            definition.code.as_str(),
        );
        assert_eq!(entry.phase, definition.phase);
        assert_eq!(entry.safe_meaning, definition.safe_meaning);
        assert_eq!(entry.rule, definition.rule);
        assert_eq!(entry.safe_remediation, definition.safe_remediation);
        assert_eq!(entry.evidence_scope, definition.evidence_scope);
        assert_eq!(entry.evidence_limitation, definition.evidence_limitation);
        assert_eq!(
            entry.docs_anchor,
            format!(
                "/reference/diagnostics/operator/#registry_platform_ops--{}",
                definition.docs_slug
            )
        );
    }
    for definition in consultation_service_activation_definitions() {
        let entry = entry_for(
            &operator.entries,
            ErrorReferenceFamily::RelayActivation,
            ErrorReferenceProduct::RegistryRelay,
            definition.code.as_str(),
        );
        assert_eq!(entry.phase, definition.phase);
        assert_eq!(entry.safe_meaning, definition.meaning);
        assert_eq!(entry.rule, definition.rule);
        assert_eq!(entry.safe_remediation, definition.remediation);
        assert_eq!(entry.evidence_scope, definition.evidence_scope);
        assert_eq!(entry.evidence_limitation, definition.evidence_limitation);
        assert_eq!(
            entry.docs_anchor,
            format!(
                "/reference/diagnostics/operator/#registry_relay--{}",
                definition.docs_slug
            )
        );
    }
    for definition in PROCESS_STARTUP_CODE_DEFINITIONS {
        let entry = entry_for(
            &operator.entries,
            ErrorReferenceFamily::RelayProcessStartup,
            ErrorReferenceProduct::RegistryRelay,
            definition.code.as_str(),
        );
        assert_eq!(entry.phase, definition.phase);
        assert_eq!(entry.safe_meaning, definition.safe_meaning);
        assert_eq!(entry.rule, definition.rule);
        assert_eq!(entry.safe_remediation, definition.safe_remediation);
        assert_eq!(entry.evidence_scope, definition.evidence_scope);
        assert_eq!(entry.evidence_limitation, definition.evidence_limitation);
        assert_eq!(
            entry.docs_anchor,
            format!(
                "/reference/diagnostics/operator/#registry_relay--{}",
                definition.docs_slug
            )
        );
    }
}

#[test]
fn strict_validation_rejects_missing_duplicate_reordered_stale_and_drifted_data() {
    let mut authoring = authoring_error_reference();
    authoring.entries.pop();
    assert_eq!(
        validate_authoring_error_reference(&authoring),
        Err(ErrorReferenceValidationError::EntriesDoNotMatchSources)
    );

    let mut fixture = fixture_error_reference();
    fixture.entries[0].safe_meaning.push_str(" changed");
    assert_eq!(
        validate_fixture_error_reference(&fixture),
        Err(ErrorReferenceValidationError::EntriesDoNotMatchSources)
    );

    let mut operator = operator_error_reference();
    operator.entries.push(operator.entries[0].clone());
    operator
        .entries
        .sort_by(|left, right| reference_key(left).cmp(&reference_key(right)));
    assert_eq!(
        validate_operator_error_reference(&operator),
        Err(ErrorReferenceValidationError::DuplicateEntry)
    );

    let mut operator = operator_error_reference();
    operator.entries.swap(0, 1);
    assert_eq!(
        validate_operator_error_reference(&operator),
        Err(ErrorReferenceValidationError::UnsortedEntries)
    );

    let mut operator = operator_error_reference();
    operator.entries[0].lifecycle = ErrorReferenceLifecycle::Active;
    assert_eq!(
        validate_operator_error_reference(&operator),
        Err(ErrorReferenceValidationError::LifecycleVersionMismatch)
    );

    let mut operator = operator_error_reference();
    operator.entries[0].docs_anchor.push_str("-drift");
    assert_eq!(
        validate_operator_error_reference(&operator),
        Err(ErrorReferenceValidationError::DocsAnchorMismatch)
    );

    let mut operator = operator_error_reference();
    operator.omissions.push(OperatorErrorOmission {
        family: OperatorErrorOmissionFamily::RelayActivation,
        product: ErrorReferenceProduct::RegistryRelay,
        reason: OperatorErrorOmissionReason::NoCompletePublicCodeCatalog,
        evidence: "stale omission".to_string(),
        required_action: "remove it".to_string(),
    });
    assert_eq!(
        validate_operator_error_reference(&operator),
        Err(ErrorReferenceValidationError::OmissionsDoNotMatchSources)
    );
}

#[test]
fn strict_json_schemas_accept_only_the_generated_shapes() {
    for (schema, document) in [
        (
            AUTHORING_SCHEMA,
            serde_json::to_value(authoring_error_reference()).unwrap(),
        ),
        (
            FIXTURE_SCHEMA,
            serde_json::to_value(fixture_error_reference()).unwrap(),
        ),
        (
            OPERATOR_SCHEMA,
            serde_json::to_value(operator_error_reference()).unwrap(),
        ),
    ] {
        let schema: Value = serde_json::from_str(schema).unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        assert!(validator.is_valid(&document));

        let mut unknown = document.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), Value::Bool(true));
        assert!(!validator.is_valid(&unknown));
    }
}

#[test]
fn operator_schema_accepts_exact_catalog_and_rejects_open_values() {
    let schema: Value = serde_json::from_str(OPERATOR_SCHEMA).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let canonical = serde_json::to_value(operator_error_reference()).unwrap();
    assert_eq!(canonical["entries"].as_array().unwrap().len(), 42);
    assert!(validator.is_valid(&canonical));

    let mut open_code = canonical.clone();
    open_code["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["family"] == "relay_process_startup")
        .unwrap()["code"] = Value::String("relay.startup.unregistered_open_value".to_string());
    assert!(!validator.is_valid(&open_code));

    for (field, stale_value) in [
        ("family", "notary_activation"),
        ("owner", "registry_notary"),
        ("product", "registry_notary"),
    ] {
        let mut stale = canonical.clone();
        stale["entries"][0][field] = Value::String(stale_value.to_string());
        assert!(!validator.is_valid(&stale));
    }

    let mut open_field = canonical;
    open_field["entries"][0]
        .as_object_mut()
        .unwrap()
        .insert("runtime_value".to_string(), Value::Bool(true));
    assert!(!validator.is_valid(&open_field));
}

#[test]
fn fixture_schema_rejects_retired_authorization_diagnostic() {
    let schema: Value = serde_json::from_str(FIXTURE_SCHEMA).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let canonical = serde_json::to_value(fixture_error_reference()).unwrap();
    assert_eq!(canonical["entries"].as_array().unwrap().len(), 15);
    assert!(validator.is_valid(&canonical));

    let mut stale = canonical;
    stale["entries"][0]["code"] = Value::String("authorization.denied".to_string());
    assert!(!validator.is_valid(&stale));
}

fn entry_for<'a>(
    entries: &'a [ErrorReferenceEntry],
    family: ErrorReferenceFamily,
    product: ErrorReferenceProduct,
    code: &str,
) -> &'a ErrorReferenceEntry {
    entries
        .iter()
        .find(|entry| entry.family == family && entry.product == product && entry.code == code)
        .unwrap_or_else(|| panic!("missing {family:?}/{product:?}/{code}"))
}

fn reference_key(entry: &ErrorReferenceEntry) -> (&str, &str, &str) {
    (
        entry.family.as_str(),
        entry.product.as_str(),
        entry.code.as_str(),
    )
}
