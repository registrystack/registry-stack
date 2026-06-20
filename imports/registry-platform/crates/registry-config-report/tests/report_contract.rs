use registry_config_report::{
    redact_config_value, ConfigDiagnosticReport, ConfigExplanation, ConfigValueClassification,
    RegistryctlValidationReport, CONFIG_EXPLANATION_FIXTURE_V1, CONFIG_EXPLANATION_SCHEMA_V1,
    NOTARY_DIAGNOSTIC_ERROR_FIXTURE_V1, NOTARY_DIAGNOSTIC_OK_FIXTURE_V1,
    PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, REDACTED_VALUE, REDACTION_INPUT_FIXTURE_V1,
    REGISTRYCTL_VALIDATION_FIXTURE_V1, REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1,
    RELAY_DIAGNOSTIC_ERROR_FIXTURE_V1, RELAY_DIAGNOSTIC_OK_FIXTURE_V1,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const LEGACY_VALIDATION_REPORT_FIXTURE: &str =
    include_str!("../fixtures/invalid/registry-relay.legacy-validation-report.json");
const BAD_HASH_FIXTURE: &str = include_str!("../fixtures/invalid/registry-relay.bad-hash.json");
const LOSSY_REGISTRYCTL_FIXTURE: &str =
    include_str!("../fixtures/invalid/registryctl.lossy-product-report.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator(schema: &str) -> jsonschema::Validator {
    let schema = parse(schema);
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn assert_valid(schema: &str, document: &Value) {
    let validator = validator(schema);
    if let Err(error) = validator.validate(document) {
        panic!("document should validate: {error}");
    }
}

fn assert_invalid(schema: &str, document: &Value) {
    let validator = validator(schema);
    assert!(
        validator.validate(document).is_err(),
        "document should not validate"
    );
}

fn round_trip<T>(fixture: &str)
where
    T: DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
{
    let decoded: T = serde_json::from_str(fixture).expect("fixture decodes");
    let encoded = serde_json::to_value(&decoded).expect("fixture re-encodes");
    let decoded_again: T = serde_json::from_value(encoded).expect("encoded fixture decodes");
    assert_eq!(decoded, decoded_again);
}

#[test]
fn product_diagnostic_schema_validates_canonical_product_fixtures() {
    for fixture in [
        RELAY_DIAGNOSTIC_OK_FIXTURE_V1,
        RELAY_DIAGNOSTIC_ERROR_FIXTURE_V1,
        NOTARY_DIAGNOSTIC_OK_FIXTURE_V1,
        NOTARY_DIAGNOSTIC_ERROR_FIXTURE_V1,
    ] {
        assert_valid(PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, &parse(fixture));
    }
}

#[test]
fn product_diagnostic_schema_rejects_wrong_schema_unknown_status_and_bad_hash() {
    assert_invalid(
        PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1,
        &parse(LEGACY_VALIDATION_REPORT_FIXTURE),
    );

    let mut unknown_status = parse(RELAY_DIAGNOSTIC_OK_FIXTURE_V1);
    unknown_status["status"] = json!("partial");
    assert_invalid(PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, &unknown_status);

    assert_invalid(
        PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1,
        &parse(BAD_HASH_FIXTURE),
    );
}

#[test]
fn explanation_schema_validates_canonical_fixture() {
    assert_valid(
        CONFIG_EXPLANATION_SCHEMA_V1,
        &parse(CONFIG_EXPLANATION_FIXTURE_V1),
    );
}

#[test]
fn explanation_schema_rejects_unknown_live_apply_class() {
    let mut document = parse(CONFIG_EXPLANATION_FIXTURE_V1);
    document["live_apply"][0]["class"] = json!("local_file");
    assert_invalid(CONFIG_EXPLANATION_SCHEMA_V1, &document);
}

#[test]
fn registryctl_schema_validates_embedded_product_diagnostics() {
    assert_valid(
        REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1,
        &parse(REGISTRYCTL_VALIDATION_FIXTURE_V1),
    );
}

#[test]
fn registryctl_schema_rejects_lossy_embedded_product_report() {
    assert_invalid(
        REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1,
        &parse(LOSSY_REGISTRYCTL_FIXTURE),
    );
}

#[test]
fn serde_types_round_trip_canonical_fixtures() {
    round_trip::<ConfigDiagnosticReport>(RELAY_DIAGNOSTIC_OK_FIXTURE_V1);
    round_trip::<ConfigDiagnosticReport>(RELAY_DIAGNOSTIC_ERROR_FIXTURE_V1);
    round_trip::<ConfigDiagnosticReport>(NOTARY_DIAGNOSTIC_OK_FIXTURE_V1);
    round_trip::<ConfigDiagnosticReport>(NOTARY_DIAGNOSTIC_ERROR_FIXTURE_V1);
    round_trip::<ConfigExplanation>(CONFIG_EXPLANATION_FIXTURE_V1);
    round_trip::<RegistryctlValidationReport>(REGISTRYCTL_VALIDATION_FIXTURE_V1);
}

#[test]
fn redaction_classifier_blocks_sensitive_values_from_reports() {
    let input = parse(REDACTION_INPUT_FIXTURE_V1);
    let redacted = redact_config_value(&input, |path, _value| match path {
        ["auth", "admin_token"] | ["auth", "bearer"] | ["signing", "private_jwk"] => {
            ConfigValueClassification::Secret
        }
        ["instance", "private_admin_bind"] => ConfigValueClassification::TopologySensitive,
        ["source_rows"] | ["env"] => ConfigValueClassification::InternalOnly,
        _ => ConfigValueClassification::Public,
    });

    assert_eq!(redacted["auth"]["admin_token"], json!(REDACTED_VALUE));
    assert_eq!(redacted["auth"]["bearer"], json!(REDACTED_VALUE));
    assert_eq!(redacted["signing"]["private_jwk"], json!(REDACTED_VALUE));
    assert_eq!(
        redacted["instance"]["private_admin_bind"],
        json!(REDACTED_VALUE)
    );
    assert_eq!(redacted["source_rows"], json!(REDACTED_VALUE));
    assert_eq!(redacted["env"], json!(REDACTED_VALUE));
    assert_eq!(redacted["instance"]["id"], json!("relay-a"));
    assert_eq!(
        redacted["instance"]["public_base_url"],
        json!("https://relay.example.test")
    );

    let rendered = serde_json::to_string(&redacted).expect("redacted JSON renders");
    for forbidden in [
        "super-secret-admin-token",
        "eyJsecret.source.token",
        "-----BEGIN PRIVATE KEY-----",
        "person-123",
        "full-env-secret",
        "10.0.0.5:9443",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "redacted output leaked {forbidden}"
        );
    }
}

#[test]
fn required_env_reports_names_and_classification_without_values() {
    let report: ConfigDiagnosticReport =
        serde_json::from_str(RELAY_DIAGNOSTIC_ERROR_FIXTURE_V1).expect("fixture decodes");
    let required = report
        .required_env
        .iter()
        .find(|item| item.name == "REGISTRY_RELAY_ADMIN_TOKEN")
        .expect("required env is present");

    assert_eq!(required.classification, ConfigValueClassification::Secret);
    let rendered = serde_json::to_string(&report).expect("report renders");
    assert!(!rendered.contains("super-secret-admin-token"));
}
