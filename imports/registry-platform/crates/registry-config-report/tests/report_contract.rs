use registry_config_report::{
    redact_config_value, ConfigDiagnosticReport, ConfigExplanation, ConfigHashes,
    ConfigValueClassification, RedactedConfig, RegistryctlValidationReport, RequiredEnvStatus,
    RequiredEnvVar, CONFIG_EXPLANATION_FIXTURE_V1, CONFIG_EXPLANATION_SCHEMA_V1,
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
fn serde_reports_omit_empty_hashes_to_preserve_schema_contract() {
    let empty_hashes = ConfigHashes {
        internal_config_hash: None,
        posture_safe_config_hash: None,
    };

    let mut diagnostic_report: ConfigDiagnosticReport =
        serde_json::from_str(RELAY_DIAGNOSTIC_OK_FIXTURE_V1).expect("fixture decodes");
    diagnostic_report.hashes = Some(empty_hashes.clone());
    let diagnostic_json = serde_json::to_value(&diagnostic_report).expect("report serializes");
    assert!(
        diagnostic_json.get("hashes").is_none(),
        "empty hashes object must be omitted"
    );
    assert_valid(PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, &diagnostic_json);

    let mut explanation_report: ConfigExplanation =
        serde_json::from_str(CONFIG_EXPLANATION_FIXTURE_V1).expect("fixture decodes");
    explanation_report.hashes = Some(empty_hashes);
    let explanation_json = serde_json::to_value(&explanation_report).expect("report serializes");
    assert!(
        explanation_json.get("hashes").is_none(),
        "empty hashes object must be omitted"
    );
    assert_valid(CONFIG_EXPLANATION_SCHEMA_V1, &explanation_json);
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

#[test]
fn redacted_config_constructor_runs_redaction() {
    let input = json!({
        "server": {
            "public_base_url": "https://relay.example.test",
            "admin_token": "super-secret-admin-token"
        }
    });

    let redacted = RedactedConfig::redacted(&input, |path, _value| match path {
        ["server", "admin_token"] => ConfigValueClassification::Secret,
        _ => ConfigValueClassification::Public,
    });

    // A Secret-classified field can never reach a populated RedactedConfig in
    // the clear: the only raw-Value constructor redacts.
    assert_eq!(
        redacted.as_value()["server"]["admin_token"],
        json!(REDACTED_VALUE)
    );
    assert_eq!(
        redacted.as_value()["server"]["public_base_url"],
        json!("https://relay.example.test")
    );

    let rendered = serde_json::to_string(&redacted).expect("redacted config renders");
    assert!(!rendered.contains("super-secret-admin-token"));

    // into_value yields the same redacted tree.
    assert_eq!(
        redacted.into_value(),
        json!({
            "server": {
                "public_base_url": "https://relay.example.test",
                "admin_token": REDACTED_VALUE
            }
        })
    );
}

#[test]
fn redacted_config_is_transparent_on_the_wire() {
    let explanation: ConfigExplanation =
        serde_json::from_str(CONFIG_EXPLANATION_FIXTURE_V1).expect("fixture decodes");

    // The newtype serializes exactly as the inner Value: the resolved_config
    // member of the serialized explanation is the bare object, not a wrapper.
    let serialized = serde_json::to_value(&explanation).expect("explanation serializes");
    let fixture: Value =
        serde_json::from_str(CONFIG_EXPLANATION_FIXTURE_V1).expect("fixture parses");
    assert_eq!(serialized["resolved_config"], fixture["resolved_config"]);
    assert_eq!(serialized, fixture);

    // And the accessor exposes the inner Value transparently.
    assert_eq!(
        explanation.resolved_config.as_value(),
        &fixture["resolved_config"]
    );
}

#[test]
fn required_env_public_safe_hides_sensitive_names() {
    let secret = RequiredEnvVar {
        name: "REGISTRY_RELAY_ADMIN_TOKEN".to_string(),
        classification: ConfigValueClassification::Secret,
        status: RequiredEnvStatus::Present,
    };
    let internal = RequiredEnvVar {
        name: "REGISTRY_INTERNAL_FEATURE_FLAG".to_string(),
        classification: ConfigValueClassification::InternalOnly,
        status: RequiredEnvStatus::Missing,
    };
    let public = RequiredEnvVar {
        name: "REGISTRY_PUBLIC_BASE_URL".to_string(),
        classification: ConfigValueClassification::Public,
        status: RequiredEnvStatus::Present,
    };
    let topology = RequiredEnvVar {
        name: "REGISTRY_PRIVATE_BIND".to_string(),
        classification: ConfigValueClassification::TopologySensitive,
        status: RequiredEnvStatus::NotChecked,
    };

    // Secret and InternalOnly names are replaced; classification/status kept.
    let safe_secret = secret.public_safe();
    assert_eq!(safe_secret.name, REDACTED_VALUE);
    assert_eq!(
        safe_secret.classification,
        ConfigValueClassification::Secret
    );
    assert_eq!(safe_secret.status, RequiredEnvStatus::Present);

    let safe_internal = internal.public_safe();
    assert_eq!(safe_internal.name, REDACTED_VALUE);
    assert_eq!(
        safe_internal.classification,
        ConfigValueClassification::InternalOnly
    );
    assert_eq!(safe_internal.status, RequiredEnvStatus::Missing);

    // Public and TopologySensitive entries are unchanged.
    assert_eq!(public.public_safe(), public);
    assert_eq!(topology.public_safe(), topology);
}
