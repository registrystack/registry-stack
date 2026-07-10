use serde_json::Value;

const ACK_CURSOR_VALID_FIXTURE: &str = include_str!("../fixtures/audit/ack-cursor.valid.json");
const ACK_CURSOR_MISSING_REQUIRED_FIXTURE: &str =
    include_str!("../fixtures/audit/ack-cursor.missing-required.invalid.json");
const ACK_CURSOR_WRONG_SCHEMA_FIXTURE: &str =
    include_str!("../fixtures/audit/ack-cursor.wrong-schema.invalid.json");
const ACK_CURSOR_MALFORMED_HASH_FIXTURE: &str =
    include_str!("../fixtures/audit/ack-cursor.malformed-hash.invalid.json");
const ACK_CURSOR_UNKNOWN_FIELD_FIXTURE: &str =
    include_str!("../fixtures/audit/ack-cursor.unknown-field.invalid.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("fixture parses as JSON")
}

fn ack_cursor_validator() -> jsonschema::Validator {
    let schema = parse(registry_platform_ops::AUDIT_ACK_CURSOR_SCHEMA_V1);
    jsonschema::validator_for(&schema).expect("ack cursor schema compiles")
}

#[test]
fn ack_cursor_valid_fixture_validates() {
    let validator = ack_cursor_validator();
    assert!(
        validator.is_valid(&parse(ACK_CURSOR_VALID_FIXTURE)),
        "the exported valid ack cursor fixture must validate"
    );
    // The library also exports the same fixture as a const for reuse.
    assert_eq!(
        parse(ACK_CURSOR_VALID_FIXTURE),
        parse(registry_platform_ops::AUDIT_ACK_CURSOR_FIXTURE_V1),
        "exported fixture const must match the fixture file"
    );
}

#[test]
fn ack_cursor_invalid_fixtures_fail_validation() {
    let validator = ack_cursor_validator();
    for (label, fixture) in [
        (
            "missing required field",
            ACK_CURSOR_MISSING_REQUIRED_FIXTURE,
        ),
        ("wrong schema const", ACK_CURSOR_WRONG_SCHEMA_FIXTURE),
        ("malformed hash", ACK_CURSOR_MALFORMED_HASH_FIXTURE),
        ("unknown property", ACK_CURSOR_UNKNOWN_FIELD_FIXTURE),
    ] {
        assert!(
            !validator.is_valid(&parse(fixture)),
            "expected invalid ack cursor fixture ({label}) to fail schema validation"
        );
    }
}

#[test]
fn ack_cursor_schema_rejects_uppercase_hash() {
    // The contract binds to the actual chain via a strictly lowercase sha256 hex
    // digest; an uppercase digest must not slip through.
    let validator = ack_cursor_validator();
    let mut uppercase = parse(ACK_CURSOR_VALID_FIXTURE);
    uppercase["last_acked_hash"] = Value::String(
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    );
    assert!(!validator.is_valid(&uppercase));
}
