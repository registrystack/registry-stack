// SPDX-License-Identifier: Apache-2.0

use jsonschema::{Draft, JSONSchema};
use registryctl::ProjectSemanticComparisonReportV1;
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.semantic_comparison.v1.schema.json");
const FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.semantic_comparison.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("semantic-comparison schema compiles")
}

fn assert_invalid(document: &Value) {
    assert!(
        validator().validate(document).is_err(),
        "document should fail the strict schema"
    );
}

#[test]
fn canonical_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    if let Err(errors) = validator().validate(&document) {
        panic!(
            "fixture should validate: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
    let decoded: ProjectSemanticComparisonReportV1 =
        serde_json::from_value(document.clone()).expect("fixture decodes");
    let encoded = serde_json::to_value(decoded).expect("fixture re-encodes");
    assert_eq!(encoded, document);
}

#[test]
fn root_and_nested_unknown_fields_fail_closed() {
    let mut root = parse(FIXTURE);
    root["future"] = json!(true);
    assert_invalid(&root);
    assert!(serde_json::from_value::<ProjectSemanticComparisonReportV1>(root).is_err());

    let mut nested = parse(FIXTURE);
    nested["changes"][0]["address"]["runtime_value"] = json!("forbidden");
    assert_invalid(&nested);
    assert!(serde_json::from_value::<ProjectSemanticComparisonReportV1>(nested).is_err());
}

#[test]
fn schema_enforces_change_occurrence_and_array_bounds() {
    let fixture = parse(FIXTURE);

    let mut zero_occurrences = fixture.clone();
    zero_occurrences["changes"][0]["occurrences"] = json!(0);
    assert_invalid(&zero_occurrences);

    let mut excessive_occurrences = fixture.clone();
    excessive_occurrences["changes"][0]["occurrences"] = json!(8193);
    assert_invalid(&excessive_occurrences);

    let mut excessive_changes = fixture;
    let change = excessive_changes["changes"][0].clone();
    excessive_changes["changes"] = Value::Array(vec![change; 1025]);
    assert_invalid(&excessive_changes);
}

#[test]
fn fixed_evidence_limitations_cannot_be_reordered_or_extended() {
    let mut reordered = parse(FIXTURE);
    reordered["evidence_limitations"]
        .as_array_mut()
        .expect("limitations array")
        .swap(0, 1);
    assert_invalid(&reordered);

    let mut extended = parse(FIXTURE);
    extended["evidence_limitations"]
        .as_array_mut()
        .expect("limitations array")
        .push(json!("future_limitation"));
    assert_invalid(&extended);
}
