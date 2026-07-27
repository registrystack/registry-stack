// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};
use std::collections::BTreeSet;

const DIAGNOSTICS_SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.project_diagnostics.v1.schema.json");
const CATALOG_SCHEMA: &str = include_str!(
    "../schemas/project-reports/registryctl.project_authoring_diagnostic_catalog.v1.schema.json"
);
const DIAGNOSTICS_FIXTURE: &str =
    include_str!("fixtures/project-reports/registryctl.project_diagnostics.v1.json");
const CATALOG_FIXTURE: &str = include_str!(
    "fixtures/project-reports/registryctl.project_authoring_diagnostic_catalog.v1.json"
);

fn parse(document: &str) -> Value {
    serde_json::from_str(document).expect("fixture or schema is JSON")
}

fn assert_valid(schema: &str, document: &Value) {
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(schema))
        .expect("strict schema compiles");
    if let Err(errors) = validator.validate(document) {
        panic!(
            "document must validate: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    };
}

fn assert_invalid(schema: &str, document: &Value) {
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(schema))
        .expect("strict schema compiles");
    assert!(validator.validate(document).is_err(), "document must fail");
}

#[test]
fn canonical_authoring_diagnostic_artifacts_are_strict() {
    assert_valid(DIAGNOSTICS_SCHEMA, &parse(DIAGNOSTICS_FIXTURE));
    assert_valid(CATALOG_SCHEMA, &parse(CATALOG_FIXTURE));
}

#[test]
fn diagnostics_reject_unknown_fields_and_non_rfc6901_addresses() {
    let mut unknown = parse(DIAGNOSTICS_FIXTURE);
    unknown["diagnostics"][0]["received_secret"] = json!("must-not-serialize");
    assert_invalid(DIAGNOSTICS_SCHEMA, &unknown);

    let mut pointer = parse(DIAGNOSTICS_FIXTURE);
    pointer["diagnostics"][0]["addresses"][0]["pointer"] = json!("not-a-pointer");
    assert_invalid(DIAGNOSTICS_SCHEMA, &pointer);

    let mut absolute = parse(DIAGNOSTICS_FIXTURE);
    absolute["diagnostics"][0]["addresses"][0]["file"] =
        json!("/tmp/private-project/registry-stack.yaml");
    assert_invalid(DIAGNOSTICS_SCHEMA, &absolute);
}

#[test]
fn diagnostics_accept_sorted_cross_file_address_pairs() {
    let mut relationship = parse(DIAGNOSTICS_FIXTURE);
    relationship["diagnostics"][0]["addresses"] = json!([
        {
            "file": "integrations/eligibility/integration.yaml",
            "pointer": "/input/household_reference"
        },
        {
            "file": "registry-stack.yaml",
            "pointer": "/services/household-eligibility/consultations/household/input/household_reference"
        }
    ]);
    assert_valid(DIAGNOSTICS_SCHEMA, &relationship);
}

#[test]
fn catalog_rejects_unsafe_summary_policy_and_unknown_definitions() {
    let mut unsafe_policy = parse(CATALOG_FIXTURE);
    unsafe_policy["diagnostics"][0]["safe_summary_policy"] = json!("received_value");
    assert_invalid(CATALOG_SCHEMA, &unsafe_policy);

    let mut unknown = parse(CATALOG_FIXTURE);
    unknown["diagnostics"][0]["received_secret"] = json!("must-not-serialize");
    assert_invalid(CATALOG_SCHEMA, &unknown);
}

#[test]
fn report_schema_and_catalog_cannot_drift_on_authoring_codes() {
    let schema = parse(DIAGNOSTICS_SCHEMA);
    let schema_codes = schema["$defs"]["code"]["enum"]
        .as_array()
        .expect("diagnostics schema defines a code enum")
        .iter()
        .map(|code| code.as_str().expect("code is a string"))
        .collect::<BTreeSet<_>>();
    let catalog = parse(CATALOG_FIXTURE);
    let catalog_codes = catalog["diagnostics"]
        .as_array()
        .expect("catalog has definitions")
        .iter()
        .map(|definition| definition["code"].as_str().expect("code is a string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_codes, catalog_codes);
}
