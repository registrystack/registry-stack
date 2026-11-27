#![allow(
    clippy::disallowed_methods,
    reason = "tests read back a published contract or fixture to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0
//! The generated development plan and scenario schemas accept each format's
//! committed example and refuse the shapes the reader refuses.

use std::path::Path;

use jsonschema::{Draft, JSONSchema};
use registry_rstack_dev::schema::documents;
use serde_json::{json, Value};

/// Each generated schema and the committed minimal example of its format.
const EXAMPLES: &[(&str, &str)] = &[
    (
        "dev.v1alpha1.schema.json",
        "products/platform/examples/licensing/dev.yaml",
    ),
    (
        "scenarios.v1alpha1.schema.json",
        "products/platform/conformance/projects/breg-project-dev/tests/scenarios.yaml",
    ),
];

/// The identifiers the catalog records, in file-name order.
const IDENTIFIERS: [&str; 2] = [
    "https://id.registrystack.org/schemas/rstack/dev/dev.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/rstack/scenarios/scenarios.v1alpha1.schema.json",
];

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate lives two levels below the repository root")
}

fn compile(document: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("a generated schema compiles as 2020-12")
}

fn example(path: &str) -> Value {
    let text = std::fs::read_to_string(repository_root().join(path))
        .expect("the committed example is readable");
    // A JSON document is also YAML, so one parser reads every example.
    serde_norway::from_str(&text).expect("the committed example parses")
}

#[test]
fn every_committed_example_satisfies_its_generated_schema() {
    let documents = documents().expect("the development schemas generate");
    assert_eq!(documents.len(), EXAMPLES.len());
    for (file, path) in EXAMPLES {
        let schema = compile(&documents[*file]);
        let instance = example(path);
        let problems = match schema.validate(&instance) {
            Ok(()) => Vec::new(),
            Err(errors) => errors
                .map(|error| format!("{} at {}", error, error.instance_path))
                .collect(),
        };
        assert!(problems.is_empty(), "{path} under {file}: {problems:?}");
    }
}

#[test]
fn the_plan_schema_names_the_rstack_dev_format() {
    let documents = documents().expect("the development schemas generate");
    let schema: Value = serde_json::from_str(&documents["dev.v1alpha1.schema.json"])
        .expect("a generated schema is JSON");

    assert_eq!(schema["$id"], IDENTIFIERS[0]);
    assert_eq!(
        schema["properties"]["apiVersion"]["const"],
        "id.registrystack.org/formats/rstack/dev/v1alpha1"
    );
    assert_eq!(schema["properties"]["kind"]["const"], "RStackDev");
}

/// Examples that run one product alone.
#[test]
fn the_single_product_examples_satisfy_the_plan_schema() {
    let documents = documents().expect("the development schemas generate");
    let plan = compile(&documents["dev.v1alpha1.schema.json"]);
    let scenarios = compile(&documents["scenarios.v1alpha1.schema.json"]);

    // BReg reads every YAML file directly under tests/ as a BReg test, so its
    // scenario file lives outside tests/.
    for (directory, scenario_file) in [
        ("products/breg/examples/minimal", "dev/scenarios.yaml"),
        (
            "products/casework/examples/standalone-decision",
            "tests/scenarios.yaml",
        ),
        (
            "products/evidence/examples/standalone",
            "tests/scenarios.yaml",
        ),
    ] {
        assert!(
            plan.is_valid(&example(&format!("{directory}/dev.yaml"))),
            "{directory}/dev.yaml"
        );
        assert!(
            scenarios.is_valid(&example(&format!("{directory}/{scenario_file}"))),
            "{directory}/{scenario_file}"
        );
    }
}

fn project_dev_with_studio_identifiers() -> Value {
    let mut plan = example("products/platform/examples/licensing/dev.yaml");
    let applicant = plan["people"]
        .as_object_mut()
        .expect("people is a mapping")
        .remove("applicant")
        .expect("the licensing example has an applicant");
    plan["people"]["date_of_birth"] = applicant;
    plan["people"]["date_of_birth"]["grants"]["breg"]["profile"] = json!("date_of_birth");
    plan["schemaTestPeople"] = json!({
        "review_flow": {"read.v1": "date_of_birth"}
    });
    plan
}

fn scenarios_with_studio_identifiers() -> Value {
    let mut scenarios =
        example("products/platform/conformance/projects/breg-project-dev/tests/scenarios.yaml");
    scenarios["scenarios"][0]["id"] = json!("review_flow");
    scenarios["scenarios"][0]["steps"][0]["id"] = json!("read.v1");
    scenarios["scenarios"][0]["steps"][0]["as"] = json!("date_of_birth");
    scenarios["scenarios"][0]["steps"][0]["capture"] =
        json!({"draftEtag": {"type": "pointer", "pointer": "/etag"}});
    scenarios
}

#[test]
fn project_dev_schema_accepts_the_readers_local_and_derived_identifiers() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["dev.v1alpha1.schema.json"]);

    assert!(schema.is_valid(&project_dev_with_studio_identifiers()));
}

#[test]
fn scenarios_schema_accepts_the_readers_local_derived_and_capture_identifiers() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["scenarios.v1alpha1.schema.json"]);

    assert!(schema.is_valid(&scenarios_with_studio_identifiers()));
}

#[test]
fn project_dev_schema_refuses_identifiers_the_reader_refuses() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["dev.v1alpha1.schema.json"]);
    let valid = project_dev_with_studio_identifiers();

    for person in ["-person", "1person", "Person", "person.name"] {
        let mut changed = valid.clone();
        let value = changed["people"]
            .as_object_mut()
            .unwrap()
            .remove("date_of_birth")
            .unwrap();
        changed["people"][person] = value;
        assert!(!schema.is_valid(&changed), "person identifier: {person}");
    }

    let mut bad_step_reference = valid.clone();
    bad_step_reference["schemaTestPeople"]["review_flow"] = json!({"read..v1": "date_of_birth"});
    assert!(!schema.is_valid(&bad_step_reference));

    let mut bad_journey_reference = valid.clone();
    let people = bad_journey_reference["schemaTestPeople"]
        .as_object_mut()
        .unwrap()
        .remove("review_flow")
        .unwrap();
    bad_journey_reference["schemaTestPeople"]["review.flow"] = people;
    assert!(!schema.is_valid(&bad_journey_reference));

    let mut bad_person_reference = valid.clone();
    bad_person_reference["schemaTestPeople"]["review_flow"] = json!({"read.v1": "date.of.birth"});
    assert!(!schema.is_valid(&bad_person_reference));

    let mut inline_journey = valid;
    inline_journey["journey"] = json!({"id": "inline", "steps": []});
    assert!(!schema.is_valid(&inline_journey));
}

#[test]
fn project_dev_schema_refuses_person_audiences_the_reader_refuses() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["dev.v1alpha1.schema.json"]);
    let mut plan = project_dev_with_studio_identifiers();

    let at_limit = format!("urn:test:{}", "p".repeat(256 - "urn:test:".len()));
    for accepted in [
        "urn:test:people",
        "https://people.example.test/audience",
        &at_limit,
    ] {
        plan["personAudience"] = json!(accepted);
        assert!(schema.is_valid(&plan), "personAudience: {accepted}");
    }
    for refused in [
        "people",
        "",
        "urn:test:people#fragment",
        "urn:test:with space",
        "urn:test:p\u{e9}ople",
        "https:\\people.example.test",
        "urn:test:a|b",
        &format!("{at_limit}p"),
    ] {
        plan["personAudience"] = json!(refused);
        assert!(!schema.is_valid(&plan), "personAudience: {refused}");
    }
}

#[test]
fn scenarios_schema_refuses_identifiers_the_reader_refuses() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["scenarios.v1alpha1.schema.json"]);
    let valid = scenarios_with_studio_identifiers();

    for step in ["-read", "1read", ".read", "read.", "read..v1", "read.-v1"] {
        let mut changed = valid.clone();
        changed["scenarios"][0]["steps"][0]["id"] = json!(step);
        assert!(!schema.is_valid(&changed), "step identifier: {step}");
    }
    for capture in ["1draft", "draft_etag", "draft.etag"] {
        let mut changed = valid.clone();
        let value = changed["scenarios"][0]["steps"][0]["capture"]
            .as_object_mut()
            .unwrap()
            .remove("draftEtag")
            .unwrap();
        changed["scenarios"][0]["steps"][0]["capture"][capture] = value;
        assert!(!schema.is_valid(&changed), "capture identifier: {capture}");
    }

    let mut bad_person_alias = valid.clone();
    bad_person_alias["scenarios"][0]["steps"][0]["as"] = json!("date.of.birth");
    assert!(!schema.is_valid(&bad_person_alias));

    let mut bad_scenario_id = valid;
    bad_scenario_id["scenarios"][0]["id"] = json!("review.flow");
    assert!(!schema.is_valid(&bad_scenario_id));
}

#[test]
fn authored_scenarios_schema_closes_the_envelope_and_reuses_runner_steps() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["scenarios.v1alpha1.schema.json"]);
    let valid =
        example("products/platform/conformance/projects/breg-project-dev/tests/scenarios.yaml");
    assert!(schema.is_valid(&valid));
    let mut unknown = valid.clone();
    unknown["unexpected"] = json!(true);
    assert!(!schema.is_valid(&unknown));
    let mut invalid_step = valid;
    invalid_step["scenarios"][0]["steps"][0]["product"] = json!("other");
    assert!(!schema.is_valid(&invalid_step));
}

#[test]
fn project_dev_schema_requires_a_scenario_file_and_refuses_an_inline_journey() {
    let documents = documents().expect("the development schemas generate");
    let schema = compile(&documents["dev.v1alpha1.schema.json"]);
    let valid = example("products/platform/examples/licensing/dev.yaml");
    assert!(schema.is_valid(&valid));

    let mut inline = valid.clone();
    inline["journey"] = json!({"id": "inline", "steps": []});
    assert!(!schema.is_valid(&inline));

    let mut missing = valid;
    missing.as_object_mut().unwrap().remove("scenarioFile");
    assert!(!schema.is_valid(&missing));
}

#[test]
fn each_identifier_names_the_format_and_its_version() {
    let documents = documents().expect("the development schemas generate");
    assert_eq!(documents.len(), IDENTIFIERS.len());
    for ((file, document), identifier) in documents.iter().zip(IDENTIFIERS) {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        let format = file.split('.').next().expect("a file name has a stem");
        assert!(identifier.ends_with(&format!("/{format}/{file}")));
        assert_eq!(value["$id"], identifier);
        assert_eq!(
            value["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}
