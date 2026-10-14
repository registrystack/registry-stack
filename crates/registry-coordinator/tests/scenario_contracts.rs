// SPDX-License-Identifier: Apache-2.0
//! Scenarios hold what the static checks leave open to the operation
//! contracts: each computed call input must satisfy the operation input, and
//! each synthetic success value must satisfy the operation output.
use registry_coordinator::{authoring, definition::Definition, scenarios};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn workflow() -> Value {
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "contracted", "version": "1"},
        "operations": {"read-record": {"uses": "breg.read-record/v1", "connection": "applications"}},
        "workflow": {
        "input": {"type": "object", "additionalProperties": false,
            "required": ["applicationId"],
            "properties": {"applicationId": {}}},
        "deadlineSeconds": 86400,
        "start": "read",
        "steps": {
            "read": {"type": "call", "operation": "read-record",
                "input": {"type": "fields", "fields": {
                    "collection": {"type": "literal", "value": "applications"},
                    "recordId": {"type": "input", "path": "/applicationId"}
                }},
                "next": "done"},
            "done": {"type": "finish", "outcome": "accepted", "output": {"type": "fields", "fields": {
                "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"}
            }}}
        },
        "outcomes": {
            "accepted": {"type": "object", "additionalProperties": false,
                "required": ["record"], "properties": {"record": {"type": "string"}}}
        }}
    })
}

fn record(revision: Value) -> Value {
    json!({
        "data": {"recordIdentifier": "r-1", "revisionIdentifier": revision, "domainData": {}},
        "meta": {"registryIdentifier": "registry", "datasetIdentifier": "dataset",
            "entityTypeIdentifier": "application"}
    })
}

fn case(id: &str, application: Value, reply: Value) -> Value {
    json!({
        "id": id, "admittedAt": "2026-10-09T09:00:00Z",
        "input": {"applicationId": application},
        "replies": {"read": [{"type": "success", "value": reply}]},
        "expect": {"path": ["read", "done"], "state": "completed",
            "outcome": {"type": "named", "value": "accepted"}, "output": {"record": "r-1"}}
    })
}

fn declared_refusal_case(id: &str) -> Value {
    json!({
        "id": id, "admittedAt": "2026-10-09T09:00:00Z",
        "input": {"applicationId": "a-1"},
        "replies": {"read": [{"type": "declared-refusal", "refusalCode": "not-eligible"}]},
        "expect": {"path": ["read"], "state": "refused", "outcome": {"type": "none"}}
    })
}

fn scenarios(cases: Vec<Value>) -> String {
    // A YAML document per line keeps each case at a stable source line.
    let mut text = format!(
        "apiVersion: {}\nkind: {}\ncases:\n",
        scenarios::API_VERSION,
        scenarios::KIND
    );
    for case in cases {
        text.push_str(&format!("- {}\n", serde_json::to_string(&case).unwrap()));
    }
    text
}

fn project(root: &Path, cases: Vec<Value>) {
    fs::write(
        root.join("workflow.yaml"),
        serde_json::to_string(&workflow()).unwrap(),
    )
    .unwrap();
    fs::write(root.join("scenarios.yaml"), scenarios(cases)).unwrap();
}

fn tested(cases: Vec<Value>) -> registry_coordinator::Result<Vec<scenarios::ScenarioReport>> {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), cases);
    let definition = Definition::load(root.path()).unwrap();
    let document = scenarios::load(&root.path().join("scenarios.yaml")).unwrap();
    scenarios::check(&definition, &document)
}

/// The one finding `coordinatorctl check` reports for the project.
fn checked(cases: Vec<Value>) -> Value {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), cases);
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "check", "--project"])
        .arg(root.path())
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["diagnostics"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{report}");
    findings[0].clone()
}

const INPUT_MESSAGE: &str = "expected a value of type string at /recordId in the input step read computes, as the breg.read-record/v1 input declares; the computed input does not match";
const INPUT_ACTION: &str = "Correct the steps.read.input mapping, or the scenario data it reads, so the computed input satisfies the breg.read-record/v1 input.";
const OUTPUT_MESSAGE: &str = "expected a value of type string at /data/revisionIdentifier in a success reply to step read, as the breg.read-record/v1 output declares; the synthetic value does not match";
const OUTPUT_ACTION: &str =
    "Correct the synthetic value so it satisfies the breg.read-record/v1 output.";

#[test]
fn scenarios_that_fit_both_contracts_pass() {
    let reports = tested(vec![case("fits", json!("a-1"), record(json!("v-1")))]).unwrap();
    assert_eq!(reports[0].output, Some(json!({"record": "r-1"})));
}

#[test]
fn a_computed_call_input_outside_the_operation_input_is_refused() {
    let error = tested(vec![
        case("fits", json!("a-1"), record(json!("v-1"))),
        case("number", json!(7), record(json!("v-1"))),
    ])
    .err()
    .unwrap();
    assert_eq!(error.code, "scenario.call-input");
    assert_eq!(error.field.as_deref(), Some("/cases/1"));
    assert_eq!(error.message, INPUT_MESSAGE);
    assert_eq!(error.suggested_action.as_deref(), Some(INPUT_ACTION));

    let finding = checked(vec![case("number", json!(7), record(json!("v-1")))]);
    assert_eq!(finding["code"], "coordinator.scenario.call-input");
    assert_eq!(finding["path"], "/cases/0");
    assert_eq!(
        finding["message"],
        format!("scenario case number: {INPUT_MESSAGE}")
    );
    assert_eq!(finding["suggestedAction"], INPUT_ACTION);
    assert_eq!(finding["source"]["line"], 4);
}

#[test]
fn a_synthetic_success_outside_the_operation_output_is_refused() {
    let error = tested(vec![
        case("fits", json!("a-1"), record(json!("v-1"))),
        case("number", json!("a-1"), record(json!(7))),
    ])
    .err()
    .unwrap();
    assert_eq!(error.code, "scenario.reply-output");
    assert_eq!(
        error.field.as_deref(),
        Some("/cases/1/replies/read/0/value/data/revisionIdentifier")
    );
    assert_eq!(error.message, OUTPUT_MESSAGE);
    assert_eq!(error.suggested_action.as_deref(), Some(OUTPUT_ACTION));

    let finding = checked(vec![case("number", json!("a-1"), record(json!(7)))]);
    assert_eq!(finding["code"], "coordinator.scenario.reply-output");
    assert_eq!(
        finding["path"],
        "/cases/0/replies/read/0/value/data/revisionIdentifier"
    );
    assert_eq!(
        finding["message"],
        format!("scenario case number: {OUTPUT_MESSAGE}")
    );
    assert_eq!(finding["suggestedAction"], OUTPUT_ACTION);
    assert_eq!(finding["source"]["line"], 4);
}

#[test]
fn every_synthetic_success_is_checked_even_when_the_run_stops_first() {
    // The computed input is refused first at run time, yet the reply the run
    // never reaches is still held to the output contract before the run.
    let error = tested(vec![case("unreached", json!(7), record(json!(7)))])
        .err()
        .unwrap();
    assert_eq!(error.code, "scenario.reply-output");
}

#[test]
fn a_declared_refusal_reply_is_rejected_for_an_operation_without_that_contract() {
    let error = tested(vec![declared_refusal_case("unsupported")])
        .err()
        .unwrap();
    assert_eq!(error.code, "scenario.reply");
    assert_eq!(error.field.as_deref(), Some("/cases/0/replies/read/0"));
    assert_eq!(
        error.message,
        "step read calls breg.read-record/v1, which cannot return a package-declared business refusal"
    );
}

#[test]
fn a_missing_member_is_reported_at_the_object_that_lacks_it() {
    let mut reply = record(json!("v-1"));
    reply["meta"]
        .as_object_mut()
        .unwrap()
        .remove("datasetIdentifier");
    let error = tested(vec![case("missing", json!("a-1"), reply)])
        .err()
        .unwrap();
    assert_eq!(
        error.field.as_deref(),
        Some("/cases/0/replies/read/0/value/meta")
    );
    assert_eq!(
        error.message,
        "expected the required member datasetIdentifier at /meta in a success reply to step read, as the breg.read-record/v1 output declares; the synthetic value does not match"
    );
}
