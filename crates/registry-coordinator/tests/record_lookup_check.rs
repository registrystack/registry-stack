// SPDX-License-Identifier: Apache-2.0
//! `breg.lookup-record/v1` at check and test time: the input shapes it
//! accepts, the refusal of a direct route from `unresolved` to a step that
//! mutates, and one offline scenario through every answer BReg can give.
use registry_coordinator::authoring;
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const UNRESOLVED_ROUTE: &str = "coordinator.definition.unresolved-route";

fn values(fields: Value) -> Value {
    json!({"type": "fields", "fields": fields})
}

fn national_id() -> Value {
    json!({"nationalId": {"type": "input", "path": "/nationalId"}})
}

fn lookup_call(input_fields: Value, next: &str, route: Option<&str>) -> Value {
    let mut call = json!({
        "type": "call", "operation": "find",
        "input": {"type": "fields", "fields": input_fields},
        "next": next
    });
    if let Some(target) = route {
        call["onDeclaredRefusal"] = json!(target);
    }
    call
}

fn lookup_fields() -> Value {
    json!({
        "entity": {"type": "literal", "value": "registrants"},
        "selector": {"type": "literal", "value": "by-national-id"},
        "values": values(national_id())
    })
}

fn absent_step() -> Value {
    json!({"type": "finish", "outcome": "absent"})
}

/// A mutating step: it submits a message, so it is not a read.
fn notify_step(next: &str) -> Value {
    json!({
        "type": "call", "operation": "notices",
        "input": {"type": "fields", "fields": {
            "senderProfile": {"type": "literal", "value": "transactional"},
            "to": {"type": "literal", "value": {"email": "person@example.invalid"}}
        }},
        "next": next
    })
}

/// A project whose first step is `lookup`, with `found` after it. `steps` adds
/// the other steps the lookup routes to.
fn project(lookup: Value, steps: Value) -> Value {
    let mut all = json!({
        "lookup": lookup,
        "found": {
            "type": "finish", "outcome": "found",
            "output": {"type": "fields", "fields": {
                "observedAt": {"type": "step", "step": "lookup", "path": "/provenance/observedAt"}
            }}
        }
    });
    for (name, step) in steps.as_object().unwrap() {
        all[name] = step.clone();
    }
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "record-lookup", "version": "1"},
        "operations": {
            "find": {"uses": "breg.lookup-record/v1", "connection": "register"},
            "second-find": {"uses": "breg.lookup-record/v1", "connection": "register"},
            "notices": {"uses": "messaging.submit-message/v1", "connection": "notices"}
        },
        "workflow": {
            "input": {"type": "object", "additionalProperties": false,
                "required": ["nationalId"], "properties": {"nationalId": {"type": "string"}}},
            "deadlineSeconds": 300, "start": "lookup",
            "steps": all,
            "outcomes": {
                "found": {"type": "object", "additionalProperties": false,
                    "required": ["observedAt"], "properties": {"observedAt": {"type": "string"}}},
                "absent": {"type": "null"}
            }
        }
    })
}

fn well_formed() -> Value {
    project(
        lookup_call(lookup_fields(), "found", Some("absent")),
        json!({"absent": absent_step()}),
    )
}

fn reply() -> Value {
    json!({
        "recordIdentifier": "00000000-0000-4000-8000-0000000000a1", "revisionIdentifier": "7",
        "domainData": {"name": "Synthetic Registrant"},
        "provenance": {
            "recordIdentifier": "00000000-0000-4000-8000-0000000000a1",
            "revisionIdentifier": "7", "observedAt": "2026-10-09T09:00:00Z"
        }
    })
}

fn cases() -> Value {
    let case = |id: &str, reply: Value, path: Value, state: &str, outcome: Value, output: Value| {
        let mut expect = json!({"path": path, "state": state, "outcome": outcome});
        if !output.is_null() {
            expect["output"] = output;
        }
        json!({
            "id": id, "admittedAt": "2026-10-09T09:00:00Z", "input": {"nationalId": "synthetic-1"},
            "replies": {"lookup": [reply]},
            "expect": expect
        })
    };
    let named = |name: &str| json!({"type": "named", "value": name});
    json!({
        "apiVersion": registry_coordinator::scenarios::API_VERSION,
        "kind": registry_coordinator::scenarios::KIND,
        "cases": [
            case("one-record-found",
                json!({"type": "success", "value": reply()}),
                json!(["lookup", "found"]), "completed", named("found"),
                json!({"observedAt": "2026-10-09T09:00:00Z"})),
            case("unresolved-takes-the-route",
                json!({"type": "declared-refusal", "refusalCode": "unresolved"}),
                json!(["lookup", "absent"]), "completed", named("absent"), Value::Null),
            case("a-refused-lookup-is-a-failure-not-an-absence",
                json!({"type": "refused", "code": "product-forbidden"}),
                json!(["lookup"]), "refused", json!({"type": "none"}), Value::Null),
        ]
    })
}

fn write(root: &Path, project: &Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(root.join("scenarios.yaml"), cases().to_string()).unwrap();
}

fn cli(root: &Path, arguments: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json"])
        .args(arguments)
        .arg("--project")
        .arg(root)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

fn check(project: &Value) -> (i32, Value) {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("workflow.yaml"), project.to_string()).unwrap();
    cli(root.path(), &["check"])
}

fn first_path(report: &Value) -> &str {
    report["diagnostics"][0]["path"]
        .as_str()
        .unwrap_or_default()
}

#[test]
fn a_lookup_with_a_route_for_unresolved_passes() {
    let (exit, report) = check(&well_formed());
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_lookup_without_a_route_for_unresolved_passes() {
    // An unrouted refusal stops the run as refused; it is not a compile error.
    let mut authored = project(lookup_call(lookup_fields(), "found", None), json!({}));
    authored["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("absent");
    let (exit, report) = check(&authored);
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn unresolved_routed_straight_to_a_mutation_is_refused() {
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("notify")),
        json!({"notify": notify_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"], UNRESOLVED_ROUTE,
        "{report}"
    );
    assert_eq!(
        first_path(&report),
        "/workflow/steps/lookup/onDeclaredRefusal"
    );
    let message = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(message.contains("two records match"), "{message}");
    assert!(message.contains("duplicate"), "{message}");
}

#[test]
fn unresolved_routed_to_another_read_before_a_mutation_passes() {
    // Only the direct route is refused: a person or another read can decide
    // between "unresolved" and a mutation.
    let mut second = lookup_call(lookup_fields(), "notify", Some("absent"));
    second["operation"] = json!("second-find");
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("second")),
        json!({"second": second, "notify": notify_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_lookup_input_that_is_not_the_structured_shape_is_refused() {
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for missing in ["entity", "selector", "values"] {
        let mut fields = lookup_fields();
        fields.as_object_mut().unwrap().remove(missing);
        cases.push((missing, fields));
    }
    let mut unknown = lookup_fields();
    unknown["filter"] = json!({"type": "literal", "value": "nationalId eq 'x'"});
    cases.push(("an unknown member such as a filter string", unknown));
    let mut empty = lookup_fields();
    empty["values"] = values(json!({}));
    cases.push(("empty values", empty));
    let mut nested = lookup_fields();
    nested["values"] = values(json!({
        "nationalId": values(json!({"inner": {"type": "literal", "value": "x"}}))
    }));
    cases.push(("a nested object value", nested));
    let mut list = lookup_fields();
    list["values"] = values(json!({"nationalId": {"type": "literal", "value": ["a", "b"]}}));
    cases.push(("a list value", list));
    let mut null_value = lookup_fields();
    null_value["values"] = values(json!({"nationalId": {"type": "literal", "value": null}}));
    cases.push(("a null value", null_value));
    let mut number_selector = lookup_fields();
    number_selector["selector"] = json!({"type": "literal", "value": 7});
    cases.push(("a numeric selector", number_selector));
    let mut text_values = lookup_fields();
    text_values["values"] = json!({"type": "literal", "value": "nationalId=x"});
    cases.push(("values given as text", text_values));
    let mut too_many = lookup_fields();
    too_many["values"] = values(
        (0..17)
            .map(|index| {
                (
                    format!("f{index}"),
                    json!({"type": "literal", "value": "x"}),
                )
            })
            .collect::<serde_json::Map<_, _>>()
            .into(),
    );
    cases.push(("more than sixteen values", too_many));

    for (case, fields) in cases {
        let (exit, report) = check(&project(
            lookup_call(fields, "found", Some("absent")),
            json!({"absent": absent_step()}),
        ));
        assert_eq!(exit, 1, "{case}: {report}");
        assert!(
            first_path(&report).starts_with("/workflow/steps/lookup/input"),
            "{case}: {report}"
        );
    }
}

#[test]
fn the_provenance_member_is_part_of_the_output_contract() {
    let mut authored = well_formed();
    authored["workflow"]["steps"]["found"]["output"]["fields"]["observedAt"]["path"] =
        json!("/provenance/lookedAt");
    let (exit, report) = check(&authored);
    assert_eq!(exit, 1, "{report}");
}

#[test]
fn offline_scenarios_cover_found_unresolved_and_a_refused_lookup() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &well_formed());
    let (exit, report) = cli(root.path(), &["test"]);
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_scenario_cannot_invent_another_refusal_code() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &well_formed());
    let mut scenarios = cases();
    scenarios["cases"][1]["replies"]["lookup"][0]["refusalCode"] = json!("not-found");
    fs::write(root.path().join("scenarios.yaml"), scenarios.to_string()).unwrap();
    let (exit, report) = cli(root.path(), &["test"]);
    assert_eq!(exit, 1, "{report}");
}

#[test]
fn a_reply_without_provenance_fails_the_scenario() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &well_formed());
    let mut scenarios = cases();
    scenarios["cases"][0]["replies"]["lookup"][0]["value"]
        .as_object_mut()
        .unwrap()
        .remove("provenance");
    fs::write(root.path().join("scenarios.yaml"), scenarios.to_string()).unwrap();
    let (exit, report) = cli(root.path(), &["test"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.scenario.reply-output"
    );
}
