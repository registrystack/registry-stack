// SPDX-License-Identifier: Apache-2.0
//! `breg.lookup-record/v1` at check and test time: the input shapes it
//! accepts, the refusal of a direct route from `unresolved` to a step that can
//! write a record, and one offline scenario through every answer BReg can give.
use registry_coordinator::authoring;
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const UNRESOLVED_ROUTE: &str = "coordinator.definition.unresolved-route";
const FACILITIES: &str = include_str!("fixtures/breg-contracts/facilities.contract.json");

/// A runtime whose only BReg connection delegates to task authority, which a
/// lookup or an in-force read cannot use.
const TASK_AUTHORITY_RUNTIME: &str = "\
apiVersion: id.registrystack.org/formats/coordinator/runtime/v1alpha1
kind: CoordinatorRuntimeConfig
secretProviders:
  environment: {}
  file:
    root: /run/registry-coordinator/secrets
database:
  runtimeUrlRef: secret:env/COORDINATOR_TEST_DATABASE_URL
  migrationUrlRef: secret:env/COORDINATOR_TEST_DATABASE_URL
namespace: coordinator_task_authority
connections:
  register:
    type: breg
    baseUrl: http://127.0.0.1:8100
    profile: registrant-reader
    authorization:
      tokenEndpoint: http://127.0.0.1:8090/token
      clientId: registrant-reader
      signingKeyRef: secret:file/client-key
      resource: urn:example:registrants
      scopes: [registrants:read]
      taskAuthority:
        baseUrl: https://casework.example.org
        issuer: https://casework.example.org
        subject: registered-reader
        exchangeAudience: https://issuer.example.org/oauth/token
        bootstrapResource: urn:example:casework
";

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

/// A step that sends a message: it mutates, but it cannot create a record.
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

/// A step that asks a person to review: it mutates, but it cannot create a
/// record.
fn review_step(next: &str) -> Value {
    json!({
        "type": "call", "operation": "review",
        "input": {"type": "literal", "value": {
            "policy": {"id": "registrant-review", "version": "1", "digest": format!("sha256:{}", "b".repeat(64))},
            "subject": {"source": "register", "type": "registrant", "id": "r-1", "version": "1",
                "digest": format!("sha256:{}", "a".repeat(64))},
            "requesterReference": "lookup-request-1",
            "context": {"mode": "submitted", "snapshot": {"summary": "Synthetic registrant"}}
        }},
        "next": next
    })
}

/// A step that writes a record: "not found, so create".
fn register_step(next: &str) -> Value {
    json!({
        "type": "call", "operation": "register",
        "input": {"type": "literal", "value": {"input": {
            "facilityCode": "F-1", "name": "Synthetic clinic", "addressLine": "1 Main Street",
            "city": "Colombo", "postalCode": "00100", "jurisdiction": "LK",
            "operatorId": "00000000-0000-4000-8000-0000000000b1"
        }}},
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
        "contracts": {"facilities": {"type": "breg", "source": "facilities.json"}},
        "operations": {
            "find": {"uses": "breg.lookup-record/v1", "connection": "register"},
            "second-find": {"uses": "breg.lookup-record/v1", "connection": "register"},
            "notices": {"uses": "messaging.submit-message/v1", "connection": "notices"},
            "review": {"uses": "casework.submit-review-request/v1", "connection": "review"},
            "register": {"uses": "breg.invoke-action/v1", "connection": "register-writer",
                "action": {"contract": "facilities", "id": "register-facility"}}
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
    fs::write(root.join("facilities.json"), FACILITIES).unwrap();
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

fn write_workflow(root: &Path, project: &Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(root.join("facilities.json"), FACILITIES).unwrap();
}

fn check(project: &Value) -> (i32, Value) {
    let root = tempfile::tempdir().unwrap();
    write_workflow(root.path(), project);
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
fn unresolved_routed_straight_to_a_step_that_writes_a_record_is_refused() {
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("create")),
        json!({"create": register_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 1, "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], UNRESOLVED_ROUTE, "{report}");
    assert_eq!(
        first_path(&report),
        "/workflow/steps/lookup/onDeclaredRefusal"
    );
    // The message is the sentence in the problem catalog; the step and the
    // operation are in the suggestion.
    assert_eq!(
        diagnostic["message"],
        "A lookup is unresolved when no record matches, but also when two records match or a record is hidden from this profile, so creating a record from this route can make a duplicate."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Route unresolved to a finish, another read or a Casework review request, and create the record from a later step. Step create (breg.invoke-action/v1) can create or change a record."
    );
}

#[test]
fn unresolved_routed_to_a_casework_review_request_passes() {
    // Asking a person to look is the safe answer to an unresolved lookup.
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("ask")),
        json!({"ask": review_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn unresolved_routed_to_a_message_passes() {
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("notify")),
        json!({"notify": notify_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn unresolved_routed_to_another_read_before_a_mutation_passes() {
    // Only the direct route is refused: a person or another read can decide
    // between "unresolved" and a mutation.
    let mut second = lookup_call(lookup_fields(), "create", Some("absent"));
    second["operation"] = json!("second-find");
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("second")),
        json!({"second": second, "create": register_step("absent"), "absent": absent_step()}),
    ));
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn unresolved_routed_through_a_choose_to_a_record_write_passes() {
    // Only the direct route is refused: a choose between the refusal and the
    // write is a decision the workflow made.
    let decide = json!({
        "type": "choose", "choose": {"type": "input", "path": "/nationalId"},
        "cases": {"synthetic-1": "create"}
    });
    let (exit, report) = check(&project(
        lookup_call(lookup_fields(), "found", Some("decide")),
        json!({"decide": decide, "create": register_step("absent"), "absent": absent_step()}),
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
fn a_lookup_has_no_etag_to_map() {
    // A lookup sends and receives no ETag, so its output has no provenance etag.
    let mut authored = well_formed();
    authored["workflow"]["steps"]["found"]["output"]["fields"]["observedAt"]["path"] =
        json!("/provenance/etag");
    let (exit, report) = check(&authored);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        first_path(&report),
        "/workflow/steps/found/output/fields/observedAt/path"
    );
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

#[test]
fn a_lookup_on_a_connection_with_task_authority_is_refused_at_check() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        include_str!("../../../products/coordinator/examples/record-lookup/workflow.yaml"),
    )
    .unwrap();
    fs::write(root.path().join("runtime.yaml"), TASK_AUTHORITY_RUNTIME).unwrap();
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    let finding = &report["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.runtime.workflow-binding");
    assert_eq!(finding["path"], "/workflow/steps/lookup/operation");
    assert!(finding["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("without taskAuthority"));
}
