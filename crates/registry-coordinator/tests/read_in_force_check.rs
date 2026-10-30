// SPDX-License-Identifier: Apache-2.0
//! `breg.read-in-force/v1` at check and test time: which record types it
//! accepts, the required route for "none in force", the ambiguity warning, and
//! one offline scenario through every answer BReg can give.
use registry_coordinator::authoring;
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const WARNING: &str = "coordinator.read-in-force.may-be-ambiguous";

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

/// A record type with a date validity interval; `scope` lists the fields each
/// `temporal-non-overlap` constraint is scoped by.
fn record_schema(value_kind: Option<&str>, scope: Value) -> Value {
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:breg:record-type:assignment", "type": "object",
        "additionalProperties": false,
        "required": ["district", "officer", "startsOn"],
        "properties": {
            "district": {"type": "string"}, "officer": {"type": "string"},
            "grade": {"type": "integer"},
            "startsOn": {"type": "string", "format": "date"},
            "endsOn": {"type": "string", "format": "date"}
        }
    });
    if let Some(kind) = value_kind {
        schema["x-registry-temporal"] = json!({
            "startProperty": "startsOn", "endProperty": "endsOn",
            "valueKind": kind, "semantics": "start-inclusive-end-exclusive",
            "route": "assignments", "nonOverlapScopeProperties": scope
        });
    }
    schema
}

/// A project with one read-in-force call. `subject` is the mapping reference
/// for the subject member; `route` is the `onDeclaredRefusal` target.
fn project(subject: Value, route: bool) -> Value {
    project_for(subject, route, "assignments")
}

/// The same project reading `entity` instead of the record type's route.
fn project_for(subject: Value, route: bool, entity: &str) -> Value {
    let mut call = json!({
        "type": "call", "operation": "lookup",
        "input": {"type": "fields", "fields": {
            "entity": {"type": "literal", "value": entity},
            "subject": subject,
            "date": {"type": "input", "path": "/date"}
        }},
        "next": "found"
    });
    if route {
        call["onDeclaredRefusal"] = json!("absent");
    }
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "read-in-force", "version": "1"},
        "contracts": {"assignment": {"type": "breg", "source": "contract.json"}},
        "operations": {"lookup": {
            "uses": "breg.read-in-force/v1", "connection": "register",
            "record": {"contract": "assignment"}
        }},
        "workflow": {
            "input": {"type": "object", "additionalProperties": false,
                "required": ["date", "subject"], "properties": {
                    "date": {"type": "string"},
                    "subject": {"type": "object", "additionalProperties": false,
                        "properties": {"district": {"type": "string"}}}
                }},
            "deadlineSeconds": 300, "start": "call",
            "steps": {
                "call": call,
                "found": {"type": "finish", "outcome": "found"},
                "absent": {"type": "finish", "outcome": "absent"}
            },
            "outcomes": {"found": {"type": "null"}, "absent": {"type": "null"}}
        }
    })
}

fn district_subject() -> Value {
    json!({"type": "literal", "value": {"district": "Colombo"}})
}

fn record_reply(domain_data: Value) -> Value {
    json!({
        "recordIdentifier": "00000000-0000-4000-8000-0000000000a1", "revisionIdentifier": "2",
        "domainData": domain_data, "asOf": "2026-06-05", "observedAt": "2026-06-05T08:00:00Z"
    })
}

fn cases() -> Value {
    let case = |id: &str, reply: Value, path: Value, state: &str, outcome: Value| {
        json!({
            "id": id, "admittedAt": "2026-10-09T09:00:00Z", "input": {"date": "2026-06-05", "subject": {"district": "Colombo"}},
            "replies": {"call": [reply]},
            "expect": {"path": path, "state": state, "outcome": outcome}
        })
    };
    let named = |name: &str| json!({"type": "named", "value": name});
    json!({
        "apiVersion": registry_coordinator::scenarios::API_VERSION,
        "kind": registry_coordinator::scenarios::KIND,
        "cases": [
            case("one-record-in-force",
                json!({"type": "success", "value": record_reply(json!({"district": "Colombo"}))}),
                json!(["call", "found"]), "completed", named("found")),
            case("none-in-force-takes-the-route",
                json!({"type": "declared-refusal", "refusalCode": "none-in-force"}),
                json!(["call", "absent"]), "completed", named("absent")),
            case("a-refused-read-is-a-failure-not-an-absence",
                json!({"type": "refused", "code": "product-forbidden"}),
                json!(["call"]), "refused", json!({"type": "none"})),
        ]
    })
}

fn write(root: &Path, project: &Value, schema: &Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(root.join("contract.json"), schema.to_string()).unwrap();
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

fn codes(report: &Value) -> Vec<String> {
    report["diagnostics"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item["code"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_record_type_without_a_date_interval_is_refused() {
    for schema in [
        record_schema(None, json!([])),
        record_schema(Some("timestamp"), json!([["district"]])),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), &project(district_subject(), true), &schema);
        let (exit, report) = cli(root.path(), &["check"]);
        assert_eq!(exit, 1, "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "coordinator.definition.read-in-force-entity"
        );
        assert_eq!(
            report["diagnostics"][0]["path"],
            "/operations/lookup/record"
        );
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("no date validity interval"));
    }
}

#[test]
fn the_operation_needs_a_record_type_selection() {
    let root = tempfile::tempdir().unwrap();
    let mut authored = project(district_subject(), true);
    authored["operations"]["lookup"]
        .as_object_mut()
        .unwrap()
        .remove("record");
    write(
        root.path(),
        &authored,
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.operation.contract-invalid"
    );
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/operations/lookup/record"
    );
}

#[test]
fn the_none_in_force_route_is_required() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(district_subject(), false),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.definition.operation"
    );
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/workflow/steps/call/onDeclaredRefusal"
    );
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("requires onDeclaredRefusal"));
}

#[test]
fn a_subject_field_outside_the_record_type_is_refused() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(
            json!({"type": "literal", "value": {"distrct": "Colombo"}}),
            true,
        ),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
}

#[test]
fn a_subject_the_constraint_scope_covers_passes_without_a_warning() {
    let root = tempfile::tempdir().unwrap();
    // The scope is a subset of the subject fields, so one subject cannot
    // match two overlapping records.
    write(
        root.path(),
        &project(
            json!({"type": "literal", "value": {"district": "Colombo", "grade": 3}}),
            true,
        ),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check", "--deny-warnings"]);
    assert_eq!(exit, 0, "{report}");
    assert!(!codes(&report).contains(&WARNING.to_owned()), "{report}");
}

#[test]
fn a_last_day_interval_is_read_like_an_exclusive_end() {
    // BReg applies the interval's own semantics on the `:as-of` read, so a
    // record type whose interval closes on an inclusive last day is accepted
    // exactly like one with an exclusive end.
    let root = tempfile::tempdir().unwrap();
    let mut schema = record_schema(Some("date"), json!([["district"]]));
    schema["x-registry-temporal"]["semantics"] = json!("start-inclusive-last-day-inclusive");
    write(
        root.path(),
        &project(
            json!({"type": "literal", "value": {"district": "Colombo"}}),
            true,
        ),
        &schema,
    );
    let (exit, report) = cli(root.path(), &["check", "--deny-warnings"]);
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_subject_the_constraint_scope_does_not_fit_warns_that_the_read_may_hold() {
    for (case, subject, scope) in [
        (
            "the constraint is scoped by a field the subject lacks",
            json!({"type": "literal", "value": {"officer": "synthetic-officer"}}),
            json!([["district"]]),
        ),
        (
            "the record type has no non-overlap constraint",
            json!({"type": "literal", "value": {"district": "Colombo"}}),
            json!([]),
        ),
        (
            "the subject is not known at check time and nothing prevents overlap",
            json!({"type": "input", "path": "/subject"}),
            json!([]),
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            &project(subject, true),
            &record_schema(Some("date"), scope),
        );
        let (exit, report) = cli(root.path(), &["check"]);
        assert_eq!(exit, 0, "{case}: {report}");
        assert!(
            codes(&report).contains(&WARNING.to_owned()),
            "{case}: {report}"
        );
        let warning = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["code"] == WARNING)
            .unwrap();
        assert_eq!(warning["severity"], "warning", "{case}");
        assert_eq!(warning["path"], "/workflow/steps/call/input", "{case}");
        assert!(warning["message"]
            .as_str()
            .unwrap()
            .contains("two records in force"));
        let (exit, _) = cli(root.path(), &["check", "--deny-warnings"]);
        assert_eq!(exit, 1, "{case}: warnings can be made to fail the check");
    }
}

#[test]
fn the_entity_must_be_the_route_of_the_selected_record_type() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project_for(district_subject(), true, "rates"),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.mapping.literal"
    );
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/workflow/steps/call/input/fields/entity/value"
    );
}

#[test]
fn a_record_schema_export_without_a_route_must_be_regenerated() {
    let root = tempfile::tempdir().unwrap();
    let mut schema = record_schema(Some("date"), json!([["district"]]));
    schema["x-registry-temporal"]
        .as_object_mut()
        .unwrap()
        .remove("route");
    write(root.path(), &project(district_subject(), true), &schema);
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.operation.contract-invalid"
    );
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/operations/lookup/record"
    );
}

#[test]
fn any_one_covered_scope_is_enough_to_rule_out_two_records() {
    // Two constraints: one scoped by district, one by officer. A subject that
    // names only the officer is covered by the second; a subject that names
    // neither is covered by none.
    let scopes = json!([["district"], ["officer"]]);
    for (subject, warns) in [
        (json!({"officer": "synthetic-officer"}), false),
        (json!({"district": "Colombo"}), false),
        (json!({"grade": 3}), true),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            &project(json!({"type": "literal", "value": subject}), true),
            &record_schema(Some("date"), scopes.clone()),
        );
        let (exit, report) = cli(root.path(), &["check"]);
        assert_eq!(exit, 0, "{subject}: {report}");
        assert_eq!(
            codes(&report).contains(&WARNING.to_owned()),
            warns,
            "{subject}: {report}"
        );
    }
}

#[test]
fn a_nested_subject_is_judged_by_the_fields_it_names() {
    // A nested fields member names its subject fields at check time even when
    // their values come from the input, so the scope rule applies to it.
    for (subject, warns) in [
        (
            json!({"type": "fields", "fields": {
                "officer": {"type": "input", "path": "/subject/district"}
            }}),
            true,
        ),
        (
            json!({"type": "fields", "fields": {
                "district": {"type": "input", "path": "/subject/district"}
            }}),
            false,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            &project(subject.clone(), true),
            &record_schema(Some("date"), json!([["district"]])),
        );
        let (exit, report) = cli(root.path(), &["check"]);
        assert_eq!(exit, 0, "{subject}: {report}");
        assert_eq!(
            codes(&report).contains(&WARNING.to_owned()),
            warns,
            "{subject}: {report}"
        );
    }
}

#[test]
fn an_unknown_subject_is_not_warned_about_when_a_constraint_exists() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(json!({"type": "input", "path": "/subject"}), true),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 0, "{report}");
    assert!(!codes(&report).contains(&WARNING.to_owned()), "{report}");
}

#[test]
fn offline_scenarios_cover_one_record_none_in_force_and_a_refused_read() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(district_subject(), true),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let (exit, report) = cli(root.path(), &["test"]);
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_reply_with_a_field_the_record_type_lacks_fails_the_scenario() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(district_subject(), true),
        &record_schema(Some("date"), json!([["district"]])),
    );
    let mut scenarios = cases();
    scenarios["cases"][0]["replies"]["call"][0]["value"]["domainData"] =
        json!({"unknownField": "x"});
    fs::write(root.path().join("scenarios.yaml"), scenarios.to_string()).unwrap();
    let (exit, report) = cli(root.path(), &["test"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.scenario.reply-output"
    );
}

#[test]
fn an_in_force_read_on_a_connection_with_task_authority_is_refused_at_check() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(district_subject(), true),
        &record_schema(Some("date"), json!([["district"]])),
    );
    fs::write(root.path().join("runtime.yaml"), TASK_AUTHORITY_RUNTIME).unwrap();
    let (exit, report) = cli(root.path(), &["check"]);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        codes(&report),
        ["coordinator.runtime.workflow-binding"],
        "{report}"
    );
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/workflow/steps/call/operation"
    );
}
