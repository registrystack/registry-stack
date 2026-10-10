// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use registry_coordinator::{definition::Definition, PocError};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const SOURCE: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const CANARY: &str = "secret-value-never-render-this";

fn project(workflow: &str, source: &str) -> TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("workflow.yaml"), workflow).unwrap();
    fs::write(project.path().join("functions.rhai"), source).unwrap();
    project
}
fn load(workflow: &str, source: &str) -> registry_coordinator::Result<Definition> {
    Definition::load(project(workflow, source).path())
}
fn fixture() -> Definition {
    load(WORKFLOW, SOURCE).unwrap()
}
fn input() -> Value {
    json!({"applicationId": "00000000-0000-4000-8000-000000000001", "sendAfter": "2026-10-10T09:00:00Z"})
}
fn instant(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}
fn refused(result: registry_coordinator::Result<Definition>) -> PocError {
    match result {
        Ok(_) => panic!("definition must refuse"),
        Err(error) => error,
    }
}

#[test]
fn synthetic_fixture_maps_current_permission_and_receipt() {
    let definition = fixture();
    let input = input();
    let now = instant("2026-10-09T09:00:00Z");
    assert_eq!(
        definition.initial_due(&input, now).unwrap(),
        Some(instant("2026-10-10T09:00:00Z"))
    );
    assert_eq!(
        definition.deadline_at(now).unwrap(),
        instant("2026-11-08T09:00:00Z")
    );
    assert_eq!(
        definition
            .evaluate("read-application", &input, &BTreeMap::new())
            .unwrap(),
        json!({"collection": "applications", "recordId": input["applicationId"]})
    );
    let record =
        json!({"data": {"domainData": {"noticeAllowed": true, "email": "person@example.invalid"}}});
    let mut outputs = BTreeMap::from([("read-application".into(), record)]);
    assert_eq!(
        definition.evaluate("permission", &input, &outputs).unwrap(),
        "send"
    );
    let command = definition.evaluate("notify", &input, &outputs).unwrap();
    assert_eq!(command["to"]["email"], "person@example.invalid");
    outputs.insert(
        "notify".into(),
        json!({"id": "00000000-0000-4000-8000-000000000002"}),
    );
    let outcome = definition.evaluate("accepted", &input, &outputs).unwrap();
    definition
        .validate_outcome("message-accepted", &outcome)
        .unwrap();
    outputs.insert(
        "read-application".into(),
        json!({"data": {"domainData": {"noticeAllowed": false}}}),
    );
    assert_eq!(
        definition.evaluate("permission", &input, &outputs).unwrap(),
        "skip"
    );
    definition
        .validate_outcome("no-current-permission", &Value::Null)
        .unwrap();
}

#[test]
fn shared_mapping_is_validated_only_for_the_executing_branch() {
    let workflow = json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject", "project": {"id": "shared-mapping", "version": "1"},
        "input": {
            "type": "object", "required": ["choice", "value"],
            "properties": {"choice": {"enum": ["number", "text"]}, "value": {}},
            "additionalProperties": false
        },
        "connections": {}, "functionsFile": "functions.rhai", "deadlineSeconds": 3600, "start": "select",
        "steps": {
            "select": {"type": "choose", "choose": {"function": "branch", "arguments": [{"type": "input"}]},
                "cases": {"number": "finish-number", "text": "finish-text"}},
            "finish-number": {"type": "finish", "outcome": "number", "output": {"function": "value", "arguments": [{"type": "input"}]}},
            "finish-text": {"type": "finish", "outcome": "text", "output": {"function": "value", "arguments": [{"type": "input"}]}}
        },
        "outcomes": {"number": {"type": "integer"}, "text": {"type": "string"}}
    });
    let definition = load(
        &serde_norway::to_string(&workflow).unwrap(),
        "fn branch(input) { input.choice } fn value(input) { input.value }",
    )
    .unwrap();
    for (choice, value, other) in [
        ("number", json!(42), "text"),
        ("text", json!("accepted"), "number"),
    ] {
        let scenario = serde_json::from_value(json!({
            "name": choice, "admittedAt": "2026-10-09T09:00:00Z",
            "input": {"choice": choice, "value": value}, "replies": {},
            "expect": {"path": ["select", format!("finish-{choice}")],
                "state": "completed", "outcome": choice, "output": value}
        }))
        .unwrap();
        let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
        assert_eq!(report.outcome.as_deref(), Some(choice));
        assert_eq!(report.output, Some(value));

        let wrong_step = format!("finish-{other}");
        let error = definition
            .evaluate(&wrong_step, &scenario.input, &BTreeMap::new())
            .unwrap_err();
        assert_eq!(error.code, "coordinator.definition.outcome");
        assert_eq!(
            error.field.as_deref(),
            Some(format!("steps.{wrong_step}.output").as_str())
        );
    }
}

#[test]
fn snapshot_restores_exact_functions_after_project_changes_or_removal() {
    let project = project(WORKFLOW, SOURCE);
    let original = Definition::load(project.path()).unwrap();
    let snapshot = original.snapshot().unwrap();
    fs::write(
        project.path().join("functions.rhai"),
        SOURCE.replace("input.sendAfter", "42"),
    )
    .unwrap();
    drop(project);
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.digest, original.digest);
    assert_eq!(restored.snapshot().unwrap(), snapshot);
    assert_eq!(
        restored
            .initial_due(&input(), instant("2026-10-09T09:00:00Z"))
            .unwrap(),
        Some(instant("2026-10-10T09:00:00Z"))
    );
}

#[test]
fn digest_pins_plan_schema_and_exact_function_bytes() {
    let baseline = fixture().digest;
    assert_ne!(
        baseline,
        load(WORKFLOW, &format!("{SOURCE}\n// extra source bytes\n"))
            .unwrap()
            .digest
    );
    assert_ne!(
        baseline,
        load(
            &WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: 2505600"),
            SOURCE
        )
        .unwrap()
        .digest
    );
    assert_ne!(
        baseline,
        load(
            &WORKFLOW.replace(
                "messageId: {type: string, format: uuid}",
                "messageId: {type: string}"
            ),
            SOURCE
        )
        .unwrap()
        .digest
    );
    assert_eq!(
        baseline,
        load(&format!("# cosmetic workflow comment\n{WORKFLOW}"), SOURCE)
            .unwrap()
            .digest
    );
}

#[test]
fn bad_graphs_and_whole_value_references_refuse() {
    for workflow in [
        WORKFLOW.replace("next: read-application", "next: due"),
        WORKFLOW.replace("next: read-application", "next: missing"),
        WORKFLOW.replace("start: due", "start: missing"),
        WORKFLOW.replace("cases: {send: notify, skip: skipped}", "cases: {}"),
        WORKFLOW.replace(
            "arguments: [{type: step, step: read-application}]",
            "arguments: [{type: step, step: read-application.output.data}]",
        ),
        WORKFLOW.replace(
            "arguments: [{type: step, step: read-application}]",
            "arguments: [{type: step, step: notify}]",
        ),
        WORKFLOW.replace("next: read-application", "next: permission"),
        WORKFLOW.replace("operation: read-record", "operation: submit-message"),
        WORKFLOW.replace("operation: read-record", "operation: arbitrary-http"),
        WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: é"),
        WORKFLOW.replace(
            "functionsFile: functions.rhai",
            "functionsFile: ../functions.rhai",
        ),
        WORKFLOW.replace(
            "kind: CoordinatorProject",
            "kind: CoordinatorProject\nunknown: true",
        ),
        WORKFLOW.replace(
            "deadlineSeconds: 2592000",
            "deadlineSeconds: 2592000\ndeadlineSeconds: 86400",
        ),
        WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: ${DEADLINE}"),
    ] {
        refused(load(&workflow, SOURCE));
    }
    // The join has one route that bypasses notify, so notify.output is not
    // available on every route even though notify exists earlier on one path.
    let workflow = WORKFLOW
        .replace("skip: skipped", "skip: accepted")
        .replace(
            "  skipped:\n    type: finish\n    outcome: no-current-permission\n",
            "",
        )
        .replace("  no-current-permission:\n    type: \"null\"\n", "");
    assert_eq!(
        refused(load(&workflow, SOURCE)).code,
        "coordinator.mapping.dominance"
    );
}

#[test]
fn function_name_arity_and_disabled_language_refuse() {
    for source in [
        SOURCE.replace("fn send_after(input)", "fn other(input)"),
        SOURCE.replace("fn send_after(input)", "fn send_after(input, extra)"),
        format!("{SOURCE}\nfn send_after(x, y) {{ x }}"),
        SOURCE.replace("input.sendAfter", "eval(\"42\")"),
        SOURCE.replace("input.sendAfter", "import \"external\"; input.sendAfter"),
    ] {
        refused(load(WORKFLOW, &source));
    }
    refused(load(WORKFLOW, &" ".repeat(65_537)));
}

#[test]
fn branch_timestamp_schema_and_missing_values_refuse_without_values() {
    let definition = load(
        WORKFLOW,
        &SOURCE.replace(
            "if record.data.domainData.noticeAllowed { \"send\" } else { \"skip\" }",
            &format!("\"{CANARY}\""),
        ),
    )
    .unwrap();
    let outputs = BTreeMap::from([("read-application".into(), json!({}))]);
    let error = definition
        .evaluate("permission", &input(), &outputs)
        .unwrap_err();
    assert_eq!(error.code, "coordinator.mapping.branch");
    assert!(!error.to_string().contains(CANARY));
    let definition = fixture();
    assert_eq!(
        definition
            .evaluate("notify", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "coordinator.mapping.missing-output"
    );
    let outputs = BTreeMap::from([("notify".into(), json!({"id": CANARY}))]);
    let error = definition
        .evaluate("accepted", &input(), &outputs)
        .unwrap_err();
    assert_eq!(error.code, "coordinator.definition.outcome");
    assert!(!error.to_string().contains(CANARY));
    assert!(definition
        .validate_input(&json!({"applicationId": CANARY, "sendAfter": CANARY}))
        .is_err());
    assert!(definition.validate_input(&json!({"applicationId": input()["applicationId"], "sendAfter": "2026-10-10T09:00:00Z", "extra": CANARY})).is_err());
    let bad_due = load(WORKFLOW, &SOURCE.replace("input.sendAfter", "42")).unwrap();
    assert_eq!(
        bad_due
            .initial_due(&input(), instant("2026-10-09T09:00:00Z"))
            .unwrap_err()
            .code,
        "coordinator.mapping.timestamp"
    );
}

#[test]
fn pure_profile_has_no_clock_sleep_or_io_and_limits_computation() {
    for expression in ["sleep(0)", "timestamp()", "read_file(\"anything\")"] {
        let definition = load(WORKFLOW, &SOURCE.replace("input.sendAfter", expression)).unwrap();
        assert_eq!(
            definition
                .evaluate("due", &input(), &BTreeMap::new())
                .unwrap_err()
                .code,
            "coordinator.function.execution"
        );
    }
    for expression in [
        "let n = 0; loop { n += 1; }",
        "let items = []; for n in 0..300 { items.push(n); } items",
        "let s = \"abcdefghijklmnop\"; for n in 0..2000 { s += \"abcdefghijklmnop\"; } s",
    ] {
        let definition = load(WORKFLOW, &SOURCE.replace("input.sendAfter", expression)).unwrap();
        assert_eq!(
            definition
                .evaluate("due", &input(), &BTreeMap::new())
                .unwrap_err()
                .code,
            "coordinator.function.resource-limit"
        );
    }
    let definition = load(
        WORKFLOW,
        &SOURCE.replace("input.sendAfter", &format!("throw \"{CANARY}\"")),
    )
    .unwrap();
    let error = definition
        .evaluate("due", &input(), &BTreeMap::new())
        .unwrap_err();
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn snapshots_refuse_unsupported_abi_duplicate_fields_and_mutation() {
    let mut definition = fixture();
    let snapshot = definition.snapshot().unwrap();
    let mut value: Value = serde_json::from_str(&snapshot).unwrap();
    value["interpreterAbi"] = json!("unknown");
    assert_eq!(
        refused(Definition::from_snapshot(&value.to_string())).code,
        "coordinator.definition.abi"
    );
    value = serde_json::from_str(&snapshot).unwrap();
    value["workflow"]["steps"]["due"]["next"] = json!("due");
    refused(Definition::from_snapshot(&value.to_string()));
    refused(Definition::from_snapshot(&snapshot.replacen(
        "{",
        "{\"source\":\"\",",
        1,
    )));
    definition.workflow.deadline = "1d".into();
    assert_eq!(
        definition.snapshot().unwrap_err().code,
        "coordinator.definition.changed"
    );
    assert_eq!(
        definition.validate_input(&input()).unwrap_err().code,
        "coordinator.definition.changed"
    );
}

#[test]
fn remote_schemas_and_non_null_finish_without_mapping_refuse() {
    let workflow = WORKFLOW.replace(
        "messageId: {type: string, format: uuid}",
        "messageId: {$ref: 'https://example.invalid/schema'}",
    );
    assert_eq!(
        refused(load(&workflow, SOURCE)).code,
        "coordinator.definition.schema"
    );
    let workflow = WORKFLOW.replace("format: uuid", "format: unsupported-format");
    assert_eq!(
        refused(load(&workflow, SOURCE)).code,
        "coordinator.definition.schema"
    );
    let workflow = WORKFLOW.replace("type: \"null\"", "type: string");
    assert_eq!(
        refused(load(&workflow, SOURCE)).code,
        "coordinator.definition.outcome"
    );
}

#[test]
fn resource_limits_include_recursion_input_values_and_non_object_commands() {
    let recursive =
        format!("{SOURCE}\nfn descend(n) {{ if n <= 0 {{ 0 }} else {{ descend(n - 1) }} }}")
            .replace("input.sendAfter", "descend(1000)");
    let definition = load(WORKFLOW, &recursive).unwrap();
    assert_eq!(
        definition
            .evaluate("due", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "coordinator.function.resource-limit"
    );
    let definition = fixture();
    let mut excessive = input();
    excessive["sendAfter"] = json!("x".repeat(16385));
    assert_eq!(
        definition.validate_input(&excessive).unwrap_err().code,
        "coordinator.function.value-limit"
    );
    let definition = load(
        WORKFLOW,
        &SOURCE.replace(
            "#{ collection: \"applications\", recordId: input.applicationId }",
            "42",
        ),
    )
    .unwrap();
    assert_eq!(
        definition
            .evaluate("read-application", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "coordinator.mapping.call-shape"
    );
}

#[test]
fn minimal_finished_workflow_needs_no_mapping_or_timer() {
    let workflow = "apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1\nkind: CoordinatorProject\nproject:\n  id: minimal\n  version: '1'\ninput: true\nconnections: {}\nfunctionsFile: functions.rhai\ndeadlineSeconds: 3600\nstart: done\nsteps:\n  done: {type: finish, outcome: done}\noutcomes:\n  done: {type: 'null'}\n";
    let definition = load(workflow, "").unwrap();
    assert_eq!(
        definition
            .initial_due(&Value::Null, instant("2026-10-09T09:00:00Z"))
            .unwrap(),
        None
    );
    assert!(definition.validate_outcome("done", &Value::Null).is_ok());
    assert!(definition
        .evaluate("arbitrary", &Value::Null, &BTreeMap::new())
        .is_err());
    assert_eq!(
        refused(load(workflow, "fn unused(x) { x } fn unused(x, y) { y }")).code,
        "coordinator.function.definition"
    );
}

#[test]
fn authored_workflow_refuses_environment_substitution() {
    let error = refused(load(
        &WORKFLOW.replace(
            "deadlineSeconds: 2592000",
            "deadlineSeconds: ${PRIVATE_DEADLINE}",
        ),
        SOURCE,
    ));
    assert_eq!(error.code, "config.substitution-not-allowed");
    assert_eq!(error.field.as_deref(), Some("/deadlineSeconds"));
    assert!(error.suggested_action.is_some());
}

#[test]
fn authoring_diagnostics_locate_graph_reference_and_functions_without_runtime_values() {
    let error = refused(load(
        &WORKFLOW.replace(
            "arguments: [{type: step, step: read-application}]",
            "arguments: [{type: step, step: notify}]",
        ),
        SOURCE,
    ));
    assert_eq!(
        error.field.as_deref(),
        Some("/steps/permission/choose/arguments/0")
    );
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("before the branch"));
    let error = refused(load(
        WORKFLOW,
        &SOURCE.replace("fn send_after(input)", "fn send_after(input, extra)"),
    ));
    assert_eq!(
        error.file.as_deref(),
        Some(std::path::Path::new("functions.rhai"))
    );
    assert_eq!(
        error.diagnostics[0].source.as_ref().unwrap().file,
        "functions.rhai"
    );
    let definition = load(
        WORKFLOW,
        &SOURCE.replace("input.sendAfter", &format!("throw \"{CANARY}\"")),
    )
    .unwrap();
    let error = definition
        .evaluate("due", &input(), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("steps.due.waitUntil"));
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn deferred_appointment_graph_preserves_grant_and_maps_product_contracts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let input = json!({"applicationId":"00000000-0000-4000-8000-000000000001",
        "bookAfter":"2026-10-09T09:16:00Z","searchStart":"2026-10-10T10:00:00Z",
        "searchEnd":"2026-10-10T11:00:00Z","grant":{"id":"00000000-0000-4000-8000-000000000003","expiresAt":1791620000}});
    definition.validate_input(&input).unwrap();
    let mut outputs = BTreeMap::from([
        (
            "read-application".into(),
            json!({"data":{"domainData":{"appointmentAllowed":true,"email":"person@example.invalid"}}}),
        ),
        (
            "metadata".into(),
            json!({"schedulingId":"pilot","policyRevision":7,"policyDigest":"sha256:policy"}),
        ),
        (
            "availability".into(),
            json!({"items":[{"kind":"slot","start":"2026-10-10T10:00:00Z","end":"2026-10-10T10:30:00Z","free":1}],"nextCursor":null}),
        ),
    ]);
    assert_eq!(
        definition
            .evaluate("eligibility", &input, &outputs)
            .unwrap(),
        json!("book")
    );
    assert_eq!(
        definition.evaluate("capacity", &input, &outputs).unwrap(),
        json!("available")
    );
    let booking = definition.evaluate("book", &input, &outputs).unwrap();
    assert_eq!(booking["grant"], input["grant"]);
    assert_eq!(booking["appointment"]["admission"]["policyRevision"], 7);
    assert_eq!(
        booking["appointment"]["admission"]["start"],
        "2026-10-10T10:00:00Z"
    );
    let _: registry_scheduling_client::CreateAppointmentRequest =
        serde_json::from_value(booking["appointment"].clone()).unwrap();
    outputs.insert(
        "book".into(),
        json!({"appointmentId":"appointment-one","start":"2026-10-10T10:00:00Z"}),
    );
    let notice = definition.evaluate("notify", &input, &outputs).unwrap();
    let _: registry_messaging_client::SubmitMessageRequest =
        serde_json::from_value(notice).unwrap();
    outputs.insert(
        "notify".into(),
        json!({"id":"00000000-0000-4000-8000-000000000002"}),
    );
    assert_eq!(
        definition.evaluate("accepted", &input, &outputs).unwrap(),
        json!({"appointmentId":"appointment-one","messageId":"00000000-0000-4000-8000-000000000002"})
    );
    outputs.insert("availability".into(), json!({"items":[],"nextCursor":null}));
    assert_eq!(
        definition.evaluate("capacity", &input, &outputs).unwrap(),
        json!("unavailable")
    );
}

#[test]
fn executable_scenarios_follow_real_graph_functions_and_frozen_commands() {
    for name in ["delayed-follow-up", "deferred-appointment"] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../products/coordinator/examples/{name}"));
        let definition = Definition::load(&root).unwrap();
        let scenarios =
            registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
        let reports = registry_coordinator::scenarios::check(&definition, &scenarios).unwrap();
        assert!(reports.iter().any(|report| report.elapsed_seconds == 960));
        assert!(reports.iter().any(|report| report.state == "uncertain"));
        assert!(reports
            .iter()
            .any(|report| report.call_attempts.values().any(|count| *count == 2)));
        let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
        let repeat = registry_coordinator::scenarios::check(&restored, &scenarios).unwrap();
        assert_eq!(
            serde_json::to_value(reports).unwrap(),
            serde_json::to_value(repeat).unwrap()
        );
    }
}

#[test]
fn scenario_waits_expire_at_the_workflow_deadline_without_executing_next_steps() {
    let definition = load(
        &WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: 3600"),
        SOURCE,
    )
    .unwrap();
    for (name, due, elapsed, expired) in [
        ("past-due", "2026-10-09T08:00:00Z", 0, false),
        ("before-deadline", "2026-10-09T09:30:00Z", 1800, false),
        ("at-deadline", "2026-10-09T10:00:00Z", 3600, true),
        ("after-deadline", "2026-10-09T12:00:00Z", 3600, true),
    ] {
        let mut value = input();
        value["sendAfter"] = json!(due);
        let mut scenario: registry_coordinator::scenarios::Scenario =
            serde_json::from_value(json!({
                "name": name, "admittedAt": "2026-10-09T09:00:00Z",
                "input": value,
                "replies": if expired { json!({}) } else { json!({
                    "read-application": [{"success": {"data": {"domainData": {"noticeAllowed": false}}}}]
                }) },
                "expect": if expired { json!({
                    "path": ["due"], "state": "deadline-exceeded", "elapsedSeconds": elapsed
                }) } else { json!({
                    "path": ["due", "read-application", "permission", "skipped"],
                    "state": "completed", "outcome": "no-current-permission", "elapsedSeconds": elapsed
                }) }
            }))
            .unwrap();
        let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
        assert_eq!(report.elapsed_seconds, elapsed, "{name}");
        assert_eq!(report.frozen_commands, 0, "{name}");
        if expired {
            assert!(report.call_attempts.is_empty(), "{name}");
            assert!(report.outcome.is_none(), "{name}");
            assert!(report.output.is_none(), "{name}");
        } else {
            assert_eq!(report.call_attempts["read-application"], 1, "{name}");
        }
        if name == "after-deadline" {
            scenario.expect.elapsed_seconds = Some(10_800);
            assert_eq!(
                registry_coordinator::scenarios::run(&definition, &scenario)
                    .err()
                    .unwrap()
                    .code,
                "coordinator.scenario.expectation"
            );
        }
    }
}

#[test]
fn scenario_past_due_wait_does_not_rewind_an_advanced_clock() {
    let mut workflow: Value = registry_coordinator::authoring::parse_project(
        std::path::Path::new("workflow.yaml"),
        WORKFLOW,
    )
    .unwrap()
    .1
    .to_json_value();
    workflow["deadlineSeconds"] = json!(3600);
    workflow["steps"]["due"]["next"] = json!("earlier");
    workflow["steps"]["earlier"] = json!({
        "type": "wait-until", "waitUntil": {"function": "earlier_due", "arguments": [{"type": "input"}]},
        "next": "read-application"
    });
    let definition = load(
        &serde_norway::to_string(&workflow).unwrap(),
        &format!("{SOURCE}\nfn earlier_due(input) {{ \"2026-10-09T09:10:00Z\" }}"),
    )
    .unwrap();
    let mut value = input();
    value["sendAfter"] = json!("2026-10-09T09:30:00Z");
    let scenario = serde_json::from_value(json!({
        "name": "earlier-wait", "admittedAt": "2026-10-09T09:00:00Z", "input": value,
        "replies": {"read-application": [{"success": {"data": {"domainData": {"noticeAllowed": false}}}}]},
        "expect": {
            "path": ["due", "earlier", "read-application", "permission", "skipped"],
            "state": "completed", "outcome": "no-current-permission", "elapsedSeconds": 1800
        }
    }))
    .unwrap();
    let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
    assert_eq!(report.elapsed_seconds, 1800);
    assert_eq!(report.call_attempts["read-application"], 1);
}

#[test]
fn scenario_recovery_is_explicit_and_freezes_each_mutation_once() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let recovered = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    let report = registry_coordinator::scenarios::run(&definition, recovered).unwrap();
    assert_eq!(report.call_attempts["book"], 2);
    assert_eq!(
        report.frozen_commands, 2,
        "booking and notice each freeze once, recovery reuses booking"
    );
    recovered.recovery.clear();
    assert_eq!(
        registry_coordinator::scenarios::run(&definition, recovered)
            .err()
            .unwrap()
            .code,
        "coordinator.scenario.recovery"
    );
}

#[test]
fn receipt_expiry_forbids_later_scenario_replies_for_retry_and_reconciliation() {
    use registry_coordinator::scenarios::{Recovery, Reply};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let case = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let recovered = registry_coordinator::scenarios::run(&definition, case).unwrap();
        assert_eq!(recovered.state, "completed");
        assert_eq!(recovered.call_attempts["book"], 2);
        assert_eq!(recovered.frozen_commands, 2);
    }
    case.replies.get_mut("book").unwrap()[0] = Reply::ReceiptExpired {
        receipt_expired: true,
    };
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let refused = registry_coordinator::scenarios::run(&definition, case)
            .err()
            .expect("an expired receipt cannot be followed by synthetic success");
        assert_eq!(refused.code, "coordinator.scenario.receipt-expired");
        assert_eq!(refused.field.as_deref(), Some("cases"));
        assert!(refused
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("no live effects were attempted"));
    }
    case.replies.get_mut("book").unwrap().pop();
    case.expect.path.truncate(
        case.expect
            .path
            .iter()
            .position(|step| step == "book")
            .unwrap()
            + 1,
    );
    case.expect.state = "uncertain".into();
    case.expect.outcome = None;
    case.expect.output = None;
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let report = registry_coordinator::scenarios::run(&definition, case).unwrap();
        assert_eq!(report.call_attempts["book"], 1);
        assert_eq!(report.frozen_commands, 1);
        assert_eq!(report.state, "uncertain");
        assert!(report.outcome.is_none());
        assert!(report.output.is_none());
    }
    case.recovery.clear();
    let report = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(report.state, "uncertain");
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

#[test]
fn authored_snapshot_must_fit_the_existing_restore_boundary() {
    let root = tempfile::tempdir().unwrap();
    snapshot_boundary::project_at_snapshot_size(root.path(), snapshot_boundary::SNAPSHOT_BOUND + 1);
    let error = refused(Definition::load(root.path()));
    assert_eq!(error.code, "coordinator.definition.snapshot-limit");
    assert!(!error.to_string().contains(&"x".repeat(100)));
}

#[test]
fn canonical_snapshot_boundary_and_fitting_noncanonical_inputs_restore_unchanged() {
    let root = tempfile::tempdir().unwrap();
    for size in [
        snapshot_boundary::SNAPSHOT_BOUND,
        snapshot_boundary::SNAPSHOT_BOUND - 64,
    ] {
        snapshot_boundary::project_at_snapshot_size(root.path(), size);
        let definition = Definition::load(root.path()).unwrap();
        let snapshot = definition.snapshot().unwrap();
        assert_eq!(snapshot.len(), size);
        let restored = Definition::from_snapshot(&snapshot).unwrap();
        assert_eq!(restored.digest, definition.digest);
        assert_eq!(restored.snapshot().unwrap(), snapshot);
        if size < snapshot_boundary::SNAPSHOT_BOUND {
            let object: Value = serde_json::from_str(&snapshot).unwrap();
            let fields = object
                .as_object()
                .unwrap()
                .iter()
                .rev()
                .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
                .collect::<Vec<_>>()
                .join(",");
            let reordered = format!(" {{ {fields} }} ");
            assert!(reordered.len() <= snapshot_boundary::SNAPSHOT_BOUND);
            let restored = Definition::from_snapshot(&reordered).unwrap();
            assert_eq!(restored.digest, definition.digest);
            assert_eq!(restored.snapshot().unwrap(), snapshot);
        } else {
            assert_eq!(
                refused(Definition::from_snapshot(&format!("{snapshot} "))).code,
                "coordinator.definition.snapshot-limit"
            );
        }
    }
}

#[test]
fn bounded_noncanonical_input_cannot_expand_into_an_unrestorable_snapshot() {
    let root = tempfile::tempdir().unwrap();
    snapshot_boundary::project_at_snapshot_size(root.path(), snapshot_boundary::SNAPSHOT_BOUND);
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    let mut value: Value = serde_json::from_str(&snapshot).unwrap();
    value["source"] = json!(format!("{}x", value["source"].as_str().unwrap()));
    let canonical = registry_platform_canonical_json::canonicalize_json(&value).unwrap();
    assert_eq!(canonical.len(), snapshot_boundary::SNAPSHOT_BOUND + 1);
    let compact = String::from_utf8(canonical)
        .unwrap()
        .replacen("0.000001", "1e-6", 1);
    assert!(compact.len() <= snapshot_boundary::SNAPSHOT_BOUND);
    assert_eq!(
        refused(Definition::from_snapshot(&compact)).code,
        "coordinator.definition.snapshot-limit"
    );
}

#[test]
fn scenario_reconciliation_requires_an_uncertain_mutation() {
    use registry_coordinator::scenarios::{Recovery, Reply};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let case = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    case.replies.get_mut("book").unwrap()[0] = Reply::Retryable {
        retryable: "rate-limited".into(),
    };
    case.recovery.insert("book".into(), Recovery::RetrySame);
    let retried = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(retried.state, "completed");
    assert_eq!(retried.call_attempts["book"], 2);
    assert_eq!(retried.frozen_commands, 2);

    case.recovery.insert("book".into(), Recovery::Reconcile);
    let refused = registry_coordinator::scenarios::run(&definition, case)
        .err()
        .expect("a definite retryable rejection has no success receipt to observe");
    assert_eq!(refused.code, "coordinator.scenario.recovery");

    case.replies.get_mut("book").unwrap()[0] = Reply::Uncertain {
        uncertain: "transport-uncertain".into(),
    };
    case.replies.get_mut("book").unwrap().insert(
        1,
        Reply::Retryable {
            retryable: "observation-unavailable".into(),
        },
    );
    let reconciled = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(reconciled.state, "completed");
    assert_eq!(reconciled.call_attempts["book"], 3);
    assert_eq!(reconciled.frozen_commands, 2);
}
