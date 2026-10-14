// SPDX-License-Identifier: Apache-2.0
//! Offline `check` and `test` report one authored mistake the same way: the
//! same code, the same place and the same words, naming the scenario cases
//! that reached it. A finding names the declared steps, run states and
//! outcomes that differ; for any other value it names where the value differs
//! and the class of each side, never the value itself.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const FUNCTIONS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const SCENARIOS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/scenarios.yaml");
const CASES: [&str; 6] = [
    "notice-accepted-after-virtual-wait",
    "permission-withdrawn",
    "same-command-after-response-loss",
    "read-only-reconciliation-after-response-loss",
    "expired-receipt-does-not-prove-no-effect",
    "refusal-after-unknown-preserves-unknown",
];
/// A scalar no finding may repeat, planted where a value is read or computed.
const MARKER: &str = "coordinator-marker-d23";
/// The record identifier every case reads; a function failure may not repeat
/// it either.
const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";

/// The delayed follow-up example with one replacement in each named file.
fn project(root: &Path, functions: (&str, &str), scenarios: (&str, &str)) {
    fs::write(root.join("workflow.yaml"), WORKFLOW).unwrap();
    assert!(functions.0.is_empty() || FUNCTIONS.contains(functions.0));
    fs::write(
        root.join("functions.rhai"),
        FUNCTIONS.replacen(functions.0, functions.1, 1),
    )
    .unwrap();
    assert!(scenarios.0.is_empty() || SCENARIOS.contains(scenarios.0));
    fs::write(
        root.join("scenarios.yaml"),
        SCENARIOS.replacen(scenarios.0, scenarios.1, 1),
    )
    .unwrap();
}

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

/// The JSON reports of `check` and `test` for one project, both refused.
fn refused(root: &Path) -> (Value, Value) {
    let directory = root.to_str().unwrap();
    let mut reports = [
        cli(&["--format", "json", "check", "--project", directory]),
        cli(&["--format", "json", "test", "--project", directory]),
    ]
    .into_iter()
    .map(|output| {
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    });
    (reports.next().unwrap(), reports.next().unwrap())
}

/// `text` with each replacement applied once; each must apply.
fn replaced(text: &str, replacements: &[(&str, &str)]) -> String {
    replacements
        .iter()
        .fold(text.to_owned(), |text, (from, to)| {
            assert!(text.contains(from), "{from}");
            text.replacen(from, to, 1)
        })
}

/// Everything `check` and `test` print for one refused project, in JSON and
/// as text, standard output and standard error together.
fn printed(root: &Path) -> String {
    let directory = root.to_str().unwrap();
    [
        ["--format", "json", "check", "--project", directory].as_slice(),
        &["--format", "json", "test", "--project", directory],
        &["check", "--project", directory],
        &["test", "--project", directory],
    ]
    .into_iter()
    .map(|arguments| {
        let output = cli(arguments);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
    .collect()
}

/// Neither command repeats any of `values` in any format.
fn assert_unrepeated(root: &Path, values: &[&str]) {
    let printed = printed(root);
    assert!(printed.contains("error["), "{printed}");
    for value in values {
        assert!(!printed.contains(value), "{value} printed:\n{printed}");
    }
}

/// Line number (from 1) of the first workflow line containing `needle`.
fn workflow_line(needle: &str) -> u64 {
    WORKFLOW
        .lines()
        .position(|line| line.contains(needle))
        .unwrap() as u64
        + 1
}

#[test]
fn a_function_returning_an_undeclared_label_is_reported_at_its_step_by_check_and_test() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let label = format!(r#""{MARKER}" }} else {{ "{MARKER}" }}"#);
    project(&root, (r#""send" } else { "skip" }"#, &label), ("", ""));
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let findings = check["diagnostics"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{check}");
    let finding = &findings[0];
    assert_eq!(finding["code"], "coordinator.function.output");
    assert_eq!(finding["path"], "/workflow/steps/permission/choose");
    assert!(finding["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("workflow.yaml"));
    assert_eq!(finding["source"]["line"], workflow_line("choose:") + 1);
    let message = finding["message"].as_str().unwrap();
    for expected in [
        "function notice-route returned a value of class string",
        "declared output schema refuses it",
    ]
    .into_iter()
    .chain(CASES)
    {
        assert!(message.contains(expected), "{expected}: {message}");
    }
    assert_eq!(test["status"], "failed");
    assert_eq!(test["passed"], 0);
    assert_eq!(test["failed"], 6);
    assert!(test["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .all(|case| case["status"] == "failed"));
    assert_unrepeated(&root, &[MARKER]);
}

#[test]
fn a_rhai_failure_names_its_kind_and_position_offline() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(
        &root,
        (
            "record.data.domainData.noticeAllowed {",
            "record.data.domainData.noticeAllowed.missing.member {",
        ),
        ("", ""),
    );
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let finding = &check["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.function.execution");
    assert_eq!(finding["path"], "/workflow/steps/permission/choose");
    assert_eq!(finding["source"]["line"], workflow_line("choose:") + 1);
    let message = finding["message"].as_str().unwrap();
    // The kind of failure and its position in functions.rhai, never the
    // engine's own words, which may repeat the values it was given.
    assert!(
        message.contains("function notice-route failed: a property is missing in function notice_route at line 6, column "),
        "{message}"
    );
    assert!(!message.contains("member"), "{message}");
    assert!(!message.contains('\n'), "{message}");
}

#[test]
fn a_thrown_rhai_error_names_its_kind_and_position_but_no_value() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let thrown = format!(r#"throw "{MARKER} " + record.data.recordIdentifier"#);
    project(
        &root,
        (
            r#"if record.data.domainData.noticeAllowed { "send" } else { "skip" }"#,
            &thrown,
        ),
        ("", ""),
    );
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let finding = &check["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.function.execution");
    let message = finding["message"].as_str().unwrap();
    assert!(
        message.contains("function notice-route failed: an error was thrown in function notice_route at line 6, column "),
        "{message}"
    );
    assert_unrepeated(&root, &[MARKER, RECORD_ID]);
}

#[test]
fn a_failure_in_a_called_function_is_placed_in_that_function() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let functions =
        format!("    helper(record)\n}}\n\nfn helper(record) {{\n    throw \"{MARKER}\";\n}}\n");
    project(
        &root,
        (
            "    if record.data.domainData.noticeAllowed { \"send\" } else { \"skip\" }\n}\n",
            &functions,
        ),
        ("", ""),
    );
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let message = check["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        message.contains(
            "function notice-route failed: an error was thrown in function helper at line 10, column 5"
        ),
        "{message}"
    );
    assert_unrepeated(&root, &[MARKER]);
}

#[test]
fn a_failing_expectation_names_the_case_and_the_expected_and_observed_state() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(
        &root,
        ("", ""),
        ("    state: completed\n", "    state: refused\n"),
    );
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let finding = &check["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.scenario.expectation");
    assert_eq!(finding["path"], "/cases/0/expect/state");
    assert_eq!(
        finding["source"]["line"],
        (SCENARIOS
            .lines()
            .position(|line| line.contains("state: completed"))
            .unwrap()
            + 1) as u64
    );
    assert_eq!(
        finding["message"],
        format!(
            "scenario case {}: /expect/state: expected state refused, observed state completed",
            CASES[0]
        )
    );
    assert_eq!(test["passed"], 5);
    assert_eq!(test["failed"], 1);
    assert_eq!(
        test["scenarios"][0],
        json!({
            "name": CASES[0],
            "status": "failed",
            "path": ["due", "read-application", "permission", "notify", "accepted"],
            "state": "completed",
            "outcome": "message-accepted",
        })
    );
    assert_eq!(
        test["scenarios"][1],
        json!({
            "name": CASES[1],
            "status": "passed",
            "path": ["due", "read-application", "permission", "skipped"],
            "state": "completed",
            "outcome": "no-current-permission",
        })
    );

    let text = cli(&["test", "--project", root.to_str().unwrap()]);
    assert_eq!(text.status.code(), Some(1));
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(
        stdout.trim_end().ends_with("5 passed, 1 failed"),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("FAIL {}", CASES[0])), "{stdout}");
    assert!(stdout.contains(&format!("PASS {}", CASES[1])), "{stdout}");
}

#[test]
fn a_failing_case_names_its_steps_state_and_outcome_but_other_values_only_by_class() {
    const EXPECTED_ID: &str = "00000000-0000-4000-8000-00000000d23e";
    const OBSERVED_ID: &str = "00000000-0000-4000-8000-00000000d23a";
    const ELAPSED: &str = "7654321";
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(&root, ("", ""), ("", ""));
    let scenarios = replaced(
        SCENARIOS,
        &[
            // The second case expects a step after its run ends.
            (
                "    - skipped\n    state: completed\n",
                "    - skipped\n    - notify\n    state: completed\n",
            ),
            // The first case expects another step where the run notified,
            // and the run then reaches a step the expected path does not
            // list.
            (
                "    - notify\n    - accepted\n    state: completed\n",
                "    - skipped\n    state: completed\n",
            ),
            // The synthetic reply carries an identifier into the output.
            (
                "        id: 00000000-0000-4000-8000-000000000002\n",
                &format!("        id: {OBSERVED_ID}\n"),
            ),
            (
                "      value: message-accepted\n",
                "      value: no-current-permission\n",
            ),
            (
                "      messageId: 00000000-0000-4000-8000-000000000002\n",
                &format!("      messageId: {EXPECTED_ID}\n      extra: {MARKER}\n"),
            ),
            (
                "    workflowElapsedSeconds: 960\n",
                &format!("    workflowElapsedSeconds: {ELAPSED}\n"),
            ),
            // The second case expects no outcome, and an object where the
            // run has null.
            (
                "      type: named\n      value: no-current-permission\n    output: null\n",
                &format!("      type: none\n    output:\n      note: {MARKER}\n"),
            ),
        ],
    );
    fs::write(root.join("scenarios.yaml"), scenarios).unwrap();
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let mut findings = check["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            assert_eq!(finding["code"], "coordinator.scenario.expectation");
            assert!(finding["source"]["file"]
                .as_str()
                .unwrap()
                .ends_with("scenarios.yaml"));
            (
                finding["path"].as_str().unwrap().to_owned(),
                finding["message"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    findings.sort();
    let first = |message: &str| format!("scenario case {}: {message}", CASES[0]);
    assert_eq!(
        findings,
        [
            (
                "/cases/0/expect/outcome/value".to_owned(),
                first("/expect/outcome/value: expected outcome no-current-permission, observed outcome message-accepted"),
            ),
            (
                "/cases/0/expect/output/extra".to_owned(),
                first("/expect/output/extra: the run has no value here (expected class string, observed absent)"),
            ),
            (
                "/cases/0/expect/output/messageId".to_owned(),
                first("/expect/output/messageId: the values differ (expected class string, observed class string)"),
            ),
            (
                "/cases/0/expect/path".to_owned(),
                first("/expect/path/4: expected no step, observed step accepted"),
            ),
            (
                "/cases/0/expect/path/3".to_owned(),
                first("/expect/path/3: expected step skipped, observed step notify"),
            ),
            (
                "/cases/0/expect/workflowElapsedSeconds".to_owned(),
                first("/expect/workflowElapsedSeconds: the values differ (expected class integer, observed class integer)"),
            ),
            (
                "/cases/1/expect/outcome".to_owned(),
                format!(
                    "scenario case {}: /expect/outcome: expected no outcome, observed outcome no-current-permission",
                    CASES[1]
                ),
            ),
            (
                "/cases/1/expect/output".to_owned(),
                format!(
                    "scenario case {}: /expect/output: the classes differ (expected class object, observed class null)",
                    CASES[1]
                ),
            ),
            (
                "/cases/1/expect/path/4".to_owned(),
                format!(
                    "scenario case {}: /expect/path/4: expected step notify, observed no step",
                    CASES[1]
                ),
            ),
        ]
    );
    assert_eq!(test["passed"], 4);
    assert_eq!(test["failed"], 2);
    // A case reports the declared steps, state and outcome its run reached,
    // and never its output.
    assert_eq!(
        test["scenarios"][0],
        json!({
            "name": CASES[0],
            "status": "failed",
            "path": ["due", "read-application", "permission", "notify", "accepted"],
            "state": "completed",
            "outcome": "message-accepted",
        })
    );
    assert_eq!(
        test["scenarios"][1],
        json!({
            "name": CASES[1],
            "status": "failed",
            "path": ["due", "read-application", "permission", "skipped"],
            "state": "completed",
            "outcome": "no-current-permission",
        })
    );
    assert_unrepeated(&root, &[MARKER, EXPECTED_ID, OBSERVED_ID, ELAPSED]);
}

#[test]
fn a_case_lists_at_most_twenty_differences_and_counts_the_rest() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(&root, ("", ""), ("", ""));
    // The first case expects 25 output members its run does not have.
    let extra = (0..25)
        .map(|index| format!("      e{index:02}: {MARKER}\n"))
        .collect::<String>();
    let scenarios = replaced(
        SCENARIOS,
        &[(
            "      messageId: 00000000-0000-4000-8000-000000000002\n",
            &format!("      messageId: 00000000-0000-4000-8000-000000000002\n{extra}"),
        )],
    );
    fs::write(root.join("scenarios.yaml"), scenarios).unwrap();
    let (check, test) = refused(&root);
    assert_eq!(check["diagnostics"], test["diagnostics"], "{check}\n{test}");
    let findings = check["diagnostics"].as_array().unwrap();
    assert_eq!(findings.len(), 21, "{check}");
    for (index, finding) in findings[..20].iter().enumerate() {
        assert_eq!(
            finding["path"],
            format!("/cases/0/expect/output/e{index:02}"),
            "{finding}"
        );
    }
    let last = &findings[20];
    assert_eq!(last["code"], "coordinator.scenario.expectation");
    assert_eq!(last["path"], "/cases/0/expect");
    assert_eq!(
        last["message"],
        format!("scenario case {}: and 5 more differences", CASES[0])
    );
    assert_eq!(test["failed"], 1);
    let text = cli(&["test", "--project", root.to_str().unwrap()]);
    let stderr = String::from_utf8(text.stderr).unwrap();
    assert!(stderr.contains("and 5 more differences"), "{stderr}");
    assert!(stderr.contains("/expect/output/e19"), "{stderr}");
    assert!(!stderr.contains("/expect/output/e20"), "{stderr}");
    assert_unrepeated(&root, &[MARKER]);
}

#[test]
fn a_refused_step_value_is_named_by_its_class_and_rule_never_by_value() {
    for kind in ["wait", "finish", "input"] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        project(&root, ("", ""), ("", ""));
        let mut workflow = authored_value();
        let mut functions = FUNCTIONS.to_owned();
        let expected = match kind {
            "wait" => {
                workflow["functions"]["send-after"] = json!({"runtime":"rhai","source":"functions.rhai","entrypoint":"send_after","inputs":{"input":{"typeRef":"workflow-input"}},"output":{"type":"string"}});
                workflow["workflow"]["steps"]["due"]["waitUntil"] = json!({"type":"function","function":"send-after","inputs":{"input":{"type":"input"}}});
                functions.push_str(&format!(
                    "\nfn send_after(args) {{ \"{MARKER}\" + args.input.applicationId }}"
                ));
                "function send-after returned a value of class string; expected an RFC 3339 instant with an offset"
            }
            "finish" => {
                workflow["functions"]["accepted-output"] = json!({"runtime":"rhai","source":"functions.rhai","entrypoint":"accepted_output","inputs":{"input":{"typeRef":"workflow-input"}},"output":{"type":"object"}});
                workflow["workflow"]["steps"]["accepted"]["output"] = json!({"type":"function","function":"accepted-output","inputs":{"input":{"type":"input"}}});
                functions.push_str(&format!("\nfn accepted_output(args) {{ #{{messageId: \"{MARKER}\" + args.input.applicationId}} }}"));
                "function accepted-output returned a value of class object; the message-accepted outcome schema refuses it at /messageId by its rule /properties/messageId/format"
            }
            _ => {
                fs::write(
                    root.join("scenarios.yaml"),
                    SCENARIOS.replacen(
                        "sendAfter: '2026-10-09T09:16:00Z'",
                        "sendAfter: 7654321",
                        1,
                    ),
                )
                .unwrap();
                "the workflow input schema refuses the case input at /sendAfter by its rule /properties/sendAfter/type"
            }
        };
        fs::write(
            root.join("workflow.yaml"),
            serde_json::to_string_pretty(&workflow).unwrap(),
        )
        .unwrap();
        fs::write(root.join("functions.rhai"), functions).unwrap();
        let (check, test) = refused(&root);
        assert_eq!(check["diagnostics"], test["diagnostics"]);
        assert!(
            check["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["message"].as_str().unwrap().contains(expected)),
            "{kind}: {check}"
        );
        assert_unrepeated(&root, &[MARKER, RECORD_ID, "7654321"]);
    }
}

#[test]
fn a_passing_test_reports_each_case_and_the_tally() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(&root, ("", ""), ("", ""));
    let json = cli(&[
        "--format",
        "json",
        "test",
        "--project",
        root.to_str().unwrap(),
    ]);
    assert!(json.status.success());
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["status"], "passed");
    assert_eq!(report["passed"], 6);
    assert_eq!(report["failed"], 0);
    // A case reports its name, status and the declared steps, state and
    // outcome its run reached; the values it computed stay out.
    let names = report["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let mut members = case.as_object().unwrap().keys().collect::<Vec<_>>();
            members.sort();
            assert_eq!(
                members,
                ["name", "outcome", "path", "state", "status"],
                "{case}"
            );
            assert_eq!(case["status"], "passed");
            case["name"].as_str().unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, CASES);
    assert_eq!(
        report["scenarios"][0]["path"],
        json!([
            "due",
            "read-application",
            "permission",
            "notify",
            "accepted"
        ])
    );
    let text = cli(&["test", "--project", root.to_str().unwrap()]);
    assert!(text.status.success());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(
        stdout.trim_end().ends_with("6 passed, 0 failed"),
        "{stdout}"
    );
}

fn authored_value() -> Value {
    registry_platform_yaml::Reader::new("workflow.yaml")
        .scan(WORKFLOW.as_bytes())
        .unwrap()
        .unwrap()
        .to_json_value()
}
fn checked_value(workflow: Value) -> Vec<Value> {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    project(&root, ("", ""), ("", ""));
    fs::write(
        root.join("workflow.yaml"),
        serde_json::to_string_pretty(&workflow).unwrap(),
    )
    .unwrap();
    let output = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        root.to_str().unwrap(),
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{report}");
    report["diagnostics"].as_array().unwrap().clone()
}

/// The one finding at `path`, which names every expected text.
fn finding<'a>(findings: &'a [Value], path: &str, code: &str, expected: &[&str]) -> &'a Value {
    let found = findings
        .iter()
        .find(|finding| finding["path"] == path)
        .unwrap_or_else(|| panic!("no finding at {path}: {findings:#?}"));
    assert_eq!(found["code"], code, "{found}");
    assert!(found["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("workflow.yaml"));
    assert!(found["source"]["line"].as_u64().unwrap() > 2, "{found}");
    let message = found["message"].as_str().unwrap();
    for text in expected {
        assert!(message.contains(text), "{text}: {message}");
    }
    found
}

#[test]
fn an_unknown_operation_lists_the_declared_aliases() {
    let mut workflow = authored_value();
    workflow["workflow"]["steps"]["read-application"]["operation"] = json!("read-recrod");
    let findings = checked_value(workflow);
    assert_eq!(findings.len(), 1);
    finding(
        &findings,
        "/workflow/steps/read-application/operation",
        "coordinator.definition.operation",
        &[
            "read-recrod",
            "applications-read-record",
            "notices-submit-message",
        ],
    );
}

#[test]
fn a_call_to_another_product_must_fit_that_alias_input_schema() {
    let mut workflow = authored_value();
    workflow["workflow"]["steps"]["read-application"]["operation"] =
        json!("notices-submit-message");
    let findings = checked_value(workflow);
    finding(
        &findings,
        "/workflow/steps/read-application/input/fields/collection",
        "coordinator.mapping.field",
        &["messaging.submit-message/v1", "collection"],
    );
}

#[test]
fn a_connection_name_is_bound_at_deployment_and_changes_the_semantic_revision() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), ("", ""), ("", ""));
    let initial = registry_coordinator::definition::Definition::load(root.path()).unwrap();
    let mut workflow = authored_value();
    workflow["operations"]["notices-submit-message"]["connection"] = json!("notice");
    fs::write(root.path().join("workflow.yaml"), workflow.to_string()).unwrap();
    assert_ne!(
        initial.digest,
        registry_coordinator::definition::Definition::load(root.path())
            .unwrap()
            .digest
    );
}

#[test]
fn an_unknown_function_is_reported_at_its_step_with_the_declared_functions() {
    let mut workflow = authored_value();
    workflow["workflow"]["steps"]["notify"]["input"]["function"] = json!("notice-reqest");
    let findings = checked_value(workflow);
    assert_eq!(findings.len(), 1);
    finding(
        &findings,
        "/workflow/steps/notify/input/function",
        "coordinator.mapping.function",
        &["notice-reqest", "notice-request", "notice-route"],
    );
}

#[test]
fn a_function_called_with_the_wrong_inputs_is_reported_at_its_step() {
    let mut workflow = authored_value();
    workflow["workflow"]["steps"]["notify"]["input"]["inputs"]
        .as_object_mut()
        .unwrap()
        .remove("record");
    let findings = checked_value(workflow);
    assert_eq!(findings.len(), 1);
    finding(
        &findings,
        "/workflow/steps/notify/input/inputs",
        "coordinator.mapping.function",
        &["named Function inputs", "signature"],
    );
}

#[test]
fn a_cycle_names_its_members() {
    let mut workflow = authored_value();
    workflow["workflow"]["steps"]["permission"]["cases"]["again"] = json!("due");
    let findings = checked_value(workflow);
    assert_eq!(findings.len(), 1);
    finding(
        &findings,
        "/workflow/steps/permission/cases",
        "coordinator.definition.cycle",
        &["due -> read-application -> permission -> due"],
    );
}

#[test]
fn a_finish_naming_an_undeclared_outcome_is_reported_at_its_step() {
    let mut workflow = authored_value();
    workflow["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("no-current-permission");
    let findings = checked_value(workflow);
    assert_eq!(findings.len(), 1);
    finding(
        &findings,
        "/workflow/steps/skipped/outcome",
        "coordinator.definition.outcome",
        &["no-current-permission", "message-accepted"],
    );
}

#[test]
fn check_reports_every_independent_error_in_one_run() {
    let mut workflow = authored_value();
    workflow["workflow"]["start"] = json!("begin");
    workflow["workflow"]["steps"]["permission"]["choose"]["function"] = json!("notice-rout");
    workflow["workflow"]["steps"]["skipped"]["outcome"] = json!("no-permission");
    let findings = checked_value(workflow);
    let mut paths = findings
        .iter()
        .map(|finding| finding["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        [
            "/workflow/outcomes/no-current-permission",
            "/workflow/start",
            "/workflow/steps/permission/choose/function",
            "/workflow/steps/skipped/outcome"
        ],
        "{findings:#?}"
    );
}

#[test]
fn the_catalog_exposes_the_casework_review_producer_operations() {
    let offers = registry_coordinator::operations::descriptors()
        .iter()
        .filter(|operation| operation.product == "casework")
        .map(|operation| operation.id)
        .collect::<Vec<_>>();
    assert_eq!(
        offers,
        [
            "casework.submit-review-request/v1",
            "casework.cancel-review-request/v1"
        ]
    );
}
