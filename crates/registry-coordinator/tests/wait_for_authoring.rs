// SPDX-License-Identifier: Apache-2.0
//! A `wait-for` step hands a run to an event another product delivers and
//! continues with that event's value as its output. `check` holds the step to
//! a request it can correlate on every route, a bounded timeout that fits the
//! run deadline, and readers that use only what the event declares.
use registry_coordinator::definition::Definition;
use serde_json::Value;
use std::{fs, path::Path, process::Command};

/// A focused review-wait project, which every test here varies. The maintained
/// example is free to evolve without changing these single-boundary cases.
const WORKFLOW: &str = include_str!("fixtures/review-wait/workflow.yaml");

const FUNCTIONS: &str = include_str!("fixtures/review-wait/functions.rhai");

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

/// The reviewed-notice project with each replacement applied once.
fn project(root: &Path, replacements: &[(&str, &str)]) {
    let mut workflow = WORKFLOW.to_owned();
    for (from, to) in replacements {
        assert!(workflow.contains(from), "{from}");
        workflow = workflow.replacen(from, to, 1);
    }
    fs::write(root.join("workflow.yaml"), workflow).unwrap();
    fs::write(root.join("functions.rhai"), FUNCTIONS).unwrap();
}

/// The findings `check` reports for the project with the replacements.
fn checked(replacements: &[(&str, &str)]) -> Vec<Value> {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), replacements);
    let output = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        root.path().to_str().unwrap(),
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{report}");
    report["diagnostics"].as_array().unwrap().clone()
}

/// The one finding at `path`, placed in the workflow, which names every
/// expected text.
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
fn a_review_wait_checks_and_explains_its_request_timeout_and_routes() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let directory = root.path().to_str().unwrap();
    let output = cli(&["--format", "json", "check", "--project", directory]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = cli(&["--format", "json", "explain", "--project", directory]);
    assert!(output.status.success());
    let explained: Value = serde_json::from_slice(&output.stdout).unwrap();
    let wait = explained["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "await-review")
        .unwrap();
    assert_eq!(wait["kind"], "wait-for");
    assert_eq!(wait["event"], "review-result");
    assert_eq!(wait["request"], "submit-review");
    assert_eq!(wait["timeoutSeconds"], 1_209_600);
    assert_eq!(wait["onTimeout"], "withdraw");
    assert!(wait["onCancel"].is_null());
    assert_eq!(wait["next"], serde_json::json!(["decide", "withdraw"]));
    let output = cli(&["explain", "--project", directory]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains(
            "await-review: wait for the review-result of submit-review, at most 1209600 seconds, then decide; on timeout withdraw; on cancel the run stops with ordinary cancellation"
        ),
        "{text}"
    );
}

/// `text` without the span from `start` through the end of `last`.
fn cut<'a>(text: &'a str, start: &str, last: &str) -> (&'a str, String) {
    let from = text.find(start).unwrap();
    let to = from + text[from..].find(last).unwrap() + last.len();
    (&text[from..to], String::new())
}

#[test]
fn a_wait_without_on_timeout_explains_that_the_run_fails() {
    let withdraw = cut(
        WORKFLOW,
        "  withdraw:\n",
        "status: {type: step, step: withdraw, path: /result/status}\n        resultId: {type: step, step: withdraw, path: /result/resultId}\n",
    );
    let outcome = cut(
        WORKFLOW,
        "  withdrawn:\n    type: object",
        "      status: {type: string}\n      resultId: {type: string, format: uuid}\n",
    );
    let root = tempfile::tempdir().unwrap();
    project(
        root.path(),
        &[
            ("    onTimeout: withdraw\n", ""),
            (withdraw.0, &withdraw.1),
            (outcome.0, &outcome.1),
        ],
    );
    let directory = root.path().to_str().unwrap();
    let output = cli(&["explain", "--project", directory]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains(
            "await-review: wait for the review-result of submit-review, at most 1209600 seconds, then decide; on timeout the run fails with wait-timed-out; on cancel the run stops with ordinary cancellation"
        ),
        "{text}"
    );
}

#[test]
fn an_authored_cancel_route_checks_and_is_explained_separately() {
    let root = tempfile::tempdir().unwrap();
    project(
        root.path(),
        &[(
            "    onTimeout: withdraw\n",
            "    onTimeout: withdraw\n    onCancel: withdraw\n",
        )],
    );
    let directory = root.path().to_str().unwrap();
    let output = cli(&["--format", "json", "check", "--project", directory]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = cli(&["--format", "json", "explain", "--project", directory]);
    let explained: Value = serde_json::from_slice(&output.stdout).unwrap();
    let wait = explained["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "await-review")
        .unwrap();
    assert_eq!(wait["onTimeout"], "withdraw");
    assert_eq!(wait["onCancel"], "withdraw");
    let output = cli(&["explain", "--project", directory]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("on timeout withdraw; on cancel withdraw"),
        "{text}"
    );
}

#[test]
fn a_wait_naming_an_undeclared_step_lists_the_review_requests() {
    let findings = checked(&[("request: submit-review}", "request: submit-reveiw}")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/await-review/event/request",
        "coordinator.definition.wait",
        &["submit-reveiw", "not declared", "submit-review"],
    );
}

#[test]
fn a_wait_naming_another_call_names_the_operation_it_needs() {
    let findings = checked(&[("request: submit-review}", "request: withdraw}")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/await-review/event/request",
        "coordinator.definition.wait",
        &["withdraw", "submit-review-request", "submit-review"],
    );
}

#[test]
fn a_wait_whose_request_is_not_submitted_on_every_route_is_refused() {
    let findings = checked(&[
        ("start: submit-review", "start: route"),
        (
            "steps:\n  submit-review:\n",
            "steps:\n  route:\n    type: choose\n    choose: {type: literal, value: review}\n    cases: {review: submit-review, skip: await-review}\n  submit-review:\n",
        ),
    ]);
    finding(
        &findings,
        "/steps/await-review/event/request",
        "coordinator.definition.wait",
        &["submit-review", "every route"],
    );
}

#[test]
fn the_wait_output_is_not_available_on_its_timeout_route() {
    let findings = checked(&[(
        "reason: {type: literal, value: \"No decision within fourteen days.\"}",
        "reason: {type: step, step: await-review, path: /status}",
    )]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/withdraw/input/fields/reason",
        "coordinator.mapping.dominance",
        &["not available on every incoming path"],
    );
}

#[test]
fn an_unknown_event_type_is_refused_where_it_is_written() {
    let findings = checked(&[("{type: review-result,", "{type: review-decision,")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let found = &findings[0];
    assert_eq!(found["path"], "/steps/await-review/event/type", "{found}");
    assert_eq!(found["code"], "config.unknown-variant", "{found}");
    assert!(
        found["message"]
            .as_str()
            .unwrap()
            .contains("`review-result`"),
        "{found}"
    );
}

#[test]
fn a_wait_without_a_timeout_is_refused() {
    let findings = checked(&[("    timeoutSeconds: 1209600\n", "")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let found = &findings[0];
    assert_eq!(found["path"], "/steps/await-review", "{found}");
    assert!(
        found["message"]
            .as_str()
            .unwrap()
            .contains("timeoutSeconds"),
        "{found}"
    );
}

#[test]
fn a_timeout_that_cannot_end_before_the_deadline_is_refused() {
    let findings = checked(&[("timeoutSeconds: 1209600", "timeoutSeconds: 2592000")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let found = finding(
        &findings,
        "/steps/await-review/timeoutSeconds",
        "coordinator.definition.wait",
        &["2592000", "deadline"],
    );
    assert!(found["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("deadlineSeconds"));
}

#[test]
fn a_timeout_naming_an_undeclared_step_is_refused_at_on_timeout() {
    let findings = checked(&[("onTimeout: withdraw", "onTimeout: withdrew")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/await-review/onTimeout",
        "coordinator.definition.target",
        &["withdrew"],
    );
}

#[test]
fn a_cancel_route_naming_an_undeclared_step_is_refused_at_on_cancel() {
    let findings = checked(&[(
        "    onTimeout: withdraw\n",
        "    onTimeout: withdraw\n    onCancel: withdrew\n",
    )]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/await-review/onCancel",
        "coordinator.definition.target",
        &["withdrew"],
    );
}

#[test]
fn a_choice_on_the_review_status_covers_every_status() {
    let findings = checked(&[("      superseded: not-decided\n", "")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/decide/cases",
        "coordinator.mapping.cases",
        &["superseded"],
    );
}

#[test]
fn a_reader_of_the_review_result_uses_only_declared_members() {
    let findings = checked(&[("path: /status}\n    cases", "path: /verdict}\n    cases")]);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    finding(
        &findings,
        "/steps/decide/choose/path",
        "coordinator.mapping.path",
        &["review-result", "await-review", "/verdict"],
    );
}

#[test]
fn a_review_wait_survives_its_snapshot() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    assert!(snapshot.contains("\"waitFor\""), "{snapshot}");
    assert!(
        !snapshot.contains("\"onCancel\""),
        "legacy snapshots omit the optional edge: {snapshot}"
    );
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.workflow, definition.workflow);
    assert_eq!(restored.digest, definition.digest);
}

#[test]
fn an_authored_cancel_route_survives_its_snapshot() {
    let root = tempfile::tempdir().unwrap();
    project(
        root.path(),
        &[(
            "    onTimeout: withdraw\n",
            "    onTimeout: withdraw\n    onCancel: withdraw\n",
        )],
    );
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    assert!(snapshot.contains("\"onCancel\":\"withdraw\""), "{snapshot}");
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.workflow, definition.workflow);
    assert_eq!(restored.digest, definition.digest);
}

/// A digest of 64 repetitions of one hexadecimal digit.
fn digest(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

/// The request Casework accepts for the case input, as the submit step's
/// synthetic success.
fn accepted() -> String {
    format!(
        "{{requestId: 00000000-0000-4000-8000-000000000010, subject: {{source: applications, type: application, id: 00000000-0000-4000-8000-000000000001, version: '3', digest: '{}'}}, policy: {{id: application-review, version: '1', digest: '{}'}}, submissionDigest: '{}'}}",
        digest('a'),
        digest('b'),
        digest('c')
    )
}

/// The result of the accepted request with `status` and the extra members.
fn result(status: &str, extra: &str) -> String {
    format!(
        "{{resultId: 00000000-0000-4000-8000-000000000011, requestId: 00000000-0000-4000-8000-000000000010, subject: {{source: applications, type: application, id: 00000000-0000-4000-8000-000000000001, version: '3', digest: '{}'}}, policy: {{id: application-review, version: '1', digest: '{}'}}, submissionDigest: '{}', status: {status}, completedAt: '2026-10-13T09:00:00Z', availableUntil: '2026-11-13T09:00:00Z'{extra}}}",
        digest('a'),
        digest('b'),
        digest('c')
    )
}

/// One case: the submit step accepts, the wait receives `wait`, any further
/// replies follow, and the run must stop as `expect` states.
fn case(id: &str, wait: &str, replies: &str, expect: &str) -> String {
    format!(
        "- id: {id}\n  admittedAt: '2026-10-12T09:00:00Z'\n  input: {{applicationId: 00000000-0000-4000-8000-000000000001, applicationVersion: '3', applicationDigest: '{}', email: person@example.invalid}}\n  replies:\n    submit-review:\n    - {{type: success, value: {}}}\n{replies}  waits:\n    await-review: {wait}\n  expect:\n{expect}",
        digest('a'),
        accepted()
    )
}

const NOTICE: &str = "    notify:\n    - {type: success, value: {id: 00000000-0000-4000-8000-000000000020, status: queued, links: {self: /v1/messages/00000000-0000-4000-8000-000000000020, cancel: /v1/messages/00000000-0000-4000-8000-000000000020/cancel}}}\n";

/// The approved, rejected, timed-out and decided-late cases of the
/// reviewed-notice workflow.
fn scenarios() -> String {
    let withdrawn = format!(
        "    withdraw:\n    - {{type: success, value: {{outcome: cancelled, result: {}}}}}\n",
        result("cancelled", "")
    );
    let decided_late = format!(
        "    withdraw:\n    - {{type: success, value: {{outcome: already-terminal, result: {}}}}}\n",
        result("approved", "")
    );
    [
        case(
            "approved",
            &format!("{{type: event, value: {}}}", result("approved", "")),
            NOTICE,
            "    path: [submit-review, await-review, decide, notify, notice-sent]\n    state: completed\n    outcome: {type: named, value: notice-sent}\n    output: {messageId: 00000000-0000-4000-8000-000000000020, resultId: 00000000-0000-4000-8000-000000000011}\n    workflowElapsedSeconds: 0\n",
        ),
        case(
            "rejected",
            &format!(
                "{{type: event, value: {}}}",
                result("rejected", ", outcome: missing-evidence")
            ),
            "",
            "    path: [submit-review, await-review, decide, rejected]\n    state: completed\n    outcome: {type: named, value: rejected}\n",
        ),
        case(
            "no-decision",
            "{type: timeout}",
            &withdrawn,
            "    path: [submit-review, await-review, withdraw, confirm-withdrawal, withdrawn]\n    state: completed\n    outcome: {type: named, value: withdrawn}\n    output: {resultId: 00000000-0000-4000-8000-000000000011}\n    workflowElapsedSeconds: 1209600\n",
        ),
        case(
            "decided-late",
            "{type: timeout}",
            &decided_late,
            "    path: [submit-review, await-review, withdraw, confirm-withdrawal, decided-late]\n    state: completed\n    outcome: {type: named, value: decided-late}\n    output: {status: approved, resultId: 00000000-0000-4000-8000-000000000011}\n    workflowElapsedSeconds: 1209600\n",
        ),
    ]
    .concat()
}

fn scenario_file(cases: &str) -> String {
    format!(
        "apiVersion: id.registrystack.org/formats/coordinator/scenarios/v1alpha1\nkind: CoordinatorScenarios\ncases:\n{cases}"
    )
}

/// The JSON `test` report for the project with the replacements and cases,
/// and everything `test` prints in either format.
fn tested(replacements: &[(&str, &str)], cases: &str) -> (Option<i32>, Value, String) {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), replacements);
    fs::write(root.path().join("scenarios.yaml"), scenario_file(cases)).unwrap();
    let directory = root.path().to_str().unwrap();
    let output = cli(&["--format", "json", "test", "--project", directory]);
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    let text = cli(&["test", "--project", directory]);
    let printed = [&output.stdout, &output.stderr, &text.stdout, &text.stderr]
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect();
    (output.status.code(), report, printed)
}

/// Each case's name, reached path, state and outcome, in case order.
fn reached(report: &Value) -> Vec<(String, Vec<String>, String, Value)> {
    report["scenarios"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"))
        .iter()
        .map(|case| {
            assert_eq!(case["status"], "passed", "{report}");
            (
                case["name"].as_str().unwrap().to_owned(),
                case["path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|step| step.as_str().unwrap().to_owned())
                    .collect(),
                case["state"].as_str().unwrap().to_owned(),
                case["outcome"].clone(),
            )
        })
        .collect()
}

#[test]
fn a_scenario_states_the_review_result_each_route_receives() {
    let (code, report, _) = tested(&[], &scenarios());
    assert_eq!(code, Some(0), "{report}");
    let steps = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        reached(&report),
        vec![
            (
                "approved".into(),
                steps(&[
                    "submit-review",
                    "await-review",
                    "decide",
                    "notify",
                    "notice-sent"
                ]),
                "completed".into(),
                Value::from("notice-sent"),
            ),
            (
                "rejected".into(),
                steps(&["submit-review", "await-review", "decide", "rejected"]),
                "completed".into(),
                Value::from("rejected"),
            ),
            (
                "no-decision".into(),
                steps(&[
                    "submit-review",
                    "await-review",
                    "withdraw",
                    "confirm-withdrawal",
                    "withdrawn"
                ]),
                "completed".into(),
                Value::from("withdrawn"),
            ),
            (
                "decided-late".into(),
                steps(&[
                    "submit-review",
                    "await-review",
                    "withdraw",
                    "confirm-withdrawal",
                    "decided-late"
                ]),
                "completed".into(),
                Value::from("decided-late"),
            ),
        ]
    );
}

#[test]
fn a_scenario_exercises_authored_operator_cancellation_separately_from_timeout() {
    let withdrawn = format!(
        "    withdraw:\n    - {{type: success, value: {{outcome: cancelled, result: {}}}}}\n",
        result("cancelled", "")
    );
    let (code, report, _) = tested(
        &[(
            "    onTimeout: withdraw\n",
            "    onTimeout: withdraw\n    onCancel: withdraw\n",
        )],
        &case(
            "operator-cancelled",
            "{type: cancel}",
            &withdrawn,
            "    path: [submit-review, await-review, withdraw, confirm-withdrawal, withdrawn]\n    state: completed\n    outcome: {type: named, value: withdrawn}\n    output: {resultId: 00000000-0000-4000-8000-000000000011}\n    workflowElapsedSeconds: 0\n",
        ),
    );
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(reached(&report)[0].2, "completed");
}

#[test]
fn a_scenario_cancel_without_an_authored_route_stops_as_cancelled() {
    let (code, report, _) = tested(
        &[],
        &case(
            "ordinary-cancel",
            "{type: cancel}",
            "",
            "    path: [submit-review, await-review]\n    state: cancelled\n    outcome: {type: none}\n    workflowElapsedSeconds: 0\n",
        ),
    );
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(reached(&report)[0].2, "cancelled");
}

#[test]
fn a_timeout_without_a_timeout_route_stops_the_run_as_timed_out() {
    let withdraw = cut(
        WORKFLOW,
        "  withdraw:\n",
        "status: {type: step, step: withdraw, path: /result/status}\n        resultId: {type: step, step: withdraw, path: /result/resultId}\n",
    );
    let outcome = cut(
        WORKFLOW,
        "  withdrawn:\n    type: object",
        "      status: {type: string}\n      resultId: {type: string, format: uuid}\n",
    );
    let (code, report, _) = tested(
        &[
            ("    onTimeout: withdraw\n", ""),
            (withdraw.0, &withdraw.1),
            (outcome.0, &outcome.1),
        ],
        &case(
            "no-decision",
            "{type: timeout}",
            "",
            "    path: [submit-review, await-review]\n    state: timed-out\n    outcome: {type: none}\n    workflowElapsedSeconds: 1209600\n",
        ),
    );
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(reached(&report)[0].2, "timed-out");
}

#[test]
fn a_timeout_the_deadline_passes_first_stops_the_run_at_the_deadline() {
    let (code, report, _) = tested(
        &[
            ("start: submit-review", "start: hold"),
            (
                "steps:\n  submit-review:\n",
                "steps:\n  hold:\n    type: wait-until\n    waitUntil: {type: literal, value: '2026-11-01T09:00:00Z'}\n    next: submit-review\n  submit-review:\n",
            ),
        ],
        &case(
            "no-decision",
            "{type: timeout}",
            "",
            "    path: [hold, submit-review, await-review]\n    state: deadline-exceeded\n    outcome: {type: none}\n    workflowElapsedSeconds: 2592000\n",
        ),
    );
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(reached(&report)[0].2, "deadline-exceeded");
}

/// The one finding `test` reports, which `printed` never repeats a value of.
fn refused<'a>(
    report: &'a Value,
    printed: &str,
    path: &str,
    code: &str,
    hidden: &[&str],
) -> &'a Value {
    let findings = report["diagnostics"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let found = &findings[0];
    assert_eq!(found["path"], path, "{found}");
    assert_eq!(found["code"], code, "{found}");
    assert!(found["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("scenarios.yaml"));
    for value in hidden {
        assert!(!printed.contains(value), "{value}: {printed}");
    }
    found
}

#[test]
fn a_stated_event_outside_the_review_result_contract_is_refused_without_its_value() {
    let approved = result("approved", "");
    for (event, path, hidden) in [
        (
            approved.replace("status: approved", "status: private-verdict"),
            "/cases/0/waits/await-review/value/status",
            vec!["private-verdict"],
        ),
        (
            result("approved", ", outcome: private-reason"),
            "/cases/0/waits/await-review/value",
            vec!["private-reason"],
        ),
        (
            approved.replacen(&digest('a'), &digest('d'), 1),
            "/cases/0/waits/await-review/value/subject",
            vec!["dddddddd"],
        ),
        (
            approved.replace(
                "requestId: 00000000-0000-4000-8000-000000000010",
                "requestId: 00000000-0000-4000-8000-000000000099",
            ),
            "/cases/0/waits/await-review/value/requestId",
            vec!["000000000099"],
        ),
    ] {
        let (code, report, printed) = tested(
            &[],
            &case(
                "approved",
                &format!("{{type: event, value: {event}}}"),
                NOTICE,
                "    path: [submit-review, await-review, decide, notify, notice-sent]\n    state: completed\n",
            ),
        );
        assert_eq!(code, Some(1), "{report}");
        let found = refused(
            &report,
            &printed,
            path,
            "coordinator.scenario.wait-event",
            &hidden,
        );
        assert!(
            found["message"].as_str().unwrap().contains("await-review"),
            "{found}"
        );
    }
}

#[test]
fn a_wait_the_case_does_not_state_is_refused_where_its_waits_belong() {
    let text = case(
        "approved",
        "{type: timeout}",
        "",
        "    path: [submit-review, await-review]\n    state: timed-out\n",
    )
    .replace("  waits:\n    await-review: {type: timeout}\n", "");
    let (code, report, printed) = tested(&[], &text);
    assert_eq!(code, Some(1), "{report}");
    let found = refused(
        &report,
        &printed,
        "/cases/0",
        "coordinator.scenario.wait",
        &[],
    );
    assert!(found["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("waits.await-review"));
}

#[test]
fn waits_name_only_the_wait_steps_of_the_workflow() {
    let stated = |step: &str| {
        case(
            "approved",
            "{type: timeout}",
            "",
            "    path: [submit-review, await-review, withdraw, confirm-withdrawal, withdrawn]\n    state: completed\n",
        )
        .replace("    await-review: {type: timeout}\n", &format!("    {step}: {{type: timeout}}\n"))
    };
    let (code, report, printed) = tested(&[], &stated("submit-review"));
    assert_eq!(code, Some(1), "{report}");
    let found = refused(
        &report,
        &printed,
        "/cases/0/waits/submit-review",
        "coordinator.scenario.wait-step",
        &[],
    );
    assert!(
        found["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("await-review"),
        "{found}"
    );
    let (code, report, printed) = tested(&[], &stated("await-reveiw"));
    assert_eq!(code, Some(1), "{report}");
    refused(
        &report,
        &printed,
        "/cases/0/waits/await-reveiw",
        "coordinator.scenarios.unknown-reference",
        &[],
    );
}
