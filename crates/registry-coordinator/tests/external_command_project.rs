// SPDX-License-Identifier: Apache-2.0
//! Authoring, checking and synthetic scenarios for `external.command/v1`. A
//! project names the command, a pure Function that builds its body, and a pure
//! Function that interprets the provider response into an accepted result, a
//! declared refusal or an uncertain outcome. The runtime file alone chooses the
//! destination, path and credentials.
use registry_coordinator::{
    definition::{Definition, Step},
    protocol::{CallOutcome, Operation},
    scenarios,
};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const WORKFLOW: &str = include_str!("fixtures/external-command/workflow.yaml");
const FUNCTIONS: &str = include_str!("fixtures/external-command/functions.rhai");
const RUNTIME: &str = include_str!("fixtures/external-command/runtime.yaml");
const SCENARIOS: &str = include_str!("fixtures/external-command/scenarios.yaml");

fn replaced(text: &str, replacements: &[(&str, &str)]) -> String {
    let mut text = text.to_owned();
    for (from, to) in replacements {
        assert!(text.contains(from), "{from}");
        text = text.replacen(from, to, 1);
    }
    text
}

/// The fee bill project with each workflow replacement applied once.
fn project(root: &Path, replacements: &[(&str, &str)]) {
    fs::write(root.join("workflow.yaml"), replaced(WORKFLOW, replacements)).unwrap();
    fs::write(root.join("functions.rhai"), FUNCTIONS).unwrap();
}

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

fn check(root: &Path) -> (i32, Value) {
    let output = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        root.to_str().unwrap(),
    ]);
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "a JSON check report: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (output.status.code().unwrap(), report)
}

/// The findings `check` reports for a project that must be refused.
fn refused(replacements: &[(&str, &str)]) -> Vec<Value> {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), replacements);
    let (exit, report) = check(root.path());
    assert_eq!(exit, 1, "{report}");
    report["diagnostics"].as_array().unwrap().clone()
}

fn finding<'a>(findings: &'a [Value], path: &str, expected: &[&str]) -> &'a Value {
    let found = findings
        .iter()
        .find(|finding| finding["path"] == path)
        .unwrap_or_else(|| panic!("no finding at {path}: {findings:#?}"));
    let message = found["message"].as_str().unwrap();
    for text in expected {
        assert!(message.contains(text), "{text}: {message}");
    }
    found
}

#[test]
fn a_command_project_checks_and_explains_its_bound_command() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    fs::write(root.path().join("runtime.yaml"), RUNTIME).unwrap();
    let (exit, report) = check(root.path());
    assert_eq!(exit, 0, "{report}");

    let directory = root.path().to_str().unwrap();
    let output = cli(&["--format", "json", "explain", "--project", directory]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    // Explanation never names the runtime destination or command path.
    assert!(!text.contains("127.0.0.1"), "{text}");
    assert!(!text.contains("commandPath"), "{text}");
    let explained: Value = serde_json::from_str(&text).unwrap();
    let create = explained["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "create")
        .unwrap();
    assert_eq!(create["uses"], "external.command/v1");
    assert_eq!(create["product"], "external-http");
    assert_eq!(create["mutating"], true);
    assert_eq!(create["recovery"], "same-command");
    assert_eq!(create["onDeclaredRefusal"], "not-billed");
    assert_eq!(
        explained["operations"]["create-bill"]["interpret"],
        "bill-outcome"
    );
    let http = &explained["operationContracts"]["external.command/v1"]["limits"]["http"];
    assert_eq!(http["maximumRequestBytes"], 65_536);
    assert_eq!(http["maximumResponseBytes"], 65_536);
    assert_eq!(http["redirects"], "refused");
}

#[test]
fn the_step_output_is_the_accepted_result_and_the_refusal_its_declared_codes() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let definition = Definition::load(root.path()).unwrap();
    let operation = &definition.workflow.operations["create-bill"];
    assert_eq!(operation.uses, Operation::ExternalCommand);
    assert_eq!(operation.interpret.as_deref(), Some("bill-outcome"));
    // The interpretation Function reads the raw bounded response.
    let response = operation.response.as_ref().unwrap();
    assert_eq!(response["required"], json!(["status", "body"]));
    let Some(Step::Call { call, .. }) = definition.workflow.steps.get("create") else {
        panic!("create is a call");
    };
    let contract = definition.operation_contract(call).unwrap();
    assert!(contract.check_output(&json!({"billId":"bill-001"})).is_ok());
    assert!(contract
        .check_output(&json!({"status":201,"body":{"billId":"bill-001"}}))
        .is_err());
    assert!(contract
        .check_refusal(&json!({"refusalCode":"account-closed"}))
        .is_ok());
    assert!(contract
        .check_refusal(&json!({"refusalCode":"another-code"}))
        .is_err());

    let snapshot = definition.snapshot().unwrap();
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.workflow, definition.workflow);
    assert_eq!(restored.digest, definition.digest);
    // A restored snapshot cannot swap the pinned interpretation.
    let swapped = snapshot.replacen(
        "\"interpret\":\"bill-outcome\"",
        "\"interpret\":\"bill-request\"",
        1,
    );
    assert_ne!(swapped, snapshot);
    assert!(Definition::from_snapshot(&swapped).is_err());
}

/// How the worker reads one provider response: the pinned Function's three
/// states, and an uncertain hold for anything it cannot interpret.
fn interpreted(response: Value) -> String {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let definition = Definition::load(root.path()).unwrap();
    let Some(Step::Call { call, .. }) = definition.workflow.steps.get("create") else {
        panic!("create is a call");
    };
    let command = json!({"reference":"application-001","amount":2500});
    match registry_coordinator::external_http::interpret_command(
        &definition,
        call,
        &command,
        response,
        false,
    ) {
        CallOutcome::Success(value) => format!("success {value}"),
        CallOutcome::DeclaredRefusal(refusal) => format!("refusal {}", refusal.refusal_code()),
        CallOutcome::Uncertain { code } => format!("uncertain {code}"),
        CallOutcome::Retryable { code, .. } => format!("retryable {code}"),
        CallOutcome::Refused { code } => format!("refused {code}"),
        CallOutcome::ReceiptExpired => "receipt-expired".into(),
    }
}

#[test]
fn the_worker_interprets_a_response_into_one_of_three_results() {
    assert_eq!(
        interpreted(json!({"status":201,"body":{"billId":"bill-001"}})),
        r#"success {"billId":"bill-001"}"#
    );
    assert_eq!(
        interpreted(json!({"status":422,"body":{"reason":"account-closed"}})),
        "refusal account-closed"
    );
    assert_eq!(
        interpreted(json!({"status":202,"body":{}})),
        "uncertain external-uncertain"
    );
    // A response outside its declared schema is never read by the Function,
    // and nothing of it reaches the outcome.
    let outside = interpreted(json!({"status":201,"body":{"canary":"response-body-canary"}}));
    assert_eq!(outside, "uncertain external-invalid-response");
}

#[test]
fn the_interpretation_is_required_on_the_command_and_nowhere_else() {
    let findings = refused(&[("    interpret: bill-outcome\n", "")]);
    finding(
        &findings,
        "/operations/create-bill/interpret",
        &["external.command/v1", "interpret"],
    );

    let findings = refused(&[("uses: external.command/v1", "uses: external.get/v1")]);
    finding(
        &findings,
        "/operations/create-bill/interpret",
        &["only external.command/v1"],
    );
}

#[test]
fn the_interpretation_takes_the_command_and_its_bounded_response() {
    let findings = refused(&[(
        "      response: {operationOutput: create-bill}\n",
        "      response: {typeRef: bill}\n",
    )]);
    finding(
        &findings,
        "/operations/create-bill/interpret",
        &["command and response"],
    );
}

#[test]
fn the_interpretation_declares_accepted_and_only_known_states() {
    let findings = refused(&[("const: accepted", "const: complete")]);
    finding(&findings, "/functions/bill-outcome/output", &["accepted"]);

    let findings = refused(&[("enum: [account-closed]", "minLength: 1")]);
    finding(
        &findings,
        "/functions/bill-outcome/output",
        &["closed enum"],
    );

    let findings = refused(&[("const: uncertain", "const: pending")]);
    finding(&findings, "/functions/bill-outcome/output", &["uncertain"]);
}

#[test]
fn a_command_without_a_refused_state_has_no_refusal_route() {
    let findings = refused(&[
        (
            concat!(
                "      - type: object\n",
                "        additionalProperties: false\n",
                "        required: [state, code]\n",
                "        properties:\n",
                "          state: {type: string, const: refused}\n",
                "          code: {type: string, enum: [account-closed]}\n",
            ),
            "",
        ),
        (
            "      outcome: not-billed\n      output: {type: step, step: create}\n",
            "      outcome: not-billed\n",
        ),
        (
            "not-billed: {operationRefusal: create-bill}",
            "not-billed: {type: \"null\"}",
        ),
    ]);
    finding(
        &findings,
        "/workflow/steps/create/onDeclaredRefusal",
        &["refusal"],
    );
}

#[test]
fn a_downstream_reader_uses_only_the_accepted_result() {
    let findings = refused(&[(
        "{type: step, step: create, path: /billId}",
        "{type: step, step: create, path: /status}",
    )]);
    assert!(
        findings
            .iter()
            .any(|finding| finding["message"].as_str().unwrap().contains("status")),
        "{findings:#?}"
    );
}

#[test]
fn check_refuses_a_command_without_its_bound_command_connection() {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let binding = |runtime: String| {
        fs::write(root.path().join("runtime.yaml"), runtime).unwrap();
        let (exit, report) = check(root.path());
        assert_eq!(exit, 1, "{report}");
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["code"] == "coordinator.runtime.workflow-binding")
            .unwrap_or_else(|| panic!("no workflow binding finding: {report}"))
            .clone()
    };

    // No connection of the workflow's logical name.
    let missing = binding(RUNTIME.replace("  payments:", "  other-payments:"));
    assert_eq!(missing["path"], "/connections/payments");

    // A connection of another type cannot carry the command.
    let messaging = binding(replaced(
        RUNTIME,
        &[(
            concat!(
                "    type: external-http\n",
                "    baseUrl: http://127.0.0.1:9020/\n",
                "    paths: [bills/status]\n",
                "    commandPath: bills\n",
                "    responseSchema:\n",
                "      type: object\n",
                "      required: [status, body]\n",
                "      properties:\n",
                "        status: {type: integer}\n",
            ),
            concat!(
                "    type: messaging\n",
                "    baseUrl: http://127.0.0.1:9020\n",
                "    authorization:\n",
                "      tokenEndpoint: http://127.0.0.1:8090/token\n",
                "      clientId: case-system\n",
                "      signingKeyRef: secret:env/CLIENT_KEY\n",
                "      resource: urn:example:messaging\n",
                "      scopes: [messaging:send]\n",
            ),
        )],
    ));
    assert_eq!(messaging["path"], "/connections/payments");

    // A read-only external connection has no command path to POST to.
    let read_only = binding(RUNTIME.replace("    commandPath: bills\n", ""));
    assert_eq!(read_only["path"], "/connections/payments/commandPath");
    assert!(read_only["message"]
        .as_str()
        .unwrap()
        .contains("commandPath"));

    fs::write(root.path().join("runtime.yaml"), RUNTIME).unwrap();
    let (exit, report) = check(root.path());
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn the_workflow_cannot_name_a_destination_path_or_credential() {
    for member in [
        "    baseUrl: http://127.0.0.1:9030/\n",
        "    commandPath: admin\n",
        "    headers: {Authorization: Bearer x}\n",
        "    authorization: {token: x}\n",
    ] {
        let findings = refused(&[(
            "    interpret: bill-outcome\n",
            &format!("    interpret: bill-outcome\n{member}"),
        )]);
        assert!(
            findings.iter().any(|finding| finding["path"]
                .as_str()
                .unwrap_or_default()
                .starts_with("/operations/create-bill")),
            "{member}: {findings:#?}"
        );
    }
}

fn scenario_reports(
    scenarios: &str,
) -> registry_coordinator::Result<Vec<scenarios::ScenarioReport>> {
    let root = tempfile::tempdir().unwrap();
    project(root.path(), &[]);
    let definition = Definition::load(root.path()).unwrap();
    let document = scenarios::decode(scenarios, "scenarios.yaml")?;
    scenarios::check(&definition, &document)
}

#[test]
fn scenarios_interpret_provider_responses_with_the_pinned_function() {
    let reports = scenario_reports(SCENARIOS).unwrap();
    let report = |name: &str| {
        reports
            .iter()
            .find(|report| report.name == name)
            .unwrap_or_else(|| panic!("no case {name}"))
    };
    let billed = report("billed");
    assert_eq!(billed.output, Some(json!({"billId":"bill-001"})));
    assert_eq!(billed.call_attempts["create"], 1);
    assert_eq!(billed.frozen_commands, 1);
    let closed = report("account-closed");
    assert_eq!(closed.outcome.as_deref(), Some("not-billed"));
    assert_eq!(closed.output, Some(json!({"refusalCode":"account-closed"})));
    let held = report("unrecognised-answer-holds");
    assert_eq!(held.state, "uncertain");
    assert_eq!(held.path, ["create"]);
    let recovered = report("lost-acknowledgement-sends-the-same-command");
    assert_eq!(recovered.state, "completed");
    assert_eq!(recovered.call_attempts["create"], 2);
    // One frozen command serves both attempts.
    assert_eq!(recovered.frozen_commands, 1);
}

#[test]
fn a_synthetic_response_is_held_to_the_declared_response_schema() {
    let error = scenario_reports(&SCENARIOS.replacen(
        "value: {status: 201, body: {billId: bill-001}}",
        "value: {status: 201, body: {billId: bill-001, extra: application-body-canary}}",
        1,
    ))
    .err()
    .expect("an undeclared response member is refused");
    assert!(error.message.contains("response"), "{}", error.message);
    assert!(!error.message.contains("application-body-canary"));
}

#[test]
fn a_provider_response_reply_belongs_only_to_the_command() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/external-job")
        .canonicalize()
        .unwrap();
    let definition = Definition::load(&root).unwrap();
    let source = fs::read_to_string(root.join("scenarios.yaml"))
        .unwrap()
        .replacen("    - type: success\n", "    - type: response\n", 1);
    let document = scenarios::decode(&source, "scenarios.yaml").unwrap();
    let error = scenarios::check(&definition, &document)
        .err()
        .expect("a read takes no provider response reply");
    assert_eq!(error.code, "scenario.reply");
    assert!(
        error.message.contains("external.get/v1"),
        "{}",
        error.message
    );
}
