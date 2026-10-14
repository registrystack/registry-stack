// SPDX-License-Identifier: Apache-2.0
//! Public remote CLI reports distinguish receiver outages from domain refusals.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

// A syntactically valid compact token for the loopback response fixture only.
const TOKEN: &str = "e30.e30.AQ";
const KEY: &str = "original-admission-key";

async fn start(server: &MockServer, root: &Path) -> std::process::Output {
    start_as(server, root, &["--format", "json"]).await
}

async fn start_as(server: &MockServer, root: &Path, format: &[&str]) -> std::process::Output {
    let token = root.join("token");
    let key = root.join("key");
    let input = root.join("input.json");
    fs::write(&token, TOKEN).unwrap();
    fs::write(&key, KEY).unwrap();
    fs::write(&input, r#"{"applicationId":"synthetic"}"#).unwrap();
    let origin = server.uri();
    let format = format
        .iter()
        .map(|argument| argument.to_string())
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(format)
            .args([
                "start",
                "--workflow",
                "follow-up",
                "--workflow-revision",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "--input",
            ])
            .arg(input)
            .arg("--key-file")
            .arg(key)
            .args(["--url", &origin, "--token-file"])
            .arg(token)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

async fn receiver(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/v1/runs"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(header("idempotency-key", KEY))
        .and(body_json(json!({
            "workflow":"follow-up","workflowRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000", "input":{"applicationId":"synthetic"}
        })))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_forwards_the_opaque_cursor_and_state_and_attention_filters() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let token = root.path().join("token");
    fs::write(&token, TOKEN).unwrap();
    Mock::given(method("GET"))
        .and(path("/v1/runs"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"runs":[]})))
        .expect(2)
        .mount(&server)
        .await;
    for attention in ["true", "false"] {
        let origin = server.uri();
        let token = token.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
                .args([
                    "--format",
                    "json",
                    "list",
                    "--limit",
                    "1",
                    "--cursor",
                    "opaque_cursor",
                    "--state",
                    "attention",
                    "--attention",
                    attention,
                    "--url",
                    &origin,
                    "--token-file",
                ])
                .arg(token)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let requests = server.received_requests().await.unwrap();
    for (request, attention) in requests.iter().zip(["true", "false"]) {
        let expected =
            format!("limit=1&cursor=opaque_cursor&state=attention&attention={attention}");
        assert_eq!(request.url.query(), Some(expected.as_str()));
    }
}

#[tokio::test]
async fn remote_admission_reports_outages_separately_without_repeating_the_request() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let guidance =
        "Inspect the original run and use its same-command recovery; never substitute a fresh key.";
    for (status, exit, classification, code) in [
        (503, 3, "operational-failure", "service-unavailable"),
        (500, 3, "operational-failure", "service-unavailable"),
        (502, 3, "operational-failure", "service-unavailable"),
        (504, 3, "operational-failure", "service-unavailable"),
        (401, 1, "domain-refusal", "service-refused"),
        (403, 1, "domain-refusal", "service-refused"),
        (409, 1, "domain-refusal", "service-refused"),
    ] {
        receiver(
            &server,
            ResponseTemplate::new(status).set_body_json(json!({
                "detail":"the requested operation could not complete",
                "suggestedAction":guidance
            })),
        )
        .await;
        let output = start(&server, root.path()).await;
        assert_eq!(output.status.code(), Some(exit), "HTTP {status}");
        assert!(output.stderr.is_empty());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["kind"], "CoordinatorCtlReport");
        assert_eq!(report["command"], "start");
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], classification);
        assert_eq!(
            report["diagnostics"][0]["code"],
            format!("coordinator.command.{code}")
        );
        // The CLI never repeats the service's own suggested action.
        assert!(!String::from_utf8_lossy(&output.stdout).contains(guidance));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.reset().await;
    }
    // A receiver without structured guidance must not turn an outage into
    // advice to repair caller policy or start another admission.
    receiver(&server, ResponseTemplate::new(503).set_body_json(json!({}))).await;
    let output = start(&server, root.path()).await;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let action = report["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap();
    assert!(action.contains("original run"));
    assert!(action.contains("same-command"));
    server.verify().await;
}

#[tokio::test]
async fn a_known_refusal_code_gets_its_own_advice_and_never_the_service_text() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let marker = "service-supplied-advice-marker";
    for (status, code, reported, wanted) in [
        (
            409,
            Some("workflow.revision-mismatch"),
            "service-refused",
            "original workflow revision",
        ),
        (
            403,
            Some("operation.not-authorized"),
            "service-refused",
            "operator: true",
        ),
        (
            401,
            Some("authentication.refused"),
            "service-refused",
            "--token-file",
        ),
        (
            404,
            Some("workflow.not-served"),
            "service-refused",
            "deployment-status",
        ),
        (
            409,
            Some("admission.held"),
            "service-refused",
            "release-admission-hold",
        ),
        (
            409,
            Some("execution.held"),
            "service-refused",
            "release-restore-hold",
        ),
        (
            409,
            Some("restore.lease-incompatible"),
            "service-refused",
            "complete-execution-recovery",
        ),
        (
            409,
            Some("run.definition-incompatible"),
            "service-refused",
            "pinned definition",
        ),
        (
            409,
            Some("idempotency.key-reused"),
            "service-refused",
            "original input",
        ),
        (
            409,
            Some("deployment.refused"),
            "service-refused",
            "deployment-status",
        ),
        (
            503,
            Some("service.unavailable"),
            "service-unavailable",
            "database connectivity",
        ),
        // An unknown or absent code keeps the generic advice, and so does
        // an internal spelling the service never answers.
        (
            409,
            Some("unknown-refusal"),
            "service-refused",
            "caller policy",
        ),
        (
            409,
            Some("workflow-revision-mismatch"),
            "service-refused",
            "caller policy",
        ),
        (409, None, "service-refused", "caller policy"),
        (
            503,
            Some("unknown-outage"),
            "service-unavailable",
            "same-command",
        ),
        (
            503,
            Some("store-unavailable"),
            "service-unavailable",
            "same-command",
        ),
    ] {
        let mut body = json!({
            "detail":"the requested operation could not complete",
            "suggestedAction":marker
        });
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        receiver(&server, ResponseTemplate::new(status).set_body_json(body)).await;
        let output = start(&server, root.path()).await;
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["code"], format!("coordinator.command.{reported}"));
        assert!(finding["message"]
            .as_str()
            .unwrap()
            .starts_with("the requested operation could not complete"));
        let action = finding["suggestedAction"].as_str().unwrap();
        assert!(action.contains(wanted), "{code:?}: {action}");
        assert!(!format!("{report}").contains(marker), "{code:?}: {report}");
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn a_refusal_names_its_problem_code_and_trace_for_the_operator() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let detail = "the requested operation could not complete";
    let trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    for (status, body, wanted) in [
        (
            404,
            json!({"detail":detail, "code":"run.not-visible", "traceId":trace}),
            format!("{detail} (problem run.not-visible, trace {trace})"),
        ),
        (
            409,
            json!({"detail":detail, "code":"workflow.revision-mismatch"}),
            format!("{detail} (problem workflow.revision-mismatch)"),
        ),
        (
            503,
            json!({"detail":detail, "traceId":trace}),
            format!("{detail} (trace {trace})"),
        ),
        // Only a code from the closed vocabulary and a well-formed trace
        // identifier are echoed; any other value the service sends is not.
        (
            409,
            json!({"detail":detail, "code":"unknown-refusal", "traceId":"\u{1b}[2J"}),
            detail.to_owned(),
        ),
        (
            409,
            json!({"detail":detail, "traceId":"00000000000000000000000000000000"}),
            detail.to_owned(),
        ),
    ] {
        receiver(&server, ResponseTemplate::new(status).set_body_json(body)).await;
        let output = start(&server, root.path()).await;
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["diagnostics"][0]["message"], wanted);
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn a_refusal_message_reaches_the_terminal_without_its_control_characters() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    // C0 (ESC, BEL), DEL and C1 (CSI) could each drive a terminal.
    let hostile = "\u{1b}[31mred\u{7}\u{7f}\u{9b}2J";
    let escaped = r"\u{1b}[31mred\u{7}\u{7f}\u{9b}2J";
    let generic = "the authenticated service refused the operation";
    // Escaping can lengthen a message past the echo bound; the bound holds.
    let lengthened = format!("{}{}", "x".repeat(200), "\u{1b}".repeat(10));
    for (message, wanted) in [(hostile.to_owned(), escaped), (lengthened, generic)] {
        for format in [&["--format", "json"][..], &[][..]] {
            receiver(
                &server,
                ResponseTemplate::new(409).set_body_json(json!({ "detail": message })),
            )
            .await;
            let output = start_as(&server, root.path(), format).await;
            assert_eq!(output.status.code(), Some(1), "{format:?}");
            for stream in [&output.stdout, &output.stderr] {
                let shown = String::from_utf8(stream.clone()).unwrap();
                assert!(
                    !shown.chars().any(|c| c.is_control() && c != '\n'),
                    "{format:?}: {shown:?}"
                );
            }
            if format.is_empty() {
                let shown = String::from_utf8_lossy(&output.stderr);
                assert!(shown.contains(wanted), "{shown:?}");
            } else {
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["diagnostics"][0]["message"], wanted);
            }
            server.verify().await;
            server.reset().await;
        }
    }
}

#[tokio::test]
async fn remote_responses_remain_bounded_and_unambiguous_before_status_classification() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    for (response, message) in [
        (
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"run":"first","run":"other"}"#, "application/json"),
            "the service response was not bounded JSON",
        ),
        (
            ResponseTemplate::new(503).set_body_json(json!({"detail":"x".repeat(1_048_576)})),
            "the service response exceeded its bound",
        ),
    ] {
        receiver(&server, response).await;
        let output = start(&server, root.path()).await;
        assert_eq!(output.status.code(), Some(3));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "operational-failure");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "coordinator.command.service-unavailable"
        );
        assert_eq!(report["diagnostics"][0]["message"], message);
        server.verify().await;
        server.reset().await;
    }
}

#[tokio::test]
async fn a_relative_token_file_is_read_from_the_current_directory() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("token"), TOKEN).unwrap();
    fs::write(root.path().join("key"), KEY).unwrap();
    fs::write(
        root.path().join("input.json"),
        r#"{"applicationId":"synthetic"}"#,
    )
    .unwrap();
    receiver(
        &server,
        ResponseTemplate::new(503).set_body_json(json!({
            "detail":"the requested operation could not complete"
        })),
    )
    .await;
    let origin = server.uri();
    let directory = root.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .current_dir(directory)
            .args(["--format", "json", "start", "--workflow", "follow-up"])
            .args([
                "--workflow-revision",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ])
            .args(["--input", "input.json", "--key-file", "key"])
            .args(["--url", &origin, "--token-file", "token"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"], "coordinator.command.service-unavailable",
        "{report}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    server.verify().await;
}

#[test]
fn a_service_command_names_the_service_argument_it_still_needs() {
    let root = tempfile::tempdir().unwrap();
    let token = root.path().join("token");
    fs::write(&token, "not-a-token").unwrap();
    let run = "00000000-0000-4000-8000-000000000001";
    for (arguments, code, wanted) in [
        (
            vec!["status", "--run", run],
            "service-required",
            "Add --url",
        ),
        (
            vec!["status", "--run", run, "--url", "https://127.0.0.1/path"],
            "service-invalid",
            "origin",
        ),
        (
            vec!["status", "--run", run, "--url", "https://127.0.0.1"],
            "token-file-required",
            "Add --token-file",
        ),
        (
            vec![
                "status",
                "--run",
                run,
                "--url",
                "https://127.0.0.1",
                "--token-file",
                token.to_str().unwrap(),
            ],
            "token-invalid",
            "compact access token",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(["--format", "json"])
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["code"], format!("coordinator.command.{code}"));
        let action = finding["suggestedAction"].as_str().unwrap();
        assert!(action.contains(wanted), "{code}: {action}");
        assert!(
            !action.contains("Inspect the command inputs"),
            "{code}: {action}"
        );
        assert!(!format!("{report}").contains("not-a-token"));
    }
}

#[tokio::test]
async fn an_accepted_admission_prints_readable_fields_by_default() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    receiver(
        &server,
        ResponseTemplate::new(202).set_body_json(json!({
            "run": "0190f3a2-7b8c-7d4e-9f00-000000000001",
            "status": "waiting"
        })),
    )
    .await;
    let output = start_as(&server, root.path(), &[]).await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.trim_start().starts_with('{'), "{text}");
    assert!(text.lines().any(|line| line == "status: waiting"), "{text}");
    assert!(!text.contains(TOKEN));
    server.verify().await;
}
