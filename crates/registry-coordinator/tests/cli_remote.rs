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
    let token = root.join("token");
    let key = root.join("key");
    let input = root.join("input.json");
    fs::write(&token, TOKEN).unwrap();
    fs::write(&key, KEY).unwrap();
    fs::write(&input, r#"{"applicationId":"synthetic"}"#).unwrap();
    let origin = server.uri();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(["--format", "json", "--url", &origin, "--token-file"])
            .arg(token)
            .args(["start", "--flow", "follow-up", "--input"])
            .arg(input)
            .arg("--key-file")
            .arg(key)
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
            "flow":"follow-up", "input":{"applicationId":"synthetic"}
        })))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn remote_admission_reports_outages_separately_without_repeating_the_request() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let guidance =
        "Inspect the original run and use its same-command recovery; never substitute a fresh key.";
    for (status, exit, classification, code) in [
        (
            503,
            3,
            "operational-failure",
            "coordinator.command.service-unavailable",
        ),
        (
            500,
            3,
            "operational-failure",
            "coordinator.command.service-unavailable",
        ),
        (
            502,
            3,
            "operational-failure",
            "coordinator.command.service-unavailable",
        ),
        (
            504,
            3,
            "operational-failure",
            "coordinator.command.service-unavailable",
        ),
        (
            401,
            1,
            "domain-refusal",
            "coordinator.command.service-refused",
        ),
        (
            403,
            1,
            "domain-refusal",
            "coordinator.command.service-refused",
        ),
        (
            409,
            1,
            "domain-refusal",
            "coordinator.command.service-refused",
        ),
    ] {
        receiver(
            &server,
            ResponseTemplate::new(status).set_body_json(json!({
                "message":"the requested operation could not complete",
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
        assert_eq!(report["diagnostics"][0]["code"], code);
        assert_eq!(report["diagnostics"][0]["suggestedAction"], guidance);
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
            ResponseTemplate::new(503).set_body_json(json!({"message":"x".repeat(1_048_576)})),
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
