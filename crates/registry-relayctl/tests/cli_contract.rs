// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(std::path::PathBuf);

impl TemporaryDirectory {
    fn create() -> Self {
        let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock follows the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "registry-relayctl-integration-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("temporary project root creates");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn relayctl(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_relayctl"))
        .args(arguments)
        .output()
        .expect("relayctl starts")
}

fn generic_project() -> (TemporaryDirectory, std::path::PathBuf) {
    let temporary = TemporaryDirectory::create();
    let project = temporary.path().join("project");
    let project_text = project.to_str().expect("project path is UTF-8");
    let initialized = relayctl(&["init", project_text]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    std::fs::remove_file(project.join("runtime.yaml"))
        .expect("runtime is optional for an authoring check");
    std::fs::write(
        project.join("fixture.sql"),
        "-- ROW-VALUE-CANARY REQUEST-VALUE-CANARY PRINCIPAL-VALUE-CANARY\n",
    )
    .expect("generic value canaries write");
    (temporary, project)
}

#[test]
fn the_adopter_workflow_is_exposed_by_one_binary() {
    for command in [
        "init", "inspect", "check", "generate", "test", "diff", "package",
    ] {
        let output = relayctl(&[command, "--help"]);
        assert!(output.status.success(), "{command} help failed");
        assert!(output.stderr.is_empty(), "{command} help used stderr");
    }
}

#[test]
fn schema_inspection_offers_no_row_or_value_sampling_surface() {
    let output = relayctl(&["inspect", "--help"]);
    assert!(output.status.success());

    let help = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(help.contains("without reading row values"));
    for forbidden in ["--sample", "--rows", "--values", "--limit"] {
        assert!(!help.contains(forbidden), "unexpected option {forbidden}");
    }
}

#[test]
fn package_refuses_an_implicit_destination_without_echoing_project_contents() {
    let output = relayctl(&["package", "project"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let error = String::from_utf8(output.stderr).expect("error is UTF-8");
    assert!(error.contains("--output"));
    assert!(!error.contains("selector"));
    assert!(!error.contains("record"));
}

#[test]
fn adopter_commands_link_the_shared_library_and_never_spawn_relay() {
    let library = include_str!("../src/lib.rs");
    let shared = include_str!("../src/shared.rs");
    let binary = include_str!("../src/main.rs");
    let production = format!("{library}\n{shared}\n{binary}");

    assert!(shared.contains("registry_relay_v2::tooling"));
    for forbidden in ["std::process::Command", "Command::new", "rusqlite"] {
        assert!(
            !production.contains(forbidden),
            "tooling boundary contains {forbidden}"
        );
    }
}

#[test]
fn json_explanation_is_one_value_free_document_and_plain_check_omits_it() {
    let (_temporary, project) = generic_project();
    assert!(!project.join("fixture.sqlite").exists());
    assert!(!project.join("generated").exists());
    let project_text = project.to_str().expect("project path is UTF-8");

    let explained = relayctl(&["--json", "check", project_text, "--explain"]);
    assert!(
        explained.status.success(),
        "{}",
        String::from_utf8_lossy(&explained.stderr)
    );
    assert!(explained.stderr.is_empty());
    let explanation: serde_json::Value =
        serde_json::from_slice(&explained.stdout).expect("one valid JSON document");
    assert_eq!(explanation["status"], "success");
    assert_eq!(
        explanation["details"]["operation_explanation"]["kind"],
        "OperationExplanation"
    );
    let rendered = String::from_utf8(explained.stdout).expect("report is UTF-8");
    for canary in [
        "ROW-VALUE-CANARY",
        "REQUEST-VALUE-CANARY",
        "PRINCIPAL-VALUE-CANARY",
    ] {
        assert!(!rendered.contains(canary), "report leaked fixture value");
    }
    assert!(rendered.ends_with('\n'));
    assert!(!rendered.ends_with("\n\n"));

    let plain = relayctl(&["check", project_text, "--json"]);
    assert!(plain.status.success());
    let plain: serde_json::Value =
        serde_json::from_slice(&plain.stdout).expect("plain check is valid JSON");
    assert!(plain["details"].get("operation_explanation").is_none());

    assert!(!project.join("fixture.sqlite").exists());
    assert!(!project.join("generated").exists());
}
