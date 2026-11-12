// SPDX-License-Identifier: Apache-2.0
use std::{path::PathBuf, process::ExitCode};

#[test]
fn payment_connections_can_be_checked_without_secrets_a_registry_project_or_network() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples/payment-collections/payments.example.yaml");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(
        [
            "adapterctl",
            "--format",
            "json",
            "payments",
            "check",
            path.to_str().unwrap(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(
        code,
        ExitCode::SUCCESS,
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["connectionCount"], 1);
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(stderr.is_empty());
    assert!(!String::from_utf8(stdout)
        .unwrap()
        .contains("PAYMENT_SIMULATOR_TOKEN"));
}

#[test]
fn payment_check_keeps_the_shared_reader_diagnostic_and_position() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("payments.yaml");
    std::fs::write(&file, "apiVersion: [\n").unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(
        [
            "adapterctl",
            "--format",
            "json",
            "payments",
            "check",
            file.to_str().unwrap(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, ExitCode::from(1));
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert!(report["diagnostics"][0]["code"]
        .as_str()
        .unwrap()
        .starts_with("yaml."));
    assert!(report["diagnostics"][0]["source"]["line"].is_number());
    assert!(stderr.is_empty());
}
