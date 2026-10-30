// SPDX-License-Identifier: Apache-2.0
use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/platform/examples/mcp-runtime/runtime.example.yaml")
        .canonicalize()
        .unwrap()
}
#[test]
fn offline_example_check_does_not_resolve_referenced_credentials() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-mcp"));
    command.env_clear();
    // Cargo supplies native linker paths on platforms with a shared FIPS module.
    for name in [
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let result = command
        .args([
            "--runtime-config",
            example().to_str().unwrap(),
            "check",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["errors"], 0);
    assert!(result.stderr.is_empty());
}
#[test]
fn unreadable_configuration_is_an_operational_failure_with_exit_three() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("missing.yaml");
    let result = Command::new(env!("CARGO_BIN_EXE_registry-mcp"))
        .args([
            "--runtime-config",
            path.to_str().unwrap(),
            "check",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "operational-failure");
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "platform.runtime-config.unavailable"));
    assert!(result.stderr.is_empty());
}
