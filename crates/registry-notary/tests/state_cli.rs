// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for the PostgreSQL state command contract.

use std::process::Command;

#[test]
fn state_doctor_configuration_failure_is_stable_and_value_free() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let config_path = temporary.path().join("notary.yaml");
    let sentinel = "SENTINEL_INVALID_STATE_DOCTOR_CONFIGURATION";
    std::fs::write(&config_path, format!("auth:\n  mode: {sentinel}\n"))
        .expect("invalid config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-notary"))
        .arg("--config")
        .arg(&config_path)
        .args(["state", "doctor"])
        .output()
        .expect("state doctor runs");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        stderr,
        "ERROR registry-notary PostgreSQL state is not ready: configuration_invalid\n"
    );
    assert!(!stderr.contains(sentinel));
    assert!(!stderr.contains(&config_path.display().to_string()));
}
