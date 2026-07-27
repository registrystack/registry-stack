// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for the PostgreSQL state command contract.

use std::process::Command;

fn assert_state_doctor_configuration_failure_is_value_free(
    output: std::process::Output,
    forbidden: &[&str],
) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        stderr,
        "ERROR notary.configuration.invalid: Registry Notary runtime configuration is invalid; next action: run registry-notary doctor, correct the reviewed configuration or binding, and retry activation\n"
    );
    for forbidden in forbidden {
        assert!(
            !stderr.contains(forbidden),
            "state doctor exposed forbidden value {forbidden:?}: {stderr}"
        );
    }
}

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

    assert_state_doctor_configuration_failure_is_value_free(
        output,
        &[sentinel, &config_path.display().to_string()],
    );
}

#[test]
fn state_doctor_missing_env_file_is_stable_and_value_free() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let config_path = temporary.path().join("notary.yaml");
    let env_path = temporary
        .path()
        .join("SENTINEL_STATE_DOCTOR_MISSING_ENV_FILE.env");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-notary"))
        .arg("--config")
        .arg(&config_path)
        .arg("--env-file")
        .arg(&env_path)
        .args(["state", "doctor"])
        .output()
        .expect("state doctor runs");

    assert_state_doctor_configuration_failure_is_value_free(
        output,
        &[
            "SENTINEL_STATE_DOCTOR_MISSING_ENV_FILE",
            &env_path.display().to_string(),
            &config_path.display().to_string(),
        ],
    );
}

#[test]
fn state_doctor_malformed_env_file_is_stable_and_value_free() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let config_path = temporary.path().join("notary.yaml");
    std::fs::write(&config_path, "auth:\n  mode: api_key\n").expect("config writes");
    let env_path = temporary.path().join("state-doctor.env");
    let parser_sentinel = "SENTINEL_STATE_DOCTOR_ENV_PARSER_TEXT";
    std::fs::write(&env_path, format!("{parser_sentinel} is not KEY=VALUE\n"))
        .expect("malformed env file writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-notary"))
        .arg("--config")
        .arg(&config_path)
        .arg("--env-file")
        .arg(&env_path)
        .args(["state", "doctor"])
        .output()
        .expect("state doctor runs");

    assert_state_doctor_configuration_failure_is_value_free(
        output,
        &[
            parser_sentinel,
            "not KEY=VALUE",
            &env_path.display().to_string(),
            &config_path.display().to_string(),
        ],
    );
}
