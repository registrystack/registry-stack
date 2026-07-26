// SPDX-License-Identifier: Apache-2.0
//! Child-process regressions for the default Relay startup stderr boundary.

use std::process::{Command, Output};

use registry_relay::process_startup::ProcessStartupCode;

#[test]
fn missing_local_config_emits_only_the_specific_source_code() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_MISSING_CONFIG_PATH.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.config_source_unavailable",
        &[
            "COUNTRY_MISSING_CONFIG_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn malformed_local_config_emits_only_static_product_diagnostics() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let private_dir = tmp
        .path()
        .join("COUNTRY_PRIVATE")
        .join("redaction-user@example.test");
    std::fs::create_dir_all(&private_dir).expect("private dir creates");
    let config_path = private_dir.join("COUNTRY_CONFIG_PATH.yaml");
    let parser_sentinel = "COUNTRY_PARSER_ERROR COUNTRY_SECRET_VALUE";
    std::fs::write(
        &config_path,
        format!("deployment:\n  profile: local\n{parser_sentinel}\n\t- invalid"),
    )
    .expect("malformed config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.config_document_invalid",
        &[
            parser_sentinel,
            "COUNTRY_PRIVATE",
            "redaction-user@example.test",
            "COUNTRY_CONFIG_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("relay.startup.runtime_initialization_failed")
            .count(),
        0,
        "a classified loader failure must not also emit the generic startup code: {stderr}"
    );
}

#[test]
fn config_validation_does_not_repeat_environment_or_authored_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_VALIDATION_PATH.yaml");
    let env_sentinel = "COUNTRY_SECRET_ENV_REFERENCE";
    std::fs::write(
        &config_path,
        format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: COUNTRY_AUTHORED_VALUE
  base_url: https://country-user@example.test/private
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys:
    - id: country_operator
      fingerprint:
        provider: env
        name: {env_sentinel}
datasets: []
audit:
  sink: stdout
"#
        ),
    )
    .expect("invalid config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env_remove(env_sentinel)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.config_validation_rejected",
        &[
            env_sentinel,
            "COUNTRY_AUTHORED_VALUE",
            "country-user@example.test",
            "country_operator",
            "COUNTRY_VALIDATION_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn undeclared_profile_emits_only_safe_config_validation_code() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_UNDECLARED_PROFILE_PATH.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
"#,
    )
    .expect("undeclared profile config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.config_validation_rejected",
        &[
            "deployment.profile_undeclared",
            "set deployment.profile: local for development",
            "production/evidence_grade",
            "COUNTRY_UNDECLARED_PROFILE_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn runtime_protected_dependency_failure_does_not_repeat_secret_or_inner_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_RUNTIME_PATH.yaml");
    let secret_env = "COUNTRY_RUNTIME_AUDIT_SECRET";
    std::fs::write(
        &config_path,
        format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  hash_secret_env: {secret_env}
"#
        ),
    )
    .expect("runtime config writes");
    let secret_sentinel = "COUNTRY_RUNTIME_SECRET_VALUE";

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env(secret_env, secret_sentinel)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.config_validation_rejected",
        &[
            secret_env,
            secret_sentinel,
            "COUNTRY_RUNTIME_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn occupied_listener_emits_only_the_specific_listener_code() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("held listener binds");
    let occupied_addr = listener.local_addr().expect("listener exposes address");
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_LISTENER_PATH.yaml");
    let secret_env = "COUNTRY_LISTENER_AUDIT_SECRET";
    std::fs::write(
        &config_path,
        format!(
            r#"
deployment:
  profile: local
server:
  bind: {occupied_addr}
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  hash_secret_env: {secret_env}
"#
        ),
    )
    .expect("listener config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env(secret_env, "registry-relay-listener-test-secret-32-bytes")
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.listener_unavailable",
        &[
            secret_env,
            "COUNTRY_LISTENER_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn unknown_process_error_does_not_render_the_inner_cli_error() {
    let cli_sentinel = "--COUNTRY_UNKNOWN_ARGUMENT_redaction-user@example.test";
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .arg(cli_sentinel)
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        "relay.startup.runtime_initialization_failed",
        &[cli_sentinel, "redaction-user@example.test"],
    );
}

fn assert_failed_output_is_safe(output: &Output, expected_code: &str, forbidden_values: &[&str]) {
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected_code),
        "stderr lacks expected stable code {expected_code}: {stderr}"
    );
    assert_eq!(
        stderr.matches(expected_code).count(),
        1,
        "stderr must emit the expected stable code exactly once: {stderr}"
    );
    if expected_code != ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED.as_str() {
        assert_eq!(
            stderr
                .matches(ProcessStartupCode::RUNTIME_INITIALIZATION_FAILED.as_str())
                .count(),
            0,
            "a specifically classified failure must not also emit the generic startup code: {stderr}"
        );
    }
    let emitted_codes = ProcessStartupCode::ALL
        .iter()
        .map(|code| code.as_str())
        .filter(|code| stderr.contains(code))
        .collect::<Vec<_>>();
    assert_eq!(
        emitted_codes,
        vec![expected_code],
        "stderr must contain exactly one product startup code: {stderr}"
    );
    for forbidden in forbidden_values {
        assert!(
            !stdout.contains(forbidden),
            "stdout leaked forbidden value {forbidden:?}: {stdout}"
        );
        assert!(
            !stderr.contains(forbidden),
            "stderr leaked forbidden value {forbidden:?}: {stderr}"
        );
    }
    for generic_forbidden in ["sha256:", "COUNTRY_PARSER_ERROR", "/Users/"] {
        assert!(
            !stderr.contains(generic_forbidden),
            "stderr leaked forbidden value {generic_forbidden:?}: {stderr}"
        );
    }
}
