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
fn missing_environment_binding_emits_exact_value_free_terminal_guidance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_ENV_BINDING_PATH.yaml");
    let env_sentinel = "COUNTRY_MISSING_ENV_BINDING";
    std::fs::write(
        &config_path,
        format!("server:\n  bind: ${{{env_sentinel}:?COUNTRY_ENV_ERROR_SENTINEL}}\n"),
    )
    .expect("environment-bound config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .env_remove(env_sentinel)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_terminal_output_is_exact(
        &output,
        ProcessStartupCode::CONFIG_ENVIRONMENT_BINDING_REJECTED,
        &[
            env_sentinel,
            "COUNTRY_ENV_ERROR_SENTINEL",
            "COUNTRY_ENV_BINDING_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn deprecated_config_field_emits_exact_value_free_terminal_guidance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_DEPRECATED_FIELD_PATH.yaml");
    let value_sentinel = "COUNTRY_DEPRECATED_FIELD_VALUE";
    std::fs::write(
        &config_path,
        format!("auth:\n  oidc:\n    audience: {value_sentinel}\n"),
    )
    .expect("deprecated-field config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_terminal_output_is_exact(
        &output,
        ProcessStartupCode::CONFIG_DEPRECATED_FIELD_REJECTED,
        &[
            "auth.oidc.audience",
            "auth.oidc.audiences",
            value_sentinel,
            "COUNTRY_DEPRECATED_FIELD_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[test]
fn typed_config_document_failure_emits_exact_value_free_terminal_guidance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_TYPED_DOCUMENT_PATH.yaml");
    let field_sentinel = "COUNTRY_UNKNOWN_TYPED_FIELD";
    let value_sentinel = "COUNTRY_TYPED_FIELD_VALUE";
    std::fs::write(
        &config_path,
        format!("server:\n  bind: 127.0.0.1:0\n{field_sentinel}: {value_sentinel}\n"),
    )
    .expect("typed-invalid config writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_terminal_output_is_exact(
        &output,
        ProcessStartupCode::CONFIG_DOCUMENT_INVALID,
        &[
            field_sentinel,
            value_sentinel,
            "COUNTRY_TYPED_DOCUMENT_PATH",
            config_path.to_str().expect("config path is UTF-8"),
        ],
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
fn occupied_data_listener_emits_exact_value_free_terminal_guidance() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("held listener binds");
    let occupied_addr = listener.local_addr().expect("listener exposes address");
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_LISTENER_PATH.yaml");
    let secret_env = "COUNTRY_LISTENER_AUDIT_SECRET";
    let secret_value = "COUNTRY_LISTENER_SECRET_VALUE_32_BYTES";
    write_listener_config(&config_path, occupied_addr, None, secret_env);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .env(secret_env, secret_value)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_terminal_output_is_exact(
        &output,
        ProcessStartupCode::DATA_LISTENER_ADDRESS_IN_USE,
        &[
            secret_env,
            secret_value,
            "COUNTRY_LISTENER_PATH",
            config_path.to_str().expect("config path is UTF-8"),
            &occupied_addr.to_string(),
        ],
    );
}

#[test]
fn occupied_admin_listener_emits_exact_value_free_terminal_guidance() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("held listener binds");
    let occupied_addr = listener.local_addr().expect("listener exposes address");
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("COUNTRY_ADMIN_LISTENER_PATH.yaml");
    let secret_env = "COUNTRY_ADMIN_LISTENER_AUDIT_SECRET";
    let secret_value = "COUNTRY_ADMIN_LISTENER_SECRET_VALUE_32_BYTES";
    write_listener_config(
        &config_path,
        "127.0.0.1:0".parse().expect("data listener parses"),
        Some(occupied_addr),
        secret_env,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .env(secret_env, secret_value)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_terminal_output_is_exact(
        &output,
        ProcessStartupCode::ADMIN_LISTENER_ADDRESS_IN_USE,
        &[
            secret_env,
            secret_value,
            "COUNTRY_ADMIN_LISTENER_PATH",
            config_path.to_str().expect("config path is UTF-8"),
            &occupied_addr.to_string(),
        ],
    );
}

#[test]
fn occupied_admin_listener_default_logging_does_not_render_bindings() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("held listener binds");
    let occupied_addr = listener.local_addr().expect("listener exposes address");
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp
        .path()
        .join("COUNTRY_DEFAULT_LOG_ADMIN_LISTENER_PATH.yaml");
    let secret_env = "COUNTRY_DEFAULT_LOG_ADMIN_LISTENER_AUDIT_SECRET";
    let secret_value = "COUNTRY_DEFAULT_LOG_ADMIN_LISTENER_SECRET_32_BYTES";
    write_listener_config(
        &config_path,
        "127.0.0.1:0".parse().expect("data listener parses"),
        Some(occupied_addr),
        secret_env,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "info")
        .env(secret_env, secret_value)
        .args([
            "--config",
            config_path.to_str().expect("config path is UTF-8"),
        ])
        .output()
        .expect("Relay runs");

    assert_failed_output_is_safe(
        &output,
        ProcessStartupCode::ADMIN_LISTENER_ADDRESS_IN_USE.as_str(),
        &[
            secret_env,
            secret_value,
            "COUNTRY_DEFAULT_LOG_ADMIN_LISTENER_PATH",
            config_path.to_str().expect("config path is UTF-8"),
            &occupied_addr.to_string(),
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

fn write_listener_config(
    config_path: &std::path::Path,
    data_bind: std::net::SocketAddr,
    admin_bind: Option<std::net::SocketAddr>,
    secret_env: &str,
) {
    let admin_bind = admin_bind
        .map(|address| format!("  admin_bind: {address}\n"))
        .unwrap_or_default();
    std::fs::write(
        config_path,
        format!(
            r#"
deployment:
  profile: local
server:
  bind: {data_bind}
{admin_bind}catalog:
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
}

fn assert_failed_terminal_output_is_exact(
    output: &Output,
    expected_code: ProcessStartupCode,
    forbidden_values: &[&str],
) {
    assert!(!output.status.success());
    let definition = expected_code.definition();
    let expected = format!(
        "ERROR {}: {}; next action: {}\n",
        definition.code, definition.safe_meaning, definition.safe_remediation
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.is_empty(), "startup failure wrote stdout: {stdout}");
    assert_eq!(stderr, expected);
    assert_eq!(stderr.lines().count(), 1);
    for forbidden in forbidden_values {
        assert!(
            !stderr.contains(forbidden),
            "terminal failure exposed forbidden value {forbidden:?}: {stderr}"
        );
    }
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
