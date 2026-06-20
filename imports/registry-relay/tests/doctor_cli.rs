// SPDX-License-Identifier: Apache-2.0
//! CLI coverage for the machine-readable operator doctor command.

use std::process::Command;

use registry_config_report::{CONFIG_EXPLANATION_SCHEMA_V1, PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1};
use serde_json::Value;
use tempfile::TempDir;

fn yaml_path(tmp: &TempDir) -> String {
    tmp.path().to_string_lossy().replace('\\', "/")
}

fn write_minimal_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("relay.yaml");
    std::fs::write(
        &path,
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
  format: jsonl
"#,
    )
    .expect("config writes");
    path
}

fn write_minimal_config_with_deployment_profile(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("relay-profile.yaml");
    std::fs::write(
        &path,
        r#"
instance:
  id: registry-relay-profile-test
deployment:
  profile: evidence_grade
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
  format: jsonl
"#,
    )
    .expect("config writes");
    path
}

fn write_profile_config(
    tmp: &TempDir,
    profile: &str,
    openapi_requires_auth: bool,
) -> std::path::PathBuf {
    let path = tmp.path().join(format!("relay-{profile}.yaml"));
    std::fs::write(
        &path,
        format!(
            r#"
instance:
  id: registry-relay-profile-test
deployment:
  profile: {profile}
config_trust:
  antirollback_state_path: {state}/antirollback.json
  local_approval_state_path: {state}/local-approvals.json
server:
  bind: 127.0.0.1:0
  openapi_requires_auth: {openapi_requires_auth}
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
  format: jsonl
"#,
            state = yaml_path(tmp)
        ),
    )
    .expect("config writes");
    path
}

fn write_public_admin_profile_config(tmp: &TempDir, profile: &str) -> std::path::PathBuf {
    let path = tmp
        .path()
        .join(format!("relay-{profile}-public-admin.yaml"));
    std::fs::write(
        &path,
        format!(
            r#"
instance:
  id: registry-relay-profile-test
deployment:
  profile: {profile}
config_trust:
  antirollback_state_path: {state}/antirollback.json
  local_approval_state_path: {state}/local-approvals.json
server:
  bind: 127.0.0.1:0
  admin_bind: 0.0.0.0:0
  openapi_requires_auth: true
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
  format: jsonl
"#,
            state = yaml_path(tmp)
        ),
    )
    .expect("config writes");
    path
}

fn write_missing_secret_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("relay-missing-secret.yaml");
    std::fs::write(
        &path,
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
  api_keys:
    - id: operator_reader
      fingerprint:
        provider: env
        name: REGISTRY_RELAY_DOCTOR_TEST_MISSING_HASH
        commitment: sha256:0000000000000000000000000000000000000000000000000000000000000000
      scopes:
        - registry_relay:ops_read
datasets: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("config writes");
    path
}

fn parse_stdout_json(output: &[u8]) -> Value {
    serde_json::from_slice(output).unwrap_or_else(|err| {
        panic!(
            "stdout must be one JSON document: {err}\n{}",
            String::from_utf8_lossy(output)
        )
    })
}

fn assert_schema_valid(schema: &str, report: &Value) {
    let schema: Value = serde_json::from_str(schema).expect("schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
    if let Err(errors) = compiled.validate(report) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("report should validate against schema: {messages:?}\n{report:#}");
    };
}

fn assert_diagnostic_report(report: &Value) {
    assert_schema_valid(PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, report);
    assert_eq!(
        report["schema_version"],
        "registry.config.diagnostic_report.v1"
    );
    assert_eq!(report["product"], "registry-relay");
    assert_eq!(report["config_schema_version"], "registry.relay.config.v1");
}

fn assert_config_explanation(report: &Value) {
    assert_schema_valid(CONFIG_EXPLANATION_SCHEMA_V1, report);
    assert_eq!(report["schema_version"], "registry.config.explanation.v1");
    assert_eq!(report["product"], "registry-relay");
    assert_eq!(report["config_schema_version"], "registry.relay.config.v1");
}

fn diagnostic_with_code<'a>(report: &'a Value, code: &str) -> Option<&'a Value> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
}

#[test]
fn doctor_json_reports_success_and_redacts_env_file_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_minimal_config(&tmp);
    let env_path = tmp.path().join("relay.env");
    std::fs::write(
        &env_path,
        "REGISTRY_RELAY_DOCTOR_TEST_SECRET=super-secret-do-not-print\n",
    )
    .expect("env writes");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--env-file",
            env_path.to_str().expect("utf-8 path"),
            "--format",
            "json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("super-secret-do-not-print"),
        "doctor output leaked env value: {stdout}"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "warning");
    assert!(diagnostic_with_code(&report, "relay.config.loaded").is_some());
    assert!(diagnostic_with_code(&report, "relay.entity_registry.verified").is_some());
    let diagnostic = diagnostic_with_code(&report, "deployment.profile_undeclared")
        .expect("undeclared profile diagnostic");
    assert_eq!(diagnostic["severity"], "warning");
}

#[test]
fn doctor_json_reports_config_failure_with_nonzero_exit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_missing_secret_config(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .env_remove("REGISTRY_RELAY_DOCTOR_TEST_MISSING_HASH")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        !output.status.success(),
        "doctor should fail when config validation fails"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "error");
    assert!(diagnostic_with_code(&report, "config.missing_secret").is_some());
}

#[test]
fn doctor_json_accepts_profile_override_without_undeclared_finding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_minimal_config(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--profile",
            "local",
            "--format",
            "json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "ok");
    assert!(diagnostic_with_code(&report, "deployment.profile_undeclared").is_none());
}

#[test]
fn doctor_json_fails_evidence_grade_unsigned_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_minimal_config_with_deployment_profile(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        !output.status.success(),
        "evidence-grade unsigned config should fail doctor"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "error");
    let diagnostic =
        diagnostic_with_code(&report, "relay.config.unsigned").expect("unsigned config diagnostic");
    assert_eq!(diagnostic["severity"], "error");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message string")
        .contains("startup_fail"));
}

#[test]
fn doctor_json_reports_public_openapi_profile_gates() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let production_config = write_profile_config(&tmp, "production", false);
    let production = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            production_config.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");
    assert!(
        production.status.success(),
        "production finding_error should not force nonzero"
    );
    let report = parse_stdout_json(&production.stdout);
    assert_diagnostic_report(&report);
    let diagnostic =
        diagnostic_with_code(&report, "relay.openapi.public").expect("public OpenAPI diagnostic");
    assert_eq!(diagnostic["severity"], "error");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message string")
        .contains("finding_error"));

    let local_config = write_profile_config(&tmp, "local", false);
    let local = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            local_config.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");
    assert!(
        local.status.success(),
        "local public OpenAPI config should pass doctor"
    );
    let report = parse_stdout_json(&local.stdout);
    assert_diagnostic_report(&report);
    assert!(diagnostic_with_code(&report, "relay.openapi.public").is_none());
}

#[test]
fn doctor_json_reports_evidence_grade_public_openapi_catalog_severity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_profile_config(&tmp, "evidence_grade", false);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        !output.status.success(),
        "evidence-grade unsigned local config should fail doctor"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "error");
    let diagnostic =
        diagnostic_with_code(&report, "relay.openapi.public").expect("public OpenAPI diagnostic");
    assert_eq!(diagnostic["severity"], "error");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message string")
        .contains("finding_error"));
}

#[test]
fn doctor_json_reports_missing_ingress_rate_limit_evidence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_profile_config(&tmp, "production", true);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        output.status.success(),
        "production finding_error should not force nonzero"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    let diagnostic = diagnostic_with_code(&report, "relay.ingress.rate_limit_missing")
        .expect("ingress rate limit diagnostic");
    assert_eq!(diagnostic["severity"], "error");
}

#[test]
fn doctor_json_fails_active_readiness_fail_gate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_public_admin_profile_config(&tmp, "production");

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        !output.status.success(),
        "production readiness_fail gate should fail doctor"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "error");
    let diagnostic = diagnostic_with_code(&report, "relay.admin.public_exposure")
        .expect("public admin diagnostic");
    assert_eq!(diagnostic["severity"], "error");
    let message = diagnostic["message"].as_str().expect("message string");
    assert!(message.contains("active"));
    assert!(message.contains("readiness_fail"));
}

#[test]
fn doctor_json_reports_evidence_grade_missing_ingress_rate_limit_evidence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_profile_config(&tmp, "evidence_grade", true);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("doctor command runs");

    assert!(
        !output.status.success(),
        "evidence-grade unsigned local config should fail doctor"
    );
    let report = parse_stdout_json(&output.stdout);
    assert_diagnostic_report(&report);
    assert_eq!(report["status"], "error");
    let diagnostic = diagnostic_with_code(&report, "relay.ingress.rate_limit_missing")
        .expect("ingress rate limit diagnostic");
    assert_eq!(diagnostic["severity"], "error");
}

#[test]
fn explain_config_json_reports_redacted_resolved_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_minimal_config(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "explain-config",
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--format=json",
        ])
        .output()
        .expect("explain-config command runs");

    assert!(
        output.status.success(),
        "explain-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_json(&output.stdout);
    assert_config_explanation(&report);
    assert_eq!(report["resolved_config"]["catalog"]["title"], "Test");
    assert!(report["optional_sections_absent"]
        .as_array()
        .expect("optional sections array")
        .iter()
        .any(|section| section["path"] == "config_trust"));
    assert!(report["live_apply"]
        .as_array()
        .expect("live apply array")
        .iter()
        .any(
            |component| component["path"] == "datasets" && component["class"] == "restart_required"
        ));
    assert!(report["hashes"]["internal_config_hash"]
        .as_str()
        .expect("hash string")
        .starts_with("sha256:"));
}
