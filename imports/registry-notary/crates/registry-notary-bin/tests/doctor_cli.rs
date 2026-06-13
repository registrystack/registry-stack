// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for doctor output contracts.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use tempfile::TempDir;

const TEST_API_HASH: &str =
    "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b";
const TEST_API_COMMITMENT: &str =
    "sha256:a185ffbb208d5b11fc66f149bd880882de96256b0dfe5357a78b78ed13c17fed";
const TEST_AUDIT_SECRET: &str = "doctor-audit-secret-32-bytes-minimum";
const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_SOURCE_TOKEN: &str = "doctor-source-token";

#[derive(Default)]
struct TestConfigOptions<'a> {
    openapi_requires_auth: Option<bool>,
    source_base_url: Option<&'a str>,
    source_allows_private_network: bool,
    openfn_batch_without_expected_sidecar: bool,
    config_trust: bool,
    multi_instance: bool,
    durable_audit: Option<bool>,
}

fn write_config(tmp: &TempDir) -> PathBuf {
    write_config_with_options(tmp, TestConfigOptions::default())
}

fn write_config_with_options(tmp: &TempDir, options: TestConfigOptions<'_>) -> PathBuf {
    let path = tmp.path().join("notary.yaml");
    let openapi_requires_auth = options
        .openapi_requires_auth
        .map(|value| format!("  openapi_requires_auth: {value}\n"))
        .unwrap_or_default();
    let admin_listener = if options.config_trust {
        "  admin_listener:\n    mode: dedicated\n    bind: 127.0.0.1:1\n"
    } else {
        ""
    };
    let config_trust = if options.config_trust {
        format!(
            r#"config_trust:
  antirollback_state_path: {}
  local_approval_state_path: {}
"#,
            tmp.path().join("antirollback.json").display(),
            tmp.path().join("local-approvals.json").display()
        )
    } else {
        String::new()
    };
    let deployment = if options.multi_instance {
        "deployment:\n  multi_instance: true\n"
    } else {
        ""
    };
    let durable_audit = options.durable_audit.unwrap_or(options.config_trust);
    let audit = if durable_audit {
        format!(
            r#"audit:
  sink: file
  path: {}
  hash_secret_env: TEST_DOCTOR_JSON_AUDIT_SECRET
"#,
            tmp.path().join("audit.jsonl").display()
        )
    } else {
        r#"audit:
  sink: stdout
  hash_secret_env: TEST_DOCTOR_JSON_AUDIT_SECRET
"#
        .to_string()
    };
    let source_base_url = options.source_base_url.or(options
        .openfn_batch_without_expected_sidecar
        .then_some("https://openfn.example.test"));
    let source_private_network = if options.source_allows_private_network {
        "      allow_insecure_private_network: true\n"
    } else {
        ""
    };
    let openfn_bulk_mode = if options.openfn_batch_without_expected_sidecar {
        "      bulk_mode: openfn_sidecar_batch\n      retry_on_5xx: false\n"
    } else {
        ""
    };
    let source_connections = source_base_url
        .map(|base_url| {
            format!(
                r#"  source_connections:
    profile_gate_test:
      base_url: "{base_url}"
{source_private_network}{openfn_bulk_mode}
      token_env: TEST_DOCTOR_JSON_SOURCE_TOKEN
"#
            )
        })
        .unwrap_or_default();
    std::fs::write(
        &path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0
{openapi_requires_auth}{admin_listener}{config_trust}auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_JSON_API_HASH
        commitment: {TEST_API_COMMITMENT}
      scopes: [registry_notary:credential_issue]
{deployment}{audit}evidence:
  enabled: true
  service_id: doctor-json-test
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_DOCTOR_JSON_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
{source_connections}
"#
        ),
    )
    .expect("config writes");
    path
}

fn write_env_file(tmp: &TempDir) -> PathBuf {
    let path = tmp.path().join(".env");
    std::fs::write(
        &path,
        format!(
            "\
TEST_DOCTOR_JSON_API_HASH={TEST_API_HASH}
TEST_DOCTOR_JSON_AUDIT_SECRET={TEST_AUDIT_SECRET}
TEST_DOCTOR_JSON_ISSUER_JWK='{TEST_ISSUER_JWK}'
TEST_DOCTOR_JSON_SOURCE_TOKEN={TEST_SOURCE_TOKEN}
"
        ),
    )
    .expect("env file writes");
    path
}

fn write_invalid_config(tmp: &TempDir) -> PathBuf {
    let path = tmp.path().join("invalid.yaml");
    std::fs::write(&path, "auth:\n  mode: definitely-not-valid\n").expect("config writes");
    path
}

fn doctor_command(config_path: &Path, env_file: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command.arg("--config").arg(config_path);
    if let Some(env_file) = env_file {
        command.arg("--env-file").arg(env_file);
    }
    command.arg("doctor");
    command
}

fn diagnostic_with_code<'a>(report: &'a Value, code: &str) -> Option<&'a Value> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
}

#[test]
fn doctor_defaults_to_text_output() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("OK    config file read"));
    assert!(
        serde_json::from_str::<Value>(&stdout).is_err(),
        "default doctor output should remain text"
    );
}

#[test]
fn doctor_json_reports_undeclared_deployment_profile() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(
        report["deployment_profile"],
        json!({ "value": null, "source": "undeclared" })
    );
    let diagnostic = diagnostic_with_code(&report, "deployment.profile_undeclared")
        .expect("undeclared profile finding");
    assert_eq!(diagnostic["severity"], "finding_warn");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_profile_override_suppresses_undeclared_finding() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "hosted_lab", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(
        report["deployment_profile"],
        json!({ "value": "hosted_lab", "source": "override" })
    );
    assert!(
        diagnostic_with_code(&report, "deployment.profile_undeclared").is_none(),
        "override must suppress undeclared profile finding"
    );
}

#[test]
fn doctor_json_hosted_lab_unsigned_config_warns_and_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "hosted_lab", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "hosted_lab unsigned config should warn only\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(
        report["deployment_profile"],
        json!({ "value": "hosted_lab", "source": "override" })
    );
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["result"], "passed");
    let diagnostic =
        diagnostic_with_code(&report, "notary.config.unsigned").expect("unsigned config finding");
    assert_eq!(diagnostic["severity"], "finding_warn");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_evidence_grade_unsigned_config_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "evidence_grade", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "doctor should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(
        report["deployment_profile"],
        json!({ "value": "evidence_grade", "source": "override" })
    );
    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    let diagnostic =
        diagnostic_with_code(&report, "notary.config.unsigned").expect("unsigned config finding");
    assert_eq!(diagnostic["severity"], "startup_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_production_public_openapi_reports_error_but_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            openapi_requires_auth: Some(false),
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "production", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "production public OpenAPI should be a finding_error, not startup_fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["result"], "passed");
    assert!(
        diagnostic_with_code(&report, "notary.config.unsigned").is_none(),
        "config_trust should isolate the OpenAPI finding"
    );
    let diagnostic =
        diagnostic_with_code(&report, "notary.openapi.public").expect("OpenAPI public finding");
    assert_eq!(diagnostic["severity"], "finding_error");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_evidence_grade_public_openapi_reports_error_but_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            openapi_requires_auth: Some(false),
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "evidence_grade", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "evidence_grade public OpenAPI should be a finding_error, not startup_fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["result"], "passed");
    assert!(
        diagnostic_with_code(&report, "notary.config.unsigned").is_none(),
        "config_trust should isolate the OpenAPI finding"
    );
    let diagnostic =
        diagnostic_with_code(&report, "notary.openapi.public").expect("OpenAPI public finding");
    assert_eq!(diagnostic["severity"], "finding_error");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_local_public_openapi_has_no_profile_finding() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            openapi_requires_auth: Some(false),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "local", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "local public OpenAPI should not emit a profile finding\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert!(
        diagnostic_with_code(&report, "notary.openapi.public").is_none(),
        "local profile must allow public OpenAPI"
    );
}

#[test]
fn doctor_json_production_insecure_source_url_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            source_base_url: Some("http://upstream.example.test"),
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "production", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "production HTTP source URL should fail readiness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(false));
    let diagnostic = diagnostic_with_code(&report, "notary.source.insecure_url")
        .expect("insecure source URL finding");
    assert_eq!(diagnostic["severity"], "readiness_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_production_in_memory_replay_high_risk_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            config_trust: true,
            multi_instance: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "production", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "production high-risk in-memory replay should fail readiness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    let diagnostic = diagnostic_with_code(&report, "notary.replay.in_memory_high_risk")
        .expect("high-risk replay finding");
    assert_eq!(diagnostic["severity"], "readiness_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_production_missing_durable_audit_sink_fails_startup() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            config_trust: true,
            durable_audit: Some(false),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "production", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "production without durable audit sink should fail startup\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    let diagnostic =
        diagnostic_with_code(&report, "notary.audit.sink_missing").expect("audit sink finding");
    assert_eq!(diagnostic["severity"], "startup_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_production_private_network_source_escape_reports_error() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            source_base_url: Some("http://10.0.0.1:9000"),
            source_allows_private_network: true,
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "production", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "private-network source escape should be a finding_error under production\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["result"], "passed");
    let diagnostic = diagnostic_with_code(&report, "notary.source.private_network_escape")
        .expect("private-network source escape finding");
    assert_eq!(diagnostic["severity"], "finding_error");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_evidence_grade_openfn_without_expected_sidecar_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            openfn_batch_without_expected_sidecar: true,
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "evidence_grade", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "evidence_grade OpenFn batch without expected sidecar should fail readiness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    let diagnostic = diagnostic_with_code(&report, "notary.sidecar.expected_sidecar_missing")
        .expect("missing expected sidecar finding");
    assert_eq!(diagnostic["severity"], "readiness_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_evidence_grade_insecure_source_url_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            source_base_url: Some("http://upstream.example.test"),
            config_trust: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "evidence_grade", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "evidence_grade HTTP source URL should fail startup\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    let diagnostic = diagnostic_with_code(&report, "notary.source.insecure_url")
        .expect("insecure source URL finding");
    assert_eq!(diagnostic["severity"], "startup_fail");
    assert_eq!(diagnostic["status"], "active");
}

#[test]
fn doctor_json_local_insecure_source_url_has_no_profile_finding() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            source_base_url: Some("http://upstream.example.test"),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--profile", "local", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "local HTTP source URL should not emit a profile finding\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");

    assert!(
        diagnostic_with_code(&report, "notary.source.insecure_url").is_none(),
        "local profile must allow HTTP source URLs"
    );
}

#[test]
fn doctor_json_reports_success_as_single_redacted_document() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--show-expanded-config", "--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits one JSON document");

    assert_eq!(report["schema"], "registry.validation.report.v1");
    assert_eq!(report["product"], "registry-notary");
    assert_eq!(report["command"], "doctor");
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["result"], "passed");
    assert!(report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .any(|check| check["code"] == "ok"
            && check["status"] == "passed"
            && check["message"] == "config file read"));
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .all(|diagnostic| diagnostic["severity"].is_string()
            && diagnostic["status"].is_string()
            && diagnostic["code"].is_string()
            && diagnostic["message"].is_string()));
    assert!(report["expanded_config"].is_object());
    assert_eq!(
        report["expanded_config"]["evidence"]["signing_keys"]["issuer"]["private_jwk_env"],
        json!("[redacted]")
    );
    assert!(!stdout.contains(TEST_ISSUER_JWK));
    assert!(!stdout.contains(TEST_AUDIT_SECRET));
    assert!(!stdout.contains(TEST_API_HASH));
    assert!(!stdout.contains(TEST_API_COMMITMENT));
}

#[test]
fn doctor_json_reports_config_parse_failure_without_text_preamble() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_invalid_config(&tmp);

    let output = doctor_command(&config, None)
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "doctor should fail for invalid config"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("failure emits JSON");

    assert_eq!(report["schema"], "registry.validation.report.v1");
    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["result"], "failed");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .any(|diagnostic| diagnostic["status"] == "failed"
            && diagnostic["message"]
                .as_str()
                .expect("message")
                .contains("config YAML parse or validation failed")
            && diagnostic["action"] == "fix the YAML syntax and field names"));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is utf8"),
        ""
    );
}
