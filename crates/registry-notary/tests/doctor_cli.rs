// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for doctor output contracts.

use std::path::{Path, PathBuf};
use std::process::Command;

use registry_config_report::{CONFIG_EXPLANATION_SCHEMA_V1, PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1};
use serde_json::{json, Value};
use tempfile::TempDir;

const TEST_API_HASH: &str =
    "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b";
const TEST_AUDIT_SECRET: &str = "doctor-audit-secret-32-bytes-minimum";
const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

#[derive(Default)]
struct TestConfigOptions<'a> {
    openapi_requires_auth: Option<bool>,
    config_trust: bool,
    omit_deployment_profile: bool,
    multi_instance: bool,
    audit_offhost_shipping: bool,
    durable_audit: Option<bool>,
    audit_ack_cursor_path: Option<&'a str>,
    unbound_credential_profile: bool,
    state_storage: Option<&'a str>,
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
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
  break_glass_override_path: {}
"#,
            tmp.path().join("trust-anchor.json").display(),
            tmp.path().join("bundle").display(),
            tmp.path().join("antirollback.json").display(),
            tmp.path().join("break-glass").display()
        )
    } else {
        String::new()
    };
    let mut evidence_lines = String::new();
    if options.audit_offhost_shipping {
        evidence_lines.push_str("    audit_offhost_shipping: true\n");
    }
    if let Some(cursor) = options.audit_ack_cursor_path {
        evidence_lines.push_str(&format!("    audit_ack_cursor_path: \"{cursor}\"\n"));
    }
    let deployment_evidence = if evidence_lines.is_empty() {
        String::new()
    } else {
        format!("  evidence:\n{evidence_lines}")
    };
    let deployment = if options.omit_deployment_profile {
        if options.multi_instance {
            format!("deployment:\n  multi_instance: true\n{deployment_evidence}")
        } else if !deployment_evidence.is_empty() {
            format!("deployment:\n{deployment_evidence}")
        } else {
            String::new()
        }
    } else if options.multi_instance {
        format!("deployment:\n  profile: local\n  multi_instance: true\n{deployment_evidence}")
    } else {
        format!("deployment:\n  profile: local\n{deployment_evidence}")
    };
    let durable_audit = options.durable_audit.unwrap_or(options.config_trust);
    let state = options
        .state_storage
        .map(|storage| format!("state:\n  storage: {storage}\n"))
        .unwrap_or_default();
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
    let credential_profiles = if options.unbound_credential_profile {
        r#"  credential_profiles:
    unbound_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer
      vct: https://issuer.example/credentials/unbound
      holder_binding:
        mode: none
      allowed_claims:
        - person-is-alive
"#
        .to_string()
    } else {
        String::new()
    };
    let mut claim_entries = String::new();
    if options.unbound_credential_profile {
        claim_entries.push_str(
            r#"    - id: person-is-alive
      title: Person is alive
      version: "1.0"
      subject_type: person
      evidence_mode:
        type: self_attested
      rule:
        type: cel
        expression: "true"
      formats:
        - application/vnd.registry-notary.claim-result+json
      credential_profiles:
        - unbound_sd_jwt
"#,
        );
    }
    let credential_profile_claims = if claim_entries.is_empty() {
        String::new()
    } else {
        format!("  claims:\n{claim_entries}")
    };
    std::fs::write(
        &path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0
{openapi_requires_auth}{admin_listener}{config_trust}auth:
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_JSON_API_HASH
      scopes: [registry_notary:credential_issue]
{deployment}{state}{audit}evidence:
  enabled: true
  service_id: doctor-json-test
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_DOCTOR_JSON_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
{credential_profiles}{credential_profile_claims}
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
REGISTRY_NOTARY_POSTGRES_URL='postgresql://registry_notary_runtime:test@127.0.0.1:1/registry_notary?sslmode=require'
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

fn write_config_with_claim_formats(tmp: &TempDir, claim_id: &str, formats: &[&str]) -> PathBuf {
    let path = write_config(tmp);
    let mut config: registry_notary_core::StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&std::fs::read_to_string(&path).expect("config reads"))
            .expect("config parses");
    let mut claim: registry_notary_core::ClaimDefinition = serde_norway::from_str(&format!(
        r#"
id: {claim_id}
title: Claim format validation
version: "1.0"
subject_type: person
evidence_mode:
  type: self_attested
rule:
  type: cel
  expression: "true"
"#,
    ))
    .expect("claim YAML parses");
    claim.formats = formats.iter().map(ToString::to_string).collect();
    config.evidence.claims = vec![claim];
    std::fs::write(
        &path,
        serde_norway::to_string(&config).expect("config serializes"),
    )
    .expect("config writes");
    path
}

fn write_config_with_empty_claim_formats(tmp: &TempDir) -> PathBuf {
    write_config_with_claim_formats(tmp, "empty-format", &[])
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

fn explain_command(config_path: &Path, env_file: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command.arg("--config").arg(config_path);
    if let Some(env_file) = env_file {
        command.arg("--env-file").arg(env_file);
    }
    command.arg("explain-config");
    command
}

fn diagnostic_with_code<'a>(report: &'a Value, code: &str) -> Option<&'a Value> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
}

fn assert_no_documentation_key(diagnostic: &Value) {
    assert!(
        diagnostic.get("documentation_key").is_none(),
        "documentation_key is reserved for documentation references, not deployment gate state"
    );
}

fn assert_active_finding(diagnostic: &Value) {
    let message = diagnostic["message"]
        .as_str()
        .expect("diagnostic message is a string");
    assert!(
        message.contains(" is active "),
        "active deployment gate state should be visible in the message: {message}"
    );
    assert_no_documentation_key(diagnostic);
}

fn assert_schema_valid(schema: &str, report: &Value) {
    let schema: Value = serde_json::from_str(schema).expect("schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
    if let Err(errors) = compiled.validate(report) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("report should validate against schema: {messages:?}");
    };
}

fn assert_product_diagnostic_report(report: &Value) {
    assert_schema_valid(PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1, report);
    assert_eq!(
        report["schema_version"],
        "registry.config.diagnostic_report.v1"
    );
    assert_eq!(report["product"], "registry-notary");
    assert_eq!(report["config_schema_version"], "registry.notary.config.v1");
}

fn assert_config_explanation(report: &Value) {
    assert_schema_valid(CONFIG_EXPLANATION_SCHEMA_V1, report);
    assert_eq!(report["schema_version"], "registry.config.explanation.v1");
    assert_eq!(report["product"], "registry-notary");
    assert_eq!(report["config_schema_version"], "registry.notary.config.v1");
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
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            omit_deployment_profile: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "undeclared profile should fail doctor\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "deployment.profile_undeclared")
        .expect("undeclared profile finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_no_documentation_key(diagnostic);
}

#[test]
fn doctor_json_profile_override_suppresses_undeclared_finding() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            omit_deployment_profile: true,
            ..TestConfigOptions::default()
        },
    );
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
    assert_product_diagnostic_report(&report);

    assert!(
        diagnostic_with_code(&report, "deployment.profile_undeclared").is_none(),
        "override must suppress undeclared profile finding"
    );
}

#[test]
fn doctor_json_hosted_lab_unsigned_config_warns_and_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            durable_audit: Some(true),
            ..TestConfigOptions::default()
        },
    );
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "warning");

    let diagnostic =
        diagnostic_with_code(&report, "notary.config.unsigned").expect("unsigned config finding");
    assert_eq!(diagnostic["severity"], "warning");
    assert_active_finding(diagnostic);
}

#[test]
fn doctor_json_evidence_grade_unsigned_config_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(&tmp, TestConfigOptions::default());
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic =
        diagnostic_with_code(&report, "notary.config.unsigned").expect("unsigned config finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    assert!(
        diagnostic_with_code(&report, "notary.config.unsigned").is_none(),
        "config_trust should isolate the OpenAPI finding"
    );
    let diagnostic =
        diagnostic_with_code(&report, "notary.openapi.public").expect("OpenAPI public finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
}

#[test]
fn doctor_json_evidence_grade_public_openapi_reports_error_with_unverified_shipping() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            openapi_requires_auth: Some(false),
            config_trust: true,
            audit_offhost_shipping: true,
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
        "evidence_grade doctor should fail closed when shipping cannot be bound to the live audit tail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    assert!(
        diagnostic_with_code(&report, "notary.config.unsigned").is_none(),
        "config_trust should isolate the OpenAPI finding"
    );
    let shipping = diagnostic_with_code(&report, "notary.audit.shipping_unverified")
        .expect("offline shipping remains unverified");
    assert_eq!(shipping["severity"], "error");
    assert_active_finding(shipping);
    let diagnostic =
        diagnostic_with_code(&report, "notary.openapi.public").expect("OpenAPI public finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
}

#[test]
fn doctor_json_production_signer_without_custody_approval_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            config_trust: true,
            unbound_credential_profile: true,
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
        "production signer without custody approval should fail readiness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.signer_custody.unapproved")
        .expect("signer custody finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);

    assert!(
        diagnostic_with_code(&report, "notary.openapi.public").is_none(),
        "local profile must allow public OpenAPI"
    );
}

#[test]
fn doctor_json_rejects_multi_instance_in_memory_state_before_profile_override() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            config_trust: true,
            multi_instance: true,
            state_storage: Some("in_memory"),
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
        "multi-instance in-memory correctness state should fail validation\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "failed").expect("invalid state diagnostic");
    assert_eq!(diagnostic["severity"], "error");
    assert!(diagnostic["message"]
        .as_str()
        .expect("diagnostic message")
        .contains("state.storage = in_memory requires deployment.multi_instance = false"));
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic =
        diagnostic_with_code(&report, "notary.audit.sink_missing").expect("audit sink finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
}

#[test]
fn doctor_json_warns_on_explicit_unbound_credential_profile() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            unbound_credential_profile: true,
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
        "explicit unbound profile should warn, not fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "warning");

    let diagnostic =
        diagnostic_with_code(&report, "notary.credential_profile.unbound_holder_binding")
            .expect("unbound holder-binding warning");
    assert_eq!(diagnostic["severity"], "warning");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message string")
        .contains("unbound_sd_jwt"));
}

#[test]
fn doctor_json_file_sink_without_attestation_warns_and_reports_unshipped_audit() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            durable_audit: Some(true),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "a local file sink without attestation should warn, not fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);

    assert_eq!(report["audit_shipping"]["sink_type"], "file");
    assert_eq!(
        report["audit_shipping"]["shipping_target_configured"],
        false
    );
    assert_eq!(report["audit_shipping"]["shipping_target"], "none");

    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics array")
            .iter()
            .any(|diagnostic| diagnostic["message"]
                .as_str()
                .expect("message string")
                .contains("local-chain-only")),
        "a local file sink without attestation must warn that audit is local-chain-only"
    );
}

#[test]
fn doctor_json_file_sink_with_attestation_reports_declared_external_without_warning() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            durable_audit: Some(true),
            audit_offhost_shipping: true,
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        output.status.success(),
        "a local file sink with attestation should pass doctor\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);

    assert_eq!(report["audit_shipping"]["sink_type"], "file");
    assert_eq!(report["audit_shipping"]["shipping_target_configured"], true);
    assert_eq!(
        report["audit_shipping"]["shipping_target"],
        "declared_external"
    );

    assert!(
        !report["diagnostics"]
            .as_array()
            .expect("diagnostics array")
            .iter()
            .any(|diagnostic| diagnostic["message"]
                .as_str()
                .expect("message string")
                .contains("local-chain-only")),
        "declaring off-host shipping must silence the local-chain-only warning"
    );
}

/// Write a `registry.audit.ack_cursor.v1` cursor with `acked_at` under `tmp`.
fn write_doctor_ack_cursor(tmp: &TempDir, acked_at: &str) -> PathBuf {
    let path = tmp.path().join("ack-cursor.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:4444444444444444444444444444444444444444444444444444444444444444","writer":"test-shipper"}}"#
        ),
    )
    .expect("ack cursor writes");
    path
}

fn run_doctor_json(config: &Path, env_file: &Path) -> Value {
    let output = doctor_command(config, Some(env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");
    assert!(
        output.status.success(),
        "doctor should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    report
}

#[test]
fn doctor_json_reports_shipping_health_unverified_for_fresh_cursor() {
    let tmp = TempDir::new().expect("tempdir");
    let acked_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let cursor = write_doctor_ack_cursor(&tmp, &acked_at);
    let cursor_path = cursor.to_str().expect("cursor path is utf8").to_string();
    // Default options use the stdout sink, so a shipping target is configured.
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            audit_ack_cursor_path: Some(&cursor_path),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let report = run_doctor_json(&config, &env_file);

    assert_eq!(report["audit_shipping"]["shipping_target_configured"], true);
    assert_eq!(report["audit_shipping"]["shipping_health"], "unverified");
    assert_eq!(report["audit_shipping"]["shipping_observed_at"], acked_at);
}

#[test]
fn doctor_json_reports_shipping_health_stale_for_old_cursor() {
    let tmp = TempDir::new().expect("tempdir");
    let cursor = write_doctor_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
    let cursor_path = cursor.to_str().expect("cursor path is utf8").to_string();
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            audit_ack_cursor_path: Some(&cursor_path),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let report = run_doctor_json(&config, &env_file);

    assert_eq!(report["audit_shipping"]["shipping_health"], "stale");
    assert_eq!(
        report["audit_shipping"]["shipping_observed_at"],
        "2026-06-04T09:59:00Z"
    );
}

#[test]
fn doctor_json_reports_shipping_health_missing_for_absent_cursor_file() {
    let tmp = TempDir::new().expect("tempdir");
    let cursor_path = tmp
        .path()
        .join("does-not-exist.json")
        .to_str()
        .expect("cursor path is utf8")
        .to_string();
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            audit_ack_cursor_path: Some(&cursor_path),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let report = run_doctor_json(&config, &env_file);

    assert_eq!(report["audit_shipping"]["shipping_health"], "missing");
    assert_eq!(
        report["audit_shipping"]["shipping_observed_at"],
        Value::Null
    );
}

#[test]
fn doctor_json_reports_shipping_health_invalid_for_malformed_cursor_file() {
    let tmp = TempDir::new().expect("tempdir");
    let cursor = tmp.path().join("ack-cursor.json");
    std::fs::write(&cursor, "{ not valid json").expect("cursor writes");
    let cursor_path = cursor.to_str().expect("cursor path is utf8").to_string();
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            audit_ack_cursor_path: Some(&cursor_path),
            ..TestConfigOptions::default()
        },
    );
    let env_file = write_env_file(&tmp);

    let report = run_doctor_json(&config, &env_file);

    assert_eq!(report["audit_shipping"]["shipping_health"], "invalid");
    assert_eq!(
        report["audit_shipping"]["shipping_observed_at"],
        Value::Null
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

    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "ok");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .all(|diagnostic| diagnostic["severity"].is_string()
            && diagnostic["code"].is_string()
            && diagnostic["message"].is_string()));
    assert!(report["required_env"]
        .as_array()
        .expect("required_env array")
        .iter()
        .any(
            |env| env["name"] == "TEST_DOCTOR_JSON_ISSUER_JWK" && env["classification"] == "secret"
        ));
    assert!(report.get("expanded_config").is_none());
    assert!(!stdout.contains(TEST_ISSUER_JWK));
    assert!(!stdout.contains(TEST_AUDIT_SECRET));
    assert!(!stdout.contains(TEST_API_HASH));
}

#[test]
fn explain_config_json_reports_redacted_resolved_config() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config(&tmp);
    let env_file = write_env_file(&tmp);

    let output = explain_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("explain-config runs");

    assert!(
        output.status.success(),
        "explain-config failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("explain-config emits JSON");
    assert_config_explanation(&report);
    assert!(report["resolved_config"].is_object());
    assert_eq!(
        report["resolved_config"]["evidence"]["signing_keys"]["issuer"]["private_jwk_env"],
        json!("[redacted]")
    );
    assert!(report["live_apply"]
        .as_array()
        .expect("live_apply array")
        .iter()
        .any(|item| item["class"] == "restart_required"));
    assert!(!stdout.contains(TEST_ISSUER_JWK));
    assert!(!stdout.contains(TEST_AUDIT_SECRET));
    assert!(!stdout.contains(TEST_API_HASH));
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .any(|diagnostic| diagnostic["severity"] == "error"
            && diagnostic["message"]
                .as_str()
                .expect("message")
                .contains("config YAML parse or validation failed")
            && diagnostic["message"]
                .as_str()
                .expect("message")
                .contains("fix the YAML syntax and field names")));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is utf8"),
        ""
    );
}

#[test]
fn doctor_json_reports_empty_claim_formats_with_remediation() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_empty_claim_formats(&tmp);

    let output = doctor_command(&config, None)
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(!output.status.success(), "doctor must reject empty formats");
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    let diagnostic = diagnostic_with_code(&report, "failed").expect("failure diagnostic");
    let message = diagnostic["message"].as_str().expect("message string");
    assert!(
        message.contains("empty-format"),
        "claim id is reported: {message}"
    );
    assert!(
        message.contains("omit formats"),
        "remediation is reported: {message}"
    );
}

#[test]
fn doctor_json_reports_sd_jwt_claim_format_with_remediation() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_claim_formats(&tmp, "sd-jwt-format", &["application/dc+sd-jwt"]);

    let output = doctor_command(&config, None)
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "doctor must reject SD-JWT formats"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    let diagnostic = diagnostic_with_code(&report, "failed").expect("failure diagnostic");
    let message = diagnostic["message"].as_str().expect("message string");
    assert!(
        message.contains("sd-jwt-format"),
        "claim id is reported: {message}"
    );
    assert!(
        message.contains("application/dc+sd-jwt") && message.contains("credential_profiles"),
        "offending format and remediation are reported: {message}"
    );
}

#[test]
fn doctor_json_reports_unknown_claim_format_with_remediation() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_claim_formats(
        &tmp,
        "unknown-format",
        &[
            "application/vnd.registry-notary.claim-result+json",
            "application/example+json",
        ],
    );

    let output = doctor_command(&config, None)
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "doctor must reject unknown formats"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    let diagnostic = diagnostic_with_code(&report, "failed").expect("failure diagnostic");
    let message = diagnostic["message"].as_str().expect("message string");
    assert!(
        message.contains("unknown-format"),
        "claim id is reported: {message}"
    );
    assert!(
        message.contains("application/example+json") && message.contains("supported formats"),
        "offending format and remediation are reported: {message}"
    );
}

#[test]
fn doctor_json_reports_missing_canonical_claim_format_with_remediation() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_claim_formats(
        &tmp,
        "missing-canonical",
        &["application/ld+json; profile=\"cccev\""],
    );

    let output = doctor_command(&config, None)
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");

    assert!(
        !output.status.success(),
        "doctor must reject formats without the canonical renderer"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    let diagnostic = diagnostic_with_code(&report, "failed").expect("failure diagnostic");
    let message = diagnostic["message"].as_str().expect("message string");
    assert!(
        message.contains("missing-canonical"),
        "claim id is reported: {message}"
    );
    assert!(
        message.contains("application/vnd.registry-notary.claim-result+json")
            && message.contains("add it"),
        "canonical format and remediation are reported: {message}"
    );
}
