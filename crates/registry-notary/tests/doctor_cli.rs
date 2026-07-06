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
const TEST_SOURCE_TOKEN: &str = "doctor-source-token";

#[derive(Default)]
struct TestConfigOptions<'a> {
    openapi_requires_auth: Option<bool>,
    source_base_url: Option<&'a str>,
    source_allows_private_network: bool,
    source_adapter_batch_without_expected_sidecar: bool,
    config_trust: bool,
    omit_deployment_profile: bool,
    multi_instance: bool,
    durable_audit: Option<bool>,
    unbound_credential_profile: bool,
    unconstrained_source_binding: bool,
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
  accepted_roots:
    - root_id: doctor-test-root
      production: false
      tuf_root_sha256: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      high_risk_change_classes: []
      signers:
        doctor-test-signer:
          kid: doctor-test-signer
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - doctor-test-signer
          allowed_change_classes:
            - public_metadata
"#,
            tmp.path().join("antirollback.json").display(),
            tmp.path().join("local-approvals.json").display()
        )
    } else {
        String::new()
    };
    let deployment = if options.omit_deployment_profile {
        if options.multi_instance {
            "deployment:\n  multi_instance: true\n"
        } else {
            ""
        }
    } else if options.multi_instance {
        "deployment:\n  profile: local\n  multi_instance: true\n"
    } else {
        "deployment:\n  profile: local\n"
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
    let source_base_url = options
        .source_base_url
        .or(options
            .source_adapter_batch_without_expected_sidecar
            .then_some("https://source-adapter.example.test"))
        .or(options
            .unconstrained_source_binding
            .then_some("https://registry-source.example.test"));
    let source_private_network = if options.source_allows_private_network {
        "      allow_insecure_private_network: true\n"
    } else {
        ""
    };
    let source_adapter_bulk_mode = if options.source_adapter_batch_without_expected_sidecar {
        "      bulk_mode: source_adapter_sidecar_batch\n      retry_on_5xx: false\n"
    } else {
        ""
    };
    let source_connections = source_base_url
        .map(|base_url| {
            format!(
                r#"  source_connections:
    profile_gate_test:
      base_url: "{base_url}"
{source_private_network}{source_adapter_bulk_mode}
      token_env: TEST_DOCTOR_JSON_SOURCE_TOKEN
"#
            )
        })
        .unwrap_or_default();
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
      rule:
        type: cel
        expression: "true"
      formats:
        - application/dc+sd-jwt
      credential_profiles:
        - unbound_sd_jwt
"#,
        );
    }
    if options.unconstrained_source_binding {
        claim_entries.push_str(
            r#"    - id: residency-lookup
      title: Residency lookup
      version: "1.0"
      subject_type: person
      source_bindings:
        registry:
          connector: registry_data_api
          connection: profile_gate_test
          dataset: registry
          entity: resident
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
      rule:
        type: exists
        source: registry
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
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_JSON_API_HASH
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
{source_connections}{credential_profiles}{credential_profile_claims}
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

fn write_opencrvs_dci_config(tmp: &TempDir) -> PathBuf {
    let path = tmp.path().join("opencrvs-dci.yaml");
    std::fs::write(
        &path,
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_JSON_API_HASH
      scopes: [civil_registry:evidence_verification]
      authorization_details:
        type: registry-notary/evidence-authorization/v1
        schema_version: v1
        legal_basis_ref: registryctl:opencrvs-dci:demo-legal-basis
        consent_ref: registryctl:opencrvs-dci:demo-consent
        jurisdiction: ZZ
        assurance_level: substantial
audit:
  sink: stdout
  hash_secret_env: TEST_DOCTOR_JSON_AUDIT_SECRET
evidence:
  enabled: true
  service_id: doctor-json-test
  source_connections:
    opencrvs_crvs:
      base_url: https://opencrvs.example.test
      source_auth:
        type: oauth2_client_credentials
        token_url: https://opencrvs.example.test/oauth2/client/token
        client_id_env: DCI_CLIENT_ID
        client_secret_env: DCI_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        registry_type: ns:org:RegistryType:Civil
        registry_event_type: birth
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          observed_at: "$response:/message/search_response/0/timestamp"
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_DOCTOR_JSON_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  claims:
    - id: opencrvs-birth-record-exists
      title: OpenCRVS birth record exists
      version: 2026-06
      subject_type: person
      value:
        type: boolean
      inputs:
        - name: target.identifiers.UIN
          type: string
      source_bindings:
        birth_record:
          connector: dci
          connection: opencrvs_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: birth_registration
          lookup:
            input: target.identifiers.UIN
            field: UIN
            op: eq
            cardinality: one
          fields: {}
          matching:
            policy_id: registryctl.opencrvs-dci.birth-record.lookup.v1
            method: configured_lookup
            context_constraints:
              legal_basis:
                required: true
              consent:
                required: true
              jurisdiction:
                permitted: [ZZ]
              assurance:
                allowed: [substantial]
              source_freshness:
                max_age_seconds: 86400
            source_observed_at_field: observed_at
            sufficient_target_inputs:
              - [target.identifiers.UIN]
            allowed_target_inputs: [target.identifiers.UIN]
            collapse_matching_errors: true
            confidence: high
      rule:
        type: exists
        source: birth_record
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#,
    )
    .expect("config writes");
    path
}

fn write_opencrvs_dci_env_file(tmp: &TempDir) -> PathBuf {
    let path = tmp.path().join("opencrvs-dci.env");
    std::fs::write(
        &path,
        format!(
            "\
TEST_DOCTOR_JSON_API_HASH={TEST_API_HASH}
TEST_DOCTOR_JSON_AUDIT_SECRET={TEST_AUDIT_SECRET}
TEST_DOCTOR_JSON_ISSUER_JWK='{TEST_ISSUER_JWK}'
DCI_CLIENT_ID=test-dci-client
DCI_CLIENT_SECRET=test-dci-secret
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

fn diagnostics_with_code<'a>(report: &'a Value, code: &str) -> Vec<&'a Value> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .filter(|diagnostic| diagnostic["code"] == code)
        .collect()
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

fn assert_opencrvs_context_constraint(report: &Value) {
    let entries = report["context_constraints"]
        .as_array()
        .expect("context_constraints array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(
        entry["container_path"],
        "/evidence/claims/0/source_bindings/birth_record/matching"
    );
    assert_eq!(entry["product"], "registry-notary");
    assert_eq!(
        entry["platform_contract"],
        "registry-platform-pdp.context_constraints.v1"
    );
    assert_eq!(entry["legal_basis"]["required"], true);
    assert_eq!(entry["legal_basis"]["approved_value_check"], false);
    assert_eq!(entry["legal_basis"]["allowed_ref_count"], 0);
    assert_eq!(
        entry["legal_basis"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
    assert_eq!(entry["consent"]["required"], true);
    assert_eq!(entry["consent"]["approved_value_check"], false);
    assert_eq!(
        entry["consent"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
    assert_eq!(entry["jurisdiction"]["permitted_count"], 1);
    assert_eq!(
        entry["jurisdiction"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
    assert_eq!(entry["assurance"]["allowed_count"], 1);
    assert_eq!(entry["assurance"]["minimum"], Value::Null);
    assert_eq!(
        entry["assurance"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
    assert_eq!(entry["assurance"]["authn_derived"], false);
    assert_eq!(entry["source_freshness"]["max_age_seconds"], 86400);
    assert_eq!(
        entry["source_freshness"]["observation_field"],
        "observed_at"
    );
    assert_eq!(
        entry["source_freshness"]["observation_timestamp_source"],
        "source_observation_timestamp"
    );
    assert_eq!(
        entry["source_freshness"]["observation_contract_proven"],
        true
    );
    assert!(entry["product_owned_adjacent_controls"]
        .as_array()
        .expect("adjacent controls array")
        .iter()
        .any(|control| control == "target_input_minimization"));
}

fn assert_opencrvs_context_constraint_has_approved_refs(report: &Value) {
    let entries = report["context_constraints"]
        .as_array()
        .expect("context_constraints array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["legal_basis"]["required"], true);
    assert_eq!(entry["legal_basis"]["approved_value_check"], true);
    assert_eq!(entry["legal_basis"]["allowed_ref_count"], 1);
    assert_eq!(
        entry["legal_basis"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
    assert_eq!(entry["consent"]["required"], true);
    assert_eq!(entry["consent"]["approved_value_check"], true);
    assert_eq!(entry["consent"]["allowed_ref_count"], 1);
    assert_eq!(
        entry["consent"]["trusted_value_source"],
        "static_credential_authorization_details"
    );
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.source.insecure_url")
        .expect("insecure source URL finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.replay.in_memory_high_risk")
        .expect("high-risk replay finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.source.private_network_escape")
        .expect("private-network source escape finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
}

#[test]
fn doctor_json_evidence_grade_source_adapter_without_expected_sidecar_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            source_adapter_batch_without_expected_sidecar: true,
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
        "evidence_grade source-adapter batch without expected sidecar should fail readiness\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.sidecar.expected_sidecar_missing")
        .expect("missing expected sidecar finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "error");

    let diagnostic = diagnostic_with_code(&report, "notary.source.insecure_url")
        .expect("insecure source URL finding");
    assert_eq!(diagnostic["severity"], "error");
    assert_active_finding(diagnostic);
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
    assert_product_diagnostic_report(&report);

    assert!(
        diagnostic_with_code(&report, "notary.source.insecure_url").is_none(),
        "local profile must allow HTTP source URLs"
    );
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
fn doctor_json_warns_on_source_binding_without_matching_policy() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            unconstrained_source_binding: true,
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
        "a binding without a matching policy should warn, not fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);
    assert_eq!(report["status"], "warning");

    let diagnostic = diagnostic_with_code(&report, "notary.source_binding.no_matching_policy")
        .expect("no-matching-policy warning");
    assert_eq!(diagnostic["severity"], "warning");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message string")
        .contains("residency-lookup/registry"));
}

#[test]
fn doctor_json_production_source_binding_without_matching_policy_reports_once() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            unconstrained_source_binding: true,
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
        "production binding without a matching policy should warn, not fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);

    let diagnostics = diagnostics_with_code(&report, "notary.source_binding.no_matching_policy");
    assert_eq!(
        diagnostics.len(),
        1,
        "the bound production gate should be the only source of this finding code: {diagnostics:?}"
    );
    assert_eq!(diagnostics[0]["severity"], "warning");
}

#[test]
fn doctor_json_evidence_grade_source_binding_without_matching_policy_reports_once() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_config_with_options(
        &tmp,
        TestConfigOptions {
            unconstrained_source_binding: true,
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
        "evidence_grade binding without a matching policy is a finding_error, not startup_fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: Value = serde_json::from_str(&stdout).expect("doctor emits JSON");
    assert_product_diagnostic_report(&report);

    let diagnostics = diagnostics_with_code(&report, "notary.source_binding.no_matching_policy");
    assert_eq!(
        diagnostics.len(),
        1,
        "the bound evidence_grade gate should be the only source of this finding code: {diagnostics:?}"
    );
    assert_eq!(diagnostics[0]["severity"], "error");
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
fn doctor_json_report_opencrvs_dci_context_constraints_approved_refs() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_opencrvs_dci_config(&tmp);
    let env_file = write_opencrvs_dci_env_file(&tmp);
    let raw_config = std::fs::read_to_string(&config).expect("config reads");
    let raw_config = raw_config.replace(
        r#"              legal_basis:
                required: true
              consent:
                required: true"#,
        r#"              legal_basis:
                required: true
                allowed_refs:
                  - registryctl:opencrvs-dci:demo-legal-basis
              consent:
                required: true
                allowed_refs:
                  - registryctl:opencrvs-dci:demo-consent"#,
    );
    std::fs::write(&config, raw_config).expect("config writes");

    let doctor_output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");
    assert!(
        doctor_output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&doctor_output.stdout),
        String::from_utf8_lossy(&doctor_output.stderr)
    );
    let doctor_stdout = String::from_utf8(doctor_output.stdout).expect("stdout is utf8");
    let doctor_report: Value =
        serde_json::from_str(&doctor_stdout).expect("doctor emits one JSON document");
    assert_product_diagnostic_report(&doctor_report);
    assert_opencrvs_context_constraint_has_approved_refs(&doctor_report);
}

#[test]
fn doctor_and_explain_json_report_opencrvs_dci_context_constraints() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_opencrvs_dci_config(&tmp);
    let env_file = write_opencrvs_dci_env_file(&tmp);

    let doctor_output = doctor_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("doctor runs");
    assert!(
        doctor_output.status.success(),
        "doctor failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&doctor_output.stdout),
        String::from_utf8_lossy(&doctor_output.stderr)
    );
    let doctor_stdout = String::from_utf8(doctor_output.stdout).expect("stdout is utf8");
    let doctor_report: Value =
        serde_json::from_str(&doctor_stdout).expect("doctor emits one JSON document");
    assert_product_diagnostic_report(&doctor_report);
    assert_opencrvs_context_constraint(&doctor_report);
    assert!(
        diagnostic_with_code(&doctor_report, "notary.source_binding.no_matching_policy").is_none(),
        "a binding with policy_id and context constraints must not warn about a missing matching policy"
    );

    let explain_output = explain_command(&config, Some(&env_file))
        .args(["--format", "json"])
        .output()
        .expect("explain-config runs");
    assert!(
        explain_output.status.success(),
        "explain-config failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&explain_output.stdout),
        String::from_utf8_lossy(&explain_output.stderr)
    );
    let explain_stdout = String::from_utf8(explain_output.stdout).expect("stdout is utf8");
    let explain_report: Value =
        serde_json::from_str(&explain_stdout).expect("explain-config emits JSON");
    assert_config_explanation(&explain_report);
    assert_opencrvs_context_constraint(&explain_report);
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
