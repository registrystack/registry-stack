// SPDX-License-Identifier: Apache-2.0
//! CLI coverage for the machine-readable operator doctor command.

use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_config_report::{CONFIG_EXPLANATION_SCHEMA_V1, PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1};
use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
};
use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackRecord, FileAntiRollbackStore, AUDIT_ACK_CURSOR_FIXTURE_V1,
};
use serde_json::Value;
use tempfile::TempDir;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn write_minimal_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("relay.yaml");
    std::fs::write(
        &path,
        r#"
deployment:
  profile: local
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
    write_signed_profile_config(tmp, profile, openapi_requires_auth, false)
}

fn write_signed_profile_config(
    tmp: &TempDir,
    profile: &str,
    openapi_requires_auth: bool,
    public_admin: bool,
) -> std::path::PathBuf {
    let fixture_name = format!(
        "{profile}-{}-{}",
        if openapi_requires_auth {
            "openapi-auth"
        } else {
            "openapi-public"
        },
        if public_admin {
            "public-admin"
        } else {
            "private-admin"
        }
    );
    let bundle_dir = tmp.path().join(format!("bundle-{fixture_name}"));
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let bundled_config = relay_profile_config_yaml(profile, openapi_requires_auth, public_admin);
    let bundled_config_hash = sha256_uri(bundled_config.as_bytes());
    std::fs::write(config_dir.join("relay.yaml"), bundled_config.as_bytes())
        .expect("bundle config writes");

    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint computes");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: "registry-relay".to_string(),
        environment: "lab".to_string(),
        stream_id: format!("relay-doctor-{fixture_name}"),
        instance_id: Some("relay-lab".to_string()),
        bundle_id: format!("relay-doctor-{fixture_name}-bundle"),
        sequence: 1,
        previous_config_hash: Some(ZERO_HASH.to_string()),
        config_hash: bundled_config_hash.clone(),
        files: vec![ConfigBundleFile {
            path: "config/relay.yaml".to_string(),
            sha256: bundled_config_hash.clone(),
        }],
        created_at: "2026-07-07T10:00:00Z".to_string(),
    };
    write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);

    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        product: "registry-relay".to_string(),
        environment: "lab".to_string(),
        stream_id: manifest.stream_id.clone(),
        instance_id: "relay-lab".to_string(),
        signers: vec![ConfigTrustAnchorSigner {
            kid,
            jwk: public,
            enabled: true,
        }],
    };
    let anchor_path = tmp.path().join(format!("trust-anchor-{fixture_name}.json"));
    std::fs::write(
        &anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");

    let state_path = tmp.path().join(format!("antirollback-{fixture_name}.json"));
    FileAntiRollbackStore::new(&state_path)
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: "relay-lab".to_string(),
                environment: "lab".to_string(),
                stream_id: manifest.stream_id.clone(),
            },
            last_sequence: 0,
            last_config_hash: ZERO_HASH.to_string(),
            last_bundle_manifest_hash: None,
            last_bundle_id: None,
            root_version: None,
            override_pin: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("state initializes");

    let path = tmp.path().join(format!("relay-{fixture_name}.yaml"));
    std::fs::write(
        &path,
        format!(
            r#"
instance:
  id: registry-relay-profile-test
deployment:
  profile: {profile}
config_trust:
  trust_anchor_path: {anchor}
  bundle_path: {bundle}
  antirollback_state_path: {state}
  break_glass_override_path: {break_glass}
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
            anchor = anchor_path.to_string_lossy().replace('\\', "/"),
            bundle = bundle_dir.to_string_lossy().replace('\\', "/"),
            state = state_path.to_string_lossy().replace('\\', "/"),
            break_glass = tmp
                .path()
                .join(format!("break-glass-{fixture_name}"))
                .to_string_lossy()
                .replace('\\', "/"),
        ),
    )
    .expect("config writes");
    path
}

fn write_public_admin_profile_config(tmp: &TempDir, profile: &str) -> std::path::PathBuf {
    write_signed_profile_config(tmp, profile, true, true)
}

fn relay_profile_config_yaml(
    profile: &str,
    openapi_requires_auth: bool,
    public_admin: bool,
) -> String {
    let admin_bind = if public_admin {
        "  admin_bind: 0.0.0.0:0\n"
    } else {
        ""
    };
    format!(
        r#"
instance:
  id: relay-lab
  environment: lab
deployment:
  profile: {profile}
server:
  bind: 127.0.0.1:0
{admin_bind}  openapi_requires_auth: {openapi_requires_auth}
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
    )
}

fn write_manifest_and_signature(
    bundle_dir: &std::path::Path,
    manifest: &ConfigBundleManifest,
    private: &PrivateJwk,
    kid: &str,
) {
    let manifest_value = serde_json::to_value(manifest).expect("manifest value");
    let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
    let signature = sign(&canonical, private).expect("manifest signs");
    let envelope = ConfigBundleSignatureEnvelope {
        schema: "registry.platform.config_bundle_signatures.v1".to_string(),
        signatures: vec![ConfigBundleSignature {
            kid: kid.to_string(),
            alg: "EdDSA".to_string(),
            sig: URL_SAFE_NO_PAD.encode(signature),
        }],
    };
    std::fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).expect("manifest serializes"),
    )
    .expect("manifest writes");
    std::fs::write(
        bundle_dir.join("manifest.sig.json"),
        serde_json::to_vec_pretty(&envelope).expect("signature serializes"),
    )
    .expect("signature writes");
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

fn assert_json_schema_compiles(schema: &Value) {
    jsonschema::JSONSchema::compile(schema).unwrap_or_else(|err| {
        panic!("schema must compile as JSON Schema: {err}\n{schema:#}");
    });
}

fn diagnostic_with_code<'a>(report: &'a Value, code: &str) -> Option<&'a Value> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
}

#[test]
fn schema_json_reports_top_level_config_sections() {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args(["schema", "--format", "json"])
        .output()
        .expect("schema command runs");

    assert!(
        output.status.success(),
        "schema failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let schema = parse_stdout_json(&output.stdout);
    assert_json_schema_compiles(&schema);
    assert_eq!(schema["title"], "Registry Relay config");
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"]["server"].is_object());
    assert!(schema["properties"]["catalog"].is_object());
    assert!(schema["properties"]["auth"].is_object());
    assert!(schema["properties"]["audit"].is_object());
    assert!(schema["properties"]["datasets"].is_object());
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
    assert_eq!(report["status"], "ok");
    assert!(diagnostic_with_code(&report, "relay.config.loaded").is_some());
    assert!(diagnostic_with_code(&report, "relay.entity_registry.verified").is_some());
    assert!(diagnostic_with_code(&report, "deployment.profile_undeclared").is_none());
}

#[test]
fn doctor_json_reports_declared_audit_shipping_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_minimal_config(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
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
    // The minimal config uses the stdout sink, which ships evidence off-host.
    assert_eq!(report["audit_shipping"]["sink_type"], "stdout");
    assert_eq!(report["audit_shipping"]["shipping_target_configured"], true);
    assert_eq!(report["audit_shipping"]["shipping_target"], "stdout");
    // No ack cursor is configured, so observed shipping health is unverified.
    assert_eq!(report["audit_shipping"]["shipping_health"], "unverified");
    assert!(report["audit_shipping"]["shipping_observed_at"].is_null());
}

/// Write a `local`-profile config with a stdout sink and the given ack cursor
/// path, so the doctor reads and reports observed shipping health.
fn write_ack_cursor_config(
    tmp: &TempDir,
    name: &str,
    cursor_path: &std::path::Path,
) -> std::path::PathBuf {
    let path = tmp.path().join(name);
    std::fs::write(
        &path,
        format!(
            r#"
deployment:
  profile: local
  evidence:
    audit_ack_cursor_path: "{cursor}"
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
  format: jsonl
"#,
            cursor = cursor_path.display()
        ),
    )
    .expect("config writes");
    path
}

fn run_doctor_json(config_path: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args([
            "doctor",
            "--config",
            config_path.to_str().expect("utf-8 path"),
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
    report
}

#[test]
fn doctor_json_reports_fresh_ack_cursor_health() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let acked_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("rfc3339 timestamp");
    // The embedded valid fixture with its acked_at rewritten to now.
    let cursor = AUDIT_ACK_CURSOR_FIXTURE_V1.replace("2026-06-04T09:59:00Z", &acked_at);
    let cursor_path = tmp.path().join("ack-cursor.json");
    std::fs::write(&cursor_path, cursor).expect("cursor writes");
    let config_path = write_ack_cursor_config(&tmp, "relay-fresh.yaml", &cursor_path);

    let report = run_doctor_json(&config_path);
    assert_eq!(report["audit_shipping"]["shipping_health"], "ok");
    assert_eq!(report["audit_shipping"]["shipping_observed_at"], acked_at);
}

#[test]
fn doctor_json_reports_stale_ack_cursor_health() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A far-past acked_at is always older than the default freshness window.
    let cursor =
        AUDIT_ACK_CURSOR_FIXTURE_V1.replace("2026-06-04T09:59:00Z", "2000-01-01T00:00:00Z");
    let cursor_path = tmp.path().join("ack-cursor.json");
    std::fs::write(&cursor_path, cursor).expect("cursor writes");
    let config_path = write_ack_cursor_config(&tmp, "relay-stale.yaml", &cursor_path);

    let report = run_doctor_json(&config_path);
    assert_eq!(report["audit_shipping"]["shipping_health"], "stale");
    assert_eq!(
        report["audit_shipping"]["shipping_observed_at"],
        "2000-01-01T00:00:00Z"
    );
}

#[test]
fn doctor_json_reports_missing_ack_cursor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cursor_path = tmp.path().join("does-not-exist.json");
    let config_path = write_ack_cursor_config(&tmp, "relay-missing.yaml", &cursor_path);

    let report = run_doctor_json(&config_path);
    assert_eq!(report["audit_shipping"]["shipping_health"], "missing");
    assert!(report["audit_shipping"]["shipping_observed_at"].is_null());
}

#[test]
fn doctor_json_reports_invalid_ack_cursor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cursor_path = tmp.path().join("invalid.json");
    std::fs::write(&cursor_path, "this is not valid json").expect("cursor writes");
    let config_path = write_ack_cursor_config(&tmp, "relay-invalid.yaml", &cursor_path);

    let report = run_doctor_json(&config_path);
    assert_eq!(report["audit_shipping"]["shipping_health"], "invalid");
    assert!(report["audit_shipping"]["shipping_observed_at"].is_null());
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
