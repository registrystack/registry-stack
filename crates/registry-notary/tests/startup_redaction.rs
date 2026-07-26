// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use registry_notary_server::NotaryActivationCode;
use registry_platform_ops::{BundleVerificationCode, BundleVerificationFailure};

const SENTINEL_COUNTRY: &str = "SENTINEL_COUNTRY_FARAJALAND";
const SENTINEL_USERNAME: &str = "SENTINEL_USERNAME_ALICE";
const SENTINEL_SECRET: &str = "SENTINEL_SECRET_DO_NOT_PRINT";
const SENTINEL_DIGEST: &str = "sha256:SENTINEL_PRIVATE_DIGEST";

fn registry_notary_command() -> Command {
    registry_notary_command_with_log("info")
}

fn registry_notary_command_with_log(rust_log: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .env_remove("REGISTRY_NOTARY_CONFIG")
        .env_remove("REGISTRY_NOTARY_ENV_FILE")
        .env("RUST_LOG", rust_log);
    command
}

fn run_server(config_path: &Path) -> Output {
    registry_notary_command()
        .arg("--config")
        .arg(config_path)
        .output()
        .expect("registry-notary starts")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_safe_configuration_failure(output: &Output, forbidden: &[&str]) {
    assert!(!output.status.success(), "invalid startup must fail closed");
    let combined = combined_output(output);
    assert!(
        combined.contains("notary.configuration.invalid"),
        "startup output must expose the stable safe activation code: {combined}"
    );
    for value in forbidden {
        assert!(
            !combined.contains(value),
            "startup output exposed forbidden value {value:?}: {combined}"
        );
    }
}

struct MissingBundleFixture {
    config_path: PathBuf,
    trust_path: PathBuf,
    bundle_path: PathBuf,
    state_path: PathBuf,
    override_path: PathBuf,
}

fn write_missing_bundle_fixture(tmp: &tempfile::TempDir) -> MissingBundleFixture {
    let config_path = tmp.path().join("bootstrap.yaml");
    let trust_path = tmp.path().join(format!("{SENTINEL_USERNAME}-anchor.json"));
    let bundle_path = tmp.path().join(format!("{SENTINEL_COUNTRY}-bundle"));
    let state_path = tmp.path().join(format!("{SENTINEL_DIGEST}-state.json"));
    let override_path = tmp.path().join(format!("{SENTINEL_SECRET}-override.json"));
    std::fs::write(
        &config_path,
        format!(
            r#"
deployment:
  profile: local
state:
  storage: in_memory
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: STARTUP_REDACTION_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: STARTUP_REDACTION_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
  break_glass_override_path: {}
"#,
            trust_path.display(),
            bundle_path.display(),
            state_path.display(),
            override_path.display(),
        ),
    )
    .expect("bootstrap config writes");
    MissingBundleFixture {
        config_path,
        trust_path,
        bundle_path,
        state_path,
        override_path,
    }
}

#[test]
fn rust_log_off_emits_one_static_local_configuration_failure_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join(format!(
        "{SENTINEL_USERNAME}-{SENTINEL_COUNTRY}-{SENTINEL_SECRET}.yaml"
    ));

    let output = registry_notary_command_with_log("off")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("registry-notary starts");

    assert!(!output.status.success(), "missing config must fail closed");
    assert!(
        output.stdout.is_empty(),
        "startup failure must not emit stdout with tracing disabled: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let definition = NotaryActivationCode::CONFIGURATION_INVALID.definition();
    let expected = format!(
        "ERROR {}: {}; next action: {}\n",
        definition.code, definition.meaning, definition.remediation
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, expected);
    assert_eq!(
        stderr.lines().count(),
        1,
        "startup must render exactly one terminal failure line"
    );
    for forbidden in [
        SENTINEL_COUNTRY,
        SENTINEL_USERNAME,
        SENTINEL_SECRET,
        config_path.to_string_lossy().as_ref(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "terminal failure line exposed forbidden value {forbidden:?}: {stderr}"
        );
    }
}

#[test]
fn rust_log_off_emits_one_exact_static_bundle_rejection_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_missing_bundle_fixture(&tmp);

    let output = registry_notary_command_with_log("off")
        .arg("--config")
        .arg(&fixture.config_path)
        .output()
        .expect("registry-notary starts");

    assert!(!output.status.success(), "missing bundle must fail closed");
    assert!(
        output.stdout.is_empty(),
        "bundle startup failure must not emit stdout with tracing disabled: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let failure = BundleVerificationFailure::from(BundleVerificationCode::REJECTED_VALIDATION);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, format!("ERROR {failure}\n"));
    assert_eq!(
        stderr.lines().count(),
        1,
        "bundle startup must render exactly one terminal failure line"
    );
    for forbidden in [
        SENTINEL_COUNTRY,
        SENTINEL_USERNAME,
        SENTINEL_SECRET,
        SENTINEL_DIGEST,
        fixture.trust_path.to_string_lossy().as_ref(),
        fixture.bundle_path.to_string_lossy().as_ref(),
        fixture.state_path.to_string_lossy().as_ref(),
        fixture.override_path.to_string_lossy().as_ref(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "terminal bundle rejection exposed forbidden value {forbidden:?}: {stderr}"
        );
    }
}

#[test]
fn malformed_local_config_does_not_expose_parser_input_or_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let private_dir = tmp
        .path()
        .join(format!("{SENTINEL_USERNAME}-{SENTINEL_COUNTRY}"));
    std::fs::create_dir_all(&private_dir).expect("private config dir");
    let config_path = private_dir.join(format!("{SENTINEL_SECRET}.yaml"));
    std::fs::write(
        &config_path,
        format!("country: {SENTINEL_COUNTRY}\nsecret: [{SENTINEL_SECRET}\n"),
    )
    .expect("malformed config writes");

    let output = run_server(&config_path);

    assert_safe_configuration_failure(
        &output,
        &[
            SENTINEL_COUNTRY,
            SENTINEL_USERNAME,
            SENTINEL_SECRET,
            config_path.to_string_lossy().as_ref(),
        ],
    );
}

#[test]
fn missing_env_file_does_not_expose_startup_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let env_path = tmp.path().join(format!(
        "{SENTINEL_USERNAME}-{SENTINEL_COUNTRY}-{SENTINEL_SECRET}.env"
    ));

    let output = registry_notary_command()
        .arg("--env-file")
        .arg(&env_path)
        .output()
        .expect("registry-notary starts");

    assert_safe_configuration_failure(
        &output,
        &[
            SENTINEL_COUNTRY,
            SENTINEL_USERNAME,
            SENTINEL_SECRET,
            env_path.to_string_lossy().as_ref(),
        ],
    );
}

#[test]
fn signed_bundle_boot_failure_does_not_expose_governed_paths_or_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_missing_bundle_fixture(&tmp);

    let output = run_server(&fixture.config_path);

    assert_safe_configuration_failure(
        &output,
        &[
            SENTINEL_COUNTRY,
            SENTINEL_USERNAME,
            SENTINEL_SECRET,
            SENTINEL_DIGEST,
            fixture.trust_path.to_string_lossy().as_ref(),
            fixture.bundle_path.to_string_lossy().as_ref(),
            fixture.state_path.to_string_lossy().as_ref(),
            fixture.override_path.to_string_lossy().as_ref(),
        ],
    );
    let combined = combined_output(&output);
    let code = BundleVerificationCode::REJECTED_VALIDATION;
    let definition = code.definition();
    assert!(combined.contains(&format!("result=\"{}\"", code.as_str())));
    assert!(combined.contains(&format!("safe_meaning=\"{}\"", definition.safe_meaning)));
    assert!(combined.contains(&format!(
        "safe_remediation=\"{}\"",
        definition.safe_remediation
    )));
}
