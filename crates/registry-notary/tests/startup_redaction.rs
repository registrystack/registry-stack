// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::{Command, Output};

const SENTINEL_COUNTRY: &str = "SENTINEL_COUNTRY_FARAJALAND";
const SENTINEL_USERNAME: &str = "SENTINEL_USERNAME_ALICE";
const SENTINEL_SECRET: &str = "SENTINEL_SECRET_DO_NOT_PRINT";
const SENTINEL_DIGEST: &str = "sha256:SENTINEL_PRIVATE_DIGEST";

fn registry_notary_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .env_remove("REGISTRY_NOTARY_CONFIG")
        .env_remove("REGISTRY_NOTARY_ENV_FILE")
        .env("RUST_LOG", "info");
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

    let output = run_server(&config_path);

    assert_safe_configuration_failure(
        &output,
        &[
            SENTINEL_COUNTRY,
            SENTINEL_USERNAME,
            SENTINEL_SECRET,
            SENTINEL_DIGEST,
            trust_path.to_string_lossy().as_ref(),
            bundle_path.to_string_lossy().as_ref(),
            state_path.to_string_lossy().as_ref(),
            override_path.to_string_lossy().as_ref(),
        ],
    );
}
