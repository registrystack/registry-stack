// SPDX-License-Identifier: Apache-2.0
//! Regression coverage for standalone API-key provisioning.

use std::collections::BTreeMap;
use std::process::Command;

use registry_platform_authcommon::verify_api_key;
use registry_relay::auth::runtime::build_auth;
use registry_relay::config;
use tempfile::TempDir;

fn parse_key_value_output(output: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8(output.to_vec())
        .expect("generator output is utf-8")
        .lines()
        .map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .unwrap_or_else(|| panic!("generator output line is KEY=VALUE: {line}"))
        })
        .collect()
}

fn write_config(tmp: &TempDir, key_id: &str, fingerprint_env: &str) -> std::path::PathBuf {
    let path = tmp.path().join("relay.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {{}}
auth:
  mode: api_key
  api_keys:
    - id: {key_id}
      fingerprint:
        provider: env
        name: {fingerprint_env}
      scopes:
        - registry_relay:ops_read
datasets: []
audit:
  sink: stdout
  format: jsonl
"#
        ),
    )
    .expect("config writes");
    path
}

#[tokio::test]
async fn generated_api_key_round_trips_through_startup_validation() {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .env("RUST_LOG", "off")
        .args(["generate-api-key", "--id", "operator_reader"])
        .output()
        .expect("generator command runs");
    assert!(
        output.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "generator should not emit operational logs on success: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let values = parse_key_value_output(&output.stdout);
    let key_id = values.get("api_key_id").expect("id emitted");
    let api_key = values.get("api_key").expect("raw api key emitted");
    let fingerprint = values.get("fingerprint").expect("fingerprint emitted");
    assert!(!values.contains_key("commitment"));
    assert_eq!(key_id, "operator_reader");
    assert_eq!(verify_api_key(api_key, fingerprint), Ok(true));

    let env_name = "REGISTRY_RELAY_TEST_GENERATED_OPERATOR_READER_HASH";
    std::env::set_var(env_name, fingerprint);
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(&tmp, key_id, env_name);

    let config = config::load(&config_path).expect("generated fingerprint reference validates");
    build_auth(&config)
        .await
        .expect("generated fingerprint reference builds startup auth provider");

    std::env::remove_var(env_name);
}
