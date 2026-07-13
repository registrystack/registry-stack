// SPDX-License-Identifier: Apache-2.0

use super::*;

const CONTRACT_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn relay_config() -> (tempfile::TempDir, PathBuf, StandaloneRegistryNotaryConfig) {
    let token_directory = tempfile::tempdir().expect("token directory creates");
    let token_file = token_directory.path().join("relay.jwt");
    std::fs::write(&token_file, b"opaque-test-token").expect("token file writes");
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(&format!(
        r#"
deployment:
  profile: local
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_NOTARY_API_KEY_HASH
      scopes: [registry:evidence]
evidence:
  enabled: true
  relay:
    base_url: https://relay.internal.example
    workload_client_id: registry-notary
    token_file: {}
    allowed_private_cidrs: [10.20.0.0/16]
  claims:
    - id: person-status
      title: Person status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          person_status:
            profile:
              id: example.person-status.exact
              contract_hash: {CONTRACT_HASH}
            inputs:
              tracked_entity: target.id
            outputs:
              status:
                type: string
                nullable: true
                max_bytes: 64
      value:
        type: string
        nullable: true
      purpose: benefit-verification
      required_scopes: [registry:evidence]
      rule:
        type: extract
        source: person_status
        field: status
"#,
        token_file.display()
    ))
    .expect("Relay config parses");
    config.validate().expect("Relay config validates");
    (token_directory, token_file, config)
}

#[test]
fn bind_override_replaces_config_bind() {
    let (_token_directory, _token_file, mut config) = relay_config();
    config.server.bind = "127.0.0.1:8081".parse().expect("socket addr parses");

    apply_bind_override(
        &mut config,
        Some("0.0.0.0:8080".parse().expect("socket addr parses")),
    );

    assert_eq!(
        config.server.bind,
        "0.0.0.0:8080"
            .parse::<SocketAddr>()
            .expect("socket addr parses")
    );
}

#[test]
fn relay_configuration_reports_reloadable_credential_and_safe_network_posture() {
    let (_token_directory, token_file, config) = relay_config();
    let env_report = EnvFileReport::default();
    let explanation = config_explanation_json(
        Path::new("/etc/registry-notary/config.yaml"),
        "redacted test config",
        &config,
        &env_report,
    );

    assert!(explanation["required_env"]
        .as_array()
        .expect("required_env is an array")
        .iter()
        .all(|entry| entry["name"] != "REGISTRY_NOTARY_TEST_RELAY_TOKEN"));
    assert_eq!(
        explanation["resolved_config"]["evidence"]["relay"]["token_file"],
        "[redacted]"
    );
    assert_eq!(
        explanation["relay_connection"],
        json!({
            "credential": {
                "mode": "reloadable_token_file",
                "reload": "per_operation",
                "offline_file_status": "present",
            },
            "network": {
                "transport": "https",
                "allowed_private_cidr_count": 1,
                "allow_insecure_localhost": false,
            },
        })
    );
    let rendered = serde_json::to_string(&explanation).expect("explanation renders");
    let token_file_text = token_file.to_string_lossy();
    assert!(!rendered.contains(token_file_text.as_ref()));

    std::fs::remove_file(&token_file).expect("token file removes");
    assert_eq!(
        notary_relay_connection_report(&config)["credential"]["offline_file_status"],
        "missing"
    );

    let relay_live_apply = explanation["live_apply"]
        .as_array()
        .expect("live_apply is an array")
        .iter()
        .find(|entry| entry["path"] == "/evidence/relay")
        .expect("Relay live-apply classification is reported");
    assert_eq!(relay_live_apply["class"], "restart_required");
}

#[test]
fn relay_consultation_report_exposes_only_pinned_operator_contract() {
    let (_token_directory, _token_file, config) = relay_config();
    let report = notary_relay_consultations_report(&config);

    assert_eq!(
        report,
        vec![json!({
            "container_path": "/evidence/claims/0/evidence_mode/consultations/person_status",
            "claim_id": "person-status",
            "consultation": "person_status",
            "profile": {
                "id": "example.person-status.exact",
                "contract_hash": CONTRACT_HASH,
            },
            "purpose": "benefit-verification",
            "required_scopes": ["registry:evidence"],
            "inputs": {
                "tracked_entity": "target.id",
            },
        })]
    );

    let rendered = serde_json::to_string(&report).expect("consultation report renders");
    assert!(!rendered.contains("relay.internal.example"));
}

#[test]
fn absent_relay_is_reported_as_an_optional_section() {
    let (_token_directory, _token_file, mut config) = relay_config();
    config.evidence.relay = None;

    assert!(optional_config_sections_absent(&config)
        .iter()
        .any(|entry| {
            entry["path"] == "/evidence/relay"
                && entry["reason"] == "no Registry Relay connection configured"
        }));
    assert_eq!(notary_relay_connection_report(&config), Value::Null);
}
