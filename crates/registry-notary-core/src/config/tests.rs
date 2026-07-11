use super::*;
use std::collections::BTreeSet;

/// Builds a minimal valid config from which individual tests can deviate.
fn minimal_config() -> StandaloneRegistryNotaryConfig {
    serde_norway::from_str(
        r#"
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
"#,
    )
    .expect("minimal config is valid YAML")
}

#[test]
fn gate_input_defaults_are_low_risk_for_minimal_config() {
    let config = minimal_config();
    let input = config.gate_input();
    // A minimal config uses in-memory replay and stdout audit by default.
    assert!(input.replay_in_memory);
    assert!(!input.audit_sink_class_durable);
    // No high-risk modes are declared.
    assert!(!input.high_risk_replay_mode());
    // No source connections, so source gates are clear.
    assert!(!input.source_insecure_url);
    assert!(!input.source_private_network_escape);
    assert!(!input.source_adapter_sidecar_without_expected_sidecar);
    // Local YAML config without config_trust is unsigned.
    assert!(input.config_unsigned);
    // Admin listener is disabled by default, so no shared exposure.
    assert!(!input.admin_shared_exposure);
    // OpenAPI requires auth by default.
    assert!(!input.openapi_public);
    // An active but unreferenced key is not a Notary signing role.
    assert!(!input.signer_without_custody_approval);
}

#[test]
fn gate_input_reports_federation_as_high_risk() {
    let mut config = minimal_config();
    config.federation.enabled = true;
    assert!(config.gate_input().high_risk_replay_mode());
}

#[test]
fn gate_input_reports_durable_audit_sink() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(config.gate_input().audit_sink_class_durable);
}

#[test]
fn gate_input_reports_audit_retention_local_only_for_file_sink_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(config.gate_input().audit_retention_local_only);
}

#[test]
fn gate_input_reports_audit_retention_local_only_for_jsonl_sink_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "jsonl".to_string();
    assert!(config.gate_input().audit_retention_local_only);
}

#[test]
fn gate_input_clears_audit_retention_local_only_when_attested() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(!config.gate_input().audit_retention_local_only);
}

#[test]
fn gate_input_requires_custody_approval_for_referenced_signer() {
    let mut config = minimal_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();

    assert!(config.gate_input().signer_without_custody_approval);
}

#[test]
fn gate_input_does_not_treat_pkcs11_as_custody_approval() {
    let mut config = minimal_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();
    config
        .evidence
        .signing_keys
        .get_mut("issuer-key")
        .expect("issuer key exists")
        .provider = SigningKeyProviderConfig::Pkcs11;

    assert!(config.gate_input().signer_without_custody_approval);
}

#[test]
fn gate_input_clears_signer_custody_when_approved() {
    let mut config = minimal_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();
    config.deployment.evidence.signer_custody_approved = true;

    assert!(!config.gate_input().signer_without_custody_approval);
}

#[test]
fn gate_input_clears_audit_retention_local_only_for_stdout_sink() {
    // Minimal config defaults to the stdout sink.
    let config = minimal_config();
    assert!(!config.gate_input().audit_retention_local_only);
}

#[test]
fn gate_input_clears_audit_retention_local_only_for_syslog_sink() {
    let mut config = minimal_config();
    config.audit.sink = "syslog".to_string();
    assert!(!config.gate_input().audit_retention_local_only);
}

/// The fixture ack cursor's `acked_at` (`2026-06-04T09:59:00Z`) as a
/// `SystemTime`, so tests can pin `now` relative to it deterministically.
fn fixture_acked_at() -> SystemTime {
    let acked = time::OffsetDateTime::parse(
        "2026-06-04T09:59:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixture acked_at parses");
    SystemTime::from(acked)
}

fn write_ack_cursor(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("ack-cursor.json");
    std::fs::write(&path, contents).expect("ack cursor writes");
    path
}

#[test]
fn gate_input_reports_shipping_declared_external_for_attested_file_sink() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(config.gate_input().audit_shipping_target_configured);
}

#[test]
fn gate_input_clears_shipping_declared_external_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(!config.gate_input().audit_shipping_target_configured);
}

#[test]
fn gate_input_reports_shipping_target_for_stdout_sink() {
    let mut config = minimal_config();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(config.gate_input().audit_shipping_target_configured);
}

#[test]
fn gate_input_reports_ack_cursor_configured_when_path_set() {
    let mut config = minimal_config();
    assert!(!config.gate_input().audit_ack_cursor_configured);
    config.deployment.evidence.audit_ack_cursor_path =
        Some(std::path::PathBuf::from("/nonexistent/ack-cursor.json"));
    assert!(config.gate_input().audit_ack_cursor_configured);
}

#[test]
fn gate_input_reports_ack_health_ok_only_after_fresh_cursor_binds_to_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_ack_cursor(
        dir.path(),
        registry_platform_ops::AUDIT_ACK_CURSOR_FIXTURE_V1,
    );
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path = Some(path);
    // now is 60s after the cursor's acked_at, well within the 900s window.
    let now = fixture_acked_at() + Duration::from_secs(60);
    assert!(!config.gate_input_at(now).audit_ack_health_ok);
    let observation = config
        .audit_ack_observation_at(now)
        .bind_to_audit_tail(Some([0x44; 32]));
    assert!(
        config
            .gate_input_with_ack_observation(&observation)
            .audit_ack_health_ok
    );
}

#[test]
fn gate_input_at_reports_ack_health_not_ok_for_stale_cursor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_ack_cursor(
        dir.path(),
        registry_platform_ops::AUDIT_ACK_CURSOR_FIXTURE_V1,
    );
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path = Some(path);
    // now is 901s after acked_at, one second past the default window.
    let now = fixture_acked_at() + Duration::from_secs(901);
    assert!(!config.gate_input_at(now).audit_ack_health_ok);
}

#[test]
fn gate_input_at_reports_ack_health_not_ok_for_missing_cursor() {
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path =
        Some(std::path::PathBuf::from("/nonexistent/ack-cursor.json"));
    let now = fixture_acked_at() + Duration::from_secs(60);
    assert!(!config.gate_input_at(now).audit_ack_health_ok);
}

#[test]
fn gate_input_at_honors_custom_max_age_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_ack_cursor(
        dir.path(),
        registry_platform_ops::AUDIT_ACK_CURSOR_FIXTURE_V1,
    );
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path = Some(path);
    config.deployment.evidence.audit_ack_max_age_secs = Some(30);
    // 60s after acked_at is stale under a 30s window.
    let now = fixture_acked_at() + Duration::from_secs(60);
    assert!(!config.gate_input_at(now).audit_ack_health_ok);
}

#[test]
fn validate_rejects_ack_max_age_without_cursor() {
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_max_age_secs = Some(600);
    let error = config
        .validate()
        .expect_err("max age without cursor rejected");
    assert!(matches!(
        error,
        EvidenceConfigError::AuditAckMaxAgeWithoutCursor
    ));
}

#[test]
fn validate_rejects_ack_cursor_on_local_file_sink_without_shipping_declared() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_ack_cursor_path = Some(std::path::PathBuf::from(
        "/var/lib/registry/ack-cursor.json",
    ));
    let error = config
        .validate()
        .expect_err("cursor on undeclared local file sink rejected");
    assert!(matches!(
        error,
        EvidenceConfigError::AuditAckCursorWithoutShippingDeclared
    ));
}

#[test]
fn validate_allows_ack_cursor_on_attested_local_file_sink() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.audit.path = Some("/var/log/registry/audit.jsonl".to_string());
    config.audit.hash_secret_env = Some("TEST_TOKEN_HASH".to_string());
    config.deployment.evidence.audit_offhost_shipping = true;
    config.deployment.evidence.audit_ack_cursor_path = Some(std::path::PathBuf::from(
        "/var/lib/registry/ack-cursor.json",
    ));
    config
        .validate()
        .expect("cursor on attested local file sink is valid");
}

#[test]
fn validate_allows_ack_cursor_on_stdout_sink_without_shipping_declared() {
    // stdout retention is owned off-box, so a cursor there does not require
    // the off-host shipping attestation.
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path = Some(std::path::PathBuf::from(
        "/var/lib/registry/ack-cursor.json",
    ));
    config
        .validate()
        .expect("cursor on stdout sink is valid without attestation");
}

#[test]
fn gate_input_reports_insecure_source_url() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        serde_norway::from_str(
            r#"
base_url: http://upstream.example
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    assert!(config.gate_input().source_insecure_url);
}

#[test]
fn gate_input_localhost_escape_is_not_an_insecure_url() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        serde_norway::from_str(
            r#"
base_url: http://127.0.0.1:9000
allow_insecure_localhost: true
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    let input = config.gate_input();
    assert!(!input.source_insecure_url);
}

#[test]
fn gate_input_reports_source_private_network_escape() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        serde_norway::from_str(
            r#"
base_url: http://10.0.0.1:9000
allow_insecure_private_network: true
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    assert!(config.gate_input().source_private_network_escape);
}

#[test]
fn gate_input_clears_source_private_network_escape_without_flag() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    assert!(!config.gate_input().source_private_network_escape);
}

#[test]
fn gate_input_reports_source_adapter_sidecar_without_expected_sidecar() {
    let mut config = minimal_config();
    // Insert a source connection with bulk_mode = source_adapter_sidecar_batch and
    // no expected_sidecar. We call gate_input() directly without validate()
    // because this projection test only checks the GateInput field.
    let mut conn: SourceConnectionConfig = serde_norway::from_str(
        r#"
base_url: https://source-adapter.example
token_env: SRC_TOKEN
"#,
    )
    .expect("source connection parses");
    conn.bulk_mode = BulkMode::SourceAdapterSidecarBatch;
    // expected_sidecar remains None by default.
    config
        .evidence
        .source_connections
        .insert("source-adapter-src".to_string(), conn);
    assert!(
        config
            .gate_input()
            .source_adapter_sidecar_without_expected_sidecar
    );
}

#[test]
fn gate_input_clears_source_adapter_sidecar_with_expected_sidecar() {
    let mut config = minimal_config();
    let mut conn: SourceConnectionConfig = serde_norway::from_str(
        r#"
base_url: https://source-adapter.example
token_env: SRC_TOKEN
expected_sidecar:
  product: source-adapter-notary-bridge
  instance_id: bridge-1
  environment: lab
  stream_id: stream-a
  config_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .expect("source connection with expected_sidecar parses");
    conn.bulk_mode = BulkMode::SourceAdapterSidecarBatch;
    config
        .evidence
        .source_connections
        .insert("source-adapter-src".to_string(), conn);
    assert!(
        !config
            .gate_input()
            .source_adapter_sidecar_without_expected_sidecar
    );
}

#[test]
fn gate_input_reports_assisted_access_transaction_token_posture() {
    let mut config = minimal_config();
    config.self_attestation.enabled = true;
    let input_without_anchor = config.gate_input();
    assert!(input_without_anchor.self_attestation_enabled);
    assert!(!input_without_anchor.transaction_token_anchor_configured);

    config.auth.access_token_signing.enabled = true;
    let input_with_anchor = config.gate_input();
    assert!(input_with_anchor.transaction_token_anchor_configured);
    assert!(
        !input_with_anchor.transaction_token_sender_constrained,
        "DPoP/mTLS proof validation is not implemented yet"
    );
}

#[test]
fn gate_input_reports_admin_shared_exposure() {
    let mut config = minimal_config();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    assert!(config.gate_input().admin_shared_exposure);
}

#[test]
fn gate_input_clears_admin_shared_exposure_when_listener_disabled() {
    let config = minimal_config();
    // Default admin listener mode is Disabled; shared exposure must be false.
    assert!(!config.gate_input().admin_shared_exposure);
}

#[test]
fn gate_input_reports_openapi_public() {
    let mut config = minimal_config();
    config.server.openapi_requires_auth = false;
    assert!(config.gate_input().openapi_public);
}

#[test]
fn gate_input_clears_openapi_public_when_auth_required() {
    let config = minimal_config();
    // Default requires auth; openapi_public must be false.
    assert!(!config.gate_input().openapi_public);
}

#[test]
fn gate_input_clears_config_unsigned_when_config_trust_configured() {
    let mut config = minimal_config();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    config.config_trust = Some(valid_config_trust());
    assert!(!config.gate_input().config_unsigned);
}

#[test]
fn gate_input_reports_config_unsigned_without_trust() {
    let config = minimal_config();
    // Minimal config has no config_trust block; must project as unsigned.
    assert!(config.gate_input().config_unsigned);
}

#[test]
fn gate_input_reports_insecure_source_url_non_triggering_with_https() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    assert!(!config.gate_input().source_insecure_url);
}

#[test]
fn gate_input_reports_source_binding_without_matching_policy() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency");
    claim
        .source_bindings
        .insert("registry".to_string(), rda_binding("registry_src", "one"));
    config.evidence.claims = vec![claim];
    assert!(config.gate_input().source_binding_without_matching_policy);
}

#[test]
fn gate_input_clears_source_binding_without_matching_policy_with_policy_id() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency");
    let mut binding = rda_binding("registry_src", "one");
    binding.matching.policy_id = Some("registry.residency.lookup.v1".to_string());
    claim
        .source_bindings
        .insert("registry".to_string(), binding);
    config.evidence.claims = vec![claim];
    assert!(!config.gate_input().source_binding_without_matching_policy);
}

#[test]
fn gate_input_clears_source_binding_without_matching_policy_with_purpose_gate() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency");
    let mut binding = rda_binding("registry_src", "one");
    binding.matching.allowed_purposes = vec!["benefits_screening".to_string()];
    claim
        .source_bindings
        .insert("registry".to_string(), binding);
    config.evidence.claims = vec![claim];
    assert!(!config.gate_input().source_binding_without_matching_policy);
}

#[test]
fn gate_input_clears_source_binding_without_matching_policy_with_ecosystem_binding() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency");
    let mut binding = rda_binding("registry_src", "one");
    binding.matching.ecosystem_binding = Some(EcosystemBindingSelectorConfig {
        policy_id: Some("policy:residency".to_string()),
        ..EcosystemBindingSelectorConfig::default()
    });
    claim
        .source_bindings
        .insert("registry".to_string(), binding);
    config.evidence.claims = vec![claim];
    assert!(!config.gate_input().source_binding_without_matching_policy);
}

#[test]
fn deployment_block_round_trips_through_yaml() {
    let mut config = minimal_config();
    config.deployment = serde_norway::from_str(
        r#"
profile: production
waivers:
  - finding: notary.openapi.public
    reason: synthetic partner integration waiver
    expires: 2099-09-30
"#,
    )
    .expect("deployment block parses");
    assert_eq!(
        config.deployment.profile,
        Some(crate::deployment::DeploymentProfile::Production)
    );
    config
        .validate()
        .expect("production config with waivable waiver validates");
}

#[test]
fn deployment_evidence_block_round_trips_through_yaml() {
    let mut config = minimal_config();
    config.deployment = serde_norway::from_str(
        r#"
profile: production
evidence:
  audit_offhost_shipping: true
"#,
    )
    .expect("deployment evidence block parses");
    assert!(config.deployment.evidence.audit_offhost_shipping);
}

#[test]
fn deployment_evidence_rejects_unknown_field_through_yaml() {
    let result: Result<crate::deployment::DeploymentConfig, _> = serde_norway::from_str(
        r#"
profile: production
evidence:
  audit_offhost_shipping: true
  made_up_field: true
"#,
    );
    assert!(
        result.is_err(),
        "unknown field inside deployment.evidence must fail deserialization"
    );
}

#[test]
fn invalid_profile_value_fails_config_load() {
    let result: Result<StandaloneRegistryNotaryConfig, _> = serde_norway::from_str(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
deployment:
  profile: prod
"#,
    );
    assert!(
        result.is_err(),
        "an invalid profile string must fail to load"
    );
}

fn use_dedicated_admin_listener(config: &mut StandaloneRegistryNotaryConfig) {
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
}

fn valid_config_trust() -> ConfigTrustConfig {
    ConfigTrustConfig {
        trust_anchor_path: PathBuf::from("/etc/registry-notary/config-anchor.json"),
        bundle_path: PathBuf::from("/etc/registry-notary/config-bundle"),
        antirollback_state_path: PathBuf::from(
            "/var/lib/registry-notary/config-state/antirollback.json",
        ),
        break_glass_override_path: None,
    }
}

fn minimal_claim(id: &str) -> ClaimDefinition {
    serde_norway::from_str(&format!(
        r#"
id: {id}
title: Test Claim
version: "1.0"
subject_type: person
rule:
  type: cel
  expression: "true"
"#
    ))
    .expect("minimal claim is valid YAML")
}

#[test]
fn config_trust_is_optional_but_requires_explicit_antirollback_path() {
    let mut config = minimal_config();
    assert!(config.config_trust.is_none());
    config.validate().expect("simple local config validates");
    use_dedicated_admin_listener(&mut config);

    let mut trust = valid_config_trust();
    trust.trust_anchor_path = PathBuf::from("");
    config.config_trust = Some(trust);
    let error = config
        .validate()
        .expect_err("empty trust-anchor path must fail validation");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidConfigTrustConfig { .. }
    ));

    let mut trust = valid_config_trust();
    trust.bundle_path = PathBuf::from("");
    config.config_trust = Some(trust);
    let error = config
        .validate()
        .expect_err("empty bundle path must fail validation");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidConfigTrustConfig { .. }
    ));

    let mut trust = valid_config_trust();
    trust.antirollback_state_path = PathBuf::from("");
    config.config_trust = Some(trust);
    let error = config
        .validate()
        .expect_err("empty anti-rollback path must fail validation");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidConfigTrustConfig { .. }
    ));

    let mut trust = valid_config_trust();
    trust.break_glass_override_path = Some(PathBuf::from(""));
    config.config_trust = Some(trust);
    let error = config
        .validate()
        .expect_err("empty break-glass override path must fail validation");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidConfigTrustConfig { .. }
    ));

    config.config_trust = Some(valid_config_trust());
    config
        .validate()
        .expect("explicit config bundle trust paths validate");
}

#[test]
fn cel_config_defaults_and_validates_operator_limits() {
    let mut config = minimal_config();
    assert_eq!(config.cel.mode, "worker");
    assert_eq!(config.cel.worker_count, 2);
    assert_eq!(config.cel.queue_max, 0);
    assert!(!config.cel.allow_regex);
    config.validate().expect("default CEL config validates");

    config.cel.queue_max = 1;
    let error = config
        .validate()
        .expect_err("queueing must be explicit and unsupported");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidCelConfig { .. }
    ));
}

#[test]
fn cel_config_deserializes_production_surface() {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
        r#"
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
cel:
  mode: worker
  worker_count: 4
  eval_timeout_ms: 1500
  queue_max: 0
  allow_regex: false
  max_expression_bytes: 4096
  max_binding_json_bytes: 32768
  max_result_json_bytes: 8192
  max_string_bytes: 4096
  max_list_items: 128
  max_object_depth: 8
  max_object_keys: 64
  worker_memory_bytes: 67108864
  worker_stderr_bytes: 512
"#,
    )
    .expect("CEL config deserializes");

    assert_eq!(config.cel.worker_count, 4);
    assert_eq!(config.cel.eval_timeout_ms, 1500);
    assert_eq!(config.cel.max_result_json_bytes, 8192);
    config.validate().expect("CEL config validates");
}

#[test]
fn matching_config_rejects_blank_policy_id() {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
        r#"
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  source_connections:
    registry:
      base_url: https://registry.example
      token_env: SOURCE_TOKEN
  claims:
    - id: person-is-alive
      title: Person is alive
      version: "1.0"
      subject_type: Person
      source_bindings:
        src:
          connector: registry_data_api
          connection: registry
          dataset: people
          entity: person
          lookup:
            input: target.attributes.birthdate
            field: birthdate
          matching:
            policy_id: ""
      rule:
        type: exists
        source: src
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
"#,
    )
    .expect("config shape parses");
    let err = config.validate().expect_err("blank policy id is rejected");
    assert!(matches!(
        err,
        EvidenceConfigError::InvalidMatchingConfig { .. }
    ));
}

#[test]
fn matching_context_constraints_deserialize_to_runtime_fields() {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
        r#"
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  source_connections:
    registry:
      base_url: https://registry.example
      token_env: SOURCE_TOKEN
  claims:
    - id: person-is-alive
      title: Person is alive
      version: "1.0"
      subject_type: Person
      source_bindings:
        src:
          connector: registry_data_api
          connection: registry
          dataset: people
          entity: person
          lookup:
            input: target.attributes.birthdate
            field: birthdate
          matching:
            context_constraints:
              legal_basis:
                required: true
                allowed_refs:
                  - law:birth-registration
              consent:
                required: true
                allowed_refs:
                  - consent:birth-registration
              jurisdiction:
                permitted:
                  - RW
              assurance:
                allowed:
                  - substantial
                minimum: substantial
              source_freshness:
                max_age_seconds: 86400
            source_observed_at_field: observed_at
      rule:
        type: exists
        source: src
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
"#,
    )
    .expect("nested context constraints deserialize");
    config
        .validate()
        .expect("nested context constraints validate");
    let matching = &config.evidence.claims[0].source_bindings["src"].matching;
    assert!(matching.require_legal_basis);
    assert!(matching.require_consent);
    assert_eq!(
        matching.allowed_legal_basis_refs,
        ["law:birth-registration"]
    );
    assert_eq!(
        matching.allowed_consent_refs,
        ["consent:birth-registration"]
    );
    assert_eq!(matching.permitted_jurisdictions, ["RW"]);
    assert_eq!(matching.allowed_assurance, ["substantial"]);
    assert_eq!(matching.minimum_assurance.as_deref(), Some("substantial"));
    assert_eq!(matching.max_source_age_seconds, Some(86400));
    assert_eq!(
        matching.source_observed_at_field.as_deref(),
        Some("observed_at")
    );
}

#[test]
fn matching_context_constraints_reject_conflicting_flattened_fields() {
    let cases = [
        (
            "legal basis allowed refs",
            r#"
allowed_legal_basis_refs:
  - law:existing
context_constraints:
  legal_basis:
    allowed_refs:
      - law:nested
"#,
            "context_constraints.legal_basis.allowed_refs",
        ),
        (
            "consent allowed refs",
            r#"
allowed_consent_refs:
  - consent:existing
context_constraints:
  consent:
    allowed_refs:
      - consent:nested
"#,
            "context_constraints.consent.allowed_refs",
        ),
        (
            "jurisdiction permitted list",
            r#"
permitted_jurisdictions:
  - RW
context_constraints:
  jurisdiction:
    permitted:
      - KE
"#,
            "context_constraints.jurisdiction.permitted",
        ),
        (
            "assurance allowed list",
            r#"
allowed_assurance:
  - substantial
context_constraints:
  assurance:
    allowed:
      - high
"#,
            "context_constraints.assurance.allowed",
        ),
        (
            "assurance minimum",
            r#"
minimum_assurance: substantial
context_constraints:
  assurance:
    minimum: high
"#,
            "context_constraints.assurance.minimum",
        ),
        (
            "source freshness",
            r#"
max_source_age_seconds: 60
context_constraints:
  source_freshness:
    max_age_seconds: 120
"#,
            "context_constraints.source_freshness.max_age_seconds",
        ),
    ];

    for (name, yaml, expected_path) in cases {
        let err = match serde_norway::from_str::<SourceMatchingConfig>(yaml) {
            Ok(_) => panic!("{name} should conflict"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains(expected_path),
            "expected {name} conflict to name {expected_path}, got {err}"
        );
    }
}

#[test]
fn matching_context_constraints_nested_allowed_refs_validate_blank_entries() {
    let ecosystem_bindings = BTreeMap::new();
    let matching: SourceMatchingConfig = serde_norway::from_str(
        r#"
context_constraints:
  legal_basis:
    allowed_refs:
      - law:benefits
      - " "
  consent:
    allowed_refs:
      - consent:benefits
"#,
    )
    .expect("nested allowed refs deserialize");
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("blank nested legal basis ref is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("allowed_legal_basis_refs")),
        "expected allowed_legal_basis_refs rejection, got {err:?}"
    );

    let matching: SourceMatchingConfig = serde_norway::from_str(
        r#"
context_constraints:
  legal_basis:
    allowed_refs:
      - law:benefits
  consent:
    allowed_refs:
      - consent:benefits
      - " "
"#,
    )
    .expect("nested allowed refs deserialize");
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("blank nested consent ref is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("allowed_consent_refs")),
        "expected allowed_consent_refs rejection, got {err:?}"
    );
}

#[test]
fn matching_config_rejects_blank_pdp_policy_entries() {
    let mut assurance = SourceMatchingConfig {
        allowed_assurance: vec!["substantial".to_string(), " ".to_string()],
        ..SourceMatchingConfig::default()
    };
    let ecosystem_bindings = BTreeMap::new();
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank assurance entry is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("allowed_assurance")),
        "expected allowed_assurance rejection, got {err:?}"
    );

    assurance.allowed_assurance.clear();
    assurance.minimum_assurance = Some(" ".to_string());
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank minimum assurance is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("minimum_assurance")),
        "expected minimum_assurance rejection, got {err:?}"
    );

    assurance.minimum_assurance = None;
    assurance.permitted_jurisdictions = vec!["RW".to_string(), " ".to_string()];
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank jurisdiction entry is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("permitted_jurisdictions")),
        "expected permitted_jurisdictions rejection, got {err:?}"
    );

    assurance.permitted_jurisdictions.clear();
    assurance.allowed_legal_basis_refs = vec!["legal-basis:benefits".to_string(), " ".to_string()];
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank legal basis ref is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("allowed_legal_basis_refs")),
        "expected allowed_legal_basis_refs rejection, got {err:?}"
    );

    assurance.allowed_legal_basis_refs.clear();
    assurance.allowed_consent_refs = vec!["consent:benefits".to_string(), " ".to_string()];
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank consent ref is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("allowed_consent_refs")),
        "expected allowed_consent_refs rejection, got {err:?}"
    );

    assurance.allowed_consent_refs.clear();
    assurance.redaction_fields = vec!["value".to_string(), " ".to_string()];
    let err = validate_source_matching_config("claim", "src", &assurance, &ecosystem_bindings)
        .expect_err("blank redaction entry is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("redaction_fields")),
        "expected redaction_fields rejection, got {err:?}"
    );
}

#[test]
fn matching_config_rejects_invalid_source_freshness_contract() {
    let ecosystem_bindings = BTreeMap::new();
    let mut matching = SourceMatchingConfig {
        max_source_age_seconds: Some(0),
        source_observed_at_field: Some("observed_at".to_string()),
        ..SourceMatchingConfig::default()
    };
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("zero max source age is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("max_source_age_seconds")),
        "expected max_source_age_seconds rejection, got {err:?}"
    );

    matching.max_source_age_seconds = Some(60);
    matching.source_observed_at_field = None;
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("missing source observed path is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("source_observed_at_field")),
        "expected source_observed_at_field rejection, got {err:?}"
    );

    matching.source_observed_at_field = Some(" ".to_string());
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("blank source observed path is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("source_observed_at_field")),
        "expected source_observed_at_field rejection, got {err:?}"
    );
}

#[test]
fn matching_config_selects_governed_ecosystem_binding_metadata() {
    let ecosystem_bindings = BTreeMap::from([(
        "civil-pack".to_string(),
        EvidenceEcosystemBindingConfig {
            profile: Some(SUPPORTED_ECOSYSTEM_BINDING_PROFILE.to_string()),
            policy_id: "evidence-pack-policy".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            unsupported_odrl_terms: Vec::new(),
        },
    )]);
    let matching = SourceMatchingConfig {
        ecosystem_binding: Some(EcosystemBindingSelectorConfig {
            id: Some("civil-pack".to_string()),
            profile: Some(SUPPORTED_ECOSYSTEM_BINDING_PROFILE.to_string()),
            ..EcosystemBindingSelectorConfig::default()
        }),
        ..SourceMatchingConfig::default()
    };

    validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect("selected governed ecosystem binding validates");
}

#[test]
fn matching_config_rejects_malformed_or_unsupported_selected_ecosystem_binding() {
    let mut ecosystem_bindings = BTreeMap::from([(
        "civil-pack".to_string(),
        EvidenceEcosystemBindingConfig {
            profile: Some("unsupported-profile".to_string()),
            policy_id: "evidence-pack-policy".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            unsupported_odrl_terms: Vec::new(),
        },
    )]);
    let matching = SourceMatchingConfig {
        ecosystem_binding: Some(EcosystemBindingSelectorConfig {
            id: Some("civil-pack".to_string()),
            ..EcosystemBindingSelectorConfig::default()
        }),
        ..SourceMatchingConfig::default()
    };
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("unsupported selected profile is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("unsupported ecosystem_binding profile")),
        "expected unsupported profile rejection, got {err:?}"
    );

    ecosystem_bindings
        .get_mut("civil-pack")
        .expect("binding exists")
        .profile = Some(SUPPORTED_ECOSYSTEM_BINDING_PROFILE.to_string());
    ecosystem_bindings
        .get_mut("civil-pack")
        .expect("binding exists")
        .policy_hash = "sha256:not-hex".to_string();
    let err = validate_source_matching_config("claim", "src", &matching, &ecosystem_bindings)
        .expect_err("malformed selected policy hash is rejected");
    assert!(
        matches!(err, EvidenceConfigError::InvalidMatchingConfig { ref reason, .. } if reason.contains("policy_hash")),
        "expected malformed policy_hash rejection, got {err:?}"
    );
}

#[test]
fn matching_config_accepts_config_local_ecosystem_binding_selector() {
    let matching = SourceMatchingConfig {
        ecosystem_binding: Some(EcosystemBindingSelectorConfig {
            profile: Some(SUPPORTED_ECOSYSTEM_BINDING_PROFILE.to_string()),
            policy_id: Some("local-policy".to_string()),
            policy_hash: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ),
            unsupported_odrl_terms: vec!["odrl:targetPolicy".to_string()],
            ..EcosystemBindingSelectorConfig::default()
        }),
        ..SourceMatchingConfig::default()
    };

    validate_source_matching_config("claim", "src", &matching, &BTreeMap::new())
        .expect("local ecosystem binding selector validates");
}

fn valid_self_attestation_config() -> StandaloneRegistryNotaryConfig {
    serde_norway::from_str(
        r#"
evidence:
  enabled: true
  source_connections:
    crvs:
      base_url: https://registry.example/source
      token_env: SOURCE_TOKEN
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer-key
      vct: https://issuer.example/credentials/civil-status
      validity_seconds: 600
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods:
          - did:jwk
      allowed_claims:
        - date-of-birth
      disclosure:
        allowed:
          - value
  claims:
    - id: date-of-birth
      title: Date of birth
      version: "1.0"
      subject_type: person
      purpose: citizen_self_attestation
      inputs:
        - name: subject_id
          type: string
      source_bindings:
        crvs:
          connector: dci
          connection: crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.identifiers.national_id
            field: NATIONAL_ID
            op: eq
            cardinality: one
      rule:
        type: exists
        source: crvs
      disclosure:
        default: value
        allowed:
          - value
      formats:
        - application/vnd.registry-notary.claim-result+json
        - application/dc+sd-jwt
      credential_profiles:
        - civil_status_sd_jwt
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/oauth/v2/keys
    audiences:
      - registry-notary-citizen
    allowed_clients:
      - citizen-portal
    scope_claim: scope
    scope_map:
      citizen_self_attestation:
        - self_attestation
    leeway: 30s
self_attestation:
  enabled: true
  requires_auth_mode: oidc
  subject_binding:
    token_claim: https://id.example.gov/claims/national_id
    request_field: SubjectId
    id_type: national_id
    normalize: exact
    allow_sub_as_civil_id: false
  citizen_clients:
    allowed_client_ids:
      - citizen-portal
    allowed_audiences:
      - registry-notary-citizen
  token_policy:
    required_acr_values:
      - urn:example:loa:substantial
    max_auth_age_seconds: 900
    max_access_token_lifetime_seconds: 900
    max_evaluation_age_seconds: 600
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: true
    issue_credential: true
    batch_evaluate: false
  allowed_purposes:
    - citizen_self_attestation
  allowed_claims:
    - date-of-birth
  allowed_formats:
    - application/vnd.registry-notary.claim-result+json
    - application/dc+sd-jwt
  allowed_disclosures:
    - value
  required_scopes:
    - self_attestation
  allowed_wallet_origins:
    - https://wallet.example.gov
  credential_profiles:
    - civil_status_sd_jwt
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
"#,
    )
    .expect("self-attestation config is valid YAML")
}

fn valid_delegated_self_attestation_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_self_attestation_config();
    let mut proof = config.evidence.claims[0].clone();
    proof.id = "guardian-link".to_string();
    proof.title = "Guardian link".to_string();
    proof.subject_type = "relationship".to_string();
    proof.purpose = Some("dependent_attestation".to_string());
    proof.rule = RuleConfig::Exists {
        source: "crvs".to_string(),
    };
    let proof_binding = proof
        .source_bindings
        .get_mut("crvs")
        .expect("proof source binding exists");
    proof_binding.connector = SourceConnectorKind::RegistryDataApi;
    proof_binding.entity = "guardian_link".to_string();
    proof_binding.lookup.input = "target.identifiers.civil_registration_id".to_string();
    proof_binding.lookup.field = "DEPENDENT_ID".to_string();
    proof_binding.query_fields = vec![SourceQueryFieldConfig {
        input: "requester.identifiers.national_id".to_string(),
        field: "GUARDIAN_ID".to_string(),
        op: "eq".to_string(),
    }];

    let mut dependent = config.evidence.claims[0].clone();
    dependent.id = "dependent-date-of-birth".to_string();
    dependent.title = "Dependent date of birth".to_string();
    dependent.purpose = Some("dependent_attestation".to_string());
    dependent.depends_on = vec!["guardian-link".to_string()];

    config.evidence.claims.push(proof);
    config.evidence.claims.push(dependent);
    config.self_attestation.delegation = SelfAttestationDelegationConfig {
        enabled: true,
        allowed_relationships: vec![SelfAttestationDelegatedRelationshipConfig {
            relationship_type: "guardian".to_string(),
            proof_claim: "guardian-link".to_string(),
            target_id_type: Some("civil_registration_id".to_string()),
            allowed_claims: vec!["dependent-date-of-birth".to_string()],
            allowed_purposes: vec!["dependent_attestation".to_string()],
            allowed_formats: vec![
                "application/vnd.registry-notary.claim-result+json".to_string(),
                "application/dc+sd-jwt".to_string(),
            ],
            allowed_disclosures: vec!["value".to_string()],
            credential_profiles: vec!["civil_status_sd_jwt".to_string()],
        }],
    };
    config
}

fn valid_oid4vci_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .vct = "http://127.0.0.1:4325/credentials/civil-status".to_string();
    config.oid4vci = serde_norway::from_str(
        r#"
enabled: true
credential_issuer: http://127.0.0.1:4325
authorization_servers:
  - http://localhost:8088/v1/esignet
accepted_token_audiences:
  - http://127.0.0.1:4325
credential_endpoint: http://127.0.0.1:4325/oid4vci/credential
offer_endpoint: http://127.0.0.1:4325/oid4vci/credential-offer
nonce_endpoint: http://127.0.0.1:4325/oid4vci/nonce
nonce:
  enabled: true
  ttl_seconds: 300
authorization:
  require_pkce_method: S256
proof:
  max_age_seconds: 300
  max_clock_skew_seconds: 30
credential_configurations:
  date_of_birth_sd_jwt:
    claim_id: date-of-birth
    credential_profile: civil_status_sd_jwt
    format: dc+sd-jwt
    scope: date-of-birth
    vct: http://127.0.0.1:4325/credentials/civil-status
    display_name: Date of birth
    proof_signing_alg_values_supported:
      - EdDSA
    cryptographic_binding_methods_supported:
      - did:jwk
"#,
    )
    .expect("oid4vci config is valid YAML");
    config
}

fn add_oid4vci_projection_claim(
    config: &mut StandaloneRegistryNotaryConfig,
    claim_id: &str,
    title: &str,
) {
    let mut claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "date-of-birth")
        .expect("base claim exists")
        .clone();
    claim.id = claim_id.to_string();
    claim.title = title.to_string();
    claim.credential_profiles = vec!["civil_status_sd_jwt".to_string()];
    config.evidence.claims.push(claim);
    config
        .self_attestation
        .allowed_claims
        .push(claim_id.to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("profile exists")
        .allowed_claims
        .push(claim_id.to_string());
}

fn valid_oid4vci_projection_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_oid4vci_config();
    add_oid4vci_projection_claim(&mut config, "birth-place", "Birth place");
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .expect("credential configuration exists");
    credential.claim_id = None;
    credential.claims = vec![
        Oid4vciCredentialClaimConfig {
            id: "date-of-birth".to_string(),
            output_path: vec!["birth_date".to_string()],
            display_name: "Date of birth".to_string(),
            sd: "always".to_string(),
        },
        Oid4vciCredentialClaimConfig {
            id: "birth-place".to_string(),
            output_path: vec!["birth_place_name".to_string()],
            display_name: "Birth place".to_string(),
            sd: "always".to_string(),
        },
    ];
    config
}

fn expect_self_attestation_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("self-attestation config must fail validation")
    {
        EvidenceConfigError::InvalidSelfAttestationConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

fn expect_oid4vci_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("oid4vci config must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

fn expect_federation_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("federation config must fail validation")
    {
        EvidenceConfigError::InvalidFederationConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

fn expect_replay_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("replay config must fail validation")
    {
        EvidenceConfigError::InvalidReplayConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

fn expect_credential_status_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("credential status config must fail validation")
    {
        EvidenceConfigError::InvalidCredentialStatusConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn admin_listener_defaults_to_disabled_for_simple_local_config() {
    let config = minimal_config();

    assert_eq!(
        config.server.admin_listener.mode,
        RegistryNotaryAdminListenerMode::Disabled
    );
    config
        .validate()
        .expect("simple local config may disable admin listener by default");
}

#[test]
fn server_limits_default_to_relay_parity_values() {
    let config = minimal_config();
    assert_eq!(config.server.request_timeout, Duration::from_secs(30));
    assert_eq!(config.server.request_body_timeout, Duration::from_secs(10));
    assert_eq!(
        config.server.http1_header_read_timeout,
        Duration::from_secs(10)
    );
    assert_eq!(config.server.max_connections, 1024);
}

#[test]
fn server_limits_must_be_nonzero() {
    let mut config = minimal_config();
    config.server.request_timeout = Duration::ZERO;
    config.server.request_body_timeout = Duration::ZERO;
    config.server.http1_header_read_timeout = Duration::ZERO;
    config.server.max_connections = 0;

    let err = config
        .validate()
        .expect_err("zero server limits must fail validation");
    match err {
        EvidenceConfigError::InvalidServerConfig { reason } => {
            assert!(reason.contains("server timeouts must be non-zero"));
            assert!(reason.contains("max_connections"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn governed_config_requires_dedicated_admin_listener() {
    let mut config = minimal_config();
    config.config_trust = Some(valid_config_trust());

    let error = config
        .validate()
        .expect_err("governed config must not default to shared admin listener");
    match error {
        EvidenceConfigError::InvalidServerConfig { reason } => {
            assert!(reason.contains("server.admin_listener.mode = dedicated"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    config
        .validate()
        .expect("governed config validates with dedicated admin listener");
}

#[test]
fn dedicated_admin_listener_must_not_reuse_public_bind() {
    let mut config = minimal_config();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    config.server.admin_listener.bind = config.server.bind;

    let error = config
        .validate()
        .expect_err("dedicated admin bind must differ from public bind");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidServerConfig { .. }
    ));
}

#[test]
fn replay_config_validates_redis_backend_shape() {
    let mut config = minimal_config();
    config.replay = serde_norway::from_str(
        r#"
storage: redis
redis:
  url_env: REGISTRY_NOTARY_REPLAY_REDIS_URL
  key_prefix: registry-notary-test
  connect_timeout_ms: 1000
  operation_timeout_ms: 500
"#,
    )
    .expect("redis replay config parses");

    config.validate().expect("redis replay config validates");

    config.replay.redis.url_env.clear();
    let reason = expect_replay_error(&config);
    assert!(reason.contains("url_env"), "unexpected: {reason}");
}

#[test]
fn credential_status_config_validates_redis_backend_shape() {
    let mut config = minimal_config();
    config.credential_status = serde_norway::from_str(
        r#"
enabled: true
base_url: https://issuer.example
storage: redis
redis:
  url_env: REGISTRY_NOTARY_STATUS_REDIS_URL
  key_prefix: registry-notary-test
  connect_timeout_ms: 1000
  operation_timeout_ms: 500
"#,
    )
    .expect("credential status config parses");

    config
        .validate()
        .expect("redis credential status config validates");

    config.credential_status.redis.url_env.clear();
    let reason = expect_credential_status_error(&config);
    assert!(reason.contains("url_env"), "unexpected: {reason}");
}

#[test]
fn credential_status_config_requires_base_url_when_enabled() {
    let mut config = minimal_config();
    config.credential_status = serde_norway::from_str(
        r#"
enabled: true
base_url: ""
"#,
    )
    .expect("credential status config parses");

    let reason = expect_credential_status_error(&config);
    assert!(
        reason.contains("credential_status.base_url"),
        "unexpected: {reason}"
    );
}

#[test]
fn audit_config_deserializes_rotation_and_syslog_fields() {
    let file: EvidenceAuditConfig = serde_norway::from_str(
        r#"
sink: file
path: /var/log/registry-notary/audit.jsonl
hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
max_size_mb: 4
max_files: 3
"#,
    )
    .expect("file audit config is valid YAML");

    assert_eq!(file.sink, "file");
    assert_eq!(
        file.path.as_deref(),
        Some("/var/log/registry-notary/audit.jsonl")
    );
    assert_eq!(file.max_size_bytes(), 4 * 1024 * 1024);
    assert_eq!(file.max_files(), 3);
    assert_eq!(file.syslog_socket_path, None);

    let syslog: EvidenceAuditConfig = serde_norway::from_str(
        r#"
sink: syslog
hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
syslog_socket_path: /dev/log
"#,
    )
    .expect("syslog audit config is valid YAML");

    assert_eq!(syslog.sink, "syslog");
    assert_eq!(syslog.path, None);
    assert_eq!(syslog.max_size_bytes(), 100 * 1024 * 1024);
    assert_eq!(syslog.max_files(), 14);
    assert_eq!(syslog.syslog_socket_path.as_deref(), Some("/dev/log"));
}

fn valid_federation_config() -> StandaloneRegistryNotaryConfig {
    let mut config = minimal_config();
    config
        .evidence
        .claims
        .push(minimal_claim("disability-status"));
    config.federation = FederationConfig {
        enabled: true,
        node_id: "did:web:agency-a.example.gov".to_string(),
        issuer: "https://agency-a.example.gov".to_string(),
        jwks_uri: "https://agency-a.example.gov/federation/jwks.json".to_string(),
        federation_api: "https://agency-a.example.gov/federation/v1".to_string(),
        supported_protocol_versions: vec![FEDERATION_PROTOCOL_V0_1.to_string()],
        signing: FederationSigningConfig {
            signing_key: "federation-key".to_string(),
        },
        pairwise_subject_hash: FederationPairwiseSubjectHashConfig {
            secret_env: "FEDERATION_PAIRWISE_SECRET".to_string(),
        },
        peers: vec![FederationPeerConfig {
            node_id: "did:web:agency-b.example.gov".to_string(),
            issuer: "https://agency-b.example.gov".to_string(),
            jwks_uri: "https://agency-b.example.gov/federation/jwks.json".to_string(),
            allowed_protocol_versions: vec![FEDERATION_PROTOCOL_V0_1.to_string()],
            allowed_purposes: vec![
                "https://purpose.example.gov/social-protection/service-delivery".to_string(),
            ],
            allowed_profiles: vec!["disability_status_predicate".to_string()],
            source_scopes: vec!["civil_registry:evidence_verification".to_string()],
            ..FederationPeerConfig::default()
        }],
        evaluation_profiles: vec![FederationEvaluationProfileConfig {
            id: "disability_status_predicate".to_string(),
            ruleset: "disability-status-v1".to_string(),
            claim_id: "disability-status".to_string(),
            subject_id_type: "national_id".to_string(),
            disclosure: Some("predicate".to_string()),
            max_source_observed_age_seconds: Some(300),
            ..FederationEvaluationProfileConfig::default()
        }],
        ..FederationConfig::default()
    };
    config.evidence.signing_keys.insert(
        "federation-key".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: FEDERATION_SIGNING_ALG_EDDSA.to_string(),
            kid: "agency-a-fed-1".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "FEDERATION_SIGNING_KEY".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    config
}

#[test]
fn federation_config_validates_enabled_mvp_shape() {
    valid_federation_config()
        .validate()
        .expect("federation config validates");
}

#[test]
fn federation_signing_key_must_reference_active_named_signing_key() {
    let mut config = valid_federation_config();
    config.federation.signing.signing_key = "missing-key".to_string();
    let reason = expect_federation_error(&config);
    assert!(
        reason.contains("unknown signing key 'missing-key'"),
        "unexpected: {reason}"
    );

    config = valid_federation_config();
    let federation_key = config
        .evidence
        .signing_keys
        .get_mut("federation-key")
        .expect("federation signing key exists");
    federation_key.status = SigningKeyStatus::PublishOnly;
    federation_key.private_jwk_env = String::new();
    federation_key.public_jwk_env = "FEDERATION_SIGNING_PUBLIC_KEY".to_string();
    let reason = expect_federation_error(&config);
    assert!(
        reason.contains("must reference an active signing key"),
        "unexpected: {reason}"
    );
}

#[test]
fn federation_legacy_redis_replay_requires_top_level_redis_replay() {
    let mut config = valid_federation_config();
    config.federation.replay.storage = REPLAY_STORAGE_REDIS.to_string();

    let reason = expect_federation_error(&config);
    assert!(
        reason.contains("top-level replay.storage = redis"),
        "unexpected: {reason}"
    );

    config.replay = ReplayConfig {
        storage: REPLAY_STORAGE_REDIS.to_string(),
        redis: ReplayRedisConfig {
            url_env: "REGISTRY_NOTARY_REPLAY_REDIS_URL".to_string(),
            ..ReplayRedisConfig::default()
        },
    };
    config
        .validate()
        .expect("matching top-level redis replay validates");
}

#[test]
fn federation_peer_private_network_jwks_escape_hatch_deserializes_and_validates() {
    let mut config = valid_federation_config();
    let peer: FederationPeerConfig = serde_norway::from_str(
        r#"
node_id: did:web:agency-b.example.gov
issuer: https://agency-b.example.gov
jwks_uri: http://federation-peer-jwks:8080/jwks.json
allow_insecure_private_network: true
allowed_protocol_versions:
  - registry-notary-federation/v0.1
allowed_purposes:
  - https://purpose.example.gov/social-protection/service-delivery
allowed_profiles:
  - disability_status_predicate
source_scopes:
  - civil_registry:evidence_verification
"#,
    )
    .expect("private-network peer YAML parses");
    assert!(peer.allow_insecure_private_network);
    config.federation.peers = vec![peer];
    config
        .validate()
        .expect("private-network peer JWKS is accepted only with explicit opt-in");
}

#[test]
fn federation_peer_http_private_network_jwks_requires_escape_hatch() {
    let mut config = valid_federation_config();
    config.federation.peers[0].jwks_uri = "http://federation-peer-jwks:8080/jwks.json".to_string();
    let reason = expect_federation_error(&config);
    assert!(reason.contains("jwks_uri must be an HTTPS URL"));
}

#[test]
fn federation_config_rejects_bad_did_issuer_binding() {
    let mut config = valid_federation_config();
    config.federation.issuer = "https://other-agency.example.gov".to_string();
    let reason = expect_federation_error(&config);
    assert!(reason.contains("node_id must bind"));
}

#[test]
fn federation_config_rejects_missing_protocol_and_bad_profile_reference() {
    let mut missing_protocol = valid_federation_config();
    missing_protocol
        .federation
        .supported_protocol_versions
        .clear();
    let reason = expect_federation_error(&missing_protocol);
    assert!(reason.contains("supported_protocol_versions"));

    let mut bad_profile = valid_federation_config();
    bad_profile.federation.evaluation_profiles[0].claim_id = "unknown".to_string();
    let reason = expect_federation_error(&bad_profile);
    assert!(reason.contains("claim_id must reference"));
}

#[test]
fn federation_profile_disclosure_must_be_known_profile() {
    let mut config = valid_federation_config();
    config.federation.evaluation_profiles[0].disclosure = Some("raw".to_string());
    let reason = expect_federation_error(&config);
    assert!(reason.contains("disclosure must be value, predicate, or redacted"));
}

// -----------------------------------------------------------------------
// Finding 3: holder binding / did-method mismatch
// -----------------------------------------------------------------------

#[test]
fn proof_of_possession_required_with_only_did_jwk_is_valid() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    assert!(
        config.validate().is_ok(),
        "did:jwk only should pass validation"
    );
}

#[test]
fn credential_profile_format_must_use_current_sd_jwt_vc_media_type() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: sd_jwt_vc
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("legacy-alias".to_string(), profile);

    let err = config
        .validate()
        .expect_err("legacy profile format alias must fail validation");
    match err {
        EvidenceConfigError::UnsupportedCredentialProfileFormat { profile, format } => {
            assert_eq!(profile, "legacy-alias");
            assert_eq!(format, "sd_jwt_vc");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn credential_profile_default_validity_is_short_lived() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.validity_seconds, 600);
}

#[test]
fn credential_profile_default_holder_binding_is_did_jwk() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.holder_binding.mode, "did");
    assert_eq!(
        profile.holder_binding.allowed_did_methods,
        vec!["did:jwk".to_string()]
    );
    assert!(profile.holder_binding.proof_of_possession.is_none());
}

#[test]
fn credential_profile_can_explicitly_opt_out_of_holder_binding() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: none
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.holder_binding.mode, "none");
    assert_eq!(
        profile.holder_binding.allowed_did_methods,
        vec!["did:jwk".to_string()]
    );
}

#[test]
fn credential_profile_explicit_validity_is_honored() {
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
validity_seconds: 300
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");

    assert_eq!(profile.validity_seconds, 300);
}

#[test]
fn credential_profile_validity_above_general_ceiling_is_rejected() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://vct.example/test
validity_seconds: 601
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("long-lived".to_string(), profile);

    let err = config
        .validate()
        .expect_err("over-ceiling credential validity must fail");
    assert!(matches!(
        err,
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile,
            validity_seconds: 601,
            max_validity_seconds: 600
        } if profile == "long-lived"
    ));
}

#[test]
fn credential_profile_non_positive_validity_is_rejected() {
    for invalid in [0, -1] {
        let mut config = minimal_config();
        let mut profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");
        profile.validity_seconds = invalid;
        config
            .evidence
            .credential_profiles
            .insert("invalid-validity".to_string(), profile);

        let err = config
            .validate()
            .expect_err("non-positive credential validity must fail");
        assert!(matches!(
            err,
            EvidenceConfigError::InvalidCredentialProfileValidity { .. }
        ));
    }
}

#[test]
fn signing_keys_are_configured_separately_from_credential_profiles() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2026:
  provider: local_jwk_env
  private_jwk_env: ISSUER_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2026
  status: active
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-2026
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    config
        .validate()
        .expect("profile may reference an active signing key");
}

#[test]
fn credential_profiles_must_reference_active_signing_keys() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-2025
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("publish-only keys must not be used for new issuance");
    match err {
        EvidenceConfigError::CredentialProfileSigningKeyNotActive { profile, key } => {
            assert_eq!(profile, "test-profile");
            assert_eq!(key, "issuer-2025");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn publish_only_local_jwk_uses_public_jwk_env_only() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  private_jwk_env: OLD_ISSUER_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("publish-only local keys must not require private material");
    assert!(
        err.to_string().contains("public_jwk_env must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn publish_only_signing_key_accepts_bounded_publication_window() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-2025:
  provider: local_jwk_env
  public_jwk_env: OLD_ISSUER_PUBLIC_KEY
  alg: EdDSA
  kid: did:web:issuer.example#issuer-2025
  status: publish_only
  publish_until_unix_seconds: 1893456000
"#,
    )
    .expect("signing key YAML is valid");

    let key = config
        .evidence
        .signing_keys
        .get("issuer-2025")
        .expect("publish-only key exists");
    assert_eq!(key.publish_until_unix_seconds, Some(1_893_456_000));
    assert!(key.may_publish_at(1_893_456_000));
    assert!(!key.may_publish_at(1_893_456_001));
    config
        .validate()
        .expect("publish-only key may carry a publication deadline");
}

#[test]
fn active_signing_key_rejects_publication_window() {
    let mut config = minimal_config();
    let active = config
        .evidence
        .signing_keys
        .values_mut()
        .find(|key| key.status == SigningKeyStatus::Active)
        .expect("minimal config has an active key");
    active.publish_until_unix_seconds = Some(1_893_456_000);

    let err = config
        .validate()
        .expect_err("active signing keys cannot carry a publication deadline");
    assert!(
        err.to_string()
            .contains("publish_until_unix_seconds is valid only for publish_only signing keys"),
        "unexpected error: {err}"
    );
}

#[test]
fn pkcs11_signing_key_shape_validates_without_loading_module() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-hsm
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    config.validate().expect("PKCS#11 key shape validates");
}

#[test]
fn file_watch_signing_key_shape_validates_without_secret_material_in_config() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  path: /run/secrets/issuer.jwk
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-file
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    config.validate().expect("file-watch key shape validates");
}

#[test]
fn file_watch_signing_key_rejects_secret_fields_and_missing_path() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("file-watch key must use a local path");
    assert!(
        err.to_string().contains("path must not be empty"),
        "unexpected error: {err}"
    );

    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-file:
  provider: file_watch
  path: /run/secrets/issuer.jwk
  private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-file
  status: active
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("file-watch key must not carry env-backed private material");
    assert!(
        err.to_string()
            .contains("private_jwk_env is not valid for this signing key provider"),
        "unexpected error: {err}"
    );
}

#[test]
fn pkcs11_signing_key_requires_absolute_module_path() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("relative module path must fail validation");
    assert!(
        err.to_string().contains("module_path must be absolute"),
        "unexpected error: {err}"
    );
}

#[test]
fn pkcs11_signing_key_rejects_rs256_algorithm() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: registry-notary
  pin_env: REGISTRY_NOTARY_PKCS11_PIN
  key_label: issuer-signing-key
  key_id_hex: 01ab23cd
  public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
  alg: RS256
  kid: did:web:issuer.example#issuer-hsm
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("PKCS#11 signing only supports EdDSA");
    assert!(
        err.to_string()
            .contains("pkcs11 provider supports only EdDSA"),
        "unexpected error: {err}"
    );
}

#[test]
fn publish_only_pkcs11_key_uses_public_jwk_env_only() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm-old:
  provider: pkcs11
  public_jwk_env: REGISTRY_NOTARY_OLD_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm-old
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");

    config
        .validate()
        .expect("publish-only PKCS#11 key needs only public metadata");

    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-hsm-old:
  provider: pkcs11
  module_path: /usr/lib/softhsm/libsofthsm2.so
  public_jwk_env: REGISTRY_NOTARY_OLD_ISSUER_PUBLIC_JWK
  alg: EdDSA
  kid: did:web:issuer.example#issuer-hsm-old
  status: publish_only
"#,
    )
    .expect("signing key YAML is valid");
    let err = config
        .validate()
        .expect_err("publish-only PKCS#11 key must not require HSM access");
    assert!(
        err.to_string()
            .contains("module_path is not valid for this signing key provider"),
        "unexpected error: {err}"
    );
}

#[test]
fn local_pkcs12_file_provider_is_deferred_without_partial_support() {
    let mut config = minimal_config();
    config.evidence.signing_keys = serde_norway::from_str(
        r#"
issuer-p12:
  provider: local_pkcs12_file
  path: /run/secrets/issuer.p12
  password_env: REGISTRY_NOTARY_P12_PASSWORD
  alg: EdDSA
  kid: did:web:issuer.example#issuer-p12
  status: active
"#,
    )
    .expect("signing key YAML is valid");

    let err = config
        .validate()
        .expect_err("PKCS#12 support must fail closed until it is implemented");
    assert!(
        err.to_string()
            .contains("local_pkcs12_file provider is intentionally not implemented yet"),
        "unexpected error: {err}"
    );
}

#[test]
fn proof_of_possession_required_with_non_jwk_method_is_rejected() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
    - did:key
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("did:key with proof_of_possession required must fail");
    match &err {
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { profile, methods } => {
            assert_eq!(profile, "test-profile");
            assert!(
                methods.contains(&"did:key".to_string()),
                "error must name did:key, got: {methods:?}"
            );
            assert!(
                !methods.contains(&"did:jwk".to_string()),
                "did:jwk must not appear in the unsupported list"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn non_jwk_methods_are_rejected_even_without_proof_of_possession() {
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
holder_binding:
  mode: did
  allowed_did_methods:
    - did:jwk
    - did:key
    - did:web
allowed_claims:
  - some-claim
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("test-profile".to_string(), profile);
    let err = config
        .validate()
        .expect_err("non-did:jwk holder methods must fail validation");
    match &err {
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { profile, methods } => {
            assert_eq!(profile, "test-profile");
            assert_eq!(methods, &vec!["did:key".to_string(), "did:web".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Finding 8: depends_on cycle detection
// -----------------------------------------------------------------------

#[test]
fn valid_dag_passes_cycle_detection() {
    // A -> B -> C (no cycle)
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-b".to_string()];
    let mut claim_b = minimal_claim("claim-b");
    claim_b.depends_on = vec!["claim-c".to_string()];
    let claim_c = minimal_claim("claim-c");
    config.evidence.claims = vec![claim_a, claim_b, claim_c];
    assert!(config.validate().is_ok(), "A->B->C DAG should pass");
}

#[test]
fn two_node_cycle_is_detected() {
    // A -> B -> A
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-b".to_string()];
    let mut claim_b = minimal_claim("claim-b");
    claim_b.depends_on = vec!["claim-a".to_string()];
    config.evidence.claims = vec![claim_a, claim_b];

    let err = config
        .validate()
        .expect_err("A->B->A cycle must fail validation");
    match &err {
        EvidenceConfigError::DependsOnCycle { cycle } => {
            assert!(
                cycle.contains(&"claim-a".to_string()),
                "cycle must mention claim-a, got: {cycle:?}"
            );
            assert!(
                cycle.contains(&"claim-b".to_string()),
                "cycle must mention claim-b, got: {cycle:?}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn self_loop_is_detected() {
    // A -> A
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-a".to_string()];
    config.evidence.claims = vec![claim_a];

    let err = config
        .validate()
        .expect_err("self-loop must fail validation");
    match &err {
        EvidenceConfigError::DependsOnCycle { cycle } => {
            assert!(
                cycle.contains(&"claim-a".to_string()),
                "cycle must mention claim-a, got: {cycle:?}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn unknown_depends_on_is_rejected() {
    let mut config = minimal_config();
    let mut claim_a = minimal_claim("claim-a");
    claim_a.depends_on = vec!["claim-nonexistent".to_string()];
    config.evidence.claims = vec![claim_a];

    let err = config
        .validate()
        .expect_err("depends_on unknown claim must fail validation");
    match &err {
        EvidenceConfigError::DependsOnUnknownClaim { claim, unknown } => {
            assert_eq!(claim, "claim-a");
            assert_eq!(unknown, "claim-nonexistent");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// GH#170 / RS-DM-CLAIM Section 10: load-time validation for invariants
// the loader previously deferred to request/evaluation time.
// -----------------------------------------------------------------------

#[test]
fn duplicate_claim_id_is_rejected() {
    // REQ-DM-CLAIM-001: two claims sharing an id previously loaded
    // cleanly; the loader must now reject it.
    let mut config = minimal_config();
    let claim_a = minimal_claim("repeated-id");
    let claim_b = minimal_claim("repeated-id");
    config.evidence.claims = vec![claim_a, claim_b];

    let err = config
        .validate()
        .expect_err("duplicate claim id must fail validation");
    match &err {
        EvidenceConfigError::DuplicateClaimId { claim } => {
            assert_eq!(claim, "repeated-id");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    assert!(
        err.to_string().contains("repeated-id"),
        "error must name the offending claim id: {err}"
    );
}

#[test]
fn disclosure_default_outside_allowed_is_rejected() {
    // REQ-DM-CLAIM-008: a disclosure default outside the allowed set
    // previously surfaced only when a result was rendered. This is the
    // most consequential of the three Section 10 gaps: a
    // privacy-sensitive claim could otherwise ship an internally
    // inconsistent disclosure policy that only fails on first render.
    let mut config = minimal_config();
    let mut claim = minimal_claim("residency-status");
    claim.disclosure = DisclosureConfig {
        default: "value".to_string(),
        allowed: vec!["redacted".to_string()],
        downgrade: "deny".to_string(),
    };
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("disclosure default outside allowed must fail validation");
    match &err {
        EvidenceConfigError::ClaimDisclosureDefaultNotAllowed {
            claim,
            default,
            allowed,
        } => {
            assert_eq!(claim, "residency-status");
            assert_eq!(default, "value");
            assert_eq!(allowed, &vec!["redacted".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("residency-status") && message.contains("disclosure"),
        "error must name the offending claim id and field: {message}"
    );
}

#[test]
fn rule_source_referencing_unknown_binding_is_rejected() {
    // REQ-DM-CLAIM-006: a rule whose source doesn't name a declared
    // source binding previously surfaced only when the source was read
    // at evaluation; the loader must now reject it.
    let mut config = minimal_config();
    let mut claim = minimal_claim("farmer-registered");
    claim.rule = RuleConfig::Exists {
        source: "nonexistent".to_string(),
    };
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("rule source naming an undeclared binding must fail validation");
    match &err {
        EvidenceConfigError::UnknownRuleSourceBinding { claim, rule_source } => {
            assert_eq!(claim, "farmer-registered");
            assert_eq!(rule_source, "nonexistent");
        }
        other => panic!("unexpected error variant: {other}"),
    }
    let message = err.to_string();
    assert!(
        message.contains("farmer-registered") && message.contains("nonexistent"),
        "error must name the offending claim id and field: {message}"
    );
}

#[test]
fn claim_config_with_consistent_id_disclosure_and_rule_source_still_loads() {
    // Sanity check: a claim configuration that satisfies all three
    // Section 10 invariants (unique id, disclosure default in allowed,
    // rule source naming a declared binding) still loads.
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://registry.example
token_env: SOURCE_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    let mut claim = minimal_claim("residency-status");
    claim.rule = RuleConfig::Exists {
        source: "registry".to_string(),
    };
    claim.disclosure = DisclosureConfig {
        default: "redacted".to_string(),
        allowed: vec!["redacted".to_string(), "value".to_string()],
        downgrade: "deny".to_string(),
    };
    claim
        .source_bindings
        .insert("registry".to_string(), rda_binding("registry", "one"));
    config.evidence.claims = vec![claim];

    config
        .validate()
        .expect("consistent claim configuration must still load");
}

#[test]
fn empty_allowed_claims_is_rejected() {
    // A credential profile with an empty allowed_claims would silently
    // accept every claim at issue time (see api.rs `is_empty()` short
    // circuit). Reject at config-load time so the operator must opt in.
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("the_profile_id".to_string(), profile);

    let err = config
        .validate()
        .expect_err("empty allowed_claims must fail validation");
    match &err {
        EvidenceConfigError::EmptyAllowedClaims { profile } => {
            assert_eq!(profile, "the_profile_id");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Stage 1: concurrency config and the kill-switch
// -----------------------------------------------------------------------

#[test]
fn default_concurrency_has_documented_defaults() {
    let cfg = ConcurrencyConfig::default();
    assert_eq!(cfg.subjects, 16);
    assert_eq!(cfg.bindings, 8);
    assert!(cfg.validate().is_ok());
}

#[test]
fn concurrency_zero_subjects_is_rejected() {
    let mut config = minimal_config();
    config.evidence.concurrency = ConcurrencyConfig {
        subjects: 0,
        bindings: 1,
    };
    let err = config
        .validate()
        .expect_err("subjects=0 must fail validation");
    assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
}

#[test]
fn concurrency_zero_bindings_is_rejected() {
    let mut config = minimal_config();
    config.evidence.concurrency = ConcurrencyConfig {
        subjects: 1,
        bindings: 0,
    };
    let err = config
        .validate()
        .expect_err("bindings=0 must fail validation");
    assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
}

#[test]
fn kill_switch_subjects_one_bindings_one_validates() {
    // The documented kill switch: concurrency.subjects=1 and
    // concurrency.bindings=1 reproduces today's strictly-sequential
    // behavior. Must validate successfully.
    let mut config = minimal_config();
    config.evidence.concurrency = ConcurrencyConfig {
        subjects: 1,
        bindings: 1,
    };
    assert!(config.validate().is_ok());
}

// -----------------------------------------------------------------------
// Machine quota config
// -----------------------------------------------------------------------

#[test]
fn machine_quota_defaults_to_disabled_with_documented_limit() {
    let cfg = MachineQuotaConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.subjects_per_minute, 6000);
    assert!(cfg.validate().is_ok());
}

#[test]
fn machine_quota_disabled_zero_limit_still_validates() {
    // A zero subjects_per_minute is only invalid once the quota is
    // enabled; an operator-provided but unused value must not block
    // deployments that leave the quota off.
    let cfg = MachineQuotaConfig {
        enabled: false,
        subjects_per_minute: 0,
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn machine_quota_enabled_zero_limit_is_rejected() {
    let mut config = minimal_config();
    config.evidence.machine_quota = MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 0,
    };
    let err = config
        .validate()
        .expect_err("enabled machine_quota with subjects_per_minute=0 must fail validation");
    match &err {
        EvidenceConfigError::InvalidMachineQuotaConfig { reason } => {
            assert!(reason.contains("subjects_per_minute"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn machine_quota_enabled_with_positive_limit_validates() {
    let mut config = minimal_config();
    config.evidence.machine_quota = MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 1,
    };
    assert!(config.validate().is_ok());
}

#[test]
fn oidc_auth_mode_requires_oidc_block() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;

    let err = config
        .validate()
        .expect_err("oidc mode requires OIDC settings");

    assert!(matches!(err, EvidenceConfigError::MissingOidcConfig));
}

#[test]
fn oidc_auth_mode_validates_required_settings() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "https://issuer.example/jwks.json".to_string(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: false,
    });

    assert!(config.validate().is_ok());
}

#[test]
fn duplicate_static_credential_api_key_id_rejected() {
    let mut config = minimal_config();
    let duplicate = config.auth.api_keys[0].clone();
    config.auth.api_keys.push(duplicate);

    let reason = match config
        .validate()
        .expect_err("duplicate API key id must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.api_keys") && reason.contains("test-key"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn duplicate_static_credential_bearer_token_id_rejected() {
    let mut config = minimal_config();
    let mut token = config.auth.api_keys[0].clone();
    token.id = "shared-bearer-token".to_string();
    config.auth.bearer_tokens.push(token.clone());
    config.auth.bearer_tokens.push(token);

    let reason = match config
        .validate()
        .expect_err("duplicate bearer token id must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.bearer_tokens") && reason.contains("shared-bearer-token"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn duplicate_static_credential_id_across_api_key_and_bearer_token_rejected() {
    let mut config = minimal_config();
    config
        .auth
        .bearer_tokens
        .push(config.auth.api_keys[0].clone());

    let reason = match config
        .validate()
        .expect_err("duplicate static credential id across types must fail validation")
    {
        EvidenceConfigError::InvalidAuthConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.bearer_tokens") && reason.contains("test-key"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn oidc_jwks_url_must_use_https() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "http://issuer.example/jwks.json".to_string(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: false,
    });

    let err = config
        .validate()
        .expect_err("remote http jwks_url must fail validation");
    match err {
        EvidenceConfigError::InvalidOidcConfig { reason } => {
            assert!(
                reason.contains("jwks_url must use https"),
                "unexpected: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }

    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .allow_insecure_localhost = true;
    let err = config
        .validate()
        .expect_err("allow_insecure_localhost must not permit remote http");
    assert!(matches!(err, EvidenceConfigError::InvalidOidcConfig { .. }));
}

#[test]
fn oidc_jwks_url_allows_insecure_localhost_only_when_enabled() {
    let mut config = minimal_config();
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_url: "http://127.0.0.1:8080/jwks.json".to_string(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: false,
    });

    let err = config
        .validate()
        .expect_err("localhost http jwks_url needs explicit opt-in");
    assert!(matches!(err, EvidenceConfigError::InvalidOidcConfig { .. }));

    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .allow_insecure_localhost = true;
    config
        .validate()
        .expect("localhost http jwks_url is allowed only with the opt-in");
}

#[test]
fn api_key_plaintext_is_never_loaded_only_fingerprint() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      token_env: TEST_TOKEN
"#,
    )
    .expect_err("plaintext token_env is not part of the credential schema");

    assert!(
        err.to_string().contains("unknown field `token_env`"),
        "unexpected error: {err}"
    );
}

#[test]
fn legacy_api_key_fingerprint_commitment_rejected() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
        commitment: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .expect_err("legacy fingerprint commitment must fail deserialization");

    assert!(
        err.to_string()
            .contains("fingerprint.commitment was removed"),
        "unexpected error: {err}"
    );
}

#[test]
fn legacy_bearer_token_fingerprint_commitment_rejected() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: api_key
  bearer_tokens:
    - id: test-bearer
      fingerprint:
        provider: env
        name: TEST_BEARER_HASH
        commitment: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .expect_err("legacy bearer token fingerprint commitment must fail deserialization");

    assert!(
        err.to_string()
            .contains("fingerprint.commitment was removed"),
        "unexpected error: {err}"
    );
}

#[test]
fn unsupported_auth_mode_is_rejected_at_parse_time() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oauth2
"#,
    )
    .expect_err("unknown auth mode must fail deserialization");

    let message = err.to_string();
    assert!(
        message.contains("oauth2") || message.contains("unknown variant"),
        "unexpected error: {message}"
    );
}

#[test]
fn oidc_auth_rejects_static_credentials() {
    let mut config = valid_self_attestation_config();
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "legacy-api-key".to_string(),
        fingerprint: CredentialFingerprintRef {
            provider: registry_platform_authcommon::CredentialFingerprintProvider::Env,
            name: Some("LEGACY_API_KEY_HASH".to_string()),
            path: None,
        },
        scopes: vec!["self_attestation".to_string()],
        authorization_details: None,
    });

    let reason = match config
        .validate()
        .expect_err("OIDC mode must not accept static credentials")
    {
        EvidenceConfigError::InvalidOidcConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };

    assert!(
        reason.contains("auth.api_keys"),
        "unexpected error reason: {reason}"
    );
}

#[test]
fn source_connection_max_in_flight_zero_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "UPSTREAM_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 0,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("max_in_flight=0 must fail validation");
    assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
}

#[test]
fn source_connection_max_in_flight_defaults_to_eight() {
    // The YAML default for `max_in_flight` must be 8; operators do not
    // need to set it explicitly to get the documented politeness cap.
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(!connection.allow_insecure_localhost);
    assert!(!connection.allow_insecure_private_network);
    assert_eq!(connection.max_in_flight, 8);
}

#[test]
fn source_connection_private_network_escape_hatch_deserializes() {
    let yaml = r#"
base_url: http://registry-relay:8080
allow_insecure_private_network: true
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(connection.allow_insecure_private_network);
}

#[test]
fn source_connection_oauth_auth_deserializes_without_static_token() {
    let yaml = r#"
base_url: https://registry.example
source_auth:
  type: oauth2_client_credentials
  token_url: https://registry.example/oauth/token
  client_id_env: SOURCE_CLIENT_ID
  client_secret_env: SOURCE_CLIENT_SECRET
  request_format: json
  scope: registry.read
  refresh_skew_seconds: 30
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(connection.token_env.is_empty());
    let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = connection.source_auth else {
        panic!("oauth source auth should deserialize");
    };
    assert_eq!(auth.request_format, "json");
    assert_eq!(auth.scope, "registry.read");
    assert_eq!(auth.refresh_skew_seconds, 30);
}

#[test]
fn source_connection_rejects_static_token_and_source_auth_together() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://upstream.example/oauth/token".to_string(),
                    client_id_env: "SRC_CLIENT_ID".to_string(),
                    client_secret_env: "SRC_CLIENT_SECRET".to_string(),
                    request_format: "json".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("token_env and source_auth must conflict");
    assert!(matches!(
        err,
        EvidenceConfigError::InvalidSourceAuthConfig { .. }
    ));
}

#[test]
fn source_connection_rejects_unknown_oauth_request_format() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://upstream.example/oauth/token".to_string(),
                    client_id_env: "SRC_CLIENT_ID".to_string(),
                    client_secret_env: "SRC_CLIENT_SECRET".to_string(),
                    request_format: "xml".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("unsupported oauth request_format must fail validation");
    match err {
        EvidenceConfigError::InvalidSourceAuthConfig { reason, .. } => {
            assert!(reason.contains("json or form"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Stage 3: bulk_mode validation
// -----------------------------------------------------------------------

fn rda_binding(connection: &str, cardinality: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::RegistryDataApi,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "farmer_registry".to_string(),
        entity: "farmer".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
            cardinality: cardinality.to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

fn dci_binding(connection: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::Dci,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "farmer_registry".to_string(),
        entity: "farmer".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "id_type".to_string(),
            op: "eq".to_string(),
            cardinality: "one".to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

fn source_adapter_sidecar_binding(connection: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::SourceAdapterSidecar,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "civil_registry".to_string(),
        entity: "civil_person".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "national_id".to_string(),
            op: "eq".to_string(),
            cardinality: "one".to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

fn add_query_fields(binding: &mut SourceBindingConfig) {
    binding.query_fields = vec![
        SourceQueryFieldConfig {
            input: "target.attributes.given_name".to_string(),
            field: "given_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.family_name".to_string(),
            field: "surname".to_string(),
            op: "eq".to_string(),
        },
    ];
}

#[test]
fn dependent_source_lookup_rejects_unknown_binding_reference() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut binding = rda_binding("farmer_registry", "one");
    binding.lookup.input = "sources.missing.birth_event_id".to_string();
    claim
        .source_bindings
        .insert("birth_event".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("unknown dependent source binding must fail validation");
    match err {
        EvidenceConfigError::UnknownSourceLookupBinding {
            claim,
            binding,
            input,
            unknown,
        } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(binding, "birth_event");
            assert_eq!(input, "sources.missing.birth_event_id");
            assert_eq!(unknown, "missing");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn dependent_source_query_field_rejects_unknown_binding_reference() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut binding = rda_binding("farmer_registry", "one");
    binding.query_fields = vec![SourceQueryFieldConfig {
        input: "source.missing.birth_event_id".to_string(),
        field: "birth_event_id".to_string(),
        op: "eq".to_string(),
    }];
    claim
        .source_bindings
        .insert("birth_event".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("unknown dependent query field binding must fail validation");
    match err {
        EvidenceConfigError::UnknownSourceLookupBinding {
            claim,
            binding,
            input,
            unknown,
        } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(binding, "birth_event");
            assert_eq!(input, "source.missing.birth_event_id");
            assert_eq!(unknown, "missing");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn dependent_source_lookup_rejects_binding_cycle() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut first = rda_binding("farmer_registry", "one");
    first.lookup.input = "sources.second.birth_event_id".to_string();
    let mut second = rda_binding("farmer_registry", "one");
    second.lookup.input = "sources.first.birth_event_id".to_string();
    claim.source_bindings =
        BTreeMap::from([("first".to_string(), first), ("second".to_string(), second)]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("dependent source binding cycle must fail validation");
    match err {
        EvidenceConfigError::SourceLookupDependencyCycle { claim, bindings } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(bindings, vec!["first".to_string(), "second".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn dependent_source_lookup_rejects_self_reference_cycle() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut solo = rda_binding("farmer_registry", "one");
    solo.lookup.input = "sources.solo.birth_event_id".to_string();
    claim.source_bindings = BTreeMap::from([("solo".to_string(), solo)]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("self-referential source binding cycle must fail validation");
    match err {
        EvidenceConfigError::SourceLookupDependencyCycle { claim, bindings } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(bindings, vec!["solo".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn detect_dependency_cycle_accepts_acyclic_chain() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["b".to_string()])),
    ]);
    assert_eq!(detect_dependency_cycle(&graph), None);
}

#[test]
fn detect_dependency_cycle_accepts_diamond_graph() {
    // `d` depends on `b` and `c`, both of which depend on `a`.
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["a".to_string()])),
        (
            "d".to_string(),
            BTreeSet::from(["b".to_string(), "c".to_string()]),
        ),
    ]);
    assert_eq!(detect_dependency_cycle(&graph), None);
}

#[test]
fn detect_dependency_cycle_reports_three_node_cycle() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::from(["c".to_string()])),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["b".to_string()])),
    ]);
    assert_eq!(
        detect_dependency_cycle(&graph),
        Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
    );
}

#[test]
fn detect_dependency_cycle_reports_self_reference_after_resolving_others() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("solo".to_string(), BTreeSet::from(["solo".to_string()])),
    ]);
    assert_eq!(
        detect_dependency_cycle(&graph),
        Some(vec!["solo".to_string()])
    );
}

#[test]
fn bulk_mode_default_is_none_and_round_trips() {
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(!connection.allow_insecure_localhost);
    assert!(!connection.allow_insecure_private_network);
    assert_eq!(connection.bulk_mode, BulkMode::None);
    assert!(!connection.bulk_mode_lookup_unique);
    assert_eq!(connection.bulk_timeout_max_ms, 30_000);
}

#[test]
fn bulk_mode_unknown_variant_is_rejected_at_deserialize() {
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
bulk_mode: unsupported_mode
"#;
    let err =
        serde_norway::from_str::<SourceConnectionConfig>(yaml).expect_err("unknown variant fails");
    let msg = err.to_string();
    assert!(
        msg.contains("unsupported_mode") || msg.contains("variant") || msg.contains("unknown"),
        "deserialize error mentions the bad variant: {msg}"
    );
}

#[test]
fn rda_in_filter_without_unique_attestation_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("rda_in_filter without unique attestation must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresUniqueLookup { connection } => {
            assert_eq!(connection, "farmer_registry");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn rda_in_filter_with_many_cardinality_binding_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "many"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("rda_in_filter with many-cardinality binding must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresCardinalityOne {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "farmer_registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn dci_batched_search_on_rda_binding_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("registry", "one"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("dci_batched_search on RDA binding must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresDciConnector {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn dci_batched_search_with_dci_bindings_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("record".to_string(), dci_binding("registry"));
    config.evidence.claims = vec![claim];
    assert!(config.validate().is_ok());
}

#[test]
fn query_fields_with_rda_bulk_mode_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = rda_binding("farmer_registry", "one");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("farmer".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use rda_in_filter bulk mode");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
            connection,
            claim,
            binding,
            bulk_mode,
        } => {
            assert_eq!(connection, "farmer_registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
            assert_eq!(bulk_mode, "rda_in_filter");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn query_fields_with_dci_bulk_mode_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use dci_batched_search bulk mode");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
            connection,
            claim,
            binding,
            bulk_mode,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "record");
            assert_eq!(bulk_mode, "dci_batched_search");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn query_fields_with_dci_idtype_value_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig {
                query_type: "idtype-value".to_string(),
                ..DciSourceConnectionConfig::default()
            },
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use idtype-value DCI");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithDciIdTypeValue {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "record");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn query_fields_with_dci_expression_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig {
                query_type: "expression".to_string(),
                ..DciSourceConnectionConfig::default()
            },
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    assert!(config.validate().is_ok());
}

#[test]
fn source_adapter_sidecar_connector_and_batch_mode_parse_and_validate_with_query_fields() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    assert!(config.validate().is_ok());
}

#[test]
fn source_adapter_sidecar_yaml_names_parse_and_validate() {
    let raw = r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      fingerprint:
        provider: env
        name: TEST_HASH
      scopes: [civil_registry:evidence_verification]
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    source_adapter_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: SOURCE_ADAPTER_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
      expected_sidecar:
        product: registry-notary-source-adapter-sidecar
        instance_id: demo
        environment: staging
        stream_id: source-adapter-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
        assurance_ttl_ms: 60000
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          query_fields:
            - input: target.attributes.given_name
              field: given_name
              op: eq
            - input: target.attributes.family_name
              field: family_name
              op: eq
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(raw).expect("source-adapter YAML config deserializes");

    assert_eq!(
        config.evidence.source_connections["source_adapter_crvs"].bulk_mode,
        BulkMode::SourceAdapterSidecarBatch
    );
    let expected_sidecar = config.evidence.source_connections["source_adapter_crvs"]
        .expected_sidecar
        .as_ref()
        .expect("expected_sidecar parses");
    assert_eq!(
        expected_sidecar.config_hash,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert!(expected_sidecar.require_expression_hashes_verified);
    assert!(expected_sidecar.require_runtime_verified);
    assert!(expected_sidecar.require_smoke_verified);
    assert_eq!(expected_sidecar.assurance_ttl_ms, 60_000);
    assert_eq!(
        config.evidence.claims[0].source_bindings["crvs"].connector,
        SourceConnectorKind::SourceAdapterSidecar
    );
    assert!(config.validate().is_ok());
}

#[test]
fn source_adapter_sidecar_expected_sidecar_rejects_invalid_config_hash() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: Some(ExpectedSidecarConfig {
                product: "registry-notary-source-adapter-sidecar".to_string(),
                instance_id: "demo".to_string(),
                environment: "staging".to_string(),
                stream_id: "source-adapter-sidecar-runtime".to_string(),
                config_hash: "sha256:NOTLOWERHEX".to_string(),
                require_expression_hashes_verified: true,
                require_runtime_verified: true,
                require_smoke_verified: true,
                assurance_ttl_ms: 60_000,
            }),
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("invalid expected_sidecar config_hash must fail");
    match err {
        EvidenceConfigError::InvalidExpectedSidecarConfig { connection, reason } => {
            assert_eq!(connection, "source_adapter_crvs");
            assert!(reason.contains("config_hash"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn source_adapter_sidecar_rejects_oauth_source_auth() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://sidecar.example/oauth/token".to_string(),
                    client_id_env: "SOURCE_ADAPTER_CLIENT_ID".to_string(),
                    client_secret_env: "SOURCE_ADAPTER_CLIENT_SECRET".to_string(),
                    request_format: "json".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar connections must use token_env auth");
    match err {
        EvidenceConfigError::InvalidSourceAuthConfig { connection, reason } => {
            assert_eq!(connection, "source_adapter_crvs");
            assert!(reason.contains("token_env"));
            assert!(reason.contains("source_adapter_sidecar"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn source_adapter_sidecar_rejects_retry_on_5xx() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar connections must not retry worker executions");
    match err {
        EvidenceConfigError::SourceAdapterSidecarRequiresNoRetry { connection } => {
            assert_eq!(connection, "source_adapter_crvs");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn source_adapter_sidecar_rejects_non_eq_lookup_operator() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    binding.lookup.op = "contains".to_string();
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar must reject non-eq lookup operators");
    match err {
        EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator { claim, binding, op } => {
            assert_eq!(claim, "date-of-birth");
            assert_eq!(binding, "crvs");
            assert_eq!(op, "contains");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn source_adapter_sidecar_rejects_non_eq_query_field_operator() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    add_query_fields(&mut binding);
    binding.query_fields[1].op = "contains".to_string();
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar must reject non-eq query field operators");
    match err {
        EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator { claim, binding, op } => {
            assert_eq!(claim, "date-of-birth");
            assert_eq!(binding, "crvs");
            assert_eq!(op, "contains");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn rda_in_filter_with_unique_and_cardinality_one_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
    config.evidence.claims = vec![claim];
    assert!(config.validate().is_ok());
}

#[test]
fn blank_only_allowed_claims_is_rejected() {
    // `allowed_claims: [""]` would pass an `is_empty()` guard but still
    // fail every issuance with EvaluationBindingMismatch. Treat blank-only
    // lists the same as empty so operators see the error at config load.
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims: ["", "   "]
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("blank_profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("blank-only allowed_claims must fail validation");
    match &err {
        EvidenceConfigError::EmptyAllowedClaims { profile } => {
            assert_eq!(profile, "blank_profile");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blank_evidence_allowed_purpose_is_rejected() {
    let mut config = minimal_config();
    config.evidence.allowed_purposes = vec!["benefits".to_string(), "  ".to_string()];

    let err = config
        .validate()
        .expect_err("blank evidence allowed_purposes must fail validation");

    assert!(matches!(err, EvidenceConfigError::InvalidPurpose));
}

#[test]
fn blank_relationship_purpose_scope_entries_are_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "crvs".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    let binding = rda_binding("crvs", "one");
    claim.source_bindings.insert("src".to_string(), binding);
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .relationship_purpose_scopes
        .insert("guardian".to_string(), vec![" ".to_string()]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("blank relationship purpose scope must fail validation");

    match err {
        EvidenceConfigError::InvalidMatchingConfig { reason, .. } => {
            assert_eq!(
                reason,
                "relationship_purpose_scopes must contain non-empty relationships and purposes",
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn relationship_purpose_scope_must_reference_allowed_relationship() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "crvs".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    let mut binding = rda_binding("crvs", "one");
    binding
        .matching
        .relationship_purpose_scopes
        .insert("guardian".to_string(), vec!["benefits".to_string()]);
    claim.source_bindings.insert("src".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("scope relationship must be in the flat allow-list");

    match err {
        EvidenceConfigError::InvalidMatchingConfig { reason, .. } => {
            assert_eq!(
                reason,
                "relationship_purpose_scopes entries must also appear in allowed_relationships",
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn self_attestation_is_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.self_attestation.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn oid4vci_is_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.oid4vci.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn disabled_default_self_attestation_is_omitted_from_serialized_config() {
    let config = minimal_config();
    let serialized = serde_json::to_value(&config).expect("config serializes as JSON");

    assert!(
        serialized.get("self_attestation").is_none(),
        "disabled default self_attestation must stay compact when serialized: {serialized}",
    );
}

#[test]
fn disabled_default_oid4vci_is_omitted_from_serialized_config() {
    let config = minimal_config();
    let serialized = serde_json::to_value(&config).expect("config serializes as JSON");

    assert!(
        serialized.get("oid4vci").is_none(),
        "disabled default oid4vci must stay compact when serialized: {serialized}",
    );
}

#[test]
fn valid_self_attestation_config_passes_validation() {
    let config = valid_self_attestation_config();
    assert!(config.validate().is_ok());
}

#[test]
fn delegated_attestation_requires_bound_proof_claim_source_inputs() {
    let mut config = valid_delegated_self_attestation_config();
    let proof = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("proof claim exists");
    proof
        .source_bindings
        .get_mut("crvs")
        .expect("proof binding exists")
        .query_fields
        .clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must bind both requester and target source inputs"),
        "unexpected: {reason}"
    );
}

#[test]
fn delegated_attestation_rejects_unsupported_allowed_disclosure() {
    let mut config = valid_delegated_self_attestation_config();
    config.self_attestation.delegation.allowed_relationships[0].allowed_disclosures =
        vec!["predicate".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must support at least one allowed disclosure"),
        "unexpected: {reason}"
    );
}

#[test]
fn valid_oid4vci_config_passes_validation() {
    let config = valid_oid4vci_config();
    assert!(config.validate().is_ok());
}

#[test]
fn valid_oid4vci_projection_config_passes_validation() {
    let config = valid_oid4vci_projection_config();
    config
        .validate()
        .expect("projection credential config validates");
}

#[test]
fn oid4vci_projection_rejects_claim_id_and_claims_together() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claim_id = Some("date-of-birth".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("exactly one of claim_id or claims"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_missing_claim_mode() {
    let mut config = valid_oid4vci_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claim_id = None;
    credential.claims.clear();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("exactly one of claim_id or claims"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_duplicate_output_paths() {
    let mut config = valid_oid4vci_projection_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claims[1].output_path = vec!["birth_date".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("duplicate") && reason.contains("output_path"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_duplicate_claim_ids() {
    let mut config = valid_oid4vci_projection_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claims[1].id = "date-of-birth".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("duplicate") && reason.contains("claims[].id"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_reserved_output_paths() {
    for reserved in [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "vct#integrity",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuanceDate",
        "expirationDate",
    ] {
        let mut config = valid_oid4vci_projection_config();
        config
            .oid4vci
            .credential_configurations
            .get_mut("date_of_birth_sd_jwt")
            .unwrap()
            .claims[0]
            .output_path = vec![reserved.to_string()];

        let reason = expect_oid4vci_error(&config);
        assert!(
            reason.contains("reserved") && reason.contains(reserved),
            "unexpected for {reserved}: {reason}"
        );
    }
}

#[test]
fn oid4vci_projection_rejects_nested_output_paths_in_v1() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claims[0]
        .output_path = vec!["birth".to_string(), "date".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("single segment"), "unexpected: {reason}");
}

#[test]
fn oid4vci_projection_rejects_unknown_claim_reference() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claims[0]
        .id = "missing-claim".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_claim_outside_profile_allow_list() {
    let mut config = valid_oid4vci_projection_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .allowed_claims
        .retain(|claim_id| claim_id != "birth-place");

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("profile") && reason.contains("does not allow"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_projection_rejects_mixed_claim_purposes() {
    let mut config = valid_oid4vci_projection_config();
    config
        .self_attestation
        .allowed_purposes
        .push("other_purpose".to_string());
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "birth-place")
        .expect("projection claim exists");
    claim.purpose = Some("other_purpose".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("share one purpose"), "unexpected: {reason}");
}

#[test]
fn oid4vci_projection_rejects_non_value_default_disclosure() {
    let mut config = valid_oid4vci_projection_config();
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "birth-place")
        .expect("projection claim exists");
    claim.disclosure.default = "redacted".to_string();
    claim.disclosure.allowed = vec!["redacted".to_string(), "value".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("must use value as the default disclosure"),
        "unexpected: {reason}"
    );
}

#[test]
fn claim_semantics_accepts_publicschema_property_mapping() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "civil_registry".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://registry.example.gov
token_env: CIVIL_REGISTRY_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    config.evidence.claims.push(
        serde_norway::from_str(
            r#"
id: date-of-birth
title: Date of birth
version: "2026-06"
subject_type: person
value:
  type: date
semantics:
  concept: https://publicschema.org/Person
  property: " https://publicschema.org/date_of_birth "
  value_mapping: publicschema
source_bindings:
  civil:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: person
    lookup:
      input: target.identifiers.national_id
      field: national_id
      cardinality: one
    fields:
      birth_date:
        field: birth_date
        type: date
        required: true
        semantic_term: " https://publicschema.org/date_of_birth "
rule:
  type: extract
  source: civil
  field: birth_date
"#,
        )
        .expect("claim parses"),
    );

    config
        .validate()
        .expect("matching PublicSchema semantics validate");
}

#[test]
fn claim_semantics_rejects_conflicting_extract_field_mapping() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "civil_registry".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://registry.example.gov
token_env: CIVIL_REGISTRY_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    config.evidence.claims.push(
        serde_norway::from_str(
            r#"
id: date-of-birth
title: Date of birth
version: "2026-06"
subject_type: person
semantics:
  property: https://publicschema.org/date_of_birth
source_bindings:
  civil:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: person
    lookup:
      input: target.identifiers.national_id
      field: national_id
      cardinality: one
    fields:
      birth_date:
        field: birth_date
        type: date
        required: true
        semantic_term: https://publicschema.org/date_of_death
rule:
  type: extract
  source: civil
  field: birth_date
"#,
        )
        .expect("claim parses"),
    );

    let error = config
        .validate()
        .expect_err("conflicting semantic terms must fail validation");
    assert!(
        matches!(error, EvidenceConfigError::InvalidClaimSemantics { ref reason, .. } if reason.contains("conflicts with source field")),
        "unexpected error: {error:?}"
    );
}

#[test]
fn oid4vci_accepts_vct_under_path_prefixed_credential_issuer() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_issuer = "http://127.0.0.1:4325/notary".to_string();
    config.oid4vci.credential_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("http://127.0.0.1:4325/notary/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/notary/credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/notary/credentials/civil-status".to_string();

    assert!(config.validate().is_ok());
}

#[test]
fn oid4vci_deserializes_absent_block_with_default() {
    let config = valid_self_attestation_config();
    assert_eq!(config.oid4vci, Oid4vciConfig::default());
}

#[test]
fn oid4vci_requires_enabled_self_attestation() {
    let mut config = valid_oid4vci_config();
    config.self_attestation.enabled = false;

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("self_attestation.enabled"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_missing_accepted_audiences() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.accepted_token_audiences.clear();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("accepted_token_audiences"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_unknown_claim_reference() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claim_id = Some("missing-claim".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_unknown_credential_profile_reference() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .credential_profile = "missing-profile".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown credential profile 'missing-profile'"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_non_loopback_http_urls() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_issuer = "http://issuer.example".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("https") && reason.contains("loopback"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_endpoint_without_path() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_endpoint = "http://127.0.0.1:4325".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("endpoint path"), "unexpected: {reason}");
}

#[test]
fn oid4vci_rejects_vct_outside_credential_issuer() {
    let mut config = valid_oid4vci_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "https://vct.example/credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "https://vct.example/credentials/civil-status".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("credential_configurations.vct")
            && reason.contains("oid4vci.credential_issuer"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_vct_outside_credentials_path() {
    let mut config = valid_oid4vci_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/not-credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/not-credentials/civil-status".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("vct path") && reason.contains("/credentials/"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_duplicate_credential_configuration_vct() {
    let mut config = valid_oid4vci_config();
    let duplicate = config
        .oid4vci
        .credential_configurations
        .get("date_of_birth_sd_jwt")
        .unwrap()
        .clone();
    config
        .oid4vci
        .credential_configurations
        .insert("duplicate_sd_jwt".to_string(), duplicate);

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("vct") && reason.contains("unique"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_missing_nonce_endpoint_when_nonce_enabled() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.nonce_endpoint = None;

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("nonce_endpoint"), "unexpected: {reason}");
}

#[test]
fn oid4vci_rejects_bad_nonce_and_proof_timing_bounds() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.nonce.ttl_seconds = 0;

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("nonce.ttl_seconds"), "unexpected: {reason}");

    config.oid4vci.nonce.ttl_seconds = 300;
    config.oid4vci.proof.max_age_seconds = 601;

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("proof.max_age_seconds"),
        "unexpected: {reason}"
    );
}

#[test]
fn oid4vci_rejects_bad_algorithm_lists() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .proof_signing_alg_values_supported
        .push("ES256".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("ES256"), "unexpected: {reason}");
}

#[test]
fn oid4vci_rejects_bad_binding_methods() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .cryptographic_binding_methods_supported
        .push("did:key".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("did:key"), "unexpected: {reason}");
}

#[test]
fn self_attestation_requires_oidc_auth_mode() {
    let mut config = valid_self_attestation_config();
    config.auth.mode = EvidenceAuthMode::ApiKey;
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "api".to_string(),
        fingerprint: CredentialFingerprintRef {
            provider: registry_platform_authcommon::CredentialFingerprintProvider::Env,
            name: Some("API_HASH".to_string()),
            path: None,
        },
        scopes: Vec::new(),
        authorization_details: None,
    });

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("auth.mode = oidc"), "unexpected: {reason}");
}

#[test]
fn self_attestation_rejects_unsafe_subject_claim_names() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "national id".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("token_claim"), "unexpected: {reason}");
}

#[test]
fn self_attestation_rejects_sub_without_explicit_civil_id_opt_in() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "sub".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allow_sub_as_civil_id"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_allows_sub_with_explicit_civil_id_opt_in() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "sub".to_string();
    config
        .self_attestation
        .subject_binding
        .allow_sub_as_civil_id = true;

    assert!(config.validate().is_ok());
}

#[test]
fn self_attestation_subject_request_field_only_accepts_subject_id() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/keys
    audiences:
      - registry-notary-citizen
self_attestation:
  enabled: true
  subject_binding:
    token_claim: https://id.example.gov/claims/national_id
    request_field: SubjectHeader
    id_type: national_id
"#,
    )
    .expect_err("unsupported request_field variant must fail deserialization");
    let msg = err.to_string();
    assert!(
        msg.contains("SubjectHeader") || msg.contains("unknown variant"),
        "unexpected error: {msg}"
    );
}

#[test]
fn shared_canonical_oidc_fixture_parses() {
    let config = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    audiences:
      - registry-notary
    jwks_url: https://id.example.gov/oauth/v2/keys
    allowed_algorithms:
      - EdDSA
    allowed_token_types:
      - JWT
    leeway: 30s
"#,
    )
    .expect("shared canonical OIDC fixture parses");
    let oidc = config.auth.oidc.expect("oidc config");

    assert_eq!(oidc.issuer, "https://id.example.gov");
    assert_eq!(oidc.audiences, vec!["registry-notary"]);
    assert_eq!(oidc.jwks_url, "https://id.example.gov/oauth/v2/keys");
    assert_eq!(oidc.allowed_algorithms, vec!["EdDSA"]);
    assert_eq!(oidc.allowed_token_types, vec!["JWT"]);
    assert_eq!(oidc.leeway, Duration::from_secs(30));
}

#[test]
fn self_attestation_rejects_non_exact_normalization() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/keys
    audiences:
      - registry-notary-citizen
self_attestation:
  enabled: true
  subject_binding:
    token_claim: https://id.example.gov/claims/national_id
    request_field: SubjectId
    id_type: national_id
    normalize: lowercase
"#,
    )
    .expect_err("unsupported normalize variant must fail deserialization");
    let msg = err.to_string();
    assert!(
        msg.contains("lowercase") || msg.contains("unknown variant"),
        "unexpected error: {msg}"
    );
}

#[test]
fn self_attestation_requires_nonempty_allow_lists() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_claims.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allowed_claims must not be empty"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_unused_allow_list_entries() {
    let mut config = valid_self_attestation_config();
    config
        .self_attestation
        .allowed_formats
        .push("application/unsupported".to_string());

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allowed_formats entry"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_batch_evaluate_operation() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_operations.batch_evaluate = true;

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("batch_evaluate"), "unexpected: {reason}");
}

#[test]
fn self_attestation_rejects_wildcard_wallet_origins() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_wallet_origins = vec!["*".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("wildcards"), "unexpected: {reason}");
}

#[test]
fn self_attestation_allows_empty_wallet_origins_for_non_browser_flows() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_wallet_origins.clear();

    config
        .validate()
        .expect("wallet origins are optional for CLI and server-side flows");
}

#[test]
fn self_attestation_rejects_zero_rate_limits() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.rate_limits.per_principal_per_minute = 0;

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("rate_limits"), "unexpected: {reason}");
}

#[test]
fn self_attestation_requires_allowed_client_or_audience() {
    let mut config = valid_self_attestation_config();
    config
        .self_attestation
        .citizen_clients
        .allowed_client_ids
        .clear();
    config
        .self_attestation
        .citizen_clients
        .allowed_audiences
        .clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("citizen_clients"), "unexpected: {reason}");
}

#[test]
fn self_attestation_requires_scopes_to_be_mapped() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().scope_map.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("scope_map"), "unexpected: {reason}");
}

#[test]
fn self_attestation_required_scope_policy_requires_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.required_scopes.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("scope_policy requires required_scopes"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_optional_scope_policy_still_requires_scope_mapping() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Optional;
    config.auth.oidc.as_mut().unwrap().scope_map.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("scope_map"), "unexpected: {reason}");
}

#[test]
fn self_attestation_optional_scope_policy_passes_with_required_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Optional;

    config
        .validate()
        .expect("optional scope policy uses configured self-attestation scopes");
}

#[test]
fn self_attestation_disabled_scope_policy_rejects_required_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Disabled;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("scope_policy = disabled"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_citizen_scope_map_granting_source_scope() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().scope_map.insert(
        "citizen_self_attestation".to_string(),
        vec![
            "self_attestation".to_string(),
            "civil_registry:evidence_verification".to_string(),
        ],
    );

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must not grant source scope"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_leeway_above_token_policy() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().leeway = Duration::from_secs(61);

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("leeway"), "unexpected: {reason}");
}

#[test]
fn self_attestation_rejects_unknown_claim_references() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_claims = vec!["missing-claim".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_unallowed_claim_purpose() {
    let mut config = valid_self_attestation_config();
    config.evidence.claims[0].purpose = Some("machine_verification".to_string());

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("unallowed purpose"), "unexpected: {reason}");
}

#[test]
fn self_attestation_rejects_claim_without_purpose() {
    let mut config = valid_self_attestation_config();
    config.evidence.claims[0].purpose = None;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must declare purpose"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_unknown_profile_references() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.credential_profiles = vec!["missing-profile".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("unknown profile 'missing-profile'"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_citizen_profile_validity_above_ceiling() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .validity_seconds = 601;

    let error = config
        .validate()
        .expect_err("validity above general ceiling is rejected");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile,
            validity_seconds: 601,
            max_validity_seconds: 600,
        } if profile == "civil_status_sd_jwt"
    ));
}

#[test]
fn self_attestation_accepts_citizen_profile_validity_at_configured_ceiling() {
    const AGENCY_CREDENTIAL_VALIDITY_SECONDS: u64 = 31_536_000;
    let mut config = valid_self_attestation_config();
    config.evidence.max_credential_validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS;
    config
        .self_attestation
        .token_policy
        .max_credential_validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS;
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS as i64;

    config
        .validate()
        .expect("wallet-held credential validity may reach the configured ceiling");
}

#[test]
fn self_attestation_profile_without_validity_uses_default_under_ceiling() {
    let mut config = valid_self_attestation_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://issuer.example/credentials/civil-status
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
allowed_claims:
  - date-of-birth
disclosure:
  allowed:
    - value
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("civil_status_sd_jwt".to_string(), profile);

    config
        .validate()
        .expect("omitted credential validity defaults under self-attestation ceiling");
    assert_eq!(
        config
            .evidence
            .credential_profiles
            .get("civil_status_sd_jwt")
            .unwrap()
            .validity_seconds,
        600
    );
}

#[test]
fn self_attestation_rejects_profile_without_did_holder_binding() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .mode = "none".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("holder_binding.mode must be did"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_rejects_profile_without_required_holder_proof() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .proof_of_possession = None;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("holder_binding.proof_of_possession must be required"),
        "unexpected: {reason}"
    );
}

#[test]
fn self_attestation_keeps_did_jwk_proof_of_possession_validation() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .allowed_did_methods
        .push("did:key".to_string());

    let err = config
        .validate()
        .expect_err("did:key must still fail proof-of-possession validation");
    assert!(matches!(
        err,
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { .. }
    ));
}

fn second_signing_key() -> SigningKeyConfig {
    serde_norway::from_str(
        r#"
provider: local_jwk_env
private_jwk_env: ACCESS_TOKEN_KEY
alg: EdDSA
kid: did:web:issuer.example#access-token-key
status: active
"#,
    )
    .expect("access-token signing key is valid YAML")
}

fn publish_only_access_token_verification_key(kid: &str) -> SigningKeyConfig {
    let mut key = second_signing_key();
    key.kid = kid.to_string();
    key.status = SigningKeyStatus::PublishOnly;
    key.private_jwk_env = String::new();
    key.public_jwk_env = "ACCESS_TOKEN_PUBLIC_KEY".to_string();
    key
}

fn test_public_jwk(kid: &str, x: &str) -> PublicJwk {
    PublicJwk::parse(
        &serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": kid,
        })
        .to_string(),
    )
    .expect("test public JWK parses")
}

/// A pre-auth-enabled oid4vci config with a dedicated access-token signing
/// key, distinct from the credential-signing key.
fn valid_pre_auth_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_oid4vci_config();
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 5;
    config
        .evidence
        .signing_keys
        .insert("access-token-key".to_string(), second_signing_key());
    config.oid4vci.pre_authorized_code = serde_norway::from_str(
        r#"
enabled: true
tx_code:
  required: true
  input_mode: numeric
  length: 6
esignet:
  client_id: registry-lab-live-client
  client_signing_key_id: issuer-key
  redirect_uri: http://127.0.0.1:4325/oid4vci/offer/callback
  authorize_url: https://id.example.gov/authorize
  token_url: https://id.example.gov/oauth/v2/token
  issuer: https://id.example.gov
  jwks_uri: https://id.example.gov/oauth/.well-known/jwks.json
  scopes:
    - openid
pre_authorized_code_ttl_seconds: 300
"#,
    )
    .expect("pre-auth config is valid YAML");
    config.auth.access_token_signing = serde_norway::from_str(
        r#"
enabled: true
issuer: http://127.0.0.1:4325
audiences:
  - http://127.0.0.1:4325
allowed_algorithms:
  - EdDSA
token_typ: registry-notary-access+jwt
signing_key_id: access-token-key
access_token_ttl_seconds: 300
"#,
    )
    .expect("access-token signing config is valid YAML");
    config
}

fn expect_access_token_signing_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("access-token signing config must fail validation")
    {
        EvidenceConfigError::InvalidAccessTokenSigningConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn pre_auth_and_access_token_signing_are_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.oid4vci.pre_authorized_code.enabled);
    assert!(!config.auth.access_token_signing.enabled);
    config
        .validate()
        .expect("a config that omits the pre-auth blocks still validates");
}

#[test]
fn omitted_pre_auth_blocks_use_safe_defaults() {
    let config = minimal_config();
    let tx_code = &config.oid4vci.pre_authorized_code.tx_code;
    assert!(tx_code.required, "tx_code is required by default");
    assert_eq!(tx_code.input_mode, "numeric");
    let signing = &config.auth.access_token_signing;
    assert_eq!(signing.allowed_algorithms, vec!["EdDSA".to_string()]);
    assert_eq!(signing.token_typ, "registry-notary-access+jwt");
}

#[test]
fn valid_pre_auth_config_validates() {
    valid_pre_auth_config()
        .validate()
        .expect("a fully-configured pre-auth config validates");
}

#[test]
fn access_token_signing_enabled_requires_issuer() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.issuer = String::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("issuer"));
}

#[test]
fn access_token_signing_enabled_requires_audiences() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.audiences = Vec::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("audiences"));
}

#[test]
fn access_token_signing_requires_known_signing_key() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.signing_key_id = "missing-key".to_string();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("evidence.signing_keys"));
}

#[test]
fn access_token_signing_key_must_be_distinct_from_credential_key() {
    let mut config = valid_pre_auth_config();
    // Point the access-token key at the credential-signing key.
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("distinct from credential profile"));
}

#[test]
fn resolved_signing_key_material_must_not_be_reused_under_distinct_kids() {
    let config = valid_pre_auth_config();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let access_token_public_jwk = test_public_jwk(
        "did:web:issuer.example#access-token-key",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    let err = config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("access-token-key", &access_token_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect_err("same public key material under different kids must fail");

    match err {
        EvidenceConfigError::InvalidSigningKeyConfig { key, reason } => {
            assert_eq!(key, "access-token-key");
            assert!(reason.contains("reuses public key material"));
            assert!(reason.contains("issuer-key"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn resolved_signing_key_material_accepts_distinct_public_keys() {
    let config = valid_pre_auth_config();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let access_token_public_jwk = test_public_jwk(
        "did:web:issuer.example#access-token-key",
        "pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("access-token-key", &access_token_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect("distinct public key material is valid");
}

#[test]
fn resolved_signing_key_material_allows_esignet_rp_key_to_reuse_credential_material() {
    // Issue #173 confines reuse detection to the separated EdDSA roles. The
    // eSignet pre-authorized-code RP client key is a relaxed role that is
    // deliberately allowed to share material with the credential issuer key,
    // so it must not appear in the reuse-scoped set and must not trip the
    // detector even when its resolved material matches a credential key.
    let mut config = valid_pre_auth_config();
    let mut esignet_key = second_signing_key();
    esignet_key.kid = "did:web:rp.example#esignet-rp-key".to_string();
    config
        .evidence
        .signing_keys
        .insert("esignet-rp-key".to_string(), esignet_key);
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    let credential_public_jwk = test_public_jwk(
        "did:web:issuer.example#key-1",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );
    let esignet_public_jwk = test_public_jwk(
        "did:web:rp.example#esignet-rp-key",
        "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
    );

    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    assert!(
        !reuse_scoped_key_ids.contains("esignet-rp-key"),
        "the eSignet RP client key must be excluded from reuse-scoped roles"
    );

    config
        .evidence
        .validate_resolved_signing_key_material(
            [
                ("issuer-key", &credential_public_jwk),
                ("esignet-rp-key", &esignet_public_jwk),
            ],
            &reuse_scoped_key_ids,
        )
        .expect("eSignet RP key may reuse credential key material");
}

#[test]
fn access_token_signing_key_must_be_active() {
    let mut config = valid_pre_auth_config();
    config
        .evidence
        .signing_keys
        .get_mut("access-token-key")
        .expect("access-token key exists")
        .status = SigningKeyStatus::PublishOnly;
    // PublishOnly requires public_jwk_env and no private_jwk_env.
    let key = config
        .evidence
        .signing_keys
        .get_mut("access-token-key")
        .expect("access-token key exists");
    key.public_jwk_env = "ACCESS_TOKEN_PUBLIC_KEY".to_string();
    key.private_jwk_env = String::new();
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("active signing key"));
}

#[test]
fn access_token_signing_rejects_non_eddsa_algorithms() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.allowed_algorithms = vec!["RS256".to_string()];
    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("EdDSA"));
}

#[test]
fn access_token_verification_key_ids_accept_publish_only_old_keys() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "access-token-key-old".to_string(),
        publish_only_access_token_verification_key("did:web:issuer.example#access-token-key-old"),
    );
    config.auth.access_token_signing.verification_key_ids =
        vec!["access-token-key-old".to_string()];

    config
        .validate()
        .expect("publish-only verification keys are valid during rotation");
}

#[test]
fn access_token_verification_key_ids_must_not_repeat_active_key() {
    let mut config = valid_pre_auth_config();
    config.auth.access_token_signing.verification_key_ids = vec!["access-token-key".to_string()];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("must not repeat active signing_key_id"));
}

#[test]
fn access_token_verification_key_ids_must_be_unique() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "access-token-key-old".to_string(),
        publish_only_access_token_verification_key("did:web:issuer.example#access-token-key-old"),
    );
    config.auth.access_token_signing.verification_key_ids = vec![
        "access-token-key-old".to_string(),
        "access-token-key-old".to_string(),
    ];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("duplicate key"));
}

#[test]
fn access_token_verification_key_ids_must_be_publish_only() {
    let mut config = valid_pre_auth_config();
    let mut active_old_key = second_signing_key();
    active_old_key.kid = "did:web:issuer.example#access-token-key-old".to_string();
    config
        .evidence
        .signing_keys
        .insert("access-token-key-old".to_string(), active_old_key);
    config.auth.access_token_signing.verification_key_ids =
        vec!["access-token-key-old".to_string()];

    let reason = expect_access_token_signing_error(&config);
    assert!(reason.contains("publish_only"));
}

/// A local JWK signing key entry. Config validation only checks the alg
/// string and the per-provider fields, so a dummy private_jwk_env name
/// suffices; the JWK itself is not decoded at validation time.
fn local_jwk_signing_key_with_alg(alg: &str, private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    SigningKeyConfig {
        provider: SigningKeyProviderConfig::LocalJwkEnv,
        alg: alg.to_string(),
        kid: kid.to_string(),
        status: SigningKeyStatus::Active,
        publish_until_unix_seconds: None,
        private_jwk_env: private_jwk_env.to_string(),
        public_jwk_env: String::new(),
        module_path: String::new(),
        token_label: String::new(),
        pin_env: String::new(),
        key_label: String::new(),
        key_id_hex: String::new(),
        path: String::new(),
        password_env: String::new(),
    }
}

fn rs256_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    local_jwk_signing_key_with_alg(CLIENT_ASSERTION_SIGNING_ALG_RS256, private_jwk_env, kid)
}

fn es256_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    local_jwk_signing_key_with_alg(CREDENTIAL_SIGNING_ALG_ES256, private_jwk_env, kid)
}

fn expect_signing_key_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("signing-key config must fail validation")
    {
        EvidenceConfigError::InvalidSigningKeyConfig { reason, .. } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn esignet_rp_client_assertion_key_may_be_rs256() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    config
        .validate()
        .expect("an RS256 eSignet RP client-assertion key validates");
}

#[test]
fn pre_auth_client_signing_key_must_exist() {
    let mut config = valid_pre_auth_config();
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "missing-rp-key".to_string();
    let reason = match config
        .validate()
        .expect_err("a missing RP client-assertion key must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };
    assert!(reason.contains("client_signing_key_id"));
    assert!(reason.contains("evidence.signing_keys"));
}

#[test]
fn pre_auth_client_signing_key_must_be_active() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config
        .oid4vci
        .pre_authorized_code
        .esignet
        .client_signing_key_id = "esignet-rp-key".to_string();
    // PublishOnly cannot sign; it requires public_jwk_env and no private_jwk_env.
    let key = config
        .evidence
        .signing_keys
        .get_mut("esignet-rp-key")
        .expect("esignet rp key exists");
    key.status = SigningKeyStatus::PublishOnly;
    key.public_jwk_env = "ESIGNET_RP_PUBLIC_KEY".to_string();
    key.private_jwk_env = String::new();
    let reason = match config
        .validate()
        .expect_err("an inactive RP client-assertion key must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    };
    assert!(reason.contains("active signing key"));
}

#[test]
fn rs256_signing_key_rejected_as_credential_profile_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        rs256_signing_key("ESIGNET_RP_KEY", "did:web:issuer.example#esignet-rp-key"),
    );
    // Point a credential profile at the RS256 key.
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .signing_key = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("RS256"));
    assert!(reason.contains("credential profile"));
}

#[test]
fn es256_signing_key_may_be_credential_profile_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "issuer-p256-key".to_string(),
        es256_signing_key("ISSUER_P256_KEY", "did:web:issuer.example#p256-key"),
    );
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("civil status credential profile exists")
        .signing_key = "issuer-p256-key".to_string();
    config
        .validate()
        .expect("an ES256 credential profile signing key validates");
}

#[test]
fn non_eddsa_signing_key_rejected_as_access_token_key() {
    let mut config = valid_pre_auth_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        es256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config.auth.access_token_signing.signing_key_id = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("client_signing_key_id"));
}

#[test]
fn non_eddsa_signing_key_rejected_as_federation_key() {
    let mut config = valid_federation_config();
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        es256_signing_key("ESIGNET_RP_KEY", "did:web:rp.example#esignet-rp-key"),
    );
    config.federation.signing.signing_key = "esignet-rp-key".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains("client_signing_key_id"));
}

#[test]
fn signing_key_alg_must_be_eddsa_es256_or_rs256() {
    let mut config = valid_pre_auth_config();
    config
        .evidence
        .signing_keys
        .get_mut("issuer-key")
        .expect("issuer-key exists")
        .alg = "PS256".to_string();
    let reason = expect_signing_key_error(&config);
    assert!(reason.contains(CREDENTIAL_SIGNING_ALG_EDDSA));
    assert!(reason.contains(CREDENTIAL_SIGNING_ALG_ES256));
    assert!(reason.contains(CLIENT_ASSERTION_SIGNING_ALG_RS256));
}

#[test]
fn pre_auth_enabled_requires_oid4vci_enabled() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.enabled = false;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("requires oid4vci.enabled = true"));
}

#[test]
fn pre_auth_allows_optional_tx_code() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .validate()
        .expect("operators may explicitly disable tx_code when required for wallet interop");
}

#[test]
fn pre_auth_optional_tx_code_caps_bearer_offer_ttl() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS + 1;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("tx_code.required = false"));

    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .validate()
        .expect("bearer-offer mode validates at the explicit cap");
}

#[test]
fn pre_auth_requires_esignet_client_id() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.esignet.client_id = String::new();
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("esignet.client_id"));
}

#[test]
fn pre_auth_rejects_out_of_range_code_ttl() {
    let mut config = valid_pre_auth_config();
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 0;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("pre_authorized_code_ttl_seconds"));
}

#[test]
fn pre_auth_requires_tx_code_rate_limit() {
    let mut config = valid_pre_auth_config();
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("tx_code_attempts_per_code_per_minute"));
}

#[test]
fn pre_auth_optional_tx_code_does_not_require_tx_code_rate_limit() {
    let mut config = valid_pre_auth_config();
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS;
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    config
        .validate()
        .expect("tx_code attempt limits are only required when tx_code is required");
}

#[test]
fn pre_auth_userinfo_binding_requires_esignet_userinfo_url() {
    let mut config = valid_pre_auth_config();
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    // Satisfy the resource-server userinfo rule so the failure is
    // specifically the missing pre-auth eSignet userinfo endpoint.
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.userinfo_endpoint = Some("https://id.example.gov/userinfo".to_string());
    }
    config.oid4vci.pre_authorized_code.esignet.userinfo_url = String::new();
    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("esignet.userinfo_url"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn pre_auth_userinfo_binding_accepts_configured_userinfo_url() {
    let mut config = valid_pre_auth_config();
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.userinfo_endpoint = Some("https://id.example.gov/userinfo".to_string());
    }
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        "https://id.example.gov/userinfo".to_string();
    config
        .validate()
        .expect("userinfo-sourced pre-auth binding validates with a userinfo_url");
}
