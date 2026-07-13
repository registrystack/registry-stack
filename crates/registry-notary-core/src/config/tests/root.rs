use super::support::*;
use super::*;
#[allow(unused_imports)]
use super::{auth::*, credentials::*, infrastructure::*, issuance::*, preauth::*};

#[test]
pub(super) fn gate_input_defaults_are_low_risk_for_minimal_config() {
    let config = minimal_config();
    let input = config.gate_input();
    // A minimal config uses in-memory replay and stdout audit by default.
    assert!(input.replay_in_memory);
    assert!(!input.audit_sink_class_durable);
    // No high-risk modes are declared.
    assert!(!input.high_risk_replay_mode());
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
pub(super) fn gate_input_reports_federation_as_high_risk() {
    let mut config = minimal_config();
    config.federation.enabled = true;
    assert!(config.gate_input().high_risk_replay_mode());
}

#[test]
pub(super) fn gate_input_reports_durable_audit_sink() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(config.gate_input().audit_sink_class_durable);
}

#[test]
pub(super) fn gate_input_reports_audit_retention_local_only_for_file_sink_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(config.gate_input().audit_retention_local_only);
}

#[test]
pub(super) fn gate_input_reports_audit_retention_local_only_for_jsonl_sink_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "jsonl".to_string();
    assert!(config.gate_input().audit_retention_local_only);
}

#[test]
pub(super) fn gate_input_clears_audit_retention_local_only_when_attested() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(!config.gate_input().audit_retention_local_only);
}

#[test]
pub(super) fn gate_input_requires_custody_approval_for_referenced_signer() {
    let mut config = minimal_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();

    assert!(config.gate_input().signer_without_custody_approval);
}

#[test]
pub(super) fn gate_input_does_not_treat_pkcs11_as_custody_approval() {
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
pub(super) fn gate_input_clears_signer_custody_when_approved() {
    let mut config = minimal_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "issuer-key".to_string();
    config.deployment.evidence.signer_custody_approved = true;

    assert!(!config.gate_input().signer_without_custody_approval);
}

#[test]
pub(super) fn gate_input_clears_audit_retention_local_only_for_stdout_sink() {
    // Minimal config defaults to the stdout sink.
    let config = minimal_config();
    assert!(!config.gate_input().audit_retention_local_only);
}

#[test]
pub(super) fn gate_input_clears_audit_retention_local_only_for_syslog_sink() {
    let mut config = minimal_config();
    config.audit.sink = "syslog".to_string();
    assert!(!config.gate_input().audit_retention_local_only);
}

/// The fixture ack cursor's `acked_at` (`2026-06-04T09:59:00Z`) as a
/// `SystemTime`, so tests can pin `now` relative to it deterministically.
pub(super) fn fixture_acked_at() -> SystemTime {
    let acked = time::OffsetDateTime::parse(
        "2026-06-04T09:59:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixture acked_at parses");
    SystemTime::from(acked)
}

pub(super) fn write_ack_cursor(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("ack-cursor.json");
    std::fs::write(&path, contents).expect("ack cursor writes");
    path
}

#[test]
pub(super) fn gate_input_reports_shipping_declared_external_for_attested_file_sink() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(config.gate_input().audit_shipping_target_configured);
}

#[test]
pub(super) fn gate_input_clears_shipping_declared_external_without_attestation() {
    let mut config = minimal_config();
    config.audit.sink = "file".to_string();
    assert!(!config.gate_input().audit_shipping_target_configured);
}

#[test]
pub(super) fn gate_input_reports_shipping_target_for_stdout_sink() {
    let mut config = minimal_config();
    config.deployment.evidence.audit_offhost_shipping = true;
    assert!(config.gate_input().audit_shipping_target_configured);
}

#[test]
pub(super) fn gate_input_reports_ack_cursor_configured_when_path_set() {
    let mut config = minimal_config();
    assert!(!config.gate_input().audit_ack_cursor_configured);
    config.deployment.evidence.audit_ack_cursor_path =
        Some(std::path::PathBuf::from("/nonexistent/ack-cursor.json"));
    assert!(config.gate_input().audit_ack_cursor_configured);
}

#[test]
pub(super) fn gate_input_reports_ack_health_ok_only_after_fresh_cursor_binds_to_tail() {
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
pub(super) fn gate_input_at_reports_ack_health_not_ok_for_stale_cursor() {
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
pub(super) fn gate_input_at_reports_ack_health_not_ok_for_missing_cursor() {
    let mut config = minimal_config();
    config.deployment.evidence.audit_ack_cursor_path =
        Some(std::path::PathBuf::from("/nonexistent/ack-cursor.json"));
    let now = fixture_acked_at() + Duration::from_secs(60);
    assert!(!config.gate_input_at(now).audit_ack_health_ok);
}

#[test]
pub(super) fn gate_input_at_honors_custom_max_age_window() {
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
pub(super) fn validate_rejects_ack_max_age_without_cursor() {
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
pub(super) fn validate_rejects_ack_cursor_on_local_file_sink_without_shipping_declared() {
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
pub(super) fn validate_allows_ack_cursor_on_attested_local_file_sink() {
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
pub(super) fn validate_allows_ack_cursor_on_stdout_sink_without_shipping_declared() {
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
pub(super) fn gate_input_reports_assisted_access_transaction_token_posture() {
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
pub(super) fn gate_input_reports_admin_shared_exposure() {
    let mut config = minimal_config();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    assert!(config.gate_input().admin_shared_exposure);
}

#[test]
pub(super) fn gate_input_clears_admin_shared_exposure_when_listener_disabled() {
    let config = minimal_config();
    // Default admin listener mode is Disabled; shared exposure must be false.
    assert!(!config.gate_input().admin_shared_exposure);
}

#[test]
pub(super) fn gate_input_reports_openapi_public() {
    let mut config = minimal_config();
    config.server.openapi_requires_auth = false;
    assert!(config.gate_input().openapi_public);
}

#[test]
pub(super) fn gate_input_clears_openapi_public_when_auth_required() {
    let config = minimal_config();
    // Default requires auth; openapi_public must be false.
    assert!(!config.gate_input().openapi_public);
}

#[test]
pub(super) fn gate_input_clears_config_unsigned_when_config_trust_configured() {
    let mut config = minimal_config();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    config.config_trust = Some(valid_config_trust());
    assert!(!config.gate_input().config_unsigned);
}

#[test]
pub(super) fn gate_input_reports_config_unsigned_without_trust() {
    let config = minimal_config();
    // Minimal config has no config_trust block; must project as unsigned.
    assert!(config.gate_input().config_unsigned);
}

#[test]
pub(super) fn deployment_block_round_trips_through_yaml() {
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
pub(super) fn deployment_evidence_block_round_trips_through_yaml() {
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
pub(super) fn deployment_evidence_rejects_unknown_field_through_yaml() {
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
pub(super) fn invalid_profile_value_fails_config_load() {
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

pub(super) fn use_dedicated_admin_listener(config: &mut StandaloneRegistryNotaryConfig) {
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
}

pub(super) fn valid_config_trust() -> ConfigTrustConfig {
    ConfigTrustConfig {
        trust_anchor_path: PathBuf::from("/etc/registry-notary/config-anchor.json"),
        bundle_path: PathBuf::from("/etc/registry-notary/config-bundle"),
        antirollback_state_path: PathBuf::from(
            "/var/lib/registry-notary/config-state/antirollback.json",
        ),
        break_glass_override_path: None,
    }
}

pub(super) fn minimal_claim(id: &str) -> ClaimDefinition {
    serde_norway::from_str(&format!(
        r#"
id: {id}
title: Test Claim
version: "1.0"
subject_type: person
evidence_mode:
  type: self_attested
rule:
  type: cel
  expression: "true"
"#
    ))
    .expect("minimal claim is valid YAML")
}

#[test]
pub(super) fn config_trust_is_optional_but_requires_explicit_antirollback_path() {
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
pub(super) fn cel_config_defaults_and_validates_operator_limits() {
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
pub(super) fn cel_config_deserializes_production_surface() {
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

pub(super) fn valid_self_attestation_config() -> StandaloneRegistryNotaryConfig {
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
      evidence_mode:
        type: self_attested
      value:
        type: boolean
      purpose: citizen_self_attestation
      rule:
        type: cel
        expression: "true"
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

pub(super) fn valid_delegated_self_attestation_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_self_attestation_config();
    config.evidence.relay = Some(
        serde_norway::from_str(
            r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_file: /run/secrets/registry-notary-relay.jwt
"#,
        )
        .expect("Relay connection parses"),
    );
    let mut proof = config.evidence.claims[0].clone();
    proof.id = "guardian-link".to_string();
    proof.title = "Guardian link".to_string();
    proof.subject_type = "relationship".to_string();
    proof.purpose = Some("dependent_attestation".to_string());
    proof.required_scopes = vec!["self_attestation".to_string()];
    proof.evidence_mode = ClaimEvidenceMode::RegistryBacked {
        consultations: BTreeMap::from([(
            "guardian_link".to_string(),
            RelayConsultationConfig {
                profile: RelayConsultationProfileRef {
                    id: "example.guardian-link.exact".to_string(),
                    contract_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                },
                inputs: BTreeMap::from([
                    (
                        "requester_id".to_string(),
                        RelayConsultationInput::RequesterIdentifier(
                            "request.requester.identifiers.national_id".to_string(),
                        ),
                    ),
                    (
                        "target_id".to_string(),
                        RelayConsultationInput::TargetIdentifier(
                            "request.target.identifiers.civil_registration_id".to_string(),
                        ),
                    ),
                ]),
                outputs: BTreeMap::from([(
                    "established".to_string(),
                    RelayOutputContract::Boolean { nullable: true },
                )]),
            },
        )]),
    };
    proof.value.nullable = true;
    proof.rule = RuleConfig::Extract {
        source: "guardian_link".to_string(),
        field: "established".to_string(),
    };

    let mut dependent = config.evidence.claims[0].clone();
    dependent.id = "dependent-date-of-birth".to_string();
    dependent.title = "Dependent date of birth".to_string();
    dependent.purpose = Some("dependent_attestation".to_string());
    dependent.depends_on = vec!["guardian-link".to_string()];

    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .allowed_claims
        .push("dependent-date-of-birth".to_string());

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

pub(super) fn valid_oid4vci_config() -> StandaloneRegistryNotaryConfig {
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

pub(super) fn add_oid4vci_projection_claim(
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

pub(super) fn valid_oid4vci_projection_config() -> StandaloneRegistryNotaryConfig {
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

pub(super) fn expect_self_attestation_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("self-attestation config must fail validation")
    {
        EvidenceConfigError::InvalidSelfAttestationConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

pub(super) fn expect_oid4vci_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("oid4vci config must fail validation")
    {
        EvidenceConfigError::InvalidOid4vciConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

pub(super) fn expect_federation_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("federation config must fail validation")
    {
        EvidenceConfigError::InvalidFederationConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

pub(super) fn expect_replay_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("replay config must fail validation")
    {
        EvidenceConfigError::InvalidReplayConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

pub(super) fn expect_credential_status_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("credential status config must fail validation")
    {
        EvidenceConfigError::InvalidCredentialStatusConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn admin_listener_defaults_to_disabled_for_simple_local_config() {
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
pub(super) fn server_limits_default_to_relay_parity_values() {
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
pub(super) fn server_limits_must_be_nonzero() {
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
pub(super) fn governed_config_requires_dedicated_admin_listener() {
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
pub(super) fn dedicated_admin_listener_must_not_reuse_public_bind() {
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
