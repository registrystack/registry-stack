use super::support::*;
use super::*;
#[allow(unused_imports)]
use super::{auth::*, credentials::*, issuance::*, preauth::*, root::*};

#[test]
pub(super) fn state_postgresql_config_parses_and_validates() {
    let mut config = minimal_config();
    config.state = serde_norway::from_str(
        r#"
storage: postgresql
postgresql:
  url_env: REGISTRY_NOTARY_POSTGRES_URL
  root_certificate_path: /run/secrets/notary-postgres-ca.pem
  connect_timeout_ms: 5000
  operation_timeout_ms: 2000
  sensitive_state_key_env: REGISTRY_NOTARY_SENSITIVE_STATE_KEY
"#,
    )
    .expect("PostgreSQL state config parses");

    config
        .validate()
        .expect("PostgreSQL state config validates");
    assert_eq!(config.state.storage, STATE_STORAGE_POSTGRESQL);
    assert_eq!(
        config.state.postgresql.root_certificate_path.as_deref(),
        Some(std::path::Path::new("/run/secrets/notary-postgres-ca.pem"))
    );
}

#[test]
pub(super) fn state_defaults_to_postgresql_contract() {
    let config = minimal_config();

    assert_eq!(config.state.storage, STATE_STORAGE_POSTGRESQL);
    assert_eq!(
        config.state.postgresql.url_env,
        "REGISTRY_NOTARY_POSTGRES_URL"
    );
    assert_eq!(config.state.postgresql.connect_timeout_ms, 5_000);
    assert_eq!(config.state.postgresql.operation_timeout_ms, 2_000);
    assert_eq!(
        config.state.postgresql.sensitive_state_key_env,
        "REGISTRY_NOTARY_SENSITIVE_STATE_KEY"
    );
    config.validate().expect("default state config validates");
}

#[test]
pub(super) fn state_postgresql_config_rejects_invalid_connection_shape() {
    let mut config = minimal_config();
    config.state.postgresql.url_env.clear();
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("state.postgresql.url_env"),
        "unexpected: {reason}"
    );

    config = minimal_config();
    config.state.postgresql.connect_timeout_ms = 0;
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("connect_timeout_ms"),
        "unexpected: {reason}"
    );

    config = minimal_config();
    config.state.postgresql.operation_timeout_ms = 0;
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("operation_timeout_ms"),
        "unexpected: {reason}"
    );

    config = minimal_config();
    config.state.postgresql.root_certificate_path = Some(std::path::PathBuf::new());
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("root_certificate_path"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn state_in_memory_is_limited_to_local_single_instance() {
    let mut config = minimal_config();
    config.state.storage = STATE_STORAGE_IN_MEMORY.to_string();

    let reason = expect_state_error(&config);
    assert!(
        reason.contains("deployment.profile = local"),
        "unexpected: {reason}"
    );

    config.deployment.profile = Some(crate::deployment::DeploymentProfile::HostedLab);
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("deployment.profile = local"),
        "unexpected: {reason}"
    );

    config.deployment.profile = Some(crate::deployment::DeploymentProfile::Local);
    config.deployment.multi_instance = true;
    let reason = expect_state_error(&config);
    assert!(
        reason.contains("deployment.multi_instance = false"),
        "unexpected: {reason}"
    );

    config.deployment.multi_instance = false;
    config
        .validate()
        .expect("local single-instance in-memory state validates");
}

#[test]
pub(super) fn state_rejects_unknown_storage() {
    let mut config = minimal_config();
    config.state.storage = "redis".to_string();

    let reason = expect_state_error(&config);
    assert!(
        reason.contains("postgresql or in_memory"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn state_postgresql_requires_sensitive_key_env_for_preauthorization() {
    let mut config = valid_pre_auth_config();
    config.state.postgresql.sensitive_state_key_env.clear();

    let reason = expect_state_error(&config);
    assert!(
        reason.contains("sensitive_state_key_env"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn removed_per_domain_storage_selectors_are_rejected() {
    let replay = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
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
replay:
  storage: redis
"#,
    )
    .expect_err("top-level replay config was removed");
    assert!(replay.to_string().contains("replay"));

    let credential_status = serde_norway::from_str::<CredentialStatusConfig>(
        r#"
enabled: true
base_url: https://issuer.example
storage: redis
redis:
  url_env: REGISTRY_NOTARY_STATUS_REDIS_URL
"#,
    )
    .expect_err("credential-status storage selectors were removed");
    let error = credential_status.to_string();
    assert!(error.contains("storage") || error.contains("redis"));
}

#[test]
pub(super) fn credential_status_config_requires_base_url_when_enabled() {
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
pub(super) fn audit_config_deserializes_rotation_and_syslog_fields() {
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

pub(super) fn valid_federation_config() -> StandaloneRegistryNotaryConfig {
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
            evaluation_scopes: vec!["civil_registry:evidence_verification".to_string()],
            ..FederationPeerConfig::default()
        }],
        evaluation_profiles: vec![FederationEvaluationProfileConfig {
            id: "disability_status_predicate".to_string(),
            ruleset: "disability-status-v1".to_string(),
            claim_id: "disability-status".to_string(),
            subject_id_type: "national_id".to_string(),
            disclosure: Some("predicate".to_string()),
            max_claim_result_age_seconds: Some(300),
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
pub(super) fn federation_config_validates_enabled_mvp_shape() {
    valid_federation_config()
        .validate()
        .expect("federation config validates");
}

#[test]
pub(super) fn federation_signing_key_must_reference_active_named_signing_key() {
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
pub(super) fn federation_replay_storage_selector_is_rejected() {
    let error = serde_norway::from_str::<FederationConfig>(
        r#"
replay:
  storage: redis
"#,
    )
    .expect_err("federation replay storage selection was removed");
    assert!(error.to_string().contains("replay"));
}

#[test]
pub(super) fn federation_peer_private_network_jwks_escape_hatch_deserializes_and_validates() {
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
evaluation_scopes:
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
pub(super) fn federation_rejects_removed_source_named_fields() {
    let peer_error = serde_norway::from_str::<FederationPeerConfig>(
        r#"
node_id: did:web:agency-b.example.gov
issuer: https://agency-b.example.gov
jwks_uri: https://agency-b.example.gov/.well-known/jwks.json
source_scopes:
  - civil_registry:evidence_verification
"#,
    )
    .expect_err("the unreleased source_scopes field must not remain an alias");
    assert!(peer_error.to_string().contains("source_scopes"));

    let profile_error = serde_norway::from_str::<FederationEvaluationProfileConfig>(
        r#"
id: disability_status_predicate
ruleset: disability-status-v1
claim_id: disability-status
subject_id_type: national_id
max_source_observed_age_seconds: 300
"#,
    )
    .expect_err("the unreleased source-age field must not remain an alias");
    assert!(profile_error
        .to_string()
        .contains("max_source_observed_age_seconds"));
}

#[test]
pub(super) fn federation_peer_http_private_network_jwks_requires_escape_hatch() {
    let mut config = valid_federation_config();
    config.federation.peers[0].jwks_uri = "http://federation-peer-jwks:8080/jwks.json".to_string();
    let reason = expect_federation_error(&config);
    assert!(reason.contains("jwks_uri must be an HTTPS URL"));
}

#[test]
pub(super) fn federation_config_rejects_bad_did_issuer_binding() {
    let mut config = valid_federation_config();
    config.federation.issuer = "https://other-agency.example.gov".to_string();
    let reason = expect_federation_error(&config);
    assert!(reason.contains("node_id must bind"));
}

#[test]
pub(super) fn federation_config_rejects_missing_protocol_and_bad_profile_reference() {
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
pub(super) fn federation_profile_rejects_registry_backed_claim() {
    let mut config = valid_federation_config();
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
    config.evidence.claims[0] = serde_norway::from_str(
        r#"
id: disability-status
title: Disability status
version: "1"
subject_type: person
evidence_mode:
  type: registry_backed
  consultations:
    disability_status:
      profile:
        id: example.disability-status.exact
        contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      inputs:
        subject_id: target.id
      outputs:
        status: { type: string, nullable: true, max_bytes: 64 }
value:
  type: string
  nullable: true
purpose: benefit-verification
required_scopes:
  - registry:consult:disability-status
rule:
  type: consultation_output
  consultation: disability_status
  output: status
"#,
    )
    .expect("registry-backed claim parses");

    let reason = expect_federation_error(&config);
    assert!(
        reason.contains("cannot reference a registry_backed claim")
            && reason.contains("audit correlation"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn federation_profile_disclosure_must_be_known_profile() {
    let mut config = valid_federation_config();
    config.federation.evaluation_profiles[0].disclosure = Some("raw".to_string());
    let reason = expect_federation_error(&config);
    assert!(reason.contains("disclosure must be value, predicate, or redacted"));
}

// -----------------------------------------------------------------------
// Finding 3: holder binding / did-method mismatch
// -----------------------------------------------------------------------
