use super::root::{
    expect_credential_status_error, expect_federation_error, expect_replay_error, minimal_claim,
};
use super::support::*;
use super::*;

#[test]
pub(super) fn replay_config_validates_redis_backend_shape() {
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
pub(super) fn credential_status_config_validates_redis_backend_shape() {
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
pub(super) fn federation_legacy_redis_replay_requires_top_level_redis_replay() {
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
pub(super) fn federation_profile_disclosure_must_be_known_profile() {
    let mut config = valid_federation_config();
    config.federation.evaluation_profiles[0].disclosure = Some("raw".to_string());
    let reason = expect_federation_error(&config);
    assert!(reason.contains("disclosure must be value, predicate, or redacted"));
}

// -----------------------------------------------------------------------
// Finding 3: holder binding / did-method mismatch
// -----------------------------------------------------------------------
