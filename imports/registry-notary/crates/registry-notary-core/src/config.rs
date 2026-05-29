// SPDX-License-Identifier: Apache-2.0
//! Registry Notary configuration model.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::net::SocketAddr;

use registry_platform_crypto::validate_did_web_https_issuer_binding;
use registry_platform_oid4vci::{
    CREDENTIAL_SIGNING_ALG_EDDSA, CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK,
    SD_JWT_VC_FORMAT as OID4VCI_SD_JWT_VC_FORMAT,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    DisclosureProfile, FORMAT_SD_JWT_VC, SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_SIGNING_ALG,
};

const PKCE_METHOD_S256: &str = "S256";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneRegistryNotaryConfig {
    #[serde(default)]
    pub server: RegistryNotaryHttpConfig,
    pub evidence: EvidenceConfig,
    pub auth: EvidenceAuthConfig,
    #[serde(default)]
    pub audit: EvidenceAuditConfig,
    #[serde(default, skip_serializing_if = "replay_config_is_default")]
    pub replay: ReplayConfig,
    #[serde(default, skip_serializing_if = "credential_status_config_is_default")]
    pub credential_status: CredentialStatusConfig,
    #[serde(default, skip_serializing_if = "self_attestation_config_is_default")]
    pub self_attestation: SelfAttestationConfig,
    #[serde(default, skip_serializing_if = "oid4vci_config_is_default")]
    pub oid4vci: Oid4vciConfig,
    #[serde(default, skip_serializing_if = "federation_config_is_default")]
    pub federation: FederationConfig,
}

impl StandaloneRegistryNotaryConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.evidence.enabled {
            return Err(EvidenceConfigError::EvidenceDisabled);
        }
        self.replay.validate()?;
        match self.auth.mode.as_str() {
            "api_key" => {
                if self.auth.api_keys.is_empty() && self.auth.bearer_tokens.is_empty() {
                    return Err(EvidenceConfigError::NoCredentialsConfigured);
                }
            }
            "oidc" => {
                let oidc = self
                    .auth
                    .oidc
                    .as_ref()
                    .ok_or(EvidenceConfigError::MissingOidcConfig)?;
                oidc.validate()?;
            }
            _ => {
                return Err(EvidenceConfigError::UnsupportedAuthMode {
                    mode: self.auth.mode.clone(),
                });
            }
        }
        self.evidence.concurrency.validate()?;
        self.credential_status.validate()?;
        for connection in self.evidence.source_connections.values() {
            if connection.max_in_flight < 1 {
                return Err(EvidenceConfigError::InvalidConcurrency);
            }
        }
        // bulk_mode preconditions are enforced at config load so the runtime
        // never observes a misconfigured combination. rda_in_filter requires
        // operator attestation + cardinality=one on every binding pointing
        // at this connection. dci_batched_search requires the dci connector.
        for (connection_id, connection) in &self.evidence.source_connections {
            match connection.bulk_mode {
                BulkMode::None => {}
                BulkMode::RdaInFilter => {
                    if !connection.bulk_mode_lookup_unique {
                        return Err(EvidenceConfigError::BulkModeRequiresUniqueLookup {
                            connection: connection_id.clone(),
                        });
                    }
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.lookup.cardinality != "one" {
                                return Err(EvidenceConfigError::BulkModeRequiresCardinalityOne {
                                    connection: connection_id.clone(),
                                    claim: claim.id.clone(),
                                    binding: binding_id.clone(),
                                });
                            }
                        }
                    }
                }
                BulkMode::DciBatchedSearch => {
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.connector != SourceConnectorKind::Dci {
                                return Err(EvidenceConfigError::BulkModeRequiresDciConnector {
                                    connection: connection_id.clone(),
                                    claim: claim.id.clone(),
                                    binding: binding_id.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        for claim in &self.evidence.claims {
            if claim.id.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidClaim);
            }
            for binding in claim.source_bindings.values() {
                if binding.connection.is_none() {
                    return Err(EvidenceConfigError::MissingSourceConnection);
                }
                if !self
                    .evidence
                    .source_connections
                    .contains_key(binding.connection.as_deref().unwrap_or_default())
                {
                    return Err(EvidenceConfigError::MissingSourceConnection);
                }
            }
        }
        // Registry Notary currently resolves holder material only from
        // did:jwk. Reject any other configured method so discovery metadata
        // cannot advertise support that issuance cannot satisfy.
        for (profile_id, profile) in &self.evidence.credential_profiles {
            if profile.format != FORMAT_SD_JWT_VC {
                return Err(EvidenceConfigError::UnsupportedCredentialProfileFormat {
                    profile: profile_id.clone(),
                    format: profile.format.clone(),
                });
            }
            let unsupported: Vec<String> = profile
                .holder_binding
                .allowed_did_methods
                .iter()
                .filter(|m| m.as_str() != SD_JWT_VC_HOLDER_BINDING_METHOD)
                .cloned()
                .collect();
            if !unsupported.is_empty() {
                return Err(
                    EvidenceConfigError::UnsupportedCredentialProfileDidMethods {
                        profile: profile_id.clone(),
                        methods: unsupported,
                    },
                );
            }
            // An empty allowed_claims short-circuits the issuance-time filter
            // in api.rs (`is_empty()` means "any claim allowed"). Require
            // operators to enumerate the claims a profile may bind to. A list
            // composed only of blank entries is treated the same as empty so
            // operators cannot trip the short-circuit via `[""]`.
            if profile
                .allowed_claims
                .iter()
                .all(|claim| claim.trim().is_empty())
            {
                return Err(EvidenceConfigError::EmptyAllowedClaims {
                    profile: profile_id.clone(),
                });
            }
        }
        // Finding 8: detect cycles in the depends_on graph using DFS with
        // grey (in-progress) and black (done) sets.
        let claim_ids: HashSet<&str> = self.evidence.claims.iter().map(|c| c.id.as_str()).collect();
        for claim in &self.evidence.claims {
            for dep in &claim.depends_on {
                if !claim_ids.contains(dep.as_str()) {
                    return Err(EvidenceConfigError::DependsOnUnknownClaim {
                        claim: claim.id.clone(),
                        unknown: dep.clone(),
                    });
                }
            }
        }
        let mut grey: HashSet<String> = HashSet::new();
        let mut black: HashSet<String> = HashSet::new();
        for claim in &self.evidence.claims {
            if !black.contains(&claim.id) {
                detect_depends_on_cycle(
                    &self.evidence.claims,
                    &claim.id,
                    &mut grey,
                    &mut black,
                    &mut Vec::new(),
                )?;
            }
        }
        self.self_attestation.validate(&self.auth, &self.evidence)?;
        self.validate_oid4vci_cross_block()?;
        self.federation.validate(&self.evidence)?;
        self.validate_replay_cross_block()?;
        Ok(())
    }

    fn validate_oid4vci_cross_block(&self) -> Result<(), EvidenceConfigError> {
        self.oid4vci
            .validate(&self.self_attestation, &self.evidence)
    }

    fn validate_replay_cross_block(&self) -> Result<(), EvidenceConfigError> {
        if self.federation.enabled
            && self.federation.replay.storage == REPLAY_STORAGE_REDIS
            && self.replay.storage != REPLAY_STORAGE_REDIS
        {
            return Err(EvidenceConfigError::InvalidFederationConfig {
                reason:
                    "federation.replay.storage = redis requires top-level replay.storage = redis"
                        .to_string(),
            });
        }
        Ok(())
    }
}

pub const FEDERATION_PROTOCOL_V0_1: &str = "registry-notary-federation/v0.1";
pub const FEDERATION_REQUEST_JWT_TYP: &str = "registry-notary-request+jwt";
pub const FEDERATION_RESPONSE_JWT_TYP: &str = "registry-notary-response+jwt";
pub const FEDERATION_SIGNING_ALG_EDDSA: &str = "EdDSA";

pub const REPLAY_STORAGE_IN_MEMORY: &str = "in_memory";
pub const REPLAY_STORAGE_REDIS: &str = "redis";

pub const CREDENTIAL_STATUS_STORAGE_IN_MEMORY: &str = "in_memory";
pub const CREDENTIAL_STATUS_STORAGE_REDIS: &str = "redis";
pub const CREDENTIAL_STATUS_VALID: &str = "valid";
pub const CREDENTIAL_STATUS_SUSPENDED: &str = "suspended";
pub const CREDENTIAL_STATUS_REVOKED: &str = "revoked";
pub const CREDENTIAL_STATUS_EXPIRED: &str = "expired";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConfig {
    #[serde(default = "default_replay_storage")]
    pub storage: String,
    #[serde(default)]
    pub redis: ReplayRedisConfig,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            storage: default_replay_storage(),
            redis: ReplayRedisConfig::default(),
        }
    }
}

impl ReplayConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        match self.storage.as_str() {
            REPLAY_STORAGE_IN_MEMORY => Ok(()),
            REPLAY_STORAGE_REDIS => {
                validate_replay_non_empty("replay.redis.url_env", &self.redis.url_env)?;
                validate_replay_non_empty("replay.redis.key_prefix", &self.redis.key_prefix)?;
                if self.redis.connect_timeout_ms == 0 {
                    return invalid_replay(
                        "replay.redis.connect_timeout_ms must be greater than zero",
                    );
                }
                if self.redis.operation_timeout_ms == 0 {
                    return invalid_replay(
                        "replay.redis.operation_timeout_ms must be greater than zero",
                    );
                }
                Ok(())
            }
            _ => invalid_replay("replay.storage must be in_memory or redis"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRedisConfig {
    #[serde(default)]
    pub url_env: String,
    #[serde(default = "default_replay_redis_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_replay_redis_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_replay_redis_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
}

impl Default for ReplayRedisConfig {
    fn default() -> Self {
        Self {
            url_env: String::new(),
            key_prefix: default_replay_redis_key_prefix(),
            connect_timeout_ms: default_replay_redis_connect_timeout_ms(),
            operation_timeout_ms: default_replay_redis_operation_timeout_ms(),
        }
    }
}

fn replay_config_is_default(config: &ReplayConfig) -> bool {
    config == &ReplayConfig::default()
}

fn default_replay_storage() -> String {
    REPLAY_STORAGE_IN_MEMORY.to_string()
}

fn default_replay_redis_key_prefix() -> String {
    "registry-notary".to_string()
}

const fn default_replay_redis_connect_timeout_ms() -> u64 {
    1000
}

const fn default_replay_redis_operation_timeout_ms() -> u64 {
    500
}

fn validate_replay_non_empty(field: &str, value: &str) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_replay(format!("{field} must not be empty"));
    }
    Ok(())
}

fn invalid_replay<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidReplayConfig {
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatusConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default = "default_credential_status_storage")]
    pub storage: String,
    #[serde(default = "default_credential_status_retention_seconds")]
    pub retention_seconds: u64,
    #[serde(default)]
    pub redis: CredentialStatusRedisConfig,
}

impl Default for CredentialStatusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            storage: default_credential_status_storage(),
            retention_seconds: default_credential_status_retention_seconds(),
            redis: CredentialStatusRedisConfig::default(),
        }
    }
}

impl CredentialStatusConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_credential_status_http_url("credential_status.base_url", &self.base_url)?;
        if self.retention_seconds == 0 {
            return invalid_credential_status(
                "credential_status.retention_seconds must be greater than zero",
            );
        }
        match self.storage.as_str() {
            CREDENTIAL_STATUS_STORAGE_IN_MEMORY => Ok(()),
            CREDENTIAL_STATUS_STORAGE_REDIS => {
                validate_credential_status_non_empty(
                    "credential_status.redis.url_env",
                    &self.redis.url_env,
                )?;
                validate_credential_status_non_empty(
                    "credential_status.redis.key_prefix",
                    &self.redis.key_prefix,
                )?;
                if self.redis.connect_timeout_ms == 0 {
                    return invalid_credential_status(
                        "credential_status.redis.connect_timeout_ms must be greater than zero",
                    );
                }
                if self.redis.operation_timeout_ms == 0 {
                    return invalid_credential_status(
                        "credential_status.redis.operation_timeout_ms must be greater than zero",
                    );
                }
                Ok(())
            }
            _ => invalid_credential_status("credential_status.storage must be in_memory or redis"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatusRedisConfig {
    #[serde(default)]
    pub url_env: String,
    #[serde(default = "default_credential_status_redis_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_credential_status_redis_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_credential_status_redis_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
}

impl Default for CredentialStatusRedisConfig {
    fn default() -> Self {
        Self {
            url_env: String::new(),
            key_prefix: default_credential_status_redis_key_prefix(),
            connect_timeout_ms: default_credential_status_redis_connect_timeout_ms(),
            operation_timeout_ms: default_credential_status_redis_operation_timeout_ms(),
        }
    }
}

fn credential_status_config_is_default(config: &CredentialStatusConfig) -> bool {
    config == &CredentialStatusConfig::default()
}

fn default_credential_status_storage() -> String {
    CREDENTIAL_STATUS_STORAGE_IN_MEMORY.to_string()
}

const fn default_credential_status_retention_seconds() -> u64 {
    86_400
}

fn default_credential_status_redis_key_prefix() -> String {
    "registry-notary".to_string()
}

const fn default_credential_status_redis_connect_timeout_ms() -> u64 {
    1000
}

const fn default_credential_status_redis_operation_timeout_ms() -> u64 {
    500
}

fn validate_credential_status_non_empty(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_credential_status(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_credential_status_http_url(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    validate_credential_status_non_empty(field, value)?;
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return invalid_credential_status(format!("{field} must be an HTTP or HTTPS URL"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return invalid_credential_status(format!("{field} must include a valid host"));
    }
    Ok(())
}

fn invalid_credential_status<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidCredentialStatusConfig {
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub federation_api: String,
    #[serde(default)]
    pub supported_protocol_versions: Vec<String>,
    #[serde(default = "default_federation_inbound_body_limit_bytes")]
    pub inbound_body_limit_bytes: usize,
    #[serde(default = "default_federation_max_request_lifetime_seconds")]
    pub max_request_lifetime_seconds: u64,
    #[serde(default = "default_federation_clock_leeway_seconds")]
    pub clock_leeway_seconds: u64,
    #[serde(default)]
    pub signing: FederationSigningConfig,
    #[serde(default)]
    pub pairwise_subject_hash: FederationPairwiseSubjectHashConfig,
    #[serde(default)]
    pub replay: FederationReplayConfig,
    #[serde(default)]
    pub response_shaping: FederationResponseShapingConfig,
    #[serde(default)]
    pub emergency_denylist: FederationEmergencyDenylistConfig,
    #[serde(default)]
    pub peers: Vec<FederationPeerConfig>,
    #[serde(default)]
    pub evaluation_profiles: Vec<FederationEvaluationProfileConfig>,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            issuer: String::new(),
            jwks_uri: String::new(),
            federation_api: String::new(),
            supported_protocol_versions: Vec::new(),
            inbound_body_limit_bytes: default_federation_inbound_body_limit_bytes(),
            max_request_lifetime_seconds: default_federation_max_request_lifetime_seconds(),
            clock_leeway_seconds: default_federation_clock_leeway_seconds(),
            signing: FederationSigningConfig::default(),
            pairwise_subject_hash: FederationPairwiseSubjectHashConfig::default(),
            replay: FederationReplayConfig::default(),
            response_shaping: FederationResponseShapingConfig::default(),
            emergency_denylist: FederationEmergencyDenylistConfig::default(),
            peers: Vec::new(),
            evaluation_profiles: Vec::new(),
        }
    }
}

fn federation_config_is_default(config: &FederationConfig) -> bool {
    config == &FederationConfig::default()
}

const fn default_federation_inbound_body_limit_bytes() -> usize {
    16 * 1024
}

const fn default_federation_max_request_lifetime_seconds() -> u64 {
    300
}

const fn default_federation_clock_leeway_seconds() -> u64 {
    60
}

impl FederationConfig {
    fn validate(&self, evidence: &EvidenceConfig) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_federation_non_empty("federation.node_id", &self.node_id)?;
        validate_federation_non_empty("federation.issuer", &self.issuer)?;
        validate_federation_https_url("federation.issuer", &self.issuer)?;
        validate_federation_https_url("federation.jwks_uri", &self.jwks_uri)?;
        validate_federation_https_url("federation.federation_api", &self.federation_api)?;
        validate_did_web_https_issuer_binding(&self.node_id, &self.issuer).map_err(|error| {
            EvidenceConfigError::InvalidFederationConfig {
                reason: format!("federation.node_id must bind to federation.issuer: {error}"),
            }
        })?;
        if !self
            .supported_protocol_versions
            .iter()
            .any(|version| version == FEDERATION_PROTOCOL_V0_1)
        {
            return invalid_federation("federation.supported_protocol_versions must include registry-notary-federation/v0.1");
        }
        if self.inbound_body_limit_bytes == 0 {
            return invalid_federation(
                "federation.inbound_body_limit_bytes must be greater than zero",
            );
        }
        if self.max_request_lifetime_seconds == 0 {
            return invalid_federation(
                "federation.max_request_lifetime_seconds must be greater than zero",
            );
        }
        if self.signing.alg != FEDERATION_SIGNING_ALG_EDDSA {
            return invalid_federation("federation.signing.alg must be EdDSA");
        }
        validate_federation_non_empty("federation.signing.kid", &self.signing.kid)?;
        validate_federation_non_empty("federation.signing.key_env", &self.signing.key_env)?;
        validate_federation_non_empty(
            "federation.pairwise_subject_hash.secret_env",
            &self.pairwise_subject_hash.secret_env,
        )?;
        if self.replay.storage != FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY
            && self.replay.storage != REPLAY_STORAGE_IN_MEMORY
            && self.replay.storage != REPLAY_STORAGE_REDIS
        {
            return invalid_federation(
                "federation.replay.storage must be in_process_single_instance_only, in_memory, or redis",
            );
        }
        if self.replay.max_entries == 0 {
            return invalid_federation("federation.replay.max_entries must be greater than zero");
        }
        if self.replay.eviction != FEDERATION_REPLAY_EVICT_EXPIRE_OLDEST {
            return invalid_federation("federation.replay.eviction must be expire_oldest");
        }
        if self.peers.is_empty() {
            return invalid_federation("federation.peers must list at least one peer");
        }
        if self.evaluation_profiles.is_empty() {
            return invalid_federation(
                "federation.evaluation_profiles must list at least one profile",
            );
        }
        let claim_ids: HashSet<&str> = evidence
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        let mut profile_ids = HashSet::new();
        for profile in &self.evaluation_profiles {
            validate_federation_non_empty("federation.evaluation_profiles[].id", &profile.id)?;
            if !profile_ids.insert(profile.id.as_str()) {
                return invalid_federation("federation.evaluation_profiles contains duplicate id");
            }
            validate_federation_non_empty(
                "federation.evaluation_profiles[].ruleset",
                &profile.ruleset,
            )?;
            validate_federation_non_empty(
                "federation.evaluation_profiles[].claim_id",
                &profile.claim_id,
            )?;
            if !claim_ids.contains(profile.claim_id.as_str()) {
                return invalid_federation(
                    "federation.evaluation_profiles[].claim_id must reference an evidence claim",
                );
            }
            validate_federation_non_empty(
                "federation.evaluation_profiles[].subject_id_type",
                &profile.subject_id_type,
            )?;
            if let Some(disclosure) = profile.disclosure.as_deref() {
                if DisclosureProfile::parse(disclosure).is_none() {
                    return invalid_federation(
                        "federation.evaluation_profiles[].disclosure must be value, predicate, or redacted",
                    );
                }
            }
        }
        let mut peer_nodes = HashSet::new();
        for peer in &self.peers {
            validate_federation_non_empty("federation.peers[].node_id", &peer.node_id)?;
            validate_federation_non_empty("federation.peers[].issuer", &peer.issuer)?;
            validate_federation_https_url("federation.peers[].issuer", &peer.issuer)?;
            if peer.allow_insecure_private_network {
                validate_federation_http_or_https_url(
                    "federation.peers[].jwks_uri",
                    &peer.jwks_uri,
                )?;
            } else if peer.allow_insecure_localhost {
                validate_federation_localhost_or_https_url(
                    "federation.peers[].jwks_uri",
                    &peer.jwks_uri,
                )?;
            } else {
                validate_federation_https_url("federation.peers[].jwks_uri", &peer.jwks_uri)?;
            }
            validate_did_web_https_issuer_binding(&peer.node_id, &peer.issuer).map_err(
                |error| EvidenceConfigError::InvalidFederationConfig {
                    reason: format!("federation.peers[].node_id must bind to issuer: {error}"),
                },
            )?;
            if !peer_nodes.insert(peer.node_id.as_str()) {
                return invalid_federation("federation.peers contains duplicate node_id");
            }
            if !peer
                .allowed_protocol_versions
                .iter()
                .any(|version| version == FEDERATION_PROTOCOL_V0_1)
            {
                return invalid_federation(
                    "federation.peers[].allowed_protocol_versions must include registry-notary-federation/v0.1",
                );
            }
            for purpose in &peer.allowed_purposes {
                validate_federation_https_url("federation.peers[].allowed_purposes[]", purpose)?;
            }
            for profile in &peer.allowed_profiles {
                if !profile_ids.contains(profile.as_str()) {
                    return invalid_federation(
                        "federation.peers[].allowed_profiles must reference an evaluation profile",
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationSigningConfig {
    pub kid: String,
    pub key_env: String,
    #[serde(default = "default_federation_signing_alg")]
    pub alg: String,
}

impl Default for FederationSigningConfig {
    fn default() -> Self {
        Self {
            kid: String::new(),
            key_env: String::new(),
            alg: default_federation_signing_alg(),
        }
    }
}

fn default_federation_signing_alg() -> String {
    FEDERATION_SIGNING_ALG_EDDSA.to_string()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPairwiseSubjectHashConfig {
    #[serde(default)]
    pub secret_env: String,
}

pub const FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY: &str =
    "in_process_single_instance_only";
pub const FEDERATION_REPLAY_EVICT_EXPIRE_OLDEST: &str = "expire_oldest";

/// Replay protection settings for the federation MVP.
///
/// `in_process_single_instance_only` is deliberately named as an operator
/// warning. It is not safe for active-active serving Notary deployments
/// because a replay accepted by one process is invisible to another process.
/// Production multi-instance federation needs a shared replay store before
/// privileged federation routes are enabled.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationReplayConfig {
    #[serde(default = "default_federation_replay_storage")]
    pub storage: String,
    #[serde(default = "default_federation_replay_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_federation_replay_eviction")]
    pub eviction: String,
}

impl Default for FederationReplayConfig {
    fn default() -> Self {
        Self {
            storage: default_federation_replay_storage(),
            max_entries: default_federation_replay_max_entries(),
            eviction: default_federation_replay_eviction(),
        }
    }
}

fn default_federation_replay_storage() -> String {
    FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY.to_string()
}

const fn default_federation_replay_max_entries() -> usize {
    10_000
}

fn default_federation_replay_eviction() -> String {
    FEDERATION_REPLAY_EVICT_EXPIRE_OLDEST.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationResponseShapingConfig {
    #[serde(default = "default_minimum_denial_latency_ms")]
    pub minimum_denial_latency_ms: u64,
}

impl Default for FederationResponseShapingConfig {
    fn default() -> Self {
        Self {
            minimum_denial_latency_ms: default_minimum_denial_latency_ms(),
        }
    }
}

const fn default_minimum_denial_latency_ms() -> u64 {
    250
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEmergencyDenylistConfig {
    #[serde(default)]
    pub node_ids: Vec<String>,
    #[serde(default)]
    pub kids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeerConfig {
    pub node_id: String,
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    #[serde(default)]
    pub allow_insecure_private_network: bool,
    #[serde(default)]
    pub allowed_protocol_versions: Vec<String>,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub allowed_profiles: Vec<String>,
    #[serde(default)]
    pub source_scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEvaluationProfileConfig {
    pub id: String,
    pub ruleset: String,
    pub claim_id: String,
    pub subject_id_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_source_observed_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub credential_issuer: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub accepted_token_audiences: Vec<String>,
    #[serde(default)]
    pub credential_endpoint: String,
    #[serde(default)]
    pub offer_endpoint: String,
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    #[serde(default)]
    pub nonce: Oid4vciNonceConfig,
    #[serde(default)]
    pub authorization: Oid4vciAuthorizationConfig,
    #[serde(default)]
    pub proof: Oid4vciProofConfig,
    #[serde(default)]
    pub credential_configurations: BTreeMap<String, Oid4vciCredentialConfigurationConfig>,
}

fn oid4vci_config_is_default(config: &Oid4vciConfig) -> bool {
    config == &Oid4vciConfig::default()
}

impl Oid4vciConfig {
    fn validate(
        &self,
        self_attestation: &SelfAttestationConfig,
        evidence: &EvidenceConfig,
    ) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !self_attestation.enabled {
            return invalid_oid4vci("enabled oid4vci requires self_attestation.enabled = true");
        }
        validate_oid4vci_public_url("oid4vci.credential_issuer", &self.credential_issuer)?;
        validate_oid4vci_endpoint_url(
            "oid4vci.credential_endpoint",
            &self.credential_endpoint,
            &self.credential_issuer,
        )?;
        validate_oid4vci_endpoint_url(
            "oid4vci.offer_endpoint",
            &self.offer_endpoint,
            &self.credential_issuer,
        )?;
        validate_oid4vci_non_empty_entries(
            "oid4vci.authorization_servers",
            &self.authorization_servers,
        )?;
        for server in &self.authorization_servers {
            validate_oid4vci_public_url("oid4vci.authorization_servers", server)?;
        }
        validate_oid4vci_non_empty_entries(
            "oid4vci.accepted_token_audiences",
            &self.accepted_token_audiences,
        )?;
        if self.credential_configurations.is_empty() {
            return invalid_oid4vci("credential_configurations must not be empty");
        }
        if self.nonce.enabled {
            let nonce_endpoint = self.nonce_endpoint.as_deref().ok_or_else(|| {
                EvidenceConfigError::InvalidOid4vciConfig {
                    reason: "nonce_endpoint must be configured when nonce.enabled = true"
                        .to_string(),
                }
            })?;
            validate_oid4vci_endpoint_url(
                "oid4vci.nonce_endpoint",
                nonce_endpoint,
                &self.credential_issuer,
            )?;
        } else if let Some(nonce_endpoint) = self.nonce_endpoint.as_deref() {
            validate_oid4vci_endpoint_url(
                "oid4vci.nonce_endpoint",
                nonce_endpoint,
                &self.credential_issuer,
            )?;
        }
        self.nonce.validate()?;
        self.authorization.validate()?;
        self.proof.validate()?;

        let claim_ids: HashSet<&str> = evidence
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        let allowed_claim_ids: HashSet<&str> = self_attestation
            .allowed_claims
            .iter()
            .map(String::as_str)
            .collect();
        let allowed_profiles: HashSet<&str> = self_attestation
            .credential_profiles
            .iter()
            .map(String::as_str)
            .collect();

        for (configuration_id, configuration) in &self.credential_configurations {
            configuration.validate(
                configuration_id,
                evidence,
                &claim_ids,
                &allowed_claim_ids,
                &allowed_profiles,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciNonceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_oid4vci_nonce_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for Oid4vciNonceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_oid4vci_nonce_ttl_seconds(),
        }
    }
}

impl Oid4vciNonceConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.ttl_seconds == 0 || self.ttl_seconds > 600 {
            return invalid_oid4vci("nonce.ttl_seconds must be between 1 and 600");
        }
        Ok(())
    }
}

const fn default_oid4vci_nonce_ttl_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciAuthorizationConfig {
    #[serde(default = "default_oid4vci_pkce_method")]
    pub require_pkce_method: String,
}

impl Default for Oid4vciAuthorizationConfig {
    fn default() -> Self {
        Self {
            require_pkce_method: default_oid4vci_pkce_method(),
        }
    }
}

impl Oid4vciAuthorizationConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.require_pkce_method != PKCE_METHOD_S256 {
            return invalid_oid4vci("authorization.require_pkce_method must be S256");
        }
        Ok(())
    }
}

fn default_oid4vci_pkce_method() -> String {
    PKCE_METHOD_S256.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciProofConfig {
    #[serde(default = "default_oid4vci_proof_max_age_seconds")]
    pub max_age_seconds: u64,
    #[serde(default = "default_oid4vci_proof_max_clock_skew_seconds")]
    pub max_clock_skew_seconds: u64,
}

impl Default for Oid4vciProofConfig {
    fn default() -> Self {
        Self {
            max_age_seconds: default_oid4vci_proof_max_age_seconds(),
            max_clock_skew_seconds: default_oid4vci_proof_max_clock_skew_seconds(),
        }
    }
}

impl Oid4vciProofConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.max_age_seconds == 0 || self.max_age_seconds > 600 {
            return invalid_oid4vci("proof.max_age_seconds must be between 1 and 600");
        }
        if self.max_clock_skew_seconds > 60 {
            return invalid_oid4vci("proof.max_clock_skew_seconds must be at most 60");
        }
        Ok(())
    }
}

const fn default_oid4vci_proof_max_age_seconds() -> u64 {
    300
}

const fn default_oid4vci_proof_max_clock_skew_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialConfigurationConfig {
    pub claim_id: String,
    pub credential_profile: String,
    pub format: String,
    pub scope: String,
    pub vct: String,
    pub display_name: String,
    #[serde(default = "default_oid4vci_proof_signing_alg_values_supported")]
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(default = "default_oid4vci_cryptographic_binding_methods_supported")]
    pub cryptographic_binding_methods_supported: Vec<String>,
}

impl Oid4vciCredentialConfigurationConfig {
    fn validate(
        &self,
        configuration_id: &str,
        evidence: &EvidenceConfig,
        claim_ids: &HashSet<&str>,
        allowed_claim_ids: &HashSet<&str>,
        allowed_profiles: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError> {
        if configuration_id.trim().is_empty() {
            return invalid_oid4vci("credential_configurations must not contain a blank id");
        }
        validate_oid4vci_non_empty_value("credential_configurations.claim_id", &self.claim_id)?;
        validate_oid4vci_non_empty_value(
            "credential_configurations.credential_profile",
            &self.credential_profile,
        )?;
        validate_oid4vci_non_empty_value("credential_configurations.scope", &self.scope)?;
        validate_oid4vci_non_empty_value(
            "credential_configurations.display_name",
            &self.display_name,
        )?;
        if !claim_ids.contains(self.claim_id.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references unknown claim '{}'",
                self.claim_id
            ));
        }
        if !allowed_claim_ids.contains(self.claim_id.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references claim '{}' outside self_attestation.allowed_claims",
                self.claim_id
            ));
        }
        let profile = evidence
            .credential_profiles
            .get(&self.credential_profile)
            .ok_or_else(|| EvidenceConfigError::InvalidOid4vciConfig {
                reason: format!(
                    "credential configuration '{configuration_id}' references unknown credential profile '{}'",
                    self.credential_profile
                ),
            })?;
        if !allowed_profiles.contains(self.credential_profile.as_str()) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references credential profile '{}' outside self_attestation.credential_profiles",
                self.credential_profile
            ));
        }
        if !profile
            .allowed_claims
            .iter()
            .any(|claim_id| claim_id == &self.claim_id)
        {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' maps claim '{}' to credential profile '{}' but the profile does not allow that claim",
                self.claim_id, self.credential_profile
            ));
        }
        let claim = evidence
            .claims
            .iter()
            .find(|claim| claim.id == self.claim_id)
            // SAFETY: the loop above has already rejected every unknown
            // credential configuration claim id before this lookup.
            .expect("claim id was checked above");
        if !claim
            .credential_profiles
            .iter()
            .any(|profile_id| profile_id == &self.credential_profile)
        {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' maps claim '{}' to credential profile '{}' but the claim does not reference that profile",
                self.claim_id, self.credential_profile
            ));
        }
        if self.format != OID4VCI_SD_JWT_VC_FORMAT {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' format must be dc+sd-jwt"
            ));
        }
        if profile.format != FORMAT_SD_JWT_VC {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' references credential profile '{}' with unsupported format '{}'",
                self.credential_profile, profile.format
            ));
        }
        if self.vct != profile.vct {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' vct must match credential profile '{}'",
                self.credential_profile
            ));
        }
        validate_oid4vci_public_url("credential_configurations.vct", &self.vct)?;
        validate_oid4vci_non_empty_entries(
            "credential_configurations.proof_signing_alg_values_supported",
            &self.proof_signing_alg_values_supported,
        )?;
        for alg in &self.proof_signing_alg_values_supported {
            if alg != CREDENTIAL_SIGNING_ALG_EDDSA {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' supports unsupported proof signing algorithm '{alg}'"
                ));
            }
        }
        validate_oid4vci_non_empty_entries(
            "credential_configurations.cryptographic_binding_methods_supported",
            &self.cryptographic_binding_methods_supported,
        )?;
        for method in &self.cryptographic_binding_methods_supported {
            if method != CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' supports unsupported binding method '{method}'"
                ));
            }
        }
        Ok(())
    }
}

fn default_oid4vci_proof_signing_alg_values_supported() -> Vec<String> {
    vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()]
}

fn default_oid4vci_cryptographic_binding_methods_supported() -> Vec<String> {
    vec![CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK.to_string()]
}

fn validate_oid4vci_public_url(name: &str, url: &str) -> Result<(), EvidenceConfigError> {
    let url = url.trim();
    let (scheme, authority, _) =
        split_absolute_url(url).ok_or_else(|| EvidenceConfigError::InvalidOid4vciConfig {
            reason: format!("{name} must be an absolute URL"),
        })?;
    if scheme != "https" && !(scheme == "http" && is_insecure_localhost_url(url)) {
        return invalid_oid4vci(format!(
            "{name} must use https unless it is an http loopback URL"
        ));
    }
    if authority.is_empty() {
        return invalid_oid4vci(format!("{name} must include a host"));
    }
    if url.contains('#') {
        return invalid_oid4vci(format!("{name} must not include a fragment"));
    }
    Ok(())
}

fn validate_oid4vci_endpoint_url(
    name: &str,
    url: &str,
    credential_issuer: &str,
) -> Result<(), EvidenceConfigError> {
    validate_oid4vci_public_url(name, url)?;
    // SAFETY: validate_oid4vci_public_url accepted the absolute URL shape.
    let (_, _, path) = split_absolute_url(url).expect("absolute URL was validated above");
    if path.is_empty() || path == "/" {
        return invalid_oid4vci(format!("{name} must include an endpoint path"));
    }
    if url.contains('?') {
        return invalid_oid4vci(format!("{name} must not include a query string"));
    }
    let issuer_prefix = credential_issuer.trim().trim_end_matches('/');
    if !url.trim().starts_with(&format!("{issuer_prefix}/")) {
        return invalid_oid4vci(format!("{name} must be under oid4vci.credential_issuer"));
    }
    Ok(())
}

fn split_absolute_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let path = if rest[authority_end..].starts_with('/') {
        rest[authority_end..]
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
    } else {
        ""
    };
    Some((scheme, authority, path))
}

fn validate_oid4vci_non_empty_entries(
    name: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_oid4vci(format!("{name} must not be empty"));
    }
    for value in values {
        validate_oid4vci_non_empty_value(name, value)?;
    }
    Ok(())
}

fn validate_oid4vci_non_empty_value(name: &str, value: &str) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_oid4vci(format!("{name} must not contain blank entries"));
    }
    Ok(())
}

fn invalid_oid4vci<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidOid4vciConfig {
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_self_attestation_required_auth_mode")]
    pub requires_auth_mode: String,
    #[serde(default)]
    pub subject_binding: SelfAttestationSubjectBindingConfig,
    #[serde(default)]
    pub citizen_clients: SelfAttestationCitizenClientsConfig,
    #[serde(default)]
    pub token_policy: SelfAttestationTokenPolicyConfig,
    #[serde(default)]
    pub allowed_operations: SelfAttestationOperationsConfig,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub allowed_formats: Vec<String>,
    #[serde(default)]
    pub allowed_disclosures: Vec<String>,
    #[serde(default)]
    pub scope_policy: SelfAttestationScopePolicy,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_wallet_origins: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub rate_limits: SelfAttestationRateLimitsConfig,
}

fn self_attestation_config_is_default(config: &SelfAttestationConfig) -> bool {
    config == &SelfAttestationConfig::default()
}

impl Default for SelfAttestationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requires_auth_mode: default_self_attestation_required_auth_mode(),
            subject_binding: SelfAttestationSubjectBindingConfig::default(),
            citizen_clients: SelfAttestationCitizenClientsConfig::default(),
            token_policy: SelfAttestationTokenPolicyConfig::default(),
            allowed_operations: SelfAttestationOperationsConfig::default(),
            allowed_purposes: Vec::new(),
            allowed_claims: Vec::new(),
            allowed_formats: Vec::new(),
            allowed_disclosures: Vec::new(),
            scope_policy: SelfAttestationScopePolicy::default(),
            required_scopes: Vec::new(),
            allowed_wallet_origins: Vec::new(),
            credential_profiles: Vec::new(),
            rate_limits: SelfAttestationRateLimitsConfig::default(),
        }
    }
}

fn default_self_attestation_required_auth_mode() -> String {
    "oidc".to_string()
}

impl SelfAttestationConfig {
    fn validate(
        &self,
        auth: &EvidenceAuthConfig,
        evidence: &EvidenceConfig,
    ) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.requires_auth_mode != "oidc" {
            return self.invalid("requires_auth_mode must be oidc");
        }
        if auth.mode != "oidc" {
            return self.invalid("enabled self_attestation requires auth.mode = oidc");
        }
        let oidc = auth
            .oidc
            .as_ref()
            .ok_or(EvidenceConfigError::MissingOidcConfig)?;

        self.subject_binding.validate()?;
        self.citizen_clients.validate(oidc)?;
        self.token_policy.validate(oidc)?;
        if self.subject_binding.claim_source == SelfAttestationClaimSource::Userinfo
            && oidc
                .userinfo_endpoint
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        {
            return self.invalid(
                "subject_binding.claim_source = userinfo requires auth.oidc.userinfo_endpoint",
            );
        }
        self.allowed_operations.validate()?;
        validate_non_empty_entries("self_attestation.allowed_purposes", &self.allowed_purposes)?;
        validate_non_empty_entries("self_attestation.allowed_claims", &self.allowed_claims)?;
        validate_non_empty_entries("self_attestation.allowed_formats", &self.allowed_formats)?;
        validate_non_empty_entries(
            "self_attestation.allowed_disclosures",
            &self.allowed_disclosures,
        )?;
        if self.scope_policy != SelfAttestationScopePolicy::Disabled
            && self.required_scopes.is_empty()
        {
            return self.invalid("scope_policy requires required_scopes unless it is disabled");
        }
        if self.scope_policy == SelfAttestationScopePolicy::Disabled
            && !self.required_scopes.is_empty()
        {
            return self.invalid("scope_policy = disabled requires required_scopes to be empty");
        }
        if self.scope_policy != SelfAttestationScopePolicy::Disabled {
            validate_non_empty_entries("self_attestation.required_scopes", &self.required_scopes)?;
        } else {
            validate_entries("self_attestation.required_scopes", &self.required_scopes)?;
        }
        validate_non_empty_entries(
            "self_attestation.credential_profiles",
            &self.credential_profiles,
        )?;
        self.rate_limits.validate()?;
        validate_exact_wallet_origins(&self.allowed_wallet_origins)?;

        let claim_ids: HashSet<&str> = evidence
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        let allowed_claim_ids: HashSet<&str> =
            self.allowed_claims.iter().map(String::as_str).collect();
        let allowed_purposes: HashSet<&str> =
            self.allowed_purposes.iter().map(String::as_str).collect();
        let allowed_formats: HashSet<&str> =
            self.allowed_formats.iter().map(String::as_str).collect();
        let allowed_disclosures: HashSet<&str> = self
            .allowed_disclosures
            .iter()
            .map(String::as_str)
            .collect();
        let allowed_profiles: HashSet<&str> = self
            .credential_profiles
            .iter()
            .map(String::as_str)
            .collect();

        for claim_id in &self.allowed_claims {
            if !claim_ids.contains(claim_id.as_str()) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!("allowed_claims references unknown claim '{claim_id}'"),
                });
            }
        }

        for profile_id in &self.credential_profiles {
            if !evidence.credential_profiles.contains_key(profile_id) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "credential_profiles references unknown profile '{profile_id}'"
                    ),
                });
            }
        }

        for profile_id in &self.credential_profiles {
            let profile = evidence
                .credential_profiles
                .get(profile_id)
                // SAFETY: the preceding credential_profiles loop rejects
                // every profile id missing from evidence.credential_profiles.
                .expect("profile id was checked above");
            validate_self_attestation_profile(
                profile_id,
                profile,
                &claim_ids,
                &allowed_claim_ids,
                &allowed_formats,
                self.token_policy.max_credential_validity_seconds,
            )?;
        }

        for claim_id in &self.allowed_claims {
            let claim = evidence
                .claims
                .iter()
                .find(|claim| claim.id == *claim_id)
                // SAFETY: the preceding allowed_claims loop rejects every
                // claim id missing from evidence.claims.
                .expect("claim id was checked above");
            validate_self_attestation_claim(
                claim,
                &allowed_purposes,
                &allowed_formats,
                &allowed_disclosures,
                &allowed_profiles,
                self.allowed_operations.issue_credential,
            )?;
        }

        validate_self_attestation_allow_lists_are_supported(self, evidence)?;
        if self.scope_policy != SelfAttestationScopePolicy::Disabled {
            validate_required_scopes_do_not_grant_source_access(self, oidc, evidence)?;
        }
        Ok(())
    }

    fn invalid<T>(&self, reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
        Err(EvidenceConfigError::InvalidSelfAttestationConfig {
            reason: reason.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAttestationScopePolicy {
    #[default]
    Required,
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationSubjectBindingConfig {
    #[serde(default)]
    pub token_claim: String,
    #[serde(default)]
    pub claim_source: SelfAttestationClaimSource,
    #[serde(default)]
    pub request_field: SubjectId,
    #[serde(default)]
    pub id_type: String,
    #[serde(default)]
    pub normalize: SubjectBindingNormalize,
    #[serde(default)]
    pub allow_sub_as_civil_id: bool,
}

impl SelfAttestationSubjectBindingConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.token_claim.is_empty() {
            return invalid_self_attestation("subject_binding.token_claim must not be empty");
        }
        if !self
            .token_claim
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '/' | '.' | '-'))
        {
            return invalid_self_attestation(
                "subject_binding.token_claim must match [A-Za-z0-9_:/\\.\\-]+",
            );
        }
        if self.token_claim == "sub" && !self.allow_sub_as_civil_id {
            return invalid_self_attestation(
                "subject_binding.token_claim = sub requires allow_sub_as_civil_id = true",
            );
        }
        if self.id_type.trim().is_empty() {
            return invalid_self_attestation("subject_binding.id_type must not be empty");
        }
        if self.normalize != SubjectBindingNormalize::Exact {
            return invalid_self_attestation("subject_binding.normalize must be exact");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAttestationClaimSource {
    #[default]
    AccessToken,
    Userinfo,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum SubjectId {
    #[default]
    SubjectId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectBindingNormalize {
    #[default]
    Exact,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationCitizenClientsConfig {
    #[serde(default)]
    pub allowed_client_ids: Vec<String>,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
}

impl SelfAttestationCitizenClientsConfig {
    fn validate(&self, oidc: &EvidenceOidcAuthConfig) -> Result<(), EvidenceConfigError> {
        if self.allowed_client_ids.is_empty() && self.allowed_audiences.is_empty() {
            return invalid_self_attestation(
                "citizen_clients must list at least one allowed client id or audience",
            );
        }
        validate_entries(
            "self_attestation.citizen_clients.allowed_client_ids",
            &self.allowed_client_ids,
        )?;
        validate_entries(
            "self_attestation.citizen_clients.allowed_audiences",
            &self.allowed_audiences,
        )?;
        for audience in &self.allowed_audiences {
            if !oidc.audiences.iter().any(|accepted| accepted == audience) {
                return invalid_self_attestation(format!(
                    "citizen audience '{audience}' is not listed in auth.oidc.audiences"
                ));
            }
        }
        if !oidc.allowed_clients.is_empty() {
            for client_id in &self.allowed_client_ids {
                if !oidc
                    .allowed_clients
                    .iter()
                    .any(|accepted| accepted == client_id)
                {
                    return invalid_self_attestation(format!(
                        "citizen client '{client_id}' is not listed in auth.oidc.allowed_clients"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationTokenPolicyConfig {
    #[serde(default)]
    pub required_acr_values: Vec<String>,
    #[serde(default)]
    pub assurance_claim_source: SelfAttestationAssuranceClaimSource,
    #[serde(default)]
    pub max_auth_age_seconds: u64,
    #[serde(default)]
    pub max_access_token_lifetime_seconds: u64,
    #[serde(default)]
    pub max_evaluation_age_seconds: u64,
    #[serde(default)]
    pub max_credential_validity_seconds: u64,
    #[serde(default)]
    pub max_clock_leeway_seconds: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAttestationAssuranceClaimSource {
    #[default]
    AccessToken,
    IdToken,
}

impl SelfAttestationTokenPolicyConfig {
    fn validate(&self, oidc: &EvidenceOidcAuthConfig) -> Result<(), EvidenceConfigError> {
        validate_entries(
            "self_attestation.token_policy.required_acr_values",
            &self.required_acr_values,
        )?;
        if self.max_auth_age_seconds == 0 {
            return invalid_self_attestation(
                "token_policy.max_auth_age_seconds must be greater than zero",
            );
        }
        if self.max_access_token_lifetime_seconds == 0 {
            return invalid_self_attestation(
                "token_policy.max_access_token_lifetime_seconds must be greater than zero",
            );
        }
        if self.max_evaluation_age_seconds == 0 || self.max_evaluation_age_seconds > 600 {
            return invalid_self_attestation(
                "token_policy.max_evaluation_age_seconds must be between 1 and 600",
            );
        }
        if self.max_credential_validity_seconds == 0 || self.max_credential_validity_seconds > 600 {
            return invalid_self_attestation(
                "token_policy.max_credential_validity_seconds must be between 1 and 600",
            );
        }
        if self.max_clock_leeway_seconds == 0 || self.max_clock_leeway_seconds > 60 {
            return invalid_self_attestation(
                "token_policy.max_clock_leeway_seconds must be between 1 and 60",
            );
        }
        if oidc.leeway_seconds > self.max_clock_leeway_seconds {
            return invalid_self_attestation(
                "auth.oidc.leeway_seconds must not exceed token_policy.max_clock_leeway_seconds",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationOperationsConfig {
    #[serde(default)]
    pub evaluate: bool,
    #[serde(default)]
    pub render: bool,
    #[serde(default)]
    pub issue_credential: bool,
    #[serde(default)]
    pub batch_evaluate: bool,
}

impl SelfAttestationOperationsConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.batch_evaluate {
            return invalid_self_attestation(
                "allowed_operations.batch_evaluate must be false in v1",
            );
        }
        if !self.evaluate && !self.render && !self.issue_credential {
            return invalid_self_attestation(
                "allowed_operations must enable at least one self-attestation operation",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationRateLimitsConfig {
    #[serde(default)]
    pub mode: SelfAttestationRateLimitMode,
    #[serde(default)]
    pub invalid_token_per_client_address_per_minute: u32,
    #[serde(default)]
    pub per_principal_per_minute: u32,
    #[serde(default)]
    pub subject_mismatch_per_principal_per_hour: u32,
    #[serde(default)]
    pub per_holder_per_hour: u32,
    #[serde(default)]
    pub credential_issuance_per_principal_per_hour: u32,
}

impl SelfAttestationRateLimitsConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.mode != SelfAttestationRateLimitMode::InProcess {
            return invalid_self_attestation("rate_limits.mode must be in_process");
        }
        if self.invalid_token_per_client_address_per_minute == 0
            || self.per_principal_per_minute == 0
            || self.subject_mismatch_per_principal_per_hour == 0
            || self.per_holder_per_hour == 0
            || self.credential_issuance_per_principal_per_hour == 0
        {
            return invalid_self_attestation("rate_limits values must all be greater than zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfAttestationRateLimitMode {
    #[default]
    InProcess,
}

fn validate_non_empty_entries(name: &str, values: &[String]) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_self_attestation(format!("{name} must not be empty"));
    }
    validate_entries(name, values)
}

fn validate_entries(name: &str, values: &[String]) -> Result<(), EvidenceConfigError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_self_attestation(format!("{name} must not contain blank entries"));
    }
    Ok(())
}

fn validate_exact_wallet_origins(origins: &[String]) -> Result<(), EvidenceConfigError> {
    for origin in origins {
        if origin == "*" || origin.contains('*') {
            return invalid_self_attestation(
                "allowed_wallet_origins must contain exact origins, not wildcards",
            );
        }
        if !origin.starts_with("https://") {
            return invalid_self_attestation("allowed_wallet_origins must use https origins");
        }
    }
    Ok(())
}

fn validate_self_attestation_claim(
    claim: &ClaimDefinition,
    allowed_purposes: &HashSet<&str>,
    allowed_formats: &HashSet<&str>,
    allowed_disclosures: &HashSet<&str>,
    allowed_profiles: &HashSet<&str>,
    issue_credential: bool,
) -> Result<(), EvidenceConfigError> {
    if !claim.operations.evaluate.enabled {
        return invalid_self_attestation(format!(
            "allowed claim '{}' must enable evaluate",
            claim.id
        ));
    }
    let purpose = claim.purpose.as_deref().ok_or_else(|| {
        EvidenceConfigError::InvalidSelfAttestationConfig {
            reason: format!("allowed claim '{}' must declare purpose", claim.id),
        }
    })?;
    if !allowed_purposes.contains(purpose) {
        return invalid_self_attestation(format!(
            "allowed claim '{}' declares unallowed purpose '{}'",
            claim.id, purpose
        ));
    }
    if !claim
        .formats
        .iter()
        .any(|format| allowed_formats.contains(format.as_str()))
    {
        return invalid_self_attestation(format!(
            "allowed claim '{}' must support at least one allowed format",
            claim.id
        ));
    }
    if !claim
        .disclosure
        .allowed
        .iter()
        .any(|disclosure| allowed_disclosures.contains(disclosure.as_str()))
    {
        return invalid_self_attestation(format!(
            "allowed claim '{}' must support at least one allowed disclosure",
            claim.id
        ));
    }
    if issue_credential
        && !claim
            .credential_profiles
            .iter()
            .any(|profile| allowed_profiles.contains(profile.as_str()))
    {
        return invalid_self_attestation(format!(
            "allowed claim '{}' must reference an allowed credential profile",
            claim.id
        ));
    }
    Ok(())
}

fn validate_self_attestation_profile(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    claim_ids: &HashSet<&str>,
    allowed_claim_ids: &HashSet<&str>,
    allowed_formats: &HashSet<&str>,
    max_credential_validity_seconds: u64,
) -> Result<(), EvidenceConfigError> {
    if profile.validity_seconds <= 0 {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' validity_seconds must be greater than zero"
        ));
    }
    let validity_seconds = u64::try_from(profile.validity_seconds).map_err(|_| {
        EvidenceConfigError::InvalidSelfAttestationConfig {
            reason: format!(
                "credential profile '{profile_id}' validity_seconds must be greater than zero"
            ),
        }
    })?;
    if validity_seconds > max_credential_validity_seconds || validity_seconds > 600 {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' validity_seconds must not exceed the self-attestation ceiling"
        ));
    }
    if !allowed_formats.contains(profile.format.as_str()) {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' uses unallowed format '{}'",
            profile.format
        ));
    }
    if profile.holder_binding.mode != "did" {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' holder_binding.mode must be did"
        ));
    }
    if profile.holder_binding.proof_of_possession.as_deref() != Some("required") {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' holder_binding.proof_of_possession must be required"
        ));
    }
    if profile.holder_binding.allowed_did_methods.is_empty()
        || profile
            .holder_binding
            .allowed_did_methods
            .iter()
            .any(|method| method != SD_JWT_VC_HOLDER_BINDING_METHOD)
    {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' holder_binding.allowed_did_methods must only contain did:jwk"
        ));
    }
    for claim_id in &profile.allowed_claims {
        if !claim_ids.contains(claim_id.as_str()) {
            return invalid_self_attestation(format!(
                "credential profile '{profile_id}' references unknown claim '{claim_id}'"
            ));
        }
    }
    if !profile
        .allowed_claims
        .iter()
        .any(|claim_id| allowed_claim_ids.contains(claim_id.as_str()))
    {
        return invalid_self_attestation(format!(
            "credential profile '{profile_id}' must allow at least one self-attestation claim"
        ));
    }
    Ok(())
}

fn validate_self_attestation_allow_lists_are_supported(
    config: &SelfAttestationConfig,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    let allowed_claims: Vec<&ClaimDefinition> = config
        .allowed_claims
        .iter()
        .filter_map(|claim_id| evidence.claims.iter().find(|claim| claim.id == *claim_id))
        .collect();
    let allowed_profiles: Vec<&CredentialProfileConfig> = config
        .credential_profiles
        .iter()
        .filter_map(|profile_id| evidence.credential_profiles.get(profile_id))
        .collect();

    for purpose in &config.allowed_purposes {
        if !allowed_claims
            .iter()
            .any(|claim| claim.purpose.as_deref() == Some(purpose.as_str()))
        {
            return invalid_self_attestation(format!(
                "allowed_purposes entry '{purpose}' is not used by any allowed claim"
            ));
        }
    }

    for format in &config.allowed_formats {
        let supported_by_claim = allowed_claims
            .iter()
            .any(|claim| claim.formats.iter().any(|candidate| candidate == format));
        let supported_by_profile = allowed_profiles
            .iter()
            .any(|profile| profile.format == *format);
        if !supported_by_claim && !supported_by_profile {
            return invalid_self_attestation(format!(
                "allowed_formats entry '{format}' is not supported by any allowed claim or profile"
            ));
        }
    }

    for disclosure in &config.allowed_disclosures {
        let supported_by_claim = allowed_claims.iter().any(|claim| {
            claim
                .disclosure
                .allowed
                .iter()
                .any(|candidate| candidate == disclosure)
        });
        let supported_by_profile = allowed_profiles.iter().any(|profile| {
            profile
                .disclosure
                .allowed
                .iter()
                .any(|candidate| candidate == disclosure)
        });
        if !supported_by_claim && !supported_by_profile {
            return invalid_self_attestation(format!(
                "allowed_disclosures entry '{disclosure}' is not supported by any allowed claim or profile"
            ));
        }
    }

    Ok(())
}

fn validate_required_scopes_do_not_grant_source_access(
    config: &SelfAttestationConfig,
    oidc: &EvidenceOidcAuthConfig,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    let required_scopes: HashSet<&str> =
        config.required_scopes.iter().map(String::as_str).collect();
    let source_scopes = source_required_scopes(evidence);

    for scope in &required_scopes {
        if source_scopes.contains(*scope) {
            return invalid_self_attestation(format!(
                "required scope '{scope}' conflicts with a source required scope"
            ));
        }
        if !oidc
            .scope_map
            .values()
            .any(|mapped_scopes| mapped_scopes.iter().any(|mapped| mapped == scope))
        {
            return invalid_self_attestation(format!(
                "required scope '{scope}' must be present in auth.oidc.scope_map"
            ));
        }
    }

    for (token_scope, mapped_scopes) in &oidc.scope_map {
        let citizen_mapping = required_scopes.contains(token_scope.as_str())
            || mapped_scopes
                .iter()
                .any(|mapped| required_scopes.contains(mapped.as_str()));
        if !citizen_mapping {
            continue;
        }
        for mapped_scope in mapped_scopes {
            if source_scopes.contains(mapped_scope.as_str()) {
                return invalid_self_attestation(format!(
                    "citizen scope_map entry '{token_scope}' must not grant source scope '{mapped_scope}'"
                ));
            }
        }
    }

    Ok(())
}

fn source_required_scopes(evidence: &EvidenceConfig) -> HashSet<String> {
    let mut scopes = HashSet::new();
    for claim in &evidence.claims {
        for binding in claim.source_bindings.values() {
            if let Some(scope) = binding.required_scope.as_deref() {
                scopes.insert(scope.to_string());
            } else {
                scopes.insert(format!("{}:evidence_verification", binding.dataset));
            }
        }
    }
    scopes
}

fn invalid_self_attestation<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidSelfAttestationConfig {
        reason: reason.into(),
    })
}

fn detect_depends_on_cycle(
    claims: &[ClaimDefinition],
    claim_id: &str,
    grey: &mut HashSet<String>,
    black: &mut HashSet<String>,
    path: &mut Vec<String>,
) -> Result<(), EvidenceConfigError> {
    grey.insert(claim_id.to_string());
    path.push(claim_id.to_string());
    let claim = claims.iter().find(|c| c.id == claim_id);
    if let Some(claim) = claim {
        for dep in &claim.depends_on {
            if grey.contains(dep.as_str()) {
                // Back edge found: build the cycle path from where dep appears.
                let cycle_start = path.iter().position(|id| id == dep).unwrap_or(0);
                let mut cycle = path[cycle_start..].to_vec();
                cycle.push(dep.clone());
                return Err(EvidenceConfigError::DependsOnCycle { cycle });
            }
            if !black.contains(dep.as_str()) {
                detect_depends_on_cycle(claims, dep, grey, black, path)?;
            }
        }
    }
    path.pop();
    grey.remove(claim_id);
    black.insert(claim_id.to_string());
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryHttpConfig {
    #[serde(default = "default_bind_addr")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub cors: RegistryNotaryCorsConfig,
}

impl Default for RegistryNotaryHttpConfig {
    fn default() -> Self {
        Self {
            bind: default_bind_addr(),
            cors: RegistryNotaryCorsConfig::default(),
        }
    }
}

fn default_bind_addr() -> SocketAddr {
    // SAFETY: the literal is a valid loopback socket address.
    "127.0.0.1:8081"
        .parse()
        .expect("default bind address is valid")
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryCorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    #[serde(default)]
    pub api_keys: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub bearer_tokens: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub oidc: Option<EvidenceOidcAuthConfig>,
}

impl Default for EvidenceAuthConfig {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            api_keys: Vec::new(),
            bearer_tokens: Vec::new(),
            oidc: None,
        }
    }
}

fn default_auth_mode() -> String {
    "api_key".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCredentialConfig {
    pub id: String,
    pub hash_env: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOidcAuthConfig {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_issuers: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default = "default_oidc_allowed_algorithms")]
    pub allowed_algorithms: Vec<String>,
    #[serde(default = "default_oidc_allowed_typ")]
    pub allowed_typ: Vec<String>,
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_oidc_scope_separator")]
    pub scope_separator: String,
    #[serde(default)]
    pub scope_map: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_oidc_principal_claim")]
    pub principal_claim: String,
    #[serde(default = "default_oidc_leeway_seconds")]
    pub leeway_seconds: u64,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

fn default_oidc_allowed_algorithms() -> Vec<String> {
    vec![SD_JWT_VC_SIGNING_ALG.to_string()]
}

fn default_oidc_allowed_typ() -> Vec<String> {
    vec!["JWT".to_string()]
}

fn default_oidc_scope_claim() -> String {
    "scope".to_string()
}

fn default_oidc_scope_separator() -> String {
    " ".to_string()
}

fn default_oidc_principal_claim() -> String {
    "sub".to_string()
}

fn default_oidc_leeway_seconds() -> u64 {
    60
}

impl EvidenceOidcAuthConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "issuer must not be empty".to_string(),
            });
        }
        if self.jwks_uri.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "jwks_uri must not be empty".to_string(),
            });
        }
        validate_jwks_uri_transport(&self.jwks_uri, self.allow_insecure_localhost)?;
        if let Some(userinfo_endpoint) = self.userinfo_endpoint.as_deref() {
            if userinfo_endpoint.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidOidcConfig {
                    reason: "userinfo_endpoint must not be empty when configured".to_string(),
                });
            }
            validate_jwks_uri_transport(userinfo_endpoint, self.allow_insecure_localhost)?;
        }
        validate_entries("auth.oidc.userinfo_issuers", &self.userinfo_issuers)?;
        if self.audiences.is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "audiences must list at least one accepted audience".to_string(),
            });
        }
        if self.scope_separator.chars().count() != 1 {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "scope_separator must be exactly one character".to_string(),
            });
        }
        if self.principal_claim.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "principal_claim must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

fn validate_jwks_uri_transport(
    jwks_uri: &str,
    allow_insecure_localhost: bool,
) -> Result<(), EvidenceConfigError> {
    let jwks_uri = jwks_uri.trim();
    if jwks_uri.starts_with("https://")
        || (allow_insecure_localhost && is_insecure_localhost_url(jwks_uri))
    {
        return Ok(());
    }
    Err(EvidenceConfigError::InvalidOidcConfig {
        reason:
            "jwks_uri must use https unless allow_insecure_localhost permits an http localhost URL"
                .to_string(),
    })
}

fn is_insecure_localhost_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        after_bracket.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuditConfig {
    #[serde(default = "default_audit_sink")]
    pub sink: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash_secret_env: Option<String>,
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
    #[serde(default)]
    pub max_files: Option<u32>,
    #[serde(default)]
    pub syslog_socket_path: Option<String>,
}

impl Default for EvidenceAuditConfig {
    fn default() -> Self {
        Self {
            sink: default_audit_sink(),
            path: None,
            hash_secret_env: None,
            max_size_bytes: None,
            max_files: None,
            syslog_socket_path: None,
        }
    }
}

impl EvidenceAuditConfig {
    pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;
    pub const DEFAULT_MAX_FILES: u32 = 5;

    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_bytes.unwrap_or(Self::DEFAULT_MAX_SIZE_BYTES)
    }

    pub fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }
}

fn default_audit_sink() -> String {
    "stdout".to_string()
}

fn invalid_federation<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidFederationConfig {
        reason: reason.into(),
    })
}

fn validate_federation_non_empty(field: &str, value: &str) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_federation(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_federation_https_url(field: &str, value: &str) -> Result<(), EvidenceConfigError> {
    validate_federation_non_empty(field, value)?;
    let Some(rest) = value.strip_prefix("https://") else {
        return invalid_federation(format!("{field} must be an HTTPS URL"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return invalid_federation(format!("{field} must include a valid host"));
    }
    Ok(())
}

fn validate_federation_localhost_or_https_url(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.starts_with("https://") {
        return validate_federation_https_url(field, value);
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return invalid_federation(format!("{field} must be HTTPS or localhost HTTP"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.starts_with("127.0.0.1:")
        || host == "127.0.0.1"
        || host.starts_with("localhost:")
        || host == "localhost"
    {
        Ok(())
    } else {
        invalid_federation(format!("{field} permits HTTP only for localhost"))
    }
}

fn validate_federation_http_or_https_url(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    validate_federation_non_empty(field, value)?;
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return invalid_federation(format!("{field} must be an HTTP or HTTPS URL"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return invalid_federation(format!("{field} must include a valid host"));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceConfigError {
    #[error("evidence.enabled must be true for the standalone Registry Notary")]
    EvidenceDisabled,
    #[error("at least one API key or bearer token must be configured")]
    NoCredentialsConfigured,
    #[error("unsupported auth.mode '{mode}'; supported values are 'api_key' and 'oidc'")]
    UnsupportedAuthMode { mode: String },
    #[error("auth.mode = oidc requires an auth.oidc block")]
    MissingOidcConfig,
    #[error("invalid auth.oidc config: {reason}")]
    InvalidOidcConfig { reason: String },
    #[error("invalid self_attestation config: {reason}")]
    InvalidSelfAttestationConfig { reason: String },
    #[error("invalid oid4vci config: {reason}")]
    InvalidOid4vciConfig { reason: String },
    #[error("invalid replay config: {reason}")]
    InvalidReplayConfig { reason: String },
    #[error("invalid credential status config: {reason}")]
    InvalidCredentialStatusConfig { reason: String },
    #[error("invalid federation config: {reason}")]
    InvalidFederationConfig { reason: String },
    #[error("claim id must not be empty")]
    InvalidClaim,
    #[error("each standalone source binding must reference a configured source connection")]
    MissingSourceConnection,
    #[error(
        "concurrency.subjects, concurrency.bindings, and source_connection.max_in_flight \
         must all be >= 1"
    )]
    InvalidConcurrency,
    /// Credential holder binding only works with did:jwk because holder_jwk()
    /// only implements did:jwk resolution. Restrict allowed_did_methods to
    /// ["did:jwk"] or leave it empty when holder binding is disabled.
    #[error(
        "credential profile '{profile}': holder binding is only supported with did:jwk, \
         but allowed_did_methods contains unsupported method(s): {methods}; \
         restrict allowed_did_methods to [\"did:jwk\"]",
        methods = methods.join(", ")
    )]
    UnsupportedCredentialProfileDidMethods {
        profile: String,
        methods: Vec<String>,
    },
    #[error("claim '{claim}' depends_on unknown claim '{unknown}'")]
    DependsOnUnknownClaim { claim: String, unknown: String },
    #[error(
        "depends_on cycle detected: {cycle}",
        cycle = cycle.join(" -> ")
    )]
    DependsOnCycle { cycle: Vec<String> },
    /// A credential profile with an empty `allowed_claims` would short-circuit
    /// the issuance-time claim filter (api.rs treats empty as "all claims
    /// allowed"). Reject at load time so operators must explicitly enumerate
    /// the claims a profile may bind to.
    #[error(
        "credential profile '{profile}': allowed_claims must list at least one \
         claim; an empty list would permit any claim at issuance"
    )]
    EmptyAllowedClaims { profile: String },
    /// Registry Notary currently issues only SD-JWT VC credentials using the
    /// current `application/dc+sd-jwt` media type. Reject aliases and profile
    /// labels so operator config cannot drift from the wire contract.
    #[error(
        "credential profile '{profile}': unsupported format '{format}'; \
         supported credential format is application/dc+sd-jwt"
    )]
    UnsupportedCredentialProfileFormat { profile: String, format: String },
    /// `rda_in_filter` requires the operator to attest that lookup values are
    /// unique per subject. Without this we cannot disambiguate per-subject
    /// rows from a single collection response.
    #[error(
        "source_connection '{connection}': bulk_mode = rda_in_filter requires \
         bulk_mode_lookup_unique = true (operator attestation that each \
         subject's lookup value yields at most one upstream row)"
    )]
    BulkModeRequiresUniqueLookup { connection: String },
    /// `rda_in_filter` requires every binding pointing at this connection to
    /// have `lookup.cardinality = one`. Bindings expecting many rows per
    /// subject cannot be batched into a single collection response.
    #[error(
        "source_connection '{connection}': bulk_mode = rda_in_filter requires \
         every binding (claim '{claim}', binding '{binding}') to set \
         lookup.cardinality = one"
    )]
    BulkModeRequiresCardinalityOne {
        connection: String,
        claim: String,
        binding: String,
    },
    /// `dci_batched_search` is DCI-specific. Bindings using the RDA connector
    /// against the same connection cannot be batched through the DCI search
    /// envelope.
    #[error(
        "source_connection '{connection}': bulk_mode = dci_batched_search \
         requires all bindings to use connector = dci (binding '{binding}' \
         in claim '{claim}' uses a different connector)"
    )]
    BulkModeRequiresDciConnector {
        connection: String,
        claim: String,
        binding: String,
    },
}

/// Registry Notary configuration. Disabled by default so existing
/// Registry Relay deployments load unchanged.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_service_id")]
    pub service_id: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    #[serde(default = "default_claims_url")]
    pub claims_url: String,
    #[serde(default = "default_formats_url")]
    pub formats_url: String,
    #[serde(default = "default_inline_batch_limit")]
    pub inline_batch_limit: usize,
    #[serde(default)]
    pub claims: Vec<ClaimDefinition>,
    #[serde(default)]
    pub credential_profiles: BTreeMap<String, CredentialProfileConfig>,
    #[serde(default)]
    pub source_connections: BTreeMap<String, SourceConnectionConfig>,
    /// Per-request fan-out caps. Setting both `subjects=1` and `bindings=1`
    /// reproduces today's strictly-sequential behavior (Stage 1 kill switch).
    #[serde(default)]
    pub concurrency: ConcurrencyConfig,
}

fn default_service_id() -> String {
    "registry-notary".to_string()
}

fn default_api_version() -> String {
    "2026-05".to_string()
}

fn default_api_base_url() -> String {
    "/".to_string()
}

fn default_claims_url() -> String {
    "/claims".to_string()
}

fn default_formats_url() -> String {
    "/formats".to_string()
}

const fn default_inline_batch_limit() -> usize {
    100
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub id: String,
    pub title: String,
    pub version: String,
    pub subject_type: String,
    #[serde(default)]
    pub value: ClaimValueConfig,
    #[serde(default)]
    pub inputs: Vec<ClaimInputConfig>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub source_bindings: BTreeMap<String, SourceBindingConfig>,
    pub rule: RuleConfig,
    #[serde(default)]
    pub operations: ClaimOperationsConfig,
    #[serde(default)]
    pub disclosure: DisclosureConfig,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub cccev: Option<CccevConfig>,
    #[serde(default)]
    pub oots: Option<OotsConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimValueConfig {
    #[serde(rename = "type", default)]
    pub value_type: String,
    #[serde(default)]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInputConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBindingConfig {
    pub connector: SourceConnectorKind,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub required_scope: Option<String>,
    pub dataset: String,
    pub entity: String,
    pub lookup: SourceLookupConfig,
    #[serde(default)]
    pub fields: BTreeMap<String, SourceFieldConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConnectionConfig {
    pub base_url: String,
    /// Development escape hatch for local demos and tests. Production source
    /// fetches stay on the strict outbound URL policy by default.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    /// Development escape hatch for Docker Compose and other private-network
    /// demos. This permits HTTP and private RFC1918 targets, while still
    /// blocking cloud metadata endpoints. Leave false for production.
    #[serde(default)]
    pub allow_insecure_private_network: bool,
    pub token_env: String,
    #[serde(default)]
    pub dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound requests to this connection.
    /// Enforced by a shared `Semaphore` so the notary cannot DOS an upstream
    /// regardless of inbound load. Must be >= 1.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
    /// Retry one time on transport errors or HTTP 5xx responses. Disable this
    /// for synchronous sidecars whose worker executions must not be repeated.
    #[serde(default = "default_retry_on_5xx")]
    pub retry_on_5xx: bool,
    /// Bulk-read mode for this connection. `none` (default) keeps the wire
    /// behavior of pre-Stage-3 deployments; `rda_in_filter` and
    /// `dci_batched_search` are connector-specific specializations.
    #[serde(default)]
    pub bulk_mode: BulkMode,
    /// Operator attestation that, for `rda_in_filter`, every subject's
    /// lookup value yields at most one upstream row. The runtime still
    /// guards against violations and falls back to per-subject reads if
    /// detected.
    #[serde(default)]
    pub bulk_mode_lookup_unique: bool,
    /// Upper bound on the per-call timeout for bulk `read_many` requests.
    /// The actual budget scales with batch size up to this cap.
    #[serde(default = "default_bulk_timeout_max_ms")]
    pub bulk_timeout_max_ms: u64,
}

const fn default_max_in_flight() -> usize {
    8
}

const fn default_retry_on_5xx() -> bool {
    true
}

const fn default_bulk_timeout_max_ms() -> u64 {
    30_000
}

/// Per-connection bulk-read mode. Default `None` preserves the existing wire
/// behavior; the other variants enable connector-specific request batching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BulkMode {
    #[default]
    None,
    RdaInFilter,
    DciBatchedSearch,
}

/// Per-request fan-out caps. `subjects=1, bindings=1` reproduces the strictly
/// sequential behavior that existed before Stage 1 of the scalability spec.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyConfig {
    #[serde(default = "default_concurrency_subjects")]
    pub subjects: usize,
    #[serde(default = "default_concurrency_bindings")]
    pub bindings: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            subjects: default_concurrency_subjects(),
            bindings: default_concurrency_bindings(),
        }
    }
}

impl ConcurrencyConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.subjects < 1 || self.bindings < 1 {
            return Err(EvidenceConfigError::InvalidConcurrency);
        }
        Ok(())
    }
}

const fn default_concurrency_subjects() -> usize {
    16
}

const fn default_concurrency_bindings() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DciSourceConnectionConfig {
    #[serde(default = "default_dci_search_path")]
    pub search_path: String,
    #[serde(default = "default_dci_sender_id")]
    pub sender_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_id: Option<String>,
    #[serde(default = "default_dci_query_type")]
    pub query_type: String,
    #[serde(default = "default_dci_records_path")]
    pub records_path: String,
    /// JSON-pointer to the records array INSIDE one `search_response[i]`
    /// entry, used by `read_many` for `dci_batched_search`. The default
    /// matches the shape produced by registry-relay (`/data/reg_records`).
    /// `read_one` continues to use `records_path` which addresses the full
    /// envelope and is hardcoded to index 0.
    #[serde(default = "default_dci_bulk_records_path")]
    pub bulk_records_path: String,
    #[serde(default = "default_dci_max_results")]
    pub max_results: usize,
    #[serde(default)]
    pub registry_type: Option<String>,
    #[serde(default)]
    pub record_type: Option<String>,
    #[serde(default)]
    pub field_paths: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Default for DciSourceConnectionConfig {
    fn default() -> Self {
        Self {
            search_path: default_dci_search_path(),
            sender_id: default_dci_sender_id(),
            receiver_id: None,
            query_type: default_dci_query_type(),
            records_path: default_dci_records_path(),
            bulk_records_path: default_dci_bulk_records_path(),
            max_results: default_dci_max_results(),
            registry_type: None,
            record_type: None,
            field_paths: BTreeMap::new(),
            signature: None,
        }
    }
}

fn default_dci_search_path() -> String {
    "/registry/sync/search".to_string()
}

fn default_dci_sender_id() -> String {
    "registry-notary".to_string()
}

fn default_dci_query_type() -> String {
    "idtype-value".to_string()
}

fn default_dci_records_path() -> String {
    "/message/search_response/0/data/reg_records".to_string()
}

fn default_dci_bulk_records_path() -> String {
    "/data/reg_records".to_string()
}

const fn default_dci_max_results() -> usize {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceConnectorKind {
    RegistryDataApi,
    Dci,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLookupConfig {
    pub input: String,
    pub field: String,
    #[serde(default = "default_lookup_op")]
    pub op: String,
    #[serde(default = "default_lookup_cardinality")]
    pub cardinality: String,
}

fn default_lookup_op() -> String {
    "eq".to_string()
}

fn default_lookup_cardinality() -> String {
    "one".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFieldConfig {
    pub field: String,
    #[serde(rename = "type", default)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub semantic_term: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleConfig {
    Extract {
        source: String,
        field: String,
    },
    Exists {
        source: String,
    },
    Cel {
        expression: String,
        #[serde(default)]
        bindings: CelBindingsConfig,
    },
    Plugin {
        plugin: String,
    },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CelBindingsConfig {
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimBindingConfig>,
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBindingConfig {
    pub claim: String,
    #[serde(default)]
    pub binding_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimOperationsConfig {
    #[serde(default = "default_enabled_operation")]
    pub evaluate: OperationConfig,
    #[serde(default)]
    pub batch_evaluate: BatchOperationConfig,
}

impl Default for ClaimOperationsConfig {
    fn default() -> Self {
        Self {
            evaluate: OperationConfig { enabled: true },
            batch_evaluate: BatchOperationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_enabled_operation() -> OperationConfig {
    OperationConfig { enabled: true }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOperationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_inline_batch_limit")]
    pub max_subjects: usize,
}

impl Default for BatchOperationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_subjects: default_inline_batch_limit(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureConfig {
    #[serde(default = "default_disclosure_profile")]
    pub default: String,
    #[serde(default = "default_disclosure_allowed")]
    pub allowed: Vec<String>,
    #[serde(default = "default_disclosure_downgrade")]
    pub downgrade: String,
}

impl Default for DisclosureConfig {
    fn default() -> Self {
        Self {
            default: default_disclosure_profile(),
            allowed: default_disclosure_allowed(),
            downgrade: default_disclosure_downgrade(),
        }
    }
}

fn default_disclosure_profile() -> String {
    "redacted".to_string()
}

fn default_disclosure_allowed() -> Vec<String> {
    vec!["redacted".to_string()]
}

fn default_disclosure_downgrade() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfileConfig {
    pub format: String,
    pub issuer: String,
    pub issuer_key_env: String,
    #[serde(default)]
    pub issuer_kid: Option<String>,
    pub vct: String,
    #[serde(default = "default_credential_validity_seconds")]
    pub validity_seconds: i64,
    #[serde(default)]
    pub holder_binding: HolderBindingConfig,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub disclosure: CredentialDisclosureConfig,
}

const fn default_credential_validity_seconds() -> i64 {
    600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HolderBindingConfig {
    #[serde(default = "default_holder_binding_mode")]
    pub mode: String,
    #[serde(default)]
    pub proof_of_possession: Option<String>,
    #[serde(default)]
    pub allowed_did_methods: Vec<String>,
}

impl Default for HolderBindingConfig {
    fn default() -> Self {
        Self {
            mode: default_holder_binding_mode(),
            proof_of_possession: None,
            allowed_did_methods: Vec::new(),
        }
    }
}

fn default_holder_binding_mode() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDisclosureConfig {
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CccevConfig {
    #[serde(default)]
    pub requirement_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type_iri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OotsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requirement: Option<String>,
    #[serde(default)]
    pub reference_framework: Option<String>,
    #[serde(default)]
    pub evidence_type_classification: Option<String>,
    #[serde(default)]
    pub evidence_type_list: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub authentication_level_of_assurance: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid config from which individual tests can deviate.
    fn minimal_config() -> StandaloneRegistryNotaryConfig {
        serde_norway::from_str(
            r#"
evidence:
  enabled: true
auth:
  mode: api_key
  api_keys:
    - id: test-key
      hash_env: TEST_TOKEN_HASH
"#,
        )
        .expect("minimal config is valid YAML")
    }

    fn minimal_claim(id: &str) -> ClaimDefinition {
        serde_norway::from_str(&format!(
            r#"
id: {id}
title: Test Claim
version: "1.0"
subject_type: person
rule:
  type: exists
  source: src
"#
        ))
        .expect("minimal claim is valid YAML")
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
  credential_profiles:
    civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      issuer_key_env: ISSUER_KEY
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
            input: subject_id
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
    jwks_uri: https://id.example.gov/oauth/v2/keys
    audiences:
      - registry-notary-citizen
    allowed_clients:
      - citizen-portal
    scope_claim: scope
    scope_map:
      citizen_self_attestation:
        - self_attestation
    leeway_seconds: 30
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

    fn valid_oid4vci_config() -> StandaloneRegistryNotaryConfig {
        let mut config = valid_self_attestation_config();
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
    vct: https://issuer.example/credentials/civil-status
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
max_size_bytes: 4096
max_files: 3
"#,
        )
        .expect("file audit config is valid YAML");

        assert_eq!(file.sink, "file");
        assert_eq!(
            file.path.as_deref(),
            Some("/var/log/registry-notary/audit.jsonl")
        );
        assert_eq!(file.max_size_bytes(), 4096);
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
        assert_eq!(syslog.max_size_bytes(), 10 * 1024 * 1024);
        assert_eq!(syslog.max_files(), 5);
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
                kid: "agency-a-fed-1".to_string(),
                key_env: "FEDERATION_SIGNING_KEY".to_string(),
                alg: FEDERATION_SIGNING_ALG_EDDSA.to_string(),
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
            }],
            ..FederationConfig::default()
        };
        config
    }

    #[test]
    fn federation_config_validates_enabled_mvp_shape() {
        valid_federation_config()
            .validate()
            .expect("federation config validates");
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
        config.federation.peers[0].jwks_uri =
            "http://federation-peer-jwks:8080/jwks.json".to_string();
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
issuer_key_env: ISSUER_KEY
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
issuer_key_env: ISSUER_KEY
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
issuer_key_env: ISSUER_KEY
vct: https://vct.example/test
allowed_claims:
  - some-claim
"#,
        )
        .expect("profile YAML is valid");

        assert_eq!(profile.validity_seconds, 600);
    }

    #[test]
    fn credential_profile_explicit_validity_is_honored() {
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
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
    fn proof_of_possession_required_with_non_jwk_method_is_rejected() {
        let mut config = minimal_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
issuer_key_env: ISSUER_KEY
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
issuer_key_env: ISSUER_KEY
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
issuer_key_env: ISSUER_KEY
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

    #[test]
    fn oidc_auth_mode_requires_oidc_block() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();

        let err = config
            .validate()
            .expect_err("oidc mode requires OIDC settings");

        assert!(matches!(err, EvidenceConfigError::MissingOidcConfig));
    }

    #[test]
    fn oidc_auth_mode_validates_required_settings() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();
        config.auth.api_keys.clear();
        config.auth.oidc = Some(EvidenceOidcAuthConfig {
            issuer: "https://issuer.example".to_string(),
            jwks_uri: "https://issuer.example/jwks.json".to_string(),
            userinfo_endpoint: None,
            userinfo_issuers: Vec::new(),
            audiences: vec!["registry-notary".to_string()],
            allowed_clients: vec!["registry-client".to_string()],
            allowed_algorithms: vec!["EdDSA".to_string()],
            allowed_typ: vec!["JWT".to_string()],
            scope_claim: "scope".to_string(),
            scope_separator: " ".to_string(),
            scope_map: BTreeMap::new(),
            principal_claim: "sub".to_string(),
            leeway_seconds: 60,
            allow_insecure_localhost: false,
        });

        assert!(config.validate().is_ok());
    }

    #[test]
    fn oidc_jwks_uri_must_use_https() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();
        config.auth.api_keys.clear();
        config.auth.oidc = Some(EvidenceOidcAuthConfig {
            issuer: "https://issuer.example".to_string(),
            jwks_uri: "http://issuer.example/jwks.json".to_string(),
            userinfo_endpoint: None,
            userinfo_issuers: Vec::new(),
            audiences: vec!["registry-notary".to_string()],
            allowed_clients: vec!["registry-client".to_string()],
            allowed_algorithms: vec!["EdDSA".to_string()],
            allowed_typ: vec!["JWT".to_string()],
            scope_claim: "scope".to_string(),
            scope_separator: " ".to_string(),
            scope_map: BTreeMap::new(),
            principal_claim: "sub".to_string(),
            leeway_seconds: 60,
            allow_insecure_localhost: false,
        });

        let err = config
            .validate()
            .expect_err("remote http jwks_uri must fail validation");
        match err {
            EvidenceConfigError::InvalidOidcConfig { reason } => {
                assert!(
                    reason.contains("jwks_uri must use https"),
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
    fn oidc_jwks_uri_allows_insecure_localhost_only_when_enabled() {
        let mut config = minimal_config();
        config.auth.mode = "oidc".to_string();
        config.auth.api_keys.clear();
        config.auth.oidc = Some(EvidenceOidcAuthConfig {
            issuer: "https://issuer.example".to_string(),
            jwks_uri: "http://127.0.0.1:8080/jwks.json".to_string(),
            userinfo_endpoint: None,
            userinfo_issuers: Vec::new(),
            audiences: vec!["registry-notary".to_string()],
            allowed_clients: vec!["registry-client".to_string()],
            allowed_algorithms: vec!["EdDSA".to_string()],
            allowed_typ: vec!["JWT".to_string()],
            scope_claim: "scope".to_string(),
            scope_separator: " ".to_string(),
            scope_map: BTreeMap::new(),
            principal_claim: "sub".to_string(),
            leeway_seconds: 60,
            allow_insecure_localhost: false,
        });

        let err = config
            .validate()
            .expect_err("localhost http jwks_uri needs explicit opt-in");
        assert!(matches!(err, EvidenceConfigError::InvalidOidcConfig { .. }));

        config
            .auth
            .oidc
            .as_mut()
            .expect("oidc config exists")
            .allow_insecure_localhost = true;
        config
            .validate()
            .expect("localhost http jwks_uri is allowed only with the opt-in");
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
    fn unsupported_auth_mode_is_rejected() {
        let mut config = minimal_config();
        config.auth.mode = "oauth2".to_string();

        let err = config
            .validate()
            .expect_err("unknown auth mode must fail validation");

        assert!(matches!(
            err,
            EvidenceConfigError::UnsupportedAuthMode { .. }
        ));
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
                input: "subject_id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: cardinality.to_string(),
            },
            fields: BTreeMap::new(),
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
                input: "subject_id".to_string(),
                field: "id_type".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            fields: BTreeMap::new(),
        }
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
        let err = serde_norway::from_str::<SourceConnectionConfig>(yaml)
            .expect_err("unknown variant fails");
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
    fn rda_in_filter_with_unique_and_cardinality_one_validates() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "farmer_registry".to_string(),
            SourceConnectionConfig {
                base_url: "https://upstream.example".to_string(),
                allow_insecure_localhost: false,
                allow_insecure_private_network: false,
                token_env: "SRC_TOKEN".to_string(),
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
issuer_key_env: ISSUER_KEY
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
    fn valid_oid4vci_config_passes_validation() {
        let config = valid_oid4vci_config();
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
            .claim_id = "missing-claim".to_string();

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
        config.auth.mode = "api_key".to_string();
        config.auth.api_keys.push(EvidenceCredentialConfig {
            id: "api".to_string(),
            hash_env: "API_HASH".to_string(),
            scopes: Vec::new(),
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
    jwks_uri: https://id.example.gov/keys
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
    fn self_attestation_rejects_non_exact_normalization() {
        let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
            r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_uri: https://id.example.gov/keys
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
        config.auth.oidc.as_mut().unwrap().leeway_seconds = 61;

        let reason = expect_self_attestation_error(&config);
        assert!(reason.contains("leeway_seconds"), "unexpected: {reason}");
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

        let reason = expect_self_attestation_error(&config);
        assert!(reason.contains("validity_seconds"), "unexpected: {reason}");
    }

    #[test]
    fn self_attestation_profile_without_validity_uses_default_under_ceiling() {
        let mut config = valid_self_attestation_config();
        let profile: CredentialProfileConfig = serde_norway::from_str(
            r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
issuer_key_env: ISSUER_KEY
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
}
