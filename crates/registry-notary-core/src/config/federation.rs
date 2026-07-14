// SPDX-License-Identifier: Apache-2.0
//! Federated evaluation configuration.

use super::*;

pub const FEDERATION_PROTOCOL_V0_1: &str = "registry-notary-federation/v0.1";
pub const FEDERATION_REQUEST_JWT_TYP: &str = "registry-notary-request+jwt";
pub const FEDERATION_RESPONSE_JWT_TYP: &str = "registry-notary-response+jwt";
pub const FEDERATION_SIGNING_ALG_EDDSA: &str = "EdDSA";
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

pub(super) fn federation_config_is_default(config: &FederationConfig) -> bool {
    config == &FederationConfig::default()
}

pub(super) const fn default_federation_inbound_body_limit_bytes() -> usize {
    16 * 1024
}

pub(super) const fn default_federation_max_request_lifetime_seconds() -> u64 {
    300
}

pub(super) const fn default_federation_clock_leeway_seconds() -> u64 {
    60
}

impl FederationConfig {
    pub(super) fn validate(&self, evidence: &EvidenceConfig) -> Result<(), EvidenceConfigError> {
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
        validate_federation_non_empty("federation.signing.signing_key", &self.signing.signing_key)?;
        let signing_key = evidence
            .signing_keys
            .get(self.signing.signing_key.as_str())
            .ok_or_else(|| EvidenceConfigError::InvalidFederationConfig {
                reason: format!(
                    "federation.signing.signing_key references unknown signing key '{}'",
                    self.signing.signing_key
                ),
            })?;
        if !signing_key.status.may_sign() {
            return invalid_federation(
                "federation.signing.signing_key must reference an active signing key",
            );
        }
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
            let claim = evidence
                .claims
                .iter()
                .find(|claim| claim.id == profile.claim_id)
                .ok_or_else(|| EvidenceConfigError::InvalidFederationConfig {
                    reason:
                        "federation.evaluation_profiles[].claim_id must reference an evidence claim"
                            .to_string(),
                })?;
            if claim.evidence_mode.is_registry_backed() {
                return invalid_federation(
                    "federation.evaluation_profiles[].claim_id cannot reference a registry_backed claim until federation preserves Relay consultation audit correlation",
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationSigningConfig {
    pub signing_key: String,
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

pub(super) fn default_federation_replay_storage() -> String {
    FEDERATION_REPLAY_IN_PROCESS_SINGLE_INSTANCE_ONLY.to_string()
}

pub(super) const fn default_federation_replay_max_entries() -> usize {
    10_000
}

pub(super) fn default_federation_replay_eviction() -> String {
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

pub(super) const fn default_minimum_denial_latency_ms() -> u64 {
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
    pub evaluation_scopes: Vec<String>,
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
    pub max_claim_result_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
}

pub(super) fn invalid_federation<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidFederationConfig {
        reason: reason.into(),
    })
}

pub(super) fn validate_federation_non_empty(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_federation(format!("{field} must not be empty"));
    }
    Ok(())
}

pub(super) fn validate_federation_https_url(
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
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

pub(super) fn validate_federation_localhost_or_https_url(
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

pub(super) fn validate_federation_http_or_https_url(
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
