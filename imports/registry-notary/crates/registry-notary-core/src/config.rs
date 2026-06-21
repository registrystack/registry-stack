// SPDX-License-Identifier: Apache-2.0
//! Registry Notary configuration model.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use registry_platform_authcommon::CredentialFingerprintRef;
use registry_platform_config::{DeprecatedConfigField, RegistryTrustRoot};
use registry_platform_crypto::validate_did_web_https_issuer_binding;
use registry_platform_crypto::PublicJwk;
pub use registry_platform_crypto::{
    KeyProviderKind as SigningKeyProviderConfig, KeyStatus as SigningKeyStatus,
};
use registry_platform_oid4vci::{
    CREDENTIAL_SIGNING_ALG_EDDSA, CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK,
    SD_JWT_VC_FORMAT as OID4VCI_SD_JWT_VC_FORMAT,
};
use serde::{Deserialize, Serialize};

use crate::deployment::DeploymentConfig;
use crate::model::{
    DisclosureProfile, EvidenceAuthorizationDetails, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_SIGNING_ALG,
};

const PKCE_METHOD_S256: &str = "S256";

/// Non-EdDSA signing algorithms accepted for credential-profile signing.
/// Access-token and federation signing stay EdDSA; `validate_signing_key_alg_usage`
/// enforces that separation.
pub const CREDENTIAL_SIGNING_ALG_ES256: &str = "ES256";
pub const CLIENT_ASSERTION_SIGNING_ALG_RS256: &str = "RS256";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneRegistryNotaryConfig {
    #[serde(default, skip_serializing_if = "instance_config_is_default")]
    pub instance: NotaryInstanceConfig,
    #[serde(default)]
    pub server: RegistryNotaryHttpConfig,
    pub evidence: EvidenceConfig,
    pub auth: EvidenceAuthConfig,
    #[serde(default)]
    pub audit: EvidenceAuditConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_trust: Option<ConfigTrustConfig>,
    #[serde(default, skip_serializing_if = "replay_config_is_default")]
    pub replay: ReplayConfig,
    #[serde(default, skip_serializing_if = "credential_status_config_is_default")]
    pub credential_status: CredentialStatusConfig,
    #[serde(default, skip_serializing_if = "registry_notary_cel_config_is_default")]
    pub cel: RegistryNotaryCelConfig,
    #[serde(default, skip_serializing_if = "self_attestation_config_is_default")]
    pub self_attestation: SelfAttestationConfig,
    #[serde(default, skip_serializing_if = "oid4vci_config_is_default")]
    pub oid4vci: Oid4vciConfig,
    #[serde(default, skip_serializing_if = "federation_config_is_default")]
    pub federation: FederationConfig,
    #[serde(default, skip_serializing_if = "DeploymentConfig::is_default")]
    pub deployment: DeploymentConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryInstanceConfig {
    #[serde(default = "default_instance_id")]
    pub id: String,
    #[serde(default = "default_instance_environment")]
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
}

/// Optional governed-configuration local trust state.
///
/// Simple local deployments omit this block. Signed/governed apply requires it
/// so anti-rollback state lives in an explicit durable location.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTrustConfig {
    pub antirollback_state_path: PathBuf,
    pub local_approval_state_path: PathBuf,
    #[serde(
        default = "default_break_glass_rate_limit",
        skip_serializing_if = "config_trust_rate_limit_is_default"
    )]
    pub break_glass_rate_limit: ConfigTrustRateLimit,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_approver_count: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_roots: Vec<RegistryTrustRoot>,
    /// Operator-owned allowlist of remote TUF config sources.
    ///
    /// Admin requests may name one of these pre-configured sources but cannot
    /// introduce new repository URLs or override the per-entry
    /// `allow_dev_insecure_fetch_urls` flag. Omit the list (or leave it empty)
    /// when all remote TUF apply flows use local repository sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_tuf_repositories: Vec<RemoteTufRepositoryConfig>,
}

/// One entry in the `config_trust.remote_tuf_repositories` operator allowlist.
///
/// An admin request that names a remote TUF source must match an entry here
/// exactly (by `root_path`, `metadata_base_url`, `targets_base_url`, and
/// `datastore_dir`). The `allow_dev_insecure_fetch_urls` flag is always taken
/// from this entry, never from the request, so operators control the fetch
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteTufRepositoryConfig {
    pub root_path: PathBuf,
    pub metadata_base_url: String,
    pub targets_base_url: String,
    pub datastore_dir: PathBuf,
    /// Permit `http://` URLs to loopback addresses (localhost, 127.0.0.1, ::1).
    /// Intended for local development and tests only; must be `false` in
    /// production.
    #[serde(default)]
    pub allow_dev_insecure_fetch_urls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTrustRateLimit {
    pub max_accepted: u32,
    pub window_seconds: u64,
}

fn default_break_glass_rate_limit() -> ConfigTrustRateLimit {
    ConfigTrustRateLimit {
        max_accepted: 1,
        window_seconds: 3600,
    }
}

fn config_trust_rate_limit_is_default(rate_limit: &ConfigTrustRateLimit) -> bool {
    rate_limit == &default_break_glass_rate_limit()
}

impl Default for NotaryInstanceConfig {
    fn default() -> Self {
        Self {
            id: default_instance_id(),
            environment: default_instance_environment(),
            owner: None,
            jurisdiction: None,
            public_base_url: None,
        }
    }
}

fn instance_config_is_default(config: &NotaryInstanceConfig) -> bool {
    config == &NotaryInstanceConfig::default()
}

fn default_instance_id() -> String {
    "registry-notary-standalone".to_string()
}

fn default_instance_environment() -> String {
    "development".to_string()
}

impl StandaloneRegistryNotaryConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.evidence.enabled {
            return Err(EvidenceConfigError::EvidenceDisabled);
        }
        self.server.validate()?;
        self.server
            .admin_listener
            .validate(self.server.bind, self.config_trust.is_some())?;
        if let Some(config_trust) = &self.config_trust {
            if config_trust.antirollback_state_path.as_os_str().is_empty() {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.antirollback_state_path must not be empty".to_string(),
                });
            }
            if config_trust
                .local_approval_state_path
                .as_os_str()
                .is_empty()
            {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.local_approval_state_path must not be empty".to_string(),
                });
            }
            if config_trust.break_glass_rate_limit.max_accepted == 0 {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason:
                        "config_trust.break_glass_rate_limit.max_accepted must be greater than zero"
                            .to_string(),
                });
            }
            if config_trust.break_glass_rate_limit.window_seconds == 0 {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.break_glass_rate_limit.window_seconds must be greater than zero"
                        .to_string(),
                });
            }
            if config_trust
                .required_approver_count
                .values()
                .any(|count| *count == 0)
            {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.required_approver_count values must be greater than zero"
                        .to_string(),
                });
            }
            for root in &config_trust.accepted_roots {
                root.validate()
                    .map_err(|error| EvidenceConfigError::InvalidConfigTrustConfig {
                        reason: format!(
                            "config_trust.accepted_roots contains an invalid trust root: {error}"
                        ),
                    })?;
            }
            for repo in &config_trust.remote_tuf_repositories {
                if repo.root_path.as_os_str().is_empty()
                    || repo.datastore_dir.as_os_str().is_empty()
                {
                    return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                        reason: "config_trust.remote_tuf_repositories paths must not be empty"
                            .to_string(),
                    });
                }
                if !is_allowed_remote_tuf_url(
                    &repo.metadata_base_url,
                    repo.allow_dev_insecure_fetch_urls,
                ) || !is_allowed_remote_tuf_url(
                    &repo.targets_base_url,
                    repo.allow_dev_insecure_fetch_urls,
                ) {
                    return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                        reason: "config_trust.remote_tuf_repositories URLs must be https:// unless allow_dev_insecure_fetch_urls is true for loopback dev"
                            .to_string(),
                    });
                }
            }
        }
        self.replay.validate()?;
        match self.auth.mode {
            EvidenceAuthMode::ApiKey => {
                if self.auth.api_keys.is_empty() && self.auth.bearer_tokens.is_empty() {
                    return Err(EvidenceConfigError::NoCredentialsConfigured);
                }
            }
            EvidenceAuthMode::Oidc => {
                let oidc = self
                    .auth
                    .oidc
                    .as_ref()
                    .ok_or(EvidenceConfigError::MissingOidcConfig)?;
                if !self.auth.api_keys.is_empty() || !self.auth.bearer_tokens.is_empty() {
                    return Err(EvidenceConfigError::InvalidOidcConfig {
                        reason: "auth.api_keys and auth.bearer_tokens must be empty when auth.mode = oidc"
                            .to_string(),
                    });
                }
                oidc.validate()?;
            }
        }
        self.evidence.concurrency.validate()?;
        self.cel.validate()?;
        if self.evidence.max_credential_validity_seconds == 0 {
            return Err(EvidenceConfigError::InvalidCredentialProfileValidity {
                profile: "*".to_string(),
                validity_seconds: self.evidence.max_credential_validity_seconds as i64,
                max_validity_seconds: self.evidence.max_credential_validity_seconds,
            });
        }
        if self
            .evidence
            .allowed_purposes
            .iter()
            .any(|purpose| purpose.trim().is_empty())
        {
            return Err(EvidenceConfigError::InvalidPurpose);
        }
        self.credential_status.validate()?;
        for (connection_id, connection) in &self.evidence.source_connections {
            if connection.max_in_flight < 1 {
                return Err(EvidenceConfigError::InvalidConcurrency);
            }
            connection.validate_auth(connection_id)?;
            connection.validate_expected_sidecar(connection_id)?;
            connection.effective_dci()?;
        }
        // bulk_mode preconditions are enforced at config load so the runtime
        // never observes a misconfigured combination. rda_in_filter requires
        // operator attestation + cardinality=one on every binding pointing
        // at this connection. dci_batched_search requires the dci connector.
        // Bindings with query_fields are excluded from bulk paths until those
        // implementations understand multi-field grouping.
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
                            if !binding.query_fields.is_empty() {
                                return Err(
                                    EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
                                        connection: connection_id.clone(),
                                        claim: claim.id.clone(),
                                        binding: binding_id.clone(),
                                        bulk_mode: "rda_in_filter".to_string(),
                                    },
                                );
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
                            if !binding.query_fields.is_empty() {
                                return Err(
                                    EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
                                        connection: connection_id.clone(),
                                        claim: claim.id.clone(),
                                        binding: binding_id.clone(),
                                        bulk_mode: "dci_batched_search".to_string(),
                                    },
                                );
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
                BulkMode::OpenFnSidecarBatch => {
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.connector != SourceConnectorKind::OpenFnSidecar {
                                return Err(
                                    EvidenceConfigError::BulkModeRequiresOpenFnSidecarConnector {
                                        connection: connection_id.clone(),
                                        claim: claim.id.clone(),
                                        binding: binding_id.clone(),
                                    },
                                );
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
            }
        }
        for claim in &self.evidence.claims {
            if claim.id.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidClaim);
            }
            validate_claim_semantics(claim)?;
            for (binding_id, binding) in &claim.source_bindings {
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
                let connection = self
                    .evidence
                    .source_connections
                    .get(binding.connection.as_deref().unwrap_or_default())
                    .expect("source connection exists after contains_key check");
                if !binding.query_fields.is_empty()
                    && binding.connector == SourceConnectorKind::Dci
                    && connection.dci.query_type == "idtype-value"
                {
                    return Err(
                        EvidenceConfigError::QueryFieldsIncompatibleWithDciIdTypeValue {
                            connection: binding.connection.clone().unwrap_or_default(),
                            claim: claim.id.clone(),
                            binding: binding_id.clone(),
                        },
                    );
                }
                if binding.connector == SourceConnectorKind::OpenFnSidecar {
                    let has_static_token = !connection.token_env.trim().is_empty();
                    if !has_static_token || connection.source_auth.is_some() {
                        return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                            connection: binding.connection.clone().unwrap_or_default(),
                            reason:
                                "openfn_sidecar requires static bearer token auth through token_env"
                                    .to_string(),
                        });
                    }
                    if connection.retry_on_5xx {
                        return Err(EvidenceConfigError::OpenFnSidecarRequiresNoRetry {
                            connection: binding.connection.clone().unwrap_or_default(),
                        });
                    }
                    if binding.lookup.op != "eq" {
                        return Err(EvidenceConfigError::OpenFnSidecarUnsupportedOperator {
                            claim: claim.id.clone(),
                            binding: binding_id.clone(),
                            op: binding.lookup.op.clone(),
                        });
                    }
                    for query_field in &binding.query_fields {
                        if query_field.op != "eq" {
                            return Err(EvidenceConfigError::OpenFnSidecarUnsupportedOperator {
                                claim: claim.id.clone(),
                                binding: binding_id.clone(),
                                op: query_field.op.clone(),
                            });
                        }
                    }
                }
                validate_source_matching_config(
                    &claim.id,
                    binding_id,
                    &binding.matching,
                    &self.evidence.ecosystem_bindings,
                )?;
                for (field_id, field) in &binding.fields {
                    if let Some(semantic_term) = field.semantic_term.as_deref() {
                        validate_semantic_reference(
                            &claim.id,
                            &format!(
                                "source_bindings.{binding_id}.fields.{field_id}.semantic_term"
                            ),
                            semantic_term,
                        )?;
                    }
                }
            }
        }
        // Registry Notary currently resolves holder material only from
        // did:jwk. Reject any other configured method so discovery metadata
        // cannot advertise support that issuance cannot satisfy.
        self.evidence.validate_signing_keys()?;
        for (profile_id, profile) in &self.evidence.credential_profiles {
            validate_credential_profile_validity(
                profile_id,
                profile,
                self.evidence.max_credential_validity_seconds,
            )?;
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
            let key = self
                .evidence
                .signing_keys
                .get(profile.signing_key.as_str())
                .ok_or_else(|| EvidenceConfigError::UnknownCredentialProfileSigningKey {
                    profile: profile_id.clone(),
                    key: profile.signing_key.clone(),
                })?;
            if !key.status.may_sign() {
                return Err(EvidenceConfigError::CredentialProfileSigningKeyNotActive {
                    profile: profile_id.clone(),
                    key: profile.signing_key.clone(),
                });
            }
            validate_profile_signing_key_issuer_binding(profile_id, profile, key)?;
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
        self.validate_access_token_signing_cross_block()?;
        self.federation.validate(&self.evidence)?;
        self.validate_replay_cross_block()?;
        self.validate_signing_key_alg_usage()?;
        self.deployment.validate().map_err(|error| {
            EvidenceConfigError::InvalidDeploymentConfig {
                reason: error.to_string(),
            }
        })?;
        Ok(())
    }

    /// Snapshot the configuration facts the deployment gate engine reads.
    ///
    /// Pure projection of the loaded config. Building it here keeps gate
    /// predicates free of config-shape knowledge.
    pub fn gate_input(&self) -> crate::deployment::GateInput {
        crate::deployment::GateInput {
            replay_in_memory: self.replay.storage != REPLAY_STORAGE_REDIS,
            federation_enabled: self.federation.enabled,
            oid4vci_preauth_enabled: self.oid4vci.enabled
                && self.oid4vci.pre_authorized_code.enabled,
            holder_proof_required: self.evidence.credential_profiles.values().any(|profile| {
                profile.holder_binding.proof_of_possession.as_deref() == Some("required")
            }),
            wallet_facing: self.self_attestation.enabled,
            multi_instance: self.deployment.multi_instance,
            audit_sink_class_durable: audit_sink_is_durable(&self.audit),
            source_insecure_url: self
                .evidence
                .source_connections
                .values()
                .any(source_connection_uses_insecure_url),
            source_private_network_escape: self
                .evidence
                .source_connections
                .values()
                .any(|connection| connection.allow_insecure_private_network),
            openfn_source_without_expected_sidecar: self.evidence.source_connections.values().any(
                |connection| {
                    connection.bulk_mode == BulkMode::OpenFnSidecarBatch
                        && connection.expected_sidecar.is_none()
                },
            ),
            admin_shared_exposure: self.server.admin_listener.mode
                == RegistryNotaryAdminListenerMode::SharedWithPublic,
            openapi_public: !self.server.openapi_requires_auth,
            config_unsigned: self.config_trust.is_none(),
            self_attestation_enabled: self.self_attestation.enabled,
            transaction_token_anchor_configured: self.auth.access_token_signing.enabled,
            // DPoP/mTLS proof validation for transaction tokens is not yet
            // implemented. Keep this explicit so production/evidence profiles
            // surface the missing sender-constraint assurance.
            transaction_token_sender_constrained: false,
        }
    }

    /// Signing-key ids whose resolved public material must not be shared, per
    /// issue #173. These are the separated signing roles: every credential
    /// profile signing key, the access-token signing key (when enabled), and the
    /// federation signing key (when enabled). The eSignet pre-authorized-code RP
    /// client key is intentionally excluded: it is a separate role that is
    /// allowed to reuse the credential issuer's key material.
    pub fn reuse_scoped_signing_key_ids(&self) -> HashSet<&str> {
        let mut scoped: HashSet<&str> = self
            .evidence
            .credential_profiles
            .values()
            .map(|profile| profile.signing_key.as_str())
            .collect();
        if self.auth.access_token_signing.enabled {
            let access_token_key = self.auth.access_token_signing.signing_key_id.as_str();
            if !access_token_key.is_empty() {
                scoped.insert(access_token_key);
            }
        }
        if self.federation.enabled {
            let federation_key = self.federation.signing.signing_key.as_str();
            if !federation_key.is_empty() {
                scoped.insert(federation_key);
            }
        }
        scoped
    }

    /// Confine ES256 signing keys to credential profiles and confine RS256 to
    /// the eSignet pre-authorized-code RP client assertion. Access-token
    /// signing and federation signing must reference EdDSA keys.
    fn validate_signing_key_alg_usage(&self) -> Result<(), EvidenceConfigError> {
        for (key_id, key) in &self.evidence.signing_keys {
            if key.alg == CREDENTIAL_SIGNING_ALG_EDDSA {
                continue;
            }
            if self.auth.access_token_signing.signing_key_id == *key_id {
                return invalid_signing_key(
                    key_id,
                    "non-EdDSA signing key is used as the access-token signing key \
                     (auth.access_token_signing.signing_key_id); non-EdDSA signing keys may only \
                     be used by credential profiles or as the eSignet pre-authorized-code RP \
                     client assertion key (oid4vci.pre_authorized_code.esignet.client_signing_key_id)",
                );
            }
            if self.federation.signing.signing_key == *key_id {
                return invalid_signing_key(
                    key_id,
                    "non-EdDSA signing key is used as the federation signing key \
                     (federation.signing.signing_key); non-EdDSA signing keys may only be used by \
                     credential profiles or as the eSignet pre-authorized-code RP client assertion \
                     key (oid4vci.pre_authorized_code.esignet.client_signing_key_id)",
                );
            }
            if key.alg == CLIENT_ASSERTION_SIGNING_ALG_RS256
                && self
                    .evidence
                    .credential_profiles
                    .values()
                    .any(|profile| profile.signing_key == *key_id)
            {
                return invalid_signing_key(
                    key_id,
                    "RS256 signing key is used by a credential profile; credential profile \
                     signing keys must use EdDSA or ES256, and RS256 is reserved for the eSignet \
                     pre-authorized-code RP client assertion key \
                     (oid4vci.pre_authorized_code.esignet.client_signing_key_id)",
                );
            }
        }
        Ok(())
    }

    fn validate_oid4vci_cross_block(&self) -> Result<(), EvidenceConfigError> {
        self.oid4vci
            .validate(&self.self_attestation, &self.evidence)
    }

    fn validate_access_token_signing_cross_block(&self) -> Result<(), EvidenceConfigError> {
        let signing = &self.auth.access_token_signing;
        if !signing.enabled {
            return Ok(());
        }
        if signing.issuer.trim().is_empty() {
            return invalid_access_token_signing("issuer must not be empty when enabled");
        }
        validate_access_token_signing_entries("audiences", &signing.audiences)?;
        if signing.allowed_algorithms.is_empty()
            || signing
                .allowed_algorithms
                .iter()
                .any(|alg| alg != CREDENTIAL_SIGNING_ALG_EDDSA)
        {
            return invalid_access_token_signing(format!(
                "allowed_algorithms must list only {CREDENTIAL_SIGNING_ALG_EDDSA}"
            ));
        }
        if signing.token_typ.trim().is_empty() {
            return invalid_access_token_signing("token_typ must not be empty when enabled");
        }
        // The access-token `typ` must differ from the pre-authorized-code `typ`,
        // or a pre-authorized code would also verify as an access token (the two
        // are distinguished only by header `typ`).
        if signing.token_typ == crate::tokens::PRE_AUTHORIZED_CODE_JWT_TYP {
            return invalid_access_token_signing(format!(
                "token_typ must not equal the pre-authorized-code typ '{}'",
                crate::tokens::PRE_AUTHORIZED_CODE_JWT_TYP
            ));
        }
        if signing.access_token_ttl_seconds == 0 || signing.access_token_ttl_seconds > 600 {
            return invalid_access_token_signing(
                "access_token_ttl_seconds must be between 1 and 600",
            );
        }
        if signing.signing_key_id.trim().is_empty() {
            return invalid_access_token_signing("signing_key_id must not be empty when enabled");
        }
        let key = self
            .evidence
            .signing_keys
            .get(signing.signing_key_id.as_str())
            .ok_or_else(|| EvidenceConfigError::InvalidAccessTokenSigningConfig {
                reason: format!(
                    "signing_key_id '{}' must reference an evidence.signing_keys entry",
                    signing.signing_key_id
                ),
            })?;
        if !key.status.may_sign() {
            return invalid_access_token_signing(format!(
                "signing_key_id '{}' must be an active signing key",
                signing.signing_key_id
            ));
        }
        // The access-token key MUST be distinct from every credential-signing
        // key so a confusion or compromise of one is not the other.
        for (profile_id, profile) in &self.evidence.credential_profiles {
            if profile.signing_key == signing.signing_key_id {
                return invalid_access_token_signing(format!(
                    "signing_key_id '{}' must be distinct from credential profile '{profile_id}' signing key",
                    signing.signing_key_id
                ));
            }
        }
        let mut verification_keys = std::collections::BTreeSet::new();
        for key_id in &signing.verification_key_ids {
            if key_id.trim().is_empty() {
                return invalid_access_token_signing(
                    "verification_key_ids must not contain blank entries",
                );
            }
            if key_id == &signing.signing_key_id {
                return invalid_access_token_signing(format!(
                    "verification_key_ids must not repeat active signing_key_id '{}'",
                    signing.signing_key_id
                ));
            }
            if !verification_keys.insert(key_id.as_str()) {
                return invalid_access_token_signing(format!(
                    "verification_key_ids contains duplicate key '{key_id}'"
                ));
            }
            let key = self.evidence.signing_keys.get(key_id).ok_or_else(|| {
                EvidenceConfigError::InvalidAccessTokenSigningConfig {
                    reason: format!(
                        "verification_key_ids entry '{key_id}' must reference an evidence.signing_keys entry"
                    ),
                }
            })?;
            if !key.status.may_publish() || key.status.may_sign() {
                return invalid_access_token_signing(format!(
                    "verification_key_ids entry '{key_id}' must be a publish_only signing key"
                ));
            }
            if key.alg != CREDENTIAL_SIGNING_ALG_EDDSA {
                return invalid_access_token_signing(format!(
                    "verification_key_ids entry '{key_id}' must use {CREDENTIAL_SIGNING_ALG_EDDSA}"
                ));
            }
            for (profile_id, profile) in &self.evidence.credential_profiles {
                if profile.signing_key == *key_id {
                    return invalid_access_token_signing(format!(
                        "verification_key_ids entry '{key_id}' must be distinct from credential profile '{profile_id}' signing key"
                    ));
                }
            }
        }
        Ok(())
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

fn validate_credential_profile_validity(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    max_validity_seconds: u64,
) -> Result<(), EvidenceConfigError> {
    if profile.validity_seconds <= 0 {
        return Err(EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        });
    }
    let validity_seconds = u64::try_from(profile.validity_seconds).map_err(|_| {
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        }
    })?;
    if validity_seconds > max_validity_seconds {
        return Err(EvidenceConfigError::InvalidCredentialProfileValidity {
            profile: profile_id.to_string(),
            validity_seconds: profile.validity_seconds,
            max_validity_seconds,
        });
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryCelConfig {
    #[serde(default = "default_cel_mode")]
    pub mode: String,
    #[serde(default = "default_cel_worker_count")]
    pub worker_count: usize,
    #[serde(default = "default_cel_eval_timeout_ms")]
    pub eval_timeout_ms: u64,
    #[serde(default)]
    pub queue_max: usize,
    #[serde(default)]
    pub allow_regex: bool,
    #[serde(default = "default_cel_max_expression_bytes")]
    pub max_expression_bytes: usize,
    #[serde(default = "default_cel_max_binding_json_bytes")]
    pub max_binding_json_bytes: usize,
    #[serde(default = "default_cel_max_result_json_bytes")]
    pub max_result_json_bytes: usize,
    #[serde(default = "default_cel_max_string_bytes")]
    pub max_string_bytes: usize,
    #[serde(default = "default_cel_max_list_items")]
    pub max_list_items: usize,
    #[serde(default = "default_cel_max_object_depth")]
    pub max_object_depth: usize,
    #[serde(default = "default_cel_max_object_keys")]
    pub max_object_keys: usize,
    #[serde(default = "default_cel_worker_memory_bytes")]
    pub worker_memory_bytes: u64,
    #[serde(default = "default_cel_worker_stderr_bytes")]
    pub worker_stderr_bytes: usize,
}

impl Default for RegistryNotaryCelConfig {
    fn default() -> Self {
        Self {
            mode: default_cel_mode(),
            worker_count: default_cel_worker_count(),
            eval_timeout_ms: default_cel_eval_timeout_ms(),
            queue_max: 0,
            allow_regex: false,
            max_expression_bytes: default_cel_max_expression_bytes(),
            max_binding_json_bytes: default_cel_max_binding_json_bytes(),
            max_result_json_bytes: default_cel_max_result_json_bytes(),
            max_string_bytes: default_cel_max_string_bytes(),
            max_list_items: default_cel_max_list_items(),
            max_object_depth: default_cel_max_object_depth(),
            max_object_keys: default_cel_max_object_keys(),
            worker_memory_bytes: default_cel_worker_memory_bytes(),
            worker_stderr_bytes: default_cel_worker_stderr_bytes(),
        }
    }
}

impl RegistryNotaryCelConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.mode != "worker" && self.mode != "disabled" {
            return invalid_cel("cel.mode must be worker or disabled");
        }
        if self.worker_count == 0 || self.worker_count > 16 {
            return invalid_cel("cel.worker_count must be between 1 and 16");
        }
        if self.eval_timeout_ms == 0 || self.eval_timeout_ms > 30_000 {
            return invalid_cel("cel.eval_timeout_ms must be between 1 and 30000");
        }
        if self.queue_max != 0 {
            return invalid_cel(
                "cel.queue_max must be 0; queued CEL evaluation is not implemented",
            );
        }
        if self.max_expression_bytes == 0 || self.max_expression_bytes > 256 * 1024 {
            return invalid_cel("cel.max_expression_bytes must be between 1 and 262144");
        }
        if self.max_binding_json_bytes == 0 || self.max_binding_json_bytes > 1024 * 1024 {
            return invalid_cel("cel.max_binding_json_bytes must be between 1 and 1048576");
        }
        if self.max_result_json_bytes == 0 || self.max_result_json_bytes > 1024 * 1024 {
            return invalid_cel("cel.max_result_json_bytes must be between 1 and 1048576");
        }
        if self.max_string_bytes == 0 || self.max_string_bytes > 256 * 1024 {
            return invalid_cel("cel.max_string_bytes must be between 1 and 262144");
        }
        if self.max_list_items == 0 || self.max_list_items > 100_000 {
            return invalid_cel("cel.max_list_items must be between 1 and 100000");
        }
        if self.max_object_depth == 0 || self.max_object_depth > 64 {
            return invalid_cel("cel.max_object_depth must be between 1 and 64");
        }
        if self.max_object_keys == 0 || self.max_object_keys > 2048 {
            return invalid_cel("cel.max_object_keys must be between 1 and 2048");
        }
        if self.worker_memory_bytes < 32 * 1024 * 1024
            || self.worker_memory_bytes > 1024 * 1024 * 1024
        {
            return invalid_cel("cel.worker_memory_bytes must be between 33554432 and 1073741824");
        }
        if self.worker_stderr_bytes == 0 || self.worker_stderr_bytes > 64 * 1024 {
            return invalid_cel("cel.worker_stderr_bytes must be between 1 and 65536");
        }
        Ok(())
    }
}

fn registry_notary_cel_config_is_default(config: &RegistryNotaryCelConfig) -> bool {
    config == &RegistryNotaryCelConfig::default()
}

fn invalid_cel<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidCelConfig {
        reason: reason.into(),
    })
}

fn default_cel_mode() -> String {
    "worker".to_string()
}

const fn default_cel_worker_count() -> usize {
    2
}

const fn default_cel_eval_timeout_ms() -> u64 {
    2_000
}

const fn default_cel_max_expression_bytes() -> usize {
    8 * 1024
}

const fn default_cel_max_binding_json_bytes() -> usize {
    64 * 1024
}

const fn default_cel_max_result_json_bytes() -> usize {
    16 * 1024
}

const fn default_cel_max_string_bytes() -> usize {
    16 * 1024
}

const fn default_cel_max_list_items() -> usize {
    1024
}

const fn default_cel_max_object_depth() -> usize {
    16
}

const fn default_cel_max_object_keys() -> usize {
    256
}

const fn default_cel_worker_memory_bytes() -> u64 {
    128 * 1024 * 1024
}

const fn default_cel_worker_stderr_bytes() -> usize {
    1024
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
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
    /// Pre-authorized-code flow settings. Disabled by default; offers fall
    /// back to the `authorization_code` grant unless this is enabled.
    #[serde(default)]
    pub pre_authorized_code: Oid4vciPreAuthorizedCodeConfig,
    #[serde(default)]
    pub display: Vec<Oid4vciIssuerDisplayConfig>,
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
        // The pre-authorized-code block is validated regardless of the oid4vci
        // enable toggle so a partially-configured flow is rejected, but the
        // flow is an OID4VCI grant and so requires oid4vci itself enabled.
        if self.pre_authorized_code.enabled && !self.enabled {
            return invalid_oid4vci(
                "pre_authorized_code.enabled = true requires oid4vci.enabled = true",
            );
        }
        self.pre_authorized_code.validate()?;
        // The eSignet RP client assertion is signed with this key, so it must
        // resolve to an active signing key. Surface that at config time rather
        // than as a startup failure when the pre-auth flow is first built.
        if self.pre_authorized_code.enabled {
            let key_id = self
                .pre_authorized_code
                .esignet
                .client_signing_key_id
                .as_str();
            let key = evidence.signing_keys.get(key_id).ok_or_else(|| {
                EvidenceConfigError::InvalidOid4vciConfig {
                    reason: format!(
                        "pre_authorized_code.esignet.client_signing_key_id '{key_id}' must reference an evidence.signing_keys entry"
                    ),
                }
            })?;
            if !key.status.may_sign() {
                return invalid_oid4vci(format!(
                    "pre_authorized_code.esignet.client_signing_key_id '{key_id}' must reference an active signing key"
                ));
            }
        }
        // The pre-auth callback resolves the subject-binding claim from the
        // eSignet userinfo endpoint when the claim is userinfo-sourced, so the
        // endpoint must be configured for that path to work.
        if self.pre_authorized_code.enabled
            && self_attestation.subject_binding.claim_source == SelfAttestationClaimSource::Userinfo
            && self
                .pre_authorized_code
                .esignet
                .userinfo_url
                .trim()
                .is_empty()
        {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.userinfo_url must be set when self_attestation.subject_binding.claim_source = userinfo",
            );
        }
        if self.pre_authorized_code.enabled
            && self.pre_authorized_code.tx_code.required
            && self_attestation
                .rate_limits
                .tx_code_attempts_per_code_per_minute
                == 0
        {
            return invalid_oid4vci(
                "self_attestation.rate_limits.tx_code_attempts_per_code_per_minute must be greater than zero when pre_authorized_code.enabled = true and tx_code.required = true",
            );
        }
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
        for display in &self.display {
            display.validate("oid4vci.display")?;
        }

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

        let mut configured_vcts = HashSet::new();
        for (configuration_id, configuration) in &self.credential_configurations {
            configuration.validate(
                configuration_id,
                &self.credential_issuer,
                evidence,
                &claim_ids,
                &allowed_claim_ids,
                &allowed_profiles,
            )?;
            if !configured_vcts.insert(configuration.vct.as_str()) {
                return invalid_oid4vci(format!(
                    "credential configuration '{configuration_id}' vct must be unique"
                ));
            }
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

/// Pre-authorized-code flow configuration.
///
/// All fields default so existing configs that omit this block load unchanged
/// with the flow disabled. When `enabled`, the eSignet RP login settings, the
/// callback redirect, and the TTLs become required (validated cross-block).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciPreAuthorizedCodeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tx_code: Oid4vciTxCodeConfig,
    /// eSignet RP settings for the citizen login leg.
    #[serde(default)]
    pub esignet: Oid4vciEsignetRpConfig,
    /// Pre-authorized-code lifetime in seconds.
    #[serde(default = "default_pre_authorized_code_ttl_seconds")]
    pub pre_authorized_code_ttl_seconds: u64,
}

impl Default for Oid4vciPreAuthorizedCodeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tx_code: Oid4vciTxCodeConfig::default(),
            esignet: Oid4vciEsignetRpConfig::default(),
            pre_authorized_code_ttl_seconds: default_pre_authorized_code_ttl_seconds(),
        }
    }
}

impl Oid4vciPreAuthorizedCodeConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        self.tx_code.validate()?;
        self.esignet.validate()?;
        if self.pre_authorized_code_ttl_seconds == 0 || self.pre_authorized_code_ttl_seconds > 600 {
            return invalid_oid4vci(
                "pre_authorized_code.pre_authorized_code_ttl_seconds must be between 1 and 600",
            );
        }
        if !self.tx_code.required
            && self.pre_authorized_code_ttl_seconds > MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS
        {
            return invalid_oid4vci(
                "pre_authorized_code.pre_authorized_code_ttl_seconds must be between 1 and 300 when pre_authorized_code.tx_code.required = false",
            );
        }
        Ok(())
    }
}

pub const MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS: u64 = 300;

const fn default_pre_authorized_code_ttl_seconds() -> u64 {
    300
}

/// `tx_code` (PIN) policy for the pre-authorized-code grant. A `tx_code` is
/// required by default because a code without a PIN is a bearer credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciTxCodeConfig {
    #[serde(default = "default_tx_code_required")]
    pub required: bool,
    #[serde(default = "default_tx_code_input_mode")]
    pub input_mode: String,
    #[serde(default = "default_tx_code_length")]
    pub length: u64,
}

impl Default for Oid4vciTxCodeConfig {
    fn default() -> Self {
        Self {
            required: default_tx_code_required(),
            input_mode: default_tx_code_input_mode(),
            length: default_tx_code_length(),
        }
    }
}

impl Oid4vciTxCodeConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if !self.required {
            return Ok(());
        }
        if self.input_mode != TX_CODE_INPUT_MODE_NUMERIC {
            return invalid_oid4vci("pre_authorized_code.tx_code.input_mode must be numeric");
        }
        if !(4..=12).contains(&self.length) {
            return invalid_oid4vci("pre_authorized_code.tx_code.length must be between 4 and 12");
        }
        Ok(())
    }
}

const fn default_tx_code_required() -> bool {
    true
}

fn default_tx_code_input_mode() -> String {
    TX_CODE_INPUT_MODE_NUMERIC.to_string()
}

const fn default_tx_code_length() -> u64 {
    6
}

/// eSignet relying-party settings for the citizen login leg of the
/// pre-authorized-code flow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciEsignetRpConfig {
    /// Confidential client id the Notary presents to eSignet.
    #[serde(default)]
    pub client_id: String,
    /// `evidence.signing_keys` entry used to sign the eSignet
    /// `private_key_jwt` client assertion.
    #[serde(default)]
    pub client_signing_key_id: String,
    /// Notary callback the citizen browser is redirected back to.
    #[serde(default)]
    pub redirect_uri: String,
    /// eSignet authorize endpoint.
    #[serde(default)]
    pub authorize_url: String,
    /// eSignet token endpoint.
    #[serde(default)]
    pub token_url: String,
    /// eSignet OIDC issuer, pinned when validating the returned `id_token`.
    #[serde(default)]
    pub issuer: String,
    /// eSignet JWKS URI, used to resolve the `id_token` signing key by `kid`.
    #[serde(default)]
    pub jwks_uri: String,
    /// eSignet userinfo endpoint. Required when the subject-binding claim is
    /// sourced from userinfo rather than the `id_token`; the callback fetches
    /// the userinfo JWS with the eSignet access token and reads the binding
    /// claim from it.
    #[serde(default)]
    pub userinfo_url: String,
    /// OAuth scopes requested at eSignet.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifetime of the short-lived login state (PKCE verifier + nonce +
    /// selection) reserved between `offer/start` and `offer/callback`.
    #[serde(default = "default_login_state_ttl_seconds")]
    pub login_state_ttl_seconds: u64,
    /// Allow `http` loopback URLs for the eSignet endpoints and JWKS transport.
    /// For local development and tests only.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

impl Oid4vciEsignetRpConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.client_id.trim().is_empty() {
            return invalid_oid4vci("pre_authorized_code.esignet.client_id must not be empty");
        }
        if self.client_signing_key_id.trim().is_empty() {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.client_signing_key_id must not be empty",
            );
        }
        validate_oid4vci_public_url(
            "pre_authorized_code.esignet.redirect_uri",
            &self.redirect_uri,
        )?;
        validate_oid4vci_public_url(
            "pre_authorized_code.esignet.authorize_url",
            &self.authorize_url,
        )?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.token_url", &self.token_url)?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.issuer", &self.issuer)?;
        validate_oid4vci_public_url("pre_authorized_code.esignet.jwks_uri", &self.jwks_uri)?;
        if !self.userinfo_url.trim().is_empty() {
            validate_oid4vci_public_url(
                "pre_authorized_code.esignet.userinfo_url",
                &self.userinfo_url,
            )?;
        }
        validate_oid4vci_non_empty_entries("pre_authorized_code.esignet.scopes", &self.scopes)?;
        if self.login_state_ttl_seconds == 0 || self.login_state_ttl_seconds > 600 {
            return invalid_oid4vci(
                "pre_authorized_code.esignet.login_state_ttl_seconds must be between 1 and 600",
            );
        }
        Ok(())
    }
}

const fn default_login_state_ttl_seconds() -> u64 {
    300
}

const TX_CODE_INPUT_MODE_NUMERIC: &str = "numeric";

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
    #[serde(default)]
    pub display: Oid4vciCredentialDisplayConfig,
    #[serde(default = "default_oid4vci_proof_signing_alg_values_supported")]
    pub proof_signing_alg_values_supported: Vec<String>,
    #[serde(default = "default_oid4vci_cryptographic_binding_methods_supported")]
    pub cryptographic_binding_methods_supported: Vec<String>,
}

impl Oid4vciCredentialConfigurationConfig {
    fn validate(
        &self,
        configuration_id: &str,
        credential_issuer: &str,
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
        self.display.validate("credential_configurations.display")?;
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
        validate_oid4vci_endpoint_url(
            "credential_configurations.vct",
            &self.vct,
            credential_issuer,
        )?;
        let Some((_, _, vct_path)) = split_absolute_url(&self.vct) else {
            return invalid_oid4vci("credential_configurations.vct must be an absolute URL");
        };
        let Some(expected_vct_prefix) = oid4vci_credentials_path_prefix(credential_issuer) else {
            return invalid_oid4vci("oid4vci.credential_issuer must be an absolute URL");
        };
        if !vct_path.starts_with(&expected_vct_prefix) {
            return invalid_oid4vci(format!(
                "credential configuration '{configuration_id}' vct path must start with {expected_vct_prefix}"
            ));
        }
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciIssuerDisplayConfig {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Oid4vciDisplayImageConfig>,
}

impl Oid4vciIssuerDisplayConfig {
    fn validate(&self, name: &str) -> Result<(), EvidenceConfigError> {
        validate_oid4vci_non_empty_value(&format!("{name}.name"), &self.name)?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.locale"),
            self.locale.as_deref(),
        )?;
        validate_oid4vci_display_image(&format!("{name}.logo"), &self.logo)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciCredentialDisplayConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Oid4vciDisplayImageConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_image: Option<Oid4vciDisplayImageConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_image: Option<Oid4vciDisplayImageConfig>,
}

impl Oid4vciCredentialDisplayConfig {
    fn validate(&self, name: &str) -> Result<(), EvidenceConfigError> {
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.locale"),
            self.locale.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.description"),
            self.description.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.background_color"),
            self.background_color.as_deref(),
        )?;
        validate_optional_oid4vci_non_empty_value(
            &format!("{name}.text_color"),
            self.text_color.as_deref(),
        )?;
        validate_oid4vci_display_image(&format!("{name}.logo"), &self.logo)?;
        validate_oid4vci_display_image(
            &format!("{name}.background_image"),
            &self.background_image,
        )?;
        validate_oid4vci_display_image(&format!("{name}.secondary_image"), &self.secondary_image)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vciDisplayImageConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
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
    let Some((_, _, path)) = split_absolute_url(url) else {
        return invalid_oid4vci(format!("{name} must be an absolute URL"));
    };
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

fn oid4vci_credentials_path_prefix(credential_issuer: &str) -> Option<String> {
    let (_, _, issuer_path) = split_absolute_url(credential_issuer.trim())?;
    let issuer_path = issuer_path.trim_end_matches('/');
    if issuer_path.is_empty() {
        Some("/credentials/".to_string())
    } else {
        Some(format!("{issuer_path}/credentials/"))
    }
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

fn validate_optional_oid4vci_non_empty_value(
    name: &str,
    value: Option<&str>,
) -> Result<(), EvidenceConfigError> {
    if let Some(value) = value {
        validate_oid4vci_non_empty_value(name, value)?;
    }
    Ok(())
}

fn validate_oid4vci_display_image(
    name: &str,
    image: &Option<Oid4vciDisplayImageConfig>,
) -> Result<(), EvidenceConfigError> {
    let Some(image) = image else {
        return Ok(());
    };
    validate_optional_oid4vci_non_empty_value(&format!("{name}.uri"), image.uri.as_deref())?;
    validate_optional_oid4vci_non_empty_value(&format!("{name}.url"), image.url.as_deref())?;
    validate_optional_oid4vci_non_empty_value(
        &format!("{name}.alt_text"),
        image.alt_text.as_deref(),
    )?;
    match (image.uri.as_deref(), image.url.as_deref()) {
        (None, None) => invalid_oid4vci(format!("{name} must include uri or url")),
        (uri, url) => {
            if let Some(uri) = uri {
                validate_oid4vci_public_url(&format!("{name}.uri"), uri)?;
            }
            if let Some(url) = url {
                validate_oid4vci_public_url(&format!("{name}.url"), url)?;
            }
            Ok(())
        }
    }
}

fn invalid_oid4vci<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidOid4vciConfig {
        reason: reason.into(),
    })
}

fn invalid_access_token_signing<T>(reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidAccessTokenSigningConfig {
        reason: reason.into(),
    })
}

fn validate_access_token_signing_entries(
    field: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_access_token_signing(format!("{field} must not be empty when enabled"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_access_token_signing(format!("{field} must not contain blank entries"));
    }
    Ok(())
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
    pub delegation: SelfAttestationDelegationConfig,
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
            delegation: SelfAttestationDelegationConfig::default(),
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
        if auth.mode != EvidenceAuthMode::Oidc {
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
        self.delegation.validate(evidence)?;
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationDelegationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_relationships: Vec<SelfAttestationDelegatedRelationshipConfig>,
}

impl SelfAttestationDelegationConfig {
    fn validate(&self, evidence: &EvidenceConfig) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            if !self.allowed_relationships.is_empty() {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason:
                        "self_attestation.delegation.enabled=false requires allowed_relationships to be empty"
                            .to_string(),
                });
            }
            return Ok(());
        }
        if self.allowed_relationships.is_empty() {
            return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                reason: "self_attestation.delegation.enabled requires allowed_relationships"
                    .to_string(),
            });
        }
        let claim_ids: HashSet<&str> = evidence
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect();
        let mut relationship_types = HashSet::new();
        for relationship in &self.allowed_relationships {
            relationship.validate(evidence, &claim_ids)?;
            if !relationship_types.insert(relationship.relationship_type.as_str()) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "self_attestation.delegation.allowed_relationships contains duplicate relationship_type '{}'",
                        relationship.relationship_type
                    ),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn relationship(
        &self,
        relationship_type: &str,
    ) -> Option<&SelfAttestationDelegatedRelationshipConfig> {
        self.allowed_relationships
            .iter()
            .find(|relationship| relationship.relationship_type == relationship_type)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfAttestationDelegatedRelationshipConfig {
    pub relationship_type: String,
    pub proof_claim: String,
    #[serde(default)]
    pub target_id_type: Option<String>,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub allowed_formats: Vec<String>,
    #[serde(default)]
    pub allowed_disclosures: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
}

impl SelfAttestationDelegatedRelationshipConfig {
    fn validate(
        &self,
        evidence: &EvidenceConfig,
        claim_ids: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError> {
        if self.relationship_type.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                reason:
                    "self_attestation.delegation.allowed_relationships.relationship_type is required"
                        .to_string(),
            });
        }
        if self.proof_claim.trim().is_empty() || !claim_ids.contains(self.proof_claim.as_str()) {
            return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                reason: format!(
                    "self_attestation.delegation proof_claim references unknown claim '{}'",
                    self.proof_claim
                ),
            });
        }
        if let Some(target_id_type) = self.target_id_type.as_deref() {
            if target_id_type.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: "self_attestation.delegation target_id_type must not be blank"
                        .to_string(),
                });
            }
        }
        validate_non_empty_entries(
            "self_attestation.delegation.allowed_claims",
            &self.allowed_claims,
        )?;
        validate_non_empty_entries(
            "self_attestation.delegation.allowed_purposes",
            &self.allowed_purposes,
        )?;
        validate_non_empty_entries(
            "self_attestation.delegation.allowed_formats",
            &self.allowed_formats,
        )?;
        validate_non_empty_entries(
            "self_attestation.delegation.allowed_disclosures",
            &self.allowed_disclosures,
        )?;
        validate_entries(
            "self_attestation.delegation.credential_profiles",
            &self.credential_profiles,
        )?;
        for claim_id in &self.allowed_claims {
            if !claim_ids.contains(claim_id.as_str()) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "self_attestation.delegation allowed_claims references unknown claim '{claim_id}'"
                    ),
                });
            }
            let claim = evidence
                .claims
                .iter()
                .find(|claim| claim.id == *claim_id)
                .expect("claim id was checked above");
            if !claim.depends_on.iter().any(|dep| dep == &self.proof_claim) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "delegated claim '{claim_id}' must depend_on proof_claim '{}'",
                        self.proof_claim
                    ),
                });
            }
        }
        for profile_id in &self.credential_profiles {
            if !evidence.credential_profiles.contains_key(profile_id) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "self_attestation.delegation credential_profiles references unknown profile '{profile_id}'"
                    ),
                });
            }
        }
        Ok(())
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
        if self.max_credential_validity_seconds == 0 {
            return invalid_self_attestation(
                "token_policy.max_credential_validity_seconds must be greater than zero",
            );
        }
        if self.max_clock_leeway_seconds == 0 || self.max_clock_leeway_seconds > 60 {
            return invalid_self_attestation(
                "token_policy.max_clock_leeway_seconds must be between 1 and 60",
            );
        }
        if oidc.leeway > Duration::from_secs(self.max_clock_leeway_seconds) {
            return invalid_self_attestation(
                "auth.oidc.leeway must not exceed token_policy.max_clock_leeway_seconds",
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
    /// Per-minute cap on `tx_code` attempts against a single
    /// `pre-authorized_code`. Bounds brute force of the numeric PIN at the
    /// pre-authorized-code token endpoint. Defaults to zero so existing
    /// configs that do not enable pre-auth still validate; it must be greater
    /// than zero only when the pre-authorized-code flow is enabled.
    #[serde(default)]
    pub tx_code_attempts_per_code_per_minute: u32,
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
    if validity_seconds > max_credential_validity_seconds {
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
    #[serde(
        default = "default_openapi_requires_auth",
        skip_serializing_if = "openapi_requires_auth_is_default"
    )]
    pub openapi_requires_auth: bool,
    #[serde(default, skip_serializing_if = "admin_listener_config_is_default")]
    pub admin_listener: RegistryNotaryAdminListenerConfig,
    #[serde(default)]
    pub cors: RegistryNotaryCorsConfig,
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
    #[serde(default = "default_request_body_timeout", with = "humantime_serde")]
    pub request_body_timeout: Duration,
    #[serde(
        default = "default_http1_header_read_timeout",
        with = "humantime_serde"
    )]
    pub http1_header_read_timeout: Duration,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxy_ips: Vec<IpAddr>,
}

impl Default for RegistryNotaryHttpConfig {
    fn default() -> Self {
        Self {
            bind: default_bind_addr(),
            openapi_requires_auth: default_openapi_requires_auth(),
            admin_listener: RegistryNotaryAdminListenerConfig::default(),
            cors: RegistryNotaryCorsConfig::default(),
            request_timeout: default_request_timeout(),
            request_body_timeout: default_request_body_timeout(),
            http1_header_read_timeout: default_http1_header_read_timeout(),
            max_connections: default_max_connections(),
            trusted_proxy_ips: Vec::new(),
        }
    }
}

impl RegistryNotaryHttpConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.request_timeout.is_zero()
            || self.request_body_timeout.is_zero()
            || self.http1_header_read_timeout.is_zero()
            || self.max_connections == 0
        {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason:
                    "server timeouts must be non-zero and max_connections must be greater than zero"
                        .to_string(),
            });
        }
        Ok(())
    }
}

fn default_bind_addr() -> SocketAddr {
    // SAFETY: the literal is a valid loopback socket address.
    "127.0.0.1:8081"
        .parse()
        .expect("default bind address is valid")
}

fn default_openapi_requires_auth() -> bool {
    true
}

fn openapi_requires_auth_is_default(value: &bool) -> bool {
    *value == default_openapi_requires_auth()
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_request_body_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_http1_header_read_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_max_connections() -> usize {
    1024
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryNotaryAdminListenerMode {
    SharedWithPublic,
    Dedicated,
    #[default]
    Disabled,
}

impl RegistryNotaryAdminListenerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedWithPublic => "shared_with_public",
            Self::Dedicated => "dedicated",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryAdminListenerConfig {
    #[serde(default, skip_serializing_if = "admin_listener_mode_is_default")]
    pub mode: RegistryNotaryAdminListenerMode,
    #[serde(default = "default_admin_bind_addr")]
    pub bind: SocketAddr,
}

impl RegistryNotaryAdminListenerConfig {
    fn validate(
        &self,
        public_bind: SocketAddr,
        governed_config_enabled: bool,
    ) -> Result<(), EvidenceConfigError> {
        if governed_config_enabled && self.mode != RegistryNotaryAdminListenerMode::Dedicated {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason: "config_trust requires server.admin_listener.mode = dedicated".to_string(),
            });
        }
        if self.mode == RegistryNotaryAdminListenerMode::Dedicated && self.bind == public_bind {
            return Err(EvidenceConfigError::InvalidServerConfig {
                reason: "server.admin_listener.bind must differ from server.bind in dedicated mode"
                    .to_string(),
            });
        }
        Ok(())
    }
}

impl Default for RegistryNotaryAdminListenerConfig {
    fn default() -> Self {
        Self {
            mode: RegistryNotaryAdminListenerMode::Disabled,
            bind: default_admin_bind_addr(),
        }
    }
}

fn default_admin_bind_addr() -> SocketAddr {
    // SAFETY: the literal is a valid loopback socket address.
    "127.0.0.1:8082"
        .parse()
        .expect("default admin bind address is valid")
}

fn admin_listener_config_is_default(config: &RegistryNotaryAdminListenerConfig) -> bool {
    config == &RegistryNotaryAdminListenerConfig::default()
}

fn admin_listener_mode_is_default(mode: &RegistryNotaryAdminListenerMode) -> bool {
    mode == &RegistryNotaryAdminListenerMode::default()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryNotaryCorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthConfig {
    #[serde(default)]
    pub mode: EvidenceAuthMode,
    #[serde(default)]
    pub api_keys: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub bearer_tokens: Vec<EvidenceCredentialConfig>,
    #[serde(default)]
    pub oidc: Option<EvidenceOidcAuthConfig>,
    /// Trust anchor for Notary-minted access tokens (the pre-authorized-code
    /// flow's second verifier). Disabled by default so existing configs load
    /// unchanged.
    #[serde(default)]
    pub access_token_signing: AccessTokenSigningConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthMode {
    #[default]
    ApiKey,
    Oidc,
}

impl EvidenceAuthMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Oidc => "oidc",
        }
    }
}

/// Self-issued access-token signing configuration.
///
/// When `enabled`, the Notary mints its own access tokens (for the
/// pre-authorized-code flow) signed with a dedicated `signing_keys` entry that
/// MUST be distinct from any credential-signing key. The minted token's
/// `iss`/`aud`/`typ`/alg pin the second verifier's trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenSigningConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Issuer (`iss`) the Notary stamps into its own access tokens.
    #[serde(default)]
    pub issuer: String,
    /// Audiences (`aud`) accepted for Notary-minted access tokens.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Allowed signing algorithms. Only EdDSA is supported.
    #[serde(default = "default_access_token_signing_algorithms")]
    pub allowed_algorithms: Vec<String>,
    /// Header `typ` stamped into Notary access tokens, distinct from the
    /// credential `typ` so a token cannot be replayed as another class.
    #[serde(default = "default_access_token_typ")]
    pub token_typ: String,
    /// `evidence.signing_keys` entry used to sign access tokens. Must be a
    /// dedicated key, never a credential-signing key.
    #[serde(default)]
    pub signing_key_id: String,
    /// Additional publish-only `evidence.signing_keys` entries accepted for
    /// verifying previously minted Notary access tokens and pre-authorized
    /// codes during a governed key rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_key_ids: Vec<String>,
    /// Access-token lifetime in seconds.
    #[serde(default = "default_access_token_ttl_seconds")]
    pub access_token_ttl_seconds: u64,
}

impl Default for AccessTokenSigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            audiences: Vec::new(),
            allowed_algorithms: default_access_token_signing_algorithms(),
            token_typ: default_access_token_typ(),
            signing_key_id: String::new(),
            verification_key_ids: Vec::new(),
            access_token_ttl_seconds: default_access_token_ttl_seconds(),
        }
    }
}

fn default_access_token_signing_algorithms() -> Vec<String> {
    vec![CREDENTIAL_SIGNING_ALG_EDDSA.to_string()]
}

fn default_access_token_typ() -> String {
    "registry-notary-access+jwt".to_string()
}

const fn default_access_token_ttl_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCredentialConfig {
    pub id: String,
    pub fingerprint: CredentialFingerprintRef,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<EvidenceAuthorizationDetails>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOidcAuthConfig {
    pub issuer: String,
    pub jwks_url: String,
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
    #[serde(default = "default_oidc_allowed_token_types")]
    pub allowed_token_types: Vec<String>,
    #[serde(default = "default_oidc_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_oidc_scope_separator")]
    pub scope_separator: String,
    #[serde(default)]
    pub scope_map: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_oidc_principal_claim")]
    pub principal_claim: String,
    #[serde(default = "default_oidc_leeway", with = "humantime_serde")]
    pub leeway: Duration,
    #[serde(default)]
    pub allow_insecure_localhost: bool,
}

fn default_oidc_allowed_algorithms() -> Vec<String> {
    vec![SD_JWT_VC_SIGNING_ALG.to_string()]
}

fn default_oidc_allowed_token_types() -> Vec<String> {
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

fn default_oidc_leeway() -> Duration {
    Duration::from_secs(60)
}

impl EvidenceOidcAuthConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "issuer must not be empty".to_string(),
            });
        }
        if self.jwks_url.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidOidcConfig {
                reason: "jwks_url must not be empty".to_string(),
            });
        }
        validate_jwks_url_transport(&self.jwks_url, self.allow_insecure_localhost)?;
        if let Some(userinfo_endpoint) = self.userinfo_endpoint.as_deref() {
            if userinfo_endpoint.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidOidcConfig {
                    reason: "userinfo_endpoint must not be empty when configured".to_string(),
                });
            }
            validate_jwks_url_transport(userinfo_endpoint, self.allow_insecure_localhost)?;
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

fn validate_jwks_url_transport(
    jwks_url: &str,
    allow_insecure_localhost: bool,
) -> Result<(), EvidenceConfigError> {
    let jwks_url = jwks_url.trim();
    if jwks_url.starts_with("https://")
        || (allow_insecure_localhost && is_insecure_localhost_url(jwks_url))
    {
        return Ok(());
    }
    Err(EvidenceConfigError::InvalidOidcConfig {
        reason:
            "jwks_url must use https unless allow_insecure_localhost permits an http localhost URL"
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

fn is_allowed_remote_tuf_url(url: &str, allow_dev_insecure_fetch_urls: bool) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    allow_dev_insecure_fetch_urls && is_insecure_localhost_url(url)
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
    pub max_size_mb: Option<u64>,
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
            max_size_mb: None,
            max_files: None,
            syslog_socket_path: None,
        }
    }
}

impl EvidenceAuditConfig {
    pub const DEFAULT_MAX_SIZE_MB: u64 = 100;
    pub const DEFAULT_MAX_FILES: u32 = 14;

    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_mb.unwrap_or(Self::DEFAULT_MAX_SIZE_MB) * 1024 * 1024
    }

    pub fn max_files(&self) -> u32 {
        self.max_files.unwrap_or(Self::DEFAULT_MAX_FILES)
    }
}

fn default_audit_sink() -> String {
    "stdout".to_string()
}

/// A durable audit sink retains the evidence trail beyond process stdout.
///
/// `stdout` and `none` are not durable, retained sinks for a production-shaped
/// deployment; `file`, `jsonl`, and `syslog` write to a retained destination.
fn audit_sink_is_durable(config: &EvidenceAuditConfig) -> bool {
    matches!(config.sink.as_str(), "file" | "jsonl" | "syslog")
}

/// A source connection fetches over an insecure URL when its base URL is plain
/// `http://` and no localhost or private-network escape hatch is enabled.
///
/// The escape hatches (`allow_insecure_localhost`, `allow_insecure_private_network`)
/// are reported by their own gate, so this predicate covers only the case of an
/// insecure URL on the strict outbound policy.
fn source_connection_uses_insecure_url(connection: &SourceConnectionConfig) -> bool {
    let base = connection.base_url.trim();
    base.starts_with("http://")
        && !connection.allow_insecure_localhost
        && !connection.allow_insecure_private_network
}

pub fn deprecated_config_fields() -> Vec<DeprecatedConfigField> {
    vec![
        DeprecatedConfigField::renamed("auth.oidc.jwks_uri", "auth.oidc.jwks_url"),
        DeprecatedConfigField::renamed("auth.oidc.leeway_seconds", "auth.oidc.leeway"),
        DeprecatedConfigField::renamed("auth.oidc.allowed_typ", "auth.oidc.allowed_token_types"),
        DeprecatedConfigField::renamed("audit.max_size_bytes", "audit.max_size_mb"),
        DeprecatedConfigField::removed(
            "server.cors.allow_credentials",
            "Notary now always disables credentialed CORS; remove the field",
        ),
    ]
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
    #[error("auth.mode = oidc requires an auth.oidc block")]
    MissingOidcConfig,
    #[error("invalid auth.oidc config: {reason}")]
    InvalidOidcConfig { reason: String },
    #[error("invalid self_attestation config: {reason}")]
    InvalidSelfAttestationConfig { reason: String },
    #[error("invalid oid4vci config: {reason}")]
    InvalidOid4vciConfig { reason: String },
    #[error("invalid auth.access_token_signing config: {reason}")]
    InvalidAccessTokenSigningConfig { reason: String },
    #[error("invalid replay config: {reason}")]
    InvalidReplayConfig { reason: String },
    #[error("invalid credential status config: {reason}")]
    InvalidCredentialStatusConfig { reason: String },
    #[error("invalid cel config: {reason}")]
    InvalidCelConfig { reason: String },
    #[error("invalid federation config: {reason}")]
    InvalidFederationConfig { reason: String },
    #[error("invalid server config: {reason}")]
    InvalidServerConfig { reason: String },
    #[error("invalid config_trust config: {reason}")]
    InvalidConfigTrustConfig { reason: String },
    #[error("invalid deployment config: {reason}")]
    InvalidDeploymentConfig { reason: String },
    #[error("source_connection '{connection}': invalid source_auth config: {reason}")]
    InvalidSourceAuthConfig { connection: String, reason: String },
    #[error("source_connection '{connection}': invalid expected_sidecar config: {reason}")]
    InvalidExpectedSidecarConfig { connection: String, reason: String },
    #[error("claim id must not be empty")]
    InvalidClaim,
    #[error("claim '{claim}' has invalid semantics config: {reason}")]
    InvalidClaimSemantics { claim: String, reason: String },
    #[error("allowed purpose must not be empty")]
    InvalidPurpose,
    #[error("claim '{claim}' binding '{binding}' has invalid matching config: {reason}")]
    InvalidMatchingConfig {
        claim: String,
        binding: String,
        reason: String,
    },
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
    #[error("signing key '{key}' is invalid: {reason}")]
    InvalidSigningKeyConfig { key: String, reason: String },
    #[error("credential profile '{profile}' references unknown signing key '{key}'")]
    UnknownCredentialProfileSigningKey { profile: String, key: String },
    #[error("credential profile '{profile}' references non-active signing key '{key}'")]
    CredentialProfileSigningKeyNotActive { profile: String, key: String },
    #[error(
        "credential profile '{profile}' validity_seconds {validity_seconds} must be between 1 and {max_validity_seconds}"
    )]
    InvalidCredentialProfileValidity {
        profile: String,
        validity_seconds: i64,
        max_validity_seconds: u64,
    },
    #[error("credential profile '{profile}' issuer does not match signing key '{key}': {reason}")]
    CredentialProfileSigningKeyIssuerMismatch {
        profile: String,
        key: String,
        reason: String,
    },
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
    #[error(
        "source_connection '{connection}': bulk_mode = openfn_sidecar_batch \
         requires all bindings to use connector = openfn_sidecar (binding \
         '{binding}' in claim '{claim}' uses a different connector)"
    )]
    BulkModeRequiresOpenFnSidecarConnector {
        connection: String,
        claim: String,
        binding: String,
    },
    #[error(
        "source_connection '{connection}': connector = openfn_sidecar requires retry_on_5xx = false"
    )]
    OpenFnSidecarRequiresNoRetry { connection: String },
    #[error(
        "claim '{claim}', binding '{binding}': connector = openfn_sidecar only supports lookup operator 'eq' (found '{op}')"
    )]
    OpenFnSidecarUnsupportedOperator {
        claim: String,
        binding: String,
        op: String,
    },
    #[error(
        "source_connection '{connection}': bulk_mode = {bulk_mode} cannot be used with \
         query_fields (binding '{binding}' in claim '{claim}'); bulk reads currently support \
         lookup only"
    )]
    QueryFieldsIncompatibleWithBulkMode {
        connection: String,
        claim: String,
        binding: String,
        bulk_mode: String,
    },
    #[error(
        "claim '{claim}' binding '{binding}' uses query_fields with DCI query_type = idtype-value \
         on source_connection '{connection}'; use lookup for idtype-value or set DCI \
         query_type to expression or predicate"
    )]
    QueryFieldsIncompatibleWithDciIdTypeValue {
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
    #[serde(default = "default_max_credential_validity_seconds")]
    pub max_credential_validity_seconds: u64,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub claims: Vec<ClaimDefinition>,
    #[serde(default)]
    pub signing_keys: BTreeMap<String, SigningKeyConfig>,
    #[serde(default)]
    pub credential_profiles: BTreeMap<String, CredentialProfileConfig>,
    #[serde(default)]
    pub ecosystem_bindings: BTreeMap<String, EvidenceEcosystemBindingConfig>,
    #[serde(default)]
    pub source_connections: BTreeMap<String, SourceConnectionConfig>,
    /// Per-request fan-out caps. Setting both `subjects=1` and `bindings=1`
    /// reproduces today's strictly-sequential behavior (Stage 1 kill switch).
    #[serde(default)]
    pub concurrency: ConcurrencyConfig,
}

const fn default_max_credential_validity_seconds() -> u64 {
    600
}

impl EvidenceConfig {
    fn validate_signing_keys(&self) -> Result<(), EvidenceConfigError> {
        let mut published_kids = HashSet::new();
        for (key_id, key) in &self.signing_keys {
            validate_signing_key_id(key_id)?;
            key.validate(key_id)?;
            if key.status.may_publish() && !published_kids.insert(key.kid.as_str()) {
                return Err(EvidenceConfigError::InvalidSigningKeyConfig {
                    key: key_id.clone(),
                    reason: format!("duplicate published kid '{}'", key.kid),
                });
            }
        }
        Ok(())
    }

    /// Validate resolved signing-capable key material after runtime providers
    /// have loaded their public JWKs. Static config can compare ids and kids,
    /// but only the resolved JWKs reveal whether different active entries reuse
    /// the same key material under different ids or kids.
    ///
    /// The reuse comparison is confined to the separated EdDSA signing roles
    /// issue #173 names: the access-token signing key and every credential
    /// profile signing key, plus the federation signing key (the documented
    /// separation boundary in `validate_signing_key_alg_usage` treats all three
    /// as distinct EdDSA roles). `reuse_scoped_key_ids` carries exactly those
    /// role keys. The eSignet pre-authorized-code RP client key is a separate,
    /// relaxed role that is deliberately allowed to share material with the
    /// credential issuer key, so callers must leave it out of
    /// `reuse_scoped_key_ids`; resolved JWKs for keys outside the set are not
    /// compared.
    pub fn validate_resolved_signing_key_material<'a, I>(
        &self,
        resolved_public_jwks: I,
        reuse_scoped_key_ids: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError>
    where
        I: IntoIterator<Item = (&'a str, &'a PublicJwk)>,
    {
        let mut thumbprints_by_key_id = BTreeMap::new();
        for (key_id, public_jwk) in resolved_public_jwks {
            let Some(key) = self.signing_keys.get(key_id) else {
                return invalid_signing_key(
                    key_id,
                    "resolved public JWK does not match a configured signing key",
                );
            };
            if !key.status.may_sign() {
                continue;
            }
            // Only the separated signing roles (#173) are compared against one
            // another; keys outside that set (notably the eSignet RP client
            // key) are allowed to reuse credential material by design.
            if !reuse_scoped_key_ids.contains(key_id) {
                continue;
            }
            let thumbprint =
                public_jwk
                    .jkt()
                    .map_err(|_| EvidenceConfigError::InvalidSigningKeyConfig {
                        key: key_id.to_string(),
                        reason: "resolved public JWK could not be thumbprinted".to_string(),
                    })?;
            if let Some(previous_key_id) =
                thumbprints_by_key_id.insert(thumbprint, key_id.to_string())
            {
                return invalid_signing_key(
                    key_id,
                    format!("reuses public key material with signing key '{previous_key_id}'"),
                );
            }
        }
        Ok(())
    }
}

const SUPPORTED_ECOSYSTEM_BINDING_PROFILE: &str = "registry-notary/source-policy/v1";

fn validate_source_matching_config(
    claim: &str,
    binding: &str,
    matching: &SourceMatchingConfig,
    ecosystem_bindings: &BTreeMap<String, EvidenceEcosystemBindingConfig>,
) -> Result<(), EvidenceConfigError> {
    if matching
        .target_type
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "target_type must not be empty");
    }
    if matching
        .requester_type
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "requester_type must not be empty");
    }
    if matching
        .policy_id
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "policy_id must not be empty");
    }
    if matching
        .method
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "method must not be empty");
    }
    if matching
        .allowed_purposes
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "allowed_purposes must not contain blanks");
    }
    if matching
        .allowed_assurance
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "allowed_assurance must not contain blanks",
        );
    }
    if matching
        .minimum_assurance
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "minimum_assurance must not be empty");
    }
    if matching
        .permitted_jurisdictions
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "permitted_jurisdictions must not contain blanks",
        );
    }
    if matching.max_source_age_seconds == Some(0) {
        return invalid_matching_config(
            claim,
            binding,
            "max_source_age_seconds must be greater than zero",
        );
    }
    if matching.max_source_age_seconds.is_some()
        && matching
            .source_observed_at_field
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "source_observed_at_field is required when max_source_age_seconds is set",
        );
    }
    if matching
        .source_observed_at_field
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "source_observed_at_field must not be empty",
        );
    }
    if matching
        .redaction_fields
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "redaction_fields must not contain blanks");
    }
    if let Some(selector) = &matching.ecosystem_binding {
        validate_ecosystem_binding_selector(claim, binding, selector, ecosystem_bindings)?;
    }
    if matching
        .allowed_relationships
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "allowed_relationships must not contain blanks",
        );
    }
    if matching
        .relationship_purpose_scopes
        .iter()
        .any(|(relationship, purposes)| {
            relationship.trim().is_empty()
                || purposes.is_empty()
                || purposes.iter().any(|purpose| purpose.trim().is_empty())
        })
    {
        return invalid_matching_config(
            claim,
            binding,
            "relationship_purpose_scopes must contain non-empty relationships and purposes",
        );
    }
    if matching
        .relationship_purpose_scopes
        .keys()
        .any(|relationship| !matching.allowed_relationships.contains(relationship))
    {
        return invalid_matching_config(
            claim,
            binding,
            "relationship_purpose_scopes entries must also appear in allowed_relationships",
        );
    }
    if matching
        .sufficient_target_inputs
        .iter()
        .any(|group| group.is_empty() || group.iter().any(|path| path.trim().is_empty()))
    {
        return invalid_matching_config(
            claim,
            binding,
            "sufficient_target_inputs groups must be non-empty and contain no blank paths",
        );
    }
    if matching
        .allowed_target_inputs
        .iter()
        .chain(matching.allowed_requester_inputs.iter())
        .any(|path| path.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "allowed input path lists must not contain blanks",
        );
    }
    Ok(())
}

fn validate_ecosystem_binding_selector(
    claim: &str,
    binding: &str,
    selector: &EcosystemBindingSelectorConfig,
    ecosystem_bindings: &BTreeMap<String, EvidenceEcosystemBindingConfig>,
) -> Result<(), EvidenceConfigError> {
    if selector
        .id
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(claim, binding, "ecosystem_binding.id must not be empty");
    }
    if selector
        .profile
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.profile must not be empty",
        );
    }
    if selector
        .policy_id
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.policy_id must not be empty",
        );
    }
    if selector
        .policy_hash
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.policy_hash must not be empty",
        );
    }
    if selector
        .unsupported_odrl_terms
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.unsupported_odrl_terms must not contain blanks",
        );
    }

    let has_local_policy = selector.policy_id.is_some() || selector.policy_hash.is_some();
    if has_local_policy {
        let (Some(policy_id), Some(policy_hash)) = (&selector.policy_id, &selector.policy_hash)
        else {
            return invalid_matching_config(
                claim,
                binding,
                "ecosystem_binding policy_id and policy_hash must be configured together",
            );
        };
        validate_supported_ecosystem_profile(claim, binding, selector.profile.as_deref())?;
        validate_policy_hash(claim, binding, policy_hash)?;
        if policy_id.trim().is_empty() {
            return invalid_matching_config(
                claim,
                binding,
                "ecosystem_binding.policy_id must not be empty",
            );
        }
        return Ok(());
    }

    let selected = select_ecosystem_binding(selector, ecosystem_bindings).map_err(|reason| {
        EvidenceConfigError::InvalidMatchingConfig {
            claim: claim.to_string(),
            binding: binding.to_string(),
            reason,
        }
    })?;
    validate_ecosystem_binding_metadata(claim, binding, selected)
}

fn select_ecosystem_binding<'a>(
    selector: &EcosystemBindingSelectorConfig,
    ecosystem_bindings: &'a BTreeMap<String, EvidenceEcosystemBindingConfig>,
) -> Result<&'a EvidenceEcosystemBindingConfig, String> {
    if let Some(id) = selector.id.as_deref() {
        let Some(candidate) = ecosystem_bindings.get(id) else {
            return Err(format!("ecosystem_binding id '{id}' was not found"));
        };
        if let Some(profile) = selector.profile.as_deref() {
            if candidate.profile.as_deref() != Some(profile) {
                return Err(format!(
                    "ecosystem_binding id '{id}' does not use selected profile '{profile}'"
                ));
            }
        }
        return Ok(candidate);
    }

    let Some(profile) = selector.profile.as_deref() else {
        return Err("ecosystem_binding must select by id, profile, or local policy".to_string());
    };
    let mut matches = ecosystem_bindings
        .values()
        .filter(|candidate| candidate.profile.as_deref() == Some(profile));
    let Some(selected) = matches.next() else {
        return Err(format!(
            "ecosystem_binding profile '{profile}' was not found"
        ));
    };
    if matches.next().is_some() {
        return Err(format!(
            "ecosystem_binding profile '{profile}' matched multiple bindings; select by id"
        ));
    }
    Ok(selected)
}

fn validate_ecosystem_binding_metadata(
    claim: &str,
    binding: &str,
    metadata: &EvidenceEcosystemBindingConfig,
) -> Result<(), EvidenceConfigError> {
    validate_supported_ecosystem_profile(claim, binding, metadata.profile.as_deref())?;
    if metadata.policy_id.trim().is_empty() {
        return invalid_matching_config(
            claim,
            binding,
            "selected ecosystem binding policy_id must not be empty",
        );
    }
    validate_policy_hash(claim, binding, &metadata.policy_hash)?;
    if metadata
        .unsupported_odrl_terms
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "selected ecosystem binding unsupported_odrl_terms must not contain blanks",
        );
    }
    Ok(())
}

fn validate_supported_ecosystem_profile(
    claim: &str,
    binding: &str,
    profile: Option<&str>,
) -> Result<(), EvidenceConfigError> {
    match profile {
        None | Some(SUPPORTED_ECOSYSTEM_BINDING_PROFILE) => Ok(()),
        Some(profile) => invalid_matching_config(
            claim,
            binding,
            &format!("unsupported ecosystem_binding profile '{profile}'"),
        ),
    }
}

fn validate_policy_hash(
    claim: &str,
    binding: &str,
    policy_hash: &str,
) -> Result<(), EvidenceConfigError> {
    let Some(hex) = policy_hash.strip_prefix("sha256:") else {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.policy_hash must use sha256:<64 lowercase hex>",
        );
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid_matching_config(
            claim,
            binding,
            "ecosystem_binding.policy_hash must use sha256:<64 lowercase hex>",
        );
    }
    Ok(())
}

fn invalid_matching_config<T>(
    claim: &str,
    binding: &str,
    reason: &str,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidMatchingConfig {
        claim: claim.to_string(),
        binding: binding.to_string(),
        reason: reason.to_string(),
    })
}

fn validate_signing_key_id(key_id: &str) -> Result<(), EvidenceConfigError> {
    if key_id.trim().is_empty() {
        return Err(EvidenceConfigError::InvalidSigningKeyConfig {
            key: key_id.to_string(),
            reason: "signing key id must not be empty".to_string(),
        });
    }
    Ok(())
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
    "/v1/claims".to_string()
}

fn default_formats_url() -> String {
    "/v1/formats".to_string()
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<ClaimSemanticConfig>,
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
pub struct ClaimSemanticConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concept: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_mapping: Option<String>,
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
    pub query_fields: Vec<SourceQueryFieldConfig>,
    #[serde(default)]
    pub fields: BTreeMap<String, SourceFieldConfig>,
    #[serde(default)]
    pub matching: SourceMatchingConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEcosystemBindingConfig {
    #[serde(default)]
    pub profile: Option<String>,
    pub policy_id: String,
    pub policy_hash: String,
    #[serde(default)]
    pub unsupported_odrl_terms: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryFieldConfig {
    pub input: String,
    pub field: String,
    #[serde(default = "default_lookup_op")]
    pub op: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMatchingConfig {
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub requester_type: Option<String>,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub allowed_assurance: Vec<String>,
    #[serde(default)]
    pub minimum_assurance: Option<String>,
    #[serde(default)]
    pub permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    pub max_source_age_seconds: Option<u64>,
    #[serde(default)]
    pub source_observed_at_field: Option<String>,
    #[serde(default)]
    pub require_legal_basis: bool,
    #[serde(default)]
    pub require_consent: bool,
    #[serde(default)]
    pub redaction_fields: Vec<String>,
    #[serde(default)]
    pub ecosystem_binding: Option<EcosystemBindingSelectorConfig>,
    #[serde(default)]
    pub allowed_relationships: Vec<String>,
    /// Relationship-specific purpose allow-lists. Empty means relationships
    /// accepted by `allowed_relationships` are not purpose-scoped.
    #[serde(default)]
    pub relationship_purpose_scopes: BTreeMap<String, Vec<String>>,
    /// OR-of-AND groups of request paths. Example:
    /// `[["target.attributes.given_name", "target.attributes.family_name"]]`.
    #[serde(default)]
    pub sufficient_target_inputs: Vec<Vec<String>>,
    /// Maximum target input paths accepted by this binding. Empty means
    /// unrestricted for backwards-compatible identifier-only configs.
    #[serde(default)]
    pub allowed_target_inputs: Vec<String>,
    /// Maximum requester input paths accepted by this binding. Empty means
    /// unrestricted.
    #[serde(default)]
    pub allowed_requester_inputs: Vec<String>,
    #[serde(default = "default_collapse_matching_errors")]
    pub collapse_matching_errors: bool,
    #[serde(default)]
    pub require_requester_reauthentication: bool,
    #[serde(default)]
    pub confidence: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemBindingSelectorConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub pack_id: Option<String>,
    #[serde(default)]
    pub pack_version: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub unsupported_odrl_terms: Vec<String>,
}

impl Default for SourceMatchingConfig {
    fn default() -> Self {
        Self {
            policy_id: None,
            method: None,
            target_type: None,
            requester_type: None,
            allowed_purposes: Vec::new(),
            allowed_assurance: Vec::new(),
            minimum_assurance: None,
            permitted_jurisdictions: Vec::new(),
            max_source_age_seconds: None,
            source_observed_at_field: None,
            require_legal_basis: false,
            require_consent: false,
            redaction_fields: Vec::new(),
            ecosystem_binding: None,
            allowed_relationships: Vec::new(),
            relationship_purpose_scopes: BTreeMap::new(),
            sufficient_target_inputs: Vec::new(),
            allowed_target_inputs: Vec::new(),
            allowed_requester_inputs: Vec::new(),
            collapse_matching_errors: default_collapse_matching_errors(),
            require_requester_reauthentication: false,
            confidence: None,
        }
    }
}

const fn default_collapse_matching_errors() -> bool {
    true
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
    #[serde(default)]
    pub token_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sidecar: Option<ExpectedSidecarConfig>,
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

impl SourceConnectionConfig {
    pub fn validate_auth(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        let has_static_token = !self.token_env.trim().is_empty();
        if has_static_token && self.source_auth.is_some() {
            return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                connection: connection_id.to_string(),
                reason: "token_env and source_auth are mutually exclusive".to_string(),
            });
        }
        if !has_static_token && self.source_auth.is_none() {
            return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                connection: connection_id.to_string(),
                reason: "either token_env or source_auth must be configured".to_string(),
            });
        }
        if let Some(source_auth) = &self.source_auth {
            source_auth.validate(connection_id)?;
        }
        Ok(())
    }

    pub fn effective_dci(&self) -> Result<DciSourceConnectionConfig, EvidenceConfigError> {
        Ok(self.dci.clone())
    }

    pub fn validate_expected_sidecar(
        &self,
        connection_id: &str,
    ) -> Result<(), EvidenceConfigError> {
        let Some(expected) = &self.expected_sidecar else {
            return Ok(());
        };
        for (field, value) in [
            ("product", expected.product.as_str()),
            ("instance_id", expected.instance_id.as_str()),
            ("environment", expected.environment.as_str()),
            ("stream_id", expected.stream_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidExpectedSidecarConfig {
                    connection: connection_id.to_string(),
                    reason: format!("{field} must not be empty"),
                });
            }
        }
        validate_sha256_uri(&expected.config_hash).map_err(|reason| {
            EvidenceConfigError::InvalidExpectedSidecarConfig {
                connection: connection_id.to_string(),
                reason: format!("config_hash {reason}"),
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSidecarConfig {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
    pub config_hash: String,
    #[serde(default)]
    pub require_expression_hashes_verified: bool,
    #[serde(default)]
    pub require_runtime_verified: bool,
    #[serde(default)]
    pub require_smoke_verified: bool,
    #[serde(default = "default_expected_sidecar_assurance_ttl_ms")]
    pub assurance_ttl_ms: u64,
}

const fn default_expected_sidecar_assurance_ttl_ms() -> u64 {
    30_000
}

fn validate_sha256_uri(value: &str) -> Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("must start with sha256:");
    };
    if hex.len() != 64 {
        return Err("must contain 64 lowercase hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("must contain only lowercase hex characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceAuthConfig {
    Oauth2ClientCredentials(Oauth2ClientCredentialsSourceAuthConfig),
}

impl SourceAuthConfig {
    fn validate(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        match self {
            SourceAuthConfig::Oauth2ClientCredentials(config) => config.validate(connection_id),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Oauth2ClientCredentialsSourceAuthConfig {
    pub token_url: String,
    pub client_id_env: String,
    pub client_secret_env: String,
    #[serde(default = "default_oauth_request_format")]
    pub request_format: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_oauth_refresh_skew_seconds")]
    pub refresh_skew_seconds: u64,
}

impl Oauth2ClientCredentialsSourceAuthConfig {
    fn validate(&self, connection_id: &str) -> Result<(), EvidenceConfigError> {
        if self.token_url.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "token_url must not be empty",
            ));
        }
        if self.client_id_env.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "client_id_env must not be empty",
            ));
        }
        if self.client_secret_env.trim().is_empty() {
            return Err(invalid_source_auth(
                connection_id,
                "client_secret_env must not be empty",
            ));
        }
        if !matches!(self.request_format.as_str(), "json" | "form") {
            return Err(invalid_source_auth(
                connection_id,
                "request_format must be json or form",
            ));
        }
        Ok(())
    }
}

fn default_oauth_request_format() -> String {
    "form".to_string()
}

const fn default_oauth_refresh_skew_seconds() -> u64 {
    60
}

fn invalid_source_auth(connection: &str, reason: &str) -> EvidenceConfigError {
    EvidenceConfigError::InvalidSourceAuthConfig {
        connection: connection.to_string(),
        reason: reason.to_string(),
    }
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
    #[serde(rename = "openfn_sidecar_batch")]
    OpenFnSidecarBatch,
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
    pub registry_event_type: Option<String>,
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
            registry_event_type: None,
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
    #[serde(rename = "openfn_sidecar")]
    OpenFnSidecar,
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

fn validate_claim_semantics(claim: &ClaimDefinition) -> Result<(), EvidenceConfigError> {
    let Some(semantics) = &claim.semantics else {
        return Ok(());
    };
    let mut has_term = false;
    for (field, value) in [
        ("concept", semantics.concept.as_deref()),
        ("property", semantics.property.as_deref()),
        ("vocabulary", semantics.vocabulary.as_deref()),
        ("predicate", semantics.predicate.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        has_term = true;
        validate_semantic_reference(&claim.id, field, value)?;
    }
    for value in &semantics.derived_from {
        has_term = true;
        validate_semantic_reference(&claim.id, "derived_from", value)?;
    }
    if let Some(value_mapping) = semantics.value_mapping.as_deref() {
        if value_mapping.trim().is_empty() {
            return invalid_claim_semantics(&claim.id, "value_mapping must not be empty");
        }
    }
    if !has_term {
        return invalid_claim_semantics(
            &claim.id,
            "at least one of concept, property, vocabulary, predicate, or derived_from must be set",
        );
    }
    if semantics.property.is_some() && semantics.predicate.is_some() {
        return invalid_claim_semantics(
            &claim.id,
            "property and predicate are mutually exclusive; use derived_from for predicate inputs",
        );
    }
    if let RuleConfig::Extract { source, field } = &claim.rule {
        validate_extract_semantics(claim, semantics, source, field)?;
    }
    Ok(())
}

fn validate_extract_semantics(
    claim: &ClaimDefinition,
    semantics: &ClaimSemanticConfig,
    source: &str,
    field: &str,
) -> Result<(), EvidenceConfigError> {
    let Some(property) = semantics.property.as_deref() else {
        return Ok(());
    };
    let Some(binding) = claim.source_bindings.get(source) else {
        return Ok(());
    };
    let Some(source_field) = binding.fields.get(field) else {
        return Ok(());
    };
    let Some(field_term) = source_field.semantic_term.as_deref().map(str::trim) else {
        return Ok(());
    };
    let property = property.trim();
    if field_term != property {
        return invalid_claim_semantics(
            &claim.id,
            format!(
                "property '{property}' conflicts with source field '{source}.{field}' semantic_term '{field_term}'"
            ),
        );
    }
    Ok(())
}

fn validate_semantic_reference(
    claim_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return invalid_claim_semantics(claim_id, format!("{field} must not be empty"));
    }
    if value.starts_with("https://") || value.starts_with("http://") || value.starts_with("urn:") {
        return Ok(());
    }
    invalid_claim_semantics(
        claim_id,
        format!("{field} must be an absolute http(s) URI or urn"),
    )
}

fn invalid_claim_semantics<T>(
    claim: &str,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidClaimSemantics {
        claim: claim.to_string(),
        reason: reason.into(),
    })
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
    pub signing_key: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    pub provider: SigningKeyProviderConfig,
    pub alg: String,
    pub kid: String,
    pub status: SigningKeyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_until_unix_seconds: Option<u64>,
    #[serde(default)]
    pub private_jwk_env: String,
    #[serde(default)]
    pub public_jwk_env: String,
    #[serde(default)]
    pub module_path: String,
    #[serde(default)]
    pub token_label: String,
    #[serde(default)]
    pub pin_env: String,
    #[serde(default)]
    pub key_label: String,
    #[serde(default)]
    pub key_id_hex: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub password_env: String,
}

impl SigningKeyConfig {
    fn validate(&self, key_id: &str) -> Result<(), EvidenceConfigError> {
        validate_signing_key_non_empty(key_id, "alg", &self.alg)?;
        if self.alg != CREDENTIAL_SIGNING_ALG_EDDSA
            && self.alg != CREDENTIAL_SIGNING_ALG_ES256
            && self.alg != CLIENT_ASSERTION_SIGNING_ALG_RS256
        {
            return invalid_signing_key(
                key_id,
                format!(
                    "alg must be {CREDENTIAL_SIGNING_ALG_EDDSA}, {CREDENTIAL_SIGNING_ALG_ES256}, or {CLIENT_ASSERTION_SIGNING_ALG_RS256}"
                ),
            );
        }
        validate_signing_key_non_empty(key_id, "kid", &self.kid)?;
        if self.publish_until_unix_seconds.is_some()
            && !matches!(self.status, SigningKeyStatus::PublishOnly)
        {
            return invalid_signing_key(
                key_id,
                "publish_until_unix_seconds is valid only for publish_only signing keys",
            );
        }
        match self.provider {
            SigningKeyProviderConfig::LocalJwkEnv => {
                if self.status.may_sign() {
                    validate_signing_key_non_empty(
                        key_id,
                        "private_jwk_env",
                        &self.private_jwk_env,
                    )?;
                }
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    validate_signing_key_non_empty(key_id, "public_jwk_env", &self.public_jwk_env)?;
                    validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                }
                validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                validate_signing_key_absent(key_id, "path", &self.path)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::Pkcs11 => {
                if self.alg != CREDENTIAL_SIGNING_ALG_EDDSA {
                    return invalid_signing_key(key_id, "pkcs11 provider supports only EdDSA");
                }
                if self.status.may_publish() {
                    validate_signing_key_non_empty(key_id, "public_jwk_env", &self.public_jwk_env)?;
                }
                if self.status.may_sign() {
                    validate_signing_key_non_empty(key_id, "module_path", &self.module_path)?;
                    if !std::path::Path::new(&self.module_path).is_absolute() {
                        return invalid_signing_key(key_id, "module_path must be absolute");
                    }
                    validate_signing_key_non_empty(key_id, "token_label", &self.token_label)?;
                    validate_signing_key_non_empty(key_id, "pin_env", &self.pin_env)?;
                    validate_signing_key_non_empty(key_id, "key_label", &self.key_label)?;
                    validate_signing_key_non_empty(key_id, "key_id_hex", &self.key_id_hex)?;
                    if !self.key_id_hex.len().is_multiple_of(2)
                        || !self.key_id_hex.chars().all(|ch| ch.is_ascii_hexdigit())
                    {
                        return invalid_signing_key(key_id, "key_id_hex must be even-length hex");
                    }
                }
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                    validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                    validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                    validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                    validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                }
                validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                validate_signing_key_absent(key_id, "path", &self.path)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::FileWatch => {
                if matches!(self.status, SigningKeyStatus::PublishOnly) {
                    return invalid_signing_key(
                        key_id,
                        "file_watch provider supports only active or disabled signing keys",
                    );
                }
                if self.status.may_sign() {
                    validate_signing_key_non_empty(key_id, "path", &self.path)?;
                }
                validate_signing_key_absent(key_id, "private_jwk_env", &self.private_jwk_env)?;
                validate_signing_key_absent(key_id, "public_jwk_env", &self.public_jwk_env)?;
                validate_signing_key_absent(key_id, "module_path", &self.module_path)?;
                validate_signing_key_absent(key_id, "token_label", &self.token_label)?;
                validate_signing_key_absent(key_id, "pin_env", &self.pin_env)?;
                validate_signing_key_absent(key_id, "key_label", &self.key_label)?;
                validate_signing_key_absent(key_id, "key_id_hex", &self.key_id_hex)?;
                validate_signing_key_absent(key_id, "password_env", &self.password_env)?;
            }
            SigningKeyProviderConfig::LocalPkcs12File => {
                invalid_signing_key(
                    key_id,
                    "local_pkcs12_file provider is intentionally not implemented yet",
                )?;
            }
            _ => {
                invalid_signing_key(key_id, "signing key provider is unsupported by this Notary")?;
            }
        }
        Ok(())
    }

    pub fn may_publish_at(&self, now_unix_seconds: u64) -> bool {
        if !self.status.may_publish() {
            return false;
        }
        self.publish_until_unix_seconds
            .is_none_or(|publish_until| now_unix_seconds <= publish_until)
    }
}

fn validate_signing_key_non_empty(
    key_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if value.trim().is_empty() {
        return invalid_signing_key(key_id, format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_signing_key_absent(
    key_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    if !value.trim().is_empty() {
        return invalid_signing_key(
            key_id,
            format!("{field} is not valid for this signing key provider"),
        );
    }
    Ok(())
}

fn invalid_signing_key<T>(
    key_id: &str,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidSigningKeyConfig {
        key: key_id.to_string(),
        reason: reason.into(),
    })
}

fn validate_profile_signing_key_issuer_binding(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    key: &SigningKeyConfig,
) -> Result<(), EvidenceConfigError> {
    if let Some(kid_did) = key
        .kid
        .split('#')
        .next()
        .filter(|did| did.starts_with("did:web:"))
    {
        if profile.issuer.starts_with("did:web:") && profile.issuer != kid_did {
            return Err(
                EvidenceConfigError::CredentialProfileSigningKeyIssuerMismatch {
                    profile: profile_id.to_string(),
                    key: profile.signing_key.clone(),
                    reason: "did:web issuer must match signing key kid DID".to_string(),
                },
            );
        }
        if profile.issuer.starts_with("https://") {
            validate_did_web_https_issuer_binding(kid_did, &profile.issuer).map_err(|error| {
                EvidenceConfigError::CredentialProfileSigningKeyIssuerMismatch {
                    profile: profile_id.to_string(),
                    key: profile.signing_key.clone(),
                    reason: error.to_string(),
                }
            })?;
        }
    }
    Ok(())
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
    use std::collections::BTreeSet;

    use registry_platform_config::{TrustRootRole, TrustRootSigner};

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
        commitment: sha256:56c3f8e9f68c7acd05bcf1e5d619cb1c4e9f91efafb471a3c60675c983fe7ed6
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
        assert!(!input.openfn_source_without_expected_sidecar);
        // Local YAML config without config_trust is unsigned.
        assert!(input.config_unsigned);
        // Admin listener is disabled by default, so no shared exposure.
        assert!(!input.admin_shared_exposure);
        // OpenAPI requires auth by default.
        assert!(!input.openapi_public);
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
    fn gate_input_reports_openfn_source_without_expected_sidecar() {
        let mut config = minimal_config();
        // Insert a source connection with bulk_mode = openfn_sidecar_batch and
        // no expected_sidecar. We call gate_input() directly without validate()
        // because this projection test only checks the GateInput field.
        let mut conn: SourceConnectionConfig = serde_norway::from_str(
            r#"
base_url: https://openfn.example
token_env: SRC_TOKEN
"#,
        )
        .expect("source connection parses");
        conn.bulk_mode = BulkMode::OpenFnSidecarBatch;
        // expected_sidecar remains None by default.
        config
            .evidence
            .source_connections
            .insert("openfn-src".to_string(), conn);
        assert!(config.gate_input().openfn_source_without_expected_sidecar);
    }

    #[test]
    fn gate_input_clears_openfn_source_with_expected_sidecar() {
        let mut config = minimal_config();
        let mut conn: SourceConnectionConfig = serde_norway::from_str(
            r#"
base_url: https://openfn.example
token_env: SRC_TOKEN
expected_sidecar:
  product: openfn-notary-bridge
  instance_id: bridge-1
  environment: lab
  stream_id: stream-a
  config_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
        )
        .expect("source connection with expected_sidecar parses");
        conn.bulk_mode = BulkMode::OpenFnSidecarBatch;
        config
            .evidence
            .source_connections
            .insert("openfn-src".to_string(), conn);
        assert!(!config.gate_input().openfn_source_without_expected_sidecar);
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
    fn gate_input_clears_config_unsigned_when_trust_configured() {
        let mut config = minimal_config();
        // Setting config_trust to Some makes config_unsigned false. We set the
        // admin listener to dedicated because validate() requires it; this test
        // only calls gate_input(), which is pure projection and does not validate.
        config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });
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

    #[test]
    fn config_trust_is_optional_but_requires_explicit_antirollback_path() {
        let mut config = minimal_config();
        assert!(config.config_trust.is_none());
        config.validate().expect("simple local config validates");
        use_dedicated_admin_listener(&mut config);

        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(""),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });
        let error = config
            .validate()
            .expect_err("empty governed-state path must fail validation");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));

        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(""),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });
        let error = config
            .validate()
            .expect_err("empty local-approval path must fail validation");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));

        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });
        config
            .validate()
            .expect("explicit governed-state paths validate");
    }

    #[test]
    fn config_trust_rejects_zero_required_approver_count() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::from([("emergency.break_glass".to_string(), 0)]),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });

        let error = config
            .validate()
            .expect_err("zero required approver count must fail validation");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));
    }

    #[test]
    fn config_trust_accepts_shared_trust_roots_and_validates_them() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: vec![RegistryTrustRoot {
                root_id: "ops-root".to_string(),
                production: false,
                tuf_root_sha256:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                valid_from_unix_seconds: None,
                valid_until_unix_seconds: None,
                high_risk_change_classes: BTreeSet::new(),
                signers: BTreeMap::from([(
                    "kid-a".to_string(),
                    TrustRootSigner {
                        kid: "kid-a".to_string(),
                        enabled: true,
                    },
                )]),
                roles: vec![TrustRootRole {
                    name: "config-admin".to_string(),
                    threshold: 1,
                    signer_kids: vec!["kid-a".to_string()],
                    allowed_change_classes: BTreeSet::from(["public_metadata".to_string()]),
                }],
            }],
            remote_tuf_repositories: Vec::new(),
        });
        config
            .validate()
            .expect("shared trust root config validates");

        let trust = config.config_trust.as_mut().expect("trust config exists");
        trust.accepted_roots[0].roles[0].threshold = 2;
        let error = config
            .validate()
            .expect_err("invalid shared trust root must fail validation");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));
    }

    #[test]
    fn config_trust_remote_tuf_repositories_accepts_https_urls() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: vec![RemoteTufRepositoryConfig {
                root_path: PathBuf::from("/etc/registry-notary/tuf/root.json"),
                metadata_base_url: "https://config.example.test/metadata".to_string(),
                targets_base_url: "https://config.example.test/targets".to_string(),
                datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
                allow_dev_insecure_fetch_urls: false,
            }],
        });
        config
            .validate()
            .expect("https remote_tuf_repositories entry validates");
    }

    #[test]
    fn config_trust_remote_tuf_repositories_rejects_http_without_dev_flag() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: vec![RemoteTufRepositoryConfig {
                root_path: PathBuf::from("/etc/registry-notary/tuf/root.json"),
                metadata_base_url: "http://config.example.test/metadata".to_string(),
                targets_base_url: "https://config.example.test/targets".to_string(),
                datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
                allow_dev_insecure_fetch_urls: false,
            }],
        });
        let error = config
            .validate()
            .expect_err("http without allow_dev_insecure_fetch_urls must fail");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));
    }

    #[test]
    fn config_trust_remote_tuf_repositories_allows_http_loopback_in_dev() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: vec![RemoteTufRepositoryConfig {
                root_path: PathBuf::from("/etc/registry-notary/tuf/root.json"),
                metadata_base_url: "http://localhost:9000/metadata".to_string(),
                targets_base_url: "http://127.0.0.1:9000/targets".to_string(),
                datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
                allow_dev_insecure_fetch_urls: true,
            }],
        });
        config
            .validate()
            .expect("http loopback with allow_dev_insecure_fetch_urls validates");
    }

    #[test]
    fn config_trust_remote_tuf_repositories_rejects_empty_paths() {
        let mut config = minimal_config();
        use_dedicated_admin_listener(&mut config);
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: vec![RemoteTufRepositoryConfig {
                root_path: PathBuf::from(""),
                metadata_base_url: "https://config.example.test/metadata".to_string(),
                targets_base_url: "https://config.example.test/targets".to_string(),
                datastore_dir: PathBuf::from("/var/lib/registry-notary/tuf"),
                allow_dev_insecure_fetch_urls: false,
            }],
        });
        let error = config
            .validate()
            .expect_err("empty root_path must fail validation");
        assert!(matches!(
            error,
            EvidenceConfigError::InvalidConfigTrustConfig { .. }
        ));
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
        commitment: sha256:56c3f8e9f68c7acd05bcf1e5d619cb1c4e9f91efafb471a3c60675c983fe7ed6
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
        commitment: sha256:56c3f8e9f68c7acd05bcf1e5d619cb1c4e9f91efafb471a3c60675c983fe7ed6
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
                policy_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
                policy_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        config.config_trust = Some(ConfigTrustConfig {
            antirollback_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-antirollback.json",
            ),
            local_approval_state_path: PathBuf::from(
                "/var/lib/registry-notary/config-local-approvals.json",
            ),
            break_glass_rate_limit: default_break_glass_rate_limit(),
            required_approver_count: BTreeMap::new(),
            accepted_roots: Vec::new(),
            remote_tuf_repositories: Vec::new(),
        });

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
                commitment:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
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

    fn openfn_sidecar_binding(connection: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::OpenFnSidecar,
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
    fn openfn_sidecar_connector_and_batch_mode_parse_and_validate_with_query_fields() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut binding = openfn_sidecar_binding("openfn_crvs");
        add_query_fields(&mut binding);
        let mut claim = minimal_claim("date-of-birth");
        claim.source_bindings.insert("crvs".to_string(), binding);
        config.evidence.claims = vec![claim];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn openfn_sidecar_yaml_names_parse_and_validate() {
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
        commitment: sha256:99292e759add3e4112a464b31437bebf77accdf88e2ca09d6a538f909ea6d694
      scopes: [civil_registry:evidence_verification]
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    openfn_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: OPENFN_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: openfn_sidecar_batch
      expected_sidecar:
        product: registry-notary-source-adapter-sidecar
        instance_id: demo
        environment: staging
        stream_id: openfn-sidecar-runtime
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
          connector: openfn_sidecar
          connection: openfn_crvs
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
            serde_norway::from_str(raw).expect("OpenFn YAML config deserializes");

        assert_eq!(
            config.evidence.source_connections["openfn_crvs"].bulk_mode,
            BulkMode::OpenFnSidecarBatch
        );
        let expected_sidecar = config.evidence.source_connections["openfn_crvs"]
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
            SourceConnectorKind::OpenFnSidecar
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn openfn_sidecar_expected_sidecar_rejects_invalid_config_hash() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: Some(ExpectedSidecarConfig {
                    product: "registry-notary-source-adapter-sidecar".to_string(),
                    instance_id: "demo".to_string(),
                    environment: "staging".to_string(),
                    stream_id: "openfn-sidecar-runtime".to_string(),
                    config_hash: "sha256:NOTLOWERHEX".to_string(),
                    require_expression_hashes_verified: true,
                    require_runtime_verified: true,
                    require_smoke_verified: true,
                    assurance_ttl_ms: 60_000,
                }),
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("date-of-birth");
        claim
            .source_bindings
            .insert("crvs".to_string(), openfn_sidecar_binding("openfn_crvs"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("invalid expected_sidecar config_hash must fail");
        match err {
            EvidenceConfigError::InvalidExpectedSidecarConfig { connection, reason } => {
                assert_eq!(connection, "openfn_crvs");
                assert!(reason.contains("config_hash"));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn openfn_sidecar_rejects_oauth_source_auth() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: String::new(),
                source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                    Oauth2ClientCredentialsSourceAuthConfig {
                        token_url: "https://sidecar.example/oauth/token".to_string(),
                        client_id_env: "OPENFN_CLIENT_ID".to_string(),
                        client_secret_env: "OPENFN_CLIENT_SECRET".to_string(),
                        request_format: "json".to_string(),
                        scope: String::new(),
                        refresh_skew_seconds: 60,
                    },
                )),
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("date-of-birth");
        claim
            .source_bindings
            .insert("crvs".to_string(), openfn_sidecar_binding("openfn_crvs"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("OpenFn sidecar connections must use token_env auth");
        match err {
            EvidenceConfigError::InvalidSourceAuthConfig { connection, reason } => {
                assert_eq!(connection, "openfn_crvs");
                assert!(reason.contains("token_env"));
                assert!(reason.contains("openfn_sidecar"));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn openfn_sidecar_rejects_retry_on_5xx() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: true,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut claim = minimal_claim("date-of-birth");
        claim
            .source_bindings
            .insert("crvs".to_string(), openfn_sidecar_binding("openfn_crvs"));
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("OpenFn sidecar connections must not retry worker executions");
        match err {
            EvidenceConfigError::OpenFnSidecarRequiresNoRetry { connection } => {
                assert_eq!(connection, "openfn_crvs");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn openfn_sidecar_rejects_non_eq_lookup_operator() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut binding = openfn_sidecar_binding("openfn_crvs");
        binding.lookup.op = "contains".to_string();
        let mut claim = minimal_claim("date-of-birth");
        claim.source_bindings.insert("crvs".to_string(), binding);
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("OpenFn sidecar must reject non-eq lookup operators");
        match err {
            EvidenceConfigError::OpenFnSidecarUnsupportedOperator { claim, binding, op } => {
                assert_eq!(claim, "date-of-birth");
                assert_eq!(binding, "crvs");
                assert_eq!(op, "contains");
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn openfn_sidecar_rejects_non_eq_query_field_operator() {
        let mut config = minimal_config();
        config.evidence.source_connections.insert(
            "openfn_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::OpenFnSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        );
        let mut binding = openfn_sidecar_binding("openfn_crvs");
        add_query_fields(&mut binding);
        binding.query_fields[1].op = "contains".to_string();
        let mut claim = minimal_claim("date-of-birth");
        claim.source_bindings.insert("crvs".to_string(), binding);
        config.evidence.claims = vec![claim];

        let err = config
            .validate()
            .expect_err("OpenFn sidecar must reject non-eq query field operators");
        match err {
            EvidenceConfigError::OpenFnSidecarUnsupportedOperator { claim, binding, op } => {
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
    fn valid_oid4vci_config_passes_validation() {
        let config = valid_oid4vci_config();
        assert!(config.validate().is_ok());
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
        config.oid4vci.nonce_endpoint =
            Some("http://127.0.0.1:4325/notary/oid4vci/nonce".to_string());
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
                commitment:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
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
            publish_only_access_token_verification_key(
                "did:web:issuer.example#access-token-key-old",
            ),
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
        config.auth.access_token_signing.verification_key_ids =
            vec!["access-token-key".to_string()];

        let reason = expect_access_token_signing_error(&config);
        assert!(reason.contains("must not repeat active signing_key_id"));
    }

    #[test]
    fn access_token_verification_key_ids_must_be_unique() {
        let mut config = valid_pre_auth_config();
        config.evidence.signing_keys.insert(
            "access-token-key-old".to_string(),
            publish_only_access_token_verification_key(
                "did:web:issuer.example#access-token-key-old",
            ),
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
    fn local_jwk_signing_key_with_alg(
        alg: &str,
        private_jwk_env: &str,
        kid: &str,
    ) -> SigningKeyConfig {
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
}
