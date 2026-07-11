// SPDX-License-Identifier: Apache-2.0
//! Registry Notary configuration model.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use registry_platform_authcommon::CredentialFingerprintRef;
use registry_platform_config::DeprecatedConfigField;
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

mod audit;
mod auth;
mod cel;
mod credential_status;
mod errors;
mod evidence;
mod federation;
mod http;
mod oid4vci;
mod replay;
mod self_attestation;

pub use audit::*;
pub use auth::*;
pub use cel::*;
pub use credential_status::*;
pub use errors::*;
pub use evidence::*;
pub use federation::*;
pub use http::*;
pub use oid4vci::*;
pub use replay::*;
pub use self_attestation::*;

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
    pub trust_anchor_path: PathBuf,
    pub bundle_path: PathBuf,
    pub antirollback_state_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_override_path: Option<PathBuf>,
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
            if config_trust.trust_anchor_path.as_os_str().is_empty() {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.trust_anchor_path must not be empty".to_string(),
                });
            }
            if config_trust.bundle_path.as_os_str().is_empty() {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.bundle_path must not be empty".to_string(),
                });
            }
            if config_trust.antirollback_state_path.as_os_str().is_empty() {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.antirollback_state_path must not be empty".to_string(),
                });
            }
            if config_trust
                .break_glass_override_path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(EvidenceConfigError::InvalidConfigTrustConfig {
                    reason: "config_trust.break_glass_override_path must not be empty when set"
                        .to_string(),
                });
            }
        }
        self.replay.validate()?;
        validate_static_credential_ids(&self.auth.api_keys, &self.auth.bearer_tokens)?;
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
        self.evidence.machine_quota.validate()?;
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
                BulkMode::SourceAdapterSidecarBatch => {
                    for claim in &self.evidence.claims {
                        for (binding_id, binding) in &claim.source_bindings {
                            if binding.connection.as_deref() != Some(connection_id.as_str()) {
                                continue;
                            }
                            if binding.connector != SourceConnectorKind::SourceAdapterSidecar {
                                return Err(
                                    EvidenceConfigError::BulkModeRequiresSourceAdapterSidecarConnector {
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
        let mut seen_claim_ids: HashSet<&str> = HashSet::new();
        for claim in &self.evidence.claims {
            if claim.id.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidClaim);
            }
            // REQ-DM-CLAIM-001: reject a duplicate claim id at load rather
            // than letting a later claim silently shadow an earlier one.
            if !seen_claim_ids.insert(claim.id.as_str()) {
                return Err(EvidenceConfigError::DuplicateClaimId {
                    claim: claim.id.clone(),
                });
            }
            validate_claim_semantics(claim)?;
            // REQ-DM-CLAIM-008: reject a disclosure default outside the
            // allowed set at load; this is the most consequential of the
            // three RS-DM-CLAIM Section 10 gaps because a privacy-sensitive
            // claim could otherwise load with an internally inconsistent
            // disclosure policy that only fails on first render.
            if !claim
                .disclosure
                .allowed
                .iter()
                .any(|mode| mode == &claim.disclosure.default)
            {
                return Err(EvidenceConfigError::ClaimDisclosureDefaultNotAllowed {
                    claim: claim.id.clone(),
                    default: claim.disclosure.default.clone(),
                    allowed: claim.disclosure.allowed.clone(),
                });
            }
            // REQ-DM-CLAIM-006: reject an extract/exists rule whose `source`
            // does not name a binding declared under this claim's
            // source_bindings. A `cel` or `plugin` rule has no single named
            // source to check here.
            let rule_source = match &claim.rule {
                RuleConfig::Extract { source, .. } => Some(source.as_str()),
                RuleConfig::Exists { source } => Some(source.as_str()),
                RuleConfig::Cel { .. } | RuleConfig::Plugin { .. } => None,
            };
            if let Some(source) = rule_source {
                if !claim.source_bindings.contains_key(source) {
                    return Err(EvidenceConfigError::UnknownRuleSourceBinding {
                        claim: claim.id.clone(),
                        rule_source: source.to_string(),
                    });
                }
            }
            let mut source_lookup_dependencies_by_binding = BTreeMap::new();
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
                let dependencies = source_lookup_dependencies(
                    &claim.id,
                    binding_id,
                    binding,
                    &claim.source_bindings,
                )?;
                source_lookup_dependencies_by_binding.insert(binding_id.clone(), dependencies);
                if binding.connector == SourceConnectorKind::SourceAdapterSidecar {
                    let has_static_token = !connection.token_env.trim().is_empty();
                    if !has_static_token || connection.source_auth.is_some() {
                        return Err(EvidenceConfigError::InvalidSourceAuthConfig {
                            connection: binding.connection.clone().unwrap_or_default(),
                            reason:
                                "source_adapter_sidecar requires static bearer token auth through token_env"
                                    .to_string(),
                        });
                    }
                    if connection.retry_on_5xx {
                        return Err(EvidenceConfigError::SourceAdapterSidecarRequiresNoRetry {
                            connection: binding.connection.clone().unwrap_or_default(),
                        });
                    }
                    if binding.lookup.op != "eq" {
                        return Err(
                            EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator {
                                claim: claim.id.clone(),
                                binding: binding_id.clone(),
                                op: binding.lookup.op.clone(),
                            },
                        );
                    }
                    for query_field in &binding.query_fields {
                        if query_field.op != "eq" {
                            return Err(
                                EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator {
                                    claim: claim.id.clone(),
                                    binding: binding_id.clone(),
                                    op: query_field.op.clone(),
                                },
                            );
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
            validate_source_lookup_dependency_graph(
                &claim.id,
                &source_lookup_dependencies_by_binding,
            )?;
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
        self.validate_audit_ack_cursor()?;
        Ok(())
    }

    /// Validate the off-host ack cursor configuration against the audit sink.
    ///
    /// A freshness window with no cursor to read is meaningless, and pointing a
    /// cursor at a local file sink that does not declare off-host shipping
    /// asserts observed shipping that the operator never attested. Both are
    /// config errors so the contradiction is caught at load, not papered over.
    fn validate_audit_ack_cursor(&self) -> Result<(), EvidenceConfigError> {
        let evidence = &self.deployment.evidence;
        if evidence.audit_ack_max_age_secs.is_some() && evidence.audit_ack_cursor_path.is_none() {
            return Err(EvidenceConfigError::AuditAckMaxAgeWithoutCursor);
        }
        if evidence.audit_ack_cursor_path.is_some()
            && matches!(self.audit.sink.as_str(), "file" | "jsonl")
            && !evidence.audit_offhost_shipping
        {
            return Err(EvidenceConfigError::AuditAckCursorWithoutShippingDeclared);
        }
        Ok(())
    }

    pub fn validate_governed_runtime(&self) -> Result<(), EvidenceConfigError> {
        self.validate()?;
        self.server.admin_listener.validate(self.server.bind, true)
    }

    /// Snapshot the configuration facts the deployment gate engine reads.
    ///
    /// Boot-time projection is configuration-only. A configured cursor clears
    /// the static shipping-unverified gate, while runtime readiness and posture
    /// must sample and bind it before shipping-stale clears. Keeping filesystem
    /// I/O out of this path prevents startup from blocking on a stalled mount.
    pub fn gate_input(&self) -> crate::deployment::GateInput {
        self.gate_input_with_ack_observation(&registry_platform_ops::AckObservation::unverified())
    }

    /// Read the current off-host shipping cursor once for callers that need to
    /// project both deployment gates and posture from the same observation.
    pub fn audit_ack_observation(&self) -> registry_platform_ops::AckObservation {
        self.audit_ack_observation_at(SystemTime::now())
    }

    /// Deterministic form of [`Self::audit_ack_observation`] for tests.
    pub fn audit_ack_observation_at(
        &self,
        now: SystemTime,
    ) -> registry_platform_ops::AckObservation {
        registry_platform_ops::evaluate_ack_health(
            self.deployment.evidence.audit_ack_cursor_path(),
            now,
            self.deployment.evidence.audit_ack_max_age(),
        )
    }

    /// Snapshot gate facts as of `now`, including a synchronous cursor read.
    ///
    /// `now` is threaded through so cursor contract tests and offline commands
    /// can evaluate freshness deterministically. Public runtime handlers use a
    /// bounded async worker instead of this synchronous path.
    pub fn gate_input_at(&self, now: SystemTime) -> crate::deployment::GateInput {
        let ack_observation = self.audit_ack_observation_at(now);
        self.gate_input_with_ack_observation(&ack_observation)
    }

    /// Project gate facts using an already sampled shipping observation.
    /// Keeping filesystem I/O outside the pure projection lets one HTTP response
    /// use a single cursor snapshot for its gate and posture fields.
    pub fn gate_input_with_ack_observation(
        &self,
        ack_observation: &registry_platform_ops::AckObservation,
    ) -> crate::deployment::GateInput {
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
            // A local file sink caps retention to whatever the host disk
            // holds; an attacker with host access can destroy it. stdout and
            // syslog are exempt: their retention is owned by the orchestrator
            // log pipeline or the syslog daemon's own forwarding surface.
            audit_retention_local_only: matches!(self.audit.sink.as_str(), "file" | "jsonl")
                && !self.deployment.evidence.audit_offhost_shipping,
            audit_shipping_target_configured: matches!(
                self.audit.sink.as_str(),
                "stdout" | "syslog"
            ) || (matches!(
                self.audit.sink.as_str(),
                "file" | "jsonl"
            ) && self
                .deployment
                .evidence
                .audit_offhost_shipping),
            audit_ack_cursor_configured: self.deployment.evidence.audit_ack_cursor_path().is_some(),
            audit_ack_health_ok: ack_observation.health == registry_platform_ops::AckHealth::Ok,
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
            source_adapter_sidecar_without_expected_sidecar: self
                .evidence
                .source_connections
                .values()
                .any(|connection| {
                    connection.bulk_mode == BulkMode::SourceAdapterSidecarBatch
                        && connection.expected_sidecar.is_none()
                }),
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
            source_binding_without_matching_policy: self.evidence.claims.iter().any(|claim| {
                claim
                    .source_bindings
                    .values()
                    .any(|binding| binding.matching.lacks_matching_policy())
            }),
            signer_without_custody_approval: !self.deployment.evidence.signer_custody_approved
                && self.custody_scoped_signing_key_ids().iter().any(|key_id| {
                    self.evidence
                        .signing_keys
                        .get(*key_id)
                        .is_some_and(|key| key.status.may_sign())
                }),
        }
    }

    /// Signing-key ids used to issue credentials or access tokens, or to sign
    /// federation responses. These are the custody-relevant Notary roles. The
    /// eSignet RP client key is intentionally excluded because it signs an
    /// outbound client assertion rather than a Notary-issued artifact.
    pub fn custody_scoped_signing_key_ids(&self) -> HashSet<&str> {
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

    /// Signing-key ids whose resolved public material must not be shared, per
    /// issue #173. These are the separated signing roles: every credential
    /// profile signing key, the access-token signing key (when enabled), and the
    /// federation signing key (when enabled). The eSignet pre-authorized-code RP
    /// client key is intentionally excluded: it is a separate role that is
    /// allowed to reuse the credential issuer's key material.
    pub fn reuse_scoped_signing_key_ids(&self) -> HashSet<&str> {
        self.custody_scoped_signing_key_ids()
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

fn validate_static_credential_ids(
    api_keys: &[EvidenceCredentialConfig],
    bearer_tokens: &[EvidenceCredentialConfig],
) -> Result<(), EvidenceConfigError> {
    let mut ids = HashSet::with_capacity(api_keys.len() + bearer_tokens.len());
    for (field, credentials) in [
        ("auth.api_keys", api_keys),
        ("auth.bearer_tokens", bearer_tokens),
    ] {
        for credential in credentials {
            if ids.insert(credential.id.as_str()) {
                continue;
            }
            return Err(EvidenceConfigError::InvalidAuthConfig {
                reason: format!("{field} contains duplicate id '{}'", credential.id),
            });
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests;
