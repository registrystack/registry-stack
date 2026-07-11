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

pub fn signing_provider_uses_local_software_custody(provider: SigningKeyProviderConfig) -> bool {
    matches!(
        provider,
        SigningKeyProviderConfig::LocalJwkEnv
            | SigningKeyProviderConfig::FileWatch
            | SigningKeyProviderConfig::LocalPkcs12File
    )
}

pub fn signing_key_uses_local_software_custody(key: &SigningKeyConfig) -> bool {
    key.status.may_sign() && signing_provider_uses_local_software_custody(key.provider)
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
    /// Per-principal budget for machine `evaluate`/`batch_evaluate` traffic,
    /// counted in subjects (a single evaluate consumes 1; a batch consumes
    /// `items.len()`) over a fixed one-minute window. Disabled by default.
    #[serde(default)]
    pub machine_quota: MachineQuotaConfig,
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

/// A parsed dependent source-lookup reference of the form
/// `sources.<binding>.<field>` (the `source.` prefix is an accepted alias).
/// `field_path` may be a dotted path into nested JSON on the referenced source
/// row. Both the config validator and the runtime enforcer parse references
/// through [`parse_source_lookup_reference`] so they can never disagree about
/// what counts as a dependent reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLookupReference<'a> {
    pub binding_id: &'a str,
    pub field_path: &'a str,
}

#[must_use]
pub fn parse_source_lookup_reference(input: &str) -> Option<SourceLookupReference<'_>> {
    let remainder = input
        .strip_prefix("sources.")
        .or_else(|| input.strip_prefix("source."))?;
    let (binding_id, field_path) = remainder.split_once('.')?;
    if binding_id.is_empty() || field_path.is_empty() {
        return None;
    }
    Some(SourceLookupReference {
        binding_id,
        field_path,
    })
}

fn source_lookup_dependencies(
    claim: &str,
    binding: &str,
    source_binding: &SourceBindingConfig,
    source_bindings: &BTreeMap<String, SourceBindingConfig>,
) -> Result<BTreeSet<String>, EvidenceConfigError> {
    let mut dependencies = BTreeSet::new();
    let inputs = std::iter::once(source_binding.lookup.input.as_str()).chain(
        source_binding
            .query_fields
            .iter()
            .map(|field| field.input.as_str()),
    );
    for input in inputs {
        let Some(reference) = parse_source_lookup_reference(input) else {
            continue;
        };
        let referenced_binding = reference.binding_id;
        if !source_bindings.contains_key(referenced_binding) {
            return Err(EvidenceConfigError::UnknownSourceLookupBinding {
                claim: claim.to_string(),
                binding: binding.to_string(),
                input: input.to_string(),
                unknown: referenced_binding.to_string(),
            });
        }
        dependencies.insert(referenced_binding.to_string());
    }
    Ok(dependencies)
}

/// Detect a dependency cycle in a binding dependency graph using Kahn's
/// algorithm. Returns `None` when the graph is acyclic, otherwise `Some` with
/// the sorted set of bindings that could not be resolved (those participating
/// in or blocked by a cycle).
///
/// Shared by config-time validation and runtime enforcement so the two can
/// never disagree about which graphs are acceptable. Precondition: every
/// referenced binding exists as a key in the map (callers verify references
/// first), so a non-empty remainder here is necessarily a cycle, including a
/// self-reference.
#[must_use]
pub fn detect_dependency_cycle(
    dependencies_by_binding: &BTreeMap<String, BTreeSet<String>>,
) -> Option<Vec<String>> {
    let mut pending: BTreeSet<String> = dependencies_by_binding.keys().cloned().collect();
    let mut resolved = BTreeSet::new();
    while !pending.is_empty() {
        let ready: Vec<String> = pending
            .iter()
            .filter_map(|id| {
                let dependencies = dependencies_by_binding.get(id)?;
                dependencies
                    .iter()
                    .all(|dependency| resolved.contains(dependency))
                    .then_some(id.clone())
            })
            .collect();
        if ready.is_empty() {
            return Some(pending.into_iter().collect());
        }
        for id in ready {
            pending.remove(&id);
            resolved.insert(id);
        }
    }
    None
}

fn validate_source_lookup_dependency_graph(
    claim: &str,
    dependencies_by_binding: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), EvidenceConfigError> {
    match detect_dependency_cycle(dependencies_by_binding) {
        Some(bindings) => Err(EvidenceConfigError::SourceLookupDependencyCycle {
            claim: claim.to_string(),
            bindings,
        }),
        None => Ok(()),
    }
}

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
    if matching
        .allowed_legal_basis_refs
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "allowed_legal_basis_refs must not contain blanks",
        );
    }
    if matching
        .allowed_consent_refs
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return invalid_matching_config(
            claim,
            binding,
            "allowed_consent_refs must not contain blanks",
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

#[derive(Debug, Clone, Serialize)]
pub struct SourceMatchingConfig {
    pub policy_id: Option<String>,
    pub method: Option<String>,
    pub target_type: Option<String>,
    pub requester_type: Option<String>,
    pub allowed_purposes: Vec<String>,
    pub allowed_assurance: Vec<String>,
    pub minimum_assurance: Option<String>,
    pub permitted_jurisdictions: Vec<String>,
    pub max_source_age_seconds: Option<u64>,
    pub source_observed_at_field: Option<String>,
    pub require_legal_basis: bool,
    pub require_consent: bool,
    pub allowed_legal_basis_refs: Vec<String>,
    pub allowed_consent_refs: Vec<String>,
    pub redaction_fields: Vec<String>,
    pub ecosystem_binding: Option<EcosystemBindingSelectorConfig>,
    pub allowed_relationships: Vec<String>,
    /// Relationship-specific purpose allow-lists. Empty means relationships
    /// accepted by `allowed_relationships` are not purpose-scoped.
    pub relationship_purpose_scopes: BTreeMap<String, Vec<String>>,
    /// OR-of-AND groups of request paths. Example:
    /// `[["target.attributes.given_name", "target.attributes.family_name"]]`.
    pub sufficient_target_inputs: Vec<Vec<String>>,
    /// Maximum target input paths accepted by this binding. Empty means
    /// unrestricted for backwards-compatible identifier-only configs.
    pub allowed_target_inputs: Vec<String>,
    /// Maximum requester input paths accepted by this binding. Empty means
    /// unrestricted.
    pub allowed_requester_inputs: Vec<String>,
    pub collapse_matching_errors: bool,
    pub require_requester_reauthentication: bool,
    pub confidence: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMatchingConfigWire {
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    target_type: Option<String>,
    #[serde(default)]
    requester_type: Option<String>,
    #[serde(default)]
    allowed_purposes: Vec<String>,
    #[serde(default)]
    allowed_assurance: Vec<String>,
    #[serde(default)]
    minimum_assurance: Option<String>,
    #[serde(default)]
    permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    max_source_age_seconds: Option<u64>,
    #[serde(default)]
    source_observed_at_field: Option<String>,
    #[serde(default)]
    require_legal_basis: bool,
    #[serde(default)]
    require_consent: bool,
    #[serde(default)]
    allowed_legal_basis_refs: Vec<String>,
    #[serde(default)]
    allowed_consent_refs: Vec<String>,
    #[serde(default)]
    context_constraints: SourceContextConstraintsConfig,
    #[serde(default)]
    redaction_fields: Vec<String>,
    #[serde(default)]
    ecosystem_binding: Option<EcosystemBindingSelectorConfig>,
    #[serde(default)]
    allowed_relationships: Vec<String>,
    #[serde(default)]
    relationship_purpose_scopes: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    sufficient_target_inputs: Vec<Vec<String>>,
    #[serde(default)]
    allowed_target_inputs: Vec<String>,
    #[serde(default)]
    allowed_requester_inputs: Vec<String>,
    #[serde(default = "default_collapse_matching_errors")]
    collapse_matching_errors: bool,
    #[serde(default)]
    require_requester_reauthentication: bool,
    #[serde(default)]
    confidence: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceContextConstraintsConfig {
    #[serde(default)]
    pub legal_basis: ContextPresenceConstraintConfig,
    #[serde(default)]
    pub consent: ContextPresenceConstraintConfig,
    #[serde(default)]
    pub jurisdiction: ContextJurisdictionConstraintConfig,
    #[serde(default)]
    pub assurance: ContextAssuranceConstraintConfig,
    #[serde(default)]
    pub source_freshness: SourceFreshnessConstraintConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPresenceConstraintConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub allowed_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextJurisdictionConstraintConfig {
    #[serde(default)]
    pub permitted: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAssuranceConstraintConfig {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub minimum: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFreshnessConstraintConfig {
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
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
            allowed_legal_basis_refs: Vec::new(),
            allowed_consent_refs: Vec::new(),
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

impl<'de> Deserialize<'de> for SourceMatchingConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SourceMatchingConfigWire::deserialize(deserializer)?;
        SourceMatchingConfig::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

impl SourceMatchingConfig {
    fn from_wire(wire: SourceMatchingConfigWire) -> Result<Self, String> {
        let mut matching = SourceMatchingConfig {
            policy_id: wire.policy_id,
            method: wire.method,
            target_type: wire.target_type,
            requester_type: wire.requester_type,
            allowed_purposes: wire.allowed_purposes,
            allowed_assurance: wire.allowed_assurance,
            minimum_assurance: wire.minimum_assurance,
            permitted_jurisdictions: wire.permitted_jurisdictions,
            max_source_age_seconds: wire.max_source_age_seconds,
            source_observed_at_field: wire.source_observed_at_field,
            require_legal_basis: wire.require_legal_basis,
            require_consent: wire.require_consent,
            allowed_legal_basis_refs: wire.allowed_legal_basis_refs,
            allowed_consent_refs: wire.allowed_consent_refs,
            redaction_fields: wire.redaction_fields,
            ecosystem_binding: wire.ecosystem_binding,
            allowed_relationships: wire.allowed_relationships,
            relationship_purpose_scopes: wire.relationship_purpose_scopes,
            sufficient_target_inputs: wire.sufficient_target_inputs,
            allowed_target_inputs: wire.allowed_target_inputs,
            allowed_requester_inputs: wire.allowed_requester_inputs,
            collapse_matching_errors: wire.collapse_matching_errors,
            require_requester_reauthentication: wire.require_requester_reauthentication,
            confidence: wire.confidence,
        };
        matching.apply_context_constraints(wire.context_constraints)?;
        Ok(matching)
    }

    /// True when this matching config declares any context-constraint gate:
    /// legal basis, consent, jurisdiction, assurance, or source freshness.
    pub fn has_context_constraints(&self) -> bool {
        self.require_legal_basis
            || self.require_consent
            || !self.allowed_legal_basis_refs.is_empty()
            || !self.allowed_consent_refs.is_empty()
            || !self.permitted_jurisdictions.is_empty()
            || !self.allowed_assurance.is_empty()
            || self.minimum_assurance.is_some()
            || self.max_source_age_seconds.is_some()
    }

    /// True when the binding declares neither a `policy_id` nor any matching
    /// gate. Per spec RS-DM-CLAIM, such a binding falls back to unrestricted,
    /// identifier-only resolution: resolution behavior is unchanged, but
    /// operators should see it so they can accept it knowingly or declare a
    /// matching policy.
    pub fn lacks_matching_policy(&self) -> bool {
        self.policy_id.is_none() && !self.has_matching_gates()
    }

    fn has_matching_gates(&self) -> bool {
        self.has_context_constraints()
            || self.target_type.is_some()
            || self.requester_type.is_some()
            || !self.allowed_purposes.is_empty()
            || self.ecosystem_binding.as_ref().is_some_and(|binding| {
                binding.id.is_some()
                    || binding.profile.is_some()
                    || binding.pack_id.is_some()
                    || binding.pack_version.is_some()
                    || binding.policy_id.is_some()
                    || binding.policy_hash.is_some()
            })
            || !self.allowed_relationships.is_empty()
            || !self.relationship_purpose_scopes.is_empty()
            || !self.sufficient_target_inputs.is_empty()
            || !self.allowed_target_inputs.is_empty()
            || !self.allowed_requester_inputs.is_empty()
            || self.require_requester_reauthentication
    }

    fn apply_context_constraints(
        &mut self,
        constraints: SourceContextConstraintsConfig,
    ) -> Result<(), String> {
        if constraints.legal_basis.required {
            self.require_legal_basis = true;
        }
        if constraints.consent.required {
            self.require_consent = true;
        }
        merge_vec_constraint(
            "matching.allowed_legal_basis_refs",
            "matching.context_constraints.legal_basis.allowed_refs",
            &mut self.allowed_legal_basis_refs,
            constraints.legal_basis.allowed_refs,
        )?;
        merge_vec_constraint(
            "matching.allowed_consent_refs",
            "matching.context_constraints.consent.allowed_refs",
            &mut self.allowed_consent_refs,
            constraints.consent.allowed_refs,
        )?;
        merge_vec_constraint(
            "matching.permitted_jurisdictions",
            "matching.context_constraints.jurisdiction.permitted",
            &mut self.permitted_jurisdictions,
            constraints.jurisdiction.permitted,
        )?;
        merge_vec_constraint(
            "matching.allowed_assurance",
            "matching.context_constraints.assurance.allowed",
            &mut self.allowed_assurance,
            constraints.assurance.allowed,
        )?;
        merge_option_constraint(
            "matching.minimum_assurance",
            "matching.context_constraints.assurance.minimum",
            &mut self.minimum_assurance,
            constraints.assurance.minimum,
        )?;
        merge_option_constraint(
            "matching.max_source_age_seconds",
            "matching.context_constraints.source_freshness.max_age_seconds",
            &mut self.max_source_age_seconds,
            constraints.source_freshness.max_age_seconds,
        )?;
        Ok(())
    }
}

fn merge_vec_constraint(
    flattened_name: &str,
    nested_name: &str,
    flattened: &mut Vec<String>,
    nested: Vec<String>,
) -> Result<(), String> {
    if nested.is_empty() {
        return Ok(());
    }
    if flattened.is_empty() {
        *flattened = nested;
        return Ok(());
    }
    if *flattened == nested {
        return Ok(());
    }
    Err(format!("{nested_name} conflicts with {flattened_name}"))
}

fn merge_option_constraint<T>(
    flattened_name: &str,
    nested_name: &str,
    flattened: &mut Option<T>,
    nested: Option<T>,
) -> Result<(), String>
where
    T: PartialEq,
{
    let Some(nested) = nested else {
        return Ok(());
    };
    if flattened
        .as_ref()
        .is_some_and(|flattened| flattened != &nested)
    {
        return Err(format!("{nested_name} conflicts with {flattened_name}"));
    }
    *flattened = Some(nested);
    Ok(())
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
    #[serde(rename = "source_adapter_sidecar_batch")]
    SourceAdapterSidecarBatch,
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

/// Per-principal quota for machine `evaluate`/`batch_evaluate` traffic.
/// Budget is counted in subjects per principal over a fixed one-minute
/// window: a single `/v1/evaluations` call consumes 1, a batch consumes
/// `items.len()`. Disabled by default so existing deployments are unaffected.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineQuotaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_machine_quota_subjects_per_minute")]
    pub subjects_per_minute: u32,
}

impl Default for MachineQuotaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            subjects_per_minute: default_machine_quota_subjects_per_minute(),
        }
    }
}

impl MachineQuotaConfig {
    pub fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.enabled && self.subjects_per_minute == 0 {
            return Err(EvidenceConfigError::InvalidMachineQuotaConfig {
                reason: "subjects_per_minute must be greater than zero when enabled".to_string(),
            });
        }
        Ok(())
    }
}

const fn default_machine_quota_subjects_per_minute() -> u32 {
    6000
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
    #[serde(rename = "source_adapter_sidecar")]
    SourceAdapterSidecar,
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
    #[serde(default = "default_holder_binding_allowed_did_methods")]
    pub allowed_did_methods: Vec<String>,
}

impl Default for HolderBindingConfig {
    fn default() -> Self {
        Self {
            mode: default_holder_binding_mode(),
            proof_of_possession: None,
            allowed_did_methods: default_holder_binding_allowed_did_methods(),
        }
    }
}

fn default_holder_binding_mode() -> String {
    "did".to_string()
}

fn default_holder_binding_allowed_did_methods() -> Vec<String> {
    vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()]
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
mod tests;
