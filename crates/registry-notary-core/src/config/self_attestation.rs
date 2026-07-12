// SPDX-License-Identifier: Apache-2.0
//! Self-attestation and delegated-attestation configuration.

use super::*;

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

pub(super) fn self_attestation_config_is_default(config: &SelfAttestationConfig) -> bool {
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

pub(super) fn default_self_attestation_required_auth_mode() -> String {
    "oidc".to_string()
}

impl SelfAttestationConfig {
    pub(super) fn validate(
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
        validate_self_attestation_evidence_paths(self, evidence)?;
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

pub(super) fn validate_self_attestation_evidence_paths(
    config: &SelfAttestationConfig,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    for claim_id in &config.allowed_claims {
        reject_registry_backed_dependency_path(
            "self_attestation.allowed_claims",
            claim_id,
            evidence,
        )?;
    }
    for relationship in &config.delegation.allowed_relationships {
        reject_registry_backed_dependency_path(
            "self_attestation.delegation.proof_claim",
            &relationship.proof_claim,
            evidence,
        )?;
        for claim_id in &relationship.allowed_claims {
            reject_registry_backed_dependency_path(
                "self_attestation.delegation.allowed_claims",
                claim_id,
                evidence,
            )?;
        }
    }
    Ok(())
}

fn reject_registry_backed_dependency_path(
    context: &str,
    root_claim_id: &str,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    let mut pending = vec![root_claim_id];
    let mut visited = HashSet::new();
    while let Some(claim_id) = pending.pop() {
        if !visited.insert(claim_id) {
            continue;
        }
        let Some(claim) = evidence
            .claims
            .iter()
            .find(|candidate| candidate.id == claim_id)
        else {
            continue;
        };
        if claim.evidence_mode.is_registry_backed() {
            return invalid_self_attestation(format!(
                "{context} path cannot include registry_backed claim '{}'",
                claim.id
            ));
        }
        pending.extend(claim.depends_on.iter().map(String::as_str));
    }
    Ok(())
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
        if !delegated_attestation_v1_enabled() {
            return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                reason: "self_attestation.delegation is unavailable in v1 until a trusted assertion design replaces direct source proof claims".to_string(),
            });
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

fn delegated_attestation_v1_enabled() -> bool {
    false
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
        let Some(proof_claim) = evidence
            .claims
            .iter()
            .find(|claim| claim.id == self.proof_claim)
        else {
            return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                reason: format!(
                    "self_attestation.delegation proof_claim references unknown claim '{}'",
                    self.proof_claim
                ),
            });
        };
        validate_delegated_proof_claim_binding(self, proof_claim)?;
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
                    reason: format!(
                        "self_attestation.delegation allowed_claims references unknown claim '{claim_id}'"
                    ),
                });
            }
            let Some(claim) = evidence.claims.iter().find(|claim| claim.id == *claim_id) else {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "self_attestation.delegation allowed_claims references unknown claim '{claim_id}'"
                    ),
                });
            };
            if !claim.depends_on.iter().any(|dep| dep == &self.proof_claim) {
                return Err(EvidenceConfigError::InvalidSelfAttestationConfig {
                    reason: format!(
                        "delegated claim '{claim_id}' must depend_on proof_claim '{}'",
                        self.proof_claim
                    ),
                });
            }
            validate_delegated_attestation_claim(
                self,
                claim,
                &allowed_purposes,
                &allowed_formats,
                &allowed_disclosures,
                &allowed_profiles,
            )?;
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
        validate_delegated_attestation_allow_lists_are_supported(self, evidence)?;
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

pub(super) fn validate_non_empty_entries(
    name: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_self_attestation(format!("{name} must not be empty"));
    }
    validate_entries(name, values)
}

pub(super) fn validate_entries(name: &str, values: &[String]) -> Result<(), EvidenceConfigError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_self_attestation(format!("{name} must not contain blank entries"));
    }
    Ok(())
}

pub(super) fn validate_exact_wallet_origins(origins: &[String]) -> Result<(), EvidenceConfigError> {
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

pub(super) fn validate_self_attestation_claim(
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

pub(super) fn validate_self_attestation_profile(
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

pub(super) fn validate_self_attestation_allow_lists_are_supported(
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

pub(super) fn validate_delegated_proof_claim_binding(
    relationship: &SelfAttestationDelegatedRelationshipConfig,
    proof_claim: &ClaimDefinition,
) -> Result<(), EvidenceConfigError> {
    if proof_claim.source_bindings.is_empty() {
        return invalid_self_attestation(format!(
            "delegated proof_claim '{}' must read a relationship source binding",
            relationship.proof_claim
        ));
    }
    if !proof_claim
        .source_bindings
        .values()
        .any(source_binding_lookup_references_requester_and_target)
    {
        return invalid_self_attestation(format!(
            "delegated proof_claim '{}' must bind both requester and target source inputs",
            relationship.proof_claim
        ));
    }
    Ok(())
}

pub(super) fn source_binding_lookup_references_requester_and_target(
    binding: &SourceBindingConfig,
) -> bool {
    let input_paths = std::iter::once(binding.lookup.input.as_str()).chain(
        binding
            .query_fields
            .iter()
            .map(|field| field.input.as_str()),
    );
    let mut has_requester = false;
    let mut has_target = false;
    for path in input_paths {
        has_requester |= source_binding_input_is_under(path, "requester");
        has_target |= source_binding_input_is_under(path, "target");
    }
    has_requester && has_target
}

pub(super) fn source_binding_input_is_under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('.'))
}

pub(super) fn validate_delegated_attestation_claim(
    relationship: &SelfAttestationDelegatedRelationshipConfig,
    claim: &ClaimDefinition,
    allowed_purposes: &HashSet<&str>,
    allowed_formats: &HashSet<&str>,
    allowed_disclosures: &HashSet<&str>,
    allowed_profiles: &HashSet<&str>,
) -> Result<(), EvidenceConfigError> {
    if !claim.operations.evaluate.enabled {
        return invalid_self_attestation(format!(
            "delegated claim '{}' must enable evaluate",
            claim.id
        ));
    }
    let purpose = claim.purpose.as_deref().ok_or_else(|| {
        EvidenceConfigError::InvalidSelfAttestationConfig {
            reason: format!("delegated claim '{}' must declare purpose", claim.id),
        }
    })?;
    if !allowed_purposes.contains(purpose) {
        return invalid_self_attestation(format!(
            "delegated claim '{}' declares unallowed purpose '{}'",
            claim.id, purpose
        ));
    }
    if !claim
        .formats
        .iter()
        .any(|format| allowed_formats.contains(format.as_str()))
    {
        return invalid_self_attestation(format!(
            "delegated claim '{}' must support at least one allowed format",
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
            "delegated claim '{}' must support at least one allowed disclosure",
            claim.id
        ));
    }
    if !relationship.credential_profiles.is_empty()
        && !claim
            .credential_profiles
            .iter()
            .any(|profile| allowed_profiles.contains(profile.as_str()))
    {
        return invalid_self_attestation(format!(
            "delegated claim '{}' must reference an allowed credential profile",
            claim.id
        ));
    }
    Ok(())
}

pub(super) fn validate_delegated_attestation_allow_lists_are_supported(
    relationship: &SelfAttestationDelegatedRelationshipConfig,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    let allowed_claims: Vec<&ClaimDefinition> = relationship
        .allowed_claims
        .iter()
        .filter_map(|claim_id| evidence.claims.iter().find(|claim| claim.id == *claim_id))
        .collect();
    let allowed_profiles: Vec<&CredentialProfileConfig> = relationship
        .credential_profiles
        .iter()
        .filter_map(|profile_id| evidence.credential_profiles.get(profile_id))
        .collect();

    for purpose in &relationship.allowed_purposes {
        if !allowed_claims
            .iter()
            .any(|claim| claim.purpose.as_deref() == Some(purpose.as_str()))
        {
            return invalid_self_attestation(format!(
                "self_attestation.delegation allowed_purposes entry '{purpose}' is not used by any allowed claim"
            ));
        }
    }

    for format in &relationship.allowed_formats {
        let supported_by_claim = allowed_claims
            .iter()
            .any(|claim| claim.formats.iter().any(|candidate| candidate == format));
        let supported_by_profile = allowed_profiles
            .iter()
            .any(|profile| profile.format == *format);
        if !supported_by_claim && !supported_by_profile {
            return invalid_self_attestation(format!(
                "self_attestation.delegation allowed_formats entry '{format}' is not supported by any allowed claim or profile"
            ));
        }
    }

    for disclosure in &relationship.allowed_disclosures {
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
                "self_attestation.delegation allowed_disclosures entry '{disclosure}' is not supported by any allowed claim or profile"
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_required_scopes_do_not_grant_source_access(
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

pub(super) fn source_required_scopes(evidence: &EvidenceConfig) -> HashSet<String> {
    let mut scopes = HashSet::new();
    for claim in &evidence.claims {
        if !claim.evidence_mode.is_self_attested() {
            scopes.extend(claim.required_scopes.iter().cloned());
        }
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

pub(super) fn invalid_self_attestation<T>(
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidSelfAttestationConfig {
        reason: reason.into(),
    })
}

pub(super) fn detect_depends_on_cycle(
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
