// SPDX-License-Identifier: Apache-2.0
//! Subject-bound and delegated subject-access configuration.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub subject_binding: SubjectAccessSubjectBindingConfig,
    #[serde(default)]
    pub citizen_clients: SubjectAccessCitizenClientsConfig,
    #[serde(default)]
    pub token_policy: SubjectAccessTokenPolicyConfig,
    #[serde(default)]
    pub allowed_operations: SubjectAccessOperationsConfig,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
    #[serde(default)]
    pub allowed_claims: Vec<String>,
    #[serde(default)]
    pub allowed_formats: Vec<String>,
    #[serde(default)]
    pub allowed_disclosures: Vec<String>,
    #[serde(default)]
    pub scope_policy: SubjectAccessScopePolicy,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_wallet_origins: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub delegation: SubjectAccessDelegationConfig,
    #[serde(default)]
    pub rate_limits: SubjectAccessRateLimitsConfig,
}

pub(super) fn subject_access_config_is_default(config: &SubjectAccessConfig) -> bool {
    config == &SubjectAccessConfig::default()
}

impl SubjectAccessConfig {
    pub(super) fn validate(
        &self,
        auth: &EvidenceAuthConfig,
        evidence: &EvidenceConfig,
    ) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            return Ok(());
        }
        let oidc =
            auth.oidc
                .as_ref()
                .ok_or_else(|| EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: "enabled subject_access requires auth.oidc".to_string(),
                })?;

        self.subject_binding.validate()?;
        self.citizen_clients.validate(oidc)?;
        self.token_policy.validate(oidc)?;
        if self.subject_binding.claim_source == SubjectAccessClaimSource::Userinfo
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
        validate_non_empty_entries("subject_access.allowed_purposes", &self.allowed_purposes)?;
        validate_non_empty_entries("subject_access.allowed_claims", &self.allowed_claims)?;
        validate_non_empty_entries("subject_access.allowed_formats", &self.allowed_formats)?;
        validate_non_empty_entries(
            "subject_access.allowed_disclosures",
            &self.allowed_disclosures,
        )?;
        if self.scope_policy != SubjectAccessScopePolicy::Disabled
            && self.required_scopes.is_empty()
        {
            return self.invalid("scope_policy requires required_scopes unless it is disabled");
        }
        if self.scope_policy == SubjectAccessScopePolicy::Disabled
            && !self.required_scopes.is_empty()
        {
            return self.invalid("scope_policy = disabled requires required_scopes to be empty");
        }
        if self.scope_policy != SubjectAccessScopePolicy::Disabled {
            validate_non_empty_entries("subject_access.required_scopes", &self.required_scopes)?;
        } else {
            validate_entries("subject_access.required_scopes", &self.required_scopes)?;
        }
        validate_non_empty_entries(
            "subject_access.credential_profiles",
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
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: format!("allowed_claims references unknown claim '{claim_id}'"),
                });
            }
        }

        for profile_id in &self.credential_profiles {
            if !evidence.credential_profiles.contains_key(profile_id) {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
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
            validate_subject_access_profile(
                profile_id,
                profile,
                &claim_ids,
                &allowed_claim_ids,
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
            validate_subject_access_claim(
                claim,
                &allowed_purposes,
                &allowed_formats,
                &allowed_disclosures,
                &allowed_profiles,
                self.allowed_operations.issue_credential,
            )?;
            validate_subject_bound_registry_inputs(claim, &self.subject_binding.id_type)?;
        }

        validate_subject_access_allow_lists_are_supported(self, evidence)?;
        if self.scope_policy != SubjectAccessScopePolicy::Disabled {
            validate_required_scope_mappings(self, oidc)?;
        }
        Ok(())
    }

    fn invalid<T>(&self, reason: impl Into<String>) -> Result<T, EvidenceConfigError> {
        Err(EvidenceConfigError::InvalidSubjectAccessConfig {
            reason: reason.into(),
        })
    }
}

fn validate_subject_bound_registry_inputs(
    claim: &ClaimDefinition,
    subject_id_type: &str,
) -> Result<(), EvidenceConfigError> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Ok(());
    };
    let target_path = format!("target.identifiers.{subject_id_type}");
    let requester_path = format!("requester.identifiers.{subject_id_type}");
    for consultation in consultations.values() {
        for input in consultation.inputs.values() {
            let path = input.request_context_path();
            if path != target_path && path != requester_path {
                return invalid_subject_access(format!(
                    "allowed registry_backed claim '{}' maps Relay input '{}' outside the authenticated subject binding; expected '{}' or '{}'",
                    claim.id, path, target_path, requester_path
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessDelegationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_relationships: Vec<SubjectAccessDelegatedRelationshipConfig>,
}

impl SubjectAccessDelegationConfig {
    fn validate(&self, evidence: &EvidenceConfig) -> Result<(), EvidenceConfigError> {
        if !self.enabled {
            if !self.allowed_relationships.is_empty() {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason:
                        "subject_access.delegation.enabled=false requires allowed_relationships to be empty"
                            .to_string(),
                });
            }
            return Ok(());
        }
        if self.allowed_relationships.is_empty() {
            return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                reason: "subject_access.delegation.enabled requires allowed_relationships"
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
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: format!(
                        "subject_access.delegation.allowed_relationships contains duplicate relationship_type '{}'",
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
    ) -> Option<&SubjectAccessDelegatedRelationshipConfig> {
        self.allowed_relationships
            .iter()
            .find(|relationship| relationship.relationship_type == relationship_type)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessDelegatedRelationshipConfig {
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

impl SubjectAccessDelegatedRelationshipConfig {
    fn validate(
        &self,
        evidence: &EvidenceConfig,
        claim_ids: &HashSet<&str>,
    ) -> Result<(), EvidenceConfigError> {
        if self.relationship_type.trim().is_empty() {
            return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                reason:
                    "subject_access.delegation.allowed_relationships.relationship_type is required"
                        .to_string(),
            });
        }
        if self.proof_claim.trim().is_empty() || !claim_ids.contains(self.proof_claim.as_str()) {
            return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                reason: format!(
                    "subject_access.delegation proof_claim references unknown claim '{}'",
                    self.proof_claim
                ),
            });
        }
        let Some(proof_claim) = evidence
            .claims
            .iter()
            .find(|claim| claim.id == self.proof_claim)
        else {
            return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                reason: format!(
                    "subject_access.delegation proof_claim references unknown claim '{}'",
                    self.proof_claim
                ),
            });
        };
        validate_delegated_proof_claim_binding(self, proof_claim)?;
        if let Some(target_id_type) = self.target_id_type.as_deref() {
            if target_id_type.trim().is_empty() {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: "subject_access.delegation target_id_type must not be blank"
                        .to_string(),
                });
            }
        }
        validate_non_empty_entries(
            "subject_access.delegation.allowed_claims",
            &self.allowed_claims,
        )?;
        validate_non_empty_entries(
            "subject_access.delegation.allowed_purposes",
            &self.allowed_purposes,
        )?;
        validate_non_empty_entries(
            "subject_access.delegation.allowed_formats",
            &self.allowed_formats,
        )?;
        validate_non_empty_entries(
            "subject_access.delegation.allowed_disclosures",
            &self.allowed_disclosures,
        )?;
        validate_entries(
            "subject_access.delegation.credential_profiles",
            &self.credential_profiles,
        )?;
        if !self.credential_profiles.is_empty() {
            return invalid_subject_access(format!(
                "subject_access.delegation.allowed_relationships relationship '{}' credential_profiles must be empty in 1.0; delegated attestation is evaluation-only. Remove credential_profiles to keep delegated evaluation, or issue a registry-backed non-delegated claim through subject_access.credential_profiles",
                self.relationship_type
            ));
        }
        let allowed_purposes: HashSet<&str> =
            self.allowed_purposes.iter().map(String::as_str).collect();
        let allowed_formats: HashSet<&str> =
            self.allowed_formats.iter().map(String::as_str).collect();
        let allowed_disclosures: HashSet<&str> = self
            .allowed_disclosures
            .iter()
            .map(String::as_str)
            .collect();
        for claim_id in &self.allowed_claims {
            if !claim_ids.contains(claim_id.as_str()) {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: format!(
                        "subject_access.delegation allowed_claims references unknown claim '{claim_id}'"
                    ),
                });
            }
            let Some(claim) = evidence.claims.iter().find(|claim| claim.id == *claim_id) else {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: format!(
                        "subject_access.delegation allowed_claims references unknown claim '{claim_id}'"
                    ),
                });
            };
            if !claim.depends_on.iter().any(|dep| dep == &self.proof_claim) {
                return Err(EvidenceConfigError::InvalidSubjectAccessConfig {
                    reason: format!(
                        "delegated claim '{claim_id}' must depend_on proof_claim '{}'",
                        self.proof_claim
                    ),
                });
            }
            if claim.purpose != proof_claim.purpose {
                return invalid_subject_access(format!(
                    "delegated claim '{claim_id}' and proof_claim '{}' must declare the same purpose",
                    self.proof_claim
                ));
            }
            if !claim.credential_profiles.is_empty() {
                return invalid_subject_access(format!(
                    "delegated claim '{claim_id}' credential_profiles must be empty in 1.0; delegated attestation is evaluation-only. Remove the claim credential_profiles binding to keep delegated evaluation, or issue a registry-backed non-delegated claim"
                ));
            }
            validate_delegated_attestation_claim(
                claim,
                &allowed_purposes,
                &allowed_formats,
                &allowed_disclosures,
            )?;
        }
        validate_delegated_attestation_allow_lists_are_supported(self, evidence)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectAccessScopePolicy {
    #[default]
    Required,
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessSubjectBindingConfig {
    #[serde(default)]
    pub token_claim: String,
    #[serde(default)]
    pub claim_source: SubjectAccessClaimSource,
    #[serde(default)]
    pub request_field: SubjectId,
    #[serde(default)]
    pub id_type: String,
    #[serde(default)]
    pub normalize: SubjectBindingNormalize,
    #[serde(default)]
    pub allow_sub_as_civil_id: bool,
}

impl SubjectAccessSubjectBindingConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.token_claim.is_empty() {
            return invalid_subject_access("subject_binding.token_claim must not be empty");
        }
        if !self
            .token_claim
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '/' | '.' | '-'))
        {
            return invalid_subject_access(
                "subject_binding.token_claim must match [A-Za-z0-9_:/\\.\\-]+",
            );
        }
        if self.token_claim == "sub" && !self.allow_sub_as_civil_id {
            return invalid_subject_access(
                "subject_binding.token_claim = sub requires allow_sub_as_civil_id = true",
            );
        }
        if self.id_type.trim().is_empty() {
            return invalid_subject_access("subject_binding.id_type must not be empty");
        }
        if self.normalize != SubjectBindingNormalize::Exact {
            return invalid_subject_access("subject_binding.normalize must be exact");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectAccessClaimSource {
    #[default]
    AccessToken,
    Userinfo,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum SubjectId {
    #[default]
    SubjectId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectBindingNormalize {
    #[default]
    Exact,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessCitizenClientsConfig {
    #[serde(default)]
    pub allowed_client_ids: Vec<String>,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
}

impl SubjectAccessCitizenClientsConfig {
    fn validate(&self, oidc: &EvidenceOidcAuthConfig) -> Result<(), EvidenceConfigError> {
        if self.allowed_client_ids.is_empty() && self.allowed_audiences.is_empty() {
            return invalid_subject_access(
                "citizen_clients must list at least one allowed client id or audience",
            );
        }
        validate_entries(
            "subject_access.citizen_clients.allowed_client_ids",
            &self.allowed_client_ids,
        )?;
        validate_entries(
            "subject_access.citizen_clients.allowed_audiences",
            &self.allowed_audiences,
        )?;
        for audience in &self.allowed_audiences {
            if !oidc.audiences.iter().any(|accepted| accepted == audience) {
                return invalid_subject_access(format!(
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
                    return invalid_subject_access(format!(
                        "citizen client '{client_id}' is not listed in auth.oidc.allowed_clients"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessTokenPolicyConfig {
    #[serde(default)]
    pub required_acr_values: Vec<String>,
    #[serde(default)]
    pub assurance_claim_source: SubjectAccessAssuranceClaimSource,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectAccessAssuranceClaimSource {
    #[default]
    AccessToken,
    IdToken,
}

impl SubjectAccessTokenPolicyConfig {
    fn validate(&self, oidc: &EvidenceOidcAuthConfig) -> Result<(), EvidenceConfigError> {
        validate_entries(
            "subject_access.token_policy.required_acr_values",
            &self.required_acr_values,
        )?;
        if self.max_auth_age_seconds == 0 {
            return invalid_subject_access(
                "token_policy.max_auth_age_seconds must be greater than zero",
            );
        }
        if self.max_access_token_lifetime_seconds == 0 {
            return invalid_subject_access(
                "token_policy.max_access_token_lifetime_seconds must be greater than zero",
            );
        }
        if self.max_evaluation_age_seconds == 0 || self.max_evaluation_age_seconds > 600 {
            return invalid_subject_access(
                "token_policy.max_evaluation_age_seconds must be between 1 and 600",
            );
        }
        if self.max_credential_validity_seconds == 0 {
            return invalid_subject_access(
                "token_policy.max_credential_validity_seconds must be greater than zero",
            );
        }
        if self.max_clock_leeway_seconds == 0 || self.max_clock_leeway_seconds > 60 {
            return invalid_subject_access(
                "token_policy.max_clock_leeway_seconds must be between 1 and 60",
            );
        }
        if oidc.leeway > Duration::from_secs(self.max_clock_leeway_seconds) {
            return invalid_subject_access(
                "auth.oidc.leeway must not exceed token_policy.max_clock_leeway_seconds",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessOperationsConfig {
    #[serde(default)]
    pub evaluate: bool,
    #[serde(default)]
    pub render: bool,
    #[serde(default)]
    pub issue_credential: bool,
    #[serde(default)]
    pub batch_evaluate: bool,
}

impl SubjectAccessOperationsConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.batch_evaluate {
            return invalid_subject_access("allowed_operations.batch_evaluate must be false in v1");
        }
        if !self.evaluate && !self.render && !self.issue_credential {
            return invalid_subject_access(
                "allowed_operations must enable at least one subject-access operation",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessRateLimitsConfig {
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

impl SubjectAccessRateLimitsConfig {
    fn validate(&self) -> Result<(), EvidenceConfigError> {
        if self.invalid_token_per_client_address_per_minute == 0
            || self.per_principal_per_minute == 0
            || self.subject_mismatch_per_principal_per_hour == 0
            || self.per_holder_per_hour == 0
            || self.credential_issuance_per_principal_per_hour == 0
        {
            return invalid_subject_access("rate_limits values must all be greater than zero");
        }
        Ok(())
    }
}

pub(super) fn validate_non_empty_entries(
    name: &str,
    values: &[String],
) -> Result<(), EvidenceConfigError> {
    if values.is_empty() {
        return invalid_subject_access(format!("{name} must not be empty"));
    }
    validate_entries(name, values)
}

pub(super) fn validate_entries(name: &str, values: &[String]) -> Result<(), EvidenceConfigError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_subject_access(format!("{name} must not contain blank entries"));
    }
    Ok(())
}

pub(super) fn validate_exact_wallet_origins(origins: &[String]) -> Result<(), EvidenceConfigError> {
    for origin in origins {
        if origin == "*" || origin.contains('*') {
            return invalid_subject_access(
                "allowed_wallet_origins must contain exact origins, not wildcards",
            );
        }
        if !origin.starts_with("https://") {
            return invalid_subject_access("allowed_wallet_origins must use https origins");
        }
    }
    Ok(())
}

pub(super) fn validate_subject_access_claim(
    claim: &ClaimDefinition,
    allowed_purposes: &HashSet<&str>,
    allowed_formats: &HashSet<&str>,
    allowed_disclosures: &HashSet<&str>,
    allowed_profiles: &HashSet<&str>,
    issue_credential: bool,
) -> Result<(), EvidenceConfigError> {
    if !claim.operations.evaluate.enabled {
        return invalid_subject_access(format!(
            "allowed claim '{}' must enable evaluate",
            claim.id
        ));
    }
    let purpose = claim.purpose.as_deref().ok_or_else(|| {
        EvidenceConfigError::InvalidSubjectAccessConfig {
            reason: format!("allowed claim '{}' must declare purpose", claim.id),
        }
    })?;
    if !allowed_purposes.contains(purpose) {
        return invalid_subject_access(format!(
            "allowed claim '{}' declares unallowed purpose '{}'",
            claim.id, purpose
        ));
    }
    if !claim
        .formats
        .iter()
        .any(|format| allowed_formats.contains(format.as_str()))
    {
        return invalid_subject_access(format!(
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
        return invalid_subject_access(format!(
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
        return invalid_subject_access(format!(
            "allowed claim '{}' must reference an allowed credential profile",
            claim.id
        ));
    }
    Ok(())
}

pub(super) fn validate_subject_access_profile(
    profile_id: &str,
    profile: &CredentialProfileConfig,
    claim_ids: &HashSet<&str>,
    allowed_claim_ids: &HashSet<&str>,
    max_credential_validity_seconds: u64,
) -> Result<(), EvidenceConfigError> {
    if profile.validity_seconds <= 0 {
        return invalid_subject_access(format!(
            "credential profile '{profile_id}' validity_seconds must be greater than zero"
        ));
    }
    let validity_seconds = u64::try_from(profile.validity_seconds).map_err(|_| {
        EvidenceConfigError::InvalidSubjectAccessConfig {
            reason: format!(
                "credential profile '{profile_id}' validity_seconds must be greater than zero"
            ),
        }
    })?;
    if validity_seconds > max_credential_validity_seconds {
        return invalid_subject_access(format!(
            "credential profile '{profile_id}' validity_seconds must not exceed the subject-access ceiling"
        ));
    }
    if profile.holder_binding.mode != "did" {
        return invalid_subject_access(format!(
            "credential profile '{profile_id}' holder_binding.mode must be did"
        ));
    }
    if profile.holder_binding.proof_of_possession.as_deref() != Some("required") {
        return invalid_subject_access(format!(
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
        return invalid_subject_access(format!(
            "credential profile '{profile_id}' holder_binding.allowed_did_methods must only contain did:jwk"
        ));
    }
    for claim_id in &profile.allowed_claims {
        if !claim_ids.contains(claim_id.as_str()) {
            return invalid_subject_access(format!(
                "credential profile '{profile_id}' references unknown claim '{claim_id}'"
            ));
        }
    }
    if !profile
        .allowed_claims
        .iter()
        .any(|claim_id| allowed_claim_ids.contains(claim_id.as_str()))
    {
        return invalid_subject_access(format!(
            "credential profile '{profile_id}' must allow at least one subject-access claim"
        ));
    }
    Ok(())
}

pub(super) fn validate_subject_access_allow_lists_are_supported(
    config: &SubjectAccessConfig,
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
            return invalid_subject_access(format!(
                "allowed_purposes entry '{purpose}' is not used by any allowed claim"
            ));
        }
    }

    for format in &config.allowed_formats {
        let supported_by_claim = allowed_claims
            .iter()
            .any(|claim| claim.formats.iter().any(|candidate| candidate == format));
        if !supported_by_claim {
            return invalid_subject_access(format!(
                "allowed_formats entry '{format}' is not supported by any allowed claim"
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
            return invalid_subject_access(format!(
                "allowed_disclosures entry '{disclosure}' is not supported by any allowed claim or profile"
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_delegated_proof_claim_binding(
    relationship: &SubjectAccessDelegatedRelationshipConfig,
    proof_claim: &ClaimDefinition,
) -> Result<(), EvidenceConfigError> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &proof_claim.evidence_mode else {
        return invalid_subject_access(format!(
            "delegated proof_claim '{}' must be registry_backed",
            relationship.proof_claim
        ));
    };
    let Some((_, consultation)) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1)
    else {
        return invalid_subject_access(format!(
            "delegated proof_claim '{}' must declare exactly one Relay consultation",
            relationship.proof_claim
        ));
    };
    let has_requester = consultation
        .inputs
        .values()
        .any(RelayConsultationInput::is_requester_derived);
    let has_target = consultation
        .inputs
        .values()
        .any(RelayConsultationInput::is_authenticated_target_identifier);
    if !has_requester || !has_target {
        return invalid_subject_access(format!(
            "delegated proof_claim '{}' must map both a requester-derived input and an authenticated target identifier",
            relationship.proof_claim
        ));
    }
    if proof_claim.value.value_type != "boolean" {
        return invalid_subject_access(format!(
            "delegated proof_claim '{}' must produce a boolean result",
            relationship.proof_claim
        ));
    }
    if proof_claim.purpose.as_deref().is_none() {
        return invalid_subject_access(format!(
            "delegated proof_claim '{}' must declare purpose",
            relationship.proof_claim
        ));
    }
    Ok(())
}

pub(super) fn validate_delegated_attestation_claim(
    claim: &ClaimDefinition,
    allowed_purposes: &HashSet<&str>,
    allowed_formats: &HashSet<&str>,
    allowed_disclosures: &HashSet<&str>,
) -> Result<(), EvidenceConfigError> {
    if !claim.operations.evaluate.enabled {
        return invalid_subject_access(format!(
            "delegated claim '{}' must enable evaluate",
            claim.id
        ));
    }
    if !claim.evidence_mode.is_self_attested() {
        return invalid_subject_access(format!(
            "delegated claim '{}' must be self_attested",
            claim.id
        ));
    }
    let purpose = claim.purpose.as_deref().ok_or_else(|| {
        EvidenceConfigError::InvalidSubjectAccessConfig {
            reason: format!("delegated claim '{}' must declare purpose", claim.id),
        }
    })?;
    if !allowed_purposes.contains(purpose) {
        return invalid_subject_access(format!(
            "delegated claim '{}' declares unallowed purpose '{}'",
            claim.id, purpose
        ));
    }
    if !claim
        .formats
        .iter()
        .any(|format| allowed_formats.contains(format.as_str()))
    {
        return invalid_subject_access(format!(
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
        return invalid_subject_access(format!(
            "delegated claim '{}' must support at least one allowed disclosure",
            claim.id
        ));
    }
    Ok(())
}

pub(super) fn validate_delegated_attestation_allow_lists_are_supported(
    relationship: &SubjectAccessDelegatedRelationshipConfig,
    evidence: &EvidenceConfig,
) -> Result<(), EvidenceConfigError> {
    let allowed_claims: Vec<&ClaimDefinition> = relationship
        .allowed_claims
        .iter()
        .filter_map(|claim_id| evidence.claims.iter().find(|claim| claim.id == *claim_id))
        .collect();
    for purpose in &relationship.allowed_purposes {
        if !allowed_claims
            .iter()
            .any(|claim| claim.purpose.as_deref() == Some(purpose.as_str()))
        {
            return invalid_subject_access(format!(
                "subject_access.delegation allowed_purposes entry '{purpose}' is not used by any allowed claim"
            ));
        }
    }

    for format in &relationship.allowed_formats {
        let supported_by_claim = allowed_claims
            .iter()
            .any(|claim| claim.formats.iter().any(|candidate| candidate == format));
        if !supported_by_claim {
            return invalid_subject_access(format!(
                "subject_access.delegation allowed_formats entry '{format}' is not supported by any allowed claim"
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
        if !supported_by_claim {
            return invalid_subject_access(format!(
                "subject_access.delegation allowed_disclosures entry '{disclosure}' is not supported by any allowed claim"
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_required_scope_mappings(
    config: &SubjectAccessConfig,
    oidc: &EvidenceOidcAuthConfig,
) -> Result<(), EvidenceConfigError> {
    let required_scopes: HashSet<&str> =
        config.required_scopes.iter().map(String::as_str).collect();
    for scope in &required_scopes {
        if !oidc
            .scope_map
            .values()
            .any(|mapped_scopes| mapped_scopes.iter().any(|mapped| mapped == scope))
        {
            return invalid_subject_access(format!(
                "required scope '{scope}' must be present in auth.oidc.scope_map"
            ));
        }
    }

    Ok(())
}

pub(super) fn invalid_subject_access<T>(
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidSubjectAccessConfig {
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
