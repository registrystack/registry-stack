// SPDX-License-Identifier: Apache-2.0
//! Source matching and governed policy configuration.

use super::*;

pub(in crate::config) const SUPPORTED_ECOSYSTEM_BINDING_PROFILE: &str =
    "registry-notary/source-policy/v1";

pub(in crate::config) fn validate_source_matching_config(
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

pub(in crate::config) fn validate_ecosystem_binding_selector(
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

pub(in crate::config) fn select_ecosystem_binding<'a>(
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

pub(in crate::config) fn validate_ecosystem_binding_metadata(
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

pub(in crate::config) fn validate_supported_ecosystem_profile(
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

pub(in crate::config) fn validate_policy_hash(
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

pub(in crate::config) fn invalid_matching_config<T>(
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

pub(in crate::config) fn merge_vec_constraint(
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

pub(in crate::config) fn merge_option_constraint<T>(
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

pub(in crate::config) const fn default_collapse_matching_errors() -> bool {
    true
}
