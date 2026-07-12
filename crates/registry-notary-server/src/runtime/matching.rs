// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn source_observed_at_from_row(
    binding: &registry_notary_core::SourceBindingConfig,
    row: &Value,
) -> Result<Option<OffsetDateTime>, EvidenceError> {
    let Some(field) = binding.matching.source_observed_at_field.as_deref() else {
        return Ok(None);
    };
    let Some(value) = get_json_path(row, field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(EvidenceError::TargetMatchingPolicyRejected);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map(Some)
        .map_err(|_| EvidenceError::TargetMatchingPolicyRejected)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_matching_freshness_policy(
    evidence: &EvidenceConfig,
    binding: &registry_notary_core::SourceBindingConfig,
    source_capability: &SourceCapability,
    context: &EvidenceRequestContext,
    purpose: &str,
    trusted_policy: &TrustedPolicyContext,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    disclosure: DisclosureProfile,
    format: &str,
    source_observed_at: Option<OffsetDateTime>,
) -> Result<(), EvidenceError> {
    if binding.matching.max_source_age_seconds.is_none() {
        return Ok(());
    }
    let source_observed_age_seconds = source_observed_at.map(source_observed_age_seconds);
    matching_pdp_decision(
        evidence,
        binding,
        source_capability,
        context,
        purpose,
        trusted_policy,
        claim_purpose_constraints,
        allowed_disclosures,
        allowed_formats,
        disclosure,
        format,
        source_observed_age_seconds,
        true,
    )
    .map(|_| ())
}

pub(super) fn source_observed_age_seconds(source_observed_at: OffsetDateTime) -> u64 {
    let age = OffsetDateTime::now_utc() - source_observed_at;
    u64::try_from(age.whole_seconds().max(0)).unwrap_or(u64::MAX)
}

pub(super) fn validate_required_binding_fields(
    binding: &registry_notary_core::SourceBindingConfig,
    row: &Value,
) -> Result<(), EvidenceError> {
    for field in binding.fields.values().filter(|field| field.required) {
        match get_json_path(row, &field.field) {
            Some(value) if !value.is_null() => {}
            _ => return Err(EvidenceError::SourceNotFound),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BindingPolicyEffect {
    pub(super) redaction_fields: BTreeSet<String>,
    pub(super) audit: Option<PdpDecisionAudit>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_matching_policy(
    evidence: &EvidenceConfig,
    source_capability: &SourceCapability,
    claim_purpose_constraints: &[Vec<String>],
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
    trusted_policy: &TrustedPolicyContext,
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    requested_disclosure: DisclosureProfile,
    requested_format: &str,
) -> Result<BindingPolicyEffect, EvidenceError> {
    let matching = &binding.matching;
    if (context.on_behalf_of.is_some()
        && !matches!(
            source_capability.access_mode(),
            AccessMode::DelegatedAttestation
        ))
        || context.target.profile.is_some()
        || context
            .requester
            .as_ref()
            .is_some_and(|requester| requester.profile.is_some())
    {
        return Err(EvidenceError::ProfileUnsupported);
    }
    let binding_policy_effect = matching_pdp_decision(
        evidence,
        binding,
        source_capability,
        context,
        purpose,
        trusted_policy,
        claim_purpose_constraints,
        allowed_disclosures,
        allowed_formats,
        requested_disclosure,
        requested_format,
        None,
        false,
    )?;
    if let Some(target_type) = matching.target_type.as_deref() {
        if context.target.entity_type != target_type {
            return Err(EvidenceError::TargetMatchingPolicyRejected);
        }
    }
    if let Some(requester_type) = matching.requester_type.as_deref() {
        if context
            .requester
            .as_ref()
            .map(|requester| requester.entity_type.as_str())
            != Some(requester_type)
        {
            return Err(EvidenceError::RequesterMatchingPolicyRejected);
        }
    }
    if matching.require_requester_reauthentication {
        return Err(EvidenceError::RequesterReauthenticationRequired);
    }
    if !matching.allowed_relationships.is_empty()
        || !matching.relationship_purpose_scopes.is_empty()
    {
        let relationship_type = context
            .relationship
            .as_ref()
            .map(|relationship| relationship.relationship_type.as_str());
        let Some(relationship_type) = relationship_type else {
            return Err(EvidenceError::RelationshipNotEstablished);
        };
        if !matching
            .allowed_relationships
            .iter()
            .any(|allowed| allowed == relationship_type)
        {
            return Err(EvidenceError::RelationshipPolicyRejected);
        }
        if let Some(allowed_purposes) = matching.relationship_purpose_scopes.get(relationship_type)
        {
            if !allowed_purposes.iter().any(|allowed| allowed == purpose) {
                return Err(EvidenceError::RelationshipPurposeNotAllowed);
            }
        }
    }
    if !matching.sufficient_target_inputs.is_empty()
        && !matching.sufficient_target_inputs.iter().any(|group| {
            group
                .iter()
                .all(|path| context.lookup_value(path.as_str()).is_some())
        })
    {
        let missing = matching
            .sufficient_target_inputs
            .iter()
            .flat_map(|group| group.iter())
            .find(|path| context.lookup_value(path.as_str()).is_none())
            .map(String::as_str)
            .unwrap_or("target.attributes");
        return Err(missing_context_error(missing));
    }
    if !matching.allowed_target_inputs.is_empty() {
        for path in present_entity_paths("target", &context.target) {
            if !path_allowed(path.as_str(), &matching.allowed_target_inputs) {
                return Err(EvidenceError::TargetMatchingPolicyRejected);
            }
        }
    }
    if !matching.allowed_requester_inputs.is_empty() {
        if let Some(requester) = &context.requester {
            for path in present_entity_paths("requester", requester) {
                if !path_allowed(path.as_str(), &matching.allowed_requester_inputs) {
                    return Err(EvidenceError::RequesterMatchingPolicyRejected);
                }
            }
        }
    }
    Ok(binding_policy_effect)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn matching_pdp_decision(
    evidence: &EvidenceConfig,
    binding: &registry_notary_core::SourceBindingConfig,
    source_capability: &SourceCapability,
    context: &EvidenceRequestContext,
    purpose: &str,
    trusted_policy: &TrustedPolicyContext,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    requested_disclosure: DisclosureProfile,
    requested_format: &str,
    source_observed_age_seconds: Option<u64>,
    enforce_freshness: bool,
) -> Result<BindingPolicyEffect, EvidenceError> {
    let matching = &binding.matching;
    let selected_policy = selected_evidence_pack_policy(evidence, binding);
    let policy_identity = matching_policy_audit_identity(evidence, binding);
    let rule_ids_by_gate = pdp_rule_ids_by_gate(
        policy_identity
            .evaluated_rule_ids
            .first()
            .map(String::as_str)
            .unwrap_or("source-binding-policy"),
    );
    let pdp_context = PdpRequestContext {
        purpose: purpose.to_string(),
        legal_basis_ref: trusted_policy.legal_basis_ref.clone(),
        consent_ref: trusted_policy.consent_ref.clone(),
        asserted_assurance: matching_context_assurance(context, trusted_policy),
        jurisdiction: matching_context_jurisdiction(context, trusted_policy),
        requester_identity: matching_context_requester_identity(context),
        subject_ref: matching_context_subject_ref(context),
        relationship: context
            .relationship
            .as_ref()
            .map(|relationship| relationship.relationship_type.clone()),
        on_behalf_of: context
            .on_behalf_of
            .as_ref()
            .map(|delegation| delegation.actor.id_hash.clone()),
        requested_fact: Some(binding.entity.clone()),
        requested_disclosure: Some(requested_disclosure.as_str().to_string()),
        requested_credential_format: Some(requested_format.to_string()),
        source_binding: Some(source_binding_policy_key(binding)),
        route_identity: Some("registry-notary.evaluate".to_string()),
        checked_scopes: trusted_policy.checked_scopes.clone(),
        source_observed_at_unix_seconds: None,
        source_observed_age_seconds,
    };
    let mut purpose_constraints = claim_purpose_constraints.to_vec();
    if !matching.allowed_purposes.is_empty() {
        purpose_constraints.push(matching.allowed_purposes.clone());
    }
    let policy = PdpPolicyInput {
        policy_id: policy_identity.policy_id.clone(),
        policy_hash: policy_identity.policy_hash.clone(),
        ecosystem_binding_id: policy_identity.ecosystem_binding_id.clone(),
        ecosystem_binding_version: policy_identity.ecosystem_binding_version.clone(),
        rule_ids: policy_identity.evaluated_rule_ids.clone(),
        rule_ids_by_gate,
        permit_unconstrained: false,
        required_context: Default::default(),
        odrl_constraint_terms: odrl_terms_for_matching_policy(matching, &purpose_constraints),
        purpose_constraints,
        permitted_jurisdictions: matching.permitted_jurisdictions.clone(),
        allowed_assurance: matching.allowed_assurance.clone(),
        minimum_assurance: matching.minimum_assurance.clone(),
        max_source_age_seconds: if enforce_freshness {
            matching.max_source_age_seconds
        } else {
            None
        },
        require_legal_basis: matching.require_legal_basis,
        require_consent: matching.require_consent,
        allowed_legal_basis_refs: matching.allowed_legal_basis_refs.clone(),
        allowed_consent_refs: matching.allowed_consent_refs.clone(),
        redaction_fields: matching.redaction_fields.iter().cloned().collect(),
        allowed_relationships: matching.allowed_relationships.clone(),
        relationship_purpose_constraints: matching
            .relationship_purpose_scopes
            .iter()
            .map(
                |(relationship, allowed_purposes)| PdpRelationshipPurposeConstraint {
                    relationship: relationship.clone(),
                    allowed_purposes: allowed_purposes.clone(),
                },
            )
            .collect(),
        allowed_requested_facts: vec![binding.entity.clone()],
        allowed_requested_disclosures: allowed_disclosures.to_vec(),
        allowed_credential_formats: allowed_formats.to_vec(),
        allowed_source_bindings: vec![source_binding_policy_key(binding)],
        allowed_route_identities: vec!["registry-notary.evaluate".to_string()],
        required_checked_scopes: required_checked_scopes_for_binding(binding, source_capability),
        unsupported_odrl_terms: selected_policy
            .as_ref()
            .map(|policy| policy.unsupported_odrl_terms.clone())
            .unwrap_or_default(),
    };
    match pdp_decide(&pdp_context, &policy) {
        PdpDecision::Permit(audit) => Ok(BindingPolicyEffect {
            audit: Some(audit),
            ..BindingPolicyEffect::default()
        }),
        PdpDecision::PermitWithRedaction {
            audit, field_set, ..
        } => Ok(BindingPolicyEffect {
            redaction_fields: field_set,
            audit: Some(audit),
        }),
        PdpDecision::Deny {
            stable_problem_code,
            audit,
        } => Err(pdp_denial_error(
            known_stable_code(&stable_problem_code).unwrap_or("pdp.denied"),
            audit,
        )),
    }
}

pub(super) fn matching_context_requester_identity(
    context: &EvidenceRequestContext,
) -> Option<String> {
    let requester = context.requester.as_ref()?;
    requester.id.clone().or_else(|| {
        requester
            .identifiers
            .first()
            .map(|identifier| identifier.scheme.clone())
    })
}

pub(super) fn matching_context_subject_ref(context: &EvidenceRequestContext) -> Option<String> {
    context.target.id.clone().or_else(|| {
        context
            .target
            .identifiers
            .first()
            .map(|identifier| identifier.scheme.clone())
    })
}

pub(super) fn source_binding_policy_key(
    binding: &registry_notary_core::SourceBindingConfig,
) -> String {
    format!(
        "{}:{}:{}",
        binding.connection.as_deref().unwrap_or("default"),
        binding.dataset,
        binding.entity
    )
}

pub(super) fn required_checked_scopes_for_binding(
    binding: &registry_notary_core::SourceBindingConfig,
    source_capability: &SourceCapability,
) -> BTreeSet<String> {
    if !matches!(source_capability, SourceCapability::Machine { .. }) {
        return BTreeSet::new();
    }
    binding
        .required_scope
        .iter()
        .filter(|scope| !scope.trim().is_empty())
        .cloned()
        .collect()
}

pub(super) fn odrl_terms_for_matching_policy(
    matching: &registry_notary_core::SourceMatchingConfig,
    purpose_constraints: &[Vec<String>],
) -> Vec<String> {
    let mut terms = Vec::new();
    if !purpose_constraints.is_empty() {
        terms.push("odrl:purpose".to_string());
    }
    if !matching.permitted_jurisdictions.is_empty() {
        terms.push("odrl:spatial".to_string());
    }
    terms.sort();
    terms.dedup();
    terms
}

pub(super) fn pdp_denial_error(code: &'static str, audit: PdpDecisionAudit) -> EvidenceError {
    EvidenceError::PolicyDenied {
        code,
        policy_id: Some(audit.policy_id),
        policy_hash: Some(audit.policy_hash),
        evaluated_rule_ids: audit.evaluated_rule_ids,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatchingPolicyAuditIdentity {
    pub policy_id: String,
    pub policy_hash: String,
    pub ecosystem_binding_id: Option<String>,
    pub ecosystem_binding_version: Option<String>,
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
    pub evaluated_rule_ids: Vec<String>,
}

pub(crate) fn matching_policy_audit_identity(
    evidence: &EvidenceConfig,
    binding: &registry_notary_core::SourceBindingConfig,
) -> MatchingPolicyAuditIdentity {
    let selected_policy = selected_evidence_pack_policy(evidence, binding);
    MatchingPolicyAuditIdentity {
        policy_id: selected_policy
            .as_ref()
            .map(|policy| policy.policy_id.clone())
            .unwrap_or_else(|| matching_purpose_policy_id(binding)),
        policy_hash: selected_policy
            .as_ref()
            .map(|policy| policy.policy_hash.clone())
            .unwrap_or_else(|| matching_purpose_policy_hash(binding)),
        ecosystem_binding_id: selected_policy
            .as_ref()
            .and_then(|policy| policy.ecosystem_binding_id.clone()),
        ecosystem_binding_version: selected_policy
            .as_ref()
            .and_then(|policy| policy.ecosystem_binding_version.clone()),
        pack_id: selected_policy
            .as_ref()
            .and_then(|policy| policy.pack_id.clone()),
        pack_version: selected_policy
            .as_ref()
            .and_then(|policy| policy.pack_version.clone()),
        evaluated_rule_ids: vec![format!("source-binding-policy:{}", binding.entity)],
    }
}

#[derive(Debug, Clone)]
pub(super) struct SelectedEvidencePackPolicy {
    pub(super) policy_id: String,
    pub(super) policy_hash: String,
    pub(super) ecosystem_binding_id: Option<String>,
    pub(super) ecosystem_binding_version: Option<String>,
    pub(super) pack_id: Option<String>,
    pub(super) pack_version: Option<String>,
    pub(super) unsupported_odrl_terms: Vec<String>,
}

pub(super) fn selected_evidence_pack_policy(
    evidence: &EvidenceConfig,
    binding: &registry_notary_core::SourceBindingConfig,
) -> Option<SelectedEvidencePackPolicy> {
    let selector = binding.matching.ecosystem_binding.as_ref()?;
    if let (Some(policy_id), Some(policy_hash)) =
        (selector.policy_id.as_ref(), selector.policy_hash.as_ref())
    {
        return Some(SelectedEvidencePackPolicy {
            policy_id: policy_id.clone(),
            policy_hash: policy_hash.clone(),
            ecosystem_binding_id: selector.id.clone(),
            ecosystem_binding_version: selector
                .id
                .as_deref()
                .and_then(ecosystem_binding_version_from_id),
            pack_id: selector.pack_id.clone().or_else(|| selector.id.clone()),
            pack_version: selector.pack_version.clone().or_else(|| {
                selector
                    .id
                    .as_deref()
                    .and_then(ecosystem_binding_version_from_id)
            }),
            unsupported_odrl_terms: selector.unsupported_odrl_terms.clone(),
        });
    }
    if let Some(id) = selector.id.as_deref() {
        let metadata = evidence.ecosystem_bindings.get(id)?;
        return Some(SelectedEvidencePackPolicy {
            policy_id: metadata.policy_id.clone(),
            policy_hash: metadata.policy_hash.clone(),
            ecosystem_binding_id: Some(id.to_string()),
            ecosystem_binding_version: ecosystem_binding_version_from_id(id),
            pack_id: selector.pack_id.clone().or_else(|| Some(id.to_string())),
            pack_version: selector
                .pack_version
                .clone()
                .or_else(|| ecosystem_binding_version_from_id(id)),
            unsupported_odrl_terms: metadata.unsupported_odrl_terms.clone(),
        });
    }
    let profile = selector.profile.as_deref()?;
    let (id, metadata) = evidence
        .ecosystem_bindings
        .iter()
        .find(|(_, candidate)| candidate.profile.as_deref() == Some(profile))?;
    Some(SelectedEvidencePackPolicy {
        policy_id: metadata.policy_id.clone(),
        policy_hash: metadata.policy_hash.clone(),
        ecosystem_binding_id: Some(id.clone()),
        ecosystem_binding_version: ecosystem_binding_version_from_id(id),
        pack_id: selector.pack_id.clone().or_else(|| Some(id.clone())),
        pack_version: selector
            .pack_version
            .clone()
            .or_else(|| ecosystem_binding_version_from_id(id)),
        unsupported_odrl_terms: metadata.unsupported_odrl_terms.clone(),
    })
}

pub(super) fn ecosystem_binding_version_from_id(id: &str) -> Option<String> {
    let (_, version) = id.rsplit_once('/')?;
    let version = version.trim();
    (!version.is_empty()).then(|| version.to_string())
}

pub(super) fn matching_context_assurance(
    _context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
) -> Option<String> {
    trusted_policy.assurance_level.clone()
}

pub(super) fn matching_context_jurisdiction(
    _context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
) -> Option<String> {
    trusted_policy.jurisdiction.clone()
}

pub(super) fn matching_purpose_policy_id(
    binding: &registry_notary_core::SourceBindingConfig,
) -> String {
    binding.matching.policy_id.clone().unwrap_or_else(|| {
        format!(
            "notary.source_binding.{}.{}.{}",
            binding
                .connection
                .as_deref()
                .filter(|connection| !connection.trim().is_empty())
                .unwrap_or("default"),
            binding.dataset,
            binding.entity
        )
    })
}

pub(super) fn matching_purpose_policy_hash(
    binding: &registry_notary_core::SourceBindingConfig,
) -> String {
    let material = serde_json::json!({
        "connection": binding.connection,
        "dataset": binding.dataset,
        "entity": binding.entity,
        "policy_id": binding.matching.policy_id,
        "allowed_purposes": binding.matching.allowed_purposes,
        "allowed_assurance": binding.matching.allowed_assurance,
        "minimum_assurance": binding.matching.minimum_assurance,
        "permitted_jurisdictions": binding.matching.permitted_jurisdictions,
        "allowed_legal_basis_refs": binding.matching.allowed_legal_basis_refs,
        "allowed_consent_refs": binding.matching.allowed_consent_refs,
        "max_source_age_seconds": binding.matching.max_source_age_seconds,
        "source_observed_at_field": binding.matching.source_observed_at_field,
        "require_legal_basis": binding.matching.require_legal_basis,
        "require_consent": binding.matching.require_consent,
        "redaction_fields": binding.matching.redaction_fields,
    });
    hash_json(&material)
        .map(|hash| format!("sha256:{hash}"))
        .unwrap_or_else(|_| {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
        })
}

pub(super) fn minimized_context_for_binding(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> EvidenceRequestContext {
    let mut paths = BTreeSet::new();
    paths.insert(binding.lookup.input.clone());
    for query_field in &binding.query_fields {
        paths.insert(query_field.input.clone());
    }
    for group in &binding.matching.sufficient_target_inputs {
        for path in group {
            paths.insert(path.clone());
        }
    }
    for path in present_entity_paths("target", &context.target) {
        if binding.matching.allowed_target_inputs.is_empty()
            || path_allowed(path.as_str(), &binding.matching.allowed_target_inputs)
        {
            paths.insert(path);
        }
    }
    if let Some(requester) = &context.requester {
        for path in present_entity_paths("requester", requester) {
            if binding.matching.allowed_requester_inputs.is_empty()
                || path_allowed(path.as_str(), &binding.matching.allowed_requester_inputs)
            {
                paths.insert(path);
            }
        }
    }
    if paths.is_empty()
        && binding.matching.allowed_target_inputs.is_empty()
        && binding.matching.allowed_requester_inputs.is_empty()
        && binding.matching.sufficient_target_inputs.is_empty()
    {
        return context.clone();
    }

    EvidenceRequestContext {
        requester: context
            .requester
            .as_ref()
            .and_then(|requester| minimized_entity("requester", requester, &paths)),
        target: minimized_entity("target", &context.target, &paths)
            .unwrap_or_else(|| EvidenceEntity::new(context.target.entity_type.clone())),
        relationship: context.relationship.as_ref().map(|relationship| {
            let mut minimized = registry_notary_core::EvidenceRelationship {
                relationship_type: relationship.relationship_type.clone(),
                attributes: BTreeMap::new(),
            };
            for path in &paths {
                if let Some(key) = path.strip_prefix("relationship.attributes.") {
                    if let Some(value) = relationship.attributes.get(key) {
                        minimized.attributes.insert(key.to_string(), value.clone());
                    }
                }
            }
            minimized
        }),
        on_behalf_of: None,
        variables: context.variables.clone(),
    }
}

pub(super) fn minimized_entity(
    prefix: &str,
    entity: &EvidenceEntity,
    paths: &BTreeSet<String>,
) -> Option<EvidenceEntity> {
    let mut minimized = EvidenceEntity::new(entity.entity_type.clone());
    let id_path = format!("{prefix}.id");
    if paths.contains(&id_path) {
        minimized.id = entity.id.clone();
    }
    for identifier in &entity.identifiers {
        let path = format!("{prefix}.identifiers.{}", identifier.scheme);
        if paths.contains(&path) {
            minimized.identifiers.push(identifier.clone());
        }
    }
    let attribute_prefix = format!("{prefix}.attributes.");
    for path in paths {
        if let Some(key) = path.strip_prefix(attribute_prefix.as_str()) {
            if key == "*" {
                minimized.attributes.extend(entity.attributes.clone());
            } else if let Some(value) = entity.attributes.get(key) {
                minimized.attributes.insert(key.to_string(), value.clone());
            }
        }
    }
    if minimized.id.is_none() && minimized.identifiers.is_empty() && minimized.attributes.is_empty()
    {
        None
    } else {
        Some(minimized)
    }
}

pub(super) fn collapse_matching_error(
    binding: &registry_notary_core::SourceBindingConfig,
    error: EvidenceError,
) -> EvidenceError {
    if !binding.matching.collapse_matching_errors {
        return error;
    }
    match error {
        matching_error @ (EvidenceError::SourceNotFound
        | EvidenceError::SourceAmbiguous
        | EvidenceError::TargetIdentifierMissing
        | EvidenceError::TargetAttributesInsufficient
        | EvidenceError::TargetMatchingPolicyRejected
        | EvidenceError::TargetNotInValidState
        | EvidenceError::TargetMatchLowConfidence
        | EvidenceError::RequesterNotFound
        | EvidenceError::RequesterMatchAmbiguous
        | EvidenceError::RequesterIdentifierMissing
        | EvidenceError::RequesterAttributesInsufficient
        | EvidenceError::RequesterMatchingPolicyRejected
        | EvidenceError::RequesterReauthenticationRequired
        | EvidenceError::RelationshipNotEstablished
        | EvidenceError::RelationshipMatchAmbiguous
        | EvidenceError::RelationshipAttributesInsufficient
        | EvidenceError::RelationshipPolicyRejected
        | EvidenceError::RelationshipPurposeNotAllowed) => {
            EvidenceError::MatchingEvidenceNotAvailable {
                audit_code: matching_error.audit_code(),
            }
        }
        other => other,
    }
}

/// Collapse errors raised while resolving a binding's *dependent* lookup
/// context (see `binding_with_resolved_source_lookup_context`).
///
/// The source read path routes its matching errors through
/// `collapse_matching_error`; this resolution stage needs a separate helper
/// because it can additionally surface `EvidenceError::InvalidRequest` when a
/// prior source field is non-scalar (`scalar_source_lookup_value`). That
/// condition is a function of upstream row data the client is not authorized to
/// observe, so it must collapse to the generic `evidence.not_available` while
/// retaining the specific `audit_code` for operators. Config-deterministic
/// failures (unknown binding, dependency cycle) are rejected before any read is
/// spawned and never reach here, so collapsing every `InvalidRequest` at this
/// call site cannot mask a genuine client request error. The
/// `collapse_matching_errors` guard intentionally gates the `InvalidRequest`
/// branch too: when collapse is disabled the raw error is preserved.
pub(super) fn collapse_dependent_lookup_error(
    binding: &registry_notary_core::SourceBindingConfig,
    error: EvidenceError,
) -> EvidenceError {
    if !binding.matching.collapse_matching_errors {
        return error;
    }
    if matches!(error, EvidenceError::InvalidRequest) {
        return EvidenceError::MatchingEvidenceNotAvailable {
            audit_code: error.audit_code(),
        };
    }
    collapse_matching_error(binding, error)
}

pub(super) fn present_entity_paths(prefix: &str, entity: &EvidenceEntity) -> Vec<String> {
    let mut paths = Vec::new();
    if entity.id.is_some() {
        paths.push(format!("{prefix}.id"));
    }
    for identifier in &entity.identifiers {
        paths.push(format!("{prefix}.identifiers.{}", identifier.scheme));
    }
    for key in entity.attributes.keys() {
        paths.push(format!("{prefix}.attributes.{key}"));
    }
    paths
}

pub(super) fn path_allowed(path: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|candidate| {
        candidate == path
            || candidate.strip_suffix(".*").is_some_and(|prefix| {
                path.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
            })
    })
}

pub(super) fn claim_matching_metadata(
    evidence: &EvidenceConfig,
    claim: &ClaimDefinition,
    audit: Option<&MatchingPolicyAudit>,
) -> Option<MatchingMetadata> {
    claim
        .source_bindings
        .iter()
        .find_map(|(binding_id, binding)| {
            let matching = &binding.matching;
            let selected_policy = selected_evidence_pack_policy(evidence, binding);
            let binding_audit = audit.and_then(|audit| audit.for_binding(binding_id));
            let policy_id = selected_policy
                .as_ref()
                .map(|policy| policy.policy_id.as_str())
                .or(matching.policy_id.as_deref())
                .map(str::to_string)
                .or_else(|| binding_audit.map(|audit| audit.policy_id.clone()))?;
            Some(MatchingMetadata {
                policy_id,
                method: matching
                    .method
                    .clone()
                    .unwrap_or_else(|| "configured_lookup".to_string()),
                confidence: matching
                    .confidence
                    .clone()
                    .unwrap_or_else(|| "high".to_string()),
                score: None,
                policy_hash: binding_audit.map(|audit| audit.policy_hash.clone()),
                evaluated_rule_ids: binding_audit
                    .map(BindingMatchingPolicyAudit::rule_ids)
                    .unwrap_or_default(),
                ecosystem_binding_id: selected_policy
                    .as_ref()
                    .and_then(|policy| policy.ecosystem_binding_id.clone()),
                ecosystem_binding_version: selected_policy
                    .as_ref()
                    .and_then(|policy| policy.ecosystem_binding_version.clone()),
                pack_id: selected_policy
                    .as_ref()
                    .and_then(|policy| policy.pack_id.clone()),
                pack_version: selected_policy
                    .as_ref()
                    .and_then(|policy| policy.pack_version.clone()),
            })
        })
}
