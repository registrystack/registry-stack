// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn principal_can_see_claim<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> bool {
    source
        .required_scopes_for_claim(evidence, claim)
        .is_ok_and(|scopes| scopes.iter().all(|scope| principal.has_scope(scope)))
}

pub(super) fn require_claim_access<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> Result<(), EvidenceError> {
    if principal.is_self_attestation() {
        return Ok(());
    }
    for scope in source.required_scopes_for_claim(evidence, claim)? {
        if !principal.has_scope(&scope) {
            return Err(EvidenceError::ScopeDenied { required: scope });
        }
    }
    Ok(())
}

pub(super) fn source_capability_for_principal(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    principal: &EvidencePrincipal,
    requested_claims: &[String],
) -> Result<SourceCapability, EvidenceError> {
    match principal.access_mode() {
        AccessMode::MachineClient => Ok(SourceCapability::Machine {
            scopes: principal.scopes.iter().cloned().collect(),
        }),
        AccessMode::SelfAttestation => {
            if requested_claims.is_empty() {
                return Err(EvidenceError::SelfAttestationDenied {
                    reason: SelfAttestationDenialCode::ClaimDenied,
                });
            }
            let mut allowed_claim_ids = BTreeSet::new();
            for claim_id in requested_claims {
                allowed_claim_ids.insert(
                    BoundedClaimId::new(claim_id.clone())
                        .map_err(|_| EvidenceError::InvalidRequest)?,
                );
            }
            let claim_id = if requested_claims.len() == 1 {
                allowed_claim_ids.iter().next().cloned()
            } else {
                None
            };
            let claims =
                principal
                    .verified_claims
                    .as_ref()
                    .ok_or(EvidenceError::SelfAttestationDenied {
                        reason: SelfAttestationDenialCode::SubjectClaimMissing,
                    })?;
            let subject_binding_value = claims.subject_binding_value.as_ref().ok_or(
                EvidenceError::SelfAttestationDenied {
                    reason: SelfAttestationDenialCode::SubjectClaimMissing,
                },
            )?;
            let subject_binding_hash = self_attestation_rate_keys
                .subject_binding(subject_binding_value.as_str())
                .map_err(|error| error.evidence_error())?;
            Ok(SourceCapability::SelfAttestation {
                claim_id,
                allowed_claim_ids,
                subject_binding_hash,
            })
        }
        AccessMode::DelegatedAttestation => Err(delegated_attestation_denied()),
        AccessMode::Unknown => Err(EvidenceError::SelfAttestationInvalidToken),
    }
}

pub(super) fn ensure_source_capability_matches_principal(
    principal: &EvidencePrincipal,
    capability: &SourceCapability,
) -> Result<(), EvidenceError> {
    match (principal.access_mode(), capability.access_mode()) {
        (AccessMode::MachineClient, AccessMode::MachineClient)
        | (AccessMode::SelfAttestation, AccessMode::SelfAttestation)
        | (AccessMode::DelegatedAttestation, AccessMode::DelegatedAttestation) => Ok(()),
        (AccessMode::SelfAttestation, AccessMode::MachineClient) => {
            Err(EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied,
            })
        }
        (AccessMode::DelegatedAttestation, AccessMode::MachineClient) => {
            Err(delegated_attestation_denied())
        }
        _ => Err(EvidenceError::SelfAttestationInvalidToken),
    }
}

pub(super) fn require_source_read_capability(
    capability: &SourceCapability,
    claim_id: &str,
) -> Result<(), EvidenceError> {
    match capability {
        SourceCapability::Machine { .. } => Ok(()),
        SourceCapability::SelfAttestation { .. }
            if capability.allows_self_attestation_claim(claim_id) =>
        {
            Ok(())
        }
        SourceCapability::DelegatedAttestation { .. }
            if capability.allows_delegated_claim(claim_id) =>
        {
            Ok(())
        }
        SourceCapability::SelfAttestation { .. } => Err(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied,
        }),
        SourceCapability::DelegatedAttestation { .. } => Err(delegated_attestation_denied()),
    }
}

pub(super) fn require_machine_source_capability(
    capability: &SourceCapability,
) -> Result<(), EvidenceError> {
    match capability {
        SourceCapability::Machine { .. } => Ok(()),
        SourceCapability::SelfAttestation { .. }
        | SourceCapability::DelegatedAttestation { .. } => {
            Err(EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied,
            })
        }
    }
}

pub(super) fn delegated_attestation_denied() -> EvidenceError {
    EvidenceError::SelfAttestationDenied {
        reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
    }
}

pub(super) fn delegated_relationship_unproven() -> EvidenceError {
    EvidenceError::SelfAttestationDenied {
        reason: SelfAttestationDenialCode::DelegatedRelationshipUnproven,
    }
}

pub(super) fn delegated_proof_denied() -> EvidenceError {
    EvidenceError::SelfAttestationDenied {
        reason: SelfAttestationDenialCode::DelegatedProofDenied,
    }
}

pub(super) fn ensure_delegated_capability_context_binding(
    ctx: &ClaimEvaluationContext,
) -> Result<(), EvidenceError> {
    let SourceCapability::DelegatedAttestation {
        requester_subject_binding_hash,
        dependent_target_hash,
        ..
    } = &ctx.source_capability
    else {
        return Ok(());
    };
    let requester_subject = ctx
        .context
        .requester
        .as_ref()
        .and_then(EvidenceEntity::to_subject_request)
        .ok_or_else(delegated_attestation_denied)?;
    let target_subject = ctx
        .context
        .target_subject()
        .ok_or_else(delegated_attestation_denied)?;
    // Re-derive the bindings over the (id_type, id) pair so they bind the
    // subject scheme as well as the value. The id_types are pinned upstream
    // (requester via subject_binding.id_type, target via the relationship's
    // delegated_target_id_type); a missing id_type fails closed.
    let requester_id_type = requester_subject
        .id_type
        .as_deref()
        .ok_or_else(delegated_attestation_denied)?;
    let target_id_type = target_subject
        .id_type
        .as_deref()
        .ok_or_else(delegated_attestation_denied)?;
    let requester_hash = ctx
        .self_attestation_rate_keys
        .delegated_subject_binding(requester_id_type, requester_subject.id.as_str())
        .map_err(|error| error.evidence_error())?;
    let target_hash = ctx
        .self_attestation_rate_keys
        .delegated_subject_binding(target_id_type, target_subject.id.as_str())
        .map_err(|error| error.evidence_error())?;
    if &requester_hash != requester_subject_binding_hash || &target_hash != dependent_target_hash {
        return Err(delegated_attestation_denied());
    }
    Ok(())
}

pub(super) fn resolve_purpose(
    header: Option<&str>,
    body: Option<&str>,
) -> Result<String, EvidenceError> {
    match (header, body) {
        (Some(header), Some(body)) if header != body => Err(EvidenceError::InvalidRequest),
        (Some(header), _) if !header.trim().is_empty() => Ok(header.to_string()),
        (_, Some(body)) if !body.trim().is_empty() => Ok(body.to_string()),
        (Some(_), _) | (_, Some(_)) => Err(EvidenceError::InvalidRequest),
        _ => Err(EvidenceError::PurposeRequired),
    }
}

pub(super) fn resolve_batch_default_purpose(
    header: Option<&str>,
    body: Option<&str>,
) -> Result<Option<String>, EvidenceError> {
    match (header, body) {
        (Some(header), Some(body)) if header != body => Err(EvidenceError::InvalidRequest),
        (Some(header), _) if !header.trim().is_empty() => Ok(Some(header.to_string())),
        (_, Some(body)) if !body.trim().is_empty() => Ok(Some(body.to_string())),
        (Some(_), _) | (_, Some(_)) => Err(EvidenceError::InvalidRequest),
        _ => Ok(None),
    }
}

pub(super) fn resolve_batch_subject_purposes(
    subjects: &[registry_notary_core::BatchEvaluateItemRequest],
    batch_default: Option<&str>,
) -> Result<Vec<String>, EvidenceError> {
    subjects
        .iter()
        .map(|subject| match subject.purpose.as_deref() {
            Some(purpose)
                if batch_default.is_some_and(|batch_default| batch_default != purpose) =>
            {
                Err(EvidenceError::InvalidRequest)
            }
            Some(purpose) if !purpose.trim().is_empty() => Ok(purpose.to_string()),
            Some(_) => Err(EvidenceError::InvalidRequest),
            None => batch_default
                .map(str::to_string)
                .ok_or(EvidenceError::PurposeRequired),
        })
        .collect()
}

pub(super) fn validate_batch_inputs_and_collect_purposes<'a>(
    subjects: &'a [registry_notary_core::BatchEvaluateItemRequest],
    subject_purposes: &'a [String],
) -> Result<BTreeSet<&'a str>, EvidenceError> {
    let mut unique_purposes = BTreeSet::new();
    for (item, purpose) in subjects.iter().zip(subject_purposes) {
        if !item.target.has_matching_input() {
            return Err(EvidenceError::TargetAttributesInsufficient);
        }
        unique_purposes.insert(purpose.as_str());
    }
    Ok(unique_purposes)
}

pub(super) fn require_purpose_allowed(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    purpose: &str,
) -> Result<(), EvidenceError> {
    for claim_ref in claims {
        let claim = find_claim_for_selection(config, claim_ref, claim_versions)?;
        if !claim.source_bindings.is_empty() {
            continue;
        }
        if !config.allowed_purposes.is_empty()
            && !config
                .allowed_purposes
                .iter()
                .any(|allowed| allowed == purpose)
        {
            return Err(EvidenceError::PurposeNotAllowed);
        }
        if claim
            .purpose
            .as_deref()
            .is_some_and(|allowed| allowed != purpose)
        {
            return Err(EvidenceError::PurposeNotAllowed);
        }
    }
    Ok(())
}

pub(super) fn claim_purpose_constraints(
    evidence: &EvidenceConfig,
    claim: &ClaimDefinition,
) -> PurposeConstraints {
    let mut constraints = Vec::new();
    if !evidence.allowed_purposes.is_empty() {
        constraints.push(evidence.allowed_purposes.clone());
    }
    if let Some(purpose) = claim
        .purpose
        .as_deref()
        .filter(|purpose| !purpose.is_empty())
    {
        constraints.push(vec![purpose.to_string()]);
    }
    constraints
}

pub(super) fn require_claim_format(
    evidence: &EvidenceConfig,
    claim_id: &str,
    format: &str,
) -> Result<(), EvidenceError> {
    let claim = find_claim(evidence, claim_id)?;
    if claim.formats.iter().any(|candidate| candidate == format) {
        Ok(())
    } else {
        Err(EvidenceError::FormatUnsupported)
    }
}

pub(super) fn requested_disclosure(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    requested: &Option<String>,
) -> Result<DisclosureProfile, EvidenceError> {
    let raw = requested
        .as_deref()
        .or_else(|| {
            claims
                .first()
                .and_then(|claim| find_claim_for_selection(config, claim, claim_versions).ok())
                .map(|claim| claim.disclosure.default.as_str())
        })
        .unwrap_or("redacted");
    DisclosureProfile::parse(raw).ok_or(EvidenceError::InvalidRequest)
}

pub(super) fn validate_requested_disclosure_before_source(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    disclosure: DisclosureProfile,
) -> Result<(), EvidenceError> {
    for claim_ref in claims {
        let claim = find_claim_for_selection(config, claim_ref, claim_versions)?;
        if claim
            .disclosure
            .allowed
            .iter()
            .any(|candidate| candidate == disclosure.as_str())
        {
            continue;
        }
        let downgraded = match DisclosureDowngrade::parse(&claim.disclosure.downgrade)
            .ok_or(EvidenceError::InvalidRequest)?
        {
            DisclosureDowngrade::Default => DisclosureProfile::parse(&claim.disclosure.default)
                .ok_or(EvidenceError::InvalidRequest)?,
            DisclosureDowngrade::Redacted => DisclosureProfile::Redacted,
            DisclosureDowngrade::Deny => return Err(EvidenceError::DisclosureNotAllowed),
        };
        if !claim
            .disclosure
            .allowed
            .iter()
            .any(|candidate| candidate == downgraded.as_str())
        {
            return Err(EvidenceError::DisclosureNotAllowed);
        }
    }
    Ok(())
}

pub(super) fn max_batch_subjects(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
) -> Result<usize, EvidenceError> {
    let mut max = config.inline_batch_limit;
    for claim_id in claims {
        let claim = find_claim_for_selection(config, claim_id, claim_versions)?;
        if !claim.operations.batch_evaluate.enabled {
            return Err(EvidenceError::OperationUnsupported);
        }
        max = max.min(claim.operations.batch_evaluate.max_subjects);
    }
    Ok(max)
}

pub(super) struct SourceScopedTrustedPolicyRequest<'a> {
    pub(super) evidence: &'a EvidenceConfig,
    pub(super) claim: &'a ClaimDefinition,
    pub(super) source_capability: &'a SourceCapability,
    pub(super) context: &'a EvidenceRequestContext,
    pub(super) trusted_policy: &'a TrustedPolicyContext,
    pub(super) purpose: &'a str,
    pub(super) disclosure: DisclosureProfile,
    pub(super) format: &'a str,
}

pub(super) fn source_scoped_trusted_policy(
    request: SourceScopedTrustedPolicyRequest<'_>,
) -> Result<TrustedPolicyContext, EvidenceError> {
    if !claim_source_policy_uses_authorization_details(request.claim) {
        return Ok(request.trusted_policy.clone());
    }
    let Some(details) = request.trusted_policy.authorization_details.as_ref() else {
        return Ok(request.trusted_policy.clone());
    };
    if !crate::authz_details::has_transaction_scope(details) {
        return Ok(request.trusted_policy.clone());
    }
    let expected_claims = [ClaimRef::with_version(
        &request.claim.id,
        &request.claim.version,
    )];
    let subject = source_authorization_subject_expectation(
        request.trusted_policy,
        request.context,
        request.source_capability,
    )?;
    let target =
        source_authorization_target_expectation(request.context, request.source_capability)?;
    crate::authz_details::validate_scoped_authorization_details(
        details,
        &crate::authz_details::ScopedAuthorizationRequest {
            service_id: &request.evidence.service_id,
            action: "evaluate",
            claims: &expected_claims,
            disclosure: request.disclosure.as_str(),
            format: request.format,
            purpose: request.purpose,
            access_mode: trusted_policy_access_mode(
                request.trusted_policy,
                request.source_capability,
            ),
            subject,
            target,
            allow_subset_claims: true,
            allowed_claims: Some(&request.trusted_policy.request_claims),
        },
    )
    .map_err(|_| EvidenceError::TargetMatchingPolicyRejected)?;
    Ok(request.trusted_policy.clone())
}

pub(super) fn claim_source_policy_uses_authorization_details(claim: &ClaimDefinition) -> bool {
    claim
        .source_bindings
        .values()
        .any(binding_policy_uses_authorization_details)
}

pub(super) fn binding_policy_uses_authorization_details(
    binding: &registry_notary_core::SourceBindingConfig,
) -> bool {
    let matching = &binding.matching;
    !matching.allowed_assurance.is_empty()
        || matching.minimum_assurance.is_some()
        || !matching.permitted_jurisdictions.is_empty()
        || matching.require_legal_basis
        || matching.require_consent
        || !matching.allowed_legal_basis_refs.is_empty()
        || !matching.allowed_consent_refs.is_empty()
}

pub(super) fn source_authorization_subject_expectation(
    trusted_policy: &TrustedPolicyContext,
    context: &EvidenceRequestContext,
    source_capability: &SourceCapability,
) -> Result<Option<crate::authz_details::ScopedAuthorizationSubject>, EvidenceError> {
    let (Some(binding_claim), Some(binding_value)) = (
        trusted_policy.subject_binding_claim.as_deref(),
        trusted_policy.subject_binding_value.as_deref(),
    ) else {
        return Ok(None);
    };
    let expected_subject = if matches!(
        source_capability.access_mode(),
        AccessMode::DelegatedAttestation
    ) {
        context
            .requester
            .as_ref()
            .and_then(EvidenceEntity::to_subject_request)
            .ok_or(EvidenceError::TargetMatchingPolicyRejected)?
    } else {
        context
            .target_subject()
            .ok_or(EvidenceError::TargetMatchingPolicyRejected)?
    };
    if expected_subject.id != binding_value {
        return Err(EvidenceError::TargetMatchingPolicyRejected);
    }
    let id_type = expected_subject
        .id_type
        .as_deref()
        .ok_or(EvidenceError::TargetMatchingPolicyRejected)?;
    Ok(Some(crate::authz_details::ScopedAuthorizationSubject {
        binding_claim: binding_claim.to_string(),
        id_type: id_type.to_string(),
    }))
}

pub(super) fn source_authorization_target_expectation(
    context: &EvidenceRequestContext,
    source_capability: &SourceCapability,
) -> Result<Option<crate::authz_details::ScopedAuthorizationTarget>, EvidenceError> {
    if !matches!(
        source_capability.access_mode(),
        AccessMode::DelegatedAttestation
    ) {
        return Ok(None);
    }
    let target_subject = context
        .target_subject()
        .ok_or(EvidenceError::TargetMatchingPolicyRejected)?;
    let id_type = target_subject
        .id_type
        .as_deref()
        .ok_or(EvidenceError::TargetMatchingPolicyRejected)?;
    if target_subject.id.trim().is_empty() {
        return Err(EvidenceError::TargetMatchingPolicyRejected);
    }
    Ok(Some(crate::authz_details::ScopedAuthorizationTarget {
        id_type: id_type.to_string(),
        id: target_subject.id,
    }))
}

pub(super) fn trusted_policy_access_mode(
    trusted_policy: &TrustedPolicyContext,
    source_capability: &SourceCapability,
) -> AccessMode {
    if matches!(
        source_capability.access_mode(),
        AccessMode::DelegatedAttestation
    ) {
        return AccessMode::DelegatedAttestation;
    }
    if trusted_policy.subject_binding_claim.is_some() {
        AccessMode::SelfAttestation
    } else {
        AccessMode::MachineClient
    }
}
