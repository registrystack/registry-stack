// SPDX-License-Identifier: Apache-2.0
//! Self-attestation and delegated-attestation authorization policy.

use super::*;

#[derive(Debug)]
pub(super) struct SelfAttestationEvaluateContext {
    pub(super) evaluation_capability: EvaluationCapability,
    pub(super) metadata: StoredSelfAttestationMetadata,
    pub(super) purpose: String,
}
pub(super) async fn consume_classification_denial_if_keyable(
    state: &RegistryNotaryApiState,
    principal: &EvidencePrincipal,
) -> Result<(), SelfAttestationRateLimitError> {
    if principal.verified_claims.is_none() {
        return Ok(());
    }
    let principal_hash = state
        .self_attestation_rate_keys
        .principal(&principal.principal_id)?;
    state
        .self_attestation_rate_limiter
        .check_authenticated_request(&principal_hash)
        .await
}

pub(super) fn classify_self_attestation_principal(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<EvidencePrincipal, EvidenceError> {
    if !config.enabled {
        if principal.is_self_attestation() {
            return Err(self_attestation_denied(SelfAttestationDenialCode::Disabled));
        }
        return Ok(principal.clone());
    }

    let citizen_scope_signal = config
        .required_scopes
        .iter()
        .any(|scope| principal.has_scope(scope));
    if principal.verified_claims.is_none() && citizen_scope_signal {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::InvalidToken,
        ));
    }
    let citizen_client_signal = principal
        .verified_claims
        .as_ref()
        .is_some_and(|claims| citizen_client_or_audience_matches(config, claims));
    let self_attestation_candidate =
        principal.is_self_attestation() || citizen_scope_signal || citizen_client_signal;
    if !self_attestation_candidate {
        return Ok(principal.clone());
    }

    let Some(verified_claims) = principal.verified_claims.as_ref() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::InvalidToken,
        ));
    };
    if !citizen_client_or_audience_matches(config, verified_claims) {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::InvalidToken,
        ));
    }
    if !self_attestation_scope_policy_allows(config, principal, verified_claims) {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::InvalidToken,
        ));
    }

    let mut classified = principal.clone();
    classified.access_mode = AccessMode::SelfAttestation;
    Ok(classified)
}

pub(super) fn self_attestation_scope_policy_allows(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    verified_claims: &registry_notary_core::BoundedVerifiedClaims,
) -> bool {
    match config.scope_policy {
        SelfAttestationScopePolicy::Required => config
            .required_scopes
            .iter()
            .all(|scope| principal.has_scope(scope) || verified_claims.has_scope(scope)),
        SelfAttestationScopePolicy::Optional => {
            let saw_scope_signal =
                !principal.scopes.is_empty() || !verified_claims.scopes.is_empty();
            !saw_scope_signal
                || config
                    .required_scopes
                    .iter()
                    .all(|scope| principal.has_scope(scope) || verified_claims.has_scope(scope))
        }
        SelfAttestationScopePolicy::Disabled => true,
    }
}

pub(super) fn citizen_client_or_audience_matches(
    config: &SelfAttestationConfig,
    claims: &registry_notary_core::BoundedVerifiedClaims,
) -> bool {
    let client_matches = claims.client_id.as_ref().is_some_and(|client_id| {
        config
            .citizen_clients
            .allowed_client_ids
            .iter()
            .any(|allowed| verified_client_matches(client_id.as_str(), allowed))
    });
    let audience_matches = claims.audiences.iter().any(|audience| {
        config
            .citizen_clients
            .allowed_audiences
            .iter()
            .any(|allowed| audience.as_str() == allowed)
    });
    client_matches || audience_matches
}

pub(super) fn verified_client_matches(candidate: &str, allowed: &str) -> bool {
    candidate == allowed
        || candidate
            .strip_prefix("azp:")
            .or_else(|| candidate.strip_prefix("client_id:"))
            .is_some_and(|raw| raw == allowed)
}

#[cfg(test)]
pub(super) fn require_self_attestation_evaluate(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<(), EvidenceError> {
    require_self_attestation_evaluate_with_runtime_config(
        evidence, config, principal, request, None,
    )
}

pub(super) fn require_self_attestation_evaluate_with_runtime_config(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
    runtime_config: Option<&StandaloneRegistryNotaryConfig>,
) -> Result<(), EvidenceError> {
    if !config.allowed_operations.evaluate {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::OperationDenied,
        ));
    }
    let request_claim_ids = claim_ids(&request.claims);
    if request.claims.is_empty()
        || !request.claims.iter().all(|claim_id| {
            config
                .allowed_claims
                .iter()
                .any(|allowed| allowed == &claim_id.id)
        })
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::ClaimDenied,
        ));
    }

    let format = request
        .format
        .as_deref()
        .unwrap_or(FORMAT_CLAIM_RESULT_JSON);
    if !config
        .allowed_formats
        .iter()
        .any(|allowed| allowed == format)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::FormatDenied,
        ));
    }

    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref())
            .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::DisclosureDenied))?;
    if !config
        .allowed_disclosures
        .iter()
        .any(|allowed| allowed == &disclosure)
        || !request
            .claims
            .iter()
            .all(|claim_id| claim_allows_disclosure(evidence, claim_id, &disclosure))
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DisclosureDenied,
        ));
    }

    for claim_id in &request.claims {
        let claim = find_requested_claim(evidence, claim_id)
            .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::ClaimDenied))?;
        if !claim.operations.evaluate.enabled {
            return Err(self_attestation_denied(
                SelfAttestationDenialCode::OperationDenied,
            ));
        }
        if claim.purpose.as_deref().is_none_or(|purpose| {
            !config
                .allowed_purposes
                .iter()
                .any(|allowed| allowed == purpose)
        }) {
            return Err(self_attestation_denied(
                SelfAttestationDenialCode::OperationDenied,
            ));
        }
    }

    let purpose = common_self_attestation_purpose(evidence, &request.claims)?;
    if request
        .purpose
        .as_deref()
        .is_some_and(|requested| requested != purpose)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::OperationDenied,
        ));
    }
    require_self_attestation_authorization_details(
        evidence.service_id.as_str(),
        config,
        principal,
        request,
        &disclosure,
        format,
        &purpose,
        runtime_config,
    )?;

    let subject_binding = &config.subject_binding;
    let Some(target_subject) = request.target_subject() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    };
    if target_subject.id.trim().is_empty() {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    if target_subject.id_type.as_deref() != Some(subject_binding.id_type.as_str()) {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    let Some(bound_subject) =
        principal.verified_subject_binding_value(&subject_binding.token_claim)
    else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectClaimMissing,
        ));
    };
    if bound_subject != target_subject.id {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn require_self_attestation_authorization_details(
    service_id: &str,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
    disclosure: &str,
    format: &str,
    purpose: &str,
    runtime_config: Option<&StandaloneRegistryNotaryConfig>,
) -> Result<(), EvidenceError> {
    let Some(details) = principal.authorization_details.as_ref() else {
        if self_attestation_requires_authorization_details(principal, runtime_config) {
            return Err(self_attestation_denied(
                SelfAttestationDenialCode::OperationDenied,
            ));
        }
        return Ok(());
    };

    crate::authz_details::validate_scoped_authorization_details(
        details,
        &crate::authz_details::ScopedAuthorizationRequest {
            service_id,
            action: "evaluate",
            claims: &request.claims,
            disclosure,
            format,
            purpose,
            access_mode: AccessMode::SelfAttestation,
            subject: Some(crate::authz_details::ScopedAuthorizationSubject {
                binding_claim: config.subject_binding.token_claim.clone(),
                id_type: config.subject_binding.id_type.clone(),
            }),
            target: None,
            allow_subset_claims: false,
            allowed_claims: None,
        },
    )
    .map_err(self_attestation_authorization_details_denial)
}

pub(super) fn delegated_relationship_config<'a>(
    config: &'a SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<&'a SelfAttestationDelegatedRelationshipConfig, EvidenceError> {
    let details = principal.authorization_details.as_ref().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
    })?;
    let relationship = details.relationship.as_ref().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
    })?;
    let relationship_config = config
        .delegation
        .relationship(&relationship.relationship_type)
        .ok_or_else(|| {
            self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
        })?;
    if relationship_config.proof_claim != relationship.proof_claim {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    Ok(relationship_config)
}

pub(super) fn require_delegated_attestation_evaluate(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<(), EvidenceError> {
    if !config.allowed_operations.evaluate || !config.delegation.enabled {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    if request.claims.len() != 1 {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    let relationship_config = delegated_relationship_config(config, principal)?;
    let requested_claim = request
        .claims
        .first()
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::DelegatedClaimDenied))?;
    if !relationship_config
        .allowed_claims
        .iter()
        .any(|allowed| allowed == &requested_claim.id)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    let claim = find_requested_claim(evidence, requested_claim)
        .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::DelegatedClaimDenied))?;
    let proof_claim = find_requested_claim(
        evidence,
        &ClaimRef::from(relationship_config.proof_claim.as_str()),
    )
    .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::DelegatedProofDenied))?;
    if !claim.operations.evaluate.enabled || !proof_claim.operations.evaluate.enabled {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    if !claim
        .depends_on
        .iter()
        .any(|depends_on| depends_on == &relationship_config.proof_claim)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }

    let purpose = claim
        .purpose
        .as_deref()
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::DelegatedClaimDenied))?;
    if !relationship_config
        .allowed_purposes
        .iter()
        .any(|allowed| allowed == purpose)
        || request
            .purpose
            .as_deref()
            .is_some_and(|requested| requested != purpose)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    let format = request
        .format
        .as_deref()
        .unwrap_or(FORMAT_CLAIM_RESULT_JSON);
    if !relationship_config
        .allowed_formats
        .iter()
        .any(|allowed| allowed == format)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    let request_claim_ids = claim_ids(&request.claims);
    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref()).map_err(
            |_| self_attestation_denied(SelfAttestationDenialCode::DelegatedClaimDenied),
        )?;
    if !relationship_config
        .allowed_disclosures
        .iter()
        .any(|allowed| allowed == &disclosure)
        || !claim_allows_disclosure(evidence, requested_claim, &disclosure)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedClaimDenied,
        ));
    }
    let Some(target_subject) = request.target_subject() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    };
    if target_subject.id.trim().is_empty()
        || target_subject.id_type.as_deref()
            != Some(delegated_target_id_type(config, relationship_config))
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    require_delegated_attestation_authorization_details(
        evidence,
        config,
        principal,
        request,
        relationship_config,
        claim,
        proof_claim,
        &disclosure,
        format,
        purpose,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn require_delegated_attestation_authorization_details(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
    relationship_config: &SelfAttestationDelegatedRelationshipConfig,
    claim: &registry_notary_core::ClaimDefinition,
    proof_claim: &registry_notary_core::ClaimDefinition,
    disclosure: &str,
    format: &str,
    purpose: &str,
) -> Result<(), EvidenceError> {
    let Some(details) = principal.authorization_details.as_ref() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    };
    let target_subject = request.target_subject().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedSubjectNotPermitted)
    })?;
    let target_id_type = delegated_target_id_type(config, relationship_config);
    if target_subject.id.trim().is_empty()
        || target_subject.id_type.as_deref() != Some(target_id_type)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    let authorized_claims = [
        ClaimRef::with_version(&claim.id, &claim.version),
        ClaimRef::with_version(&proof_claim.id, &proof_claim.version),
    ];
    crate::authz_details::validate_scoped_authorization_details(
        details,
        &crate::authz_details::ScopedAuthorizationRequest {
            service_id: evidence.service_id.as_str(),
            action: "evaluate",
            claims: &authorized_claims,
            disclosure,
            format,
            purpose,
            access_mode: AccessMode::DelegatedAttestation,
            subject: Some(crate::authz_details::ScopedAuthorizationSubject {
                binding_claim: config.subject_binding.token_claim.clone(),
                id_type: config.subject_binding.id_type.clone(),
            }),
            target: Some(crate::authz_details::ScopedAuthorizationTarget {
                id_type: target_id_type.to_string(),
                id: target_subject.id.clone(),
            }),
            allow_subset_claims: true,
            allowed_claims: Some(&authorized_claims),
        },
    )
    .map_err(delegated_attestation_authorization_details_denial)?;
    let relationship = details.relationship.as_ref().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
    })?;
    if relationship.relationship_type != relationship_config.relationship_type
        || relationship.proof_claim != relationship_config.proof_claim
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    if request
        .relationship
        .as_ref()
        .map(|relationship| relationship.relationship_type.as_str())
        != Some(relationship_config.relationship_type.as_str())
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    Ok(())
}

pub(super) fn self_attestation_requires_authorization_details(
    principal: &EvidencePrincipal,
    runtime_config: Option<&StandaloneRegistryNotaryConfig>,
) -> bool {
    let Some(claims) = principal.verified_claims.as_ref() else {
        return false;
    };
    let Some(token_type) = claims.token_type.as_ref() else {
        return false;
    };
    if token_type.as_str() != registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP {
        return false;
    }
    let Some(config) = runtime_config else {
        return true;
    };
    let signing = &config.auth.access_token_signing;
    signing.enabled && claims.issuer.as_str() == signing.issuer
}

pub(super) fn self_attestation_authorization_details_denial(
    error: crate::authz_details::ScopedAuthorizationError,
) -> EvidenceError {
    let reason = match error {
        crate::authz_details::ScopedAuthorizationError::Claim => {
            SelfAttestationDenialCode::ClaimDenied
        }
        crate::authz_details::ScopedAuthorizationError::Disclosure => {
            SelfAttestationDenialCode::DisclosureDenied
        }
        crate::authz_details::ScopedAuthorizationError::Format => {
            SelfAttestationDenialCode::FormatDenied
        }
        crate::authz_details::ScopedAuthorizationError::Subject => {
            SelfAttestationDenialCode::SubjectMismatch
        }
        crate::authz_details::ScopedAuthorizationError::Target => {
            SelfAttestationDenialCode::SubjectMismatch
        }
        crate::authz_details::ScopedAuthorizationError::DetailType
        | crate::authz_details::ScopedAuthorizationError::Action
        | crate::authz_details::ScopedAuthorizationError::Location
        | crate::authz_details::ScopedAuthorizationError::Purpose
        | crate::authz_details::ScopedAuthorizationError::AccessMode => {
            SelfAttestationDenialCode::OperationDenied
        }
    };
    self_attestation_denied(reason)
}

pub(super) fn delegated_attestation_authorization_details_denial(
    error: crate::authz_details::ScopedAuthorizationError,
) -> EvidenceError {
    let reason = match error {
        crate::authz_details::ScopedAuthorizationError::Claim
        | crate::authz_details::ScopedAuthorizationError::Disclosure
        | crate::authz_details::ScopedAuthorizationError::Format
        | crate::authz_details::ScopedAuthorizationError::Purpose => {
            SelfAttestationDenialCode::DelegatedClaimDenied
        }
        crate::authz_details::ScopedAuthorizationError::Subject => {
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted
        }
        crate::authz_details::ScopedAuthorizationError::Target => {
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted
        }
        crate::authz_details::ScopedAuthorizationError::DetailType
        | crate::authz_details::ScopedAuthorizationError::Action
        | crate::authz_details::ScopedAuthorizationError::Location
        | crate::authz_details::ScopedAuthorizationError::AccessMode => {
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed
        }
    };
    self_attestation_denied(reason)
}

pub(super) fn find_requested_claim<'a>(
    evidence: &'a EvidenceConfig,
    claim: &ClaimRef,
) -> Result<&'a registry_notary_core::ClaimDefinition, EvidenceError> {
    match claim.version.as_deref() {
        Some(version) => crate::runtime::find_claim_version(evidence, &claim.id, version),
        None => crate::find_claim(evidence, &claim.id),
    }
}

pub(super) fn common_self_attestation_purpose(
    evidence: &EvidenceConfig,
    claims: &[ClaimRef],
) -> Result<String, EvidenceError> {
    if claims.is_empty() {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::ClaimDenied,
        ));
    }
    let mut purpose = None;
    for claim_ref in claims {
        let claim = find_requested_claim(evidence, claim_ref)
            .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::ClaimDenied))?;
        let claim_purpose = claim
            .purpose
            .as_deref()
            .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::OperationDenied))?;
        if let Some(existing) = purpose {
            if existing != claim_purpose {
                return Err(self_attestation_denied(
                    SelfAttestationDenialCode::OperationDenied,
                ));
            }
        } else {
            purpose = Some(claim_purpose);
        }
    }
    purpose
        .map(str::to_string)
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::ClaimDenied))
}

pub(super) fn prepare_self_attestation_evaluate(
    state: &RegistryNotaryApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<SelfAttestationEvaluateContext, EvidenceError> {
    if principal.access_mode() == AccessMode::DelegatedAttestation {
        return prepare_delegated_attestation_evaluate(state, evidence, principal, request);
    }
    let runtime_config = state.runtime_config();
    require_self_attestation_evaluate_with_runtime_config(
        evidence,
        &state.self_attestation,
        principal,
        request,
        runtime_config.as_deref(),
    )?;
    require_self_attestation_token_policy(&state.self_attestation, principal)?;

    let purpose = common_self_attestation_purpose(evidence, &request.claims)?;
    let format = request
        .format
        .as_deref()
        .unwrap_or(FORMAT_CLAIM_RESULT_JSON)
        .to_string();
    let request_claim_ids = claim_ids(&request.claims);
    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref()).map_err(
            |_| EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DisclosureDenied,
            },
        )?;
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    let subject_binding_value = principal
        .verified_subject_binding_value(&state.self_attestation.subject_binding.token_claim)
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectClaimMissing,
        })?;
    let principal_hash = state
        .self_attestation_rate_keys
        .principal(&principal.principal_id)
        .map_err(|error| error.evidence_error())?;
    let subject_binding_hash = state
        .self_attestation_rate_keys
        .subject_binding(subject_binding_value)
        .map_err(|error| error.evidence_error())?;
    let requested_claims_hash =
        Hashed::<ClaimSet>::from_hash(evidence_claim_hash(&request_claim_ids));
    let policy_hash = self_attestation_policy_hash(
        evidence,
        &state.self_attestation,
        &request_claim_ids,
        &disclosure,
        &format,
    )?;
    let now = OffsetDateTime::now_utc();
    let evaluation_expires_at = now
        + time::Duration::seconds(
            state
                .self_attestation
                .token_policy
                .max_evaluation_age_seconds as i64,
        );

    let metadata = StoredSelfAttestationMetadata {
        access_mode: AccessMode::SelfAttestation,
        issuer: claims.issuer.clone(),
        audiences: claims.audiences.clone(),
        client_id: claims.client_id.clone(),
        principal_hash,
        subject_id_type: ConfigMetadata::new(
            state.self_attestation.subject_binding.id_type.clone(),
        )
        .map_err(|_| EvidenceError::InvalidRequest)?,
        subject_binding_claim: ConfigMetadata::new(
            state.self_attestation.subject_binding.token_claim.clone(),
        )
        .map_err(|_| EvidenceError::InvalidRequest)?,
        subject_binding_hash: subject_binding_hash.clone(),
        dependent_target_hash: None,
        relationship_type: None,
        proof_claim_id: None,
        requested_claims_hash,
        disclosure: ConfigMetadata::new(disclosure.clone())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        result_format: ConfigMetadata::new(format).map_err(|_| EvidenceError::InvalidRequest)?,
        delegation_chain: Vec::new(),
        policy_version: None,
        policy_hash: Some(policy_hash.clone()),
        evaluation_expires_at: Some(format_time(evaluation_expires_at)),
    };
    let mut allowed_claim_ids = BTreeSet::new();
    for claim_id in request_claim_ids {
        allowed_claim_ids
            .insert(BoundedClaimId::new(claim_id).map_err(|_| EvidenceError::InvalidRequest)?);
    }
    let evaluation_capability = EvaluationCapability::SelfAttestation {
        claim_id: if allowed_claim_ids.len() == 1 {
            allowed_claim_ids.iter().next().cloned()
        } else {
            None
        },
        allowed_claim_ids,
        subject_binding_hash,
    };

    Ok(SelfAttestationEvaluateContext {
        evaluation_capability,
        metadata,
        purpose,
    })
}

pub(super) fn prepare_delegated_attestation_evaluate(
    state: &RegistryNotaryApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<SelfAttestationEvaluateContext, EvidenceError> {
    require_delegated_attestation_evaluate(evidence, &state.self_attestation, principal, request)?;
    require_self_attestation_token_policy(&state.self_attestation, principal)?;

    let relationship_config = delegated_relationship_config(&state.self_attestation, principal)?;
    let claim_id = request
        .claims
        .first()
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedClaimDenied,
        })?;
    let claim = find_requested_claim(evidence, claim_id).map_err(|_| {
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedClaimDenied,
        }
    })?;
    let purpose = claim
        .purpose
        .clone()
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedClaimDenied,
        })?;
    let format = request
        .format
        .as_deref()
        .unwrap_or(FORMAT_CLAIM_RESULT_JSON)
        .to_string();
    let request_claim_ids = claim_ids(&request.claims);
    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref()).map_err(
            |_| EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedClaimDenied,
            },
        )?;
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    let subject_binding_value = principal
        .verified_subject_binding_value(&state.self_attestation.subject_binding.token_claim)
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectClaimMissing,
        })?;
    let target_subject = request
        .target_subject()
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        })?;
    let principal_hash = state
        .self_attestation_rate_keys
        .principal(&principal.principal_id)
        .map_err(|error| error.evidence_error())?;
    let requester_subject_binding_hash = state
        .self_attestation_rate_keys
        .delegated_subject_binding(
            state.self_attestation.subject_binding.id_type.as_str(),
            subject_binding_value,
        )
        .map_err(|error| error.evidence_error())?;
    let target_id_type = delegated_target_id_type(&state.self_attestation, relationship_config);
    let dependent_target_hash = state
        .self_attestation_rate_keys
        .delegated_subject_binding(target_id_type, target_subject.id.as_str())
        .map_err(|error| error.evidence_error())?;
    let requested_claims_hash =
        Hashed::<ClaimSet>::from_hash(evidence_claim_hash(&request_claim_ids));
    let policy_hash = self_attestation_policy_hash(
        evidence,
        &state.self_attestation,
        &request_claim_ids,
        &disclosure,
        &format,
    )?;
    let now = OffsetDateTime::now_utc();
    let evaluation_expires_at = now
        + time::Duration::seconds(
            state
                .self_attestation
                .token_policy
                .max_evaluation_age_seconds as i64,
        );
    let proof_claim_id = BoundedClaimId::new(relationship_config.proof_claim.clone())
        .map_err(|_| EvidenceError::InvalidRequest)?;
    let delegated_claim_id =
        BoundedClaimId::new(claim_id.id.clone()).map_err(|_| EvidenceError::InvalidRequest)?;
    let relationship_type = ConfigMetadata::new(relationship_config.relationship_type.clone())
        .map_err(|_| EvidenceError::InvalidRequest)?;
    let metadata = StoredSelfAttestationMetadata {
        access_mode: AccessMode::DelegatedAttestation,
        issuer: claims.issuer.clone(),
        audiences: claims.audiences.clone(),
        client_id: claims.client_id.clone(),
        principal_hash,
        subject_id_type: ConfigMetadata::new(target_id_type.to_string())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        subject_binding_claim: ConfigMetadata::new(
            state.self_attestation.subject_binding.token_claim.clone(),
        )
        .map_err(|_| EvidenceError::InvalidRequest)?,
        subject_binding_hash: requester_subject_binding_hash.clone(),
        dependent_target_hash: Some(dependent_target_hash.clone()),
        relationship_type: Some(relationship_type.clone()),
        proof_claim_id: Some(proof_claim_id.clone()),
        requested_claims_hash,
        disclosure: ConfigMetadata::new(disclosure.clone())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        result_format: ConfigMetadata::new(format.clone())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        delegation_chain: request
            .on_behalf_of
            .as_ref()
            .map(|delegation| vec![delegation.actor.clone()])
            .unwrap_or_default(),
        policy_version: None,
        policy_hash: Some(policy_hash.clone()),
        evaluation_expires_at: Some(format_time(evaluation_expires_at)),
    };
    let evaluation_capability = EvaluationCapability::DelegatedAttestation {
        proof_claim_id,
        allowed_claim_ids: BTreeSet::from([delegated_claim_id]),
        requester_subject_binding_hash,
        dependent_target_hash,
        relationship_type,
    };

    Ok(SelfAttestationEvaluateContext {
        evaluation_capability,
        metadata,
        purpose,
    })
}

pub(super) fn require_self_attestation_token_policy(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<(), EvidenceError> {
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let leeway = config.token_policy.max_clock_leeway_seconds as i64;
    let auth_time = claims
        .auth_time
        .ok_or(EvidenceError::SelfAttestationAssuranceDenied)?;
    if auth_time > now + leeway {
        return Err(EvidenceError::SelfAttestationAssuranceDenied);
    }
    if now.saturating_sub(auth_time) > config.token_policy.max_auth_age_seconds as i64 + leeway {
        return Err(EvidenceError::SelfAttestationAssuranceDenied);
    }
    require_self_attestation_pdp_decision(
        config,
        claims.acr.as_ref().map(|acr| acr.as_str()),
        now,
        auth_time,
        leeway,
    )?;
    let exp = claims
        .exp
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    let iat = claims
        .iat
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    if iat > now + leeway {
        return Err(EvidenceError::SelfAttestationAssuranceDenied);
    }
    if exp < iat
        || exp.saturating_sub(iat)
            > config.token_policy.max_access_token_lifetime_seconds as i64 + leeway
    {
        return Err(EvidenceError::SelfAttestationAssuranceDenied);
    }
    Ok(())
}

pub(super) fn require_self_attestation_pdp_decision(
    config: &SelfAttestationConfig,
    acr: Option<&str>,
    now: i64,
    auth_time: i64,
    leeway: i64,
) -> Result<(), EvidenceError> {
    let observed_age = now
        .saturating_sub(auth_time)
        .try_into()
        .ok()
        .unwrap_or_default();
    let context = PdpRequestContext {
        purpose: "self_attestation".to_string(),
        legal_basis_ref: None,
        consent_ref: None,
        asserted_assurance: acr.map(str::to_string),
        jurisdiction: None,
        requester_identity: None,
        subject_ref: None,
        relationship: None,
        on_behalf_of: None,
        requested_fact: None,
        requested_disclosure: None,
        requested_credential_format: None,
        source_binding: None,
        route_identity: Some("registry-notary.self-attestation".to_string()),
        checked_scopes: Default::default(),
        source_observed_at_unix_seconds: None,
        source_observed_age_seconds: Some(observed_age),
    };
    let policy = PdpPolicyInput {
        policy_id: "self-attestation".to_string(),
        policy_hash: self_attestation_token_policy_hash(config)?,
        ecosystem_binding_id: None,
        ecosystem_binding_version: None,
        rule_ids: vec!["self-attestation-token-policy".to_string()],
        rule_ids_by_gate: Default::default(),
        permit_unconstrained: false,
        required_context: Default::default(),
        odrl_constraint_terms: Vec::new(),
        purpose_constraints: vec![vec!["self_attestation".to_string()]],
        permitted_jurisdictions: Vec::new(),
        allowed_assurance: config.token_policy.required_acr_values.clone(),
        minimum_assurance: None,
        max_source_age_seconds: Some(config.token_policy.max_auth_age_seconds + leeway as u64),
        require_legal_basis: false,
        require_consent: false,
        allowed_legal_basis_refs: Vec::new(),
        allowed_consent_refs: Vec::new(),
        redaction_fields: Default::default(),
        allowed_relationships: Vec::new(),
        relationship_purpose_constraints: Vec::new(),
        allowed_requested_facts: Vec::new(),
        allowed_requested_disclosures: Vec::new(),
        allowed_credential_formats: Vec::new(),
        allowed_source_bindings: Vec::new(),
        allowed_route_identities: vec!["registry-notary.self-attestation".to_string()],
        required_checked_scopes: Default::default(),
        unsupported_odrl_terms: Vec::new(),
    };
    match pdp_decide(&context, &policy) {
        PdpDecision::Permit(_) | PdpDecision::PermitWithRedaction { .. } => Ok(()),
        PdpDecision::Deny { .. } => Err(EvidenceError::SelfAttestationAssuranceDenied),
    }
}

pub(super) fn self_attestation_token_policy_hash(
    config: &SelfAttestationConfig,
) -> Result<String, EvidenceError> {
    let canonical = json!({
        "purpose_constraints": [["self_attestation"]],
        "required_acr_values": config.token_policy.required_acr_values,
        "assurance_claim_source": config.token_policy.assurance_claim_source,
        "max_auth_age_seconds": config.token_policy.max_auth_age_seconds,
        "max_clock_leeway_seconds": config.token_policy.max_clock_leeway_seconds,
    });
    sha256_canonical_json(&canonical)
}

pub(super) fn require_self_attestation_credential_profile_policy(
    config: &SelfAttestationConfig,
    profile_id: &str,
    profile: &CredentialProfileConfig,
) -> Result<(), EvidenceError> {
    let allowed = config
        .credential_profiles
        .iter()
        .any(|allowed| allowed == profile_id);
    let validity_seconds = u64::try_from(profile.validity_seconds).ok();
    let validity_ceiling = config.token_policy.max_credential_validity_seconds;
    let did_jwk_only = !profile.holder_binding.allowed_did_methods.is_empty()
        && profile
            .holder_binding
            .allowed_did_methods
            .iter()
            .all(|method| method == "did:jwk");
    if !allowed
        || profile.format != FORMAT_SD_JWT_VC
        || validity_seconds.is_none_or(|seconds| seconds == 0 || seconds > validity_ceiling)
        || profile.holder_binding.mode != "did"
        || profile.holder_binding.proof_of_possession.as_deref() != Some("required")
        || !did_jwk_only
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::ProfileDenied,
        ));
    }
    Ok(())
}

pub(super) fn require_delegated_attestation_credential_profile_policy(
    config: &SelfAttestationConfig,
    metadata: &StoredSelfAttestationMetadata,
    profile_id: &str,
    profile: &CredentialProfileConfig,
) -> Result<(), EvidenceError> {
    let relationship_type = metadata
        .relationship_type
        .as_ref()
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::ProfileDenied))?;
    let relationship = config
        .delegation
        .relationship(relationship_type.as_str())
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::ProfileDenied))?;
    let allowed = relationship
        .credential_profiles
        .iter()
        .any(|allowed| allowed == profile_id);
    let validity_seconds = u64::try_from(profile.validity_seconds).ok();
    let validity_ceiling = config.token_policy.max_credential_validity_seconds;
    let did_jwk_only = !profile.holder_binding.allowed_did_methods.is_empty()
        && profile
            .holder_binding
            .allowed_did_methods
            .iter()
            .all(|method| method == "did:jwk");
    if !allowed
        || profile.format != FORMAT_SD_JWT_VC
        || validity_seconds.is_none_or(|seconds| seconds == 0 || seconds > validity_ceiling)
        || profile.holder_binding.mode != "did"
        || profile.holder_binding.proof_of_possession.as_deref() != Some("required")
        || !did_jwk_only
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::ProfileDenied,
        ));
    }
    Ok(())
}

pub(super) async fn consume_subject_mismatch_denial(
    state: &RegistryNotaryApiState,
    principal_hash: &Hashed<registry_notary_core::PrincipalIdentifier>,
) -> Result<(), SelfAttestationRateLimitError> {
    state
        .self_attestation_rate_limiter
        .consume_subject_mismatch_denial_only(principal_hash)
        .await
}

#[allow(clippy::too_many_arguments)]
pub(super) fn require_self_attestation_stored_access(
    state: &RegistryNotaryApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
    requested_claims: &[String],
    disclosure: &str,
    format: &str,
    credential_profile: Option<&str>,
) -> Result<(), EvidenceError> {
    let Some(metadata) = evaluation.self_attestation.as_ref() else {
        if principal.is_self_attestation() {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        return Ok(());
    };
    if !principal.is_self_attestation() {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if principal.access_mode() != metadata.access_mode {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if credential_profile.is_some() && !state.self_attestation.allowed_operations.issue_credential {
        return Err(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied,
        });
    }
    if credential_profile.is_none() && !state.self_attestation.allowed_operations.render {
        return Err(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied,
        });
    }
    if let Some(expires_at) = metadata.evaluation_expires_at.as_deref() {
        let expires_at = OffsetDateTime::parse(expires_at, &Rfc3339)
            .map_err(|_| EvidenceError::EvaluationBindingMismatch)?;
        if OffsetDateTime::now_utc() > expires_at {
            return Err(EvidenceError::EvaluationNotFound);
        }
    }
    require_self_attestation_token_policy(&state.self_attestation, principal)?;
    let principal_hash = state
        .self_attestation_rate_keys
        .principal(&principal.principal_id)
        .map_err(|error| error.evidence_error())?;
    if principal_hash != metadata.principal_hash {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if metadata.subject_binding_claim.as_str() != state.self_attestation.subject_binding.token_claim
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let delegated_relationship = if metadata.access_mode == AccessMode::DelegatedAttestation {
        if !state.self_attestation.delegation.enabled || metadata.dependent_target_hash.is_none() {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let relationship_type = metadata
            .relationship_type
            .as_ref()
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let proof_claim_id = metadata
            .proof_claim_id
            .as_ref()
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        let relationship = state
            .self_attestation
            .delegation
            .relationship(relationship_type.as_str())
            .ok_or(EvidenceError::EvaluationBindingMismatch)?;
        if proof_claim_id.as_str() != relationship.proof_claim
            || metadata.subject_id_type.as_str()
                != delegated_target_id_type(&state.self_attestation, relationship)
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        Some(relationship)
    } else {
        if metadata.subject_id_type.as_str() != state.self_attestation.subject_binding.id_type
            || metadata.dependent_target_hash.is_some()
            || metadata.relationship_type.is_some()
            || metadata.proof_claim_id.is_some()
        {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        None
    };
    if let Some(relationship) = delegated_relationship {
        require_delegated_stored_authorization_details(
            evidence,
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            principal,
            evaluation,
            metadata,
            relationship,
        )?;
    }
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    if claims.issuer != metadata.issuer
        || claims.client_id != metadata.client_id
        || !verified_audiences_match(&claims.audiences, &metadata.audiences)
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let subject_binding_value = principal
        .verified_subject_binding_value(&state.self_attestation.subject_binding.token_claim)
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectClaimMissing,
        })?;
    // Delegated evaluations bind the requester subject over the (id_type, id)
    // pair (see prepare_delegated_attestation_evaluate); non-delegated
    // self-attestation keeps the value-only binding byte-for-byte unchanged.
    let subject_binding_hash = if metadata.access_mode == AccessMode::DelegatedAttestation {
        state
            .self_attestation_rate_keys
            .delegated_subject_binding(
                state.self_attestation.subject_binding.id_type.as_str(),
                subject_binding_value,
            )
            .map_err(|error| error.evidence_error())?
    } else {
        state
            .self_attestation_rate_keys
            .subject_binding(subject_binding_value)
            .map_err(|error| error.evidence_error())?
    };
    if subject_binding_hash != metadata.subject_binding_hash {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if metadata.requested_claims_hash.as_str() != evidence_claim_hash(requested_claims) {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if metadata.disclosure.as_str() != disclosure || metadata.result_format.as_str() != format {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    if let Some(profile_id) = credential_profile {
        match delegated_relationship {
            Some(relationship) => {
                if !relationship
                    .credential_profiles
                    .iter()
                    .any(|allowed| allowed == profile_id)
                {
                    return Err(EvidenceError::SelfAttestationDenied {
                        reason: SelfAttestationDenialCode::ProfileDenied,
                    });
                }
            }
            None => {
                if !state
                    .self_attestation
                    .credential_profiles
                    .iter()
                    .any(|allowed| allowed == profile_id)
                {
                    return Err(EvidenceError::SelfAttestationDenied {
                        reason: SelfAttestationDenialCode::ProfileDenied,
                    });
                }
            }
        }
    }
    let expected_policy_hash = self_attestation_policy_hash(
        evidence,
        &state.self_attestation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
    )?;
    if metadata.policy_hash.as_ref() != Some(&expected_policy_hash) {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    Ok(())
}

pub(super) fn require_delegated_stored_authorization_details(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    keys: &SelfAttestationRateLimitKeys,
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
    metadata: &StoredSelfAttestationMetadata,
    relationship_config: &SelfAttestationDelegatedRelationshipConfig,
) -> Result<(), EvidenceError> {
    let details = principal.authorization_details.as_ref().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
    })?;
    let relationship = details.relationship.as_ref().ok_or_else(|| {
        self_attestation_denied(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed)
    })?;
    let proof_claim_id = metadata
        .proof_claim_id
        .as_ref()
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::DelegatedProofDenied))?;
    if relationship.relationship_type != relationship_config.relationship_type
        || relationship.proof_claim != relationship_config.proof_claim
        || relationship.proof_claim != proof_claim_id.as_str()
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    require_delegated_authorization_target_binding(details, metadata, keys)?;
    let proof_claim = find_requested_claim(evidence, &ClaimRef::from(proof_claim_id.as_str()))
        .map_err(|_| self_attestation_denied(SelfAttestationDenialCode::DelegatedProofDenied))?;
    let mut authorized_claims = evaluation.selected_claim_refs();
    let proof_ref = ClaimRef::with_version(&proof_claim.id, &proof_claim.version);
    if !authorized_claims.contains(&proof_ref) {
        authorized_claims.push(proof_ref);
    }
    crate::authz_details::validate_scoped_authorization_details(
        details,
        &crate::authz_details::ScopedAuthorizationRequest {
            service_id: evidence.service_id.as_str(),
            action: "evaluate",
            claims: &authorized_claims,
            disclosure: &evaluation.disclosure,
            format: &evaluation.format,
            purpose: &evaluation.purpose,
            access_mode: AccessMode::DelegatedAttestation,
            subject: Some(crate::authz_details::ScopedAuthorizationSubject {
                binding_claim: config.subject_binding.token_claim.clone(),
                id_type: config.subject_binding.id_type.clone(),
            }),
            target: None,
            allow_subset_claims: true,
            allowed_claims: Some(&authorized_claims),
        },
    )
    .map_err(delegated_attestation_authorization_details_denial)
}

pub(super) fn require_delegated_authorization_target_binding(
    details: &registry_notary_core::EvidenceAuthorizationDetails,
    metadata: &StoredSelfAttestationMetadata,
    keys: &SelfAttestationRateLimitKeys,
) -> Result<(), EvidenceError> {
    let target = details
        .target
        .as_ref()
        .ok_or(EvidenceError::EvaluationBindingMismatch)?;
    let expected_hash = metadata
        .dependent_target_hash
        .as_ref()
        .ok_or(EvidenceError::EvaluationBindingMismatch)?;
    if target.id.trim().is_empty() || target.id_type != metadata.subject_id_type.as_str() {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let target_hash = keys
        .delegated_subject_binding(target.id_type.as_str(), target.id.as_str())
        .map_err(|error| error.evidence_error())?;
    if &target_hash != expected_hash {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    Ok(())
}

pub(super) fn verified_audiences_match(
    left: &[VerifiedClaimValue],
    right: &[VerifiedClaimValue],
) -> bool {
    let left = left.iter().collect::<std::collections::BTreeSet<_>>();
    let right = right.iter().collect::<std::collections::BTreeSet<_>>();
    left == right
}

pub(super) fn claim_allows_disclosure(
    evidence: &EvidenceConfig,
    claim_id: &str,
    disclosure: &str,
) -> bool {
    crate::find_claim(evidence, claim_id).is_ok_and(|claim| {
        claim.disclosure.default == disclosure
            || claim
                .disclosure
                .allowed
                .iter()
                .any(|allowed| allowed == disclosure)
    })
}

pub(super) fn selected_disclosure(
    evidence: &EvidenceConfig,
    claim_ids: &[String],
    requested: Option<&str>,
) -> Result<String, EvidenceError> {
    let disclosure = requested
        .or_else(|| {
            claim_ids
                .first()
                .and_then(|claim_id| crate::find_claim(evidence, claim_id).ok())
                .map(|claim| claim.disclosure.default.as_str())
        })
        .unwrap_or("redacted");
    registry_notary_core::DisclosureProfile::parse(disclosure)
        .ok_or(EvidenceError::InvalidRequest)
        .map(|profile| profile.as_str().to_string())
}

pub(super) fn self_attestation_denied(reason: SelfAttestationDenialCode) -> EvidenceError {
    EvidenceError::SelfAttestationDenied { reason }
}

pub(super) fn denial_code_from_error(error: &EvidenceError) -> Option<SelfAttestationDenialCode> {
    match error {
        EvidenceError::SelfAttestationDenied { reason } => Some(*reason),
        EvidenceError::SelfAttestationRateLimited => Some(SelfAttestationDenialCode::RateLimited),
        EvidenceError::SelfAttestationInvalidToken => Some(SelfAttestationDenialCode::InvalidToken),
        EvidenceError::SelfAttestationAssuranceDenied => {
            Some(SelfAttestationDenialCode::AssuranceDenied)
        }
        _ => None,
    }
}

pub(super) fn subject_mismatch_denial_code(reason: SelfAttestationDenialCode) -> bool {
    matches!(
        reason,
        SelfAttestationDenialCode::SubjectMismatch
            | SelfAttestationDenialCode::DelegatedSubjectNotPermitted
    )
}

pub(super) fn denial_code_from_response(response: &Response) -> Option<SelfAttestationDenialCode> {
    response
        .extensions()
        .get::<EvidenceErrorCodeContext>()
        .and_then(|context| SelfAttestationDenialCode::parse(&context.0))
}
