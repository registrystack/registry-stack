// SPDX-License-Identifier: Apache-2.0
//! OID4VCI credential issuance and authorization binding.

use super::super::*;

pub(in crate::api) async fn oid4vci_credential(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    validated_proof: Option<Extension<ValidatedProof>>,
    Json(request): Json<Oid4vciCredentialRequest>,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(Extension(principal)) = principal else {
        return oid4vci_error_response(Oid4vciWireError::InvalidToken);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let principal = match classify_subject_access_principal(&state.subject_access, &principal) {
        Ok(principal) if principal.is_subject_access() => principal,
        _ => return oid4vci_error_response(Oid4vciWireError::InvalidToken),
    };
    if let Err(error) = require_oid4vci_token_audience(&state.oid4vci, &principal) {
        return oid4vci_error_response(error);
    }
    if request.format != SD_JWT_VC_FORMAT {
        return oid4vci_error_response(Oid4vciWireError::UnsupportedCredentialType);
    }
    if let Err(error) = oid4vci_single_proof_jwt(&request) {
        return oid4vci_error_response(error);
    }
    let Some(Extension(validated_proof)) = validated_proof else {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    };
    let (configuration_id, configuration) =
        match oid4vci_configuration_for_request(&state.oid4vci, &request) {
            Ok(configuration) => configuration,
            Err(error) => return oid4vci_error_response(error),
        };
    let configuration_claim_ids = configuration.credential_claim_ids();
    if requested_attestation_access_mode(&principal) == AccessMode::DelegatedAttestation {
        let mut response = oid4vci_error_response(Oid4vciWireError::AccessDenied);
        attach_oid4vci_subject_access_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            Some(SubjectAccessDenialCode::DelegatedRelationshipNotAllowed),
            Some(state.subject_access.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    if let Err(error) = require_oid4vci_configuration_scope(configuration, &principal) {
        let mut response = oid4vci_error_response(error);
        attach_oid4vci_subject_access_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            Some(SubjectAccessDenialCode::OperationDenied),
            Some(state.subject_access.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    if let Err(error) = require_oid4vci_issuance_authorization_details(
        evidence,
        &state.subject_access,
        configuration,
        &principal,
        oid4vci_requires_authorization_details(
            &principal,
            state.runtime_config().as_deref(),
            Some(preauth.as_ref()),
        ),
    ) {
        let denial_code = denial_code_from_error(&error);
        let mut response = oid4vci_error_response(oid4vci_error_from_evidence(&error));
        attach_oid4vci_subject_access_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            denial_code,
            Some(state.subject_access.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    let Some(claims) = principal.verified_claims.as_ref() else {
        return oid4vci_error_response(Oid4vciWireError::InvalidToken);
    };
    let (Some(transaction_id), Some(transaction_commitment), Some(token_configuration_id)) = (
        claims
            .issuance_transaction_id
            .as_ref()
            .map(VerifiedClaimValue::as_str),
        claims
            .issuance_transaction_commitment
            .as_ref()
            .map(VerifiedClaimValue::as_str),
        claims
            .credential_configuration_id
            .as_ref()
            .map(VerifiedClaimValue::as_str),
    ) else {
        return oid4vci_error_response(Oid4vciWireError::InvalidToken);
    };
    if token_configuration_id != configuration_id {
        return oid4vci_error_response(Oid4vciWireError::InvalidToken);
    }
    let Some(nonce) = validated_proof.nonce.as_deref() else {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    };
    let holder_thumbprint = match validated_proof.holder_jwk.jkt() {
        Ok(thumbprint) => thumbprint,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidProof),
    };
    let request_hash = match serde_json::to_value(&request)
        .map_err(|_| EvidenceError::InvalidRequest)
        .and_then(|value| sha256_canonical_json(&value))
    {
        Ok(hash) => hash,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let transaction = match preauth
        .preauthorization_state()
        .begin_credential_materialization(
            transaction_id,
            transaction_commitment,
            configuration_id,
            nonce,
            &holder_thumbprint,
            &request_hash,
        )
        .await
    {
        Ok(CredentialMaterialization::Cached(response)) => {
            state
                .metrics
                .record_credential("openid4vci", "retry_cached");
            return Json(response).into_response();
        }
        Ok(CredentialMaterialization::Acquired(transaction)) => transaction,
        Ok(CredentialMaterialization::Busy) => {
            return oid4vci_error_response(Oid4vciWireError::ServerError);
        }
        Ok(CredentialMaterialization::Denied) | Err(_) => {
            return oid4vci_error_response(Oid4vciWireError::InvalidToken);
        }
    };
    let materialized = materialize_oid4vci_transaction(
        &state,
        evidence,
        &principal,
        &validated_proof,
        configuration_id,
        configuration,
        &transaction,
        nonce,
    )
    .await;
    let (response_body, evaluation) = match materialized {
        Ok(materialized) => materialized,
        Err(error) => {
            let _ = preauth
                .preauthorization_state()
                .fail_credential_materialization(transaction_id, &holder_thumbprint)
                .await;
            return oid4vci_error_response(error);
        }
    };
    if !matches!(
        preauth
            .preauthorization_state()
            .complete_credential_materialization(
                transaction_id,
                &holder_thumbprint,
                &request_hash,
                response_body.clone(),
            )
            .await,
        Ok(true)
    ) {
        let _ = preauth
            .preauthorization_state()
            .fail_credential_materialization(transaction_id, &holder_thumbprint)
            .await;
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    let profile = match evidence
        .credential_profiles
        .get(&configuration.credential_profile)
    {
        Some(profile) => profile,
        None => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let mut response = Json(response_body).into_response();
    state.metrics.record_credential("openid4vci", "issued");
    if attach_subject_access_credential_audit(
        &mut response,
        &state.subject_access_rate_keys,
        &transaction.evaluation_id,
        &evaluation.claim_ids,
        &evaluation.results,
        evaluation.results.len() as u64,
        SubjectAccessCredentialAuditDetails {
            profile_id: &configuration.credential_profile,
            holder_binding_mode: &profile.holder_binding.mode,
            policy_hash: evaluation
                .subject_access
                .as_ref()
                .and_then(|metadata| metadata.policy_hash.clone()),
            purposes: Some(vec![evaluation.purpose.clone()]),
            protocol: Some("openid4vci"),
            credential_configuration_id: Some(configuration_id),
        },
    )
    .is_err()
    {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    response
}

pub(in crate::api) async fn materialize_oid4vci_transaction(
    state: &RegistryNotaryApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    validated_proof: &ValidatedProof,
    configuration_id: &str,
    configuration: &Oid4vciCredentialConfigurationConfig,
    transaction: &IssuanceTransaction,
    nonce: &str,
) -> Result<(Value, registry_notary_core::StoredEvaluation), Oid4vciWireError> {
    let key = state
        .subject_access_rate_keys
        .oid4vci_nonce(&state.oid4vci.credential_issuer, configuration_id, nonce)
        .map_err(|_| Oid4vciWireError::ServerError)?;
    let replay_scope = oid4vci_nonce_replay_scope(state, configuration_id)?;
    let replay_key = ReplayKey::new(key).map_err(|_| Oid4vciWireError::ServerError)?;
    consume_validated_proof_nonce_once(
        validated_proof,
        nonce,
        state.replay.nonce_store().as_ref(),
        &replay_scope,
        &replay_key,
    )
    .await
    .map_err(|_| Oid4vciWireError::InvalidProof)?;
    state.metrics.record_replay("oid4vci_nonce", "consumed");
    check_oid4vci_subject_access_rate_limit(
        state,
        principal,
        Some(validated_proof.holder_id.as_str()),
    )
    .await
    .map_err(|_| Oid4vciWireError::RateLimited)?;
    let evaluation = state
        .store
        .get(
            &transaction.evaluation_id,
            &transaction.evaluation_client_id,
        )
        .await
        .map_err(|_| Oid4vciWireError::ServerError)?
        .ok_or(Oid4vciWireError::AccessDenied)?;
    if evaluation.claim_ids != configuration.credential_claim_ids() {
        return Err(Oid4vciWireError::AccessDenied);
    }
    require_oid4vci_transaction_stored_access(
        state,
        evidence,
        principal,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
    )
    .map_err(|error| oid4vci_error_from_evidence(&error))?;
    let profile = evidence
        .credential_profiles
        .get(&configuration.credential_profile)
        .ok_or(Oid4vciWireError::UnsupportedCredentialType)?;
    require_subject_access_credential_profile_policy(
        &state.subject_access,
        &configuration.credential_profile,
        profile,
    )
    .map_err(|error| oid4vci_error_from_evidence(&error))?;
    require_issuable_evaluation_provenance(evidence, &transaction.evaluation_id, &evaluation)
        .map_err(|error| oid4vci_error_from_evidence(&error))?;
    let configuration_fingerprint =
        oid4vci_configuration_fingerprint(evidence, configuration_id, configuration)
            .map_err(|_| Oid4vciWireError::ServerError)?;
    let commitment = oid4vci_issuance_transaction_commitment(
        &transaction.transaction_id,
        evidence,
        configuration_id,
        configuration,
        &configuration_fingerprint,
        &transaction.evaluation_id,
        &evaluation,
    )
    .map_err(|_| Oid4vciWireError::ServerError)?;
    if commitment != transaction.commitment {
        return Err(Oid4vciWireError::AccessDenied);
    }
    let issuer = state
        .issuer_resolver()
        .issuer(&configuration.credential_profile)
        .map_err(|_| Oid4vciWireError::ServerError)?;
    if holder_key_matches_issuer_key(&validated_proof.holder_jwk, &issuer.public_jwk()) {
        return Err(Oid4vciWireError::InvalidProof);
    }
    let holder_id = validated_proof.holder_id.as_str();
    let iat = earliest_issued_at(&evaluation.results).unwrap_or_else(OffsetDateTime::now_utc);
    let credential_id = state
        .credential_status
        .is_enabled()
        .then(sd_jwt::new_credential_id);
    let status_claim = credential_id
        .as_deref()
        .and_then(|credential_id| state.credential_status.status_claim(credential_id));
    let signed = sd_jwt::issue(
        profile,
        &issuer,
        &evaluation.results,
        holder_id,
        Some(holder_id),
        iat,
        sd_jwt::IssueOptions {
            credential_id,
            status: status_claim,
            projection: oid4vci_sd_jwt_projection(configuration),
        },
    )
    .await
    .map_err(|_| Oid4vciWireError::ServerError)?;
    let expires_at = iat
        .checked_add(time::Duration::seconds(profile.validity_seconds))
        .ok_or(Oid4vciWireError::ServerError)?;
    if state.credential_status.is_enabled() {
        state
            .credential_status
            .record_issued(
                signed.credential_id.clone(),
                signed.issuer.clone(),
                configuration.credential_profile.clone(),
                iat,
                expires_at,
            )
            .await
            .map_err(|_| Oid4vciWireError::ServerError)?;
    }
    let credential = signed.compact;
    let response = Oid4vciCredentialResponse {
        credential: credential.clone().into(),
        credentials: vec![CredentialResponseCredential {
            credential: credential.into(),
        }],
        format: Some(SD_JWT_VC_FORMAT.to_string()),
        // The 1.0 profile has no response next-nonce.
        c_nonce: None,
        c_nonce_expires_in: None,
    };
    let response = serde_json::to_value(response).map_err(|_| Oid4vciWireError::ServerError)?;
    Ok((response, evaluation))
}

pub(in crate::api) fn earliest_issued_at(
    results: &[registry_notary_core::ClaimResultView],
) -> Option<OffsetDateTime> {
    results
        .iter()
        .filter_map(|r| OffsetDateTime::parse(&r.issued_at, &Rfc3339).ok())
        .min()
}
pub(in crate::api) fn oid4vci_configuration_for_request<'a>(
    config: &'a Oid4vciConfig,
    request: &Oid4vciCredentialRequest,
) -> Result<(&'a str, &'a Oid4vciCredentialConfigurationConfig), Oid4vciWireError> {
    if let (Some(identifier), Some(configuration_id)) = (
        request.credential_identifier.as_deref(),
        request.credential_configuration_id.as_deref(),
    ) {
        if identifier != configuration_id {
            return Err(Oid4vciWireError::InvalidRequest);
        }
    }
    if let Some(id) = request
        .credential_configuration_id
        .as_deref()
        .or(request.credential_identifier.as_deref())
    {
        let (id, configuration) = config
            .credential_configurations
            .get_key_value(id)
            .ok_or(Oid4vciWireError::UnsupportedCredentialType)?;
        if let Some(vct) = request.vct.as_deref() {
            if configuration.vct != vct {
                return Err(Oid4vciWireError::InvalidRequest);
            }
        }
        return Ok((id.as_str(), configuration));
    }
    if let Some(vct) = request.vct.as_deref() {
        return config
            .credential_configurations
            .iter()
            .find(|(_, configuration)| configuration.vct == vct)
            .map(|(id, configuration)| (id.as_str(), configuration))
            .ok_or(Oid4vciWireError::UnsupportedCredentialType);
    }
    config
        .credential_configurations
        .iter()
        .next()
        .map(|(id, configuration)| (id.as_str(), configuration))
        .ok_or(Oid4vciWireError::UnsupportedCredentialType)
}

pub(in crate::api) fn oid4vci_nonce_replay_scope(
    state: &RegistryNotaryApiState,
    configuration_id: &str,
) -> Result<ReplayScope, Oid4vciWireError> {
    ReplayScope::oid4vci_nonce(
        &state.evidence.service_id,
        &state.oid4vci.credential_issuer,
        configuration_id,
    )
    .map_err(|_| Oid4vciWireError::ServerError)
}

pub(in crate::api) fn require_oid4vci_token_audience(
    config: &Oid4vciConfig,
    principal: &EvidencePrincipal,
) -> Result<(), Oid4vciWireError> {
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(Oid4vciWireError::InvalidToken)?;
    let accepted = config.accepted_token_audiences.iter().any(|accepted| {
        claims
            .audiences
            .iter()
            .any(|audience| audience.as_str() == accepted)
    });
    if accepted {
        Ok(())
    } else {
        Err(Oid4vciWireError::InvalidToken)
    }
}

pub(in crate::api) fn require_oid4vci_configuration_scope(
    configuration: &Oid4vciCredentialConfigurationConfig,
    principal: &EvidencePrincipal,
) -> Result<(), Oid4vciWireError> {
    if principal.has_scope(&configuration.scope) {
        Ok(())
    } else {
        Err(Oid4vciWireError::AccessDenied)
    }
}

pub(in crate::api) fn oid4vci_issuance_authorization_details(
    evidence: &EvidenceConfig,
    config: &SubjectAccessConfig,
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Result<registry_notary_core::EvidenceAuthorizationDetails, EvidenceError> {
    let claims = oid4vci_credential_claim_refs(configuration);
    let claim_ids = claim_ids(&claims);
    let disclosure = selected_disclosure(evidence, &claim_ids, None)
        .map_err(|_| EvidenceError::InvalidRequest)?;
    let purpose = common_subject_access_purpose(evidence, &claims)?;
    Ok(registry_notary_core::EvidenceAuthorizationDetails {
        detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
            .to_string(),
        actions: vec!["evaluate".to_string()],
        locations: vec![evidence.service_id.clone()],
        claims,
        disclosure: Some(disclosure),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some(purpose),
        subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
            binding_claim: config.subject_binding.token_claim.clone(),
            id_type: config.subject_binding.id_type.clone(),
        }),
        access_mode: Some(AccessMode::SubjectBound),
        ..Default::default()
    })
}

pub(in crate::api) fn require_oid4vci_issuance_authorization_details(
    evidence: &EvidenceConfig,
    config: &SubjectAccessConfig,
    configuration: &Oid4vciCredentialConfigurationConfig,
    principal: &EvidencePrincipal,
    require_details: bool,
) -> Result<(), EvidenceError> {
    let details = match principal.authorization_details.as_ref() {
        Some(details) if crate::authz_details::has_transaction_scope(details) => details,
        Some(_) | None if require_details => {
            return Err(subject_access_denied(
                SubjectAccessDenialCode::OperationDenied,
            ));
        }
        Some(_) | None => {
            // Direct Walt/Inji/eSignet OIDC issuance can arrive without
            // RAR-style transaction details, so those tokens keep using the
            // configured credential scope. Notary-minted pre-auth tokens are
            // local to this issuer and must carry the scoped detail minted by
            // `oid4vci_token`; empty or context-only details are not enough.
            return Ok(());
        }
    };
    let expected = oid4vci_issuance_authorization_details(evidence, config, configuration)?;
    crate::authz_details::validate_scoped_authorization_details(
        details,
        &crate::authz_details::ScopedAuthorizationRequest {
            service_id: evidence.service_id.as_str(),
            action: "evaluate",
            claims: &expected.claims,
            disclosure: expected.disclosure.as_deref().unwrap_or(""),
            format: expected.format.as_deref().unwrap_or(""),
            purpose: expected.purpose.as_deref().unwrap_or(""),
            access_mode: AccessMode::SubjectBound,
            subject: Some(crate::authz_details::ScopedAuthorizationSubject {
                binding_claim: config.subject_binding.token_claim.clone(),
                id_type: config.subject_binding.id_type.clone(),
            }),
            target: None,
            allow_subset_claims: false,
            allowed_claims: None,
        },
    )
    .map_err(subject_access_authorization_details_denial)
}

pub(in crate::api) fn oid4vci_requires_authorization_details(
    principal: &EvidencePrincipal,
    runtime_config: Option<&StandaloneRegistryNotaryConfig>,
    preauth: Option<&PreAuthRuntime>,
) -> bool {
    let Some(claims) = principal.verified_claims.as_ref() else {
        return false;
    };
    let Some(token_type) = claims.token_type.as_ref() else {
        return false;
    };
    let Some(config) = runtime_config else {
        return token_type.as_str()
            == registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP
            || token_type.as_str() == registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP
            || preauth.is_some_and(|preauth| token_type.as_str() == preauth.access_token_typ());
    };
    let signing = &config.auth.access_token_signing;
    let notary_issuer_matches = signing.enabled && claims.issuer.as_str() == signing.issuer;
    notary_issuer_matches
        && (token_type.as_str() == registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP
            || token_type.as_str() == registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP
            || preauth.is_some_and(|preauth| token_type.as_str() == preauth.access_token_typ())
            || token_type.as_str() == signing.token_typ)
}

pub(in crate::api) fn oid4vci_credential_claim_refs(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Vec<ClaimRef> {
    configuration
        .credential_claim_ids()
        .into_iter()
        .map(ClaimRef::from)
        .collect()
}

pub(in crate::api) fn add_scope_if_missing(scopes: &mut Vec<String>, scope: &str) {
    if !scopes.iter().any(|candidate| candidate == scope) {
        scopes.push(scope.to_string());
    }
}

pub(in crate::api) fn oid4vci_bound_subject(
    config: &SubjectAccessConfig,
    principal: &EvidencePrincipal,
) -> Result<SubjectRequest, EvidenceError> {
    let subject_id = principal
        .verified_subject_binding_value(&config.subject_binding.token_claim)
        .ok_or(EvidenceError::SubjectAccessInvalidToken)?;
    Ok(SubjectRequest {
        id: subject_id.to_string(),
        id_type: Some(config.subject_binding.id_type.clone()),
    })
}

pub(in crate::api) fn subject_access_bound_subject(
    config: &SubjectAccessConfig,
    principal: &EvidencePrincipal,
) -> Result<SubjectRequest, EvidenceError> {
    let subject_id = principal
        .verified_subject_binding_value(&config.subject_binding.token_claim)
        .ok_or_else(|| subject_access_denied(SubjectAccessDenialCode::SubjectClaimMissing))?;
    Ok(SubjectRequest {
        id: subject_id.to_string(),
        id_type: Some(config.subject_binding.id_type.clone()),
    })
}

pub(in crate::api) fn derive_subject_access_request_context(
    config: &SubjectAccessConfig,
    principal: &EvidencePrincipal,
    request: &mut EvaluateRequest,
) -> Result<(), EvidenceError> {
    let subject = subject_access_bound_subject(config, principal)?;
    let derived = EvidenceEntity::from_subject_request("Person", subject.clone());
    ensure_optional_entity_matches_subject(config, request.target.as_ref(), &subject)?;
    ensure_optional_entity_matches_subject(config, request.requester.as_ref(), &subject)?;
    if let Some(relationship) = request.relationship.as_ref() {
        if relationship.relationship_type != "self" || !relationship.attributes.is_empty() {
            return Err(subject_access_denied(
                SubjectAccessDenialCode::SubjectMismatch,
            ));
        }
    }
    if request.on_behalf_of.is_some() {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::SubjectMismatch,
        ));
    }
    request.target = Some(derived.clone());
    request.requester = Some(derived);
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "self".to_string(),
        attributes: Default::default(),
    });
    Ok(())
}

pub(in crate::api) fn requested_attestation_access_mode(
    principal: &EvidencePrincipal,
) -> AccessMode {
    match principal
        .authorization_details
        .as_ref()
        .and_then(|details| details.access_mode)
    {
        Some(AccessMode::DelegatedAttestation) => AccessMode::DelegatedAttestation,
        _ => AccessMode::SubjectBound,
    }
}

pub(in crate::api) fn apply_stored_subject_access_access_mode(
    principal: &mut EvidencePrincipal,
    metadata: &StoredSubjectAccessMetadata,
) -> Result<(), EvidenceError> {
    let requested_access_mode = requested_attestation_access_mode(principal);
    if requested_access_mode != metadata.access_mode {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    principal.access_mode = requested_access_mode;
    Ok(())
}

pub(in crate::api) fn derive_delegated_attestation_request_context(
    config: &SubjectAccessConfig,
    keys: &SubjectAccessRateLimitKeys,
    principal: &EvidencePrincipal,
    request: &mut EvaluateRequest,
) -> Result<(), EvidenceError> {
    if !config.delegation.enabled {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    if request.requester.is_some()
        || request.relationship.is_some()
        || request.on_behalf_of.is_some()
    {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    let Some(details) = principal.authorization_details.as_ref() else {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedRelationshipNotAllowed,
        ));
    };
    let Some(relationship) = details.relationship.as_ref() else {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedRelationshipNotAllowed,
        ));
    };
    let relationship_config = config
        .delegation
        .relationship(&relationship.relationship_type)
        .ok_or_else(|| {
            subject_access_denied(SubjectAccessDenialCode::DelegatedRelationshipNotAllowed)
        })?;
    if relationship_config.proof_claim != relationship.proof_claim {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    let target_id_type = delegated_target_id_type(config, relationship_config);
    let Some(target_subject) = request.target_subject() else {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedSubjectNotPermitted,
        ));
    };
    if target_subject.id.trim().is_empty()
        || target_subject.id_type.as_deref() != Some(target_id_type)
    {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    // Rebuild the target canonically from the validated (id, id_type) only,
    // mirroring how the requester is derived below. This collapses
    // to_subject_request(), target.identifiers.<id_type>, and target.id to a
    // single value so the binding hash, the proof claim, and the dependent
    // claim provably read the same subject. No arbitrary caller-supplied target
    // context (extra identifiers, canonical id, attributes, profile) is trusted.
    request.target = Some(EvidenceEntity::from_subject_request(
        "Person",
        target_subject,
    ));

    let requester_subject = subject_access_bound_subject(config, principal)?;
    let requester = EvidenceEntity::from_subject_request("Person", requester_subject);
    let principal_hash = keys
        .principal(&principal.principal_id)
        .map_err(|error| error.evidence_error())?;
    let assurance = principal
        .verified_claims
        .as_ref()
        .and_then(|claims| claims.acr.as_ref())
        .map(|acr| acr.as_str().to_string());
    request.requester = Some(requester);
    request.relationship = Some(EvidenceRelationship {
        relationship_type: relationship_config.relationship_type.clone(),
        attributes: Default::default(),
    });
    request.on_behalf_of = Some(EvidenceOnBehalfOf {
        actor: EvidenceActor {
            actor_type: "person".to_string(),
            id_hash: principal_hash.as_str().to_string(),
            assurance,
        },
        delegation_ref: None,
    });
    Ok(())
}

pub(in crate::api) fn delegated_target_id_type<'a>(
    config: &'a SubjectAccessConfig,
    relationship: &'a SubjectAccessDelegatedRelationshipConfig,
) -> &'a str {
    relationship
        .target_id_type
        .as_deref()
        .unwrap_or(config.subject_binding.id_type.as_str())
}

pub(in crate::api) fn ensure_optional_entity_matches_subject(
    config: &SubjectAccessConfig,
    entity: Option<&EvidenceEntity>,
    expected: &SubjectRequest,
) -> Result<(), EvidenceError> {
    let Some(entity) = entity else {
        return Ok(());
    };
    let Some(actual) = entity.to_subject_request() else {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::SubjectMismatch,
        ));
    };
    if actual.id.trim().is_empty()
        || actual.id != expected.id
        || actual.id_type.as_deref() != Some(config.subject_binding.id_type.as_str())
    {
        return Err(subject_access_denied(
            SubjectAccessDenialCode::SubjectMismatch,
        ));
    }
    Ok(())
}

pub(in crate::api) async fn check_oid4vci_subject_access_rate_limit(
    state: &RegistryNotaryApiState,
    principal: &EvidencePrincipal,
    holder_id: Option<&str>,
) -> Result<(), SubjectAccessRateLimitError> {
    let principal_hash = state
        .subject_access_rate_keys
        .principal(&principal.principal_id)?;
    let holder_hash = holder_id
        .map(|holder_id| state.subject_access_rate_keys.holder(holder_id))
        .transpose()?;
    state
        .subject_access_rate_limiter
        .check_credential_issuance(&principal_hash, holder_hash.as_ref())
        .await
}
