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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) if principal.is_self_attestation() => principal,
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
        attach_oid4vci_self_attestation_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            Some(SelfAttestationDenialCode::DelegatedRelationshipNotAllowed),
            Some(state.self_attestation.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    if let Err(error) = require_oid4vci_configuration_scope(configuration, &principal) {
        let mut response = oid4vci_error_response(error);
        attach_oid4vci_self_attestation_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            Some(SelfAttestationDenialCode::OperationDenied),
            Some(state.self_attestation.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    let preauth = preauth_runtime(&state);
    if let Err(error) = require_oid4vci_issuance_authorization_details(
        evidence,
        &state.self_attestation,
        configuration,
        &principal,
        oid4vci_requires_authorization_details(
            &principal,
            state.runtime_config().as_deref(),
            preauth.as_deref(),
        ),
    ) {
        let denial_code = denial_code_from_error(&error);
        let mut response = oid4vci_error_response(oid4vci_error_from_evidence(&error));
        attach_oid4vci_self_attestation_denial_audit(
            &mut response,
            "oid4vci_credential_denied",
            &configuration_claim_ids,
            configuration_id,
            denial_code,
            Some(state.self_attestation.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    let expected_nonce = if state.oid4vci.nonce.enabled {
        let Some(nonce) = validated_proof.nonce.as_deref() else {
            return oid4vci_error_response(Oid4vciWireError::InvalidProof);
        };
        Some(nonce)
    } else {
        None
    };
    let profile = match evidence
        .credential_profiles
        .get(&configuration.credential_profile)
    {
        Some(profile) => profile,
        None => return oid4vci_error_response(Oid4vciWireError::UnsupportedCredentialType),
    };
    let issuer = match state
        .issuer_resolver()
        .issuer(&configuration.credential_profile)
    {
        Ok(issuer) => issuer,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    if holder_key_matches_issuer_key(&validated_proof.holder_jwk, &issuer.public_jwk()) {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    }
    if let Some(nonce) = expected_nonce {
        let key = match state.self_attestation_rate_keys.oid4vci_nonce(
            &state.oid4vci.credential_issuer,
            configuration_id,
            nonce,
        ) {
            Ok(key) => key,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
        };
        let replay_scope = match oid4vci_nonce_replay_scope(&state, configuration_id) {
            Ok(scope) => scope,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
        };
        let replay_key = match ReplayKey::new(key) {
            Ok(key) => key,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
        };
        match consume_validated_proof_nonce_once(
            &validated_proof,
            nonce,
            state.replay.nonce_store().as_ref(),
            &replay_scope,
            &replay_key,
        )
        .await
        {
            Ok(()) => {
                state.metrics.record_replay("oid4vci_nonce", "consumed");
            }
            Err(registry_platform_oid4vci::ProofError::InvalidNonce) => {
                state.metrics.record_replay("oid4vci_nonce", "replayed");
                return oid4vci_error_response(Oid4vciWireError::InvalidProof);
            }
            Err(_) => {
                state.metrics.record_replay("oid4vci_nonce", "invalid");
                return oid4vci_error_response(Oid4vciWireError::InvalidProof);
            }
        }
    }
    let holder_id = validated_proof.holder_id.as_str();
    if let Err(error) =
        check_oid4vci_self_attestation_rate_limit(&state, &principal, Some(holder_id))
    {
        let mut response = oid4vci_error_response(Oid4vciWireError::RateLimited);
        attach_self_attestation_rate_limit_audit(
            &mut response,
            "oid4vci_rate_limited",
            &configuration_claim_ids,
            error.bucket(),
        );
        return response;
    }
    let target = match oid4vci_bound_subject(&state.self_attestation, &principal) {
        Ok(subject) => EvidenceEntity::from_subject_request("Person", subject),
        Err(_) => {
            let mut response = oid4vci_error_response(Oid4vciWireError::InvalidToken);
            attach_oid4vci_self_attestation_denial_audit(
                &mut response,
                "oid4vci_credential_denied",
                &configuration_claim_ids,
                configuration_id,
                Some(SelfAttestationDenialCode::InvalidToken),
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let request = EvaluateRequest {
        requester: Some(target.clone()),
        target: Some(target),
        relationship: Some(EvidenceRelationship {
            relationship_type: "self".to_string(),
            attributes: Default::default(),
        }),
        on_behalf_of: None,
        claims: configuration_claim_ids
            .iter()
            .map(|claim_id| ClaimRef::from(claim_id.as_str()))
            .collect(),
        disclosure: None,
        format: Some(FORMAT_SD_JWT_VC.to_string()),
        purpose: None,
    };
    let mut request = request;
    let context = match prepare_self_attestation_evaluate(&state, evidence, &principal, &request) {
        Ok(context) => {
            request.purpose = Some(context.purpose.clone());
            context
        }
        Err(error) => {
            let denial_code = denial_code_from_error(&error);
            let mut response = oid4vci_error_response(oid4vci_error_from_evidence(&error));
            attach_oid4vci_self_attestation_denial_audit(
                &mut response,
                "oid4vci_credential_denied",
                &configuration_claim_ids,
                configuration_id,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let results = match state
        .runtime()
        .evaluate_with_source_capability(
            Arc::clone(&state.evidence),
            Arc::clone(&state.source),
            &state.store,
            &principal,
            context.source_capability,
            request,
            None,
            Some(context.metadata.clone()),
            None,
        )
        .await
    {
        Ok(results) => results,
        Err(error) => {
            let denial_code = denial_code_from_error(&error);
            let mut response = oid4vci_error_response(oid4vci_error_from_evidence(&error));
            attach_oid4vci_self_attestation_denial_audit(
                &mut response,
                "oid4vci_credential_denied",
                &configuration_claim_ids,
                configuration_id,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let evaluation_id = results
        .first()
        .map(|result| result.evaluation_id.clone())
        .unwrap_or_default();
    let evaluation = match state.store.get(&evaluation_id) {
        Some(evaluation) => evaluation,
        None => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    if let Err(error) = require_self_attestation_stored_access(
        &state,
        evidence,
        &principal,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        Some(configuration.credential_profile.as_str()),
    ) {
        return oid4vci_error_response(oid4vci_error_from_evidence(&error));
    }
    if !state.self_attestation.allowed_operations.issue_credential {
        return oid4vci_error_response(Oid4vciWireError::AccessDenied);
    }
    if let Err(error) = require_self_attestation_credential_profile_policy(
        &state.self_attestation,
        &configuration.credential_profile,
        profile,
    ) {
        return oid4vci_error_response(oid4vci_error_from_evidence(&error));
    }
    let iat = earliest_issued_at(&evaluation.results).unwrap_or_else(OffsetDateTime::now_utc);
    let credential_id = state
        .credential_status
        .is_enabled()
        .then(sd_jwt::new_credential_id);
    let status_claim = credential_id
        .as_deref()
        .and_then(|credential_id| state.credential_status.status_claim(credential_id));
    let projection = oid4vci_sd_jwt_projection(configuration);
    let signed = match sd_jwt::issue(
        profile,
        &issuer,
        &evaluation.results,
        holder_id,
        Some(holder_id),
        iat,
        sd_jwt::IssueOptions {
            credential_id,
            status: status_claim,
            projection,
        },
    )
    .await
    {
        Ok(signed) => signed,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let expires_at = match iat.checked_add(time::Duration::seconds(profile.validity_seconds)) {
        Some(expires_at) => expires_at,
        None => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    if state.credential_status.is_enabled()
        && state
            .credential_status
            .record_issued(
                signed.credential_id.clone(),
                signed.issuer.clone(),
                configuration.credential_profile.clone(),
                iat,
                expires_at,
            )
            .await
            .is_err()
    {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    let next_nonce = if state.oid4vci.nonce.enabled {
        match generate_nonce() {
            Ok(nonce) => {
                if let Ok(key) = state.self_attestation_rate_keys.oid4vci_nonce(
                    &state.oid4vci.credential_issuer,
                    configuration_id,
                    &nonce,
                ) {
                    let expires_at = OffsetDateTime::now_utc()
                        + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
                    let replay_scope = oid4vci_nonce_replay_scope(&state, configuration_id).ok();
                    let replay_key = ReplayKey::new(key).ok();
                    match (replay_scope, replay_key) {
                        (Some(scope), Some(key)) => {
                            if state
                                .replay
                                .nonce_store()
                                .reserve_nonce(&scope, &key, expires_at)
                                .await
                                .is_ok()
                            {
                                state.metrics.record_replay("oid4vci_nonce", "reserved");
                                Some(nonce)
                            } else {
                                state.metrics.record_replay("oid4vci_nonce", "error");
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let credential = signed.compact;
    let mut response = Json(Oid4vciCredentialResponse {
        credential: credential.clone().into(),
        credentials: vec![CredentialResponseCredential {
            credential: credential.into(),
        }],
        format: Some(SD_JWT_VC_FORMAT.to_string()),
        c_nonce: next_nonce,
        c_nonce_expires_in: state
            .oid4vci
            .nonce
            .enabled
            .then_some(state.oid4vci.nonce.ttl_seconds),
    })
    .into_response();
    state.metrics.record_credential("openid4vci", "issued");
    if attach_self_attestation_credential_audit(
        &mut response,
        &state.self_attestation_rate_keys,
        &evaluation_id,
        &evaluation.claim_ids,
        &evaluation.results,
        evaluation.results.len() as u64,
        SelfAttestationCredentialAuditDetails {
            profile_id: &configuration.credential_profile,
            holder_binding_mode: &profile.holder_binding.mode,
            policy_hash: context.metadata.policy_hash,
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

pub(in crate::api) fn oid4vci_nonce_configuration_id(
    config: &Oid4vciConfig,
    requested_id: Option<String>,
) -> Result<&str, Oid4vciWireError> {
    if let Some(id) = requested_id {
        return config
            .credential_configurations
            .get_key_value(&id)
            .map(|(id, _)| id.as_str())
            .ok_or(Oid4vciWireError::InvalidRequest);
    }
    let mut ids = config.credential_configurations.keys();
    let Some(first) = ids.next() else {
        return Err(Oid4vciWireError::InvalidRequest);
    };
    if ids.next().is_some() {
        return Err(Oid4vciWireError::InvalidRequest);
    }
    Ok(first.as_str())
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
    config: &SelfAttestationConfig,
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Result<registry_notary_core::EvidenceAuthorizationDetails, EvidenceError> {
    let claims = oid4vci_credential_claim_refs(configuration);
    let claim_ids = claim_ids(&claims);
    let disclosure = selected_disclosure(evidence, &claim_ids, None)
        .map_err(|_| EvidenceError::InvalidRequest)?;
    let purpose = common_self_attestation_purpose(evidence, &claims)?;
    Ok(registry_notary_core::EvidenceAuthorizationDetails {
        detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
            .to_string(),
        actions: vec!["evaluate".to_string()],
        locations: vec![evidence.service_id.clone()],
        claims,
        disclosure: Some(disclosure),
        format: Some(FORMAT_SD_JWT_VC.to_string()),
        purpose: Some(purpose),
        subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
            binding_claim: config.subject_binding.token_claim.clone(),
            id_type: config.subject_binding.id_type.clone(),
        }),
        access_mode: Some(AccessMode::SelfAttestation),
        ..Default::default()
    })
}

pub(in crate::api) fn require_oid4vci_issuance_authorization_details(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    configuration: &Oid4vciCredentialConfigurationConfig,
    principal: &EvidencePrincipal,
    require_details: bool,
) -> Result<(), EvidenceError> {
    let details = match principal.authorization_details.as_ref() {
        Some(details) if crate::authz_details::has_transaction_scope(details) => details,
        Some(_) | None if require_details => {
            return Err(self_attestation_denied(
                SelfAttestationDenialCode::OperationDenied,
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
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<SubjectRequest, EvidenceError> {
    let subject_id = principal
        .verified_subject_binding_value(&config.subject_binding.token_claim)
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    Ok(SubjectRequest {
        id: subject_id.to_string(),
        id_type: Some(config.subject_binding.id_type.clone()),
    })
}

pub(in crate::api) fn self_attestation_bound_subject(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<SubjectRequest, EvidenceError> {
    let subject_id = principal
        .verified_subject_binding_value(&config.subject_binding.token_claim)
        .ok_or_else(|| self_attestation_denied(SelfAttestationDenialCode::SubjectClaimMissing))?;
    Ok(SubjectRequest {
        id: subject_id.to_string(),
        id_type: Some(config.subject_binding.id_type.clone()),
    })
}

pub(in crate::api) fn derive_self_attestation_request_context(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &mut EvaluateRequest,
) -> Result<(), EvidenceError> {
    let subject = self_attestation_bound_subject(config, principal)?;
    let derived = EvidenceEntity::from_subject_request("Person", subject.clone());
    ensure_optional_entity_matches_subject(config, request.target.as_ref(), &subject)?;
    ensure_optional_entity_matches_subject(config, request.requester.as_ref(), &subject)?;
    if let Some(relationship) = request.relationship.as_ref() {
        if relationship.relationship_type != "self" || !relationship.attributes.is_empty() {
            return Err(self_attestation_denied(
                SelfAttestationDenialCode::SubjectMismatch,
            ));
        }
    }
    if request.on_behalf_of.is_some() {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
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
        _ => AccessMode::SelfAttestation,
    }
}

pub(in crate::api) fn apply_stored_self_attestation_access_mode(
    principal: &mut EvidencePrincipal,
    metadata: &StoredSelfAttestationMetadata,
) -> Result<(), EvidenceError> {
    let requested_access_mode = requested_attestation_access_mode(principal);
    if requested_access_mode != metadata.access_mode {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    principal.access_mode = requested_access_mode;
    Ok(())
}

pub(in crate::api) fn derive_delegated_attestation_request_context(
    config: &SelfAttestationConfig,
    keys: &SelfAttestationRateLimitKeys,
    principal: &EvidencePrincipal,
    request: &mut EvaluateRequest,
) -> Result<(), EvidenceError> {
    if !config.delegation.enabled {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    }
    if request.requester.is_some()
        || request.relationship.is_some()
        || request.on_behalf_of.is_some()
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    }
    let Some(details) = principal.authorization_details.as_ref() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    };
    let Some(relationship) = details.relationship.as_ref() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedRelationshipNotAllowed,
        ));
    };
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
    let target_id_type = delegated_target_id_type(config, relationship_config);
    let Some(target_subject) = request.target_subject() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
        ));
    };
    if target_subject.id.trim().is_empty()
        || target_subject.id_type.as_deref() != Some(target_id_type)
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::DelegatedSubjectNotPermitted,
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

    let requester_subject = self_attestation_bound_subject(config, principal)?;
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
    config: &'a SelfAttestationConfig,
    relationship: &'a SelfAttestationDelegatedRelationshipConfig,
) -> &'a str {
    relationship
        .target_id_type
        .as_deref()
        .unwrap_or(config.subject_binding.id_type.as_str())
}

pub(in crate::api) fn ensure_optional_entity_matches_subject(
    config: &SelfAttestationConfig,
    entity: Option<&EvidenceEntity>,
    expected: &SubjectRequest,
) -> Result<(), EvidenceError> {
    let Some(entity) = entity else {
        return Ok(());
    };
    let Some(actual) = entity.to_subject_request() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    };
    if actual.id.trim().is_empty()
        || actual.id != expected.id
        || actual.id_type.as_deref() != Some(config.subject_binding.id_type.as_str())
    {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    Ok(())
}

pub(in crate::api) fn check_oid4vci_self_attestation_rate_limit(
    state: &RegistryNotaryApiState,
    principal: &EvidencePrincipal,
    holder_id: Option<&str>,
) -> Result<(), SelfAttestationRateLimitError> {
    let principal_hash = state
        .self_attestation_rate_keys
        .principal(&principal.principal_id)?;
    let holder_hash = holder_id
        .map(|holder_id| state.self_attestation_rate_keys.holder(holder_id))
        .transpose()?;
    state
        .self_attestation_rate_limiter
        .check_credential_issuance(&principal_hash, holder_hash.as_ref())
}
