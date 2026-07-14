// SPDX-License-Identifier: Apache-2.0
//! Direct credential issuance and issuance policy hashing.

use super::*;

pub(super) async fn issue_credential(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    request: Result<Json<CredentialIssueRequest>, JsonRejection>,
) -> Response {
    if has_idempotency_key(&headers) {
        return credential_denial_response_without_evaluation(EvidenceError::InvalidRequest);
    }
    let request = match parse_json_body(request) {
        Ok(request) => request,
        Err(error) => return credential_denial_response_without_evaluation(error),
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(Extension(principal)) = principal else {
        return credential_denial_response_without_evaluation(EvidenceError::MissingCredential);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let mut principal =
        match classify_self_attestation_principal(&state.self_attestation, &principal) {
            Ok(principal) => principal,
            Err(error) => {
                let denial_code = denial_code_from_error(&error);
                let mut response = evidence_error_response(error);
                attach_self_attestation_audit(
                    &mut response,
                    "credential_denied",
                    &[],
                    denial_code,
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                attach_zero_relay_no_forward_audit(&mut response);
                return response;
            }
        };
    let evaluation = match state.store.get(&request.evaluation_id) {
        Some(evaluation) => evaluation,
        None => {
            return credential_denial_response_without_evaluation(
                EvidenceError::EvaluationNotFound,
            );
        }
    };
    if let Some(metadata) = evaluation.self_attestation.as_ref() {
        if principal.is_self_attestation() {
            if let Err(error) = apply_stored_self_attestation_access_mode(&mut principal, metadata)
            {
                return credential_denial_response_for_evaluation(
                    &state,
                    error,
                    &request.evaluation_id,
                    &evaluation,
                    &principal,
                    None,
                );
            }
        }
    }
    if !evaluation_client_matches(&state, &principal, &evaluation)
        || evaluation.access_mode() != principal.access_mode()
    {
        let error = if principal.is_self_attestation() {
            EvidenceError::EvaluationNotFound
        } else {
            EvidenceError::EvaluationBindingMismatch
        };
        return credential_denial_response_for_evaluation(
            &state,
            error,
            &request.evaluation_id,
            &evaluation,
            &principal,
            None,
        );
    }
    if let Err(error) = require_evaluation_access(evidence, &principal, &evaluation) {
        return credential_denial_response_for_evaluation(
            &state,
            error,
            &request.evaluation_id,
            &evaluation,
            &principal,
            None,
        );
    }
    if let Some(format) = request.format.as_deref() {
        if format != FORMAT_SD_JWT_VC {
            return credential_denial_response_for_evaluation(
                &state,
                EvidenceError::FormatUnsupported,
                &request.evaluation_id,
                &evaluation,
                &principal,
                None,
            );
        }
    }
    if let Some(disclosure) = request.disclosure.as_deref() {
        if disclosure != evaluation.disclosure {
            return credential_denial_response_for_evaluation(
                &state,
                EvidenceError::EvaluationBindingMismatch,
                &request.evaluation_id,
                &evaluation,
                &principal,
                None,
            );
        }
    }
    if let Some(claims) = &request.claims {
        if claims != &evaluation.claim_ids {
            return credential_denial_response_for_evaluation(
                &state,
                EvidenceError::EvaluationBindingMismatch,
                &request.evaluation_id,
                &evaluation,
                &principal,
                None,
            );
        }
    }
    if let Some(purpose) = request.purpose.as_deref() {
        if purpose != evaluation.purpose {
            return credential_denial_response_for_evaluation(
                &state,
                EvidenceError::EvaluationBindingMismatch,
                &request.evaluation_id,
                &evaluation,
                &principal,
                None,
            );
        }
    }
    let (profile_id, profile) = match credential_profile_for(
        evidence,
        &evaluation,
        request.credential_profile.as_deref(),
    ) {
        Ok(profile) => profile,
        Err(error) => return evidence_error_response(error),
    };
    if evaluation.format != FORMAT_SD_JWT_VC {
        return credential_denial_response_for_evaluation(
            &state,
            EvidenceError::EvaluationBindingMismatch,
            &request.evaluation_id,
            &evaluation,
            &principal,
            Some((profile_id, profile)),
        );
    }
    if let Err(error) = require_self_attestation_stored_access(
        &state,
        evidence,
        &principal,
        &evaluation,
        request.claims.as_deref().unwrap_or(&evaluation.claim_ids),
        request
            .disclosure
            .as_deref()
            .unwrap_or(&evaluation.disclosure),
        request.format.as_deref().unwrap_or(&evaluation.format),
        Some(profile_id),
    ) {
        return credential_denial_response_for_evaluation(
            &state,
            error,
            &request.evaluation_id,
            &evaluation,
            &principal,
            Some((profile_id, profile)),
        );
    }
    if principal.is_self_attestation() {
        if !state.self_attestation.allowed_operations.issue_credential {
            return credential_denial_response_for_evaluation(
                &state,
                self_attestation_denied(SelfAttestationDenialCode::OperationDenied),
                &request.evaluation_id,
                &evaluation,
                &principal,
                Some((profile_id, profile)),
            );
        }
        let profile_policy = match evaluation.self_attestation.as_ref() {
            Some(metadata) if metadata.access_mode == AccessMode::DelegatedAttestation => {
                require_delegated_attestation_credential_profile_policy(
                    &state.self_attestation,
                    metadata,
                    profile_id,
                    profile,
                )
            }
            _ => require_self_attestation_credential_profile_policy(
                &state.self_attestation,
                profile_id,
                profile,
            ),
        };
        if let Err(error) = profile_policy {
            return credential_denial_response_for_evaluation(
                &state,
                error,
                &request.evaluation_id,
                &evaluation,
                &principal,
                Some((profile_id, profile)),
            );
        }
    }
    // Fail-closed: every evaluated claim must appear in the profile's
    // allow-list. An empty `allowed_claims` therefore permits nothing rather
    // than permitting everything. The config-load validator (see
    // `EvidenceConfigError::EmptyAllowedClaims`) catches misconfiguration up
    // front; this inversion is the type-level safety net for any code path
    // that constructs an `EvidenceConfig` without going through validate().
    if !evaluation.claim_ids.iter().all(|claim| {
        profile
            .allowed_claims
            .iter()
            .any(|allowed| allowed == claim)
    }) {
        return credential_denial_response_for_evaluation(
            &state,
            EvidenceError::EvaluationBindingMismatch,
            &request.evaluation_id,
            &evaluation,
            &principal,
            Some((profile_id, profile)),
        );
    }
    if !profile.disclosure.allowed.is_empty()
        && !profile
            .disclosure
            .allowed
            .iter()
            .any(|allowed| allowed == &evaluation.disclosure)
    {
        return credential_denial_response_for_evaluation(
            &state,
            EvidenceError::DisclosureNotAllowed,
            &request.evaluation_id,
            &evaluation,
            &principal,
            Some((profile_id, profile)),
        );
    }
    let proof_binding = match validate_holder_request(
        profile,
        profile_id,
        &request,
        &evaluation,
        request.holder.as_ref(),
        &evidence.service_id,
    ) {
        Ok(binding) => binding,
        Err(error) => {
            return credential_denial_response_for_evaluation(
                &state,
                error,
                &request.evaluation_id,
                &evaluation,
                &principal,
                Some((profile_id, profile)),
            );
        }
    };
    let holder_id = request
        .holder
        .as_ref()
        .and_then(|holder| holder.id.as_deref());
    if principal.is_self_attestation() {
        let principal_hash = match state
            .self_attestation_rate_keys
            .principal(&principal.principal_id)
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        let holder_hash = match holder_id
            .map(|holder_id| state.self_attestation_rate_keys.holder(holder_id))
            .transpose()
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        if let Err(error) = state
            .self_attestation_rate_limiter
            .check_credential_issuance(&principal_hash, holder_hash.as_ref())
        {
            let mut response = evidence_error_response(error.evidence_error());
            if let Err(audit_error) = attach_self_attestation_credential_denial_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                &request.evaluation_id,
                &evaluation,
                Some((profile_id, profile)),
            ) {
                return evidence_error_response(audit_error);
            }
            if let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() {
                audit.verification_decision = Some("credential_issue_rate_limited".to_string());
                audit.denial_code = Some(SelfAttestationDenialCode::RateLimited);
                audit.rate_limit_bucket = error
                    .bucket()
                    .and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok());
            }
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            attach_zero_relay_no_forward_audit(&mut response);
            return response;
        }
    }
    let issuer = match state.issuer_resolver().issuer(profile_id) {
        Ok(issuer) => issuer,
        Err(error) => return evidence_error_response(error),
    };
    // Anchor the signed JWT `iat` to the earliest claim `issued_at` so two
    // re-issuances of the same evaluation produce identical `iat`. When claims
    // shared a memoized upstream read, all `issued_at` are equal and the JWT
    // `iat` matches the disclosure timestamps.
    let iat = earliest_issued_at(&evaluation.results).unwrap_or_else(OffsetDateTime::now_utc);
    let subject_ref = if principal.is_self_attestation() {
        match holder_id {
            Some(holder_id) => holder_id,
            None => {
                return credential_denial_response_for_evaluation(
                    &state,
                    EvidenceError::HolderProofRequired,
                    &request.evaluation_id,
                    &evaluation,
                    &principal,
                    Some((profile_id, profile)),
                );
            }
        }
    } else {
        match holder_id.or_else(|| {
            evaluation
                .results
                .first()
                .map(|result| result.target_ref.handle.as_str())
        }) {
            Some(subject_ref) => subject_ref,
            None => {
                return credential_denial_response_for_evaluation(
                    &state,
                    EvidenceError::InvalidRequest,
                    &request.evaluation_id,
                    &evaluation,
                    &principal,
                    Some((profile_id, profile)),
                );
            }
        }
    };
    if let Some(binding) = proof_binding {
        if let Err(error) = require_replay_insert(
            state.replay.store().as_ref(),
            &binding.scope,
            &binding.key,
            binding.expires_at,
        )
        .await
        {
            let evidence_error = match error {
                RequiredReplayError::AlreadySeen => {
                    state.metrics.record_replay("holder_proof", "replayed");
                    EvidenceError::HolderProofReplay
                }
                RequiredReplayError::Store { .. } => {
                    state.metrics.record_replay("holder_proof", "error");
                    EvidenceError::CredentialIssuanceFailed
                }
                _ => {
                    state.metrics.record_replay("holder_proof", "error");
                    EvidenceError::CredentialIssuanceFailed
                }
            };
            if matches!(evidence_error, EvidenceError::HolderProofReplay) {
                return credential_denial_response_for_evaluation(
                    &state,
                    evidence_error,
                    &request.evaluation_id,
                    &evaluation,
                    &principal,
                    Some((profile_id, profile)),
                );
            }
            return evidence_error_response(evidence_error);
        }
        state.metrics.record_replay("holder_proof", "accepted");
    }
    let credential_id = state
        .credential_status
        .is_enabled()
        .then(sd_jwt::new_credential_id);
    let status_claim = credential_id
        .as_deref()
        .and_then(|credential_id| state.credential_status.status_claim(credential_id));
    let signed = match sd_jwt::issue(
        profile,
        &issuer,
        &evaluation.results,
        subject_ref,
        holder_id,
        iat,
        sd_jwt::IssueOptions {
            credential_id,
            status: status_claim,
            projection: None,
        },
    )
    .await
    {
        Ok(signed) => signed,
        Err(error) => return evidence_error_response(error),
    };
    let expires_at = match iat.checked_add(time::Duration::seconds(profile.validity_seconds)) {
        Some(expires_at) => expires_at,
        None => return evidence_error_response(EvidenceError::CredentialIssuanceFailed),
    };
    if state.credential_status.is_enabled()
        && state
            .credential_status
            .record_issued(
                signed.credential_id.clone(),
                signed.issuer.clone(),
                profile_id.to_string(),
                iat,
                expires_at,
            )
            .await
            .is_err()
    {
        return evidence_error_response(EvidenceError::CredentialIssuanceFailed);
    }
    state.metrics.record_credential("direct", "issued");
    let mut response = Json(json!({
        "credential_id": signed.credential_id,
        "credential_profile": profile_id,
        "format": FORMAT_SD_JWT_VC,
        "issuer": signed.issuer,
        "expires_at": signed.expires_at,
        "credential": signed.compact,
        "issuer_signed_jwt": signed.issuer_signed_jwt,
        "disclosures": signed.disclosures,
    }))
    .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(metadata) = evaluation.self_attestation.as_ref() {
        if let Err(error) = attach_self_attestation_credential_audit(
            &mut response,
            &state.self_attestation_rate_keys,
            &request.evaluation_id,
            &evaluation.claim_ids,
            &evaluation.results,
            evaluation.results.len() as u64,
            SelfAttestationCredentialAuditDetails {
                profile_id,
                holder_binding_mode: &profile.holder_binding.mode,
                policy_hash: metadata.policy_hash.clone(),
                purposes: Some(vec![evaluation.purpose.clone()]),
                protocol: None,
                credential_configuration_id: None,
            },
        ) {
            return evidence_error_response(error);
        }
        override_attestation_audit_access_mode(&mut response, metadata.access_mode);
    } else {
        attach_evidence_audit_with_purposes(
            &mut response,
            "credential_issued",
            Some(request.evaluation_id.clone()),
            &evaluation.claim_ids,
            Some(evaluation.results.len() as u64),
            Some(vec![evaluation.purpose.clone()]),
        );
    }
    response
}

/// Pick the earliest `issued_at` from a set of claim results to use as the
/// signed JWT `iat`. Returns `None` if there are no results or none parse,
/// in which case the caller falls back to `OffsetDateTime::now_utc()`.
pub(super) fn self_attestation_policy_hash(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    claim_ids: &[String],
    disclosure: &str,
    format: &str,
) -> Result<Hashed<PolicyIdentifier>, EvidenceError> {
    let mut claim_profiles = Vec::new();
    let mut credential_profiles = Vec::new();
    for claim_id in claim_ids {
        let claim = crate::find_claim(evidence, claim_id)?;
        claim_profiles.push(json!({
            "id": claim.id,
            "purpose": claim.purpose,
            "formats": claim.formats,
            "disclosure": {
                "default": claim.disclosure.default,
                "allowed": claim.disclosure.allowed,
            },
            "credential_profiles": claim.credential_profiles,
        }));
    }
    for profile_id in &config.credential_profiles {
        let Some(profile) = evidence.credential_profiles.get(profile_id) else {
            continue;
        };
        credential_profiles.push(json!({
            "id": profile_id,
            "format": profile.format,
            "issuer": profile.issuer,
            "signing_key": profile.signing_key,
            "vct": profile.vct,
            "validity_seconds": profile.validity_seconds,
            "holder_binding": {
                "mode": profile.holder_binding.mode,
                "proof_of_possession": profile.holder_binding.proof_of_possession,
                "allowed_did_methods": profile.holder_binding.allowed_did_methods,
            },
            "allowed_claims": profile.allowed_claims,
            "disclosure": {
                "allowed": profile.disclosure.allowed,
            },
        }));
    }
    let canonical = json!({
        "subject_binding": {
            "token_claim": config.subject_binding.token_claim,
            "request_field": config.subject_binding.request_field,
            "id_type": config.subject_binding.id_type,
            "normalize": config.subject_binding.normalize,
        },
        "allowed_claims": config.allowed_claims,
        "requested_claims": claim_ids,
        "allowed_disclosures": config.allowed_disclosures,
        "requested_disclosure": disclosure,
        "allowed_formats": config.allowed_formats,
        "requested_format": format,
        "credential_profiles": config.credential_profiles,
        "delegation": config.delegation,
        "credential_profile_policy": credential_profiles,
        "max_credential_validity_seconds": config.token_policy.max_credential_validity_seconds,
        "claim_profiles": claim_profiles,
    });
    sha256_canonical_json(&canonical).map(Hashed::from_hash)
}
