// SPDX-License-Identifier: Apache-2.0
//! OID4VCI pre-authorized-code offer and token flow.

use super::super::*;

const REGISTRY_OFFER_SIGNER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
const REGISTRY_OFFER_LEASE_RENEWAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REGISTRY_OFFER_FINAL_RESERVATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(45);
const REGISTRY_OFFER_OPERATION_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(250);
const REGISTRY_OFFER_OPERATION_MAX_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(2);
const REGISTRY_OFFER_OPERATION_WAIT: std::time::Duration = std::time::Duration::from_secs(20);
pub(in crate::api) const REGISTRY_OFFER_OPERATION_RETRY_AFTER_SECONDS: &str = "5";
const _: () = assert!(
    REGISTRY_OFFER_LEASE_RENEWAL_TIMEOUT.as_secs()
        + REGISTRY_OFFER_FINAL_RESERVATION_TIMEOUT.as_secs()
        < OPERATION_LEASE_SECONDS as u64
);

#[derive(Debug, Deserialize)]
pub(in crate::api) struct Oid4vciOfferStartQuery {
    pub(in crate::api) credential_configuration_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api) struct Oid4vciRegistryOfferRequest {
    pub(in crate::api) evaluation_id: String,
    pub(in crate::api) credential_configuration_id: String,
}

/// `POST /oid4vci/offers` (authenticated): create one registrar-initiated
/// pre-authorized offer from an already stored machine evaluation.
///
/// The request cannot supply facts, target, purpose, profile, or provenance.
/// Every authority-bearing value is recovered from authenticated configuration
/// and the immutable stored evaluation.
pub(in crate::api) async fn oid4vci_create_registry_offer(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    request: Result<Json<Oid4vciRegistryOfferRequest>, JsonRejection>,
) -> Response {
    let mut response =
        oid4vci_create_registry_offer_inner(headers, state, principal, request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn oid4vci_create_registry_offer_inner(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    request: Result<Json<Oid4vciRegistryOfferRequest>, JsonRejection>,
) -> Response {
    let request = match parse_json_body(request) {
        Ok(request) => request,
        Err(error) => return evidence_error_response(error),
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let principal = match classify_subject_access_principal(&state.subject_access, &principal) {
        Ok(principal)
            if principal.access_mode() == AccessMode::MachineClient
                && principal.auth_profile_id
                    != registry_notary_core::EvidenceAuthProfileId::NotaryAccessToken
                && principal.has_scope(REGISTRY_OFFER_CREATE_SCOPE) =>
        {
            principal
        }
        Ok(_) => {
            return evidence_error_response(EvidenceError::ScopeDenied {
                required: REGISTRY_OFFER_CREATE_SCOPE.to_string(),
            })
        }
        Err(error) => return evidence_error_response(error),
    };
    let Some(idempotency_key) = idempotency_key(&headers).filter(|key| {
        !key.is_empty()
            && key.len() <= 256
            && key
                .bytes()
                .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
    }) else {
        return evidence_error_response(EvidenceError::InvalidRequest);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let Some((configuration_id, configuration)) = state
        .oid4vci
        .credential_configurations
        .get_key_value(&request.credential_configuration_id)
    else {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
    if !principal.has_scope(&configuration.scope) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: configuration.scope.clone(),
        });
    }
    let evaluation = match state
        .store
        .get(&request.evaluation_id, &principal.principal_id)
        .await
    {
        Ok(Some(evaluation))
            if evaluation.subject_access.is_none()
                && evaluation.client_id == principal.principal_id
                && evaluation.access_mode() == AccessMode::MachineClient =>
        {
            evaluation
        }
        Ok(Some(_)) | Ok(None) => {
            return evidence_error_response(EvidenceError::EvaluationNotFound);
        }
        Err(error) => return evidence_error_response(error),
    };
    let now = OffsetDateTime::now_utc();
    let evaluation_expires_at = match OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339) {
        Ok(expires_at) if expires_at > now => expires_at,
        _ => return evidence_error_response(EvidenceError::EvaluationNotFound),
    };
    let configuration_claim_ids = configuration.credential_claim_ids();
    let configuration_claim_refs = oid4vci_credential_claim_refs(configuration);
    let result_claim_ids = evaluation
        .results
        .iter()
        .map(|result| result.claim_id.clone())
        .collect::<Vec<_>>();
    if !crate::authz_details::exact_unique_string_set(
        &evaluation.claim_ids,
        &configuration_claim_ids,
    ) || !crate::authz_details::exact_unique_string_set(
        &result_claim_ids,
        &configuration_claim_ids,
    ) || !crate::authz_details::exact_unique_claim_ref_set(
        &evaluation.selected_claim_refs(),
        &configuration_claim_refs,
    ) || evaluation.disclosure != DisclosureProfile::Value.as_str()
        || evaluation.format != FORMAT_CLAIM_RESULT_JSON
        || evaluation.results.is_empty()
        || evaluation.results.iter().any(|result| {
            result.value.as_ref().is_none_or(Value::is_null)
                || result.satisfied == Some(false)
                || !result.redacted_fields.is_empty()
        })
    {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    let Some(target_ref) = evaluation.results.first().map(|result| &result.target_ref) else {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    };
    if evaluation
        .results
        .iter()
        .any(|result| !same_target_ref(&result.target_ref, target_ref))
    {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    if let Err(error) = require_evaluation_access(evidence, &principal, &evaluation) {
        return evidence_error_response(error);
    }
    let selected = evaluation.selected_claim_refs();
    let configured_purpose = match common_subject_access_purpose(evidence, &selected) {
        Ok(purpose) => purpose,
        Err(error) => return evidence_error_response(error),
    };
    if configured_purpose != evaluation.purpose
        || (!evidence.allowed_purposes.is_empty()
            && !evidence
                .allowed_purposes
                .iter()
                .any(|purpose| purpose == &evaluation.purpose))
    {
        return evidence_error_response(EvidenceError::PurposeNotAllowed);
    }
    if let Err(error) =
        require_registry_backed_credential_claims(evidence, &configuration_claim_ids)
    {
        return evidence_error_response(error);
    }
    let (profile_id, profile) = match credential_profile_for(
        evidence,
        &evaluation,
        Some(&configuration.credential_profile),
    ) {
        Ok(profile) => profile,
        Err(error) => return evidence_error_response(error),
    };
    if profile_id != configuration.credential_profile
        || (!profile.disclosure.allowed.is_empty()
            && !profile
                .disclosure
                .allowed
                .iter()
                .any(|allowed| allowed == &evaluation.disclosure))
    {
        return evidence_error_response(EvidenceError::DisclosureNotAllowed);
    }
    let credential_issued_at = earliest_issued_at(&evaluation.results).unwrap_or(now);
    let credential_expires_at =
        match credential_issued_at.checked_add(time::Duration::seconds(profile.validity_seconds)) {
            Some(expires_at) if expires_at > now => expires_at,
            Some(_) => return evidence_error_response(EvidenceError::EvaluationNotFound),
            None => return evidence_error_response(EvidenceError::CredentialIssuanceFailed),
        };
    let offer_expires_at = evaluation_expires_at.min(credential_expires_at);
    if let Err(error) =
        require_issuable_evaluation_provenance(evidence, &request.evaluation_id, &evaluation)
    {
        return evidence_error_response(error);
    }
    let Some(details) = principal.authorization_details.as_ref() else {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    };
    let Some(authorized_target) = details.target.as_ref() else {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    };
    let Some(stored_target_binding) = evaluation
        .issuance_provenance
        .as_ref()
        .map(|provenance| provenance.authorization_target_binding.as_str())
        .filter(|binding| !binding.is_empty())
    else {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    };
    let authorized_target_binding = match issuance_authorization_target_binding(
        &state.subject_access_rate_keys,
        target_ref,
        &authorized_target.id_type,
        &authorized_target.id,
    ) {
        Ok(binding) => binding,
        Err(error) => return evidence_error_response(error),
    };
    if authorized_target_binding != stored_target_binding
        || crate::authz_details::validate_scoped_authorization_details(
            details,
            &crate::authz_details::ScopedAuthorizationRequest {
                service_id: evidence.service_id.as_str(),
                action: "create_credential_offer",
                claims: &selected,
                disclosure: DisclosureProfile::Value.as_str(),
                format: FORMAT_CLAIM_RESULT_JSON,
                purpose: evaluation.purpose.as_str(),
                access_mode: AccessMode::MachineClient,
                subject: None,
                target: Some(crate::authz_details::ScopedAuthorizationTarget {
                    id_type: authorized_target.id_type.clone(),
                    id: authorized_target.id.clone(),
                }),
                allow_subset_claims: false,
                allowed_claims: None,
            },
        )
        .is_err()
    {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    let configuration_fingerprint =
        match oid4vci_configuration_fingerprint(evidence, configuration_id, configuration) {
            Ok(fingerprint) => fingerprint,
            Err(error) => return evidence_error_response(error),
        };
    let initiating_client_id_hash = match state
        .subject_access_rate_keys
        .principal(&principal.principal_id)
    {
        Ok(hash) => hash.as_str().to_string(),
        Err(error) => return evidence_error_response(error.evidence_error()),
    };
    let canonical_idempotency_input = format!(
        "client\0{}\0{}\0key\0{}\0{}",
        initiating_client_id_hash.len(),
        initiating_client_id_hash,
        idempotency_key.len(),
        idempotency_key
    );
    let idempotency_key_hash = match state.subject_access_rate_keys.audit_pseudonym_ref(
        "oid4vci-registry-offer-idempotency-v1",
        &canonical_idempotency_input,
    ) {
        Ok(hash) => hash.as_str().to_string(),
        Err(error) => return evidence_error_response(error.evidence_error()),
    };
    let mut canonical_authorized_scopes = principal.scopes.clone();
    canonical_authorized_scopes.sort();
    canonical_authorized_scopes.dedup();
    let canonical_authorization_details = canonical_registry_offer_authorization_details(details);
    let canonical_request_hash = match sha256_canonical_json(&json!({
        "schema": "registry.notary.registry-client-offer-request/v1",
        "request": request,
        "configuration_fingerprint": configuration_fingerprint,
        "evaluation": evaluation,
        "initiating_client_id_hash": initiating_client_id_hash,
        "auth_profile_id": principal.auth_profile_id,
        "authorized_scopes": canonical_authorized_scopes,
        "authorization_details": canonical_authorization_details,
    })) {
        Ok(hash) => hash,
        Err(error) => return evidence_error_response(error),
    };
    match preauth
        .preauthorization_state()
        .registry_client_offer_preflight(
            &request.evaluation_id,
            &principal.principal_id,
            &idempotency_key_hash,
            &canonical_request_hash,
        )
        .await
    {
        Ok(RegistryClientOfferPreflightOutcome::Available) => {}
        Ok(RegistryClientOfferPreflightOutcome::Replayed(response)) => {
            state
                .metrics
                .record_credential("openid4vci_registry_offer", "replayed");
            return registry_client_offer_success_response(
                response,
                &state.subject_access_rate_keys,
                "registry_offer_replayed",
                &request.evaluation_id,
                &evaluation,
                configuration_id,
                profile_id,
                &profile.holder_binding.mode,
                target_ref,
            );
        }
        Ok(RegistryClientOfferPreflightOutcome::IdempotencyConflict)
        | Ok(RegistryClientOfferPreflightOutcome::EvaluationConsumed) => {
            return registry_offer_problem(StatusCode::CONFLICT, "offer_conflict");
        }
        Err(_) => {
            return registry_offer_problem(StatusCode::SERVICE_UNAVAILABLE, "offer_unavailable");
        }
    }
    let quota_operation_id = format!(
        "idempotency\0{}\0{}",
        idempotency_key_hash.len(),
        idempotency_key_hash,
    );
    let transaction_id = match generate_opaque_token() {
        Ok(transaction_id) => transaction_id,
        Err(_) => return evidence_error_response(EvidenceError::CredentialIssuanceFailed),
    };
    let quota_wait_deadline = tokio::time::Instant::now() + REGISTRY_OFFER_OPERATION_WAIT;
    let quota_poll_jitter = std::time::Duration::from_millis(
        transaction_id.bytes().fold(0_u64, |accumulator, byte| {
            accumulator.wrapping_mul(33).wrapping_add(u64::from(byte))
        }) % 101,
    );
    let mut quota_poll_interval = REGISTRY_OFFER_OPERATION_POLL_INTERVAL;
    let _initial_quota_operation_fence = loop {
        let quota_outcome = match tokio::time::timeout_at(
            quota_wait_deadline,
            state.machine_quota_limiter.check_and_consume_once(
                &principal.principal_id,
                1,
                &quota_operation_id,
                &canonical_request_hash,
                &transaction_id,
                offer_expires_at,
            ),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                return registry_offer_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "offer_unavailable",
                );
            }
        };
        match quota_outcome {
            Ok(MachineQuotaOperationOutcome::Acquired(fence)) => break fence,
            Ok(MachineQuotaOperationOutcome::Conflict) => {
                return registry_offer_problem(StatusCode::CONFLICT, "offer_conflict");
            }
            Ok(MachineQuotaOperationOutcome::Existing) => {
                // A concurrent exact request owns the charged lease. Only
                // that owner may sign. Contenders wait for its authoritative
                // reservation, or take over an expired/released lease without
                // spending quota again.
                let preflight = match tokio::time::timeout_at(
                    quota_wait_deadline,
                    preauth
                        .preauthorization_state()
                        .registry_client_offer_preflight(
                            &request.evaluation_id,
                            &principal.principal_id,
                            &idempotency_key_hash,
                            &canonical_request_hash,
                        ),
                )
                .await
                {
                    Ok(preflight) => preflight,
                    Err(_) => {
                        return registry_offer_problem(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "offer_unavailable",
                        );
                    }
                };
                match preflight {
                    Ok(RegistryClientOfferPreflightOutcome::Replayed(response)) => {
                        state
                            .metrics
                            .record_credential("openid4vci_registry_offer", "replayed");
                        return registry_client_offer_success_response(
                            response,
                            &state.subject_access_rate_keys,
                            "registry_offer_replayed",
                            &request.evaluation_id,
                            &evaluation,
                            configuration_id,
                            profile_id,
                            &profile.holder_binding.mode,
                            target_ref,
                        );
                    }
                    Ok(RegistryClientOfferPreflightOutcome::IdempotencyConflict)
                    | Ok(RegistryClientOfferPreflightOutcome::EvaluationConsumed) => {
                        return registry_offer_problem(StatusCode::CONFLICT, "offer_conflict");
                    }
                    Ok(RegistryClientOfferPreflightOutcome::Available) => {}
                    Err(_) => {
                        return registry_offer_problem(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "offer_unavailable",
                        );
                    }
                }
                let now = tokio::time::Instant::now();
                if now >= quota_wait_deadline {
                    return registry_offer_problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "offer_unavailable",
                    );
                }
                tokio::time::sleep_until(std::cmp::min(
                    now + quota_poll_interval + quota_poll_jitter,
                    quota_wait_deadline,
                ))
                .await;
                quota_poll_interval = std::cmp::min(
                    quota_poll_interval.saturating_mul(2),
                    REGISTRY_OFFER_OPERATION_MAX_POLL_INTERVAL,
                );
            }
            Err(error) => {
                return evidence_error_response(EvidenceError::MachineQuotaExceeded {
                    retry_after_seconds: error.retry_after_seconds,
                });
            }
        }
    };
    let (quota_principal_hash, _quota_limit, quota_cost) = match state
        .machine_quota_limiter
        .batch_reservation_parameters(&principal.principal_id, 1)
    {
        Ok(parameters) => parameters,
        Err(error) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(EvidenceError::MachineQuotaExceeded {
                retry_after_seconds: error.retry_after_seconds,
            });
        }
    };
    let commitment = match oid4vci_registry_client_transaction_commitment(
        &transaction_id,
        evidence,
        configuration_id,
        configuration,
        &configuration_fingerprint,
        &request.evaluation_id,
        &evaluation,
        &initiating_client_id_hash,
        principal.auth_profile_id,
        &principal.scopes,
        target_ref,
    ) {
        Ok(commitment) => commitment,
        Err(error) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(error);
        }
    };
    let authority = IssuanceAuthority::RegistryClient {
        initiating_client_id: principal.principal_id.clone(),
        initiating_client_id_hash,
        auth_profile_id: principal.auth_profile_id,
        authorized_scopes: principal.scopes.clone(),
        target_ref: target_ref.clone(),
        service_id: evidence.service_id.clone(),
        purpose: evaluation.purpose.clone(),
    };
    let transaction = IssuanceTransaction {
        transaction_id: transaction_id.clone(),
        evaluation_id: request.evaluation_id.clone(),
        evaluation_client_id: principal.principal_id.clone(),
        credential_configuration_id: configuration_id.clone(),
        commitment: commitment.clone(),
        authority,
    };
    let now_unix = now.unix_timestamp();
    let code_exp = (now_unix + preauth.pre_authorized_code_ttl_seconds() as i64)
        .min(offer_expires_at.unix_timestamp());
    if code_exp <= now_unix {
        release_registry_offer_quota_operation(
            &state,
            &principal.principal_id,
            &quota_operation_id,
            &transaction_id,
        )
        .await;
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    }
    let code_expires_at = match OffsetDateTime::from_unix_timestamp(code_exp) {
        Ok(expires_at) => expires_at,
        Err(_) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(EvidenceError::CredentialIssuanceFailed);
        }
    };
    let transaction_expires_at = offer_expires_at
        .min(code_expires_at + time::Duration::seconds(preauth.access_token_ttl_seconds() as i64));
    let wallet_authority = BoundSubject {
        subject: transaction_id.clone(),
        subject_binding_claim: state.subject_access.subject_binding.token_claim.clone(),
        subject_binding_value: transaction_id.clone(),
        client_id: "registry-notary-wallet-transaction".to_string(),
        scopes: vec![configuration.scope.clone()],
        acr: None,
        auth_time: None,
    };
    let code_claims = PreAuthorizedCodeClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: transaction_id.clone(),
        credential_configuration_id: configuration_id.clone(),
        issuance_transaction_id: transaction_id.clone(),
        issuance_transaction_commitment: commitment,
        // Registrar-initiated offers always require a separately presented
        // transaction code, independent of the citizen self-service setting.
        tx_code_required: true,
        subject: wallet_authority,
        iat: now_unix,
        exp: code_exp,
    };
    let Some(signing_timeout) =
        registry_offer_completion_timeout(code_expires_at, REGISTRY_OFFER_SIGNER_TIMEOUT)
    else {
        release_registry_offer_quota_operation(
            &state,
            &principal.principal_id,
            &quota_operation_id,
            &transaction_id,
        )
        .await;
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
    let signed_code = match tokio::time::timeout(
        signing_timeout,
        mint_pre_authorized_code(
            preauth.access_token_signer(),
            PRE_AUTHORIZED_CODE_JWT_TYP,
            &code_claims,
        ),
    )
    .await
    {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(error);
        }
        Err(_) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(EvidenceError::CredentialIssuanceFailed);
        }
    };
    let Some(lease_renewal_timeout) =
        registry_offer_completion_timeout(code_expires_at, REGISTRY_OFFER_LEASE_RENEWAL_TIMEOUT)
    else {
        release_registry_offer_quota_operation(
            &state,
            &principal.principal_id,
            &quota_operation_id,
            &transaction_id,
        )
        .await;
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
    // The initial 60-second owner lease safely contains the 25-second signer
    // deadline. Renew immediately after signing, then bound the authoritative
    // reservation to 45 seconds. The 5-second renewal deadline leaves at
    // least ten seconds before takeover is possible. PostgreSQL and the
    // in-memory path both fence final completion on this returned owner token.
    let quota_operation_fence = match tokio::time::timeout(
        lease_renewal_timeout,
        state.machine_quota_limiter.check_and_consume_once(
            &principal.principal_id,
            1,
            &quota_operation_id,
            &canonical_request_hash,
            &transaction_id,
            offer_expires_at,
        ),
    )
    .await
    {
        Ok(Ok(MachineQuotaOperationOutcome::Acquired(fence))) => fence,
        Ok(Ok(MachineQuotaOperationOutcome::Conflict)) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return registry_offer_problem(StatusCode::CONFLICT, "offer_conflict");
        }
        Ok(Ok(MachineQuotaOperationOutcome::Existing)) | Ok(Err(_)) | Err(_) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return registry_offer_problem(StatusCode::SERVICE_UNAVAILABLE, "offer_unavailable");
        }
    };
    let tx_code = match generate_numeric_tx_code(preauth.tx_code_length()) {
        Ok(code) => code,
        Err(_) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(EvidenceError::CredentialIssuanceFailed);
        }
    };
    let offer = CredentialOffer::pre_authorized_code(
        state.oid4vci.credential_issuer.clone(),
        vec![configuration_id.clone()],
        signed_code.compact,
        Some(TxCode::new(
            preauth.tx_code_length(),
            Some("Enter the PIN delivered separately by the registrar".to_string()),
        )),
    );
    let credential_offer_uri = match offer_request_uri(&offer) {
        Ok(uri) => uri,
        Err(()) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &transaction_id,
            )
            .await;
            return evidence_error_response(EvidenceError::CredentialIssuanceFailed);
        }
    };
    let response = RegistryClientOfferResponse {
        credential_offer_uri,
        tx_code: Some(tx_code.clone()),
        expires_at: format_time(code_expires_at),
    };
    let audit_evaluation_id = request.evaluation_id.clone();
    let quota_lease_owner_id = transaction_id.clone();
    let reservation = RegistryClientOfferReservation {
        transaction_id,
        evaluation_id: request.evaluation_id,
        evaluation_expires_at,
        idempotency_key_hash,
        canonical_request_hash,
        transaction,
        transaction_code: Some(RegistryClientTransactionCode {
            pin: tx_code,
            pin_length: preauth.tx_code_length(),
        }),
        code_expires_at,
        transaction_expires_at,
        response,
        // Replays must stop when the signed code does. Evaluation consumption
        // remains independently retained through evaluation_expires_at.
        retention_expires_at: code_expires_at,
        quota_principal_hash,
        // Quota was charged before signer work. The atomic final reservation
        // must not debit the same request a second time.
        quota_limit: None,
        quota_cost,
    };
    let Some(final_reservation_timeout) = registry_offer_completion_timeout(
        code_expires_at,
        REGISTRY_OFFER_FINAL_RESERVATION_TIMEOUT,
    ) else {
        release_registry_offer_quota_operation(
            &state,
            &principal.principal_id,
            &quota_operation_id,
            &quota_lease_owner_id,
        )
        .await;
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
    let reservation_result = tokio::time::timeout(
        final_reservation_timeout,
        preauth
            .preauthorization_state()
            .reserve_registry_client_offer_fenced(reservation, &quota_operation_fence),
    )
    .await;
    let (response, audit_decision) = match reservation_result {
        Ok(Ok(RegistryClientOfferReservationOutcome::Created(response))) => {
            state
                .metrics
                .record_credential("openid4vci_registry_offer", "created");
            (response, "registry_offer_created")
        }
        Ok(Ok(RegistryClientOfferReservationOutcome::Replayed(response))) => {
            state
                .metrics
                .record_credential("openid4vci_registry_offer", "replayed");
            (response, "registry_offer_replayed")
        }
        Ok(Err(PreauthorizationStateError::IdempotencyConflict))
        | Ok(Err(PreauthorizationStateError::EvaluationConsumed)) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &quota_lease_owner_id,
            )
            .await;
            return registry_offer_problem(StatusCode::CONFLICT, "offer_conflict");
        }
        Ok(Err(PreauthorizationStateError::IssuanceTransactionCapacity)) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &quota_lease_owner_id,
            )
            .await;
            return registry_offer_problem(StatusCode::TOO_MANY_REQUESTS, "offer_rate_limited");
        }
        Ok(Err(PreauthorizationStateError::MachineQuotaExceeded {
            retry_after_seconds,
        })) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &quota_lease_owner_id,
            )
            .await;
            return evidence_error_response(EvidenceError::MachineQuotaExceeded {
                retry_after_seconds,
            });
        }
        Ok(Err(_)) => {
            release_registry_offer_quota_operation(
                &state,
                &principal.principal_id,
                &quota_operation_id,
                &quota_lease_owner_id,
            )
            .await;
            return registry_offer_problem(StatusCode::SERVICE_UNAVAILABLE, "offer_unavailable");
        }
        Err(_) => {
            // Do not release early: the dropped PostgreSQL request is poisoned
            // and canceled, but retaining the renewed lease until its bounded
            // expiry prevents a contender from signing while cancellation is
            // still propagating. A later request may take over safely.
            return registry_offer_problem(StatusCode::SERVICE_UNAVAILABLE, "offer_unavailable");
        }
    };
    registry_client_offer_success_response(
        response,
        &state.subject_access_rate_keys,
        audit_decision,
        &audit_evaluation_id,
        &evaluation,
        configuration_id,
        profile_id,
        &profile.holder_binding.mode,
        target_ref,
    )
}

/// Match authorization's exact claim-set semantics: order carries no
/// authority, while multiplicity and version do. Every other signed field
/// remains unchanged in the request identity.
fn canonical_registry_offer_authorization_details(
    details: &registry_notary_core::EvidenceAuthorizationDetails,
) -> registry_notary_core::EvidenceAuthorizationDetails {
    let mut canonical = details.clone();
    canonical.claims.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.version.cmp(&right.version))
    });
    canonical
}

pub(in crate::api) fn same_target_ref(left: &TargetRefView, right: &TargetRefView) -> bool {
    left.entity_type == right.entity_type
        && left.handle == right.handle
        && left.identifier_schemes == right.identifier_schemes
        && left.profile == right.profile
}

async fn release_registry_offer_quota_operation(
    state: &RegistryNotaryApiState,
    principal_id: &str,
    operation_id: &str,
    lease_owner_id: &str,
) {
    let _ = state
        .machine_quota_limiter
        .release_operation(principal_id, operation_id, lease_owner_id)
        .await;
}

fn registry_offer_completion_timeout(
    code_expires_at: OffsetDateTime,
    maximum: std::time::Duration,
) -> Option<std::time::Duration> {
    std::time::Duration::try_from(code_expires_at - OffsetDateTime::now_utc())
        .ok()
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(maximum))
}

pub(in crate::api) fn registry_offer_problem(status: StatusCode, code: &'static str) -> Response {
    let request_id = crate::standalone::current_request_correlation_id();
    let mut body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('_', "/")),
        "title": "Credential offer was not created",
        "status": status.as_u16(),
        "detail": "the registrar-initiated credential offer could not be created",
        "code": code,
    });
    if let Some(request_id) = request_id.as_ref() {
        body["request_id"] = json!(request_id.as_str());
    }
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(REGISTRY_OFFER_OPERATION_RETRY_AFTER_SECONDS),
        );
    }
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(code.to_string()));
    if let Some(request_id) = request_id {
        if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
            response.headers_mut().insert("x-request-id", value);
        }
    }
    response
}

#[allow(clippy::too_many_arguments)]
fn registry_client_offer_success_response(
    response: RegistryClientOfferResponse,
    keys: &SubjectAccessRateLimitKeys,
    audit_decision: &str,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
    configuration_id: &str,
    profile_id: &str,
    holder_binding_mode: &str,
    target_ref: &TargetRefView,
) -> Response {
    let response_is_fresh = OffsetDateTime::parse(&response.expires_at, &Rfc3339)
        .is_ok_and(|expires_at| expires_at > OffsetDateTime::now_utc());
    if !response_is_fresh {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    }
    let mut response = Json(response).into_response();
    if let Err(error) = attach_registry_client_offer_audit(
        &mut response,
        keys,
        audit_decision,
        evaluation_id,
        evaluation,
        configuration_id,
        profile_id,
        holder_binding_mode,
        target_ref,
    ) {
        return evidence_error_response(error);
    }
    response
}

/// `GET /oid4vci/offer/start` (public): begin the eSignet authorization-code
/// login as the confidential RP and redirect the citizen browser to eSignet.
///
/// Mints no code or credential material. Only a short-lived single-use login
/// state (PKCE verifier + nonce + selection) is reserved.
pub(in crate::api) async fn oid4vci_offer_start(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    Query(query): Query<Oid4vciOfferStartQuery>,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let configuration_id = match query
        .credential_configuration_id
        .as_deref()
        .map(|id| oid4vci_validated_configuration_id(&state.oid4vci, id))
        .transpose()
    {
        Ok(Some(id)) => id,
        Ok(None) => match single_credential_configuration_id(&state.oid4vci) {
            Some(id) => id,
            None => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
        },
        Err(()) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let (Ok(login_state), Ok(nonce), Ok(pkce_verifier)) = (
        generate_opaque_token(),
        generate_opaque_token(),
        generate_opaque_token(),
    ) else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    let pkce_challenge = pkce_s256_challenge(&pkce_verifier);
    let reserved = preauth
        .preauthorization_state()
        .reserve_login(
            &login_state,
            LoginState {
                pkce_verifier,
                nonce: nonce.clone(),
                credential_configuration_id: configuration_id,
            },
            preauth.login_state_ttl_seconds(),
        )
        .await;
    if let Err(error) = reserved {
        return match error {
            PreauthorizationStateError::LoginStateCapacity => {
                oid4vci_error_response(Oid4vciWireError::RateLimited)
            }
            PreauthorizationStateError::DuplicateLoginState
            | PreauthorizationStateError::DuplicateIssuanceTransaction
            | PreauthorizationStateError::IssuanceTransactionCapacity
            | PreauthorizationStateError::IdempotencyConflict
            | PreauthorizationStateError::EvaluationConsumed
            | PreauthorizationStateError::MachineQuotaExceeded { .. }
            | PreauthorizationStateError::OperationLeaseLost
            | PreauthorizationStateError::Unavailable
            | PreauthorizationStateError::IncompatibleTransactionCodeProof
            | PreauthorizationStateError::InvalidExpiry
            | PreauthorizationStateError::SensitiveState(_) => {
                oid4vci_error_response(Oid4vciWireError::ServerError)
            }
        };
    }
    let redirect_url = match preauth.authorize_redirect_url(&login_state, &nonce, &pkce_challenge) {
        Ok(url) => url,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    Redirect::to(&redirect_url).into_response()
}

#[derive(Debug, Deserialize)]
pub(in crate::api) struct Oid4vciOfferCallbackQuery {
    pub(in crate::api) code: Option<String>,
    pub(in crate::api) state: Option<String>,
}

pub(in crate::api) async fn prepare_registry_backed_issuance_transaction(
    state: &RegistryNotaryApiState,
    preauth: &PreAuthRuntime,
    bound_subject: &BoundSubject,
    configuration_id: &str,
    transaction_id: &str,
) -> Result<IssuanceTransaction, EvidenceError> {
    let evidence = state.enabled_evidence()?;
    let (configuration_id, configuration) = state
        .oid4vci
        .credential_configurations
        .get_key_value(configuration_id)
        .ok_or(EvidenceError::InvalidRequest)?;
    let configuration_claim_ids = configuration.credential_claim_ids();
    require_registry_backed_credential_claims(evidence, &configuration_claim_ids)?;
    let mut principal = preauth.principal_for_subject(bound_subject)?;
    add_scope_if_missing(&mut principal.scopes, &configuration.scope);
    let principal = classify_subject_access_principal(&state.subject_access, &principal)?;
    if !principal.is_subject_access()
        || requested_attestation_access_mode(&principal) == AccessMode::DelegatedAttestation
    {
        return Err(EvidenceError::SubjectAccessInvalidToken);
    }
    let target = EvidenceEntity::from_subject_request(
        "Person",
        oid4vci_bound_subject(&state.subject_access, &principal)?,
    );
    let mut request = EvaluateRequest {
        requester: Some(target.clone()),
        target: Some(target),
        relationship: Some(EvidenceRelationship {
            relationship_type: "self".to_string(),
            attributes: Default::default(),
        }),
        on_behalf_of: None,
        variables: Default::default(),
        claims: configuration_claim_ids
            .iter()
            .map(|claim_id| ClaimRef::from(claim_id.as_str()))
            .collect(),
        disclosure: None,
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: None,
    };
    let context =
        prepare_subject_access_credential_evaluation(state, evidence, &principal, &request)?;
    request.purpose = Some(context.purpose.clone());
    let results = state
        .runtime()
        .evaluate_with_capability(
            Arc::clone(&state.evidence),
            &state.store,
            &principal,
            context.evaluation_capability,
            request,
            None,
            Some(context.metadata),
            None,
        )
        .await?;
    let evaluation_id = results
        .first()
        .map(|result| result.evaluation_id.clone())
        .filter(|id| !id.is_empty())
        .ok_or(EvidenceError::CredentialIssuanceFailed)?;
    let evaluation_client_id = stored_evaluation_client_id(state, &principal)?;
    let evaluation = state
        .store
        .get(&evaluation_id, &evaluation_client_id)
        .await?
        .ok_or(EvidenceError::EvaluationNotFound)?;
    require_subject_access_stored_access(
        state,
        evidence,
        &principal,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        true,
    )?;
    if !state.subject_access.allowed_operations.issue_credential {
        return Err(EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::OperationDenied,
        });
    }
    let profile = evidence
        .credential_profiles
        .get(&configuration.credential_profile)
        .ok_or(EvidenceError::ProfileUnsupported)?;
    require_subject_access_credential_profile_policy(
        &state.subject_access,
        &configuration.credential_profile,
        profile,
    )?;
    require_issuable_evaluation_provenance(evidence, &evaluation_id, &evaluation)?;
    let configuration_fingerprint =
        oid4vci_configuration_fingerprint(evidence, configuration_id, configuration)?;
    let commitment = oid4vci_issuance_transaction_commitment(
        transaction_id,
        evidence,
        configuration_id,
        configuration,
        &configuration_fingerprint,
        &evaluation_id,
        &evaluation,
    )?;
    Ok(IssuanceTransaction {
        transaction_id: transaction_id.to_string(),
        evaluation_id,
        evaluation_client_id,
        credential_configuration_id: configuration_id.clone(),
        commitment,
        authority: crate::preauth_state::IssuanceAuthority::SubjectAccess,
    })
}

pub(in crate::api) fn oid4vci_configuration_fingerprint(
    evidence: &EvidenceConfig,
    configuration_id: &str,
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Result<String, EvidenceError> {
    let profile = evidence
        .credential_profiles
        .get(&configuration.credential_profile)
        .ok_or(EvidenceError::ProfileUnsupported)?;
    let signing_key = evidence
        .signing_keys
        .get(&profile.signing_key)
        .ok_or(EvidenceError::CredentialIssuerNotConfigured)?;
    let mut normalized = BTreeMap::new();
    normalized.insert("schema_version", json!("registry-notary-oid4vci-config/v1"));
    normalized.insert("service_id", json!(evidence.service_id));
    normalized.insert("credential_configuration_id", json!(configuration_id));
    normalized.insert(
        "credential_configuration",
        serde_json::to_value(configuration).map_err(|_| EvidenceError::InvalidRequest)?,
    );
    let claim_definitions = configuration
        .credential_claim_ids()
        .into_iter()
        .map(|claim_id| {
            let definition = evidence
                .claims
                .iter()
                .find(|claim| claim.id == claim_id)
                .ok_or(EvidenceError::InvalidRequest)?;
            serde_json::to_value(definition)
                .map(|definition| (claim_id, definition))
                .map_err(|_| EvidenceError::InvalidRequest)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    normalized.insert("claim_definitions", json!(claim_definitions));
    normalized.insert(
        "credential_profile",
        json!({
            "id": configuration.credential_profile,
            "format": profile.format,
            "issuer": profile.issuer,
            "signing_key": profile.signing_key,
            "vct": profile.vct,
            "validity_seconds": profile.validity_seconds,
            "holder_binding": profile.holder_binding,
            "allowed_claims": profile.allowed_claims,
            "disclosure": profile.disclosure,
        }),
    );
    normalized.insert(
        "signing_key",
        json!({
            "id": profile.signing_key,
            "provider": signing_key.provider,
            "alg": signing_key.alg,
            "kid": signing_key.kid,
            "status": signing_key.status,
            "publish_until_unix_seconds": signing_key.publish_until_unix_seconds,
        }),
    );
    sha256_canonical_json(
        &serde_json::to_value(normalized).map_err(|_| EvidenceError::InvalidRequest)?,
    )
}

pub(in crate::api) fn oid4vci_issuance_transaction_commitment(
    transaction_id: &str,
    evidence: &EvidenceConfig,
    configuration_id: &str,
    configuration: &Oid4vciCredentialConfigurationConfig,
    configuration_fingerprint: &str,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<String, EvidenceError> {
    let subject_access = evaluation
        .subject_access
        .as_ref()
        .ok_or(EvidenceError::EvaluationBindingMismatch)?;
    let provenance = evaluation
        .issuance_provenance
        .as_ref()
        .ok_or(EvidenceError::CredentialIssuanceFailed)?;
    if !subject_access
        .principal_hash
        .as_str()
        .starts_with("hmac-sha256:")
        || !subject_access
            .subject_binding_hash
            .as_str()
            .starts_with("hmac-sha256:")
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let mut normalized = BTreeMap::new();
    normalized.insert(
        "schema_version",
        json!("registry-notary-oid4vci-issuance-transaction/v1"),
    );
    normalized.insert("transaction_id", json!(transaction_id));
    normalized.insert(
        "authenticated_principal_hash",
        json!(subject_access.principal_hash),
    );
    normalized.insert(
        "authenticated_subject_binding_hash",
        json!(subject_access.subject_binding_hash),
    );
    normalized.insert("authenticated_issuer", json!(subject_access.issuer));
    normalized.insert("authenticated_client", json!(subject_access.client_id));
    normalized.insert("service", json!(evidence.service_id));
    normalized.insert("purpose", json!(evaluation.purpose));
    normalized.insert(
        "canonical_claim_references",
        json!(evaluation.selected_claim_refs()),
    );
    normalized.insert("credential_configuration_id", json!(configuration_id));
    normalized.insert(
        "credential_profile",
        json!(configuration.credential_profile),
    );
    normalized.insert(
        "configuration_fingerprint",
        json!(configuration_fingerprint),
    );
    normalized.insert(
        "relay_contract_and_provenance",
        serde_json::to_value(provenance).map_err(|_| EvidenceError::InvalidRequest)?,
    );
    normalized.insert("stored_evaluation_id", json!(evaluation_id));
    sha256_canonical_json(
        &serde_json::to_value(normalized).map_err(|_| EvidenceError::InvalidRequest)?,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::api) fn oid4vci_registry_client_transaction_commitment(
    transaction_id: &str,
    evidence: &EvidenceConfig,
    configuration_id: &str,
    configuration: &Oid4vciCredentialConfigurationConfig,
    configuration_fingerprint: &str,
    evaluation_id: &str,
    evaluation: &registry_notary_core::StoredEvaluation,
    initiating_client_id_hash: &str,
    auth_profile_id: registry_notary_core::EvidenceAuthProfileId,
    authorized_scopes: &[String],
    target_ref: &TargetRefView,
) -> Result<String, EvidenceError> {
    if evaluation.subject_access.is_some()
        || evaluation.client_id.is_empty()
        || !initiating_client_id_hash.starts_with("hmac-sha256:")
        || evaluation.results.is_empty()
        || evaluation
            .results
            .iter()
            .any(|result| !same_target_ref(&result.target_ref, target_ref))
    {
        return Err(EvidenceError::EvaluationBindingMismatch);
    }
    let provenance = evaluation
        .issuance_provenance
        .as_ref()
        .ok_or(EvidenceError::EvaluationBindingMismatch)?;
    let issuance_material_binding = sha256_canonical_json(&json!({
        "schema": "registry.notary.oid4vci-issuance-material/v1",
        "evaluation_id": evaluation_id,
        "purpose": evaluation.purpose,
        "claim_references": evaluation.selected_claim_refs(),
        "disclosure": evaluation.disclosure,
        "format": evaluation.format,
        "results": evaluation.results,
        "created_at": evaluation.created_at,
        "expires_at": evaluation.expires_at,
        "request_hash": evaluation.request_hash,
        "issuance_provenance": provenance,
    }))?;
    let mut authorized_scopes = authorized_scopes.to_vec();
    authorized_scopes.sort();
    authorized_scopes.dedup();
    let mut normalized = BTreeMap::new();
    normalized.insert(
        "schema_version",
        json!("registry-notary-oid4vci-registry-client-transaction/v1"),
    );
    normalized.insert("transaction_id", json!(transaction_id));
    normalized.insert(
        "initiating_client_id_hash",
        json!(initiating_client_id_hash),
    );
    normalized.insert("auth_profile_id", json!(auth_profile_id));
    normalized.insert("authorized_scopes", json!(authorized_scopes));
    normalized.insert("target_ref", json!(target_ref));
    normalized.insert("service", json!(evidence.service_id));
    normalized.insert("purpose", json!(evaluation.purpose));
    normalized.insert(
        "canonical_claim_references",
        json!(evaluation.selected_claim_refs()),
    );
    normalized.insert("credential_configuration_id", json!(configuration_id));
    normalized.insert(
        "credential_profile",
        json!(configuration.credential_profile),
    );
    normalized.insert(
        "configuration_fingerprint",
        json!(configuration_fingerprint),
    );
    normalized.insert("stored_evaluation_id", json!(evaluation_id));
    normalized.insert(
        "issuance_material_binding",
        json!(issuance_material_binding),
    );
    sha256_canonical_json(
        &serde_json::to_value(normalized).map_err(|_| EvidenceError::InvalidRequest)?,
    )
}

/// `GET /oid4vci/offer/callback` (public): consume the login state, exchange the
/// eSignet code via `private_key_jwt`, validate the `id_token`, mint a single-use
/// `pre-authorized_code`, and render the offer page.
pub(in crate::api) async fn oid4vci_offer_callback(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    Query(query): Query<Oid4vciOfferCallbackQuery>,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = "/oid4vci/offer/callback";
    let (Some(code), Some(login_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return preauth_denied(
            &preauth,
            path,
            "GET",
            None,
            SubjectAccessDenialCode::InvalidToken,
            Oid4vciWireError::InvalidRequest,
        )
        .await;
    };
    // Single-use consume: unknown/expired/replayed state is the CSRF/replay
    // guard. A missing state yields no code.
    let stored = match preauth
        .preauthorization_state()
        .consume_login(login_state)
        .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                None,
                SubjectAccessDenialCode::InvalidToken,
                Oid4vciWireError::InvalidRequest,
            )
            .await;
        }
        Err(_) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                None,
                SubjectAccessDenialCode::OperationDenied,
                Oid4vciWireError::ServerError,
            )
            .await;
        }
    };
    let subject_binding_claim = state.subject_access.subject_binding.token_claim.clone();
    let subject = match preauth
        .exchange_code_for_subject(
            code,
            &stored.pkce_verifier,
            &stored.nonce,
            &subject_binding_claim,
        )
        .await
    {
        Ok(subject) => subject,
        Err(_) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                Some(&stored.credential_configuration_id),
                SubjectAccessDenialCode::InvalidToken,
                Oid4vciWireError::InvalidToken,
            )
            .await;
        }
    };
    let bound_subject = BoundSubject {
        subject: subject.subject,
        subject_binding_claim,
        subject_binding_value: subject.subject_binding_value,
        client_id: subject.client_id,
        scopes: subject.scopes,
        acr: subject.acr,
        auth_time: subject.auth_time,
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Ok(jti) = generate_opaque_token() else {
        return preauth_server_error(&preauth, path, "GET", &stored.credential_configuration_id)
            .await;
    };
    // The registry-backed evaluation is completed before any offer is minted.
    // A denied, unavailable, stale, malformed, or provenance-invalid Relay
    // outcome therefore leaves the caller with no wallet grant at all.
    let transaction = match prepare_registry_backed_issuance_transaction(
        &state,
        &preauth,
        &bound_subject,
        &stored.credential_configuration_id,
        &jti,
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::warn!(
                code = error.audit_code(),
                "registry-backed OID4VCI evaluation denied before offer minting"
            );
            return preauth_denied(
                &preauth,
                path,
                "GET",
                Some(&stored.credential_configuration_id),
                denial_code_from_error(&error).unwrap_or(SubjectAccessDenialCode::OperationDenied),
                oid4vci_error_from_evidence(&error),
            )
            .await;
        }
    };
    let code_exp = now + preauth.pre_authorized_code_ttl_seconds() as i64;
    let transaction_expires_at = match OffsetDateTime::from_unix_timestamp(
        code_exp + preauth.access_token_ttl_seconds() as i64,
    ) {
        Ok(expires_at) => expires_at,
        Err(_) => {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
    };
    if preauth
        .preauthorization_state()
        .reserve_issuance_transaction(&jti, transaction.clone(), transaction_expires_at)
        .await
        .is_err()
    {
        return preauth_server_error(&preauth, path, "GET", &stored.credential_configuration_id)
            .await;
    }
    let code_claims = PreAuthorizedCodeClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: jti.clone(),
        credential_configuration_id: stored.credential_configuration_id.clone(),
        issuance_transaction_id: jti.clone(),
        issuance_transaction_commitment: transaction.commitment.clone(),
        tx_code_required: preauth.tx_code_required(),
        subject: bound_subject,
        iat: now,
        exp: code_exp,
    };
    let signed_code = match mint_pre_authorized_code(
        preauth.access_token_signer(),
        PRE_AUTHORIZED_CODE_JWT_TYP,
        &code_claims,
    )
    .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
    };
    let tx_code_pin = if preauth.tx_code_required() {
        let Ok(pin) = generate_numeric_tx_code(preauth.tx_code_length()) else {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        };
        // Persist the PIN keyed by the code's jti so the token endpoint can verify
        // the holder-presented tx_code. The PIN is never embedded in the offer code
        // JWT (otherwise the code holder would know it).
        let expires_at = match OffsetDateTime::from_unix_timestamp(code_claims.exp) {
            Ok(expires_at) => expires_at,
            Err(_) => {
                return preauth_server_error(
                    &preauth,
                    path,
                    "GET",
                    &stored.credential_configuration_id,
                )
                .await;
            }
        };
        if !matches!(
            preauth
                .preauthorization_state()
                .reserve_transaction_code(&jti, &pin, preauth.tx_code_length(), expires_at,)
                .await,
            Ok(true)
        ) {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
        Some(pin)
    } else {
        None
    };
    let tx_code = tx_code_pin.as_ref().map(|_| {
        TxCode::new(
            preauth.tx_code_length(),
            Some("Enter the PIN shown by the issuer".to_string()),
        )
    });
    let offer = CredentialOffer::pre_authorized_code(
        state.oid4vci.credential_issuer.clone(),
        vec![stored.credential_configuration_id.clone()],
        signed_code.compact.clone(),
        tx_code,
    );
    let offer_uri = match offer_request_uri(&offer) {
        Ok(uri) => uri,
        Err(_) => {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
    };
    let audit = pre_auth_audit_event(
        "GET",
        path,
        StatusCode::OK.as_u16(),
        "preauth_offer_minted",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                &stored.credential_configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    state
        .metrics
        .record_credential("openid4vci_preauth", "offer_minted");
    Html(offer_page_html(&offer_uri, tx_code_pin.as_deref())).into_response()
}

/// `POST /oid4vci/token` (public): the OID4VCI token endpoint for the
/// pre-authorized-code grant. Verifies the code and optional `tx_code`, then mints a
/// short-TTL Notary access token + `c_nonce`.
pub(in crate::api) async fn oid4vci_token(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = "/oid4vci/token";
    let client_address = token_client_address(&state, &headers, connect_info.as_deref());
    let request = match parse_token_request(&headers, &body) {
        Ok(request) => request,
        Err(error) => {
            return token_error_with_audit(
                &preauth,
                path,
                None,
                SubjectAccessDenialCode::OperationDenied,
                error,
            )
            .await;
        }
    };
    if request.grant_type != PRE_AUTHORIZED_CODE_GRANT_TYPE {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SubjectAccessDenialCode::OperationDenied,
            TokenWireError::UnsupportedGrantType,
        )
        .await;
    }
    let Some(code) = request
        .pre_authorized_code
        .as_deref()
        .filter(|c| !c.is_empty())
    else {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SubjectAccessDenialCode::OperationDenied,
            TokenWireError::InvalidRequest,
        )
        .await;
    };
    // Throttle random-code floods per client address (reuse the existing
    // invalid-token-per-address limiter bucket).
    if check_token_client_address_rate_limit(&state, &client_address)
        .await
        .is_err()
    {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SubjectAccessDenialCode::RateLimited,
            TokenWireError::SlowDown,
        )
        .await;
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let verified = match preauth
        .access_token_verification_keys()
        .iter()
        .filter(|key| key.may_verify_at(now))
        .find_map(|key| {
            verify_notary_token(
                code,
                key.public_jwk(),
                PRE_AUTHORIZED_CODE_JWT_TYP,
                preauth.notary_issuer(),
                &[],
                now,
            )
            .ok()
        }) {
        Some(verified) => verified,
        None => {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                None,
                TokenWireError::InvalidGrant,
            )
            .await;
        }
    };
    let configuration_id = verified
        .claim_str("credential_configuration_id")
        .map(ToString::to_string);
    let Some(jti) = verified.claim_str("jti").map(ToString::to_string) else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(code_expires_at) = verified
        .claim_i64("exp")
        .and_then(|expiry| OffsetDateTime::from_unix_timestamp(expiry).ok())
    else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(tx_code_required) = verified
        .payload
        .get("tx_code_required")
        .and_then(Value::as_bool)
    else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(configuration_id) = configuration_id else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            None,
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some((configuration_id, configuration)) = state
        .oid4vci
        .credential_configurations
        .get_key_value(&configuration_id)
    else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            Some(&configuration_id),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(transaction_id) = verified.claim_str("issuance_transaction_id") else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(transaction_commitment) = verified.claim_str("issuance_transaction_commitment") else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let live_transaction = match preauth
        .preauthorization_state()
        .transaction(transaction_id)
        .await
    {
        Ok(Some(live))
            if live.transaction.commitment == transaction_commitment
                && live.transaction.credential_configuration_id == *configuration_id =>
        {
            Some(live)
        }
        _ => None,
    };
    let transaction_access_mode = live_transaction
        .as_ref()
        .map(|live| issuance_authority_access_mode(&live.transaction.authority))
        .unwrap_or(AccessMode::SubjectBound);
    // Enforce the signed code's PIN-attempt policy even when its transaction
    // binding is absent or invalid. This prevents a forged transaction ID from
    // bypassing the per-code brute-force guard.
    if tx_code_required && check_tx_code_attempt(&state, code).await.is_err() {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::SlowDown,
        )
        .await;
    }
    if transaction_id != jti {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::InvalidGrant,
        )
        .await;
    }
    let Some(live_transaction) = live_transaction else {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let access_token_exp = (now + preauth.access_token_ttl_seconds() as i64)
        .min(live_transaction.expires_at.unix_timestamp());
    let Ok(access_token_expires_in) = u64::try_from(access_token_exp - now) else {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    if access_token_expires_in == 0 {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::InvalidGrant,
        )
        .await;
    }
    let transaction = live_transaction.transaction;
    let transaction_code = if tx_code_required {
        let tx_code = request.tx_code.as_deref().unwrap_or("");
        match preauth
            .preauthorization_state()
            .verify_transaction_code(&jti, tx_code)
            .await
        {
            Ok(Some(proof)) => Some(proof),
            Ok(None) => {
                return token_error_after_invalid_attempt_with_access_mode(
                    &state,
                    &preauth,
                    path,
                    &client_address,
                    Some(configuration_id),
                    transaction_access_mode,
                    TokenWireError::InvalidGrant,
                )
                .await;
            }
            Err(_) => {
                return token_error_with_audit_access_mode(
                    &preauth,
                    path,
                    Some(configuration_id),
                    SubjectAccessDenialCode::OperationDenied,
                    transaction_access_mode,
                    TokenWireError::ServerError,
                )
                .await;
            }
        }
    } else {
        None
    };
    let Some(bound_subject) = bound_subject_from_code(&verified, &state) else {
        return token_error_after_invalid_attempt_with_access_mode(
            &state,
            &preauth,
            path,
            &client_address,
            Some(configuration_id),
            transaction_access_mode,
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let mut bound_subject = bound_subject;
    add_scope_if_missing(&mut bound_subject.scopes, &configuration.scope);
    let (authorization_detail, actor) = match &transaction.authority {
        IssuanceAuthority::SubjectAccess => (
            oid4vci_issuance_authorization_details(
                &state.evidence,
                &state.subject_access,
                configuration,
            ),
            None,
        ),
        IssuanceAuthority::RegistryClient {
            initiating_client_id_hash,
            auth_profile_id,
            service_id,
            purpose,
            ..
        } if service_id == &state.evidence.service_id
            && initiating_client_id_hash.starts_with("hmac-sha256:") =>
        {
            (
                Ok(oid4vci_registry_client_authorization_details(
                    &state.evidence,
                    configuration,
                    purpose,
                )),
                Some(json!({
                    "type": "registry_client",
                    "client_id_hash": initiating_client_id_hash,
                    "auth_profile_id": auth_profile_id,
                })),
            )
        }
        IssuanceAuthority::RegistryClient { .. } => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::InvalidGrant,
            )
            .await;
        }
    };
    let authorization_details = match authorization_detail.and_then(|details| {
        serde_json::to_value(details).map_err(|_| EvidenceError::CredentialIssuanceFailed)
    }) {
        Ok(details) => vec![details],
        Err(_) => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    let replay_scope = match verified
        .claim_str("iss")
        .and_then(|issuer| pre_authorized_code_replay_scope(issuer).ok())
    {
        Some(scope) => scope,
        None => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    match preauth
        .preauthorization_state()
        .redeem(
            &replay_scope,
            &jti,
            code_expires_at,
            tx_code_required,
            transaction_code,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return token_error_after_invalid_attempt_with_access_mode(
                &state,
                &preauth,
                path,
                &client_address,
                Some(configuration_id),
                transaction_access_mode,
                TokenWireError::InvalidGrant,
            )
            .await;
        }
        Err(_) => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::ServerError,
            )
            .await;
        }
    }
    let configuration_id = configuration_id.as_str();
    let c_nonce = match issue_c_nonce(&state, configuration_id).await {
        Some(c_nonce) => c_nonce,
        None => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    if !matches!(
        preauth
            .preauthorization_state()
            .bind_transaction_nonce(transaction_id, &transaction.commitment, c_nonce.clone(),)
            .await,
        Ok(true)
    ) {
        return token_error_with_audit_access_mode(
            &preauth,
            path,
            Some(configuration_id),
            SubjectAccessDenialCode::OperationDenied,
            transaction_access_mode,
            TokenWireError::ServerError,
        )
        .await;
    }
    let access_token_claims = AccessTokenClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: None,
        audiences: preauth.notary_audiences().to_vec(),
        token_type: "Bearer".to_string(),
        credential_configuration_id: configuration_id.to_string(),
        issuance_transaction_id: transaction_id.to_string(),
        issuance_transaction_commitment: transaction.commitment.clone(),
        subject: bound_subject,
        authorization_details,
        confirmation: None,
        actor,
        iat: now,
        exp: access_token_exp,
    };
    let access_token = match mint_access_token(
        preauth.access_token_signer(),
        preauth.access_token_typ(),
        &access_token_claims,
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            return token_error_with_audit_access_mode(
                &preauth,
                path,
                Some(configuration_id),
                SubjectAccessDenialCode::OperationDenied,
                transaction_access_mode,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    let mut audit = pre_auth_audit_event(
        "POST",
        path,
        StatusCode::OK.as_u16(),
        "preauth_token_issued",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    audit.access_mode = Some(issuance_authority_access_mode(&transaction.authority));
    if preauth.emit_audit(&audit).await.is_err() {
        return token_error_response(TokenWireError::ServerError);
    }
    state
        .metrics
        .record_credential("openid4vci_preauth", "token_issued");
    Json(Oid4vciTokenResponse {
        access_token: access_token.compact,
        token_type: "Bearer".to_string(),
        expires_in: Some(access_token_expires_in),
        c_nonce: Some(c_nonce),
        c_nonce_expires_in: state
            .oid4vci
            .nonce
            .enabled
            .then_some(state.oid4vci.nonce.ttl_seconds),
    })
    .into_response()
}

pub(in crate::api) const fn issuance_authority_access_mode(
    authority: &IssuanceAuthority,
) -> AccessMode {
    match authority {
        IssuanceAuthority::SubjectAccess => AccessMode::SubjectBound,
        IssuanceAuthority::RegistryClient { .. } => AccessMode::MachineClient,
    }
}

/// The pre-auth runtime, present only when the flow is enabled and configured.
pub(in crate::api) fn preauth_runtime(
    state: &RegistryNotaryApiState,
) -> Option<Arc<PreAuthRuntime>> {
    if !state.oid4vci.enabled {
        return None;
    }
    state.runtime_snapshot().preauth.clone()
}

/// Validate a requested `credential_configuration_id` against the configured
/// set. Returns the canonical id, or `Err(())` if unknown.
pub(in crate::api) fn oid4vci_validated_configuration_id(
    config: &Oid4vciConfig,
    requested: &str,
) -> Result<String, ()> {
    config
        .credential_configurations
        .get_key_value(requested)
        .map(|(id, _)| id.clone())
        .ok_or(())
}

/// The single configured credential configuration id, or `None` if zero or
/// more than one are configured.
pub(in crate::api) fn single_credential_configuration_id(config: &Oid4vciConfig) -> Option<String> {
    let mut ids = config.credential_configurations.keys();
    let first = ids.next()?;
    if ids.next().is_some() {
        return None;
    }
    Some(first.clone())
}

pub(in crate::api) fn pre_authorized_code_replay_scope(
    verified_notary_issuer: &str,
) -> Result<ReplayScope, ()> {
    ReplayScope::new([
        (
            "protocol".to_string(),
            "openid4vci-pre-authorized-code".to_string(),
        ),
        (
            "notary_issuer".to_string(),
            verified_notary_issuer.to_string(),
        ),
    ])
    .map_err(|_| ())
}

/// Build the `openid-credential-offer://` request URI carrying the offer JSON.
pub(in crate::api) fn offer_request_uri(offer: &CredentialOffer) -> Result<String, ()> {
    let json = serde_json::to_string(offer).map_err(|_| ())?;
    let encoded = url_percent_encode(&json);
    Ok(format!(
        "openid-credential-offer://?credential_offer={encoded}"
    ))
}

/// Percent-encode a value for a query string (RFC 3986 unreserved set kept).
pub(in crate::api) fn url_percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                out.push('%');
                out.push(HEX[(other >> 4) as usize] as char);
                out.push(HEX[(other & 0x0F) as usize] as char);
            }
        }
    }
    out
}

/// Render the citizen-facing offer page: the QR-encodable offer URI plus an
/// out-of-band PIN when the offer requires one.
pub(in crate::api) fn offer_page_html(offer_uri: &str, pin: Option<&str>) -> String {
    let offer_uri = html_escape(offer_uri);
    let pin_html = pin.map(|pin| {
        let pin = html_escape(pin);
        format!(
            "<p>Then enter this PIN when your wallet asks:</p>\
<p><strong id=\"tx-code\">{pin}</strong></p>"
        )
    });
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Credential offer</title></head><body>\
<h1>Scan to receive your credential</h1>\
<p>Scan this offer in your wallet:</p>\
<p><a id=\"credential-offer\" href=\"{offer_uri}\">{offer_uri}</a></p>\
{}\
</body></html>",
        pin_html.unwrap_or_default()
    )
}

pub(in crate::api) fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Reconstruct the `BoundSubject` carried inside a verified pre-authorized code.
pub(in crate::api) fn bound_subject_from_code(
    verified: &registry_notary_core::tokens::VerifiedNotaryToken,
    state: &RegistryNotaryApiState,
) -> Option<BoundSubject> {
    let subject_binding_claim = state.subject_access.subject_binding.token_claim.clone();
    Some(BoundSubject {
        subject: verified.claim_str("sub")?.to_string(),
        subject_binding_value: verified.claim_str(&subject_binding_claim)?.to_string(),
        subject_binding_claim,
        client_id: verified.claim_str("client_id")?.to_string(),
        scopes: verified.scopes(),
        acr: verified.claim_str("acr").map(ToString::to_string),
        auth_time: verified.claim_i64("auth_time"),
    })
}

/// Issue a `c_nonce` for the credential endpoint, reserving it in the replay
/// store exactly as the nonce endpoint does.
pub(in crate::api) async fn issue_c_nonce(
    state: &RegistryNotaryApiState,
    configuration_id: &str,
) -> Option<String> {
    if !state.oid4vci.nonce.enabled {
        // The credential endpoint requires a c_nonce; without the nonce
        // endpoint enabled there is nothing to reserve, so the value is unused.
        return generate_nonce().ok();
    }
    let nonce = generate_nonce().ok()?;
    let key = state
        .subject_access_rate_keys
        .oid4vci_nonce(&state.oid4vci.credential_issuer, configuration_id, &nonce)
        .ok()?;
    let scope = oid4vci_nonce_replay_scope(state, configuration_id).ok()?;
    let replay_key = ReplayKey::new(key).ok()?;
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
    if state
        .replay
        .nonce_store()
        .reserve_nonce(&scope, &replay_key, expires_at)
        .await
        .is_ok()
    {
        state.metrics.record_replay("oid4vci_nonce", "reserved");
        Some(nonce)
    } else {
        None
    }
}

/// Derive a per-client identifier for public endpoint flood throttles.
///
/// Forwarding headers are accepted only from explicitly trusted proxy peers.
/// Otherwise the public OID4VCI endpoints use the socket peer so
/// caller-controlled `X-Forwarded-*` headers cannot create fresh buckets.
pub(in crate::api) fn token_client_address(
    state: &RegistryNotaryApiState,
    headers: &HeaderMap,
    connect_info: Option<&axum::extract::ConnectInfo<SocketAddr>>,
) -> String {
    token_client_address_with_trusted_proxy_ips(
        headers,
        connect_info,
        &state
            .runtime_config()
            .map(|config| config.server.trusted_proxy_ips.clone())
            .unwrap_or_default(),
    )
}

pub(in crate::api) fn token_client_address_with_trusted_proxy_ips(
    headers: &HeaderMap,
    connect_info: Option<&axum::extract::ConnectInfo<SocketAddr>>,
    trusted_proxy_ips: &[IpAddr],
) -> String {
    let Some(axum::extract::ConnectInfo(addr)) = connect_info else {
        return "unknown-client-address".to_string();
    };
    let peer_ip = addr.ip();
    if trusted_proxy_ips.contains(&peer_ip) {
        if let Some(forwarded_ip) = forwarded_client_ip(headers) {
            return forwarded_ip.to_string();
        }
    }
    peer_ip.to_string()
}

pub(in crate::api) fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|candidate| candidate.parse::<IpAddr>().ok())
        })
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
}

/// Per-client-address throttle so random-code floods are bounded. Reuses the
/// existing invalid-token-per-address limiter bucket. This is a check-only gate
/// (availability); the bucket is consumed only on an invalid attempt, matching
/// the auth middleware's check-before / consume-after pattern.
pub(in crate::api) async fn check_token_client_address_rate_limit(
    state: &RegistryNotaryApiState,
    client_address: &str,
) -> Result<(), SubjectAccessRateLimitError> {
    let hashed = state
        .subject_access_rate_keys
        .client_address(client_address)?;
    state
        .subject_access_rate_limiter
        .check_invalid_token_for_client_address_available(&hashed)
        .await
}

/// Record one `tx_code` attempt against the hashed pre-authorized code. After
/// the configured cap the code is locked.
pub(in crate::api) async fn check_tx_code_attempt(
    state: &RegistryNotaryApiState,
    pre_authorized_code: &str,
) -> Result<(), SubjectAccessRateLimitError> {
    let hashed = state
        .subject_access_rate_keys
        .pre_authorized_code(pre_authorized_code)?;
    state
        .subject_access_rate_limiter
        .check_tx_code_attempt(&hashed)
        .await
}

/// Emit a denial audit event for a public pre-auth endpoint and return the
/// matching OID4VCI error response.
pub(in crate::api) async fn preauth_denied(
    preauth: &PreAuthRuntime,
    path: &str,
    method: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SubjectAccessDenialCode,
    wire_error: Oid4vciWireError,
) -> Response {
    let response = oid4vci_error_response(wire_error);
    let status = response.status().as_u16();
    let audit = pre_auth_audit_event(
        method,
        path,
        status,
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: credential_configuration_id
                .and_then(|id| registry_notary_core::ConfigMetadata::new(id).ok()),
            denial_code: Some(denial_code),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    response
}

pub(in crate::api) async fn preauth_server_error(
    preauth: &PreAuthRuntime,
    path: &str,
    method: &str,
    credential_configuration_id: &str,
) -> Response {
    let audit = pre_auth_audit_event(
        method,
        path,
        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                credential_configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    let _ = preauth.emit_audit(&audit).await;
    oid4vci_error_response(Oid4vciWireError::ServerError)
}

/// Count an invalid token-endpoint attempt against the client address, emit a
/// denial audit event, and return the OAuth error. The rate counter for the
/// flood guard is consumed here so repeated random codes are throttled.
pub(in crate::api) async fn token_error_after_invalid_attempt(
    state: &RegistryNotaryApiState,
    preauth: &PreAuthRuntime,
    path: &str,
    client_address: &str,
    credential_configuration_id: Option<&str>,
    error: TokenWireError,
) -> Response {
    token_error_after_invalid_attempt_with_access_mode(
        state,
        preauth,
        path,
        client_address,
        credential_configuration_id,
        AccessMode::SubjectBound,
        error,
    )
    .await
}

async fn token_error_after_invalid_attempt_with_access_mode(
    state: &RegistryNotaryApiState,
    preauth: &PreAuthRuntime,
    path: &str,
    client_address: &str,
    credential_configuration_id: Option<&str>,
    access_mode: AccessMode,
    error: TokenWireError,
) -> Response {
    if let Ok(hashed) = state
        .subject_access_rate_keys
        .client_address(client_address)
    {
        let _ = state
            .subject_access_rate_limiter
            .check_invalid_token_for_client_address(&hashed)
            .await;
    }
    token_error_with_audit_access_mode(
        preauth,
        path,
        credential_configuration_id,
        SubjectAccessDenialCode::InvalidToken,
        access_mode,
        error,
    )
    .await
}

pub(in crate::api) async fn token_error_with_audit(
    preauth: &PreAuthRuntime,
    path: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SubjectAccessDenialCode,
    error: TokenWireError,
) -> Response {
    token_error_with_audit_access_mode(
        preauth,
        path,
        credential_configuration_id,
        denial_code,
        AccessMode::SubjectBound,
        error,
    )
    .await
}

async fn token_error_with_audit_access_mode(
    preauth: &PreAuthRuntime,
    path: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SubjectAccessDenialCode,
    access_mode: AccessMode,
    error: TokenWireError,
) -> Response {
    let response = token_error_response(error);
    let audit = token_error_audit_event_with_access_mode(
        path,
        response.status().as_u16(),
        credential_configuration_id,
        denial_code,
        access_mode,
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return token_error_after_audit_result(response, true);
    }
    token_error_after_audit_result(response, false)
}

pub(in crate::api) fn token_error_after_audit_result(
    response: Response,
    audit_failed: bool,
) -> Response {
    if audit_failed {
        token_error_response(TokenWireError::ServerError)
    } else {
        response
    }
}

pub(in crate::api) fn token_error_audit_event_with_access_mode(
    path: &str,
    status: u16,
    credential_configuration_id: Option<&str>,
    denial_code: SubjectAccessDenialCode,
    access_mode: AccessMode,
) -> EvidenceAuditEvent {
    let mut audit = token_error_audit_event(path, status, credential_configuration_id, denial_code);
    audit.access_mode = Some(access_mode);
    audit
}

pub(in crate::api) fn token_error_audit_event(
    path: &str,
    status: u16,
    credential_configuration_id: Option<&str>,
    denial_code: SubjectAccessDenialCode,
) -> EvidenceAuditEvent {
    pre_auth_audit_event(
        "POST",
        path,
        status,
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: credential_configuration_id
                .and_then(|id| registry_notary_core::ConfigMetadata::new(id).ok()),
            denial_code: Some(denial_code),
            ..PreAuthAuditFields::default()
        },
    )
}

/// Parse a `TokenRequest` from a form-encoded or JSON body. A missing/other
/// grant or unparseable body is returned as a clean `invalid_request`, never a
/// deserialize panic.
pub(in crate::api) fn parse_token_request(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Oid4vciTokenRequest, TokenWireError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/json") {
        serde_json::from_slice(body).map_err(|_| TokenWireError::InvalidRequest)
    } else {
        // Default to form encoding (the OID4VCI / OAuth content type).
        parse_token_form(body)
    }
}

/// Parse an `application/x-www-form-urlencoded` token request body. Only the
/// three pre-authorized-code grant fields are recognized; a missing
/// `grant_type` is `invalid_request`.
pub(in crate::api) fn parse_token_form(
    body: &Bytes,
) -> Result<Oid4vciTokenRequest, TokenWireError> {
    let raw = std::str::from_utf8(body).map_err(|_| TokenWireError::InvalidRequest)?;
    let mut grant_type = None;
    let mut pre_authorized_code = None;
    let mut tx_code = None;
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = form_urldecode(key)?;
        let value = form_urldecode(value)?;
        match key.as_str() {
            "grant_type" => grant_type = Some(value),
            "pre-authorized_code" => pre_authorized_code = Some(value),
            "tx_code" => tx_code = Some(value),
            _ => {}
        }
    }
    Ok(Oid4vciTokenRequest {
        grant_type: grant_type.ok_or(TokenWireError::InvalidRequest)?,
        pre_authorized_code,
        tx_code,
    })
}

/// Decode one `application/x-www-form-urlencoded` component (`+` to space,
/// `%XX` to byte). Rejects malformed percent escapes.
pub(in crate::api) fn form_urldecode(value: &str) -> Result<String, TokenWireError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let hi = bytes
                    .get(index + 1)
                    .copied()
                    .ok_or(TokenWireError::InvalidRequest)?;
                let lo = bytes
                    .get(index + 2)
                    .copied()
                    .ok_or(TokenWireError::InvalidRequest)?;
                let byte = hex_nibble(hi)? * 16 + hex_nibble(lo)?;
                out.push(byte);
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| TokenWireError::InvalidRequest)
}

pub(in crate::api) fn hex_nibble(byte: u8) -> Result<u8, TokenWireError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TokenWireError::InvalidRequest),
    }
}

#[cfg(test)]
mod replay_scope_tests {
    use super::*;

    #[test]
    fn preauthorized_code_scope_is_fixed_by_the_verified_token_issuer() {
        let issuer = "https://notary.example";
        assert_eq!(
            pre_authorized_code_replay_scope(issuer).unwrap(),
            pre_authorized_code_replay_scope(issuer).unwrap()
        );
        assert_ne!(
            pre_authorized_code_replay_scope(issuer).unwrap(),
            pre_authorized_code_replay_scope("https://other-notary.example").unwrap()
        );
    }
}
