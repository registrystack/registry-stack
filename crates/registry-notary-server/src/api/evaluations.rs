// SPDX-License-Identifier: Apache-2.0
//! Evaluation, batch evaluation, and rendering handlers.

use super::*;

pub(super) async fn evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    correlation_id: Option<Extension<BoundedCorrelationId>>,
    request: Result<Json<EvaluateRequest>, JsonRejection>,
) -> Response {
    if has_idempotency_key(&headers) {
        return evidence_error_response(EvidenceError::InvalidRequest);
    }
    let request = match parse_json_body(request) {
        Ok(request) => request,
        Err(error) => return evidence_error_response(error),
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let mut request = request;
    match negotiate_request_format(evidence, &headers, request.format.as_deref()) {
        Ok(format) => request.format = Some(format),
        Err(error) => return evidence_error_response(error),
    }
    let request_claim_ids = claim_ids(&request.claims);
    let mut principal =
        match classify_self_attestation_principal(&state.self_attestation, &principal) {
            Ok(principal) => principal,
            Err(error) => {
                if let Err(rate_error) =
                    consume_classification_denial_if_keyable(&state, &principal)
                {
                    let mut response = evidence_error_response(rate_error.evidence_error());
                    attach_self_attestation_rate_limit_audit(
                        &mut response,
                        "evaluate_rate_limited",
                        &request_claim_ids,
                        rate_error.bucket(),
                    );
                    return response;
                }
                let mut response = evidence_error_response(error);
                let denial_code = denial_code_from_response(&response);
                attach_self_attestation_audit(
                    &mut response,
                    "evaluate_denied",
                    &request_claim_ids,
                    denial_code,
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                return response;
            }
        };
    let mut self_attestation_context = None;
    if principal.is_self_attestation() {
        // Classification only proves the caller is a citizen attester. The
        // transaction token authorization details select self vs delegated.
        let attestation_access_mode = requested_attestation_access_mode(&principal);
        principal.access_mode = attestation_access_mode;
        let principal_hash = match state
            .self_attestation_rate_keys
            .principal(&principal.principal_id)
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        if let Err(error) = state
            .self_attestation_rate_limiter
            .check_authenticated_request(&principal_hash)
        {
            let mut response = evidence_error_response(error.evidence_error());
            attach_self_attestation_rate_limit_audit(
                &mut response,
                "evaluate_rate_limited",
                &request_claim_ids,
                error.bucket(),
            );
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            return response;
        }
        let context_result = if attestation_access_mode == AccessMode::DelegatedAttestation {
            derive_delegated_attestation_request_context(
                &state.self_attestation,
                &state.self_attestation_rate_keys,
                &principal,
                &mut request,
            )
        } else {
            derive_self_attestation_request_context(
                &state.self_attestation,
                &principal,
                &mut request,
            )
        };
        if let Err(error) = context_result {
            if denial_code_from_error(&error).is_some_and(subject_mismatch_denial_code) {
                if let Err(rate_error) = consume_subject_mismatch_denial(&state, &principal_hash) {
                    let mut response = evidence_error_response(rate_error.evidence_error());
                    attach_self_attestation_rate_limit_audit(
                        &mut response,
                        "evaluate_rate_limited",
                        &request_claim_ids,
                        rate_error.bucket(),
                    );
                    override_attestation_audit_access_mode(&mut response, principal.access_mode());
                    return response;
                }
            }
            let denial_code = denial_code_from_error(&error);
            let mut response = evidence_error_response(error);
            attach_self_attestation_audit(
                &mut response,
                "evaluate_denied",
                &request_claim_ids,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            return response;
        }
        match prepare_self_attestation_evaluate(&state, evidence, &principal, &request) {
            Ok(context) => {
                request.purpose = Some(context.purpose.clone());
                self_attestation_context = Some(context);
            }
            Err(error) => {
                if denial_code_from_error(&error).is_some_and(subject_mismatch_denial_code) {
                    if let Err(rate_error) =
                        consume_subject_mismatch_denial(&state, &principal_hash)
                    {
                        let mut response = evidence_error_response(rate_error.evidence_error());
                        attach_self_attestation_rate_limit_audit(
                            &mut response,
                            "evaluate_rate_limited",
                            &request_claim_ids,
                            rate_error.bucket(),
                        );
                        override_attestation_audit_access_mode(
                            &mut response,
                            principal.access_mode(),
                        );
                        return response;
                    }
                }
                let denial_code = denial_code_from_error(&error);
                let mut response = evidence_error_response(error);
                attach_self_attestation_audit(
                    &mut response,
                    "evaluate_denied",
                    &request_claim_ids,
                    denial_code,
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
                return response;
            }
        }
    } else if let Err(error) = state
        .machine_quota_limiter
        .check_and_consume(&principal.principal_id, 1)
    {
        let quota_error = EvidenceError::MachineQuotaExceeded {
            retry_after_seconds: error.retry_after_seconds,
        };
        let audit_code = quota_error.audit_code();
        let mut response = evidence_error_response(quota_error);
        attach_evidence_audit_with_purposes(
            &mut response,
            "evaluate_denied",
            None,
            &request_claim_ids,
            None,
            resolved_evaluate_audit_purposes(purpose_header(&headers), request.purpose.as_deref()),
        );
        attach_zero_source_no_forward_audit(&mut response);
        if let Err(error) = attach_evaluate_request_audit(
            &mut response,
            &state.self_attestation_rate_keys,
            &request,
            None,
            Some(audit_code),
            None,
        ) {
            return evidence_error_response(error);
        }
        return response;
    }
    let runtime = state.runtime();
    let requested_claims = request_claim_ids;
    let self_attestation_policy_hash = self_attestation_context
        .as_ref()
        .and_then(|context| context.metadata.policy_hash.clone());
    let request_correlation_id = correlation_id
        .as_ref()
        .map(|Extension(correlation_id)| correlation_id.clone());
    let audit_request = request.clone();
    let evaluation_future = async {
        if let Some(context) = self_attestation_context {
            runtime
                .evaluate_with_source_capability(
                    Arc::clone(&state.evidence),
                    Arc::clone(&state.source),
                    &state.store,
                    &principal,
                    context.source_capability,
                    request,
                    None,
                    Some(context.metadata),
                    request_correlation_id.clone(),
                )
                .await
        } else {
            runtime
                .evaluate(
                    Arc::clone(&state.evidence),
                    Arc::clone(&state.source),
                    &state.store,
                    &principal,
                    request,
                    purpose_header(&headers),
                )
                .await
        }
    };
    let evaluation = if let Some(Extension(correlation_id)) = correlation_id {
        crate::standalone::with_request_correlation_id(correlation_id, evaluation_future).await
    } else {
        evaluation_future.await
    };
    match evaluation {
        Ok(results) => {
            let evaluation_id = results.first().map(|result| result.evaluation_id.clone());
            let mut response = Json(json!({ "results": results })).into_response();
            if principal.is_self_attestation() {
                attach_self_attestation_success_audit(
                    &mut response,
                    "evaluate",
                    evaluation_id,
                    &requested_claims,
                    Some(1),
                    None,
                    self_attestation_policy_hash,
                );
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
            } else {
                attach_evidence_audit(
                    &mut response,
                    "evaluate",
                    evaluation_id,
                    &requested_claims,
                    Some(1),
                );
            }
            let sidecar_config_hashes = state
                .source
                .observed_sidecar_config_hashes(evidence, &requested_claims)
                .await;
            attach_source_sidecar_config_hashes(&mut response, sidecar_config_hashes);
            attach_redacted_fields_audit(&mut response, &results);
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                &audit_request,
                results.first(),
                None,
                None,
            ) {
                return evidence_error_response(error);
            }
            response
        }
        Err(error) => {
            let audit_code = error.audit_code();
            let zero_source_no_forward = matches!(
                &error,
                EvidenceError::PolicyDenied { code, .. } if *code != registry_platform_pdp::EVIDENCE_STALE
            );
            let requested_matching_policy =
                denied_matching_policy_audit_identity(evidence, &audit_request, Some(audit_code));
            let denied_matching_policy = merge_matching_policy_audit_identity(
                matching_policy_audit_identity_from_error(evidence, &error),
                requested_matching_policy,
            );
            let mut response = evidence_error_response(error);
            attach_evidence_audit(
                &mut response,
                "evaluate_denied",
                None,
                &requested_claims,
                None,
            );
            if principal.is_self_attestation() {
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
            }
            if zero_source_no_forward {
                attach_zero_source_no_forward_audit(&mut response);
            }
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                &audit_request,
                None,
                Some(audit_code),
                denied_matching_policy.as_ref(),
            ) {
                return evidence_error_response(error);
            }
            response
        }
    }
}

pub(super) async fn batch_evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    correlation_id: Option<Extension<BoundedCorrelationId>>,
    request: Result<Json<BatchEvaluateRequest>, JsonRejection>,
) -> Response {
    let request = match parse_json_body(request) {
        Ok(request) => request,
        Err(error) => return evidence_error_response(error),
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let mut request = request;
    match negotiate_request_format(evidence, &headers, request.format.as_deref()) {
        Ok(format) => request.format = Some(format),
        Err(error) => return evidence_error_response(error),
    }
    let request_claim_ids = claim_ids(&request.claims);
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            let mut response = evidence_error_response(error);
            let denial_code = denial_code_from_response(&response);
            attach_self_attestation_audit(
                &mut response,
                "batch_evaluate_denied",
                &request_claim_ids,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    if principal.is_self_attestation() {
        let error = EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::BatchDenied,
        };
        let mut response = evidence_error_response(error);
        attach_self_attestation_audit(
            &mut response,
            "batch_evaluate_denied",
            &request_claim_ids,
            Some(SelfAttestationDenialCode::BatchDenied),
            Some(state.self_attestation.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    let requested_claims = request_claim_ids;
    let requested_subject_count = request.items.len();
    let audit_purposes = resolved_batch_audit_purposes(
        purpose_header(&headers),
        request.purpose.as_deref(),
        &request.items,
    );
    let audit_request = request.clone();
    if let Some(key) = idempotency_key(&headers) {
        let request_hash = match batch_request_hash(&request) {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error),
        };
        let scoped_key = batch_idempotency_key(&principal.principal_id, key);
        match state.store.idempotent_batch(&scoped_key, &request_hash) {
            Ok(Some(result)) => {
                let mut response = Json(result.clone()).into_response();
                let batch_audit_purposes = audit_purposes.clone();
                attach_evidence_audit_with_purposes(
                    &mut response,
                    "batch_evaluate",
                    None,
                    &requested_claims,
                    Some(requested_subject_count as u64),
                    audit_purposes,
                );
                if let Err(error) = attach_batch_evaluate_response_audit(
                    &mut response,
                    &state.self_attestation_rate_keys,
                    evidence,
                    &audit_request,
                    &result,
                    batch_audit_purposes.as_deref(),
                ) {
                    return evidence_error_response(error);
                }
                let sidecar_config_hashes = state
                    .source
                    .observed_sidecar_config_hashes(evidence, &requested_claims)
                    .await;
                attach_source_sidecar_config_hashes(&mut response, sidecar_config_hashes);
                return response;
            }
            Ok(None) => {}
            Err(error) => return evidence_error_response(error),
        }
    }
    if let Err(error) = validate_batch_subject_limit(evidence, &request) {
        return evidence_error_response(error);
    }
    let batch_cost = u32::try_from(request.items.len()).unwrap_or(u32::MAX);
    if let Err(error) = state
        .machine_quota_limiter
        .check_and_consume(&principal.principal_id, batch_cost)
    {
        let quota_error = EvidenceError::MachineQuotaExceeded {
            retry_after_seconds: error.retry_after_seconds,
        };
        let mut response = evidence_error_response(quota_error);
        attach_evidence_audit_with_purposes(
            &mut response,
            "batch_evaluate_denied",
            None,
            &requested_claims,
            None,
            audit_purposes,
        );
        attach_zero_source_no_forward_audit(&mut response);
        return response;
    }
    let runtime = state.runtime();
    let evaluation_future = runtime.batch_evaluate(
        Arc::clone(&state.evidence),
        Arc::clone(&state.source),
        &state.store,
        &principal,
        request,
        BatchEvaluateOptions {
            header_purpose: purpose_header(&headers),
            idempotency_key: idempotency_key(&headers),
            memo_observer: None,
        },
    );
    let result = if let Some(Extension(correlation_id)) = correlation_id {
        crate::standalone::with_request_correlation_id(correlation_id, evaluation_future).await
    } else {
        evaluation_future.await
    };
    match result {
        Ok(result) => {
            let mut response = Json(result.clone()).into_response();
            let batch_audit_purposes = audit_purposes.clone();
            attach_evidence_audit_with_purposes(
                &mut response,
                "batch_evaluate",
                None,
                &requested_claims,
                Some(requested_subject_count as u64),
                audit_purposes,
            );
            if let Err(error) = attach_batch_evaluate_response_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                evidence,
                &audit_request,
                &result,
                batch_audit_purposes.as_deref(),
            ) {
                return evidence_error_response(error);
            }
            let sidecar_config_hashes = state
                .source
                .observed_sidecar_config_hashes(evidence, &requested_claims)
                .await;
            attach_source_sidecar_config_hashes(&mut response, sidecar_config_hashes);
            response
        }
        Err(error) => evidence_error_response(error),
    }
}

pub(super) async fn render(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Path(evaluation_id): Path<String>,
    request: Result<Json<RenderEvaluationRequest>, JsonRejection>,
) -> Response {
    if has_idempotency_key(&headers) {
        return evidence_error_response(EvidenceError::InvalidRequest);
    }
    let request = match parse_json_body(request) {
        Ok(request) => request,
        Err(error) => return evidence_error_response(error),
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let request = request.with_evaluation_id(evaluation_id);
    let evaluation_id = request.evaluation_id.clone();
    let requested_claims = request.claims.clone();
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let mut principal =
        match classify_self_attestation_principal(&state.self_attestation, &principal) {
            Ok(principal) => principal,
            Err(error) => return evidence_error_response(error),
        };
    let Some(evaluation) = state.store.get(&request.evaluation_id) else {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
    if let Some(metadata) = evaluation.self_attestation.as_ref() {
        if principal.is_self_attestation() {
            if let Err(error) = apply_stored_self_attestation_access_mode(&mut principal, metadata)
            {
                return evidence_error_response(error);
            }
        }
    }
    if !evaluation_client_matches(&state, &principal, &evaluation)
        || evaluation.access_mode() != principal.access_mode()
    {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
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
        &request.format,
        None,
    ) {
        return evidence_error_response(error);
    }
    if principal.is_self_attestation() {
        let principal_hash = match state
            .self_attestation_rate_keys
            .principal(&principal.principal_id)
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        if let Err(error) = state
            .self_attestation_rate_limiter
            .check_authenticated_request(&principal_hash)
        {
            let mut response = evidence_error_response(error.evidence_error());
            attach_self_attestation_rate_limit_audit(
                &mut response,
                "render_rate_limited",
                &evaluation.claim_ids,
                error.bucket(),
            );
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            return response;
        }
    }
    if let Err(error) =
        require_evaluation_access(evidence, state.source.as_ref(), &principal, &evaluation)
    {
        return evidence_error_response(error);
    }
    let runtime = state.runtime();
    let runtime_principal = runtime_principal_for_stored_evaluation(&principal, &evaluation);
    match runtime.render(evidence, &state.store, &runtime_principal, request) {
        Ok(value) => {
            let mut response = Json(value).into_response();
            if principal.is_self_attestation() {
                attach_self_attestation_success_audit(
                    &mut response,
                    "render",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&evaluation.claim_ids),
                    None,
                    Some(vec![evaluation.purpose.clone()]),
                    evaluation
                        .self_attestation
                        .as_ref()
                        .and_then(|metadata| metadata.policy_hash.clone()),
                );
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
            } else {
                attach_evidence_audit_with_purposes(
                    &mut response,
                    "render",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&[]),
                    None,
                    Some(vec![evaluation.purpose.clone()]),
                );
            }
            response
        }
        Err(error) => {
            let mut response = evidence_error_response(error);
            if principal.is_self_attestation() {
                attach_self_attestation_success_audit(
                    &mut response,
                    "render_failed",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&evaluation.claim_ids),
                    None,
                    None,
                    evaluation
                        .self_attestation
                        .as_ref()
                        .and_then(|metadata| metadata.policy_hash.clone()),
                );
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
            } else {
                attach_evidence_audit(
                    &mut response,
                    "render_failed",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&[]),
                    None,
                );
            }
            response
        }
    }
}
pub(super) fn result_json(result: Result<Value, EvidenceError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => evidence_error_response(error),
    }
}

pub(super) fn require_evaluation_access(
    evidence: &EvidenceConfig,
    source: &(impl SourceReader + ?Sized),
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    if principal.is_self_attestation() {
        return Ok(());
    }
    for claim_ref in evaluation.selected_claim_refs() {
        let claim = find_requested_claim(evidence, &claim_ref)?;
        for scope in source.required_scopes_for_claim(evidence, claim)? {
            if !principal.has_scope(&scope) {
                return Err(EvidenceError::ScopeDenied { required: scope });
            }
        }
    }
    Ok(())
}

pub(super) fn evaluation_client_matches(
    state: &RegistryNotaryApiState,
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> bool {
    if let Some(metadata) = evaluation.self_attestation.as_ref() {
        principal.is_self_attestation()
            && state
                .self_attestation_rate_keys
                .principal(&principal.principal_id)
                .is_ok_and(|hash| {
                    hash == metadata.principal_hash && evaluation.client_id == hash.as_str()
                })
    } else {
        evaluation.client_id == principal.principal_id
    }
}

pub(super) fn runtime_principal_for_stored_evaluation(
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> EvidencePrincipal {
    if evaluation.self_attestation.is_some() {
        let mut runtime_principal = principal.clone();
        runtime_principal.principal_id = evaluation.client_id.clone();
        runtime_principal
    } else {
        principal.clone()
    }
}
