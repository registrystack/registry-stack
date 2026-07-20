// SPDX-License-Identifier: Apache-2.0
//! Evaluation, batch evaluation, and rendering handlers.

use super::*;
use crate::runtime::registry_backed_batch_requested;

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
    let mut principal = match classify_subject_access_principal(&state.subject_access, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            if let Err(rate_error) =
                consume_classification_denial_if_keyable(&state, &principal).await
            {
                let mut response = evidence_error_response(rate_error.evidence_error());
                attach_subject_access_rate_limit_audit(
                    &mut response,
                    "evaluate_rate_limited",
                    &request_claim_ids,
                    rate_error.bucket(),
                );
                return response;
            }
            let mut response = evidence_error_response(error);
            let denial_code = denial_code_from_response(&response);
            attach_subject_access_audit(
                &mut response,
                "evaluate_denied",
                &request_claim_ids,
                denial_code,
                Some(state.subject_access.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let mut subject_access_context = None;
    if principal.is_subject_access() {
        // Classification only proves the caller is a citizen attester. The
        // transaction token authorization details select self vs delegated.
        let attestation_access_mode = requested_attestation_access_mode(&principal);
        principal.access_mode = attestation_access_mode;
        let principal_hash = match state
            .subject_access_rate_keys
            .principal(&principal.principal_id)
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        if let Err(error) = state
            .subject_access_rate_limiter
            .check_authenticated_request(&principal_hash)
            .await
        {
            let mut response = evidence_error_response(error.evidence_error());
            attach_subject_access_rate_limit_audit(
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
                &state.subject_access,
                &state.subject_access_rate_keys,
                &principal,
                &mut request,
            )
        } else {
            derive_subject_access_request_context(&state.subject_access, &principal, &mut request)
        };
        if let Err(error) = context_result {
            if denial_code_from_error(&error).is_some_and(subject_mismatch_denial_code) {
                if let Err(rate_error) =
                    consume_subject_mismatch_denial(&state, &principal_hash).await
                {
                    let mut response = evidence_error_response(rate_error.evidence_error());
                    attach_subject_access_rate_limit_audit(
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
            attach_subject_access_audit(
                &mut response,
                "evaluate_denied",
                &request_claim_ids,
                denial_code,
                Some(state.subject_access.subject_binding.token_claim.as_str()),
            );
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            return response;
        }
        match prepare_subject_access_evaluate(&state, evidence, &principal, &request) {
            Ok(context) => {
                request.purpose = Some(context.purpose.clone());
                subject_access_context = Some(context);
            }
            Err(error) => {
                if denial_code_from_error(&error).is_some_and(subject_mismatch_denial_code) {
                    if let Err(rate_error) =
                        consume_subject_mismatch_denial(&state, &principal_hash).await
                    {
                        let mut response = evidence_error_response(rate_error.evidence_error());
                        attach_subject_access_rate_limit_audit(
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
                attach_subject_access_audit(
                    &mut response,
                    "evaluate_denied",
                    &request_claim_ids,
                    denial_code,
                    Some(state.subject_access.subject_binding.token_claim.as_str()),
                );
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
                return response;
            }
        }
    } else if let Err(error) = state
        .machine_quota_limiter
        .check_and_consume(&principal.principal_id, 1)
        .await
    {
        let quota_error = EvidenceError::MachineQuotaExceeded {
            retry_after_seconds: error.retry_after_seconds,
        };
        let mut response = evidence_error_response(quota_error);
        attach_evidence_audit_with_purposes(
            &mut response,
            "evaluate_denied",
            None,
            &request_claim_ids,
            None,
            resolved_evaluate_audit_purposes(purpose_header(&headers), request.purpose.as_deref()),
        );
        attach_zero_relay_no_forward_audit(&mut response);
        if let Err(error) = attach_evaluate_request_audit(
            &mut response,
            &state.subject_access_rate_keys,
            &request,
            None,
        ) {
            return evidence_error_response(error);
        }
        return response;
    }
    let runtime = state.runtime();
    let requested_claims = request_claim_ids;
    let subject_access_policy_hash = subject_access_context
        .as_ref()
        .and_then(|context| context.metadata.policy_hash.clone());
    let request_correlation_id = correlation_id
        .as_ref()
        .map(|Extension(correlation_id)| correlation_id.clone());
    let audit_request = request.clone();
    let evaluation_future = async {
        if let Some(context) = subject_access_context {
            runtime
                .evaluate_with_capability_for_api(
                    Arc::clone(&state.evidence),
                    &state.store,
                    &principal,
                    context.evaluation_capability,
                    request,
                    None,
                    Some(context.metadata),
                    request_correlation_id.clone(),
                )
                .await
        } else {
            runtime
                .evaluate_for_api(
                    Arc::clone(&state.evidence),
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
        (Ok(results), runtime_audit) => {
            let evaluation_id = runtime_audit.evaluation_id().map(str::to_string);
            let mut response = Json(json!({ "results": results })).into_response();
            if principal.is_subject_access() {
                attach_subject_access_success_audit(
                    &mut response,
                    "evaluate",
                    evaluation_id,
                    &requested_claims,
                    Some(1),
                    None,
                    subject_access_policy_hash,
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
            attach_runtime_evaluation_audit(&mut response, runtime_audit);
            attach_redacted_fields_audit(&mut response, &results);
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.subject_access_rate_keys,
                &audit_request,
                results.first(),
            ) {
                return evidence_error_response(error);
            }
            response
        }
        (Err(error), runtime_audit) => {
            let zero_source_no_forward = matches!(
                &error,
                EvidenceError::PolicyDenied { code, .. } if *code != registry_platform_pdp::EVIDENCE_STALE
            );
            let mut response = evidence_error_response(error);
            attach_evidence_audit(
                &mut response,
                "evaluate_denied",
                runtime_audit.evaluation_id().map(str::to_string),
                &requested_claims,
                None,
            );
            attach_runtime_evaluation_audit(&mut response, runtime_audit);
            if principal.is_subject_access() {
                override_attestation_audit_access_mode(&mut response, principal.access_mode());
            }
            if zero_source_no_forward {
                attach_zero_relay_no_forward_audit(&mut response);
            }
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.subject_access_rate_keys,
                &audit_request,
                None,
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
    let principal = match classify_subject_access_principal(&state.subject_access, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            let mut response = evidence_error_response(error);
            let denial_code = denial_code_from_response(&response);
            attach_subject_access_audit(
                &mut response,
                "batch_evaluate_denied",
                &request_claim_ids,
                denial_code,
                Some(state.subject_access.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    if principal.is_subject_access() {
        let error = EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::BatchDenied,
        };
        let mut response = evidence_error_response(error);
        attach_subject_access_audit(
            &mut response,
            "batch_evaluate_denied",
            &request_claim_ids,
            Some(SubjectAccessDenialCode::BatchDenied),
            Some(state.subject_access.subject_binding.token_claim.as_str()),
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
    if let Err(error) = validate_batch_subject_limit(evidence, &request) {
        return evidence_error_response(error);
    }
    let registry_backed_batch = match registry_backed_batch_requested(evidence, &request) {
        Ok(value) => value,
        Err(error) => return evidence_error_response(error),
    };
    if registry_backed_batch
        && idempotency_key(&headers).is_none_or(|key| key.is_empty() || key.len() > 256)
    {
        return evidence_error_response(EvidenceError::ConsultationInvalidRequest);
    }
    let batch_cost = u32::try_from(request.items.len()).unwrap_or(u32::MAX);
    let runtime = state.runtime();
    let evaluation_future = runtime.batch_evaluate(
        Arc::clone(&state.evidence),
        &state.store,
        &principal,
        request,
        BatchEvaluateOptions {
            header_purpose: purpose_header(&headers),
            idempotency_key: idempotency_key(&headers),
            owner_quota: Some((&state.machine_quota_limiter, batch_cost)),
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
                &state.subject_access_rate_keys,
                evidence,
                &audit_request,
                &result,
                batch_audit_purposes.as_deref(),
            ) {
                return evidence_error_response(error);
            }
            response
        }
        Err(error) => {
            let owner_quota_denial = matches!(error, EvidenceError::MachineQuotaExceeded { .. });
            let mut response = evidence_error_response(error);
            if owner_quota_denial {
                attach_evidence_audit_with_purposes(
                    &mut response,
                    "batch_evaluate_denied",
                    None,
                    &requested_claims,
                    None,
                    audit_purposes,
                );
                attach_zero_relay_no_forward_audit(&mut response);
            }
            response
        }
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
    let mut principal = match classify_subject_access_principal(&state.subject_access, &principal) {
        Ok(principal) => principal,
        Err(error) => return evidence_error_response(error),
    };
    let lookup_client_id = match stored_evaluation_client_id(&state, &principal) {
        Ok(client_id) => client_id,
        Err(error) => return evidence_error_response(error),
    };
    let evaluation = match state
        .store
        .get(&request.evaluation_id, &lookup_client_id)
        .await
    {
        Ok(Some(evaluation)) => evaluation,
        Ok(None) => return evidence_error_response(EvidenceError::EvaluationNotFound),
        Err(error) => return evidence_error_response(error),
    };
    if let Some(metadata) = evaluation.subject_access.as_ref() {
        if principal.is_subject_access() {
            if let Err(error) = apply_stored_subject_access_access_mode(&mut principal, metadata) {
                return evidence_error_response(error);
            }
        }
    }
    if !evaluation_client_matches(&state, &principal, &evaluation)
        || evaluation.access_mode() != principal.access_mode()
    {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    }
    if let Err(error) = require_subject_access_stored_access(
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
        false,
    ) {
        return evidence_error_response(error);
    }
    if principal.is_subject_access() {
        let principal_hash = match state
            .subject_access_rate_keys
            .principal(&principal.principal_id)
        {
            Ok(hash) => hash,
            Err(error) => return evidence_error_response(error.evidence_error()),
        };
        if let Err(error) = state
            .subject_access_rate_limiter
            .check_authenticated_request(&principal_hash)
            .await
        {
            let mut response = evidence_error_response(error.evidence_error());
            attach_subject_access_rate_limit_audit(
                &mut response,
                "render_rate_limited",
                &evaluation.claim_ids,
                error.bucket(),
            );
            override_attestation_audit_access_mode(&mut response, principal.access_mode());
            return response;
        }
    }
    if let Err(error) = require_evaluation_access(evidence, &principal, &evaluation) {
        return evidence_error_response(error);
    }
    let runtime = state.runtime();
    let runtime_principal = runtime_principal_for_stored_evaluation(&principal, &evaluation);
    match runtime
        .render(evidence, &state.store, &runtime_principal, request)
        .await
    {
        Ok(value) => {
            let mut response = Json(value).into_response();
            if principal.is_subject_access() {
                attach_subject_access_success_audit(
                    &mut response,
                    "render",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&evaluation.claim_ids),
                    None,
                    Some(vec![evaluation.purpose.clone()]),
                    evaluation
                        .subject_access
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
            if principal.is_subject_access() {
                attach_subject_access_success_audit(
                    &mut response,
                    "render_failed",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&evaluation.claim_ids),
                    None,
                    None,
                    evaluation
                        .subject_access
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
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    if principal.is_subject_access() {
        return Ok(());
    }
    for claim_ref in evaluation.selected_claim_refs() {
        let claim = find_requested_claim(evidence, &claim_ref)?;
        for scope in &claim.required_scopes {
            if !principal.has_scope(scope) {
                return Err(EvidenceError::ScopeDenied {
                    required: scope.clone(),
                });
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
    if let Some(metadata) = evaluation.subject_access.as_ref() {
        principal.is_subject_access()
            && state
                .subject_access_rate_keys
                .principal(&principal.principal_id)
                .is_ok_and(|hash| {
                    hash == metadata.principal_hash && evaluation.client_id == hash.as_str()
                })
    } else {
        evaluation.client_id == principal.principal_id
    }
}

pub(super) fn stored_evaluation_client_id(
    state: &RegistryNotaryApiState,
    principal: &EvidencePrincipal,
) -> Result<String, EvidenceError> {
    if principal.is_subject_access() {
        state
            .subject_access_rate_keys
            .principal(&principal.principal_id)
            .map(|hash| hash.as_str().to_string())
            .map_err(|error| error.evidence_error())
    } else {
        Ok(principal.principal_id.clone())
    }
}

pub(super) fn runtime_principal_for_stored_evaluation(
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> EvidencePrincipal {
    if evaluation.subject_access.is_some() {
        let mut runtime_principal = principal.clone();
        runtime_principal.principal_id = evaluation.client_id.clone();
        runtime_principal
    } else {
        principal.clone()
    }
}
