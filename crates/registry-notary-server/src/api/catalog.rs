// SPDX-License-Identifier: Apache-2.0
//! Service discovery, schema catalog, formats, and issuer key handlers.

use super::*;

pub(super) async fn openapi_json(
    principal: Option<Extension<EvidencePrincipal>>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
) -> Response {
    let state = state.map(|Extension(state)| state);
    if openapi_requires_auth_from_state(state.as_deref()) && principal.is_none() {
        return evidence_error_response(EvidenceError::MissingCredential);
    }
    Json(openapi_document()).into_response()
}

pub(super) fn openapi_requires_auth_from_state(state: Option<&RegistryNotaryApiState>) -> bool {
    state.is_none_or(RegistryNotaryApiState::openapi_requires_auth)
}
pub(super) async fn service_document(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    let include_self_attestation_details =
        classify_self_attestation_principal(&state.self_attestation, &principal)
            .is_ok_and(|principal| principal.is_self_attestation());
    let mut document = RegistryNotaryRuntime::service_document_with_self_attestation(
        evidence,
        &state.self_attestation,
        include_self_attestation_details,
    );
    if state.credential_status.is_enabled() {
        advertise_credential_status(&mut document);
    }
    Json(document).into_response()
}

pub(super) fn advertise_credential_status(document: &mut Value) {
    document["credential_capabilities"]["sd_jwt_vc"]["status_methods"] = json!(["status_list"]);
    document["credential_capabilities"]["sd_jwt_vc"]["credential_status_url"] =
        json!("/v1/credentials/{credential_id}/status");
    document["credential_capabilities"]["sd_jwt_vc"]["credential_status_media_type"] =
        json!("application/statuslist+jwt");
    if let Some(features) =
        document["credential_capabilities"]["unsupported_features"].as_array_mut()
    {
        features.retain(|feature| feature.as_str() != Some("credential_status"));
    }
}
pub(super) async fn issuer_jwks(state: Option<Extension<Arc<RegistryNotaryApiState>>>) -> Response {
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    match state.issuer_resolver().public_jwks(evidence) {
        Ok(keys) => Json(json!({ "keys": keys })).into_response(),
        Err(error) => evidence_error_response(error),
    }
}

pub(super) async fn list_claims(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
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
    Json(json!({
        "data": RegistryNotaryRuntime::list_claims(evidence, &principal),
    }))
    .into_response()
}

pub(super) async fn get_claim(
    Path(claim_id): Path<String>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
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
    result_json(RegistryNotaryRuntime::get_claim(
        evidence, &principal, &claim_id,
    ))
}

pub(super) async fn list_formats(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
    if principal.is_none() {
        return evidence_error_response(EvidenceError::MissingCredential);
    }
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    Json(json!({
        "formats": RegistryNotaryRuntime::list_formats(evidence),
    }))
    .into_response()
}
