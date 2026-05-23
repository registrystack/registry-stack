// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Witness routes.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use registry_witness_core::sd_jwt;
use registry_witness_core::{
    BatchEvaluateRequest, CredentialIssueRequest, CredentialProfileConfig, EvaluateRequest,
    EvidenceConfig, EvidenceError, EvidencePrincipal, HolderRequest, RenderRequest,
    FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    credential_profile_for, openapi_document, BatchEvaluateOptions, EvidenceStore,
    RegistryWitnessRuntime, SourceReader,
};

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/openapi.json", get(openapi_json))
        .route("/.well-known/evidence-service", get(service_document))
        .route("/.well-known/evidence/jwks.json", get(issuer_jwks))
        .route("/claims", get(list_claims))
        .route("/claims/{claim_id}", get(get_claim))
        .route("/formats", get(list_formats))
        .route("/claims/evaluate", post(evaluate))
        .route("/claims/batch-evaluate", post(batch_evaluate))
        .route("/evidence/render", post(render))
        .route("/credentials/issue", post(issue_credential))
}

async fn openapi_json(principal: Option<Extension<EvidencePrincipal>>) -> Response {
    if principal.is_none() {
        return evidence_error_response(EvidenceError::MissingCredential);
    }
    Json(openapi_document()).into_response()
}

pub trait EvidenceIssuerResolver: Send + Sync {
    fn issuer(
        &self,
        profile_id: &str,
    ) -> Result<registry_witness_core::sd_jwt::EvidenceIssuer, EvidenceError>;

    fn public_jwks(&self, evidence: &EvidenceConfig) -> Result<Vec<Value>, EvidenceError> {
        evidence
            .credential_profiles
            .keys()
            .map(|profile_id| {
                self.issuer(profile_id)
                    .map(|issuer| issuer.public_jwk().clone())
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct RegistryWitnessApiState {
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    store: Arc<EvidenceStore>,
    issuers: Arc<dyn EvidenceIssuerResolver>,
}

impl RegistryWitnessApiState {
    #[must_use]
    pub fn new(
        evidence: Arc<EvidenceConfig>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self {
            evidence,
            source,
            store,
            issuers,
        }
    }

    fn enabled_evidence(&self) -> Result<&EvidenceConfig, EvidenceError> {
        if self.evidence.enabled {
            Ok(&self.evidence)
        } else {
            Err(EvidenceError::ServerDisabled)
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceAuditContext {
    pub verification_id: Option<String>,
    pub verification_decision: Option<String>,
    pub claim_hash: Option<String>,
    pub row_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EvidenceErrorCodeContext(pub String);

async fn service_document(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
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
    Json(RegistryWitnessRuntime::service_document(evidence)).into_response()
}

async fn issuer_jwks(state: Option<Extension<Arc<RegistryWitnessApiState>>>) -> Response {
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    match state.issuers.public_jwks(evidence) {
        Ok(keys) => Json(json!({ "keys": keys })).into_response(),
        Err(error) => evidence_error_response(error),
    }
}

async fn list_claims(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
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
        "data": RegistryWitnessRuntime::list_claims(evidence, state.source.as_ref(), &principal),
    }))
    .into_response()
}

async fn get_claim(
    Path(claim_id): Path<String>,
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
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
    result_json(RegistryWitnessRuntime::get_claim(
        evidence,
        state.source.as_ref(),
        &principal,
        &claim_id,
    ))
}

async fn list_formats(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
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
        "formats": RegistryWitnessRuntime::list_formats(evidence),
    }))
    .into_response()
}

async fn evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<EvaluateRequest>,
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
    let mut request = request;
    match negotiate_request_format(evidence, &headers, request.format.as_deref()) {
        Ok(format) => request.format = Some(format),
        Err(error) => return evidence_error_response(error),
    }
    let runtime = RegistryWitnessRuntime::new();
    let requested_claims = request.claims.clone();
    match runtime
        .evaluate(
            evidence,
            state.source.as_ref(),
            &state.store,
            &principal,
            request,
            purpose_header(&headers),
        )
        .await
    {
        Ok(results) => {
            let evaluation_id = results.first().map(|result| result.evaluation_id.clone());
            let mut response = Json(json!({ "results": results })).into_response();
            attach_evidence_audit(
                &mut response,
                "evaluate",
                evaluation_id,
                &requested_claims,
                Some(1),
            );
            response
        }
        Err(error) => evidence_error_response(error),
    }
}

async fn batch_evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<BatchEvaluateRequest>,
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
    let mut request = request;
    match negotiate_request_format(evidence, &headers, request.format.as_deref()) {
        Ok(format) => request.format = Some(format),
        Err(error) => return evidence_error_response(error),
    }
    let runtime = RegistryWitnessRuntime::new();
    let requested_claims = request.claims.clone();
    let requested_subject_count = request.subjects.len();
    match runtime
        .batch_evaluate(
            evidence,
            state.source.as_ref(),
            &state.store,
            &principal,
            request,
            BatchEvaluateOptions {
                header_purpose: purpose_header(&headers),
                idempotency_key: idempotency_key(&headers),
            },
        )
        .await
    {
        Ok(result) => {
            let mut response = Json(result).into_response();
            attach_evidence_audit(
                &mut response,
                "batch_evaluate",
                None,
                &requested_claims,
                Some(requested_subject_count as u64),
            );
            response
        }
        Err(error) => evidence_error_response(error),
    }
}

async fn render(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<RenderRequest>,
) -> Response {
    let Some(Extension(state)) = state else {
        return evidence_error_response(EvidenceError::ServerDisabled);
    };
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    let evaluation_id = request.evaluation_id.clone();
    let requested_claims = request.claims.clone();
    let evidence = match state.enabled_evidence() {
        Ok(evidence) => evidence,
        Err(error) => return evidence_error_response(error),
    };
    if let Some(evaluation) = state.store.get(&request.evaluation_id) {
        if let Err(error) =
            require_evaluation_access(evidence, state.source.as_ref(), &principal, &evaluation)
        {
            return evidence_error_response(error);
        }
    }
    let runtime = RegistryWitnessRuntime::new();
    match runtime.render(evidence, &state.store, &principal, request) {
        Ok(value) => {
            let mut response = Json(value).into_response();
            attach_evidence_audit(
                &mut response,
                "render",
                Some(evaluation_id),
                requested_claims.as_deref().unwrap_or(&[]),
                None,
            );
            response
        }
        Err(error) => {
            let mut response = evidence_error_response(error);
            attach_evidence_audit(
                &mut response,
                "render_failed",
                Some(evaluation_id),
                requested_claims.as_deref().unwrap_or(&[]),
                None,
            );
            response
        }
    }
}

async fn issue_credential(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<CredentialIssueRequest>,
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
    let evaluation = match state.store.get(&request.evaluation_id) {
        Some(evaluation) => evaluation,
        None => return evidence_error_response(EvidenceError::EvaluationNotFound),
    };
    if evaluation.client_id != principal.principal_id {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    if let Err(error) =
        require_evaluation_access(evidence, state.source.as_ref(), &principal, &evaluation)
    {
        return evidence_error_response(error);
    }
    if let Some(format) = request.format.as_deref() {
        if format != FORMAT_SD_JWT_VC {
            return evidence_error_response(EvidenceError::FormatUnsupported);
        }
    }
    if let Some(disclosure) = request.disclosure.as_deref() {
        if disclosure != evaluation.disclosure {
            return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
        }
    }
    if let Some(claims) = &request.claims {
        if claims != &evaluation.claim_ids {
            return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
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
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    if !profile.allowed_claims.is_empty()
        && !evaluation.claim_ids.iter().all(|claim| {
            profile
                .allowed_claims
                .iter()
                .any(|allowed| allowed == claim)
        })
    {
        return evidence_error_response(EvidenceError::EvaluationBindingMismatch);
    }
    if !profile.disclosure.allowed.is_empty()
        && !profile
            .disclosure
            .allowed
            .iter()
            .any(|allowed| allowed == &evaluation.disclosure)
    {
        return evidence_error_response(EvidenceError::DisclosureNotAllowed);
    }
    let proof_binding = match validate_holder_request(
        profile,
        profile_id,
        &request,
        &evaluation,
        request.holder.as_ref(),
    ) {
        Ok(binding) => binding,
        Err(error) => return evidence_error_response(error),
    };
    let holder_id = request
        .holder
        .as_ref()
        .and_then(|holder| holder.id.as_deref());
    let issuer = match state.issuers.issuer(profile_id) {
        Ok(issuer) => issuer,
        Err(error) => return evidence_error_response(error),
    };
    let signed = match sd_jwt::issue(profile, &issuer, &evaluation.results, holder_id) {
        Ok(signed) => signed,
        Err(error) => return evidence_error_response(error),
    };
    if let Some(binding) = proof_binding {
        if let Err(error) = state
            .store
            .record_holder_proof(binding.replay_key, binding.expires_at)
        {
            return evidence_error_response(error);
        }
    }
    let mut response = Json(json!({
        "credential_id": signed.credential_id,
        "format": FORMAT_SD_JWT_VC,
        "issuer": signed.issuer,
        "expires_at": signed.expires_at,
        "credential": signed.compact,
    }))
    .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    attach_evidence_audit(
        &mut response,
        "credential_issued",
        Some(request.evaluation_id.clone()),
        &evaluation.claim_ids,
        Some(evaluation.results.len() as u64),
    );
    response
}

struct HolderProofBinding {
    replay_key: String,
    expires_at: OffsetDateTime,
}

fn validate_holder_request(
    profile: &CredentialProfileConfig,
    profile_id: &str,
    request: &CredentialIssueRequest,
    evaluation: &registry_witness_core::StoredEvaluation,
    holder: Option<&HolderRequest>,
) -> Result<Option<HolderProofBinding>, EvidenceError> {
    if profile.holder_binding.mode == "none" {
        return Ok(None);
    }
    let Some(holder) = holder else {
        return Err(EvidenceError::HolderProofRequired);
    };
    if holder.binding.as_deref() != Some(profile.holder_binding.mode.as_str()) {
        return Err(EvidenceError::HolderProofRequired);
    }
    let holder_id = holder
        .id
        .as_deref()
        .ok_or(EvidenceError::HolderProofRequired)?;
    if profile.holder_binding.mode == "did"
        && !profile
            .holder_binding
            .allowed_did_methods
            .iter()
            .any(|method| holder_id.starts_with(&format!("{method}:")))
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    if profile.holder_binding.proof_of_possession.as_deref() == Some("required") {
        let proof = holder
            .proof
            .as_deref()
            .ok_or(EvidenceError::HolderProofRequired)?;
        return validate_holder_proof_payload(proof, holder_id, profile_id, request, evaluation)
            .map(Some);
    }
    Ok(None)
}

fn validate_holder_proof_payload(
    proof: &str,
    holder_id: &str,
    profile_id: &str,
    request: &CredentialIssueRequest,
    evaluation: &registry_witness_core::StoredEvaluation,
) -> Result<HolderProofBinding, EvidenceError> {
    let header = decode_header(proof).map_err(|_| EvidenceError::HolderProofRequired)?;
    if header.alg != Algorithm::EdDSA {
        return Err(EvidenceError::HolderProofRequired);
    }
    let jwk = holder_jwk(holder_id)?;
    let decoding_key =
        DecodingKey::from_jwk(&jwk).map_err(|_| EvidenceError::HolderProofRequired)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.algorithms = vec![Algorithm::EdDSA];
    validation.set_audience(&["registry-witness"]);
    validation.required_spec_claims = [
        "sub",
        "aud",
        "exp",
        "iat",
        "jti",
        "evaluation_id",
        "credential_profile",
        "disclosure",
        "claims",
    ]
    .iter()
    .map(|claim| (*claim).to_string())
    .collect();
    let token = decode::<Value>(proof, &decoding_key, &validation)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    if token.claims.get("sub").and_then(Value::as_str) != Some(holder_id) {
        return Err(EvidenceError::HolderProofRequired);
    }
    if token.claims.get("evaluation_id").and_then(Value::as_str)
        != Some(request.evaluation_id.as_str())
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    if token
        .claims
        .get("credential_profile")
        .and_then(Value::as_str)
        != Some(profile_id)
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    if token.claims.get("disclosure").and_then(Value::as_str)
        != request
            .disclosure
            .as_deref()
            .or(Some(evaluation.disclosure.as_str()))
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    if token.claims.get("claims") != Some(&json!(evaluation.claim_ids)) {
        return Err(EvidenceError::HolderProofRequired);
    }
    let iat = token
        .claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(EvidenceError::HolderProofRequired)?;
    let exp = token
        .claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(EvidenceError::HolderProofRequired)?;
    let jti = token
        .claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(EvidenceError::HolderProofRequired)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if iat < now - 120 || iat > now + 30 {
        return Err(EvidenceError::HolderProofRequired);
    }
    let expires_at =
        OffsetDateTime::from_unix_timestamp(exp).map_err(|_| EvidenceError::HolderProofRequired)?;
    Ok(HolderProofBinding {
        replay_key: format!(
            "{}:{}:{}:{}:{}",
            evaluation.client_id, request.evaluation_id, profile_id, holder_id, jti
        ),
        expires_at,
    })
}

fn holder_jwk(holder_id: &str) -> Result<jsonwebtoken::jwk::Jwk, EvidenceError> {
    let encoded = holder_id
        .strip_prefix("did:jwk:")
        .ok_or(EvidenceError::HolderProofRequired)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| EvidenceError::HolderProofRequired)?;
    if ["d", "p", "q", "dp", "dq", "qi"]
        .iter()
        .any(|field| value.get(field).is_some())
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    serde_json::from_value(value).map_err(|_| EvidenceError::HolderProofRequired)
}

fn result_json(result: Result<Value, EvidenceError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => evidence_error_response(error),
    }
}

fn require_evaluation_access(
    evidence: &EvidenceConfig,
    source: &(impl SourceReader + ?Sized),
    principal: &EvidencePrincipal,
    evaluation: &registry_witness_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    for claim_id in &evaluation.claim_ids {
        for scope in source.required_scopes(evidence, claim_id)? {
            if !principal.has_scope(&scope) {
                return Err(EvidenceError::ScopeDenied { required: scope });
            }
        }
    }
    Ok(())
}

fn attach_evidence_audit(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count,
    });
}

fn evidence_error_response(error: EvidenceError) -> Response {
    let code = error.code().to_string();
    let status = evidence_status(&error);
    let body = json!({
        "type": format!("https://data.example.gov/problems/{}", code.replace('.', "/")),
        "title": evidence_title(&error),
        "status": status.as_u16(),
        "detail": evidence_detail(&error),
        "code": code,
    });
    let mut response = (status, Json(body)).into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(code));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

fn evidence_status(error: &EvidenceError) -> StatusCode {
    match error {
        EvidenceError::ServerDisabled
        | EvidenceError::OperationUnsupported
        | EvidenceError::CredentialIssuerNotConfigured => StatusCode::NOT_IMPLEMENTED,
        EvidenceError::FormatUnsupported => StatusCode::NOT_ACCEPTABLE,
        EvidenceError::ClaimNotFound
        | EvidenceError::SourceNotFound
        | EvidenceError::EvaluationNotFound => StatusCode::NOT_FOUND,
        EvidenceError::MissingCredential => StatusCode::UNAUTHORIZED,
        EvidenceError::InvalidRequest
        | EvidenceError::HolderProofRequired
        | EvidenceError::PurposeRequired => StatusCode::BAD_REQUEST,
        EvidenceError::DisclosureNotAllowed
        | EvidenceError::EvaluationBindingMismatch
        | EvidenceError::ScopeDenied { .. } => StatusCode::FORBIDDEN,
        EvidenceError::SourceAmbiguous
        | EvidenceError::IdempotencyConflict
        | EvidenceError::HolderProofReplay => StatusCode::CONFLICT,
        EvidenceError::SourceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        EvidenceError::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        EvidenceError::CredentialIssuanceFailed | EvidenceError::RuleEvaluationFailed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn evidence_title(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::ServerDisabled => "Evidence server disabled",
        EvidenceError::ClaimNotFound => "Claim not found",
        EvidenceError::OperationUnsupported => "Claim operation unsupported",
        EvidenceError::InvalidRequest => "Invalid evidence request",
        EvidenceError::DisclosureNotAllowed => "Disclosure not allowed",
        EvidenceError::SourceNotFound => "Source record not found",
        EvidenceError::SourceAmbiguous => "Source lookup ambiguous",
        EvidenceError::SourceUnavailable => "Source unavailable",
        EvidenceError::BatchTooLarge => "Batch too large",
        EvidenceError::EvaluationNotFound => "Evaluation not found",
        EvidenceError::EvaluationBindingMismatch => "Evaluation binding mismatch",
        EvidenceError::FormatUnsupported => "Claim format not supported",
        EvidenceError::CredentialIssuerNotConfigured => "Credential issuer not configured",
        EvidenceError::HolderProofRequired => "Holder proof required",
        EvidenceError::HolderProofReplay => "Holder proof replay",
        EvidenceError::CredentialIssuanceFailed => "Credential issuance failed",
        EvidenceError::RuleEvaluationFailed => "Claim rule evaluation failed",
        EvidenceError::IdempotencyConflict => "Idempotency conflict",
        EvidenceError::PurposeRequired => "Purpose required",
        EvidenceError::MissingCredential => "Missing credential",
        EvidenceError::ScopeDenied { .. } => "Scope denied",
        _ => "Evidence error",
    }
}

fn evidence_detail(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::ServerDisabled => "the evidence server is not enabled",
        EvidenceError::ClaimNotFound => "the requested claim is not available",
        EvidenceError::OperationUnsupported => "the requested operation is not enabled",
        EvidenceError::InvalidRequest => "the evidence request is invalid",
        EvidenceError::DisclosureNotAllowed => "the requested disclosure profile is not allowed",
        EvidenceError::SourceNotFound => "the required source record was not found",
        EvidenceError::SourceAmbiguous => "the source lookup returned multiple records",
        EvidenceError::SourceUnavailable => "the source registry is unavailable",
        EvidenceError::BatchTooLarge => "the batch exceeds the configured inline limit",
        EvidenceError::EvaluationNotFound => "the evaluation id is unknown or expired",
        EvidenceError::EvaluationBindingMismatch => {
            "the request exceeds the original evaluation binding"
        }
        EvidenceError::FormatUnsupported => "the requested claim format is not supported",
        EvidenceError::CredentialIssuerNotConfigured => {
            "no credential issuer is configured for this claim and format"
        }
        EvidenceError::HolderProofRequired => "holder proof of possession is required",
        EvidenceError::HolderProofReplay => "holder proof of possession has already been used",
        EvidenceError::CredentialIssuanceFailed => "credential issuance failed",
        EvidenceError::RuleEvaluationFailed => "claim rule evaluation failed",
        EvidenceError::IdempotencyConflict => {
            "the idempotency key was reused with a different request"
        }
        EvidenceError::PurposeRequired => "a data purpose is required",
        EvidenceError::MissingCredential => "missing authentication credential",
        EvidenceError::ScopeDenied { .. } => "missing required scope",
        _ => "evidence request failed",
    }
}

fn evidence_claim_hash(claim_ids: &[String]) -> String {
    let mut hasher = Sha256::new();
    for claim_id in claim_ids {
        hasher.update(claim_id.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{}", hex_digest(hasher.finalize()))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn negotiate_request_format(
    evidence: &EvidenceConfig,
    headers: &HeaderMap,
    body_format: Option<&str>,
) -> Result<String, EvidenceError> {
    let supported = RegistryWitnessRuntime::list_formats(evidence)
        .into_iter()
        .filter(|format| format.status == "enabled")
        .map(|format| format.id)
        .collect::<Vec<_>>();
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    if let Some(format) = body_format.filter(|format| !format.trim().is_empty()) {
        if accept_permits(accept, format) {
            return Ok(format.to_string());
        }
        return Err(EvidenceError::FormatUnsupported);
    }
    match accept {
        None => Ok(FORMAT_CLAIM_RESULT_JSON.to_string()),
        Some(value) if accept_is_default(value) => Ok(FORMAT_CLAIM_RESULT_JSON.to_string()),
        Some(value) => {
            accept_preferred_format(value, &supported).ok_or(EvidenceError::FormatUnsupported)
        }
    }
}

fn accept_is_default(value: &str) -> bool {
    accept_entries(value)
        .into_iter()
        .find(|entry| entry.q > 0.0)
        .is_some_and(|entry| entry.media_range == "*/*" || entry.media_range.trim().is_empty())
}

fn accept_permits(accept: Option<&str>, format: &str) -> bool {
    let Some(accept) = accept else {
        return true;
    };
    accept_entries(accept)
        .into_iter()
        .any(|entry| entry.q > 0.0 && media_range_matches(&entry.media_range, format))
}

fn accept_preferred_format(accept: &str, supported: &[String]) -> Option<String> {
    accept_entries(accept).into_iter().find_map(|entry| {
        if entry.q <= 0.0 {
            return None;
        }
        supported
            .iter()
            .find(|format| media_range_matches(&entry.media_range, format))
            .cloned()
    })
}

#[derive(Debug)]
struct AcceptEntry {
    media_range: String,
    q: f32,
    order: usize,
}

fn accept_entries(accept: &str) -> Vec<AcceptEntry> {
    let mut entries = accept
        .split(',')
        .enumerate()
        .filter_map(|(order, part)| {
            let mut segments = part.split(';').map(str::trim);
            let media_type = segments.next()?.to_ascii_lowercase();
            let mut params = Vec::new();
            let mut q = 1.0;
            for segment in segments {
                if let Some(raw_q) = segment.strip_prefix("q=") {
                    q = raw_q.parse::<f32>().unwrap_or(0.0);
                } else if !segment.is_empty() {
                    params.push(segment.to_ascii_lowercase());
                }
            }
            let suffix = if params.is_empty() {
                String::new()
            } else {
                format!("; {}", params.join("; "))
            };
            Some(AcceptEntry {
                media_range: format!("{media_type}{suffix}"),
                q,
                order,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .q
            .partial_cmp(&left.q)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.order.cmp(&right.order))
    });
    entries
}

fn media_range_matches(range: &str, format: &str) -> bool {
    let format = format.to_ascii_lowercase();
    if range == "*/*" || range == format {
        return true;
    }
    range
        .strip_suffix("/*")
        .and_then(|prefix| format.split_once('/').map(|(kind, _)| (prefix, kind)))
        .is_some_and(|(prefix, kind)| prefix == kind)
}

fn purpose_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DATA_PURPOSE_HEADER)
        .and_then(|value| value.to_str().ok())
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
}
