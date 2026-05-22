// SPDX-License-Identifier: Apache-2.0
//! Standalone Evidence Server routes.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use evidence_core::sd_jwt::{self, EvidenceIssuer};
use evidence_core::{
    BatchEvaluateRequest, CredentialIssueRequest, CredentialProfileConfig, EvaluateRequest,
    EvidenceConfig, EvidenceError, HolderRequest, RenderRequest, FORMAT_SD_JWT_VC,
};
use evidence_server::{
    credential_profile_for, BatchEvaluateOptions, EvidenceRuntime, EvidenceStore,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::audit::AuditContextExt;
use crate::auth::Principal;
use crate::config::Config;
use crate::error::{AuthError, Error};
use crate::evidence::{evidence_principal, require_evaluation_access, RegistryRelaySourceReader};
use crate::query::EntityQueryEngine;

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
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

async fn service_document(
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if principal.is_none() {
        return Error::from(AuthError::MissingCredential).into_response();
    }
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    Json(EvidenceRuntime::service_document(evidence)).into_response()
}

async fn issuer_jwks(config: Option<Extension<Arc<Config>>>) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let mut keys = Vec::new();
    for profile in evidence.credential_profiles.values() {
        match EvidenceIssuer::from_profile(profile) {
            Ok(issuer) => keys.push(issuer.public_jwk()),
            Err(error) => return Error::from(error).into_response(),
        }
    }
    Json(json!({ "keys": keys })).into_response()
}

async fn list_claims(
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let source = RegistryRelaySourceReader::new(&config, &query);
    let principal = evidence_principal(&principal);
    Json(json!({
        "data": EvidenceRuntime::list_claims(evidence, &source, &principal),
    }))
    .into_response()
}

async fn get_claim(
    Path(claim_id): Path<String>,
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let source = RegistryRelaySourceReader::new(&config, &query);
    result_json(
        EvidenceRuntime::get_claim(
            evidence,
            &source,
            &evidence_principal(&principal),
            &claim_id,
        )
        .map_err(Error::from),
    )
}

async fn list_formats(
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if principal.is_none() {
        return Error::from(AuthError::MissingCredential).into_response();
    }
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    Json({
        let formats = EvidenceRuntime::list_formats(evidence);
        json!({
            "data": formats,
        })
    })
    .into_response()
}

async fn evaluate(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    store: Option<Extension<Arc<EvidenceStore>>>,
    principal: Option<Extension<Principal>>,
    Json(request): Json<EvaluateRequest>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(store)) = store else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let source = RegistryRelaySourceReader::new(&config, &query);
    let principal = evidence_principal(&principal);
    let runtime = EvidenceRuntime::new();
    let requested_claims = request.claims.clone();
    match runtime
        .evaluate(
            evidence,
            &source,
            &store,
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
        Err(error) => Error::from(error).into_response(),
    }
}

async fn batch_evaluate(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    store: Option<Extension<Arc<EvidenceStore>>>,
    principal: Option<Extension<Principal>>,
    Json(request): Json<BatchEvaluateRequest>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(store)) = store else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let source = RegistryRelaySourceReader::new(&config, &query);
    let principal = evidence_principal(&principal);
    let runtime = EvidenceRuntime::new();
    let requested_claims = request.claims.clone();
    let requested_subject_count = request.subjects.len();
    match runtime
        .batch_evaluate(
            evidence,
            &source,
            &store,
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
        Err(error) => Error::from(error).into_response(),
    }
}

async fn render(
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    store: Option<Extension<Arc<EvidenceStore>>>,
    principal: Option<Extension<Principal>>,
    Json(request): Json<RenderRequest>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(store)) = store else {
        return Error::from(EvidenceError::EvaluationNotFound).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let evaluation_id = request.evaluation_id.clone();
    let requested_claims = request.claims.clone();
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    if let Some(evaluation) = store.get(&request.evaluation_id) {
        let source = RegistryRelaySourceReader::new(&config, &query);
        if let Err(error) = require_evaluation_access(
            evidence,
            &source,
            &evidence_principal(&principal),
            &evaluation,
        ) {
            return Error::from(error).into_response();
        }
    }
    let runtime = EvidenceRuntime::new();
    match runtime.render(&store, &evidence_principal(&principal), request) {
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
            let mut response = Error::from(error).into_response();
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
    config: Option<Extension<Arc<Config>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    store: Option<Extension<Arc<EvidenceStore>>>,
    principal: Option<Extension<Principal>>,
    Json(request): Json<CredentialIssueRequest>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(EvidenceError::ServerDisabled).into_response();
    };
    let Some(Extension(store)) = store else {
        return Error::from(EvidenceError::EvaluationNotFound).into_response();
    };
    let Some(Extension(query)) = query else {
        return Error::from(EvidenceError::SourceUnavailable).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let evidence = match enabled_evidence(&config) {
        Ok(evidence) => evidence,
        Err(error) => return error.into_response(),
    };
    let evaluation = match store.get(&request.evaluation_id) {
        Some(evaluation) => evaluation,
        None => return Error::from(EvidenceError::EvaluationNotFound).into_response(),
    };
    if evaluation.client_id != principal.principal_id {
        return Error::from(EvidenceError::EvaluationBindingMismatch).into_response();
    }
    let source = RegistryRelaySourceReader::new(&config, &query);
    let evidence_principal = evidence_principal(&principal);
    if let Err(error) =
        require_evaluation_access(evidence, &source, &evidence_principal, &evaluation)
    {
        return Error::from(error).into_response();
    }
    if let Some(format) = request.format.as_deref() {
        if format != FORMAT_SD_JWT_VC {
            return Error::from(EvidenceError::FormatUnsupported).into_response();
        }
    }
    if let Some(disclosure) = request.disclosure.as_deref() {
        if disclosure != evaluation.disclosure {
            return Error::from(EvidenceError::EvaluationBindingMismatch).into_response();
        }
    }
    if let Some(claims) = &request.claims {
        if claims != &evaluation.claim_ids {
            return Error::from(EvidenceError::EvaluationBindingMismatch).into_response();
        }
    }
    let (profile_id, profile) = match credential_profile_for(
        evidence,
        &evaluation,
        request.credential_profile.as_deref(),
    ) {
        Ok(profile) => profile,
        Err(error) => return Error::from(error).into_response(),
    };
    if !profile.allowed_claims.is_empty()
        && !evaluation.claim_ids.iter().all(|claim| {
            profile
                .allowed_claims
                .iter()
                .any(|allowed| allowed == claim)
        })
    {
        return Error::from(EvidenceError::EvaluationBindingMismatch).into_response();
    }
    if !profile.disclosure.allowed.is_empty()
        && !profile
            .disclosure
            .allowed
            .iter()
            .any(|allowed| allowed == &evaluation.disclosure)
    {
        return Error::from(EvidenceError::DisclosureNotAllowed).into_response();
    }
    let proof_binding = match validate_holder_request(
        profile,
        profile_id,
        &request,
        &evaluation,
        request.holder.as_ref(),
    ) {
        Ok(binding) => binding,
        Err(error) => return error.into_response(),
    };
    let holder_id = request
        .holder
        .as_ref()
        .and_then(|holder| holder.id.as_deref());
    let issuer = match EvidenceIssuer::from_profile(profile) {
        Ok(issuer) => issuer,
        Err(error) => return Error::from(error).into_response(),
    };
    let signed = match sd_jwt::issue(profile, &issuer, &evaluation.results, holder_id) {
        Ok(signed) => signed,
        Err(error) => return Error::from(error).into_response(),
    };
    if let Some(binding) = proof_binding {
        if let Err(error) = store.record_holder_proof(binding.replay_key, binding.expires_at) {
            return Error::from(error).into_response();
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
    evaluation: &evidence_core::StoredEvaluation,
    holder: Option<&HolderRequest>,
) -> Result<Option<HolderProofBinding>, Error> {
    if profile.holder_binding.mode == "none" {
        return Ok(None);
    }
    let Some(holder) = holder else {
        return Err(EvidenceError::HolderProofRequired.into());
    };
    if holder.binding.as_deref() != Some(profile.holder_binding.mode.as_str()) {
        return Err(EvidenceError::HolderProofRequired.into());
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
        return Err(EvidenceError::HolderProofRequired.into());
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
    evaluation: &evidence_core::StoredEvaluation,
) -> Result<HolderProofBinding, Error> {
    let header = decode_header(proof).map_err(|_| EvidenceError::HolderProofRequired)?;
    if header.alg != Algorithm::EdDSA {
        return Err(EvidenceError::HolderProofRequired.into());
    }
    let jwk = holder_jwk(holder_id)?;
    let decoding_key =
        DecodingKey::from_jwk(&jwk).map_err(|_| EvidenceError::HolderProofRequired)?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.algorithms = vec![Algorithm::EdDSA];
    validation.set_audience(&["evidence-server"]);
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
        return Err(EvidenceError::HolderProofRequired.into());
    }
    if token.claims.get("evaluation_id").and_then(Value::as_str)
        != Some(request.evaluation_id.as_str())
    {
        return Err(EvidenceError::HolderProofRequired.into());
    }
    if token
        .claims
        .get("credential_profile")
        .and_then(Value::as_str)
        != Some(profile_id)
    {
        return Err(EvidenceError::HolderProofRequired.into());
    }
    if token.claims.get("disclosure").and_then(Value::as_str)
        != request
            .disclosure
            .as_deref()
            .or(Some(evaluation.disclosure.as_str()))
    {
        return Err(EvidenceError::HolderProofRequired.into());
    }
    if token.claims.get("claims") != Some(&json!(evaluation.claim_ids)) {
        return Err(EvidenceError::HolderProofRequired.into());
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
        return Err(EvidenceError::HolderProofRequired.into());
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

fn holder_jwk(holder_id: &str) -> Result<jsonwebtoken::jwk::Jwk, Error> {
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
        return Err(EvidenceError::HolderProofRequired.into());
    }
    serde_json::from_value(value).map_err(|_| EvidenceError::HolderProofRequired.into())
}

fn result_json(result: Result<Value, Error>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
}

fn enabled_evidence(config: &Config) -> Result<&EvidenceConfig, Error> {
    if config.evidence.enabled {
        Ok(&config.evidence)
    } else {
        Err(EvidenceError::ServerDisabled.into())
    }
}

fn attach_evidence_audit(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
) {
    response.extensions_mut().insert(AuditContextExt {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count,
        ..AuditContextExt::default()
    });
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
