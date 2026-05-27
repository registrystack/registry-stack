// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Witness routes.

use std::{sync::Arc, time::Duration};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_audit::AuditKeyHasher;
use registry_platform_crypto::PublicJwk;
use registry_platform_oid4vci::{
    validate_proof_jwt, CredentialConfigurationMetadata, CredentialIssuerMetadata, CredentialOffer,
    CredentialRequest as Oid4vciCredentialRequest, CredentialResponse as Oid4vciCredentialResponse,
    NonceRequest as Oid4vciNonceRequest, NonceResponse, ProofValidationPolicy, WireError,
    PROOF_TYPE_JWT, SD_JWT_VC_FORMAT,
};
use registry_platform_sdjwt::{validate_holder_proof, HolderProofBindings, HolderProofPolicy};
use registry_witness_core::sd_jwt;
use registry_witness_core::{
    AccessMode, BatchEvaluateRequest, BoundedClaimId, BoundedCorrelationId, ClaimSet,
    ConfigMetadata, CredentialIssueRequest, CredentialProfileConfig, EvaluateRequest,
    EvidenceConfig, EvidenceError, EvidencePrincipal, FederationConfig, Hashed, HolderRequest,
    Oid4vciConfig, Oid4vciCredentialConfigurationConfig, PolicyIdentifier, RateLimitBucket,
    RenderRequest, SelfAttestationConfig, SelfAttestationDenialCode, SelfAttestationScopePolicy,
    SourceCapability, StoredSelfAttestationMetadata, SubjectRequest, VerifiedClaimValue,
    FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{
    credential_profile_for, format_time, openapi_document, BatchEvaluateOptions, EvidenceStore,
    RegistryWitnessRuntime, SelfAttestationRateLimitBucket, SelfAttestationRateLimitError,
    SelfAttestationRateLimitKeys, SelfAttestationRateLimiter, SourceReader,
};

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const ADMIN_SCOPE: &str = "registry_witness:admin";
const OID4VCI_CREDENTIAL_PATH: &str = "/oid4vci/credential";

pub use crate::federation::federation_router;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/admin/reload", post(admin_reload))
        .route("/openapi.json", get(openapi_json))
        .route("/.well-known/evidence-service", get(service_document))
        .route("/.well-known/evidence/jwks.json", get(issuer_jwks))
        .route(
            "/.well-known/openid-credential-issuer",
            get(oid4vci_issuer_metadata),
        )
        .route("/oid4vci/credential-offer", get(oid4vci_credential_offer))
        .route("/oid4vci/nonce", post(oid4vci_nonce))
        .route("/oid4vci/credential", post(oid4vci_credential))
        .route("/claims", get(list_claims))
        .route("/claims/{claim_id}", get(get_claim))
        .route("/formats", get(list_formats))
        .route("/claims/evaluate", post(evaluate))
        .route("/claims/batch-evaluate", post(batch_evaluate))
        .route("/evidence/render", post(render))
        .route("/credentials/issue", post(issue_credential))
}

pub async fn oid4vci_proof_precheck_middleware(
    State(state): State<Arc<RegistryWitnessApiState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.uri().path() != OID4VCI_CREDENTIAL_PATH {
        return next.run(request).await;
    }
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let request = match serde_json::from_slice::<Oid4vciCredentialRequest>(&bytes) {
        Ok(request) => request,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    if request.proof.proof_type != PROOF_TYPE_JWT {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    }
    if validate_proof_jwt(
        &request.proof.jwt,
        &ProofValidationPolicy {
            audience: &state.oid4vci.credential_issuer,
            expected_nonce: None,
            max_lifetime: Duration::from_secs(state.oid4vci.proof.max_age_seconds),
            future_skew: Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
        },
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .is_err()
    {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

async fn healthz() -> Response {
    Json(json!({
        "status": "ok",
        "checks": {
            "total": 1,
            "ok": 1,
            "failed": 0,
        },
    }))
    .into_response()
}

async fn ready(state: Option<Extension<Arc<RegistryWitnessApiState>>>) -> Response {
    let ready = state
        .as_ref()
        .is_some_and(|Extension(state)| state.enabled_evidence().is_ok());
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "checks": {
                "total": 1,
                "ok": u8::from(ready),
                "failed": u8::from(!ready),
            },
        })),
    )
        .into_response()
}

async fn admin_reload(principal: Option<Extension<EvidencePrincipal>>) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(ADMIN_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: ADMIN_SCOPE.to_string(),
        });
    }
    Json(json!({
        "reloaded": false,
        "status": "noop",
        "detail": "standalone router has no reloadable external config handle",
    }))
    .into_response()
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
    pub(crate) evidence: Arc<EvidenceConfig>,
    self_attestation: Arc<SelfAttestationConfig>,
    oid4vci: Arc<Oid4vciConfig>,
    pub(crate) federation: Arc<FederationConfig>,
    pub(crate) federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
    self_attestation_rate_limiter: Arc<SelfAttestationRateLimiter>,
    pub(crate) self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    pub(crate) source: Arc<dyn SourceReader>,
    pub(crate) store: Arc<EvidenceStore>,
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
        Self::new_with_self_attestation(
            evidence,
            Arc::new(SelfAttestationConfig::default()),
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci(
            evidence,
            self_attestation,
            Arc::new(Oid4vciConfig::default()),
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_and_oid4vci(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci_hasher(
            evidence,
            self_attestation,
            oid4vci,
            AuditKeyHasher::unkeyed_dev_only(),
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_hasher(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci_hasher(
            evidence,
            self_attestation,
            Arc::new(Oid4vciConfig::default()),
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_and_oid4vci_hasher(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_runtime_blocks(
            evidence,
            self_attestation,
            oid4vci,
            Arc::new(FederationConfig::default()),
            None,
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_federation(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        federation: Arc<FederationConfig>,
        audit_hasher: AuditKeyHasher,
        federation_audit: Option<crate::standalone::AuditPipeline>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Result<Self, crate::standalone::StandaloneServerError> {
        let federation_runtime = federation
            .enabled
            .then(|| {
                crate::federation::FederationRuntimeState::from_config(
                    &federation,
                    federation_audit,
                )
            })
            .transpose()?
            .map(Arc::new);
        Ok(Self::new_with_runtime_blocks(
            evidence,
            self_attestation,
            oid4vci,
            federation,
            federation_runtime,
            audit_hasher,
            source,
            store,
            issuers,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_runtime_blocks(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        federation: Arc<FederationConfig>,
        federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        let self_attestation_rate_limiter = Arc::new(SelfAttestationRateLimiter::new(
            self_attestation.rate_limits.clone(),
        ));
        let self_attestation_rate_keys = Arc::new(SelfAttestationRateLimitKeys::new(audit_hasher));
        Self {
            evidence,
            self_attestation,
            oid4vci,
            federation,
            federation_runtime,
            self_attestation_rate_limiter,
            self_attestation_rate_keys,
            source,
            store,
            issuers,
        }
    }

    pub(crate) fn enabled_evidence(&self) -> Result<&EvidenceConfig, EvidenceError> {
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
    pub access_mode: Option<AccessMode>,
    pub denial_code: Option<SelfAttestationDenialCode>,
    pub token_claim_name: Option<ConfigMetadata>,
    pub credential_profile: Option<ConfigMetadata>,
    pub protocol: Option<ConfigMetadata>,
    pub credential_configuration_id: Option<ConfigMetadata>,
    pub holder_binding_mode: Option<ConfigMetadata>,
    pub rate_limit_bucket: Option<RateLimitBucket>,
    pub policy_hash: Option<Hashed<PolicyIdentifier>>,
}

#[derive(Debug, Clone)]
pub struct EvidenceErrorCodeContext(pub String);

struct SelfAttestationEvaluateContext {
    source_capability: SourceCapability,
    metadata: StoredSelfAttestationMetadata,
    purpose: String,
}

async fn service_document(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
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
    Json(
        RegistryWitnessRuntime::service_document_with_self_attestation(
            evidence,
            &state.self_attestation,
            include_self_attestation_details,
        ),
    )
    .into_response()
}

async fn oid4vci_issuer_metadata(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(oid4vci_metadata(&state.oid4vci)).into_response()
}

async fn oid4vci_credential_offer(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    Query(query): Query<Oid4vciCredentialOfferQuery>,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let credential_configuration_ids = if let Some(id) = query.credential_configuration_id {
        if !state.oid4vci.credential_configurations.contains_key(&id) {
            return oid4vci_error_response(Oid4vciWireError::InvalidRequest);
        }
        vec![id]
    } else {
        state
            .oid4vci
            .credential_configurations
            .keys()
            .cloned()
            .collect()
    };
    Json(CredentialOffer::authorization_code(
        state.oid4vci.credential_issuer.clone(),
        credential_configuration_ids,
        generate_nonce().unwrap_or_else(|_| "registry-witness:self-attestation".to_string()),
        state.oid4vci.authorization_servers.first().cloned(),
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct Oid4vciCredentialOfferQuery {
    credential_configuration_id: Option<String>,
}

async fn oid4vci_nonce(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    body: Bytes,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled || !state.oid4vci.nonce.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let request = if body.is_empty() {
        Oid4vciNonceRequest {
            credential_configuration_id: None,
        }
    } else {
        match serde_json::from_slice::<Oid4vciNonceRequest>(&body) {
            Ok(request) => request,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
        }
    };
    let configuration_id =
        match oid4vci_nonce_configuration_id(&state.oid4vci, request.credential_configuration_id) {
            Ok(configuration_id) => configuration_id,
            Err(error) => return oid4vci_error_response(error),
        };
    let nonce = match generate_nonce() {
        Ok(nonce) => nonce,
        Err(error) => return evidence_error_response(error),
    };
    let key = match state.self_attestation_rate_keys.oid4vci_nonce(
        &state.oid4vci.credential_issuer,
        configuration_id,
        &nonce,
    ) {
        Ok(key) => key,
        Err(error) => return evidence_error_response(error.evidence_error()),
    };
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
    if state.store.insert_oid4vci_nonce(key, expires_at).is_err() {
        return oid4vci_error_response(Oid4vciWireError::RateLimited);
    }
    Json(NonceResponse {
        c_nonce: nonce,
        c_nonce_expires_in: state.oid4vci.nonce.ttl_seconds,
    })
    .into_response()
}

async fn oid4vci_credential(
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
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
    if request.format != SD_JWT_VC_FORMAT || request.proof.proof_type != PROOF_TYPE_JWT {
        return oid4vci_error_response(Oid4vciWireError::UnsupportedCredentialType);
    }
    let (configuration_id, configuration) =
        match oid4vci_configuration_for_request(&state.oid4vci, &request) {
            Ok(configuration) => configuration,
            Err(error) => return oid4vci_error_response(error),
        };
    let validated_proof = match validate_proof_jwt(
        &request.proof.jwt,
        &ProofValidationPolicy {
            audience: &state.oid4vci.credential_issuer,
            expected_nonce: None,
            max_lifetime: Duration::from_secs(state.oid4vci.proof.max_age_seconds),
            future_skew: Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
        },
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        Ok(proof) => proof,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidProof),
    };
    let profile = match evidence
        .credential_profiles
        .get(&configuration.credential_profile)
    {
        Some(profile) => profile,
        None => return oid4vci_error_response(Oid4vciWireError::UnsupportedCredentialType),
    };
    let issuer = match state.issuers.issuer(&configuration.credential_profile) {
        Ok(issuer) => issuer,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    if holder_key_matches_issuer_key(&validated_proof.holder_jwk, &issuer.public_jwk()) {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    }
    if state.oid4vci.nonce.enabled {
        let Some(nonce) = validated_proof.nonce.as_deref() else {
            return oid4vci_error_response(Oid4vciWireError::InvalidProof);
        };
        let key = match state.self_attestation_rate_keys.oid4vci_nonce(
            &state.oid4vci.credential_issuer,
            configuration_id,
            nonce,
        ) {
            Ok(key) => key,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
        };
        if state.store.consume_oid4vci_nonce(&key).is_err() {
            return oid4vci_error_response(Oid4vciWireError::InvalidProof);
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
            std::slice::from_ref(&configuration.claim_id),
            error.bucket(),
        );
        return response;
    }
    let request = EvaluateRequest {
        subject: match oid4vci_bound_subject(&state.self_attestation, &principal) {
            Ok(subject) => subject,
            Err(_) => {
                let mut response = oid4vci_error_response(Oid4vciWireError::InvalidToken);
                attach_oid4vci_self_attestation_denial_audit(
                    &mut response,
                    "oid4vci_credential_denied",
                    std::slice::from_ref(&configuration.claim_id),
                    configuration_id,
                    Some(SelfAttestationDenialCode::InvalidToken),
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                return response;
            }
        },
        claims: vec![configuration.claim_id.clone()],
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
                &request.claims,
                configuration_id,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let results = match RegistryWitnessRuntime::new_with_self_attestation_rate_keys(Arc::clone(
        &state.self_attestation_rate_keys,
    ))
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
                std::slice::from_ref(&configuration.claim_id),
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
    let signed = match sd_jwt::issue(
        profile,
        &issuer,
        &evaluation.results,
        holder_id,
        Some(holder_id),
        iat,
    ) {
        Ok(signed) => signed,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
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
                    if state.store.insert_oid4vci_nonce(key, expires_at).is_ok() {
                        Some(nonce)
                    } else {
                        None
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
    let mut response = Json(Oid4vciCredentialResponse {
        credential: signed.compact,
        format: Some(SD_JWT_VC_FORMAT.to_string()),
        c_nonce: next_nonce,
        c_nonce_expires_in: state
            .oid4vci
            .nonce
            .enabled
            .then_some(state.oid4vci.nonce.ttl_seconds),
    })
    .into_response();
    attach_self_attestation_credential_audit(
        &mut response,
        &evaluation_id,
        &evaluation.claim_ids,
        evaluation.results.len() as u64,
        SelfAttestationCredentialAuditDetails {
            profile_id: &configuration.credential_profile,
            holder_binding_mode: &profile.holder_binding.mode,
            policy_hash: context.metadata.policy_hash,
            protocol: Some("openid4vci"),
            credential_configuration_id: Some(configuration_id),
        },
    );
    response
}

async fn issuer_jwks(
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
    correlation_id: Option<Extension<BoundedCorrelationId>>,
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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            if let Err(rate_error) = consume_classification_denial_if_keyable(&state, &principal) {
                let mut response = evidence_error_response(rate_error.evidence_error());
                attach_self_attestation_rate_limit_audit(
                    &mut response,
                    "evaluate_rate_limited",
                    &request.claims,
                    rate_error.bucket(),
                );
                return response;
            }
            let mut response = evidence_error_response(error);
            let denial_code = denial_code_from_response(&response);
            attach_self_attestation_audit(
                &mut response,
                "evaluate_denied",
                &request.claims,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
            );
            return response;
        }
    };
    let mut self_attestation_context = None;
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
                "evaluate_rate_limited",
                &request.claims,
                error.bucket(),
            );
            return response;
        }
        match prepare_self_attestation_evaluate(&state, evidence, &principal, &request) {
            Ok(context) => {
                request.purpose = Some(context.purpose.clone());
                self_attestation_context = Some(context);
            }
            Err(error) => {
                if denial_code_from_error(&error)
                    == Some(SelfAttestationDenialCode::SubjectMismatch)
                {
                    if let Err(rate_error) =
                        consume_subject_mismatch_denial(&state, &principal_hash)
                    {
                        let mut response = evidence_error_response(rate_error.evidence_error());
                        attach_self_attestation_rate_limit_audit(
                            &mut response,
                            "evaluate_rate_limited",
                            &request.claims,
                            rate_error.bucket(),
                        );
                        return response;
                    }
                }
                let denial_code = denial_code_from_error(&error);
                let mut response = evidence_error_response(error);
                attach_self_attestation_audit(
                    &mut response,
                    "evaluate_denied",
                    &request.claims,
                    denial_code,
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                return response;
            }
        }
    }
    let runtime = RegistryWitnessRuntime::new_with_self_attestation_rate_keys(Arc::clone(
        &state.self_attestation_rate_keys,
    ));
    let requested_claims = request.claims.clone();
    let self_attestation_policy_hash = self_attestation_context
        .as_ref()
        .and_then(|context| context.metadata.policy_hash.clone());
    let request_correlation_id = correlation_id
        .as_ref()
        .map(|Extension(correlation_id)| correlation_id.clone());
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
                    self_attestation_policy_hash,
                );
            } else {
                attach_evidence_audit(
                    &mut response,
                    "evaluate",
                    evaluation_id,
                    &requested_claims,
                    Some(1),
                );
            }
            response
        }
        Err(error) => evidence_error_response(error),
    }
}

async fn batch_evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryWitnessApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    correlation_id: Option<Extension<BoundedCorrelationId>>,
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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            let mut response = evidence_error_response(error);
            let denial_code = denial_code_from_response(&response);
            attach_self_attestation_audit(
                &mut response,
                "batch_evaluate_denied",
                &request.claims,
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
            &request.claims,
            Some(SelfAttestationDenialCode::BatchDenied),
            Some(state.self_attestation.subject_binding.token_claim.as_str()),
        );
        return response;
    }
    let runtime = RegistryWitnessRuntime::new_with_self_attestation_rate_keys(Arc::clone(
        &state.self_attestation_rate_keys,
    ));
    let requested_claims = request.claims.clone();
    let requested_subject_count = request.subjects.len();
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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => return evidence_error_response(error),
    };
    let Some(evaluation) = state.store.get(&request.evaluation_id) else {
        return evidence_error_response(EvidenceError::EvaluationNotFound);
    };
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
            return response;
        }
    }
    if let Err(error) =
        require_evaluation_access(evidence, state.source.as_ref(), &principal, &evaluation)
    {
        return evidence_error_response(error);
    }
    let runtime = RegistryWitnessRuntime::new_with_self_attestation_rate_keys(Arc::clone(
        &state.self_attestation_rate_keys,
    ));
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
                    evaluation
                        .self_attestation
                        .as_ref()
                        .and_then(|metadata| metadata.policy_hash.clone()),
                );
            } else {
                attach_evidence_audit(
                    &mut response,
                    "render",
                    Some(evaluation_id),
                    requested_claims.as_deref().unwrap_or(&[]),
                    None,
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
                    evaluation
                        .self_attestation
                        .as_ref()
                        .and_then(|metadata| metadata.policy_hash.clone()),
                );
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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => return evidence_error_response(error),
    };
    let evaluation = match state.store.get(&request.evaluation_id) {
        Some(evaluation) => evaluation,
        None => return evidence_error_response(EvidenceError::EvaluationNotFound),
    };
    if !evaluation_client_matches(&state, &principal, &evaluation)
        || evaluation.access_mode() != principal.access_mode()
    {
        let error = if principal.is_self_attestation() {
            EvidenceError::EvaluationNotFound
        } else {
            EvidenceError::EvaluationBindingMismatch
        };
        return evidence_error_response(error);
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
        return evidence_error_response(error);
    }
    if principal.is_self_attestation() {
        if !state.self_attestation.allowed_operations.issue_credential {
            return evidence_error_response(self_attestation_denied(
                SelfAttestationDenialCode::OperationDenied,
            ));
        }
        if let Err(error) = require_self_attestation_credential_profile_policy(
            &state.self_attestation,
            profile_id,
            profile,
        ) {
            return evidence_error_response(error);
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
        &evidence.service_id,
    ) {
        Ok(binding) => binding,
        Err(error) => return evidence_error_response(error),
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
            attach_self_attestation_rate_limit_audit(
                &mut response,
                "credential_issue_rate_limited",
                &evaluation.claim_ids,
                error.bucket(),
            );
            return response;
        }
    }
    let issuer = match state.issuers.issuer(profile_id) {
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
            None => return evidence_error_response(EvidenceError::HolderProofRequired),
        }
    } else {
        match holder_id.or_else(|| {
            evaluation
                .results
                .first()
                .map(|result| result.subject_ref.as_str())
        }) {
            Some(subject_ref) => subject_ref,
            None => return evidence_error_response(EvidenceError::InvalidRequest),
        }
    };
    let signed = match sd_jwt::issue(
        profile,
        &issuer,
        &evaluation.results,
        subject_ref,
        holder_id,
        iat,
    ) {
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
        "issuer_signed_jwt": signed.issuer_signed_jwt,
        "disclosures": signed.disclosures,
    }))
    .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(metadata) = evaluation.self_attestation.as_ref() {
        attach_self_attestation_credential_audit(
            &mut response,
            &request.evaluation_id,
            &evaluation.claim_ids,
            evaluation.results.len() as u64,
            SelfAttestationCredentialAuditDetails {
                profile_id,
                holder_binding_mode: &profile.holder_binding.mode,
                policy_hash: metadata.policy_hash.clone(),
                protocol: None,
                credential_configuration_id: None,
            },
        );
    } else {
        attach_evidence_audit(
            &mut response,
            "credential_issued",
            Some(request.evaluation_id.clone()),
            &evaluation.claim_ids,
            Some(evaluation.results.len() as u64),
        );
    }
    response
}

/// Pick the earliest `issued_at` from a set of claim results to use as the
/// signed JWT `iat`. Returns `None` if there are no results or none parse,
/// in which case the caller falls back to `OffsetDateTime::now_utc()`.
fn earliest_issued_at(
    results: &[registry_witness_core::ClaimResultView],
) -> Option<OffsetDateTime> {
    results
        .iter()
        .filter_map(|r| OffsetDateTime::parse(&r.issued_at, &Rfc3339).ok())
        .min()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Oid4vciWireError {
    InvalidRequest,
    InvalidToken,
    InvalidProof,
    UnsupportedCredentialType,
    AccessDenied,
    RateLimited,
    ServerError,
}

fn oid4vci_error_response(error: Oid4vciWireError) -> Response {
    let (status, code, description) = match error {
        Oid4vciWireError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credential request is invalid",
        ),
        Oid4vciWireError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "credential access token is invalid",
        ),
        Oid4vciWireError::InvalidProof => (
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "credential proof is invalid",
        ),
        Oid4vciWireError::UnsupportedCredentialType => (
            StatusCode::BAD_REQUEST,
            "unsupported_credential_type",
            "credential request is not supported",
        ),
        Oid4vciWireError::AccessDenied => (
            StatusCode::FORBIDDEN,
            "access_denied",
            "credential request is denied",
        ),
        Oid4vciWireError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "credential request is rate limited",
        ),
        Oid4vciWireError::ServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "credential issuer failed",
        ),
    };
    let mut response = (
        status,
        Json(WireError::new(code, Some(description.to_string()))),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(format!("oid4vci.{code}")));
    response
}

fn oid4vci_error_from_evidence(error: &EvidenceError) -> Oid4vciWireError {
    match error {
        EvidenceError::SelfAttestationRateLimited => Oid4vciWireError::RateLimited,
        EvidenceError::HolderProofRequired | EvidenceError::HolderProofReplay => {
            Oid4vciWireError::InvalidProof
        }
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => Oid4vciWireError::InvalidToken,
        EvidenceError::FormatUnsupported | EvidenceError::CredentialIssuerNotConfigured => {
            Oid4vciWireError::UnsupportedCredentialType
        }
        EvidenceError::CredentialIssuanceFailed | EvidenceError::SourceUnavailable => {
            Oid4vciWireError::ServerError
        }
        _ => Oid4vciWireError::AccessDenied,
    }
}

fn oid4vci_metadata(config: &Oid4vciConfig) -> CredentialIssuerMetadata {
    CredentialIssuerMetadata::new(
        config.credential_issuer.clone(),
        config.credential_endpoint.clone(),
        config
            .nonce
            .enabled
            .then(|| config.nonce_endpoint.clone())
            .flatten(),
        config.authorization_servers.clone(),
        config
            .credential_configurations
            .iter()
            .map(|(id, configuration)| (id.clone(), oid4vci_configuration_metadata(configuration)))
            .collect(),
    )
}

fn oid4vci_configuration_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> CredentialConfigurationMetadata {
    CredentialConfigurationMetadata::sd_jwt_vc(
        configuration.scope.clone(),
        configuration
            .cryptographic_binding_methods_supported
            .clone(),
        configuration.display_name.clone(),
        configuration.vct.clone(),
    )
}

fn holder_key_matches_issuer_key(holder_jwk: &PublicJwk, issuer_jwk: &Value) -> bool {
    let Ok(issuer) = PublicJwk::parse(&issuer_jwk.to_string()) else {
        return false;
    };
    let Ok(issuer_jkt) = issuer.jkt() else {
        return false;
    };
    let Ok(holder_jkt) = holder_jwk.jkt() else {
        return false;
    };
    issuer_jkt == holder_jkt
}

fn oid4vci_configuration_for_request<'a>(
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

fn oid4vci_nonce_configuration_id(
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

fn require_oid4vci_token_audience(
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

fn oid4vci_bound_subject(
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

fn check_oid4vci_self_attestation_rate_limit(
    state: &RegistryWitnessApiState,
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

fn generate_nonce() -> Result<String, EvidenceError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

#[derive(Debug)]
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
    service_id: &str,
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
        return validate_holder_proof_payload(
            proof, holder_id, profile_id, request, evaluation, service_id,
        )
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
    service_id: &str,
) -> Result<HolderProofBinding, EvidenceError> {
    let jwk = sd_jwt::holder_jwk(holder_id)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let disclosure = request
        .disclosure
        .as_deref()
        .unwrap_or(evaluation.disclosure.as_str());
    let disclosure_hash = Sha256::digest(disclosure.as_bytes()).to_vec();
    let claims = validate_holder_proof(
        proof,
        &jwk,
        &HolderProofBindings {
            expected_sub: holder_id,
            evaluation_id: request.evaluation_id.as_str(),
            credential_profile: profile_id,
            disclosure_hash: &disclosure_hash,
            claim_set: &evaluation.claim_ids,
        },
        &HolderProofPolicy {
            audience: service_id.to_string(),
            max_lifetime: Duration::from_secs(300),
        },
        now,
    )
    .map_err(|_| EvidenceError::HolderProofRequired)?;
    let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    Ok(HolderProofBinding {
        replay_key: format!(
            "{}:{}:{}:{}:{}",
            evaluation.client_id, request.evaluation_id, profile_id, holder_id, claims.jti
        ),
        expires_at,
    })
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
    if principal.is_self_attestation() {
        return Ok(());
    }
    for claim_id in &evaluation.claim_ids {
        for scope in source.required_scopes(evidence, claim_id)? {
            if !principal.has_scope(&scope) {
                return Err(EvidenceError::ScopeDenied { required: scope });
            }
        }
    }
    Ok(())
}

fn evaluation_client_matches(
    state: &RegistryWitnessApiState,
    principal: &EvidencePrincipal,
    evaluation: &registry_witness_core::StoredEvaluation,
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

fn runtime_principal_for_stored_evaluation(
    principal: &EvidencePrincipal,
    evaluation: &registry_witness_core::StoredEvaluation,
) -> EvidencePrincipal {
    if evaluation.self_attestation.is_some() {
        let mut runtime_principal = principal.clone();
        runtime_principal.principal_id = evaluation.client_id.clone();
        runtime_principal
    } else {
        principal.clone()
    }
}

fn consume_classification_denial_if_keyable(
    state: &RegistryWitnessApiState,
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
}

fn classify_self_attestation_principal(
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

fn self_attestation_scope_policy_allows(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    verified_claims: &registry_witness_core::BoundedVerifiedClaims,
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

fn citizen_client_or_audience_matches(
    config: &SelfAttestationConfig,
    claims: &registry_witness_core::BoundedVerifiedClaims,
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

fn verified_client_matches(candidate: &str, allowed: &str) -> bool {
    candidate == allowed
        || candidate
            .strip_prefix("azp:")
            .or_else(|| candidate.strip_prefix("client_id:"))
            .is_some_and(|raw| raw == allowed)
}

fn require_self_attestation_evaluate(
    evidence: &EvidenceConfig,
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<(), EvidenceError> {
    if !config.allowed_operations.evaluate {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::OperationDenied,
        ));
    }
    if request.claims.len() != 1
        || !request.claims.iter().all(|claim_id| {
            config
                .allowed_claims
                .iter()
                .any(|allowed| allowed == claim_id)
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

    let disclosure = selected_disclosure(evidence, &request.claims, request.disclosure.as_deref())
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
        let claim = crate::find_claim(evidence, claim_id)
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

    let subject_binding = &config.subject_binding;
    if request.subject.id.trim().is_empty() {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    if request.subject.id_type.as_deref() != Some(subject_binding.id_type.as_str()) {
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
    if bound_subject != request.subject.id {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    Ok(())
}

fn prepare_self_attestation_evaluate(
    state: &RegistryWitnessApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    request: &EvaluateRequest,
) -> Result<SelfAttestationEvaluateContext, EvidenceError> {
    require_self_attestation_evaluate(evidence, &state.self_attestation, principal, request)?;
    require_self_attestation_token_policy(&state.self_attestation, principal)?;

    let claim_id = request
        .claims
        .first()
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied,
        })?;
    let claim = crate::find_claim(evidence, claim_id).map_err(|_| {
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied,
        }
    })?;
    let purpose = claim
        .purpose
        .clone()
        .ok_or(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied,
        })?;
    let format = request
        .format
        .as_deref()
        .unwrap_or(FORMAT_CLAIM_RESULT_JSON)
        .to_string();
    let disclosure = selected_disclosure(evidence, &request.claims, request.disclosure.as_deref())
        .map_err(|_| EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DisclosureDenied,
        })?;
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
    let requested_claims_hash = Hashed::<ClaimSet>::from_hash(evidence_claim_hash(&request.claims));
    let policy_hash = self_attestation_policy_hash(
        evidence,
        &state.self_attestation,
        &request.claims,
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
        requested_claims_hash,
        disclosure: ConfigMetadata::new(disclosure.clone())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        result_format: ConfigMetadata::new(format).map_err(|_| EvidenceError::InvalidRequest)?,
        delegation_chain: Vec::new(),
        policy_version: None,
        policy_hash: Some(policy_hash.clone()),
        evaluation_expires_at: Some(format_time(evaluation_expires_at)),
    };
    let source_capability = SourceCapability::SelfAttestation {
        claim_id: BoundedClaimId::new(claim_id.clone())
            .map_err(|_| EvidenceError::InvalidRequest)?,
        subject_binding_hash,
    };

    Ok(SelfAttestationEvaluateContext {
        source_capability,
        metadata,
        purpose,
    })
}

fn require_self_attestation_token_policy(
    config: &SelfAttestationConfig,
    principal: &EvidencePrincipal,
) -> Result<(), EvidenceError> {
    let claims = principal
        .verified_claims
        .as_ref()
        .ok_or(EvidenceError::SelfAttestationInvalidToken)?;
    if !config.token_policy.required_acr_values.is_empty() {
        let acr = claims
            .acr
            .as_ref()
            .ok_or(EvidenceError::SelfAttestationAssuranceDenied)?;
        if !config
            .token_policy
            .required_acr_values
            .iter()
            .any(|allowed| allowed == acr.as_str())
        {
            return Err(EvidenceError::SelfAttestationAssuranceDenied);
        }
    }
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

fn require_self_attestation_credential_profile_policy(
    config: &SelfAttestationConfig,
    profile_id: &str,
    profile: &CredentialProfileConfig,
) -> Result<(), EvidenceError> {
    let allowed = config
        .credential_profiles
        .iter()
        .any(|allowed| allowed == profile_id);
    let validity_seconds = u64::try_from(profile.validity_seconds).ok();
    let validity_ceiling = config.token_policy.max_credential_validity_seconds.min(600);
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

fn consume_subject_mismatch_denial(
    state: &RegistryWitnessApiState,
    principal_hash: &Hashed<registry_witness_core::PrincipalIdentifier>,
) -> Result<(), SelfAttestationRateLimitError> {
    state
        .self_attestation_rate_limiter
        .consume_subject_mismatch_denial_only(principal_hash)
}

#[allow(clippy::too_many_arguments)]
fn require_self_attestation_stored_access(
    state: &RegistryWitnessApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    evaluation: &registry_witness_core::StoredEvaluation,
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
    if metadata.subject_id_type.as_str() != state.self_attestation.subject_binding.id_type {
        return Err(EvidenceError::EvaluationBindingMismatch);
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
    let subject_binding_hash = state
        .self_attestation_rate_keys
        .subject_binding(subject_binding_value)
        .map_err(|error| error.evidence_error())?;
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

fn verified_audiences_match(left: &[VerifiedClaimValue], right: &[VerifiedClaimValue]) -> bool {
    let left = left.iter().collect::<std::collections::BTreeSet<_>>();
    let right = right.iter().collect::<std::collections::BTreeSet<_>>();
    left == right
}

fn claim_allows_disclosure(evidence: &EvidenceConfig, claim_id: &str, disclosure: &str) -> bool {
    crate::find_claim(evidence, claim_id).is_ok_and(|claim| {
        claim.disclosure.default == disclosure
            || claim
                .disclosure
                .allowed
                .iter()
                .any(|allowed| allowed == disclosure)
    })
}

fn selected_disclosure(
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
    registry_witness_core::DisclosureProfile::parse(disclosure)
        .ok_or(EvidenceError::InvalidRequest)
        .map(|profile| profile.as_str().to_string())
}

fn self_attestation_denied(reason: SelfAttestationDenialCode) -> EvidenceError {
    EvidenceError::SelfAttestationDenied { reason }
}

fn denial_code_from_error(error: &EvidenceError) -> Option<SelfAttestationDenialCode> {
    match error {
        EvidenceError::SelfAttestationDenied { reason } => Some(*reason),
        _ => None,
    }
}

fn denial_code_from_response(response: &Response) -> Option<SelfAttestationDenialCode> {
    response
        .extensions()
        .get::<EvidenceErrorCodeContext>()
        .and_then(|context| SelfAttestationDenialCode::parse(&context.0))
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
        access_mode: None,
        denial_code: None,
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
    });
}

struct SelfAttestationCredentialAuditDetails<'a> {
    profile_id: &'a str,
    holder_binding_mode: &'a str,
    policy_hash: Option<Hashed<PolicyIdentifier>>,
    protocol: Option<&'a str>,
    credential_configuration_id: Option<&'a str>,
}

fn attach_self_attestation_credential_audit(
    response: &mut Response,
    evaluation_id: &str,
    claim_ids: &[String],
    row_count: u64,
    details: SelfAttestationCredentialAuditDetails<'_>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: Some(evaluation_id.to_string()),
        verification_decision: Some("credential_issued".to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count: Some(row_count),
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: None,
        token_claim_name: None,
        credential_profile: ConfigMetadata::new(details.profile_id).ok(),
        protocol: details
            .protocol
            .and_then(|value| ConfigMetadata::new(value).ok()),
        credential_configuration_id: details
            .credential_configuration_id
            .and_then(|value| ConfigMetadata::new(value).ok()),
        holder_binding_mode: ConfigMetadata::new(details.holder_binding_mode).ok(),
        rate_limit_bucket: None,
        policy_hash: details.policy_hash,
    });
}

fn attach_self_attestation_success_audit(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
    policy_hash: Option<Hashed<PolicyIdentifier>>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: None,
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash,
    });
}

fn attach_self_attestation_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    denial_code: Option<SelfAttestationDenialCode>,
    token_claim_name: Option<&str>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code,
        token_claim_name: token_claim_name.and_then(|name| ConfigMetadata::new(name).ok()),
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
    });
}

fn attach_oid4vci_self_attestation_denial_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    credential_configuration_id: &str,
    denial_code: Option<SelfAttestationDenialCode>,
    token_claim_name: Option<&str>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code,
        token_claim_name: token_claim_name.and_then(|name| ConfigMetadata::new(name).ok()),
        credential_profile: None,
        protocol: ConfigMetadata::new("openid4vci").ok(),
        credential_configuration_id: ConfigMetadata::new(credential_configuration_id).ok(),
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_hash: None,
    });
}

fn attach_self_attestation_rate_limit_audit(
    response: &mut Response,
    decision: &str,
    claim_ids: &[String],
    bucket: Option<SelfAttestationRateLimitBucket>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: None,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        row_count: None,
        access_mode: Some(AccessMode::SelfAttestation),
        denial_code: Some(SelfAttestationDenialCode::RateLimited),
        token_claim_name: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: bucket.and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
        policy_hash: None,
    });
}

pub(crate) fn evidence_error_response(error: EvidenceError) -> Response {
    let code = error.code().to_string();
    let audit_code = error.audit_code().to_string();
    let status = evidence_status(&error);
    let body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": evidence_title(&error),
        "status": status.as_u16(),
        "detail": evidence_detail(&error),
        "code": code,
    });
    let mut response = (status, Json(body)).into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(audit_code));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub(crate) fn evidence_status(error: &EvidenceError) -> StatusCode {
    match error {
        EvidenceError::ServerDisabled
        | EvidenceError::OperationUnsupported
        | EvidenceError::CredentialIssuerNotConfigured => StatusCode::NOT_IMPLEMENTED,
        EvidenceError::FormatUnsupported => StatusCode::NOT_ACCEPTABLE,
        EvidenceError::ClaimNotFound
        | EvidenceError::SourceNotFound
        | EvidenceError::EvaluationNotFound => StatusCode::NOT_FOUND,
        EvidenceError::MissingCredential => StatusCode::UNAUTHORIZED,
        EvidenceError::SelfAttestationInvalidToken => StatusCode::UNAUTHORIZED,
        EvidenceError::InvalidRequest
        | EvidenceError::HolderProofRequired
        | EvidenceError::PurposeRequired => StatusCode::BAD_REQUEST,
        EvidenceError::DisclosureNotAllowed
        | EvidenceError::EvaluationBindingMismatch
        | EvidenceError::ScopeDenied { .. }
        | EvidenceError::SelfAttestationDenied { .. }
        | EvidenceError::SelfAttestationAssuranceDenied => StatusCode::FORBIDDEN,
        EvidenceError::SourceAmbiguous
        | EvidenceError::IdempotencyConflict
        | EvidenceError::HolderProofReplay => StatusCode::CONFLICT,
        EvidenceError::SourceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        EvidenceError::SelfAttestationRateLimited => StatusCode::TOO_MANY_REQUESTS,
        EvidenceError::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        EvidenceError::CredentialIssuanceFailed | EvidenceError::RuleEvaluationFailed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub(crate) fn evidence_title(error: &EvidenceError) -> &'static str {
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
        EvidenceError::SelfAttestationDenied { .. } => "Self-attestation denied",
        EvidenceError::SelfAttestationRateLimited => "Self-attestation rate limited",
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => "Self-attestation denied",
        _ => "Evidence error",
    }
}

pub(crate) fn evidence_detail(error: &EvidenceError) -> &'static str {
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
        EvidenceError::SelfAttestationDenied { .. } => "self-attestation request was denied",
        EvidenceError::SelfAttestationRateLimited => "self-attestation request was rate limited",
        EvidenceError::SelfAttestationInvalidToken
        | EvidenceError::SelfAttestationAssuranceDenied => "self-attestation request was denied",
        _ => "evidence request failed",
    }
}

pub(crate) fn evidence_claim_hash(claim_ids: &[String]) -> String {
    let mut hasher = Sha256::new();
    for claim_id in claim_ids {
        hasher.update(claim_id.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

fn self_attestation_policy_hash(
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
            "issuer_kid": profile.issuer_kid,
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
        "credential_profile_policy": credential_profiles,
        "max_credential_validity_seconds": config.token_policy.max_credential_validity_seconds,
        "claim_profiles": claim_profiles,
    });
    let bytes = serde_json::to_vec(&canonical).map_err(|_| EvidenceError::InvalidRequest)?;
    Ok(Hashed::from_hash(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(bytes))
    )))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
    use registry_platform_testing::sign_openid4vci_proof_jwt;
    use registry_witness_core::{
        BoundedVerifiedClaims, SourceBindingConfig, SubjectRequest, VerifiedClaimName,
        VerifiedClaimValue,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Ed25519 keypair: `d` is the seed, `x` is the corresponding public key,
    // both base64url (no padding). Identical to the key in
    // registry-witness-core::sd_jwt tests so behavior is consistent.
    const HOLDER_PRIV_D_B64: &str = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw";
    const HOLDER_PUB_X_B64: &str = "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc";
    const ISSUER_PRIV_D_B64: &str = "f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys";
    const ISSUER_PUB_X_B64: &str = "pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec";
    const SUBJECT_BINDING_CLAIM: &str = "https://id.example.gov/claims/national_id";

    fn holder_did_jwk() -> String {
        let holder = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": HOLDER_PRIV_D_B64,
                "x": HOLDER_PUB_X_B64,
                "alg": "EdDSA"
            })
            .to_string(),
        )
        .expect("holder JWK parses");
        did_jwk_from_public_jwk(&holder.public()).expect("did:jwk encodes")
    }

    fn bounded(value: &str) -> VerifiedClaimValue {
        VerifiedClaimValue::new(value).expect("test claim value is bounded")
    }

    fn self_attestation_config() -> SelfAttestationConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "requires_auth_mode": "oidc",
            "subject_binding": {
                "token_claim": SUBJECT_BINDING_CLAIM,
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact",
                "allow_sub_as_civil_id": false
            },
            "citizen_clients": {
                "allowed_client_ids": ["citizen-portal"],
                "allowed_audiences": ["registry-witness-citizen"]
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 600,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": true,
                "batch_evaluate": false
            },
            "allowed_purposes": ["citizen_self_attestation"],
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "allowed_wallet_origins": ["https://wallet.example.gov"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses")
    }

    fn evidence_config() -> EvidenceConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "1",
                "subject_type": "person",
                "purpose": "citizen_self_attestation",
                "rule": { "type": "cel", "expression": "true" },
                "operations": {
                    "evaluate": { "enabled": true },
                    "batch_evaluate": { "enabled": true, "max_subjects": 5 }
                },
                "disclosure": {
                    "default": "predicate",
                    "allowed": ["predicate"],
                    "downgrade": "deny"
                },
                "formats": [FORMAT_CLAIM_RESULT_JSON]
            }]
        }))
        .expect("evidence config parses")
    }

    fn oid4vci_config() -> Oid4vciConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "credential_issuer": "http://127.0.0.1:4325",
            "authorization_servers": ["http://localhost:8088/v1/esignet"],
            "accepted_token_audiences": ["http://127.0.0.1:4325"],
            "credential_endpoint": "http://127.0.0.1:4325/oid4vci/credential",
            "offer_endpoint": "http://127.0.0.1:4325/oid4vci/credential-offer",
            "nonce_endpoint": "http://127.0.0.1:4325/oid4vci/nonce",
            "nonce": { "enabled": true, "ttl_seconds": 300 },
            "credential_configurations": {
                "person_is_alive_sd_jwt": {
                    "claim_id": "person-is-alive",
                    "credential_profile": "civil_status_sd_jwt",
                    "format": "dc+sd-jwt",
                    "scope": "person_is_alive",
                    "vct": "https://issuer.example/credentials/civil-status",
                    "display_name": "Person is alive"
                }
            }
        }))
        .expect("oid4vci config parses")
    }

    #[test]
    fn oid4vci_metadata_is_public_but_not_operationally_leaky() {
        let metadata =
            serde_json::to_value(oid4vci_metadata(&oid4vci_config())).expect("metadata serializes");

        assert_eq!(
            metadata["credential_endpoint"],
            "http://127.0.0.1:4325/oid4vci/credential"
        );
        assert_eq!(
            metadata["nonce_endpoint"],
            "http://127.0.0.1:4325/oid4vci/nonce"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
                ["name"],
            "Person is alive"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["scope"],
            "person_is_alive"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
                ["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"][0],
            "EdDSA"
        );
        let mut without_nonce = oid4vci_config();
        without_nonce.nonce.enabled = false;
        let without_nonce =
            serde_json::to_value(oid4vci_metadata(&without_nonce)).expect("metadata serializes");
        assert!(without_nonce.get("nonce_endpoint").is_none());
        let text = metadata.to_string();
        assert!(!text.contains("token_env"));
        assert!(!text.contains("source_connections"));
        assert!(!text.contains("NAT-123"));
    }

    #[tokio::test]
    async fn oid4vci_wire_errors_use_oauth_codes_and_keep_internal_audit_code() {
        let response = oid4vci_error_response(Oid4vciWireError::InvalidProof);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<EvidenceErrorCodeContext>()
                .map(|context| context.0.as_str()),
            Some("oid4vci.invalid_proof")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");

        assert_eq!(body["error"], "invalid_proof");
        assert!(body.get("code").is_none());
    }

    #[test]
    fn oid4vci_nonce_store_consumes_once_and_rejects_replay() {
        let store = EvidenceStore::default();
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let key = keys
            .oid4vci_nonce(
                "https://issuer.example",
                "person_is_alive_sd_jwt",
                "nonce-1",
            )
            .expect("nonce hashes");
        let wrong_config_key = keys
            .oid4vci_nonce(
                "https://issuer.example",
                "other_credential_sd_jwt",
                "nonce-1",
            )
            .expect("nonce hashes for other config");
        store
            .insert_oid4vci_nonce(
                key.clone(),
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .expect("nonce inserts");

        assert!(matches!(
            store.consume_oid4vci_nonce(&wrong_config_key),
            Err(EvidenceError::HolderProofRequired)
        ));
        store
            .consume_oid4vci_nonce(&key)
            .expect("first nonce use succeeds");
        assert!(matches!(
            store.consume_oid4vci_nonce(&key),
            Err(EvidenceError::HolderProofRequired)
        ));
    }

    #[cfg(feature = "registry-witness-cel")]
    #[tokio::test]
    async fn oid4vci_credential_issues_sd_jwt_and_rejects_nonce_replay() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let mut self_attestation = self_attestation_config();
        self_attestation
            .allowed_formats
            .push(FORMAT_SD_JWT_VC.to_string());
        let mut evidence = evidence_config();
        evidence
            .claims
            .first_mut()
            .expect("claim exists")
            .formats
            .push(FORMAT_SD_JWT_VC.to_string());
        evidence
            .claims
            .first_mut()
            .expect("claim exists")
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.credential_profiles.insert(
            "civil_status_sd_jwt".to_string(),
            serde_json::from_value(json!({
                "format": FORMAT_SD_JWT_VC,
                "issuer": "did:web:issuer.example",
                "issuer_key_env": "ISSUER_KEY",
                "vct": "https://issuer.example/credentials/civil-status",
                "validity_seconds": 600,
                "holder_binding": {
                    "mode": "did",
                    "proof_of_possession": "required",
                    "allowed_did_methods": ["did:jwk"]
                },
                "allowed_claims": ["person-is-alive"],
                "disclosure": { "allowed": ["predicate"] }
            }))
            .expect("profile parses"),
        );
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-witness-citizen".to_string()];
        let state = Arc::new(
            RegistryWitnessApiState::new_with_self_attestation_and_oid4vci(
                Arc::new(evidence),
                Arc::new(self_attestation),
                Arc::new(oid4vci),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(StaticIssuerResolver),
            ),
        );
        let nonce = "nonce-1";
        let nonce_key = state
            .self_attestation_rate_keys
            .oid4vci_nonce(
                &state.oid4vci.credential_issuer,
                "person_is_alive_sd_jwt",
                nonce,
            )
            .expect("nonce hashes");
        store
            .insert_oid4vci_nonce(
                nonce_key,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .expect("nonce inserts");
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
        let request = Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof.clone(),
            },
        };

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Json(request.clone()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("credential body parses");
        assert_eq!(body["format"], SD_JWT_VC_FORMAT);
        assert!(
            body["credential"]
                .as_str()
                .is_some_and(|credential| credential.contains('~')),
            "expected compact SD-JWT credential: {body}"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        let replay = oid4vci_credential(
            Some(Extension(state)),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Json(request),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let replay_body = axum::body::to_bytes(replay.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let replay_body: Value = serde_json::from_slice(&replay_body).expect("error body parses");
        assert_eq!(replay_body["error"], "invalid_proof");
    }

    #[tokio::test]
    async fn oid4vci_rejects_holder_key_equal_to_issuer_key_before_side_effects() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let mut self_attestation = self_attestation_config();
        self_attestation
            .allowed_formats
            .push(FORMAT_SD_JWT_VC.to_string());
        let mut evidence = evidence_config();
        evidence
            .claims
            .first_mut()
            .expect("claim exists")
            .formats
            .push(FORMAT_SD_JWT_VC.to_string());
        evidence
            .claims
            .first_mut()
            .expect("claim exists")
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.credential_profiles.insert(
            "civil_status_sd_jwt".to_string(),
            serde_json::from_value(json!({
                "format": FORMAT_SD_JWT_VC,
                "issuer": "did:web:issuer.example",
                "issuer_key_env": "ISSUER_KEY",
                "vct": "https://issuer.example/credentials/civil-status",
                "validity_seconds": 600,
                "holder_binding": {
                    "mode": "did",
                    "proof_of_possession": "required",
                    "allowed_did_methods": ["did:jwk"]
                },
                "allowed_claims": ["person-is-alive"],
                "disclosure": { "allowed": ["predicate"] }
            }))
            .expect("profile parses"),
        );
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-witness-citizen".to_string()];
        let state = Arc::new(
            RegistryWitnessApiState::new_with_self_attestation_and_oid4vci(
                Arc::new(evidence),
                Arc::new(self_attestation),
                Arc::new(oid4vci),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(HolderIssuerResolver),
            ),
        );
        let nonce = "nonce-equal-key";
        let nonce_key = state
            .self_attestation_rate_keys
            .oid4vci_nonce(
                &state.oid4vci.credential_issuer,
                "person_is_alive_sd_jwt",
                nonce,
            )
            .expect("nonce hashes");
        store
            .insert_oid4vci_nonce(
                nonce_key.clone(),
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .expect("nonce inserts");

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce),
                },
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        store
            .consume_oid4vci_nonce(&nonce_key)
            .expect("nonce is not consumed before equal-key denial");
    }

    #[test]
    fn oid4vci_credential_request_rejects_ambiguous_configuration_ids() {
        let mut request = Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: Some("other_sd_jwt".to_string()),
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: "a.b.c".to_string(),
            },
        };

        assert_eq!(
            oid4vci_configuration_for_request(&oid4vci_config(), &request),
            Err(Oid4vciWireError::InvalidRequest)
        );

        request.credential_configuration_id = Some("person_is_alive_sd_jwt".to_string());
        request.vct = Some("https://issuer.example/credentials/other".to_string());
        assert_eq!(
            oid4vci_configuration_for_request(&oid4vci_config(), &request),
            Err(Oid4vciWireError::InvalidRequest)
        );
    }

    fn oidc_principal(client_id: Option<&str>, scopes: &[&str]) -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "citizen-subject".to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            access_mode: AccessMode::MachineClient,
            verified_claims: Some(BoundedVerifiedClaims {
                issuer: bounded("https://id.example.gov"),
                audiences: vec![bounded("registry-witness-citizen")],
                client_id: client_id.map(bounded),
                token_type: Some(bounded("JWT")),
                scopes: scopes.iter().map(|scope| bounded(scope)).collect(),
                subject: Some(bounded("login-subject")),
                subject_binding_claim: Some(
                    VerifiedClaimName::new(SUBJECT_BINDING_CLAIM)
                        .expect("subject claim name is bounded"),
                ),
                subject_binding_value: Some(bounded("NAT-123")),
                acr: Some(bounded("urn:example:loa:substantial")),
                auth_time: Some(1_700_000_000),
                exp: Some(1_700_000_900),
                iat: Some(1_700_000_000),
                nbf: None,
            }),
        }
    }

    fn fresh_oidc_principal(client_id: Option<&str>, scopes: &[&str]) -> EvidencePrincipal {
        let mut principal = oidc_principal(client_id, scopes);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.auth_time = Some(now);
        claims.iat = Some(now);
        claims.exp = Some(now + 600);
        principal
    }

    fn evaluate_request(subject_id: &str) -> EvaluateRequest {
        EvaluateRequest {
            subject: SubjectRequest {
                id: subject_id.to_string(),
                id_type: Some("national_id".to_string()),
            },
            claims: vec!["person-is-alive".to_string()],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        }
    }

    #[test]
    fn self_attestation_classification_requires_citizen_client_and_scope() {
        let config = self_attestation_config();

        let classified = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen client and scope classify");
        assert!(classified.is_self_attestation());

        let missing_scope = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &[]),
        )
        .expect_err("citizen client without scope fails closed");
        assert!(matches!(
            missing_scope,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::InvalidToken
            }
        ));

        let mut no_citizen_client_or_audience =
            oidc_principal(Some("client_id:other"), &["self_attestation"]);
        no_citizen_client_or_audience
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .audiences
            .clear();
        let missing_client =
            classify_self_attestation_principal(&config, &no_citizen_client_or_audience)
                .expect_err("scope without citizen client or audience fails closed");
        assert!(matches!(
            missing_client,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::InvalidToken
            }
        ));
    }

    #[test]
    fn self_attestation_optional_scope_policy_allows_absent_scope_only() {
        let mut config = self_attestation_config();
        config.scope_policy = SelfAttestationScopePolicy::Optional;

        let no_scope = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &[]),
        )
        .expect(
            "optional policy accepts a scoped-out citizen token when no scope claim is present",
        );
        assert!(no_scope.is_self_attestation());

        let wrong_scope = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &["openid"]),
        )
        .expect_err("optional policy still rejects a present but insufficient scope claim");
        assert!(matches!(
            wrong_scope,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::InvalidToken
            }
        ));
    }

    #[test]
    fn self_attestation_disabled_scope_policy_uses_client_and_audience_only() {
        let mut config = self_attestation_config();
        config.scope_policy = SelfAttestationScopePolicy::Disabled;
        config.required_scopes.clear();

        let classified = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &[]),
        )
        .expect("disabled policy classifies by verified citizen client and audience");
        assert!(classified.is_self_attestation());

        let mut wrong_client = oidc_principal(Some("client_id:other"), &[]);
        wrong_client
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .audiences
            .clear();
        let denied = classify_self_attestation_principal(&config, &wrong_client)
            .expect("non-citizen token remains a machine-client candidate");
        assert!(!denied.is_self_attestation());
    }

    #[test]
    fn self_attestation_scope_without_verified_claims_fails_closed() {
        let config = self_attestation_config();
        let principal = EvidencePrincipal {
            principal_id: "citizen-subject".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };

        let err = classify_self_attestation_principal(&config, &principal)
            .expect_err("citizen scope without verified claims must not fall back to machine mode");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::InvalidToken
            }
        ));
    }

    #[test]
    fn self_attestation_evaluate_guard_rejects_subject_mismatch() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");

        let err = require_self_attestation_evaluate(
            &evidence,
            &config,
            &principal,
            &evaluate_request("NAT-999"),
        )
        .expect_err("mismatched subject must be denied before runtime");
        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::SubjectMismatch
            }
        ));
    }

    #[test]
    fn self_attestation_prepare_pins_claim_purpose_and_metadata() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let state = RegistryWitnessApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );

        let context = prepare_self_attestation_evaluate(
            &state,
            &evidence,
            &principal,
            &evaluate_request("NAT-123"),
        )
        .expect("self-attestation evaluate context prepares");

        assert_eq!(context.purpose, "citizen_self_attestation");
        assert_eq!(context.metadata.access_mode, AccessMode::SelfAttestation);
        assert_eq!(context.metadata.subject_id_type.as_str(), "national_id");
        assert!(context.metadata.policy_hash.is_some());
        assert!(
            context.metadata.evaluation_expires_at.is_some(),
            "self-attestation evaluation must carry its capped expiry"
        );
        assert!(matches!(
            context.source_capability,
            SourceCapability::SelfAttestation { .. }
        ));
    }

    #[test]
    fn self_attestation_token_policy_fails_closed_without_auth_time() {
        let config = self_attestation_config();
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .auth_time = None;

        let err = require_self_attestation_token_policy(&config, &principal)
            .expect_err("missing auth_time fails closed");

        assert!(matches!(err, EvidenceError::SelfAttestationAssuranceDenied));
    }

    #[test]
    fn self_attestation_token_policy_fails_closed_without_required_acr() {
        let mut config = self_attestation_config();
        config.token_policy.required_acr_values = vec!["urn:example:loa:substantial".to_string()];
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .acr = None;

        let err = require_self_attestation_token_policy(&config, &principal)
            .expect_err("missing acr fails closed when required");

        assert!(matches!(err, EvidenceError::SelfAttestationAssuranceDenied));
    }

    #[test]
    fn self_attestation_token_policy_rejects_future_iat_and_auth_time() {
        let config = self_attestation_config();
        let principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");

        let mut future_auth_time = principal.clone();
        future_auth_time
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .auth_time = Some(OffsetDateTime::now_utc().unix_timestamp() + 3_600);
        assert!(matches!(
            require_self_attestation_token_policy(&config, &future_auth_time),
            Err(EvidenceError::SelfAttestationAssuranceDenied)
        ));

        let mut future_iat = principal;
        future_iat
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .iat = Some(OffsetDateTime::now_utc().unix_timestamp() + 3_600);
        assert!(matches!(
            require_self_attestation_token_policy(&config, &future_iat),
            Err(EvidenceError::SelfAttestationAssuranceDenied)
        ));
    }

    #[test]
    fn stored_self_attestation_rechecks_issuer_client_and_audience() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let state = RegistryWitnessApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let context = prepare_self_attestation_evaluate(
            &state,
            &evidence,
            &principal,
            &evaluate_request("NAT-123"),
        )
        .expect("self-attestation context prepares");
        let mut evaluation = evaluation_for_proof();
        evaluation.client_id = principal.principal_id.clone();
        evaluation.claim_ids = vec!["person-is-alive".to_string()];
        evaluation.disclosure = "predicate".to_string();
        evaluation.format = FORMAT_CLAIM_RESULT_JSON.to_string();
        evaluation.self_attestation = Some(context.metadata);

        let mut changed_client = principal.clone();
        changed_client
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .client_id = Some(bounded("client_id:other-portal"));

        let err = require_self_attestation_stored_access(
            &state,
            &evidence,
            &changed_client,
            &evaluation,
            &evaluation.claim_ids,
            &evaluation.disclosure,
            &evaluation.format,
            None,
        )
        .expect_err("changed client id must not access stored evaluation");

        assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
    }

    #[test]
    fn stored_self_attestation_rejects_expired_metadata_even_with_future_store_ttl() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let state = RegistryWitnessApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut context = prepare_self_attestation_evaluate(
            &state,
            &evidence,
            &principal,
            &evaluate_request("NAT-123"),
        )
        .expect("self-attestation context prepares");
        context.metadata.evaluation_expires_at = Some("1970-01-01T00:00:00Z".to_string());
        let mut evaluation = evaluation_for_proof();
        evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
        evaluation.claim_ids = vec!["person-is-alive".to_string()];
        evaluation.disclosure = "predicate".to_string();
        evaluation.format = FORMAT_CLAIM_RESULT_JSON.to_string();
        evaluation.expires_at = "2999-01-01T00:00:00Z".to_string();
        evaluation.self_attestation = Some(context.metadata);

        let err = require_self_attestation_stored_access(
            &state,
            &evidence,
            &principal,
            &evaluation,
            &evaluation.claim_ids,
            &evaluation.disclosure,
            &evaluation.format,
            None,
        )
        .expect_err("expired self-attestation metadata must fail closed");

        assert!(matches!(err, EvidenceError::EvaluationNotFound));
    }

    #[test]
    fn self_attestation_public_problem_codes_remain_generic() {
        assert_eq!(
            EvidenceError::SelfAttestationInvalidToken.code(),
            "self_attestation.denied"
        );
        assert_eq!(
            EvidenceError::SelfAttestationInvalidToken.audit_code(),
            "self_attestation.invalid_token"
        );
        assert_eq!(
            evidence_status(&EvidenceError::SelfAttestationInvalidToken),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            EvidenceError::SelfAttestationAssuranceDenied.code(),
            "self_attestation.denied"
        );
        assert_eq!(
            EvidenceError::SelfAttestationAssuranceDenied.audit_code(),
            "self_attestation.assurance_denied"
        );
        assert_eq!(
            evidence_status(&EvidenceError::SelfAttestationAssuranceDenied),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn self_attestation_policy_hash_includes_credential_profile_policy() {
        let config = self_attestation_config();
        let mut evidence = evidence_config();
        evidence.credential_profiles.insert(
            "civil_status_sd_jwt".to_string(),
            serde_json::from_value(json!({
                "format": FORMAT_SD_JWT_VC,
                "issuer": "did:web:issuer.example",
                "issuer_key_env": "ISSUER_KEY",
                "vct": "https://issuer.example/credentials/civil-status",
                "validity_seconds": 600,
                "holder_binding": {
                    "mode": "did",
                    "proof_of_possession": "required",
                    "allowed_did_methods": ["did:jwk"]
                },
                "allowed_claims": ["person-is-alive"],
                "disclosure": { "allowed": ["predicate"] }
            }))
            .expect("profile parses"),
        );
        let claims = vec!["person-is-alive".to_string()];
        let original = self_attestation_policy_hash(
            &evidence,
            &config,
            &claims,
            "predicate",
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("policy hashes");

        evidence
            .credential_profiles
            .get_mut("civil_status_sd_jwt")
            .expect("profile exists")
            .holder_binding
            .proof_of_possession = None;
        let changed = self_attestation_policy_hash(
            &evidence,
            &config,
            &claims,
            "predicate",
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("changed policy hashes");

        assert_ne!(original, changed);
    }

    #[derive(Default)]
    struct CountingSource {
        reads: Arc<AtomicUsize>,
    }

    impl SourceReader for CountingSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Err(EvidenceError::SourceUnavailable)
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec!["civil_registry:evidence_verification".to_string()])
        }
    }

    struct NoopIssuerResolver;

    impl EvidenceIssuerResolver for NoopIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_witness_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            Err(EvidenceError::CredentialIssuerNotConfigured)
        }
    }

    #[cfg(feature = "registry-witness-cel")]
    struct StaticIssuerResolver;

    #[cfg(feature = "registry-witness-cel")]
    impl EvidenceIssuerResolver for StaticIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_witness_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_witness_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "d": ISSUER_PRIV_D_B64,
                    "x": ISSUER_PUB_X_B64,
                    "alg": "EdDSA"
                })
                .to_string(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    struct HolderIssuerResolver;

    impl EvidenceIssuerResolver for HolderIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_witness_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_witness_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &holder_private_jwk(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    #[tokio::test]
    async fn self_attestation_batch_evaluate_is_rejected_before_source_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(RegistryWitnessApiState::new_with_self_attestation(
            Arc::new(evidence_config()),
            Arc::new(self_attestation_config()),
            Arc::new(CountingSource {
                reads: Arc::clone(&reads),
            }),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        ));
        let request = BatchEvaluateRequest {
            subjects: vec![SubjectRequest {
                id: "NAT-123".to_string(),
                id_type: Some("national_id".to_string()),
            }],
            claims: vec!["person-is-alive".to_string()],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        };

        let response = batch_evaluate(
            HeaderMap::new(),
            Some(Extension(state)),
            Some(Extension(oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            None,
            Json(request),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("self-attestation denial audit context is attached");
        assert_eq!(audit.access_mode, Some(AccessMode::SelfAttestation));
        assert_eq!(
            audit.denial_code,
            Some(SelfAttestationDenialCode::BatchDenied)
        );
    }

    fn sign_holder_proof(holder_id: &str, payload: Value) -> String {
        let holder = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": HOLDER_PRIV_D_B64,
                "x": HOLDER_PUB_X_B64,
                "alg": "EdDSA",
                "kid": holder_id,
            })
            .to_string(),
        )
        .expect("holder JWK parses");
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA",
                "typ": "kb+jwt",
                "kid": holder_id,
            }))
            .expect("header serializes"),
        );
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload serializes"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign(signing_input.as_bytes(), &holder).expect("sign holder proof");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn sign_oid4vci_proof(audience: &str, nonce: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sign_openid4vci_proof_jwt(&holder_private_jwk(), audience, Some(nonce), now)
    }

    fn holder_private_jwk() -> String {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": HOLDER_PRIV_D_B64,
            "x": HOLDER_PUB_X_B64,
            "alg": "EdDSA"
        })
        .to_string()
    }

    fn issuer_private_jwk() -> String {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": ISSUER_PRIV_D_B64,
            "x": ISSUER_PUB_X_B64,
            "alg": "EdDSA"
        })
        .to_string()
    }

    #[test]
    fn oid4vci_rejects_holder_key_equal_to_issuer_key() {
        let issuer = registry_witness_core::sd_jwt::EvidenceIssuer::from_jwk_str(
            &issuer_private_jwk(),
            "did:web:issuer.example#key-1".to_string(),
        )
        .expect("issuer parses");
        let issuer_public =
            PublicJwk::parse(&issuer.public_jwk().to_string()).expect("issuer public parses");
        let holder_public = PrivateJwk::parse(&holder_private_jwk())
            .expect("holder parses")
            .public();

        assert!(holder_key_matches_issuer_key(
            &issuer_public,
            &issuer.public_jwk()
        ));
        assert!(!holder_key_matches_issuer_key(
            &holder_public,
            &issuer.public_jwk()
        ));
    }

    fn evaluation_for_proof() -> registry_witness_core::StoredEvaluation {
        registry_witness_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        }
    }

    fn issue_request() -> CredentialIssueRequest {
        CredentialIssueRequest {
            evaluation_id: "eval-1".to_string(),
            credential_profile: Some("profile-a".to_string()),
            format: None,
            claims: None,
            disclosure: None,
            holder: None,
        }
    }

    fn holder_required_profile() -> CredentialProfileConfig {
        serde_json::from_value(json!({
            "format": FORMAT_SD_JWT_VC,
            "issuer": "did:web:issuer.example",
            "issuer_key_env": "ISSUER_KEY",
            "vct": "https://issuer.example/credentials/civil-status",
            "validity_seconds": 600,
            "holder_binding": {
                "mode": "did",
                "proof_of_possession": "required",
                "allowed_did_methods": ["did:jwk"]
            },
            "allowed_claims": ["claim-a"],
            "disclosure": { "allowed": ["redacted"] }
        }))
        .expect("profile parses")
    }

    fn proof_payload(holder_id: &str, aud: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp() + 10;
        json!({
            "sub": holder_id,
            "aud": aud,
            "iat": now,
            "exp": now + 60,
            "jti": "jti-1",
            "evaluation_id": "eval-1",
            "credential_profile": "profile-a",
            "disclosure": holder_proof_disclosure("redacted"),
            "claims": ["claim-a"],
        })
    }

    #[test]
    fn holder_proof_audience_must_match_configured_service_id() {
        // Aim: the holder proof JWT's `aud` is bound to the configured
        // service_id, not the hard-coded literal "registry-witness".
        let holder_id = holder_did_jwk();
        let service_id = "my.witness.example";
        let request = issue_request();
        let evaluation = evaluation_for_proof();

        let proof_matching = sign_holder_proof(&holder_id, proof_payload(&holder_id, service_id));
        validate_holder_proof_payload(
            &proof_matching,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect("proof signed with aud=service_id must be accepted");

        let proof_legacy_literal =
            sign_holder_proof(&holder_id, proof_payload(&holder_id, "registry-witness"));
        let err = validate_holder_proof_payload(
            &proof_legacy_literal,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect_err("proof with aud=\"registry-witness\" must be rejected when service_id differs");
        assert!(matches!(err, EvidenceError::HolderProofRequired));
    }

    #[test]
    fn strict_credential_issue_rejects_oid4vci_proof_shape() {
        let holder_id = holder_did_jwk();
        let proof = sign_oid4vci_proof("registry-witness", "nonce-1");
        let request = issue_request();
        let evaluation = evaluation_for_proof();
        let holder = HolderRequest {
            binding: Some("did".to_string()),
            id: Some(holder_id),
            proof: Some(proof),
        };

        let err = validate_holder_request(
            &holder_required_profile(),
            "profile-a",
            &request,
            &evaluation,
            Some(&holder),
            "registry-witness",
        )
        .expect_err("OID4VCI proof must not relax the strict credential endpoint proof");

        assert!(matches!(err, EvidenceError::HolderProofRequired));
    }

    fn windowed_proof_payload(holder_id: &str, aud: &str, iat: i64, exp: i64) -> Value {
        json!({
            "sub": holder_id,
            "aud": aud,
            "iat": iat,
            "exp": exp,
            "jti": "jti-window",
            "evaluation_id": "eval-1",
            "credential_profile": "profile-a",
            "disclosure": holder_proof_disclosure("redacted"),
            "claims": ["claim-a"],
        })
    }

    fn holder_proof_disclosure(disclosure: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()))
    }

    #[test]
    fn holder_proof_exp_window_is_bounded_below_and_above() {
        // The accepted lifetime is a strictly positive interval up to 300s.
        // Anything outside that window must be rejected before reaching the
        // replay-key path.
        let holder_id = holder_did_jwk();
        let service_id = "my.witness.example";
        let request = issue_request();
        let evaluation = evaluation_for_proof();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let proof_zero_window = sign_holder_proof(
            &holder_id,
            windowed_proof_payload(&holder_id, service_id, now, now),
        );
        let err = validate_holder_proof_payload(
            &proof_zero_window,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect_err("exp == iat must be rejected");
        assert!(matches!(err, EvidenceError::HolderProofRequired));

        let proof_backdated = sign_holder_proof(
            &holder_id,
            windowed_proof_payload(&holder_id, service_id, now, now - 60),
        );
        let err = validate_holder_proof_payload(
            &proof_backdated,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect_err("exp < iat must be rejected");
        assert!(matches!(err, EvidenceError::HolderProofRequired));

        let proof_over_ceiling = sign_holder_proof(
            &holder_id,
            windowed_proof_payload(&holder_id, service_id, now, now + 301),
        );
        let err = validate_holder_proof_payload(
            &proof_over_ceiling,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect_err("exp > iat + 300 must be rejected");
        assert!(matches!(err, EvidenceError::HolderProofRequired));

        let proof_just_positive = sign_holder_proof(
            &holder_id,
            windowed_proof_payload(&holder_id, service_id, now, now + 1),
        );
        validate_holder_proof_payload(
            &proof_just_positive,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect("exp = iat + 1 must be accepted");
    }
}
