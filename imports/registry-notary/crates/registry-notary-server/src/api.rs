// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary routes.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::sd_jwt;
use registry_notary_core::tokens::{
    mint_access_token, mint_pre_authorized_code, verify_notary_token, AccessTokenClaims,
    BoundSubject, PreAuthorizedCodeClaims, PRE_AUTHORIZED_CODE_JWT_TYP,
};
#[cfg(feature = "registry-notary-cel")]
use registry_notary_core::RegistryNotaryCelConfig;
use registry_notary_core::{
    AccessMode, BatchEvaluateItemRequest, BatchEvaluateRequest, BoundedClaimId,
    BoundedCorrelationId, ClaimRef, ClaimResultView, ClaimSet, ConfigMetadata,
    CredentialIssueRequest, CredentialProfileConfig, EvaluateRequest, EvidenceBatchItemAuditEvent,
    EvidenceConfig, EvidenceEntity, EvidenceEntityReference, EvidenceError, EvidencePrincipal,
    EvidenceRelationship, FederationConfig, Hashed, HolderRequest, Oid4vciConfig,
    Oid4vciCredentialConfigurationConfig, Oid4vciDisplayImageConfig, Oid4vciIssuerDisplayConfig,
    PolicyIdentifier, RateLimitBucket, RenderEvaluationRequest, SelfAttestationConfig,
    SelfAttestationDenialCode, SelfAttestationScopePolicy, SourceCapability,
    StoredSelfAttestationMetadata, SubjectRequest, VerifiedClaimValue, FORMAT_CLAIM_RESULT_JSON,
    FORMAT_SD_JWT_VC,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_crypto::PublicJwk;
use registry_platform_crypto::SigningProvider;
use registry_platform_oid4vci::{
    consume_validated_proof_nonce_once, validate_proof_jwt, CredentialConfigurationMetadata,
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest as Oid4vciCredentialRequest,
    CredentialResponse as Oid4vciCredentialResponse, DisplayImageMetadata, DisplayMetadata,
    NonceRequest as Oid4vciNonceRequest, NonceResponse, ProofValidationPolicy,
    TokenRequest as Oid4vciTokenRequest, TokenResponse as Oid4vciTokenResponse, TxCode,
    ValidatedProof, WireError, PRE_AUTHORIZED_CODE_GRANT_TYPE, PROOF_TYPE_JWT, SD_JWT_VC_FORMAT,
};
use registry_platform_ops::PostureFilterError;
use registry_platform_replay::{ReplayKey, ReplayScope, RequiredReplayError};
use registry_platform_sdjwt::{validate_holder_proof, HolderProofBindings, HolderProofPolicy};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::CelWorker;
use crate::{
    credential_profile_for,
    credential_status::{is_mutable_status, CredentialStatusStore},
    format_time,
    metrics::AppMetrics,
    openapi_document,
    posture::{posture_document, PostureContext},
    preauth_state::LoginState,
    replay::{require_replay_insert, ReplayReadiness, ReplayStores},
    runtime::claim_ids,
    standalone::{
        constant_time_eq, generate_numeric_tx_code, generate_opaque_token, pkce_s256_challenge,
        pre_auth_audit_event, PreAuthAuditFields, PreAuthRuntime, SignerReadiness,
    },
    BatchEvaluateOptions, EvidenceStore, RegistryNotaryRuntime, SelfAttestationRateLimitBucket,
    SelfAttestationRateLimitError, SelfAttestationRateLimitKeys, SelfAttestationRateLimiter,
    SourceReader,
};

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub(crate) const ADMIN_SCOPE: &str = "registry_notary:admin";
pub(crate) const OPS_READ_SCOPE: &str = "registry_notary:ops_read";
const OID4VCI_CREDENTIAL_PATH: &str = "/oid4vci/credential";
// SD-JWT VC Type Metadata well-known prefix inserted between host and vct path.
const WELL_KNOWN_VCT_PREFIX: &str = "/.well-known/vct";
const POSTURE_FILTER_FAILED_CODE: &str = "posture.filter_failed";

pub use crate::federation::federation_router;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/admin/v1/posture", get(admin_posture))
        .route("/admin/v1/reload", post(admin_reload))
        .route("/openapi.json", get(openapi_json))
        .route("/.well-known/evidence-service", get(service_document))
        .route("/.well-known/evidence/jwks.json", get(issuer_jwks))
        .route(
            "/.well-known/openid-credential-issuer",
            get(oid4vci_issuer_metadata),
        )
        .route("/credentials/{*vct_path}", get(oid4vci_type_metadata))
        .route(
            "/.well-known/vct/{*vct_path}",
            get(oid4vci_well_known_type_metadata),
        )
        .route("/oid4vci/credential-offer", get(oid4vci_credential_offer))
        .route("/oid4vci/offer/start", get(oid4vci_offer_start))
        .route("/oid4vci/offer/callback", get(oid4vci_offer_callback))
        .route("/oid4vci/token", post(oid4vci_token))
        .route("/oid4vci/nonce", post(oid4vci_nonce))
        .route("/oid4vci/credential", post(oid4vci_credential))
        .route("/v1/claims", get(list_claims))
        .route("/v1/claims/{claim_id}", get(get_claim))
        .route("/v1/formats", get(list_formats))
        .route("/v1/evaluations", post(evaluate))
        .route("/v1/batch-evaluations", post(batch_evaluate))
        .route("/v1/evaluations/{evaluation_id}/render", post(render))
        .route("/v1/credentials", post(issue_credential))
        .route(
            "/v1/credentials/{credential_id}/status",
            get(get_credential_status),
        )
        .route(
            "/admin/v1/credentials/{credential_id}/status",
            post(update_credential_status),
        )
}

pub async fn oid4vci_proof_precheck_middleware(
    State(state): State<Arc<RegistryNotaryApiState>>,
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
    let expected_nonce = if state.oid4vci.nonce.enabled {
        match oid4vci_proof_nonce(&request.proof.jwt) {
            Ok(nonce) => Some(nonce),
            Err(error) => return oid4vci_error_response(error),
        }
    } else {
        None
    };
    let validated_proof = match validate_proof_jwt(
        &request.proof.jwt,
        &ProofValidationPolicy::credential_endpoint(
            &state.oid4vci.credential_issuer,
            expected_nonce.as_deref(),
            Duration::from_secs(state.oid4vci.proof.max_age_seconds),
            Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
        ),
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        Ok(proof) => proof,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidProof),
    };
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(validated_proof);
    next.run(request).await
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

async fn ready(state: Option<Extension<Arc<RegistryNotaryApiState>>>) -> Response {
    let (base_ready, base_degraded, signer_total, signer_ok, signer_failed) = match state.as_ref() {
        Some(Extension(state)) if state.enabled_evidence().is_ok() => {
            let replay_readiness = state.replay.check_ready().await;
            let credential_status_ready = state.credential_status.check_ready().await.is_ok();
            let replay_ready = matches!(replay_readiness, Ok(ReplayReadiness::Ready));
            let signer_ready = state.signer_readiness.is_ready();
            let degraded = matches!(replay_readiness, Ok(ReplayReadiness::Degraded))
                && credential_status_ready
                && signer_ready;
            (
                replay_ready && credential_status_ready && signer_ready && !degraded,
                degraded,
                state.signer_readiness.total(),
                state.signer_readiness.ready_count(),
                state.signer_readiness.failed_count(),
            )
        }
        _ => (false, false, 0, 0, 0),
    };
    let degraded = usize::from(base_degraded);
    #[cfg(feature = "registry-notary-cel")]
    let (total, ok, failed) = {
        let mut total = 1 + signer_total;
        let mut ok = usize::from(base_ready) + signer_ok;
        let mut failed = usize::from(!base_ready && !base_degraded) + signer_failed;
        if let Some(Extension(state)) = state.as_ref() {
            if let Some(cel_worker) = &state.cel_worker {
                total += 1;
                if cel_worker.check_ready().await {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
        }
        (total, ok, failed)
    };
    #[cfg(not(feature = "registry-notary-cel"))]
    let (total, ok, failed) = (
        1 + signer_total,
        usize::from(base_ready) + signer_ok,
        usize::from(!base_ready && !base_degraded) + signer_failed,
    );

    let ready = ok == total;
    let is_degraded = !ready && failed == 0 && degraded > 0;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status_text = match (ready, is_degraded) {
        (true, _) => "ready",
        (false, true) => "degraded",
        (false, false) => "not_ready",
    };
    (
        status,
        Json(json!({
            "status": status_text,
            "checks": {
                "total": total,
                "ok": ok,
                "degraded": degraded,
                "failed": failed,
                "signing_providers": {
                    "total": signer_total,
                    "ok": signer_ok,
                    "failed": signer_failed,
                },
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

async fn admin_posture(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(OPS_READ_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: OPS_READ_SCOPE.to_string(),
        });
    }
    let Some(Extension(state)) = state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "code": "posture.unavailable",
                "detail": "posture state is unavailable",
            })),
        )
            .into_response();
    };
    match posture_document(&state).await {
        Ok(posture) => Json(posture).into_response(),
        Err(error) => posture_filter_failed(error),
    }
}

async fn get_credential_status(
    Path(credential_id): Path<String>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
) -> Response {
    let Some(Extension(state)) = state else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status is unavailable",
        );
    };
    if !state.credential_status.is_enabled() {
        return credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.disabled",
            "Credential status disabled",
            "credential status is not enabled",
        );
    }
    match state.credential_status.get(&credential_id).await {
        Ok(Some(record)) => Json(record.response_body(OffsetDateTime::now_utc())).into_response(),
        Ok(None) => credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.not_found",
            "Credential status not found",
            "credential status record was not found",
        ),
        Err(_) => credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status store is unavailable",
        ),
    }
}

#[derive(Debug, Deserialize)]
struct CredentialStatusUpdateRequest {
    status: String,
}

async fn update_credential_status(
    Path(credential_id): Path<String>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<CredentialStatusUpdateRequest>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(ADMIN_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: ADMIN_SCOPE.to_string(),
        });
    }
    let Some(Extension(state)) = state else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status is unavailable",
        );
    };
    if !state.credential_status.is_enabled() {
        return credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.disabled",
            "Credential status disabled",
            "credential status is not enabled",
        );
    }
    if !is_mutable_status(request.status.as_str()) {
        return credential_status_problem(
            StatusCode::BAD_REQUEST,
            "credential_status.invalid_status",
            "Invalid credential status",
            "status must be valid, suspended, or revoked",
        );
    }
    match state
        .credential_status
        .update_status(&credential_id, &request.status)
        .await
    {
        Ok(Some(record)) => Json(record.response_body(OffsetDateTime::now_utc())).into_response(),
        Ok(None) => credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.not_found",
            "Credential status not found",
            "credential status record was not found",
        ),
        Err(_) => credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status store is unavailable",
        ),
    }
}

fn credential_status_problem(
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    detail: &'static str,
) -> Response {
    let body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

fn posture_filter_failed(error: PostureFilterError) -> Response {
    tracing::error!(error = %error, "failed to filter admin posture");
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/posture/filter_failed", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Admin posture unavailable",
            "status": status.as_u16(),
            "detail": "admin posture could not be filtered for the requested tier",
            "code": POSTURE_FILTER_FAILED_CODE,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response.extensions_mut().insert(EvidenceErrorCodeContext(
        POSTURE_FILTER_FAILED_CODE.to_string(),
    ));
    response
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
    ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError>;

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
pub struct RegistryNotaryApiState {
    pub(crate) evidence: Arc<EvidenceConfig>,
    pub(crate) self_attestation: Arc<SelfAttestationConfig>,
    pub(crate) oid4vci: Arc<Oid4vciConfig>,
    pub(crate) federation: Arc<FederationConfig>,
    pub(crate) federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
    self_attestation_rate_limiter: Arc<SelfAttestationRateLimiter>,
    pub(crate) self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    pub(crate) replay: ReplayStores,
    pub(crate) credential_status: CredentialStatusStore,
    pub(crate) metrics: Arc<AppMetrics>,
    pub(crate) source: Arc<dyn SourceReader>,
    pub(crate) store: Arc<EvidenceStore>,
    issuers: Arc<dyn EvidenceIssuerResolver>,
    pub(crate) signer_readiness: SignerReadiness,
    pub(crate) posture: Option<Arc<PostureContext>>,
    /// Pre-authorized-code flow runtime. `None` unless the flow is enabled and
    /// the dedicated access-token signing key plus eSignet RP settings loaded.
    pub(crate) preauth: Option<Arc<PreAuthRuntime>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_config: Arc<RegistryNotaryCelConfig>,
}

impl RegistryNotaryApiState {
    #[must_use]
    pub fn new(
        evidence: Arc<EvidenceConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation(
            evidence,
            Arc::new(SelfAttestationConfig::default()),
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci(
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
    pub fn new_with_self_attestation_and_oid4vci(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci_hasher(
            evidence,
            self_attestation,
            oid4vci,
            audit_hasher,
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
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            source,
            store,
            issuers,
            SignerReadiness::default(),
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
        replay: ReplayStores,
        credential_status: CredentialStatusStore,
        metrics: Arc<AppMetrics>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
        federation_signing_provider: Option<Arc<dyn SigningProvider>>,
    ) -> Result<Self, crate::standalone::StandaloneServerError> {
        let federation_runtime = federation
            .enabled
            .then(|| {
                let signing_provider = federation_signing_provider.clone().ok_or_else(|| {
                    crate::standalone::StandaloneServerError::InvalidFederationConfig(
                        "federation signing provider was not built".to_string(),
                    )
                })?;
                crate::federation::FederationRuntimeState::from_config(
                    &federation,
                    signing_provider,
                    federation_audit,
                    replay.store(),
                    Arc::clone(&metrics),
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
            replay,
            credential_status,
            metrics,
            source,
            store,
            issuers,
            SignerReadiness::default(),
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
        replay: ReplayStores,
        credential_status: CredentialStatusStore,
        metrics: Arc<AppMetrics>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
        signer_readiness: SignerReadiness,
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
            replay,
            credential_status,
            metrics,
            source,
            store,
            issuers,
            signer_readiness,
            posture: None,
            preauth: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_worker: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_config: Arc::new(RegistryNotaryCelConfig::default()),
        }
    }

    #[must_use]
    pub(crate) fn with_preauth_runtime(mut self, preauth: Option<Arc<PreAuthRuntime>>) -> Self {
        self.preauth = preauth;
        self
    }

    pub(crate) fn with_signer_readiness(mut self, signer_readiness: SignerReadiness) -> Self {
        self.signer_readiness = signer_readiness;
        self
    }

    pub(crate) fn with_posture_context(mut self, posture: PostureContext) -> Self {
        self.posture = Some(Arc::new(posture));
        self
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub(crate) fn with_cel_worker(mut self, cel_worker: Option<Arc<CelWorker>>) -> Self {
        self.cel_worker = cel_worker;
        self
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub(crate) fn with_cel_config(mut self, cel_config: Arc<RegistryNotaryCelConfig>) -> Self {
        self.cel_config = cel_config;
        self
    }

    pub(crate) fn runtime(&self) -> RegistryNotaryRuntime {
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(
            &self.self_attestation_rate_keys,
        ));
        #[cfg(feature = "registry-notary-cel")]
        {
            runtime
                .with_cel_worker(self.cel_worker.as_ref().map(Arc::clone))
                .with_cel_config(Arc::clone(&self.cel_config))
        }
        #[cfg(not(feature = "registry-notary-cel"))]
        {
            runtime
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
    pub purposes: Option<Vec<String>>,
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
    pub target_type: Option<String>,
    pub target_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    pub requester_type: Option<String>,
    pub requester_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    pub matching_policy_id: Option<String>,
    pub matching_method: Option<String>,
    pub matching_outcome: Option<String>,
    pub matching_error_code: Option<String>,
    pub batch_items: Option<Vec<EvidenceBatchItemAuditEvent>>,
}

#[derive(Debug, Clone)]
pub struct EvidenceErrorCodeContext(pub String);

struct SelfAttestationEvaluateContext {
    source_capability: SourceCapability,
    metadata: StoredSelfAttestationMetadata,
    purpose: String,
}

async fn service_document(
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

fn advertise_credential_status(document: &mut Value) {
    document["credential_capabilities"]["sd_jwt_vc"]["status_methods"] =
        json!(["RegistryNotaryCredentialStatus"]);
    document["credential_capabilities"]["sd_jwt_vc"]["credential_status_url"] =
        json!("/v1/credentials/{credential_id}/status");
    if let Some(features) =
        document["credential_capabilities"]["unsupported_features"].as_array_mut()
    {
        features.retain(|feature| feature.as_str() != Some("credential_status"));
    }
}

async fn oid4vci_issuer_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
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
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
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
        generate_nonce().unwrap_or_else(|_| "registry-notary:self-attestation".to_string()),
        state.oid4vci.authorization_servers.first().cloned(),
    ))
    .into_response()
}

async fn oid4vci_type_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    oid4vci_type_metadata_response(&state, &headers, &uri, uri.path())
}

async fn oid4vci_well_known_type_metadata(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    // Consumers dereference an HTTPS vct by inserting /.well-known/vct between the
    // host and the path. Strip that prefix so the candidate vct reconstructs to the
    // configured identifier (https://{host}/{vct_path}), not the well-known URL.
    let Some(vct_path) = uri.path().strip_prefix(WELL_KNOWN_VCT_PREFIX) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    oid4vci_type_metadata_response(&state, &headers, &uri, vct_path)
}

fn oid4vci_type_metadata_response(
    state: &RegistryNotaryApiState,
    headers: &HeaderMap,
    uri: &Uri,
    request_path: &str,
) -> Response {
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(request_vct) =
        oid4vci_requested_absolute_url_for_path(&state.oid4vci, headers, uri, request_path)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(configuration) = state
        .oid4vci
        .credential_configurations
        .values()
        .find(|configuration| configuration.vct == request_vct)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(oid4vci_type_metadata_document(configuration)).into_response()
}

#[derive(Debug, Deserialize)]
struct Oid4vciCredentialOfferQuery {
    credential_configuration_id: Option<String>,
}

async fn oid4vci_nonce(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
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
    let replay_scope = match oid4vci_nonce_replay_scope(&state, configuration_id) {
        Ok(scope) => scope,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let replay_key = match ReplayKey::new(key) {
        Ok(key) => key,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
    if state
        .replay
        .nonce_store()
        .reserve_nonce(&replay_scope, &replay_key, expires_at)
        .await
        .is_err()
    {
        state.metrics.record_replay("oid4vci_nonce", "error");
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    state.metrics.record_replay("oid4vci_nonce", "reserved");
    Json(NonceResponse {
        c_nonce: nonce,
        c_nonce_expires_in: state.oid4vci.nonce.ttl_seconds,
    })
    .into_response()
}

fn oid4vci_proof_nonce(proof_jwt: &str) -> Result<String, Oid4vciWireError> {
    #[derive(Deserialize)]
    struct NonceClaims {
        nonce: Option<String>,
    }

    let mut parts = proof_jwt.split('.');
    let Some(_) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    let Some(payload_b64) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    let Some(_) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    if parts.next().is_some() {
        return Err(Oid4vciWireError::InvalidProof);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Oid4vciWireError::InvalidProof)?;
    let claims: NonceClaims =
        serde_json::from_slice(&payload).map_err(|_| Oid4vciWireError::InvalidProof)?;
    claims
        .nonce
        .filter(|nonce| !nonce.is_empty())
        .ok_or(Oid4vciWireError::InvalidProof)
}

async fn oid4vci_credential(
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
    if request.format != SD_JWT_VC_FORMAT || request.proof.proof_type != PROOF_TYPE_JWT {
        return oid4vci_error_response(Oid4vciWireError::UnsupportedCredentialType);
    }
    let Some(Extension(validated_proof)) = validated_proof else {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    };
    let (configuration_id, configuration) =
        match oid4vci_configuration_for_request(&state.oid4vci, &request) {
            Ok(configuration) => configuration,
            Err(error) => return oid4vci_error_response(error),
        };
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
    let issuer = match state.issuers.issuer(&configuration.credential_profile) {
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
            std::slice::from_ref(&configuration.claim_id),
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
                std::slice::from_ref(&configuration.claim_id),
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
        claims: vec![ClaimRef::from(configuration.claim_id.clone())],
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
                std::slice::from_ref(&configuration.claim_id),
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
        holder_id,
        Some(holder_id),
        iat,
        sd_jwt::IssueOptions {
            credential_id,
            status: status_claim,
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

#[derive(Debug, Deserialize)]
struct Oid4vciOfferStartQuery {
    credential_configuration_id: Option<String>,
}

/// `GET /oid4vci/offer/start` (public): begin the eSignet authorization-code
/// login as the confidential RP and redirect the citizen browser to eSignet.
///
/// Mints no code or credential material. Only a short-lived single-use login
/// state (PKCE verifier + nonce + selection) is reserved.
async fn oid4vci_offer_start(
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
    let reserved = preauth.login_states().reserve(
        &login_state,
        LoginState {
            pkce_verifier,
            nonce: nonce.clone(),
            credential_configuration_id: configuration_id,
        },
        preauth.login_state_ttl_seconds(),
    );
    if !reserved {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    let redirect_url = match preauth.authorize_redirect_url(&login_state, &nonce, &pkce_challenge) {
        Ok(url) => url,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    Redirect::to(&redirect_url).into_response()
}

#[derive(Debug, Deserialize)]
struct Oid4vciOfferCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /oid4vci/offer/callback` (public): consume the login state, exchange the
/// eSignet code via `private_key_jwt`, validate the `id_token`, mint a single-use
/// `pre-authorized_code`, and render the offer page.
async fn oid4vci_offer_callback(
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
            SelfAttestationDenialCode::InvalidToken,
            Oid4vciWireError::InvalidRequest,
        )
        .await;
    };
    // Single-use consume: unknown/expired/replayed state is the CSRF/replay
    // guard. A missing state yields no code.
    let Some(stored) = preauth.login_states().consume(login_state) else {
        return preauth_denied(
            &preauth,
            path,
            "GET",
            None,
            SelfAttestationDenialCode::InvalidToken,
            Oid4vciWireError::InvalidRequest,
        )
        .await;
    };
    let subject_binding_claim = state.self_attestation.subject_binding.token_claim.clone();
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
                SelfAttestationDenialCode::InvalidToken,
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
    let code_claims = PreAuthorizedCodeClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: jti.clone(),
        credential_configuration_id: stored.credential_configuration_id.clone(),
        subject: bound_subject,
        iat: now,
        exp: now + preauth.pre_authorized_code_ttl_seconds() as i64,
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
        if !preauth.tx_code_sessions().reserve(
            &jti,
            crate::preauth_state::TxCodeSession { pin: pin.clone() },
            preauth.pre_authorized_code_ttl_seconds(),
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
async fn oid4vci_token(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
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
    let client_address = token_client_address(&headers, connect_info.as_deref());
    let request = match parse_token_request(&headers, &body) {
        Ok(request) => request,
        Err(error) => return token_error_response(error),
    };
    if request.grant_type != PRE_AUTHORIZED_CODE_GRANT_TYPE {
        return token_error_response(TokenWireError::UnsupportedGrantType);
    }
    let Some(code) = request
        .pre_authorized_code
        .as_deref()
        .filter(|c| !c.is_empty())
    else {
        return token_error_response(TokenWireError::InvalidRequest);
    };
    // Throttle random-code floods per client address (reuse the existing
    // invalid-token-per-address limiter bucket).
    if check_token_client_address_rate_limit(&state, &client_address).is_err() {
        return token_error_response(TokenWireError::SlowDown);
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let verified = match verify_notary_token(
        code,
        preauth.access_token_public_jwk(),
        PRE_AUTHORIZED_CODE_JWT_TYP,
        preauth.notary_issuer(),
        &[],
        now,
    ) {
        Ok(verified) => verified,
        Err(_) => {
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
    if preauth.tx_code_required() {
        // Cap wrong-PIN attempts per code (brute-force guard). A locked code
        // (attempts over the cap) is rejected before the PIN compare.
        if check_tx_code_attempt(&state, code).is_err() {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                configuration_id.as_deref(),
                TokenWireError::SlowDown,
            )
            .await;
        }
        let tx_code = request.tx_code.as_deref().unwrap_or("");
        // Read (do not consume) the per-code PIN by jti. Missing means the code was
        // already redeemed or expired. A wrong PIN does not consume the code, so it
        // can be retried until the rate cap locks it.
        let session_pin = preauth
            .tx_code_sessions()
            .peek(&jti)
            .map(|session| session.pin);
        let pin_ok = session_pin.as_deref().is_some_and(|pin| {
            !tx_code.is_empty() && constant_time_eq(tx_code.as_bytes(), pin.as_bytes())
        });
        if !pin_ok {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                configuration_id.as_deref(),
                TokenWireError::InvalidGrant,
            )
            .await;
        }
    }
    // Single-use: claim the code's jti in the replay store now that the PIN
    // matched. A second redemption fails AlreadySeen.
    if consume_pre_authorized_code_jti(&state, &jti, now)
        .await
        .is_err()
    {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    }
    // The code is now spent; drop its PIN session. This is a safe no-op when
    // optional tx_code mode did not create one.
    preauth.tx_code_sessions().remove(&jti);
    let Some(bound_subject) = bound_subject_from_code(&verified, &state) else {
        return token_error_response(TokenWireError::InvalidGrant);
    };
    let Some(configuration_id) = configuration_id else {
        return token_error_response(TokenWireError::InvalidGrant);
    };
    let access_token_claims = AccessTokenClaims {
        issuer: preauth.notary_issuer().to_string(),
        audiences: preauth.notary_audiences().to_vec(),
        token_type: "Bearer".to_string(),
        credential_configuration_id: configuration_id.clone(),
        subject: bound_subject,
        iat: now,
        exp: now + preauth.access_token_ttl_seconds() as i64,
    };
    let access_token = match mint_access_token(
        preauth.access_token_signer(),
        preauth.access_token_typ(),
        &access_token_claims,
    )
    .await
    {
        Ok(token) => token,
        Err(_) => return token_error_response(TokenWireError::ServerError),
    };
    let c_nonce = match issue_c_nonce(&state, &configuration_id).await {
        Some(c_nonce) => c_nonce,
        None => return token_error_response(TokenWireError::ServerError),
    };
    let audit = pre_auth_audit_event(
        "POST",
        path,
        StatusCode::OK.as_u16(),
        "preauth_token_issued",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                &configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return token_error_response(TokenWireError::ServerError);
    }
    state
        .metrics
        .record_credential("openid4vci_preauth", "token_issued");
    Json(Oid4vciTokenResponse {
        access_token: access_token.compact,
        token_type: "Bearer".to_string(),
        expires_in: Some(preauth.access_token_ttl_seconds()),
        c_nonce: Some(c_nonce),
        c_nonce_expires_in: state
            .oid4vci
            .nonce
            .enabled
            .then_some(state.oid4vci.nonce.ttl_seconds),
    })
    .into_response()
}

/// The pre-auth runtime, present only when the flow is enabled and configured.
fn preauth_runtime(state: &RegistryNotaryApiState) -> Option<Arc<PreAuthRuntime>> {
    if !state.oid4vci.enabled {
        return None;
    }
    state.preauth.clone()
}

/// Validate a requested `credential_configuration_id` against the configured
/// set. Returns the canonical id, or `Err(())` if unknown.
fn oid4vci_validated_configuration_id(
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
fn single_credential_configuration_id(config: &Oid4vciConfig) -> Option<String> {
    let mut ids = config.credential_configurations.keys();
    let first = ids.next()?;
    if ids.next().is_some() {
        return None;
    }
    Some(first.clone())
}

/// Claim the pre-authorized code's `jti` exactly once. The first redemption
/// inserts the jti; any later redemption of the same code fails `AlreadySeen`.
/// This is the single-use guarantee for the code.
async fn consume_pre_authorized_code_jti(
    state: &RegistryNotaryApiState,
    jti: &str,
    now: i64,
) -> Result<(), ()> {
    let scope = pre_authorized_code_replay_scope(state)?;
    let key = ReplayKey::new(jti).map_err(|_| ())?;
    // Bound the single-use marker's storage to roughly the code lifetime.
    let expires_at = OffsetDateTime::from_unix_timestamp(now).map_err(|_| ())?
        + time::Duration::seconds(
            state
                .preauth
                .as_ref()
                .map(|preauth| preauth.pre_authorized_code_ttl_seconds())
                .unwrap_or(300) as i64,
        );
    require_replay_insert(state.replay.store().as_ref(), &scope, &key, expires_at)
        .await
        .map_err(|_| ())
}

fn pre_authorized_code_replay_scope(state: &RegistryNotaryApiState) -> Result<ReplayScope, ()> {
    ReplayScope::new([
        ("tenant".to_string(), state.evidence.service_id.clone()),
        ("kind".to_string(), "oid4vci-preauth-code".to_string()),
        (
            "issuer".to_string(),
            state.oid4vci.credential_issuer.clone(),
        ),
    ])
    .map_err(|_| ())
}

/// Build the `openid-credential-offer://` request URI carrying the offer JSON.
fn offer_request_uri(offer: &CredentialOffer) -> Result<String, ()> {
    let json = serde_json::to_string(offer).map_err(|_| ())?;
    let encoded = url_percent_encode(&json);
    Ok(format!(
        "openid-credential-offer://?credential_offer={encoded}"
    ))
}

/// Percent-encode a value for a query string (RFC 3986 unreserved set kept).
fn url_percent_encode(value: &str) -> String {
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
fn offer_page_html(offer_uri: &str, pin: Option<&str>) -> String {
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

fn html_escape(value: &str) -> String {
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
fn bound_subject_from_code(
    verified: &registry_notary_core::tokens::VerifiedNotaryToken,
    state: &RegistryNotaryApiState,
) -> Option<BoundSubject> {
    let subject_binding_claim = state.self_attestation.subject_binding.token_claim.clone();
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
async fn issue_c_nonce(state: &RegistryNotaryApiState, configuration_id: &str) -> Option<String> {
    if !state.oid4vci.nonce.enabled {
        // The credential endpoint requires a c_nonce; without the nonce
        // endpoint enabled there is nothing to reserve, so the value is unused.
        return generate_nonce().ok();
    }
    let nonce = generate_nonce().ok()?;
    let key = state
        .self_attestation_rate_keys
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

/// Derive a per-client identifier for the token endpoint's flood throttle.
///
/// Prefers the proxy-set forwarding headers (the notary runs behind a reverse
/// proxy), then the connection peer address, then a constant fallback so the
/// bucket still functions when no client address is available.
fn token_client_address(
    headers: &HeaderMap,
    connect_info: Option<&axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> String {
    if let Some(value) = forwarded_header_value(headers, "x-forwarded-for") {
        return value.to_string();
    }
    if let Some(value) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return value.to_string();
    }
    connect_info
        .map(|axum::extract::ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown-client-address".to_string())
}

/// Per-client-address throttle so random-code floods are bounded. Reuses the
/// existing invalid-token-per-address limiter bucket. This is a check-only gate
/// (availability); the bucket is consumed only on an invalid attempt, matching
/// the auth middleware's check-before / consume-after pattern.
fn check_token_client_address_rate_limit(
    state: &RegistryNotaryApiState,
    client_address: &str,
) -> Result<(), SelfAttestationRateLimitError> {
    let hashed = state
        .self_attestation_rate_keys
        .client_address(client_address)?;
    state
        .self_attestation_rate_limiter
        .check_invalid_token_for_client_address_available(&hashed)
}

/// Record one `tx_code` attempt against the hashed pre-authorized code. After
/// the configured cap the code is locked.
fn check_tx_code_attempt(
    state: &RegistryNotaryApiState,
    pre_authorized_code: &str,
) -> Result<(), SelfAttestationRateLimitError> {
    let hashed = state
        .self_attestation_rate_keys
        .pre_authorized_code(pre_authorized_code)?;
    state
        .self_attestation_rate_limiter
        .check_tx_code_attempt(&hashed)
}

/// Emit a denial audit event for a public pre-auth endpoint and return the
/// matching OID4VCI error response.
async fn preauth_denied(
    preauth: &PreAuthRuntime,
    path: &str,
    method: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SelfAttestationDenialCode,
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

async fn preauth_server_error(
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
async fn token_error_after_invalid_attempt(
    state: &RegistryNotaryApiState,
    preauth: &PreAuthRuntime,
    path: &str,
    client_address: &str,
    credential_configuration_id: Option<&str>,
    error: TokenWireError,
) -> Response {
    if let Ok(hashed) = state
        .self_attestation_rate_keys
        .client_address(client_address)
    {
        let _ = state
            .self_attestation_rate_limiter
            .check_invalid_token_for_client_address(&hashed);
    }
    let response = token_error_response(error);
    let audit = pre_auth_audit_event(
        "POST",
        path,
        response.status().as_u16(),
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: credential_configuration_id
                .and_then(|id| registry_notary_core::ConfigMetadata::new(id).ok()),
            denial_code: Some(SelfAttestationDenialCode::InvalidToken),
            ..PreAuthAuditFields::default()
        },
    );
    let _ = preauth.emit_audit(&audit).await;
    response
}

/// OAuth 2.0 token-endpoint errors per RFC 6749 / OID4VCI.
#[derive(Debug, Clone, Copy)]
enum TokenWireError {
    InvalidRequest,
    InvalidGrant,
    UnsupportedGrantType,
    SlowDown,
    ServerError,
}

fn token_error_response(error: TokenWireError) -> Response {
    let (status, code, description) = match error {
        TokenWireError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token request is invalid",
        ),
        TokenWireError::InvalidGrant => (
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "pre-authorized code or tx_code is invalid",
        ),
        TokenWireError::UnsupportedGrantType => (
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only the pre-authorized_code grant is supported",
        ),
        TokenWireError::SlowDown => (
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "too many token requests",
        ),
        TokenWireError::ServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token issuance failed",
        ),
    };
    let mut response = (
        status,
        Json(WireError::new(code, Some(description.to_string()))),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(format!("oid4vci.token.{code}")));
    response
}

/// Parse a `TokenRequest` from a form-encoded or JSON body. A missing/other
/// grant or unparseable body is returned as a clean `invalid_request`, never a
/// deserialize panic.
fn parse_token_request(
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
fn parse_token_form(body: &Bytes) -> Result<Oid4vciTokenRequest, TokenWireError> {
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
fn form_urldecode(value: &str) -> Result<String, TokenWireError> {
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

fn hex_nibble(byte: u8) -> Result<u8, TokenWireError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TokenWireError::InvalidRequest),
    }
}

async fn issuer_jwks(
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
    match state.issuers.public_jwks(evidence) {
        Ok(keys) => Json(json!({ "keys": keys })).into_response(),
        Err(error) => evidence_error_response(error),
    }
}

async fn list_claims(
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
        "data": RegistryNotaryRuntime::list_claims(evidence, state.source.as_ref(), &principal),
    }))
    .into_response()
}

async fn get_claim(
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
        evidence,
        state.source.as_ref(),
        &principal,
        &claim_id,
    ))
}

async fn list_formats(
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

async fn evaluate(
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
    let principal = match classify_self_attestation_principal(&state.self_attestation, &principal) {
        Ok(principal) => principal,
        Err(error) => {
            if let Err(rate_error) = consume_classification_denial_if_keyable(&state, &principal) {
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
            return response;
        }
        if let Err(error) = derive_self_attestation_request_context(
            &state.self_attestation,
            &principal,
            &mut request,
        ) {
            if denial_code_from_error(&error) == Some(SelfAttestationDenialCode::SubjectMismatch) {
                if let Err(rate_error) = consume_subject_mismatch_denial(&state, &principal_hash) {
                    let mut response = evidence_error_response(rate_error.evidence_error());
                    attach_self_attestation_rate_limit_audit(
                        &mut response,
                        "evaluate_rate_limited",
                        &request_claim_ids,
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
                &request_claim_ids,
                denial_code,
                Some(state.self_attestation.subject_binding.token_claim.as_str()),
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
                            &request_claim_ids,
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
                    &request_claim_ids,
                    denial_code,
                    Some(state.self_attestation.subject_binding.token_claim.as_str()),
                );
                return response;
            }
        }
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
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                &audit_request,
                results.first(),
                None,
            ) {
                return evidence_error_response(error);
            }
            response
        }
        Err(error) => {
            let audit_code = error.audit_code();
            let mut response = evidence_error_response(error);
            attach_evidence_audit(
                &mut response,
                "evaluate_denied",
                None,
                &requested_claims,
                None,
            );
            if let Err(error) = attach_evaluate_request_audit(
                &mut response,
                &state.self_attestation_rate_keys,
                &audit_request,
                None,
                Some(audit_code),
            ) {
                return evidence_error_response(error);
            }
            response
        }
    }
}

async fn batch_evaluate(
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
    let runtime = state.runtime();
    let requested_claims = request_claim_ids;
    let requested_subject_count = request.items.len();
    let audit_purposes = resolved_batch_audit_purposes(
        purpose_header(&headers),
        request.purpose.as_deref(),
        &request.items,
    );
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
                &result,
                batch_audit_purposes.as_deref(),
            ) {
                return evidence_error_response(error);
            }
            response
        }
        Err(error) => evidence_error_response(error),
    }
}

async fn render(
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
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    request: Result<Json<CredentialIssueRequest>, JsonRejection>,
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
                .map(|result| result.target_ref.handle.as_str())
        }) {
            Some(subject_ref) => subject_ref,
            None => return evidence_error_response(EvidenceError::InvalidRequest),
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
            return evidence_error_response(match error {
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
            });
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
                protocol: None,
                credential_configuration_id: None,
            },
        ) {
            return evidence_error_response(error);
        }
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
fn earliest_issued_at(results: &[registry_notary_core::ClaimResultView]) -> Option<OffsetDateTime> {
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
    let metadata = CredentialIssuerMetadata::new(
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
    .with_display(oid4vci_issuer_display_metadata(&config.display));
    // When the pre-authorized-code flow is enabled the Notary is its own
    // authorization server for that grant, so issuer metadata advertises its
    // token endpoint. Per OID4VCI, the credential offer's `grants` carries the
    // `urn:ietf:params:oauth:grant-type:pre-authorized_code` advertisement
    // per-offer (see the offer/callback handler); the `token_endpoint` is the
    // metadata signal that the issuer accepts that grant directly. When the
    // flow is disabled there is no token endpoint and metadata is unchanged.
    match (
        config.pre_authorized_code.enabled,
        oid4vci_token_endpoint_url(config),
    ) {
        (true, Some(token_endpoint)) => metadata.with_token_endpoint(token_endpoint),
        _ => metadata,
    }
}

/// The Notary's own OID4VCI token endpoint URL: the credential-issuer base with
/// `oid4vci/token` appended (preserving any configured base subpath). Returns
/// `None` when the configured `credential_issuer` is not a usable absolute URL.
fn oid4vci_token_endpoint_url(config: &Oid4vciConfig) -> Option<String> {
    let base = reqwest::Url::parse(config.credential_issuer.trim()).ok()?;
    registry_platform_httputil::url::append_path_segments(&base, &["oid4vci", "token"])
        .ok()
        .map(|url| url.to_string())
}

fn oid4vci_configuration_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> CredentialConfigurationMetadata {
    let mut metadata = CredentialConfigurationMetadata::sd_jwt_vc(
        configuration.scope.clone(),
        configuration
            .cryptographic_binding_methods_supported
            .clone(),
        configuration.display_name.clone(),
        configuration.vct.clone(),
    );
    metadata.display = vec![oid4vci_credential_display_metadata(configuration)];
    metadata
}

fn oid4vci_type_metadata_document(configuration: &Oid4vciCredentialConfigurationConfig) -> Value {
    let display = oid4vci_credential_type_display_metadata(configuration);
    let mut document = json!({
        "vct": configuration.vct,
        "name": configuration.display_name,
        "display": [display],
        "claims": [
            {
                "path": [configuration.claim_id],
                "display": [
                    {
                        "locale": configuration.display.locale.as_deref().unwrap_or("en-US"),
                        "label": configuration.display_name,
                    }
                ],
                "sd": "always",
            }
        ],
    });
    if let Some(description) = configuration.display.description.as_deref() {
        document["description"] = json!(description);
    }
    document
}

fn oid4vci_issuer_display_metadata(
    displays: &[Oid4vciIssuerDisplayConfig],
) -> Vec<DisplayMetadata> {
    displays
        .iter()
        .map(|display| {
            let mut metadata = DisplayMetadata::new(display.name.clone());
            metadata.locale = display.locale.clone();
            metadata.logo = display.logo.as_ref().map(oid4vci_display_image_metadata);
            metadata
        })
        .collect()
}

fn oid4vci_credential_display_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> DisplayMetadata {
    let mut metadata = DisplayMetadata::new(configuration.display_name.clone());
    metadata.locale = configuration.display.locale.clone();
    metadata.logo = configuration
        .display
        .logo
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata.description = configuration.display.description.clone();
    metadata.background_color = configuration.display.background_color.clone();
    metadata.text_color = configuration.display.text_color.clone();
    metadata.background_image = configuration
        .display
        .background_image
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata.secondary_image = configuration
        .display
        .secondary_image
        .as_ref()
        .map(oid4vci_display_image_metadata);
    metadata
}

fn oid4vci_display_image_metadata(image: &Oid4vciDisplayImageConfig) -> DisplayImageMetadata {
    DisplayImageMetadata {
        uri: image.uri.clone(),
        url: image.url.clone(),
        alt_text: image.alt_text.clone(),
    }
}

fn oid4vci_credential_type_display_metadata(
    configuration: &Oid4vciCredentialConfigurationConfig,
) -> Value {
    let display = oid4vci_credential_display_metadata(configuration);
    let mut value = serde_json::to_value(display).expect("display metadata serializes");
    if value
        .get("locale")
        .and_then(|value| value.as_str())
        .is_none()
    {
        value["locale"] = json!("en-US");
    }
    value
}

fn oid4vci_requested_absolute_url_for_path(
    config: &Oid4vciConfig,
    headers: &HeaderMap,
    uri: &Uri,
    request_path: &str,
) -> Option<String> {
    let (issuer_scheme, issuer_authority, issuer_path) =
        absolute_url_parts(&config.credential_issuer)?;
    let scheme = forwarded_header_value(headers, "x-forwarded-proto")
        .or_else(|| uri.scheme_str())
        .unwrap_or(issuer_scheme)
        .to_lowercase();
    let authority = forwarded_header_value(headers, "x-forwarded-host")
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
        .unwrap_or(issuer_authority)
        .to_lowercase();
    let external_path = oid4vci_external_path(issuer_path, request_path);
    Some(format!("{scheme}://{authority}{external_path}"))
}

fn absolute_url_parts(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest[..authority_end].trim();
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    let path = if rest[authority_end..].starts_with('/') {
        rest[authority_end..]
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
    } else {
        ""
    };
    Some((scheme, authority, path))
}

fn oid4vci_external_path(issuer_path: &str, path: &str) -> String {
    let issuer_path = issuer_path.trim_end_matches('/');
    if issuer_path.is_empty()
        || path.starts_with(&format!("{issuer_path}/"))
        || !path.starts_with("/credentials/")
    {
        path.to_string()
    } else {
        format!("{issuer_path}{path}")
    }
}

fn forwarded_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn oid4vci_nonce_replay_scope(
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

fn self_attestation_bound_subject(
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

fn derive_self_attestation_request_context(
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

fn ensure_optional_entity_matches_subject(
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

fn check_oid4vci_self_attestation_rate_limit(
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

fn generate_nonce() -> Result<String, EvidenceError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

#[derive(Debug)]
struct HolderProofBinding {
    scope: ReplayScope,
    key: ReplayKey,
    expires_at: OffsetDateTime,
}

fn validate_holder_request(
    profile: &CredentialProfileConfig,
    profile_id: &str,
    request: &CredentialIssueRequest,
    evaluation: &registry_notary_core::StoredEvaluation,
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
    evaluation: &registry_notary_core::StoredEvaluation,
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
    let scope = ReplayScope::holder_proof_jwt(service_id, service_id, profile_id, holder_id)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    let key = ReplayKey::new(claims.jti).map_err(|_| EvidenceError::HolderProofRequired)?;
    Ok(HolderProofBinding {
        scope,
        key,
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
    evaluation: &registry_notary_core::StoredEvaluation,
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

fn runtime_principal_for_stored_evaluation(
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

fn consume_classification_denial_if_keyable(
    state: &RegistryNotaryApiState,
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
    verified_claims: &registry_notary_core::BoundedVerifiedClaims,
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
    claims: &registry_notary_core::BoundedVerifiedClaims,
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
    let request_claim_ids = claim_ids(&request.claims);
    if request.claims.len() != 1
        || !request.claims.iter().all(|claim_id| {
            config
                .allowed_claims
                .iter()
                .any(|allowed| allowed == &claim_id.id)
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

    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref())
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
        let claim = find_requested_claim(evidence, claim_id)
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
    let Some(target_subject) = request.target_subject() else {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    };
    if target_subject.id.trim().is_empty() {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    if target_subject.id_type.as_deref() != Some(subject_binding.id_type.as_str()) {
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
    if bound_subject != target_subject.id {
        return Err(self_attestation_denied(
            SelfAttestationDenialCode::SubjectMismatch,
        ));
    }
    Ok(())
}

fn find_requested_claim<'a>(
    evidence: &'a EvidenceConfig,
    claim: &ClaimRef,
) -> Result<&'a registry_notary_core::ClaimDefinition, EvidenceError> {
    match claim.version.as_deref() {
        Some(version) => crate::runtime::find_claim_version(evidence, &claim.id, version),
        None => crate::find_claim(evidence, &claim.id),
    }
}

fn prepare_self_attestation_evaluate(
    state: &RegistryNotaryApiState,
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
    let claim = find_requested_claim(evidence, claim_id).map_err(|_| {
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
    let request_claim_ids = claim_ids(&request.claims);
    let disclosure =
        selected_disclosure(evidence, &request_claim_ids, request.disclosure.as_deref()).map_err(
            |_| EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DisclosureDenied,
            },
        )?;
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
    let requested_claims_hash =
        Hashed::<ClaimSet>::from_hash(evidence_claim_hash(&request_claim_ids));
    let policy_hash = self_attestation_policy_hash(
        evidence,
        &state.self_attestation,
        &request_claim_ids,
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
        claim_id: BoundedClaimId::new(claim_id.id.clone())
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
    state: &RegistryNotaryApiState,
    principal_hash: &Hashed<registry_notary_core::PrincipalIdentifier>,
) -> Result<(), SelfAttestationRateLimitError> {
    state
        .self_attestation_rate_limiter
        .consume_subject_mismatch_denial_only(principal_hash)
}

#[allow(clippy::too_many_arguments)]
fn require_self_attestation_stored_access(
    state: &RegistryNotaryApiState,
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    evaluation: &registry_notary_core::StoredEvaluation,
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
    registry_notary_core::DisclosureProfile::parse(disclosure)
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
    attach_evidence_audit_with_purposes(
        response,
        decision,
        verification_id,
        claim_ids,
        row_count,
        None,
    );
}

fn attach_evidence_audit_with_purposes(
    response: &mut Response,
    decision: &str,
    verification_id: Option<String>,
    claim_ids: &[String],
    row_count: Option<u64>,
    purposes: Option<Vec<String>>,
) {
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id,
        verification_decision: Some(decision.to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes,
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
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
    });
}

fn attach_evaluate_request_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    request: &EvaluateRequest,
    result: Option<&ClaimResultView>,
    matching_error_code: Option<&str>,
) -> Result<(), EvidenceError> {
    let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() else {
        return Ok(());
    };
    audit.target_type = result
        .map(|result| result.target_ref.entity_type.as_str())
        .or_else(|| {
            request
                .target
                .as_ref()
                .map(|target| target.entity_type.as_str())
        })
        .filter(|entity_type| !entity_type.is_empty())
        .map(str::to_string);
    audit.target_ref_hash = match result {
        Some(result) => Some(hash_audit_handle(
            keys,
            "target",
            result.target_ref.entity_type.as_str(),
            request.purpose.as_deref(),
            &result.target_ref.handle,
        )?),
        None => match request.target.as_ref() {
            Some(target) => {
                hash_audit_matching_attempt(keys, "target", request.purpose.as_deref(), target)?
            }
            None => None,
        },
    };
    if let Some(requester_ref) = result.and_then(|result| result.requester_ref.as_ref()) {
        audit.requester_type = Some(requester_ref.entity_type.clone());
        audit.requester_ref_hash = Some(hash_audit_handle(
            keys,
            "requester",
            requester_ref.entity_type.as_str(),
            request.purpose.as_deref(),
            &requester_ref.handle,
        )?);
    } else if let Some(requester) = request.requester.as_ref() {
        audit.requester_type = Some(requester.entity_type.clone());
        audit.requester_ref_hash =
            hash_audit_matching_attempt(keys, "requester", request.purpose.as_deref(), requester)?;
    }
    if let Some(matching) = result.and_then(|result| result.matching.as_ref()) {
        audit.matching_policy_id = Some(matching.policy_id.clone());
        audit.matching_method = Some(matching.method.clone());
        audit.matching_outcome = Some("matched".to_string());
    } else if let Some(error_code) = matching_error_code.filter(|code| is_matching_audit_code(code))
    {
        audit.matching_outcome = Some("error".to_string());
        audit.matching_error_code = Some(error_code.to_string());
    }
    Ok(())
}

fn attach_batch_evaluate_response_audit(
    response: &mut Response,
    keys: &SelfAttestationRateLimitKeys,
    result: &registry_notary_core::BatchEvaluateResponse,
    audit_purposes: Option<&[String]>,
) -> Result<(), EvidenceError> {
    let Some(audit) = response.extensions_mut().get_mut::<EvidenceAuditContext>() else {
        return Ok(());
    };
    let mut batch_items = Vec::with_capacity(result.items.len());
    for item in &result.items {
        let purpose_scope = audit_purposes
            .and_then(|purposes| purposes.get(item.input_index))
            .map(String::as_str);
        let matching_error_code = item
            .errors
            .first()
            .and_then(|error| error.audit_code.as_deref().or(Some(error.code.as_str())))
            .filter(|code| is_matching_audit_code(code))
            .map(str::to_string);
        let matching = item.matching.as_ref();
        batch_items.push(EvidenceBatchItemAuditEvent {
            input_index: item.input_index,
            target_type: Some(item.target_ref.entity_type.clone())
                .filter(|entity_type| !entity_type.is_empty()),
            target_ref_hash: if item.errors.is_empty() {
                Some(hash_audit_handle(
                    keys,
                    "target",
                    item.target_ref.entity_type.as_str(),
                    purpose_scope,
                    &item.target_ref.handle,
                )?)
            } else {
                None
            },
            requester_type: item
                .requester_ref
                .as_ref()
                .map(|requester| requester.entity_type.clone()),
            requester_ref_hash: item
                .requester_ref
                .as_ref()
                .filter(|_| item.errors.is_empty())
                .map(|requester| {
                    hash_audit_handle(
                        keys,
                        "requester",
                        requester.entity_type.as_str(),
                        purpose_scope,
                        &requester.handle,
                    )
                })
                .transpose()?,
            matching_policy_id: matching.map(|matching| matching.policy_id.clone()),
            matching_method: matching.map(|matching| matching.method.clone()),
            matching_outcome: if item.errors.is_empty() {
                Some("matched".to_string())
            } else if matching_error_code.is_some() {
                Some("error".to_string())
            } else {
                None
            },
            matching_error_code,
        });
    }
    audit.batch_items = Some(batch_items);
    Ok(())
}

fn hash_audit_handle(
    keys: &SelfAttestationRateLimitKeys,
    role: &str,
    entity_type: &str,
    purpose_scope: Option<&str>,
    handle: &str,
) -> Result<Hashed<EvidenceEntityReference>, EvidenceError> {
    let input = canonical_audit_handle_input(role, entity_type, purpose_scope, handle)?;
    keys.audit_pseudonym_ref("matched-reference-v1", &input)
        .map(|hash| Hashed::from_hash(hash.as_str().to_string()))
        .map_err(|error| error.evidence_error())
}

fn hash_audit_matching_attempt(
    _keys: &SelfAttestationRateLimitKeys,
    role: &str,
    purpose_scope: Option<&str>,
    entity: &EvidenceEntity,
) -> Result<Option<Hashed<EvidenceEntityReference>>, EvidenceError> {
    let _ = canonical_audit_identifier_input(role, purpose_scope, entity)?;
    Ok(None)
}

fn canonical_audit_handle_input(
    role: &str,
    entity_type: &str,
    purpose_scope: Option<&str>,
    handle: &str,
) -> Result<String, EvidenceError> {
    serde_json::to_string(&json!({
        "class": "matched-reference-v1",
        "version": 1,
        "role": role,
        "entity_type": entity_type,
        "purpose_scope": purpose_scope.unwrap_or(""),
        "handle": handle,
    }))
    .map_err(|_| EvidenceError::InvalidRequest)
}

fn canonical_audit_identifier_input(
    role: &str,
    purpose_scope: Option<&str>,
    entity: &EvidenceEntity,
) -> Result<Option<String>, EvidenceError> {
    let mut identifiers = entity
        .identifiers
        .iter()
        .filter(|identifier| !identifier.value.trim().is_empty())
        .map(|identifier| {
            let mut canonical = BTreeMap::new();
            canonical.insert("country", identifier.country.as_deref().unwrap_or(""));
            canonical.insert("issuer", identifier.issuer.as_deref().unwrap_or(""));
            canonical.insert("scheme", identifier.scheme.as_str());
            canonical.insert("value", identifier.value.as_str());
            canonical
        })
        .collect::<Vec<_>>();
    identifiers.sort_by(|left, right| {
        (
            left["scheme"],
            left["issuer"],
            left["country"],
            left["value"],
        )
            .cmp(&(
                right["scheme"],
                right["issuer"],
                right["country"],
                right["value"],
            ))
    });
    identifiers.dedup();
    if identifiers.is_empty() && entity.id.as_deref().is_none_or(str::is_empty) {
        return Ok(None);
    }
    serde_json::to_string(&json!({
        "class": "matching-attempt-v1",
        "version": 1,
        "role": role,
        "entity_type": entity.entity_type,
        "purpose_scope": purpose_scope.unwrap_or(""),
        "id": entity.id.as_deref().unwrap_or(""),
        "identifiers": identifiers,
    }))
    .map(Some)
    .map_err(|_| EvidenceError::InvalidRequest)
}

fn is_matching_audit_code(code: &str) -> bool {
    code.starts_with("target.")
        || code.starts_with("requester.")
        || code.starts_with("relationship.")
        || matches!(code, "purpose.not_allowed" | "evidence.not_available")
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
    keys: &SelfAttestationRateLimitKeys,
    evaluation_id: &str,
    claim_ids: &[String],
    results: &[ClaimResultView],
    row_count: u64,
    details: SelfAttestationCredentialAuditDetails<'_>,
) -> Result<(), EvidenceError> {
    let first_result = results.first();
    let target_type = first_result
        .map(|result| result.target_ref.entity_type.clone())
        .filter(|entity_type| !entity_type.is_empty());
    let target_ref_hash = first_result
        .map(|result| {
            hash_audit_handle(
                keys,
                "target",
                result.target_ref.entity_type.as_str(),
                None,
                &result.target_ref.handle,
            )
        })
        .transpose()?;
    let requester_type = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| requester.entity_type.clone());
    let requester_ref_hash = first_result
        .and_then(|result| result.requester_ref.as_ref())
        .map(|requester| {
            hash_audit_handle(
                keys,
                "requester",
                requester.entity_type.as_str(),
                None,
                &requester.handle,
            )
        })
        .transpose()?;
    let matching = first_result.and_then(|result| result.matching.as_ref());
    response.extensions_mut().insert(EvidenceAuditContext {
        verification_id: Some(evaluation_id.to_string()),
        verification_decision: Some("credential_issued".to_string()),
        claim_hash: (!claim_ids.is_empty()).then(|| evidence_claim_hash(claim_ids)),
        purposes: None,
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
        target_type,
        target_ref_hash,
        requester_type,
        requester_ref_hash,
        matching_policy_id: matching.map(|matching| matching.policy_id.clone()),
        matching_method: matching.map(|matching| matching.method.clone()),
        matching_outcome: matching.map(|_| "matched".to_string()),
        matching_error_code: None,
        batch_items: None,
    });
    Ok(())
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
        purposes: None,
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
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
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
        purposes: None,
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
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
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
        purposes: None,
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
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
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
        purposes: None,
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
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        batch_items: None,
    });
}

pub(crate) fn evidence_error_response(error: EvidenceError) -> Response {
    let request_id = crate::standalone::current_request_correlation_id();
    evidence_error_response_with_request_id(error, request_id.as_ref())
}

pub(crate) fn evidence_error_response_with_request_id(
    error: EvidenceError,
    request_id: Option<&BoundedCorrelationId>,
) -> Response {
    let code = error.code().to_string();
    let audit_code = error.audit_code().to_string();
    let status = evidence_status(&error);
    let mut body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": evidence_title(&error),
        "status": status.as_u16(),
        "detail": evidence_detail(&error),
        "code": code,
    });
    if let Some(request_id) = request_id {
        body["request_id"] = json!(request_id.as_str());
    }
    let mut response = (status, Json(body)).into_response();
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(audit_code));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let Some(request_id) = request_id {
        if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
            response.headers_mut().insert("x-request-id", value);
        }
    }
    response
}

pub(crate) fn evidence_status(error: &EvidenceError) -> StatusCode {
    match error {
        EvidenceError::ServerDisabled
        | EvidenceError::OperationUnsupported
        | EvidenceError::CredentialIssuerNotConfigured => StatusCode::NOT_IMPLEMENTED,
        EvidenceError::FormatUnsupported => StatusCode::NOT_ACCEPTABLE,
        EvidenceError::ClaimNotFound
        | EvidenceError::ClaimVersionNotFound
        | EvidenceError::SourceNotFound
        | EvidenceError::RequesterNotFound
        | EvidenceError::EvaluationNotFound => StatusCode::NOT_FOUND,
        EvidenceError::MissingCredential => StatusCode::UNAUTHORIZED,
        EvidenceError::MultipleCredentials => StatusCode::BAD_REQUEST,
        EvidenceError::SelfAttestationInvalidToken => StatusCode::UNAUTHORIZED,
        EvidenceError::InvalidRequest
        | EvidenceError::TargetIdentifierMissing
        | EvidenceError::TargetAttributesInsufficient
        | EvidenceError::RequesterIdentifierMissing
        | EvidenceError::RequesterAttributesInsufficient
        | EvidenceError::RelationshipAttributesInsufficient
        | EvidenceError::ProfileUnsupported
        | EvidenceError::HolderProofRequired
        | EvidenceError::PurposeRequired => StatusCode::BAD_REQUEST,
        EvidenceError::DisclosureNotAllowed
        | EvidenceError::EvaluationBindingMismatch
        | EvidenceError::PurposeNotAllowed
        | EvidenceError::RequesterReauthenticationRequired
        | EvidenceError::RequesterMatchingPolicyRejected
        | EvidenceError::TargetMatchingPolicyRejected
        | EvidenceError::RelationshipNotEstablished
        | EvidenceError::RelationshipPolicyRejected
        | EvidenceError::ScopeDenied { .. }
        | EvidenceError::SelfAttestationDenied { .. }
        | EvidenceError::SelfAttestationAssuranceDenied => StatusCode::FORBIDDEN,
        EvidenceError::SourceAmbiguous
        | EvidenceError::RequesterMatchAmbiguous
        | EvidenceError::RelationshipMatchAmbiguous
        | EvidenceError::TargetNotInValidState
        | EvidenceError::TargetMatchLowConfidence
        | EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. }
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
        EvidenceError::ClaimVersionNotFound => "Claim version not found",
        EvidenceError::OperationUnsupported => "Claim operation unsupported",
        EvidenceError::InvalidRequest => "Invalid evidence request",
        EvidenceError::DisclosureNotAllowed => "Disclosure not allowed",
        EvidenceError::SourceNotFound => "Target not found",
        EvidenceError::SourceAmbiguous => "Target match ambiguous",
        EvidenceError::TargetIdentifierMissing => "Target identifier missing",
        EvidenceError::TargetAttributesInsufficient => "Target attributes insufficient",
        EvidenceError::TargetMatchingPolicyRejected => "Target matching policy rejected",
        EvidenceError::TargetNotInValidState => "Target not in valid state",
        EvidenceError::TargetMatchLowConfidence => "Target match confidence too low",
        EvidenceError::RequesterNotFound => "Requester not found",
        EvidenceError::RequesterMatchAmbiguous => "Requester match ambiguous",
        EvidenceError::RequesterIdentifierMissing => "Requester identifier missing",
        EvidenceError::RequesterAttributesInsufficient => "Requester attributes insufficient",
        EvidenceError::RequesterMatchingPolicyRejected => "Requester matching policy rejected",
        EvidenceError::RequesterReauthenticationRequired => "Requester reauthentication required",
        EvidenceError::RelationshipNotEstablished => "Relationship not established",
        EvidenceError::RelationshipMatchAmbiguous => "Relationship match ambiguous",
        EvidenceError::RelationshipAttributesInsufficient => "Relationship attributes insufficient",
        EvidenceError::RelationshipPolicyRejected => "Relationship policy rejected",
        EvidenceError::PurposeNotAllowed => "Purpose not allowed",
        EvidenceError::ProfileUnsupported => "Profile unsupported",
        EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. } => "Evidence not available",
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
        EvidenceError::MultipleCredentials => "Multiple credentials",
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
        EvidenceError::ClaimVersionNotFound => "the requested claim version is not available",
        EvidenceError::OperationUnsupported => "the requested operation is not enabled",
        EvidenceError::InvalidRequest => "the evidence request is invalid",
        EvidenceError::DisclosureNotAllowed => "the requested disclosure profile is not allowed",
        EvidenceError::SourceNotFound => "the target could not be uniquely matched",
        EvidenceError::SourceAmbiguous => "the target match is ambiguous",
        EvidenceError::TargetIdentifierMissing => {
            "a required target identifier is missing for the configured matching policy"
        }
        EvidenceError::TargetAttributesInsufficient => {
            "the target data is insufficient for the configured matching policy"
        }
        EvidenceError::TargetMatchingPolicyRejected => {
            "the target context is rejected by the configured matching policy"
        }
        EvidenceError::TargetNotInValidState => "the target is not in a valid state",
        EvidenceError::TargetMatchLowConfidence => {
            "the target match confidence is below the configured threshold"
        }
        EvidenceError::RequesterNotFound => "the requester could not be uniquely matched",
        EvidenceError::RequesterMatchAmbiguous => "the requester match is ambiguous",
        EvidenceError::RequesterIdentifierMissing => {
            "a required requester identifier is missing for the configured matching policy"
        }
        EvidenceError::RequesterAttributesInsufficient => {
            "the requester data is insufficient for the configured matching policy"
        }
        EvidenceError::RequesterMatchingPolicyRejected => {
            "the requester context is rejected by the configured matching policy"
        }
        EvidenceError::RequesterReauthenticationRequired => {
            "stronger requester authentication is required"
        }
        EvidenceError::RelationshipNotEstablished => {
            "the required requester-target relationship is missing"
        }
        EvidenceError::RelationshipMatchAmbiguous => {
            "the requester-target relationship match is ambiguous"
        }
        EvidenceError::RelationshipAttributesInsufficient => {
            "the relationship data is insufficient for the configured matching policy"
        }
        EvidenceError::RelationshipPolicyRejected => {
            "the requester-target relationship is not allowed"
        }
        EvidenceError::PurposeNotAllowed => "the declared purpose is not allowed",
        EvidenceError::ProfileUnsupported => "the requested profile is not supported",
        EvidenceError::EvidenceNotAvailable
        | EvidenceError::MatchingEvidenceNotAvailable { .. } => "the evidence is not available",
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
        EvidenceError::MultipleCredentials => "provide exactly one authentication credential",
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
    let supported = RegistryNotaryRuntime::list_formats(evidence)
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

fn parse_json_body<T>(request: Result<Json<T>, JsonRejection>) -> Result<T, EvidenceError> {
    request
        .map(|Json(request)| request)
        .map_err(|_| EvidenceError::InvalidRequest)
}

fn resolved_batch_audit_purposes(
    header_purpose: Option<&str>,
    body_purpose: Option<&str>,
    subjects: &[BatchEvaluateItemRequest],
) -> Option<Vec<String>> {
    let default = match (header_purpose, body_purpose) {
        (Some(header), Some(body)) if header != body => return None,
        (Some(header), _) if !header.trim().is_empty() => Some(header),
        (_, Some(body)) if !body.trim().is_empty() => Some(body),
        (Some(_), _) | (_, Some(_)) => return None,
        _ => None,
    };
    subjects
        .iter()
        .map(|subject| match subject.purpose.as_deref() {
            Some(purpose) if !purpose.trim().is_empty() => Some(purpose.to_string()),
            Some(_) => None,
            None => default.map(str::to_string),
        })
        .collect()
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
}

fn has_idempotency_key(headers: &HeaderMap) -> bool {
    headers.contains_key(IDEMPOTENCY_KEY_HEADER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_notary_core::{
        BoundedVerifiedClaims, CredentialStatusConfig, CredentialStatusRedisConfig,
        SourceBindingConfig, SubjectRequest, VerifiedClaimName, VerifiedClaimValue,
        CREDENTIAL_STATUS_STORAGE_REDIS,
    };
    use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
    use registry_platform_replay::ReplayInsertOutcome;
    use registry_platform_testing::{assert_json_absent_strings, sign_openid4vci_proof_jwt};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    // Ed25519 keypair: `d` is the seed, `x` is the corresponding public key,
    // both base64url (no padding). Identical to the key in
    // registry-notary-core::sd_jwt tests so behavior is consistent.
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
                "allowed_audiences": ["registry-notary-citizen"]
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
            "display": [{
                "name": "Civil Registry Notary",
                "locale": "en-US",
                "logo": {
                    "uri": "https://issuer.example/assets/notary-logo.png",
                    "alt_text": "Civil Registry Notary logo"
                }
            }],
            "credential_configurations": {
                "person_is_alive_sd_jwt": {
                    "claim_id": "person-is-alive",
                    "credential_profile": "civil_status_sd_jwt",
                    "format": "dc+sd-jwt",
                    "scope": "person_is_alive",
                    "vct": "https://issuer.example/credentials/civil-status",
                    "display_name": "Person is alive",
                    "display": {
                        "locale": "en-US",
                        "description": "Proof that the civil registry currently records this person as alive.",
                        "background_color": "#0057B8",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://issuer.example/assets/person-is-alive.png",
                            "alt_text": "Person is alive credential logo"
                        }
                    }
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
        assert_eq!(metadata["display"][0]["name"], "Civil Registry Notary");
        assert_eq!(
            metadata["display"][0]["logo"]["uri"],
            "https://issuer.example/assets/notary-logo.png"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
                ["description"],
            "Proof that the civil registry currently records this person as alive."
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
                ["background_color"],
            "#0057B8"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
                ["logo"]["url"],
            "https://issuer.example/assets/person-is-alive.png"
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

    #[test]
    fn oid4vci_type_metadata_defaults_display_locale_when_unconfigured() {
        let mut oid4vci = oid4vci_config();
        let configuration = oid4vci
            .credential_configurations
            .get_mut("person_is_alive_sd_jwt")
            .expect("configuration exists");
        configuration.display.locale = None;

        let metadata = oid4vci_type_metadata_document(configuration);

        assert_eq!(metadata["display"][0]["locale"], "en-US");
        assert_eq!(metadata["claims"][0]["display"][0]["locale"], "en-US");
    }

    #[test]
    fn oid4vci_metadata_advertises_token_endpoint_only_when_preauth_enabled() {
        // Pre-auth disabled (the default): no token endpoint is advertised, so a
        // wallet sees an authorization_code-only issuer.
        let disabled = oid4vci_config();
        assert!(!disabled.pre_authorized_code.enabled);
        let disabled_metadata =
            serde_json::to_value(oid4vci_metadata(&disabled)).expect("metadata serializes");
        assert!(
            disabled_metadata.get("token_endpoint").is_none(),
            "disabled pre-auth must not advertise a token endpoint"
        );

        // Pre-auth enabled: the Notary's own token endpoint is advertised,
        // derived from the credential-issuer base like the credential endpoint.
        let mut enabled = oid4vci_config();
        enabled.pre_authorized_code.enabled = true;
        let enabled_metadata =
            serde_json::to_value(oid4vci_metadata(&enabled)).expect("metadata serializes");
        assert_eq!(
            enabled_metadata["token_endpoint"],
            json!("http://127.0.0.1:4325/oid4vci/token"),
            "enabled pre-auth advertises the Notary token endpoint"
        );
        // The credential-configuration metadata is otherwise unchanged: the
        // pre-authorized-code grant is advertised per-offer in `grants`, not on
        // the credential configuration.
        assert_eq!(
            enabled_metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
                ["scope"],
            json!("person_is_alive")
        );
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

    #[cfg(feature = "registry-notary-cel")]
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
                "signing_key": "issuer-key",
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
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::new(evidence),
                Arc::new(self_attestation),
                Arc::new(oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(StaticIssuerResolver),
            ),
        );
        let missing_nonce = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            None,
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer),
                },
            }),
        )
        .await;
        assert_eq!(missing_nonce.status(), StatusCode::BAD_REQUEST);
        let missing_nonce_body = axum::body::to_bytes(missing_nonce.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let missing_nonce_body: Value =
            serde_json::from_slice(&missing_nonce_body).expect("error body parses");
        assert_eq!(missing_nonce_body["error"], "invalid_proof");
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        let proof_without_nonce =
            sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer);
        let missing_validated_nonce = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Some(Extension(validated_oid4vci_proof(
                &state,
                &proof_without_nonce,
                None,
            ))),
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: proof_without_nonce,
                },
            }),
        )
        .await;
        assert_eq!(missing_validated_nonce.status(), StatusCode::BAD_REQUEST);
        let missing_validated_nonce_body =
            axum::body::to_bytes(missing_validated_nonce.into_body(), usize::MAX)
                .await
                .expect("body reads");
        let missing_validated_nonce_body: Value =
            serde_json::from_slice(&missing_validated_nonce_body).expect("error body parses");
        assert_eq!(missing_validated_nonce_body["error"], "invalid_proof");
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        let nonce = "nonce-1";
        let nonce_key = state
            .self_attestation_rate_keys
            .oid4vci_nonce(
                &state.oid4vci.credential_issuer,
                "person_is_alive_sd_jwt",
                nonce,
            )
            .expect("nonce hashes");
        let nonce_scope =
            oid4vci_nonce_replay_scope(&state, "person_is_alive_sd_jwt").expect("nonce scope");
        let nonce_key = ReplayKey::new(nonce_key).expect("nonce replay key");
        state
            .replay
            .nonce_store()
            .reserve_nonce(
                &nonce_scope,
                &nonce_key,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .await
            .expect("nonce reserves");
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
        let validated_proof = validated_oid4vci_proof(&state, &proof, Some(nonce));

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Some(Extension(validated_proof.clone())),
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
            Some(Extension(validated_proof)),
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
                "signing_key": "issuer-key",
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
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::new(evidence),
                Arc::new(self_attestation),
                Arc::new(oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
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
        let nonce_scope =
            oid4vci_nonce_replay_scope(&state, "person_is_alive_sd_jwt").expect("nonce scope");
        let nonce_key = ReplayKey::new(nonce_key).expect("nonce replay key");
        state
            .replay
            .nonce_store()
            .reserve_nonce(
                &nonce_scope,
                &nonce_key,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .await
            .expect("nonce reserves");
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(fresh_oidc_principal(
                Some("client_id:citizen-portal"),
                &["self_attestation"],
            ))),
            Some(Extension(validated_oid4vci_proof(
                &state,
                &proof,
                Some(nonce),
            ))),
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: proof,
                },
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert!(matches!(
            state
                .replay
                .nonce_store()
                .consume_nonce(&nonce_scope, &nonce_key)
                .await
                .expect("nonce store is available"),
            ReplayInsertOutcome::Inserted
        ));
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
                audiences: vec![bounded("registry-notary-citizen")],
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
            requester: None,
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: subject_id.to_string(),
                    id_type: Some("national_id".to_string()),
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from("person-is-alive")],
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
    fn self_attestation_derives_missing_request_identity_from_token_binding() {
        let config = self_attestation_config();
        let principal = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let mut request = EvaluateRequest {
            requester: None,
            target: None,
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from("person-is-alive")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        };

        derive_self_attestation_request_context(&config, &principal, &mut request)
            .expect("request identity is derived");

        let target_subject = request
            .target_subject()
            .expect("derived target maps to subject");
        assert_eq!(target_subject.id, "NAT-123");
        assert_eq!(target_subject.id_type.as_deref(), Some("national_id"));
        assert_eq!(
            request
                .requester
                .as_ref()
                .and_then(EvidenceEntity::to_subject_request)
                .expect("derived requester maps to subject")
                .id,
            "NAT-123"
        );
        assert_eq!(
            request
                .relationship
                .as_ref()
                .map(|relationship| relationship.relationship_type.as_str()),
            Some("self")
        );
    }

    #[test]
    fn self_attestation_derivation_rejects_conflicting_request_identity() {
        let config = self_attestation_config();
        let principal = classify_self_attestation_principal(
            &config,
            &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let mut request = evaluate_request("NAT-999");

        let err = derive_self_attestation_request_context(&config, &principal, &mut request)
            .expect_err("conflicting target must be denied before runtime");

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
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            AuditKeyHasher::unkeyed_dev_only(),
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

    #[tokio::test]
    async fn readiness_fails_when_signer_readiness_fails() {
        let state = Arc::new(
            RegistryNotaryApiState::new(
                Arc::new(evidence_config()),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource::default()),
                Arc::new(EvidenceStore::default()),
                Arc::new(NoopIssuerResolver),
            )
            .with_signer_readiness(SignerReadiness::from_provider_flags(vec![
                Arc::new(AtomicBool::new(false)),
            ])),
        );

        let response = ready(Some(Extension(state))).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("ready body reads");
        let value: Value = serde_json::from_slice(&body).expect("ready body is JSON");

        assert_eq!(value["status"], "not_ready");
        assert_eq!(value["checks"]["signing_providers"]["total"], json!(1));
        assert_eq!(value["checks"]["signing_providers"]["ok"], json!(0));
        assert_eq!(value["checks"]["signing_providers"]["failed"], json!(1));
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
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            AuditKeyHasher::unkeyed_dev_only(),
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
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            AuditKeyHasher::unkeyed_dev_only(),
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
                "signing_key": "issuer-key",
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
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            Err(EvidenceError::CredentialIssuerNotConfigured)
        }
    }

    struct TestIssuerResolver;

    impl EvidenceIssuerResolver for TestIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &issuer_private_jwk(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    #[cfg(feature = "registry-notary-cel")]
    struct StaticIssuerResolver;

    #[cfg(feature = "registry-notary-cel")]
    impl EvidenceIssuerResolver for StaticIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
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
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &holder_private_jwk(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    #[tokio::test]
    async fn self_attestation_batch_evaluate_is_rejected_before_source_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence_config()),
            Arc::new(self_attestation_config()),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::new(CountingSource {
                reads: Arc::clone(&reads),
            }),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        ));
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "NAT-123".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("person-is-alive")],
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
            Ok(Json(request)),
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

    #[test]
    fn batch_audit_purposes_resolve_per_subject_overrides() {
        let purposes = resolved_batch_audit_purposes(
            None,
            Some("program-b"),
            &[
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "NAT-123".to_string(),
                        id_type: Some("national_id".to_string()),
                        purpose: Some("program-a".to_string()),
                    },
                ),
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "NAT-456".to_string(),
                        id_type: Some("national_id".to_string()),
                        purpose: None,
                    },
                ),
            ],
        )
        .expect("audit purposes resolve");

        assert_eq!(purposes, vec!["program-a", "program-b"]);
    }

    #[test]
    fn batch_audit_context_hashes_each_item_and_keeps_matching_audit_code() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let result = registry_notary_core::BatchEvaluateResponse {
            batch_id: "batch-1".to_string(),
            status: registry_notary_core::BatchStatus::Completed,
            claims: vec!["person-is-alive".to_string()],
            items: vec![
                registry_notary_core::BatchItemResponse {
                    input_index: 0,
                    target_ref: registry_notary_core::TargetRefView {
                        entity_type: "Person".to_string(),
                        handle: "rnref:v1:target-handle-1".to_string(),
                        identifier_schemes: vec!["national_id".to_string()],
                        profile: None,
                    },
                    requester_ref: Some(registry_notary_core::EvidenceEntityRef {
                        entity_type: "Person".to_string(),
                        handle: "rnref:v1:requester-handle".to_string(),
                        identifier_schemes: vec!["national_id".to_string()],
                        profile: None,
                    }),
                    matching: Some(registry_notary_core::MatchingMetadata {
                        policy_id: "policy-v1".to_string(),
                        method: "configured_lookup".to_string(),
                        confidence: "high".to_string(),
                        score: None,
                    }),
                    evaluation_id: Some("eval-1".to_string()),
                    status: registry_notary_core::BatchItemStatus::Succeeded,
                    claim_results: Vec::new(),
                    errors: Vec::new(),
                },
                registry_notary_core::BatchItemResponse {
                    input_index: 1,
                    target_ref: registry_notary_core::TargetRefView {
                        entity_type: "Person".to_string(),
                        handle: "rnref:v1:target-handle-2".to_string(),
                        identifier_schemes: vec!["national_id".to_string()],
                        profile: None,
                    },
                    requester_ref: None,
                    matching: None,
                    evaluation_id: None,
                    status: registry_notary_core::BatchItemStatus::Failed,
                    claim_results: Vec::new(),
                    errors: vec![registry_notary_core::BatchItemError {
                        code: "evidence.not_available".to_string(),
                        title: "Evidence not available".to_string(),
                        retryable: false,
                        audit_code: Some("target.match_ambiguous".to_string()),
                    }],
                },
            ],
            summary: registry_notary_core::BatchSummary {
                succeeded: 1,
                failed: 1,
            },
        };
        let mut response = StatusCode::OK.into_response();
        attach_evidence_audit(
            &mut response,
            "batch_evaluate",
            None,
            &["person-is-alive".to_string()],
            Some(2),
        );

        attach_batch_evaluate_response_audit(&mut response, &keys, &result, None)
            .expect("batch audit context attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        let items = audit.batch_items.as_ref().expect("batch items captured");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].input_index, 0);
        assert_eq!(items[0].target_type.as_deref(), Some("Person"));
        assert_eq!(items[0].matching_outcome.as_deref(), Some("matched"));
        assert_eq!(items[0].matching_policy_id.as_deref(), Some("policy-v1"));
        assert!(items[0]
            .target_ref_hash
            .as_ref()
            .map(Hashed::as_str)
            .is_some_and(|hash| !hash.contains("target-handle-1")));
        assert!(items[0].requester_ref_hash.is_some());
        assert_eq!(items[1].input_index, 1);
        assert_eq!(items[1].matching_outcome.as_deref(), Some("error"));
        assert_eq!(
            items[1].matching_error_code.as_deref(),
            Some("target.match_ambiguous")
        );
        assert!(
            items[1].target_ref_hash.is_none(),
            "failed batch items must not emit durable matched-reference pseudonyms"
        );
    }

    #[test]
    fn evaluate_request_audit_context_hashes_entity_refs_and_matching_metadata() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let request = EvaluateRequest {
            requester: Some(EvidenceEntity::with_identifier(
                "person",
                "national_id",
                "NID-REQUESTER",
            )),
            target: Some({
                let mut target =
                    EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET");
                target
                    .attributes
                    .insert("given_name".to_string(), json!("Amina"));
                target
            }),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from("person-is-alive")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-a".to_string()),
        };
        let mut result = claim_result_view("eval-1", "person-is-alive");
        result.requester_ref = Some(registry_notary_core::EvidenceEntityRef {
            entity_type: "Person".to_string(),
            handle: "rnref:v1:requester-handle".to_string(),
            identifier_schemes: vec!["national_id".to_string()],
            profile: None,
        });
        result.matching = Some(registry_notary_core::MatchingMetadata {
            policy_id: "policy-v1".to_string(),
            method: "configured_lookup".to_string(),
            confidence: "high".to_string(),
            score: None,
        });
        let mut response = StatusCode::OK.into_response();
        attach_evidence_audit(
            &mut response,
            "evaluate",
            Some("eval-1".to_string()),
            &["person-is-alive".to_string()],
            Some(1),
        );

        attach_evaluate_request_audit(&mut response, &keys, &request, Some(&result), None)
            .expect("audit context attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(audit.target_type.as_deref(), Some("Person"));
        assert_eq!(audit.requester_type.as_deref(), Some("Person"));
        assert_eq!(audit.matching_policy_id.as_deref(), Some("policy-v1"));
        assert_eq!(audit.matching_method.as_deref(), Some("configured_lookup"));
        assert_eq!(audit.matching_outcome.as_deref(), Some("matched"));
        let target_hash = audit
            .target_ref_hash
            .as_ref()
            .map(Hashed::as_str)
            .expect("target ref hash is present");
        let requester_hash = audit
            .requester_ref_hash
            .as_ref()
            .map(Hashed::as_str)
            .expect("requester ref hash is present");
        assert!(!target_hash.contains("NID-TARGET"));
        assert!(!target_hash.contains("Amina"));
        assert!(!requester_hash.contains("NID-REQUESTER"));
    }

    #[test]
    fn canonical_audit_identifier_input_sorts_identifiers_and_explicit_empty_fields() {
        let mut first = registry_notary_core::EvidenceIdentifier {
            scheme: "national_id".to_string(),
            value: "NID-1001".to_string(),
            issuer: None,
            country: Some("RW".to_string()),
        };
        let second = registry_notary_core::EvidenceIdentifier {
            scheme: "animal_ear_tag".to_string(),
            value: "EAR-77".to_string(),
            issuer: Some("vet-registry".to_string()),
            country: None,
        };
        let mut entity = EvidenceEntity::new("Person");
        entity.identifiers = vec![first.clone(), second.clone()];
        let canonical = canonical_audit_identifier_input("target", Some("program-a"), &entity)
            .expect("canonicalizes")
            .expect("identifier input is present");

        first.country = Some("RW".to_string());
        let mut reordered = EvidenceEntity::new("Person");
        reordered.identifiers = vec![second, first];
        let reordered_canonical =
            canonical_audit_identifier_input("target", Some("program-a"), &reordered)
                .expect("canonicalizes")
                .expect("identifier input is present");

        assert_eq!(canonical, reordered_canonical);
        assert!(canonical.contains(r#""issuer":"""#));
        assert!(canonical.contains(r#""country":"""#));
        assert!(canonical.find("animal_ear_tag") < canonical.find("national_id"));
    }

    #[test]
    fn credential_audit_context_links_stored_target_and_requester_refs() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut result = claim_result_view("eval-1", "person-is-alive");
        result.requester_ref = Some(registry_notary_core::EvidenceEntityRef {
            entity_type: "Person".to_string(),
            handle: "rnref:v1:requester-handle".to_string(),
            identifier_schemes: vec!["national_id".to_string()],
            profile: None,
        });
        result.matching = Some(registry_notary_core::MatchingMetadata {
            policy_id: "policy-v1".to_string(),
            method: "configured_lookup".to_string(),
            confidence: "high".to_string(),
            score: None,
        });
        let mut response = StatusCode::OK.into_response();

        attach_self_attestation_credential_audit(
            &mut response,
            &keys,
            "eval-1",
            &["person-is-alive".to_string()],
            &[result],
            1,
            SelfAttestationCredentialAuditDetails {
                profile_id: "person_is_alive_sd_jwt",
                holder_binding_mode: "did",
                policy_hash: None,
                protocol: Some("openid4vci"),
                credential_configuration_id: Some("person_is_alive_sd_jwt"),
            },
        )
        .expect("credential audit attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(audit.target_type.as_deref(), Some("Person"));
        assert_eq!(audit.requester_type.as_deref(), Some("Person"));
        assert_eq!(audit.matching_policy_id.as_deref(), Some("policy-v1"));
        assert_eq!(audit.matching_outcome.as_deref(), Some("matched"));
        assert!(audit.target_ref_hash.is_some());
        assert!(audit.requester_ref_hash.is_some());
    }

    #[test]
    fn evaluate_request_audit_context_carries_matching_error_without_raw_inputs() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut target = EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET");
        target
            .attributes
            .insert("date_of_birth".to_string(), json!("1984-02-10"));
        target
            .attributes
            .insert("given_name".to_string(), json!("Amina"));
        let request = EvaluateRequest {
            requester: None,
            target: Some(target),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from("person-is-alive")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-a".to_string()),
        };
        let mut response = StatusCode::FORBIDDEN.into_response();
        attach_evidence_audit(
            &mut response,
            "evaluate_denied",
            None,
            &["person-is-alive".to_string()],
            None,
        );

        attach_evaluate_request_audit(
            &mut response,
            &keys,
            &request,
            None,
            Some("target.attributes_insufficient"),
        )
        .expect("audit context attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(audit.target_type.as_deref(), Some("person"));
        assert_eq!(audit.matching_outcome.as_deref(), Some("error"));
        assert_eq!(
            audit.matching_error_code.as_deref(),
            Some("target.attributes_insufficient")
        );
        assert!(
            audit.target_ref_hash.is_none(),
            "pre-match target errors must not create durable request-attribute pseudonyms"
        );
        let audit_value = json!({ "debug": format!("{audit:?}") });
        assert_json_absent_strings(&audit_value, ["NID-TARGET", "Amina", "1984-02-10"])
            .expect("raw matching inputs are absent from audit context");
        assert!(audit.requester_type.is_none());
        assert!(audit.requester_ref_hash.is_none());
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

    fn validated_oid4vci_proof(
        state: &RegistryNotaryApiState,
        proof: &str,
        nonce: Option<&str>,
    ) -> ValidatedProof {
        validate_proof_jwt(
            proof,
            &ProofValidationPolicy::credential_endpoint(
                &state.oid4vci.credential_issuer,
                nonce,
                Duration::from_secs(state.oid4vci.proof.max_age_seconds),
                Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
            ),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .expect("proof validates")
    }

    #[cfg(feature = "registry-notary-cel")]
    fn sign_oid4vci_proof_without_nonce(audience: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sign_openid4vci_proof_jwt(&holder_private_jwk(), audience, None, now)
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
        let issuer = registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
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

    fn evaluation_for_proof() -> registry_notary_core::StoredEvaluation {
        registry_notary_core::StoredEvaluation {
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

    fn claim_result_view(
        evaluation_id: &str,
        claim_id: &str,
    ) -> registry_notary_core::ClaimResultView {
        registry_notary_core::ClaimResultView {
            evaluation_id: evaluation_id.to_string(),
            claim_id: claim_id.to_string(),
            claim_version: "1".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: registry_notary_core::TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:subject-hash".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: registry_notary_core::ClaimProvenance {
                source_count: 0,
                source_versions: std::collections::BTreeMap::new(),
                computed_by: "test".to_string(),
            },
        }
    }

    fn credential_issue_evidence_config() -> EvidenceConfig {
        let mut evidence = evidence_config();
        evidence.service_id = "registry-notary".to_string();
        evidence
            .claims
            .first_mut()
            .expect("person-is-alive claim exists")
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.credential_profiles.insert(
            "civil_status_sd_jwt".to_string(),
            serde_json::from_value(json!({
                "format": FORMAT_SD_JWT_VC,
                "issuer": "did:web:issuer.example",
                "signing_key": "issuer-key",
                "vct": "https://issuer.example/credentials/civil-status",
                "validity_seconds": 600,
                "allowed_claims": ["person-is-alive"],
                "disclosure": { "allowed": ["predicate"] }
            }))
            .expect("credential profile parses"),
        );
        evidence
    }

    #[tokio::test]
    async fn issue_credential_fails_closed_when_status_record_write_fails() {
        std::env::set_var(
            "TEST_CREDENTIAL_STATUS_UNREACHABLE_REDIS_URL",
            "redis://127.0.0.1:1",
        );
        let evidence = credential_issue_evidence_config();
        let store = Arc::new(EvidenceStore::default());
        store.insert(registry_notary_core::StoredEvaluation {
            client_id: "caseworker".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            disclosure: "predicate".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: vec![claim_result_view(
                "eval-status-write-fails",
                "person-is-alive",
            )],
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            self_attestation: None,
        });
        let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            storage: CREDENTIAL_STATUS_STORAGE_REDIS.to_string(),
            retention_seconds: 60,
            redis: CredentialStatusRedisConfig {
                url_env: "TEST_CREDENTIAL_STATUS_UNREACHABLE_REDIS_URL".to_string(),
                key_prefix: "registry-notary-status-fail-test".to_string(),
                connect_timeout_ms: 10,
                operation_timeout_ms: 10,
            },
        })
        .expect("status store builds without connecting");
        let state = Arc::new(
            RegistryNotaryApiState::new_with_federation(
                Arc::new(evidence),
                Arc::new(SelfAttestationConfig::default()),
                Arc::new(Oid4vciConfig::default()),
                Arc::new(FederationConfig::default()),
                AuditKeyHasher::unkeyed_dev_only(),
                None,
                ReplayStores::memory(),
                credential_status,
                Arc::new(AppMetrics::default()),
                Arc::new(CountingSource::default()),
                Arc::clone(&store),
                Arc::new(TestIssuerResolver),
                None,
            )
            .expect("state builds"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };

        let response = issue_credential(
            HeaderMap::new(),
            Some(Extension(state)),
            Some(Extension(principal)),
            Ok(Json(CredentialIssueRequest {
                evaluation_id: "eval-status-write-fails".to_string(),
                credential_profile: Some("civil_status_sd_jwt".to_string()),
                format: Some(FORMAT_SD_JWT_VC.to_string()),
                claims: Some(vec!["person-is-alive".to_string()]),
                disclosure: Some("predicate".to_string()),
                holder: None,
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem body parses");
        assert_eq!(body["code"], json!("credential.issuance_failed"));
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
            "signing_key": "issuer-key",
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
        // service_id, not the hard-coded literal "registry-notary".
        let holder_id = holder_did_jwk();
        let service_id = "my.notary.example";
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
            sign_holder_proof(&holder_id, proof_payload(&holder_id, "registry-notary"));
        let err = validate_holder_proof_payload(
            &proof_legacy_literal,
            &holder_id,
            "profile-a",
            &request,
            &evaluation,
            service_id,
        )
        .expect_err("proof with aud=\"registry-notary\" must be rejected when service_id differs");
        assert!(matches!(err, EvidenceError::HolderProofRequired));
    }

    #[test]
    fn strict_credential_issue_rejects_oid4vci_proof_shape() {
        let holder_id = holder_did_jwk();
        let proof = sign_oid4vci_proof("registry-notary", "nonce-1");
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
            "registry-notary",
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
        let service_id = "my.notary.example";
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

        let valid_now = OffsetDateTime::now_utc().unix_timestamp() + 20;
        let proof_just_positive = sign_holder_proof(
            &holder_id,
            windowed_proof_payload(&holder_id, service_id, valid_now, valid_now + 1),
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
