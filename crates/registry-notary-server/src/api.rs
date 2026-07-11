// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary routes.

mod admin;
mod attestation_policy;
mod audit;
mod catalog;
mod credentials;
mod evaluations;
mod oid4vci;
mod probes;
mod request;
mod status;

use admin::*;
use attestation_policy::*;
use audit::*;
use catalog::*;
use credentials::*;
use evaluations::*;
use oid4vci::*;
use probes::*;
use request::*;
use status::*;

pub(crate) use admin::{ConfigApplyPosture, ConfigEmergencyPosture};
pub(crate) use audit::{evidence_error_response, evidence_error_response_with_request_id};

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, SystemTime},
};

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
    signing_key_uses_local_software_custody, AccessMode, BatchEvaluateItemRequest,
    BatchEvaluateRequest, BoundedClaimId, BoundedCorrelationId, ClaimRef, ClaimResultView,
    ClaimSet, ConfigMetadata, CredentialIssueRequest, CredentialProfileConfig, DeploymentProfile,
    EvaluateRequest, EvidenceActor, EvidenceAuditEvent, EvidenceBatchItemAuditEvent,
    EvidenceConfig, EvidenceEntity, EvidenceEntityReference, EvidenceError, EvidenceOnBehalfOf,
    EvidencePrincipal, EvidenceRelationship, FederationConfig, Hashed, HolderRequest,
    Oid4vciConfig, Oid4vciCredentialClaimMode, Oid4vciCredentialConfigurationConfig,
    Oid4vciDisplayImageConfig, Oid4vciIssuerDisplayConfig, PolicyIdentifier, RateLimitBucket,
    RegistryNotaryAdminListenerMode, RenderEvaluationRequest, SelfAttestationConfig,
    SelfAttestationDelegatedRelationshipConfig, SelfAttestationDenialCode,
    SelfAttestationScopePolicy, SourceCapability, StandaloneRegistryNotaryConfig,
    StoredSelfAttestationMetadata, SubjectRequest, VerifiedClaimValue, FORMAT_CLAIM_RESULT_JSON,
    FORMAT_SD_JWT_VC,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_crypto::KeyReadiness;
use registry_platform_crypto::PublicJwk;
use registry_platform_crypto::SigningProvider;
use registry_platform_oid4vci::{
    consume_validated_proof_nonce_once, validate_proof_jwt, CredentialConfigurationMetadata,
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest as Oid4vciCredentialRequest,
    CredentialResponse as Oid4vciCredentialResponse, CredentialResponseCredential,
    DisplayImageMetadata, DisplayMetadata, NonceRequest as Oid4vciNonceRequest, NonceResponse,
    ProofValidationPolicy, TokenRequest as Oid4vciTokenRequest,
    TokenResponse as Oid4vciTokenResponse, TxCode, ValidatedProof, WireError,
    PRE_AUTHORIZED_CODE_GRANT_TYPE, PROOF_TYPE_JWT, SD_JWT_VC_FORMAT,
};
use registry_platform_ops::{
    AckObservation, ConfigOverridePin, ConfigProvenance, ConfigSource, PostureApplyResult,
};
use registry_platform_pdp::{
    decide as pdp_decide, Decision as PdpDecision, EvidenceRequestContext as PdpRequestContext,
    PolicyInput as PdpPolicyInput,
};
use registry_platform_replay::{ReplayKey, ReplayScope, ReplayStoreError, RequiredReplayError};
use registry_platform_sdjwt::{validate_holder_proof, HolderProofBindings, HolderProofPolicy};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::CelWorker;
use crate::config_governed::ConfigGovernanceContext;
use crate::{
    credential_profile_for,
    credential_status::{
        encoded_single_entry_status_list, is_mutable_status, CredentialStatusRecord,
        CredentialStatusStore, CredentialStatusStoreError,
    },
    format_time,
    metrics::AppMetrics,
    openapi_document,
    posture::{posture_document, PostureContext, PostureDocumentError},
    preauth_state::{LoginState, SingleUseReserveError},
    replay::{require_replay_insert, ReplayReadiness, ReplayStores},
    runtime::{
        batch_idempotency_key, batch_request_hash, claim_ids, claim_semantics_metadata, find_claim,
        find_claim_version, matching_policy_audit_identity, validate_batch_subject_limit,
        MatchingPolicyAuditIdentity,
    },
    standalone::{
        constant_time_eq, generate_numeric_tx_code, generate_opaque_token, pkce_s256_challenge,
        pre_auth_audit_event, AuthAuditState, PreAuthAuditFields, PreAuthRuntime, SignerReadiness,
    },
    BatchEvaluateOptions, EvidenceStore, MachineQuotaLimiter, RegistryNotaryRuntime,
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter, SourceReader,
};

pub(crate) use crate::digest::evidence_claim_hash;
use crate::digest::{sha256_canonical_json, sha256_json};
pub(crate) use crate::problem::{evidence_detail, evidence_status, evidence_title};
pub use crate::response_context::{EvidenceAuditContext, EvidenceErrorCodeContext};
pub use oid4vci::oid4vci_proof_precheck_middleware;

const AUDIT_ACK_CURSOR_READ_TIMEOUT: Duration = Duration::from_millis(500);
static AUDIT_ACK_CURSOR_READ_PERMIT: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn audit_ack_cursor_read_permit() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(
        AUDIT_ACK_CURSOR_READ_PERMIT.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1))),
    )
}

async fn bounded_audit_ack_observation(config: &StandaloneRegistryNotaryConfig) -> AckObservation {
    let Some(path) = config
        .deployment
        .evidence
        .audit_ack_cursor_path()
        .map(std::path::Path::to_path_buf)
    else {
        return AckObservation::unverified();
    };
    let max_age = config.deployment.evidence.audit_ack_max_age();
    let permit = match audit_ack_cursor_read_permit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::Closed) => {
            return AckObservation::invalid("ack cursor read worker is unavailable");
        }
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return AckObservation::invalid("ack cursor read is still in progress");
        }
    };
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        registry_platform_ops::evaluate_ack_health(Some(path.as_path()), SystemTime::now(), max_age)
    });
    match tokio::time::timeout(AUDIT_ACK_CURSOR_READ_TIMEOUT, worker).await {
        Ok(Ok(observation)) => observation,
        Ok(Err(_)) => AckObservation::invalid("ack cursor read worker failed"),
        Err(_) => AckObservation::invalid("ack cursor read timed out"),
    }
}

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub(crate) const ADMIN_SCOPE: &str = "registry_notary:admin";
pub(crate) const METRICS_SCOPE: &str = "registry_notary:metrics_read";
pub(crate) const OPS_READ_SCOPE: &str = "registry_notary:ops_read";
const OID4VCI_CREDENTIAL_PATH: &str = "/oid4vci/credential";
// SD-JWT VC Type Metadata well-known prefix inserted between host and vct path.
const WELL_KNOWN_VCT_PREFIX: &str = "/.well-known/vct";
const POSTURE_FILTER_FAILED_CODE: &str = "posture.filter_failed";
const ADMIN_CAPABILITY_NOT_SUPPORTED_CODE: &str = "registry.admin.capability.not_supported";
const POSTURE_TIER_INVALID_CODE: &str = "registry.admin.posture.invalid_tier";

pub use crate::federation::federation_router;

pub(crate) fn oid4vci_proof_precheck_applies(path: &str) -> bool {
    path == OID4VCI_CREDENTIAL_PATH
}

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    public_router().merge(admin_router())
}

/// Routes mounted on the public listener.
///
/// This is not an unauthenticated router. Standalone composition wraps these
/// routes in the auth/audit middleware, which exempts only explicit public
/// protocol and probe paths.
pub fn public_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(crate::docs::router())
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
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
}

pub fn admin_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/v1/capabilities", get(admin_capabilities))
        .route("/admin/v1/posture", get(admin_posture))
        .route("/admin/v1/reload", post(admin_reload))
        .route(
            "/admin/v1/credentials/{credential_id}/status",
            post(update_credential_status),
        )
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
    self_attestation_rate_limiter: Arc<SelfAttestationRateLimiter>,
    pub(crate) self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    machine_quota_limiter: Arc<MachineQuotaLimiter>,
    pub(crate) replay: ReplayStores,
    pub(crate) credential_status: CredentialStatusStore,
    status_list_jwt_cache: Arc<StatusListJwtCache>,
    pub(crate) metrics: Arc<AppMetrics>,
    pub(crate) source: Arc<dyn SourceReader>,
    pub(crate) store: Arc<EvidenceStore>,
    runtime: Arc<RwLock<Arc<ApiRuntimeSnapshot>>>,
    auth_state: Option<Arc<AuthAuditState>>,
    audit: Option<crate::standalone::AuditPipeline>,
    pub(crate) posture: Option<Arc<PostureContext>>,
    pub(crate) deployment_gates: Arc<crate::standalone::DeploymentGateState>,
    config_apply_posture: Arc<RwLock<ConfigApplyPosture>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_config: Arc<RegistryNotaryCelConfig>,
}

#[derive(Clone)]
struct ApiRuntimeSnapshot {
    federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
    issuer_runtime: Arc<IssuerRuntimeBundle>,
    config_governance: ConfigGovernanceContext,
    runtime_config: Option<Arc<StandaloneRegistryNotaryConfig>>,
    /// Pre-authorized-code flow runtime. `None` unless the flow is enabled and
    /// the dedicated access-token signing key plus eSignet RP settings loaded.
    preauth: Option<Arc<PreAuthRuntime>>,
}

struct IssuerRuntimeBundle {
    issuers: Arc<dyn EvidenceIssuerResolver>,
    signer_readiness: SignerReadiness,
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
        let machine_quota_limiter = Arc::new(MachineQuotaLimiter::new(evidence.machine_quota));
        let issuer_runtime = Arc::new(IssuerRuntimeBundle {
            issuers,
            signer_readiness,
        });
        let runtime = Arc::new(ApiRuntimeSnapshot {
            federation_runtime,
            issuer_runtime,
            config_governance: ConfigGovernanceContext::default(),
            runtime_config: None,
            preauth: None,
        });
        Self {
            evidence,
            self_attestation,
            oid4vci,
            federation,
            self_attestation_rate_limiter,
            self_attestation_rate_keys,
            machine_quota_limiter,
            replay,
            credential_status,
            status_list_jwt_cache: Arc::new(StatusListJwtCache::default()),
            metrics,
            source,
            store,
            runtime: Arc::new(RwLock::new(runtime)),
            auth_state: None,
            audit: None,
            posture: None,
            deployment_gates: Arc::new(crate::standalone::DeploymentGateState::default()),
            config_apply_posture: Arc::new(RwLock::new(ConfigApplyPosture::default())),
            #[cfg(feature = "registry-notary-cel")]
            cel_worker: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_config: Arc::new(RegistryNotaryCelConfig::default()),
        }
    }

    #[must_use]
    pub(crate) fn with_auth_state(mut self, auth_state: Arc<AuthAuditState>) -> Self {
        self.auth_state = Some(auth_state);
        self
    }

    #[must_use]
    pub(crate) fn with_audit_pipeline(mut self, audit: crate::standalone::AuditPipeline) -> Self {
        self.audit = Some(audit);
        self
    }

    #[must_use]
    pub(crate) fn with_preauth_runtime(self, preauth: Option<Arc<PreAuthRuntime>>) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.preauth = preauth;
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_signer_readiness(self, signer_readiness: SignerReadiness) -> Self {
        let current = self.issuer_runtime();
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.issuer_runtime = Arc::new(IssuerRuntimeBundle {
            issuers: current.issuers.clone(),
            signer_readiness,
        });
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_posture_context(mut self, posture: PostureContext) -> Self {
        self.posture = Some(Arc::new(posture));
        self
    }

    pub(crate) fn with_deployment_gates(
        mut self,
        gates: crate::standalone::DeploymentGateState,
    ) -> Self {
        self.deployment_gates = Arc::new(gates);
        self
    }

    pub(crate) fn with_config_governance(self, context: ConfigGovernanceContext) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.config_governance = context;
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_runtime_config(self, config: Arc<StandaloneRegistryNotaryConfig>) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.runtime_config = Some(config);
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    fn runtime_snapshot(&self) -> Arc<ApiRuntimeSnapshot> {
        self.runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn publish_runtime_snapshot(&self, snapshot: Arc<ApiRuntimeSnapshot>) {
        *self
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }

    pub(crate) fn runtime_config(&self) -> Option<Arc<StandaloneRegistryNotaryConfig>> {
        self.runtime_snapshot().runtime_config.clone()
    }

    pub(crate) fn deployment_gates_for_observation(
        &self,
        config: &StandaloneRegistryNotaryConfig,
        observation: &registry_platform_ops::AckObservation,
    ) -> crate::standalone::DeploymentGateState {
        self.deployment_gates.evaluate_current(config, observation)
    }

    pub(crate) async fn current_audit_ack_observation(
        &self,
        config: &StandaloneRegistryNotaryConfig,
    ) -> registry_platform_ops::AckObservation {
        let observation = bounded_audit_ack_observation(config).await;
        if !observation.requires_audit_tail_binding() {
            return observation;
        }
        let tail = match &self.audit {
            Some(audit) => audit.current_tail_hash_bounded().await,
            None => None,
        };
        observation.bind_to_audit_tail(tail)
    }

    pub(crate) async fn current_deployment_gates(&self) -> crate::standalone::DeploymentGateState {
        let Some(config) = self.runtime_config() else {
            return (*self.deployment_gates).clone();
        };
        let observation = self.current_audit_ack_observation(&config).await;
        self.deployment_gates_for_observation(&config, &observation)
    }

    fn openapi_requires_auth(&self) -> bool {
        self.auth_state.as_ref().map_or_else(
            || {
                self.runtime_config()
                    .map(|config| config.server.openapi_requires_auth)
                    .unwrap_or(true)
            },
            |auth_state| auth_state.openapi_requires_auth(),
        )
    }

    pub(crate) fn federation_runtime(
        &self,
    ) -> Option<Arc<crate::federation::FederationRuntimeState>> {
        self.runtime_snapshot().federation_runtime.clone()
    }

    pub(crate) fn config_apply_posture(&self) -> ConfigApplyPosture {
        self.config_apply_posture
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn record_config_apply(&self, posture: ConfigApplyPosture) {
        *self
            .config_apply_posture
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = posture;
    }

    fn issuer_runtime(&self) -> Arc<IssuerRuntimeBundle> {
        self.runtime_snapshot().issuer_runtime.clone()
    }

    fn issuer_resolver(&self) -> Arc<dyn EvidenceIssuerResolver> {
        self.issuer_runtime().issuers.clone()
    }

    pub(crate) fn signer_readiness(&self) -> SignerReadiness {
        self.issuer_runtime().signer_readiness.clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_notary_core::{
        BoundedVerifiedClaims, CredentialStatusConfig, CredentialStatusRedisConfig,
        EvidenceAuthorizationDetails, SourceBindingConfig, SubjectRequest, VerifiedClaimName,
        VerifiedClaimValue, CREDENTIAL_STATUS_STORAGE_REDIS,
    };
    use registry_platform_crypto::{did_jwk_from_public_jwk, sign, LocalJwkSigner, PrivateJwk};
    use registry_platform_replay::ReplayInsertOutcome;
    use registry_platform_testing::{assert_json_absent_strings, sign_openid4vci_proof_jwt};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    // Ed25519 keypair: `d` is the seed, `x` is the corresponding public key,
    // both base64url (no padding). Identical to the key in
    // registry-notary-core::sd_jwt tests so behavior is consistent.
    const HOLDER_PRIV_D_B64: &str = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw";
    const HOLDER_PUB_X_B64: &str = "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc";
    const ISSUER_PRIV_D_B64: &str = "f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys";
    const ISSUER_PUB_X_B64: &str = "pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec";
    const SUBJECT_BINDING_CLAIM: &str = "https://id.example.gov/claims/national_id";

    #[test]
    fn token_client_address_ignores_forwarded_headers_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let connect_info =
            axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());

        assert_eq!(
            token_client_address_with_trusted_proxy_ips(&headers, Some(&connect_info), &[]),
            "198.51.100.10"
        );
    }

    #[test]
    fn token_client_address_trusts_forwarded_for_from_configured_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
        );
        let connect_info =
            axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());
        let trusted_proxy = "198.51.100.10".parse::<IpAddr>().unwrap();

        assert_eq!(
            token_client_address_with_trusted_proxy_ips(
                &headers,
                Some(&connect_info),
                &[trusted_proxy]
            ),
            "203.0.113.10"
        );
    }

    #[test]
    fn token_client_address_trusts_real_ip_from_configured_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.11"));
        let connect_info =
            axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());
        let trusted_proxy = "198.51.100.10".parse::<IpAddr>().unwrap();

        assert_eq!(
            token_client_address_with_trusted_proxy_ips(
                &headers,
                Some(&connect_info),
                &[trusted_proxy]
            ),
            "203.0.113.11"
        );
    }

    #[test]
    fn oid4vci_requested_url_ignores_forwarded_host_from_untrusted_peer() {
        let config = Oid4vciConfig {
            credential_issuer: "https://issuer.example".to_string(),
            ..Oid4vciConfig::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        headers.insert(header::HOST, HeaderValue::from_static("host.example"));
        let uri = "/credentials/identity".parse::<Uri>().unwrap();

        // Untrusted peer: forwarded scheme/host are ignored, Host header wins.
        assert_eq!(
            oid4vci_requested_absolute_url_for_path(
                &config,
                &headers,
                &uri,
                "/credentials/identity",
                false,
            ),
            Some("https://host.example/credentials/identity".to_string())
        );
    }

    #[test]
    fn oid4vci_requested_url_trusts_forwarded_host_from_trusted_peer() {
        let config = Oid4vciConfig {
            credential_issuer: "https://issuer.example".to_string(),
            ..Oid4vciConfig::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("proxy.example"),
        );
        headers.insert(header::HOST, HeaderValue::from_static("host.example"));
        let uri = "/credentials/identity".parse::<Uri>().unwrap();

        // Trusted peer: forwarded scheme/host are honored.
        assert_eq!(
            oid4vci_requested_absolute_url_for_path(
                &config,
                &headers,
                &uri,
                "/credentials/identity",
                true,
            ),
            Some("http://proxy.example/credentials/identity".to_string())
        );
    }

    fn classifier_config() -> StandaloneRegistryNotaryConfig {
        serde_json::from_value(json!({
            "evidence": {
                "enabled": true
            },
            "auth": {
                "mode": "api_key",
                "api_keys": [{
                    "id": "primary-api-key",
                    "fingerprint": {
                        "provider": "env",
                        "name": "PRIMARY_API_KEY_HASH"
                    },
                    "scopes": ["claims:read"]
                }],
                "bearer_tokens": [{
                    "id": "primary-bearer-token",
                    "fingerprint": {
                        "provider": "env",
                        "name": "PRIMARY_BEARER_TOKEN_HASH"
                    },
                    "scopes": ["claims:write"]
                }]
            }
        }))
        .expect("classifier config parses")
    }

    #[test]
    fn runtime_snapshot_read_never_observes_torn_issuer_federation_generation() {
        let old_issuers: Arc<dyn EvidenceIssuerResolver> = Arc::new(NoopIssuerResolver);
        let new_issuers: Arc<dyn EvidenceIssuerResolver> = Arc::new(TestIssuerResolver);
        let old_federation = test_federation_runtime("old");
        let new_federation = test_federation_runtime("new");
        let old_snapshot = Arc::new(ApiRuntimeSnapshot {
            federation_runtime: Some(Arc::clone(&old_federation)),
            issuer_runtime: Arc::new(IssuerRuntimeBundle {
                issuers: Arc::clone(&old_issuers),
                signer_readiness: SignerReadiness::default(),
            }),
            config_governance: ConfigGovernanceContext::default(),
            runtime_config: None,
            preauth: None,
        });
        let new_snapshot = Arc::new(ApiRuntimeSnapshot {
            federation_runtime: Some(Arc::clone(&new_federation)),
            issuer_runtime: Arc::new(IssuerRuntimeBundle {
                issuers: Arc::clone(&new_issuers),
                signer_readiness: SignerReadiness::default(),
            }),
            config_governance: ConfigGovernanceContext::default(),
            runtime_config: None,
            preauth: None,
        });
        let state = Arc::new(RegistryNotaryApiState::new_with_runtime_blocks(
            Arc::new(EvidenceConfig::default()),
            Arc::new(SelfAttestationConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            Some(Arc::clone(&old_federation)),
            AuditKeyHasher::unkeyed_dev_only(),
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::clone(&old_issuers),
            SignerReadiness::default(),
        ));
        state.publish_runtime_snapshot(Arc::clone(&old_snapshot));

        let worker_count = 8;
        let start = Arc::new(Barrier::new(worker_count + 1));
        let done = Arc::new(AtomicBool::new(false));
        let torn = Arc::new(AtomicBool::new(false));
        let observed_old = Arc::new(AtomicBool::new(false));
        let observed_new = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();
        for _ in 0..worker_count {
            let state = Arc::clone(&state);
            let start = Arc::clone(&start);
            let done = Arc::clone(&done);
            let torn = Arc::clone(&torn);
            let observed_old = Arc::clone(&observed_old);
            let observed_new = Arc::clone(&observed_new);
            let old_issuers = Arc::clone(&old_issuers);
            let new_issuers = Arc::clone(&new_issuers);
            let old_federation = Arc::clone(&old_federation);
            let new_federation = Arc::clone(&new_federation);
            workers.push(thread::spawn(move || {
                start.wait();
                while !done.load(Ordering::SeqCst) {
                    let snapshot = state.runtime_snapshot();
                    let issuer_is_old = Arc::ptr_eq(&snapshot.issuer_runtime.issuers, &old_issuers);
                    let issuer_is_new = Arc::ptr_eq(&snapshot.issuer_runtime.issuers, &new_issuers);
                    let federation_is_old = snapshot
                        .federation_runtime
                        .as_ref()
                        .is_some_and(|runtime| Arc::ptr_eq(runtime, &old_federation));
                    let federation_is_new = snapshot
                        .federation_runtime
                        .as_ref()
                        .is_some_and(|runtime| Arc::ptr_eq(runtime, &new_federation));
                    if issuer_is_old && federation_is_old {
                        observed_old.store(true, Ordering::SeqCst);
                    } else if issuer_is_new && federation_is_new {
                        observed_new.store(true, Ordering::SeqCst);
                    } else {
                        torn.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }));
        }

        start.wait();
        // The reader threads race a publisher that does nothing but atomic swaps, so on
        // an oversubscribed runner every publish can complete before any reader executes
        // its loop body even once. A fixed iteration count therefore isn't a reliable way
        // to guarantee both generations get observed; keep alternating publishes until
        // they actually have been, bounded by a generous wall-clock deadline so a genuine
        // regression (e.g. readers never getting scheduled at all) still fails the test
        // instead of hanging.
        let coverage_deadline_duration = Duration::from_secs(15);
        let coverage_deadline = Instant::now() + coverage_deadline_duration;
        let mut publish_pairs: u64 = 0;
        loop {
            state.publish_runtime_snapshot(Arc::clone(&new_snapshot));
            state.publish_runtime_snapshot(Arc::clone(&old_snapshot));
            publish_pairs += 1;

            if torn.load(Ordering::SeqCst) {
                break;
            }
            if observed_old.load(Ordering::SeqCst) && observed_new.load(Ordering::SeqCst) {
                break;
            }
            if Instant::now() >= coverage_deadline {
                break;
            }
        }
        done.store(true, Ordering::SeqCst);
        for worker in workers {
            worker.join().expect("observer thread joins");
        }

        // The real correctness property: a reader must never see a snapshot with an old
        // issuer paired with a new federation runtime (or vice versa).
        assert!(!torn.load(Ordering::SeqCst));
        // Coverage is a test-harness concern, not a correctness one: it just confirms the
        // race above actually exercised both generations before the deadline elapsed.
        assert!(
            observed_old.load(Ordering::SeqCst) && observed_new.load(Ordering::SeqCst),
            "reader threads never observed both snapshot generations after {publish_pairs} \
             publish pairs and a {:?} coverage deadline (observed_old={}, observed_new={}); \
             this is a scheduling coverage failure, not a torn read (the torn invariant above \
             already holds)",
            coverage_deadline_duration,
            observed_old.load(Ordering::SeqCst),
            observed_new.load(Ordering::SeqCst),
        );
    }

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
                "required_acr_values": ["urn:example:loa:substantial"],
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

    fn delegated_self_attestation_config() -> SelfAttestationConfig {
        let mut config = self_attestation_config();
        config.delegation = registry_notary_core::SelfAttestationDelegationConfig {
            enabled: true,
            allowed_relationships: vec![SelfAttestationDelegatedRelationshipConfig {
                relationship_type: "guardian".to_string(),
                proof_claim: "guardian-link-established".to_string(),
                target_id_type: Some("civil_registration_id".to_string()),
                allowed_claims: vec!["dependent-person-is-alive".to_string()],
                allowed_purposes: vec!["dependent_attestation".to_string()],
                allowed_formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
                allowed_disclosures: vec!["predicate".to_string()],
                credential_profiles: vec!["dependent_status_sd_jwt".to_string()],
            }],
        };
        config
    }

    fn delegated_evidence_config() -> EvidenceConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "service_id": "https://notary.example.test",
            "claims": [
                {
                    "id": "guardian-link-established",
                    "title": "Guardian link is established",
                    "version": "1",
                    "subject_type": "relationship",
                    "purpose": "dependent_attestation",
                    "source_bindings": {
                        "link": {
                            "connector": "registry_data_api",
                            "dataset": "guardian_registry",
                            "entity": "guardian_link",
                            "lookup": {
                                "input": "target.identifiers.civil_registration_id",
                                "field": "dependent_id",
                                "op": "eq",
                                "cardinality": "one"
                            },
                            "query_fields": [{
                                "input": "requester.identifiers.national_id",
                                "field": "guardian_id",
                                "op": "eq"
                            }],
                            "fields": {
                                "value": {
                                    "field": "value",
                                    "type": "boolean",
                                    "required": true
                                }
                            }
                        }
                    },
                    "rule": { "type": "extract", "source": "link", "field": "value" },
                    "operations": {
                        "evaluate": { "enabled": true },
                        "batch_evaluate": { "enabled": false, "max_subjects": 1 }
                    },
                    "disclosure": {
                        "default": "predicate",
                        "allowed": ["predicate"],
                        "downgrade": "deny"
                    },
                    "formats": [FORMAT_CLAIM_RESULT_JSON]
                },
                {
                    "id": "dependent-person-is-alive",
                    "title": "Dependent person is alive",
                    "version": "1",
                    "subject_type": "person",
                    "purpose": "dependent_attestation",
                    "depends_on": ["guardian-link-established"],
                    "rule": { "type": "cel", "expression": "claims.guardian.satisfied", "bindings": { "claims": { "guardian": { "claim": "guardian-link-established" } } } },
                    "operations": {
                        "evaluate": { "enabled": true },
                        "batch_evaluate": { "enabled": false, "max_subjects": 1 }
                    },
                    "disclosure": {
                        "default": "predicate",
                        "allowed": ["predicate"],
                        "downgrade": "deny"
                    },
                    "formats": [FORMAT_CLAIM_RESULT_JSON],
                    "credential_profiles": ["dependent_status_sd_jwt"]
                }
            ],
            "credential_profiles": {
                "dependent_status_sd_jwt": {
                    "format": FORMAT_SD_JWT_VC,
                    "issuer": "did:web:issuer.example",
                    "signing_key": "issuer-key",
                    "vct": "https://issuer.example/credentials/dependent-status",
                    "validity_seconds": 600,
                    "holder_binding": {
                        "mode": "did",
                        "proof_of_possession": "required",
                        "allowed_did_methods": ["did:jwk"]
                    },
                    "allowed_claims": ["dependent-person-is-alive"],
                    "disclosure": { "allowed": ["predicate"] }
                }
            }
        }))
        .expect("delegated evidence config parses")
    }

    fn delegated_request() -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "CHILD-123".to_string(),
                    id_type: Some("civil_registration_id".to_string()),
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::with_version("dependent-person-is-alive", "1")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        }
    }

    fn delegated_authorization_details(evidence: &EvidenceConfig) -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec![evidence.service_id.clone()],
            claims: vec![
                ClaimRef::with_version("dependent-person-is-alive", "1"),
                ClaimRef::with_version("guardian-link-established", "1"),
            ],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("dependent_attestation".to_string()),
            legal_basis_ref: None,
            consent_ref: None,
            jurisdiction: None,
            assurance_level: None,
            subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
                binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
                id_type: "national_id".to_string(),
            }),
            target: Some(registry_notary_core::EvidenceAuthorizationTarget {
                id_type: "civil_registration_id".to_string(),
                id: "CHILD-123".to_string(),
            }),
            relationship: Some(registry_notary_core::EvidenceAuthorizationRelationship {
                relationship_type: "guardian".to_string(),
                proof_claim: "guardian-link-established".to_string(),
            }),
            access_mode: Some(AccessMode::DelegatedAttestation),
            assisted_access_context: None,
        }
    }

    fn delegated_transaction_principal(
        config: &SelfAttestationConfig,
        evidence: &EvidenceConfig,
    ) -> EvidencePrincipal {
        let mut principal = classify_self_attestation_principal(
            config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal.authorization_details = Some(delegated_authorization_details(evidence));
        principal.access_mode = AccessMode::DelegatedAttestation;
        principal
    }

    fn delegated_test_audit_hasher() -> AuditKeyHasher {
        const ENV: &str = "TEST_DELEGATED_AUDIT_HASH_SECRET";
        std::env::set_var(ENV, "0123456789abcdef0123456789abcdef");
        AuditKeyHasher::from_env(ENV).expect("delegated test audit hasher loads")
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

    fn oid4vci_evidence_config() -> EvidenceConfig {
        let mut evidence = evidence_config();
        let claim = evidence.claims.first_mut().expect("claim exists");
        claim.formats.push(FORMAT_SD_JWT_VC.to_string());
        claim
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.signing_keys.insert(
            "issuer-key".to_string(),
            serde_json::from_value(json!({
                "provider": "local_jwk_env",
                "private_jwk_env": "ISSUER_KEY",
                "alg": "EdDSA",
                "kid": "did:web:issuer.example#key-1",
                "status": "active"
            }))
            .expect("signing key parses"),
        );
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
            .expect("credential profile parses"),
        );
        evidence
    }

    #[test]
    fn oid4vci_metadata_is_public_but_not_operationally_leaky() {
        let evidence = oid4vci_evidence_config();
        let metadata = serde_json::to_value(
            oid4vci_metadata(&oid4vci_config(), &evidence).expect("metadata builds"),
        )
        .expect("metadata serializes");

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
                ["logo"]["uri"],
            "https://issuer.example/assets/person-is-alive.png"
        );
        assert!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
                ["logo"]
                .get("url")
                .is_none()
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["scope"],
            "person_is_alive"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
                ["credential_signing_alg_values_supported"][0],
            "EdDSA"
        );
        assert_eq!(
            metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
                ["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"][0],
            "EdDSA"
        );
        let mut without_nonce = oid4vci_config();
        without_nonce.nonce.enabled = false;
        let without_nonce = serde_json::to_value(
            oid4vci_metadata(&without_nonce, &evidence).expect("metadata builds"),
        )
        .expect("metadata serializes");
        assert!(without_nonce.get("nonce_endpoint").is_none());
        let text = metadata.to_string();
        assert!(!text.contains("token_env"));
        assert!(!text.contains("source_connections"));
        assert!(!text.contains("NAT-123"));
    }

    #[test]
    fn oid4vci_metadata_advertises_configured_credential_signing_alg() {
        let oid4vci = oid4vci_config();
        let mut evidence = oid4vci_evidence_config();
        evidence
            .signing_keys
            .get_mut("issuer-key")
            .expect("issuer key exists")
            .alg = "ES256".to_string();

        let metadata =
            serde_json::to_value(oid4vci_metadata(&oid4vci, &evidence).expect("metadata builds"))
                .expect("metadata serializes");
        let configuration =
            &metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"];

        assert_eq!(
            configuration["credential_signing_alg_values_supported"],
            json!(["ES256"])
        );
        assert_eq!(
            configuration["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
            json!(["EdDSA"]),
            "holder proof algorithms stay independent from issuer signing algorithms"
        );
    }

    #[tokio::test]
    async fn oid4vci_credential_rejects_delegated_transaction_token() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::new(oid4vci_evidence_config()),
                Arc::new(delegated_self_attestation_config()),
                Arc::new(oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(TestIssuerResolver),
            ),
        );
        let mut principal =
            fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]);
        principal.authorization_details =
            Some(delegated_authorization_details(&delegated_evidence_config()));
        let nonce = "delegated-oid4vci-nonce";
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(principal)),
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");
        assert_eq!(body["error"], "access_denied");
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oid4vci_credential_scope_prevents_cross_configuration_issuance_before_nonce_consume() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let evidence = Arc::new(oid4vci_evidence_config());
        let self_attestation = Arc::new(self_attestation_config());
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let mut other_configuration = oid4vci
            .credential_configurations
            .get("person_is_alive_sd_jwt")
            .expect("base configuration exists")
            .clone();
        other_configuration.scope = "date_of_birth".to_string();
        other_configuration.vct = "https://issuer.example/credentials/date-of-birth".to_string();
        oid4vci
            .credential_configurations
            .insert("date_of_birth_sd_jwt".to_string(), other_configuration);
        let principal = oid4vci_authorized_principal(
            &evidence,
            &self_attestation,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["self_attestation", "person_is_alive"],
        );
        let oid4vci = Arc::new(oid4vci);
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&self_attestation),
                Arc::clone(&oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(TestIssuerResolver),
            ),
        );
        let nonce = "cross-configuration-nonce";
        let (nonce_scope, nonce_key) =
            reserve_oid4vci_test_nonce(&state, "date_of_birth_sd_jwt", nonce).await;
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(principal)),
            Some(Extension(validated_oid4vci_proof(
                &state,
                &proof,
                Some(nonce),
            ))),
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("date_of_birth_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: proof,
                },
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");
        assert_eq!(body["error"], "access_denied");
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

    #[tokio::test]
    async fn oid4vci_credential_requires_authorization_details_before_nonce_consume() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let evidence = Arc::new(oid4vci_evidence_config());
        let self_attestation = Arc::new(self_attestation_config());
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let oid4vci = Arc::new(oid4vci);
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&self_attestation),
                Arc::clone(&oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(TestIssuerResolver),
            ),
        );
        let nonce = "missing-authz-nonce";
        let (nonce_scope, nonce_key) =
            reserve_oid4vci_test_nonce(&state, "person_is_alive_sd_jwt", nonce).await;
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
        let mut principal = fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation", "person_is_alive"],
        );
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.token_type = Some(bounded(
            registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        ));

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(principal)),
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");
        assert_eq!(body["error"], "access_denied");
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

    #[tokio::test]
    async fn oid4vci_credential_requires_custom_notary_typ_details_before_nonce_consume() {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(EvidenceStore::default());
        let evidence = Arc::new(oid4vci_evidence_config());
        let self_attestation = Arc::new(self_attestation_config());
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        let oid4vci = Arc::new(oid4vci);
        let runtime_config = Arc::new(runtime_config_with_custom_access_token_typ());
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&self_attestation),
                Arc::clone(&oid4vci),
                AuditKeyHasher::unkeyed_dev_only(),
                Arc::new(CountingSource {
                    reads: Arc::clone(&reads),
                }),
                Arc::clone(&store),
                Arc::new(TestIssuerResolver),
            )
            .with_runtime_config(runtime_config),
        );
        let nonce = "custom-typ-missing-authz-nonce";
        let (nonce_scope, nonce_key) =
            reserve_oid4vci_test_nonce(&state, "person_is_alive_sd_jwt", nonce).await;
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
        let mut principal = fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation", "person_is_alive"],
        );
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.issuer = bounded("https://notary.example.test");
        claims.token_type = Some(bounded("custom-notary-access+jwt"));

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(principal)),
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");
        assert_eq!(body["error"], "access_denied");
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
    fn oid4vci_type_metadata_defaults_display_locale_when_unconfigured() {
        let mut oid4vci = oid4vci_config();
        let configuration = oid4vci
            .credential_configurations
            .get_mut("person_is_alive_sd_jwt")
            .expect("configuration exists");
        configuration.display.locale = None;

        let evidence = evidence_config();
        let metadata = oid4vci_type_metadata_document(&evidence, configuration);

        assert_eq!(metadata["display"][0]["locale"], "en-US");
        assert_eq!(metadata["claims"][0]["display"][0]["locale"], "en-US");
    }

    #[test]
    fn oid4vci_type_metadata_advertises_claim_semantics_extension() {
        let oid4vci = oid4vci_config();
        let configuration = oid4vci
            .credential_configurations
            .get("person_is_alive_sd_jwt")
            .expect("configuration exists");
        let mut evidence = oid4vci_evidence_config();
        evidence.claims.first_mut().expect("claim exists").semantics = Some(
            serde_json::from_value(json!({
                "concept": "https://publicschema.org/Person",
                "predicate": "urn:registry-notary:predicate:person-is-alive",
                "derived_from": ["https://publicschema.org/date_of_death"]
            }))
            .expect("claim semantics parses"),
        );

        let metadata = oid4vci_type_metadata_document(&evidence, configuration);

        assert_eq!(
            metadata["claims"][0]["registry_notary_semantics"]["concept"],
            json!("https://publicschema.org/Person")
        );
        assert_eq!(
            metadata["claims"][0]["registry_notary_semantics"]["predicate"],
            json!("urn:registry-notary:predicate:person-is-alive")
        );
        assert_eq!(
            metadata["claims"][0]["registry_notary_semantics"]["derived_from"],
            json!(["https://publicschema.org/date_of_death"])
        );
    }

    #[test]
    fn oid4vci_metadata_advertises_token_endpoint_only_when_preauth_enabled() {
        // Pre-auth disabled (the default): no token endpoint is advertised, so a
        // wallet sees an authorization_code-only issuer.
        let disabled = oid4vci_config();
        assert!(!disabled.pre_authorized_code.enabled);
        let evidence = oid4vci_evidence_config();
        let disabled_metadata =
            serde_json::to_value(oid4vci_metadata(&disabled, &evidence).expect("metadata builds"))
                .expect("metadata serializes");
        assert!(
            disabled_metadata.get("token_endpoint").is_none(),
            "disabled pre-auth must not advertise a token endpoint"
        );

        // Pre-auth enabled: the Notary's own token endpoint is advertised,
        // derived from the credential-issuer base like the credential endpoint.
        let mut enabled = oid4vci_config();
        enabled.pre_authorized_code.enabled = true;
        let enabled_metadata =
            serde_json::to_value(oid4vci_metadata(&enabled, &evidence).expect("metadata builds"))
                .expect("metadata serializes");
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

    #[test]
    fn oid4vci_token_denial_audit_records_public_token_path() {
        let audit = token_error_audit_event(
            "/oid4vci/token",
            StatusCode::BAD_REQUEST.as_u16(),
            Some("person_is_alive_sd_jwt"),
            SelfAttestationDenialCode::OperationDenied,
        );

        assert_eq!(audit.method, "POST");
        assert_eq!(audit.path, "/oid4vci/token");
        assert_eq!(audit.status, StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(audit.decision, "denied");
        assert_eq!(
            audit.denial_code,
            Some(SelfAttestationDenialCode::OperationDenied)
        );
        assert_eq!(
            audit.protocol.as_ref().map(|value| value.as_str()),
            Some("openid4vci")
        );
        assert_eq!(
            audit
                .credential_configuration_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("person_is_alive_sd_jwt")
        );
    }

    #[tokio::test]
    async fn oid4vci_token_error_fails_closed_when_denial_audit_fails() {
        let response = token_error_after_audit_result(
            token_error_response(TokenWireError::InvalidRequest),
            true,
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("error body parses");
        assert_eq!(body["error"], "server_error");
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
        let evidence = Arc::new(evidence);
        let self_attestation = Arc::new(self_attestation);
        let oid4vci = Arc::new(oid4vci);
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&self_attestation),
                Arc::clone(&oid4vci),
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
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
            Some(Extension(oid4vci_authorized_principal(
                &evidence,
                &self_attestation,
                &oid4vci,
                "person_is_alive_sd_jwt",
                &["self_attestation", "person_is_alive"],
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
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
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        };
        let validated_proof = validated_oid4vci_proof(&state, &proof, Some(nonce));

        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(oid4vci_authorized_principal(
                &evidence,
                &self_attestation,
                &oid4vci,
                "person_is_alive_sd_jwt",
                &["self_attestation", "person_is_alive"],
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
            Some(Extension(Arc::clone(&state))),
            Some(Extension(oid4vci_authorized_principal(
                &evidence,
                &self_attestation,
                &oid4vci,
                "person_is_alive_sd_jwt",
                &["self_attestation", "person_is_alive"],
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
        let evidence = Arc::new(evidence);
        let self_attestation = Arc::new(self_attestation);
        let oid4vci = Arc::new(oid4vci);
        let state = Arc::new(
            RegistryNotaryApiState::new_with_self_attestation_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&self_attestation),
                Arc::clone(&oid4vci),
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
            Some(Extension(oid4vci_authorized_principal(
                &evidence,
                &self_attestation,
                &oid4vci,
                "person_is_alive_sd_jwt",
                &["self_attestation", "person_is_alive"],
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
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
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
    fn oid4vci_single_proof_jwt_accepts_proofs_array() {
        let mut request = Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: String::new(),
                jwt: String::new(),
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs {
                jwt: vec!["array-proof.jwt.sig".to_string()],
            },
        };

        assert_eq!(
            oid4vci_single_proof_jwt(&request).expect("single array proof is accepted"),
            "array-proof.jwt.sig"
        );

        request.proofs.jwt.push("second-proof.jwt.sig".to_string());
        assert_eq!(
            oid4vci_single_proof_jwt(&request),
            Err(Oid4vciWireError::InvalidProof)
        );
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
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
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

    #[test]
    fn oid4vci_issuance_authorization_details_bind_selected_configuration() {
        let evidence = oid4vci_evidence_config();
        let config = self_attestation_config();
        let oid4vci = oid4vci_config();
        let configuration = oid4vci
            .credential_configurations
            .get("person_is_alive_sd_jwt")
            .expect("configuration exists");

        let details = oid4vci_issuance_authorization_details(&evidence, &config, configuration)
            .expect("details build");

        assert_eq!(details.actions, vec!["evaluate"]);
        assert_eq!(details.locations, vec![evidence.service_id.clone()]);
        assert_eq!(details.claims, vec![ClaimRef::from("person-is-alive")]);
        assert_eq!(details.disclosure.as_deref(), Some("predicate"));
        assert_eq!(details.format.as_deref(), Some(FORMAT_SD_JWT_VC));
        assert_eq!(details.purpose.as_deref(), Some("citizen_self_attestation"));
        assert_eq!(details.access_mode, Some(AccessMode::SelfAttestation));
        let subject = details.subject.as_ref().expect("subject binding is set");
        assert_eq!(subject.binding_claim, SUBJECT_BINDING_CLAIM);
        assert_eq!(subject.id_type, "national_id");

        let principal = oid4vci_authorized_principal(
            &evidence,
            &config,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["self_attestation", "person_is_alive"],
        );
        require_oid4vci_issuance_authorization_details(
            &evidence,
            &config,
            configuration,
            &principal,
            true,
        )
        .expect("matching details authorize issuance");

        let direct_esignet_principal = fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation", "person_is_alive"],
        );
        require_oid4vci_issuance_authorization_details(
            &evidence,
            &config,
            configuration,
            &direct_esignet_principal,
            false,
        )
        .expect("direct eSignet tokens can rely on scope without RAR details");
    }

    #[test]
    fn oid4vci_issuance_authorization_details_fail_closed_for_empty_notary_details() {
        let evidence = oid4vci_evidence_config();
        let config = self_attestation_config();
        let oid4vci = oid4vci_config();
        let configuration = oid4vci
            .credential_configurations
            .get("person_is_alive_sd_jwt")
            .expect("configuration exists");
        let mut principal = fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation", "person_is_alive"],
        );
        principal.authorization_details = Some(EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            legal_basis_ref: Some("wallet-compat-context".to_string()),
            ..EvidenceAuthorizationDetails::default()
        });

        require_oid4vci_issuance_authorization_details(
            &evidence,
            &config,
            configuration,
            &principal,
            false,
        )
        .expect("direct eSignet/OIDC tokens can carry context-only details");

        let err = require_oid4vci_issuance_authorization_details(
            &evidence,
            &config,
            configuration,
            &principal,
            true,
        )
        .expect_err("Notary-issued tokens must carry transaction-scoped details");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied
            }
        ));
    }

    #[test]
    fn oid4vci_requires_authorization_details_for_custom_notary_access_typ() {
        let runtime_config = runtime_config_with_custom_access_token_typ();
        let mut principal = fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation", "person_is_alive"],
        );
        {
            let claims = principal
                .verified_claims
                .as_mut()
                .expect("test principal has claims");
            claims.issuer = bounded("https://notary.example.test");
            claims.token_type = Some(bounded("custom-notary-access+jwt"));
        }

        assert!(oid4vci_requires_authorization_details(
            &principal,
            Some(&runtime_config),
            None
        ));

        principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .issuer = bounded("https://id.example.gov");

        assert!(!oid4vci_requires_authorization_details(
            &principal,
            Some(&runtime_config),
            None
        ));

        {
            let claims = principal
                .verified_claims
                .as_mut()
                .expect("test principal has claims");
            claims.issuer = bounded("https://notary.example.test");
            claims.token_type = Some(bounded(
                registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
            ));
        }

        assert!(oid4vci_requires_authorization_details(
            &principal,
            Some(&runtime_config),
            None
        ));

        principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .issuer = bounded("https://id.example.gov");

        assert!(!oid4vci_requires_authorization_details(
            &principal,
            Some(&runtime_config),
            None
        ));
    }

    fn runtime_config_with_custom_access_token_typ() -> StandaloneRegistryNotaryConfig {
        let mut config = classifier_config();
        config.auth.access_token_signing.enabled = true;
        config.auth.access_token_signing.issuer = "https://notary.example.test".to_string();
        config.auth.access_token_signing.token_typ = "custom-notary-access+jwt".to_string();
        config
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
            authorization_details: None,
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

    fn oid4vci_authorized_principal(
        evidence: &EvidenceConfig,
        config: &SelfAttestationConfig,
        oid4vci: &Oid4vciConfig,
        configuration_id: &str,
        scopes: &[&str],
    ) -> EvidencePrincipal {
        let mut principal = fresh_oidc_principal(Some("client_id:citizen-portal"), scopes);
        let configuration = oid4vci
            .credential_configurations
            .get(configuration_id)
            .expect("credential configuration exists");
        principal.authorization_details = Some(
            oid4vci_issuance_authorization_details(evidence, config, configuration)
                .expect("authorization details build"),
        );
        principal
    }

    async fn reserve_oid4vci_test_nonce(
        state: &RegistryNotaryApiState,
        configuration_id: &str,
        nonce: &str,
    ) -> (ReplayScope, ReplayKey) {
        let nonce_key = state
            .self_attestation_rate_keys
            .oid4vci_nonce(&state.oid4vci.credential_issuer, configuration_id, nonce)
            .expect("nonce hashes");
        let nonce_scope = oid4vci_nonce_replay_scope(state, configuration_id).expect("nonce scope");
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
        (nonce_scope, nonce_key)
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

    fn transaction_authorization_details(
        evidence: &EvidenceConfig,
    ) -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec![evidence.service_id.clone()],
            claims: vec![ClaimRef::with_version("person-is-alive", "1")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("citizen_self_attestation".to_string()),
            legal_basis_ref: None,
            consent_ref: None,
            jurisdiction: None,
            assurance_level: None,
            subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
                binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
                id_type: "national_id".to_string(),
            }),
            target: None,
            relationship: None,
            access_mode: Some(AccessMode::SelfAttestation),
            assisted_access_context: None,
        }
    }

    fn classified_transaction_principal(
        config: &SelfAttestationConfig,
        evidence: &EvidenceConfig,
    ) -> EvidencePrincipal {
        let mut principal = classify_self_attestation_principal(
            config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal.authorization_details = Some(transaction_authorization_details(evidence));
        principal
    }

    #[test]
    fn self_attestation_authorization_details_allow_exact_transaction() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classified_transaction_principal(&config, &evidence);
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect("exact transaction details authorize request");
    }

    #[test]
    fn self_attestation_authorization_details_required_for_transaction_token() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal.authorization_details = None;
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("classified principal carries verified claims");
        claims.token_type = Some(bounded(
            registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        ));
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("transaction tokens must carry authorization_details");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_reject_omitted_claim_version() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classified_transaction_principal(&config, &evidence);
        let request = evaluate_request("NAT-123");

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("omitting a versioned authorized claim broadens the request");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_reject_broadened_claims() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classified_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .expect("details exist")
            .claims
            .push(ClaimRef::with_version("date-of-birth", "1"));
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("broadened transaction claims must be denied");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_reject_duplicate_action() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classified_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .expect("details exist")
            .actions
            .push("evaluate".to_string());
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("duplicate transaction action must be denied");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_reject_empty_claims_without_panic() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let principal = classified_transaction_principal(&config, &evidence);
        let mut request = evaluate_request("NAT-123");
        request.claims = Vec::new();

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("empty claim array must deny instead of panicking");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_tolerate_future_fields() {
        let details: EvidenceAuthorizationDetails = serde_json::from_value(serde_json::json!({
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["registry-notary:test"],
            "claims": [{"id": "person-is-alive", "version": "1"}],
            "subject": {
                "binding_claim": SUBJECT_BINDING_CLAIM,
                "id_type": "national_id",
                "future_subject_metadata": true
            },
            "assisted_access_context": {
                "channel": "citizen_self_service",
                "future_context_metadata": true
            },
            "future_authorization_metadata": true
        }))
        .expect("authorization_details should ignore future metadata fields");

        assert_eq!(
            details.subject.as_ref().unwrap().binding_claim,
            SUBJECT_BINDING_CLAIM
        );
        assert_eq!(
            details.assisted_access_context.as_ref().unwrap().channel,
            "citizen_self_service"
        );
    }

    #[test]
    fn self_attestation_authorization_details_reject_wrong_notary_location() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classified_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .expect("details exist")
            .locations = vec!["other-notary".to_string()];
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("wrong Notary audience broadens the transaction");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied
            }
        ));
    }

    #[test]
    fn self_attestation_authorization_details_reject_wrong_subject_binding_metadata() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classified_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .and_then(|details| details.subject.as_mut())
            .expect("subject details exist")
            .id_type = "other_id".to_string();
        let mut request = evaluate_request("NAT-123");
        request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

        let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
            .expect_err("wrong subject binding metadata broadens the transaction");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::SubjectMismatch
            }
        ));
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
            authorization_details: None,
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

    #[test]
    fn self_attestation_external_standard_at_jwt_uses_scope_without_notary_details() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("classified principal carries verified claims");
        claims.issuer = bounded("https://id.example.gov");
        claims.token_type = Some(bounded(
            registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        ));
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        )
        .with_runtime_config(Arc::new(runtime_config_with_custom_access_token_typ()));

        prepare_self_attestation_evaluate(
            &state,
            &evidence,
            &principal,
            &evaluate_request("NAT-123"),
        )
        .expect("external standard at+jwt can rely on configured self-attestation scope");
    }

    #[test]
    fn self_attestation_notary_standard_at_jwt_still_requires_transaction_details() {
        let config = self_attestation_config();
        let evidence = evidence_config();
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("classified principal carries verified claims");
        claims.issuer = bounded("https://notary.example.test");
        claims.token_type = Some(bounded(
            registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        ));
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        )
        .with_runtime_config(Arc::new(runtime_config_with_custom_access_token_typ()));

        let err = prepare_self_attestation_evaluate(
            &state,
            &evidence,
            &principal,
            &evaluate_request("NAT-123"),
        )
        .expect_err("Notary-issued standard at+jwt must carry transaction details");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied
            }
        ));
    }

    #[test]
    fn delegated_attestation_derives_requester_and_pins_metadata() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let principal = delegated_transaction_principal(&config, &evidence);
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();

        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("delegated request context derives");
        let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
            .expect("delegated evaluate context prepares");

        assert_eq!(
            request
                .requester
                .as_ref()
                .and_then(EvidenceEntity::to_subject_request)
                .expect("requester is derived")
                .id,
            "NAT-123"
        );
        assert_eq!(
            request
                .relationship
                .as_ref()
                .map(|relationship| relationship.relationship_type.as_str()),
            Some("guardian")
        );
        assert!(
            request
                .on_behalf_of
                .as_ref()
                .map(|delegation| delegation.actor.id_hash.starts_with("hmac-sha256:"))
                .unwrap_or(false),
            "delegated actor is stored as a keyed hash"
        );
        assert_eq!(context.purpose, "dependent_attestation");
        assert_eq!(
            context.metadata.access_mode,
            AccessMode::DelegatedAttestation
        );
        assert_eq!(
            context
                .metadata
                .relationship_type
                .as_ref()
                .map(ConfigMetadata::as_str),
            Some("guardian")
        );
        assert_eq!(
            context
                .metadata
                .proof_claim_id
                .as_ref()
                .map(BoundedClaimId::as_str),
            Some("guardian-link-established")
        );
        assert!(context
            .metadata
            .dependent_target_hash
            .as_ref()
            .map(|hash| hash.as_str().starts_with("hmac-sha256:"))
            .unwrap_or(false));
        assert!(matches!(
            context.source_capability,
            SourceCapability::DelegatedAttestation { .. }
        ));
    }

    #[test]
    fn delegated_attestation_rejects_spoofed_requester_context() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let principal = delegated_transaction_principal(&config, &evidence);
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();
        request.requester = Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "ATTACKER".to_string(),
                id_type: Some("national_id".to_string()),
            },
        ));

        let err = derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect_err("caller-supplied requester must not be trusted");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
    }

    #[test]
    fn delegated_attestation_canonicalizes_target_to_validated_subject() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let principal = delegated_transaction_principal(&config, &evidence);
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        // Caller pins the validated subject CHILD-123 via the configured id_type,
        // but smuggles a divergent canonical id (VICTIM-A) plus an extra
        // identifier and attribute that the binding hash would never see.
        let mut request = delegated_request();
        let target = request
            .target
            .as_mut()
            .expect("delegated target is present");
        target.id = Some("VICTIM-A".to_string());
        target
            .identifiers
            .push(registry_notary_core::EvidenceIdentifier {
                scheme: "national_id".to_string(),
                value: "DIVERGENT-NID".to_string(),
                issuer: None,
                country: None,
            });
        target
            .attributes
            .insert("given_name".to_string(), json!("smuggled"));
        target.profile = Some("smuggled-profile".to_string());

        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("delegated request context derives");

        let canonical_target = request.target.as_ref().expect("target survives derivation");
        // The canonical id field must be collapsed so an arbitrary lookup keyed on
        // target.id can never read the smuggled VICTIM-A value.
        assert!(
            canonical_target.id.is_none(),
            "divergent canonical id must be dropped"
        );
        assert!(
            canonical_target.attributes.is_empty(),
            "caller-supplied target attributes must be dropped"
        );
        assert!(
            canonical_target.profile.is_none(),
            "caller-supplied target profile must be dropped"
        );
        // The only surviving identifier is the validated (id_type, id) pair, so
        // to_subject_request() and every configured lookup path resolve the same
        // subject.
        let subject = canonical_target
            .to_subject_request()
            .expect("canonical target resolves a subject");
        assert_eq!(subject.id, "CHILD-123");
        assert_eq!(subject.id_type.as_deref(), Some("civil_registration_id"));

        let context = request
            .request_context()
            .expect("delegated request yields a context");
        assert_eq!(
            context.lookup_value("target.identifiers.civil_registration_id"),
            Some(json!("CHILD-123"))
        );
        // The binding-hash projection and the proof/dependent lookups now agree:
        // no path can observe VICTIM-A or DIVERGENT-NID.
        assert_eq!(context.lookup_value("target.id"), None);
        assert_eq!(context.lookup_value("target.identifiers.national_id"), None);
    }

    #[test]
    fn delegated_attestation_requires_transaction_details_to_cover_proof_claim() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let mut principal = delegated_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .expect("delegated details exist")
            .claims = vec![ClaimRef::with_version("dependent-person-is-alive", "1")];
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();
        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("relationship context still derives");

        let err = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
            .expect_err("missing proof claim authorization must fail closed");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedClaimDenied
            }
        ));
    }

    #[test]
    fn delegated_attestation_requires_transaction_details_target() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let mut principal = delegated_transaction_principal(&config, &evidence);
        principal
            .authorization_details
            .as_mut()
            .expect("delegated details exist")
            .target = None;
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();
        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("relationship context still derives before target-scoped authorization check");

        let err = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
            .expect_err("delegated target must be explicit in authorization_details");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
    }

    #[test]
    fn stored_delegated_attestation_rechecks_current_authorization_details() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let principal = delegated_transaction_principal(&config, &evidence);
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();
        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("delegated request context derives");
        let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
            .expect("delegated context prepares");
        let mut evaluation = evaluation_for_proof();
        evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
        evaluation.purpose = context.purpose.clone();
        evaluation.claim_ids = vec!["dependent-person-is-alive".to_string()];
        evaluation.claim_refs = request.claims.clone();
        evaluation.disclosure = context.metadata.disclosure.as_str().to_string();
        evaluation.format = context.metadata.result_format.as_str().to_string();
        evaluation.self_attestation = Some(context.metadata);
        let mut narrowed = principal.clone();
        narrowed
            .authorization_details
            .as_mut()
            .expect("delegated authorization details exist")
            .claims = vec![ClaimRef::with_version("dependent-person-is-alive", "1")];

        let err = require_self_attestation_stored_access(
            &state,
            &evidence,
            &narrowed,
            &evaluation,
            &evaluation.claim_ids,
            &evaluation.disclosure,
            &evaluation.format,
            None,
        )
        .expect_err("stored delegated access must re-check current proof coverage");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedClaimDenied
            }
        ));
    }

    #[test]
    fn stored_delegated_attestation_rechecks_current_target_binding() {
        let config = delegated_self_attestation_config();
        let evidence = delegated_evidence_config();
        let principal = delegated_transaction_principal(&config, &evidence);
        let state = RegistryNotaryApiState::new_with_self_attestation(
            Arc::new(evidence.clone()),
            Arc::new(config),
            delegated_test_audit_hasher(),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        );
        let mut request = delegated_request();
        derive_delegated_attestation_request_context(
            &state.self_attestation,
            &state.self_attestation_rate_keys,
            &principal,
            &mut request,
        )
        .expect("delegated request context derives");
        let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
            .expect("delegated context prepares");
        let mut evaluation = evaluation_for_proof();
        evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
        evaluation.purpose = context.purpose.clone();
        evaluation.claim_ids = vec!["dependent-person-is-alive".to_string()];
        evaluation.claim_refs = request.claims.clone();
        evaluation.disclosure = context.metadata.disclosure.as_str().to_string();
        evaluation.format = context.metadata.result_format.as_str().to_string();
        evaluation.self_attestation = Some(context.metadata);
        let mut different_target = principal.clone();
        different_target
            .authorization_details
            .as_mut()
            .and_then(|details| details.target.as_mut())
            .expect("delegated authorization target exists")
            .id = "OTHER-CHILD".to_string();

        let err = require_self_attestation_stored_access(
            &state,
            &evidence,
            &different_target,
            &evaluation,
            &evaluation.claim_ids,
            &evaluation.disclosure,
            &evaluation.format,
            None,
        )
        .expect_err("stored delegated access must re-check current target binding");

        assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
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

        assert_eq!(value["status"], json!(503));
        assert_eq!(value["code"], "readiness.not_ready");
        assert_eq!(value["readiness_status"], "not_ready");
        assert_eq!(value["checks"]["signing_providers"]["total"], json!(1));
        assert_eq!(value["checks"]["signing_providers"]["ok"], json!(0));
        assert_eq!(value["checks"]["signing_providers"]["failed"], json!(1));
    }

    #[test]
    fn access_token_issuance_signer_is_in_custody_counts() {
        let mut config = classifier_config();
        config.auth.access_token_signing.enabled = true;
        config.auth.access_token_signing.signing_key_id = "access-token-key".to_string();
        config.evidence.signing_keys.insert(
            "access-token-key".to_string(),
            serde_norway::from_str(
                r#"
provider: local_jwk_env
private_jwk_env: ACCESS_TOKEN_JWK
alg: EdDSA
kid: access-token-key
status: active
"#,
            )
            .expect("signing key parses"),
        );

        let access_token = access_token_issuance_signer_counts(&config);
        assert_eq!(access_token.total, 1);
        assert_eq!(access_token.local_software, 1);
        let scoped = custody_scoped_signer_counts(&config);
        assert_eq!(scoped.total, 1);
        assert_eq!(scoped.local_software, 1);
    }

    #[tokio::test]
    async fn readiness_fails_when_source_readiness_check_fails() {
        let source = ReadinessSource {
            ready: Arc::new(AtomicBool::new(false)),
        };
        let state = Arc::new(RegistryNotaryApiState::new(
            Arc::new(evidence_config()),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::new(source),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        ));

        let response = ready(Some(Extension(state))).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("ready body reads");
        let value: Value = serde_json::from_slice(&body).expect("ready body is JSON");

        assert_eq!(value["status"], json!(503));
        assert_eq!(value["code"], "readiness.not_ready");
        assert_eq!(value["readiness_status"], "not_ready");
        assert_eq!(value["checks"]["total"], json!(2));
        assert_eq!(value["checks"]["ok"], json!(0));
        assert_eq!(value["checks"]["failed"], json!(1));
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
    fn self_attestation_token_policy_rejects_stale_auth_time() {
        let config = self_attestation_config();
        let mut principal = classify_self_attestation_principal(
            &config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims")
            .auth_time = Some(
            now - config.token_policy.max_auth_age_seconds as i64
                - config.token_policy.max_clock_leeway_seconds as i64
                - 1,
        );

        let err = require_self_attestation_token_policy(&config, &principal)
            .expect_err("stale auth_time fails closed");

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
    fn pdp_policy_denials_keep_public_stable_problem_codes() {
        let error = EvidenceError::PolicyDenied {
            code: "pdp.assurance_insufficient",
            policy_id: None,
            policy_hash: None,
            evaluated_rule_ids: Vec::new(),
        };

        assert_eq!(error.code(), "pdp.assurance_insufficient");
        assert_eq!(error.audit_code(), "pdp.assurance_insufficient");
        assert_eq!(evidence_status(&error), StatusCode::FORBIDDEN);
        assert_eq!(evidence_title(&error), "Policy decision denied");
        assert_eq!(
            evidence_detail(&error),
            "the configured policy denied the evidence request"
        );
    }

    #[test]
    fn posture_problem_response_uses_problem_json() {
        // RFC 9457 problem details must be served as application/problem+json,
        // not application/json.
        let response = posture_unavailable();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("problem response sets a content-type");
        assert_eq!(
            content_type, "application/problem+json",
            "RFC 9457 problem responses must use application/problem+json"
        );
    }

    #[test]
    fn pdp_pre_source_denial_audit_records_zero_source_and_no_forward() {
        let mut response = StatusCode::FORBIDDEN.into_response();
        attach_evidence_audit(
            &mut response,
            "evaluate_denied",
            None,
            &["person-is-alive".to_string()],
            None,
        );
        attach_zero_source_no_forward_audit(&mut response);

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(audit.source_read_count, Some(0));
        assert_eq!(audit.forwarded, Some(false));
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

    struct ReadinessSource {
        ready: Arc<AtomicBool>,
    }

    impl SourceReader for ReadinessSource {
        fn has_readiness_check(&self) -> bool {
            true
        }

        fn check_ready<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move { self.ready.load(Ordering::SeqCst) })
        }

        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async { Err(EvidenceError::SourceUnavailable) })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec!["civil_registry:evidence_verification".to_string()])
        }
    }

    #[derive(Default)]
    struct VersionScopedSource;

    impl SourceReader for VersionScopedSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async { Err(EvidenceError::SourceUnavailable) })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{claim_id}:1.0")])
        }

        fn required_scopes_for_claim(
            &self,
            _evidence: &EvidenceConfig,
            claim: &registry_notary_core::ClaimDefinition,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{}:{}", claim.id, claim.version)])
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

    struct CountingSigningProvider {
        inner: LocalJwkSigner,
        sign_count: Arc<AtomicUsize>,
    }

    impl CountingSigningProvider {
        fn new(sign_count: Arc<AtomicUsize>) -> Self {
            let mut jwk = PrivateJwk::parse(&issuer_private_jwk()).expect("issuer key parses");
            jwk.kid = Some("did:web:issuer.example#key-1".to_string());
            let inner = LocalJwkSigner::new(jwk).expect("local signer builds");
            Self { inner, sign_count }
        }
    }

    #[async_trait::async_trait]
    impl SigningProvider for CountingSigningProvider {
        fn algorithm(&self) -> registry_platform_crypto::SigningAlgorithm {
            self.inner.algorithm()
        }

        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.inner.public_jwk()
        }

        async fn sign(
            &self,
            payload: &[u8],
        ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
            self.sign_count.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(payload).await
        }
    }

    struct CountingIssuerResolver {
        sign_count: Arc<AtomicUsize>,
    }

    impl EvidenceIssuerResolver for CountingIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_signing_provider(Arc::new(
                CountingSigningProvider::new(Arc::clone(&self.sign_count)),
            ))
        }
    }

    #[tokio::test]
    async fn credential_status_list_response_is_signed_status_list_jwt() {
        let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            ..CredentialStatusConfig::default()
        })
        .expect("credential status builds");
        let issued_at = OffsetDateTime::now_utc();
        credential_status
            .record_issued(
                "credential-1".to_string(),
                "did:web:issuer.example".to_string(),
                "civil_status_sd_jwt".to_string(),
                issued_at,
                issued_at + time::Duration::seconds(600),
            )
            .await
            .expect("status record writes");
        let record = credential_status
            .get("credential-1")
            .await
            .expect("status record reads")
            .expect("status record exists");
        let state = RegistryNotaryApiState::new_with_runtime_blocks(
            Arc::new(evidence_config()),
            Arc::new(SelfAttestationConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            None,
            AuditKeyHasher::unkeyed_dev_only(),
            ReplayStores::memory(),
            credential_status,
            Arc::new(AppMetrics::default()),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(TestIssuerResolver),
            SignerReadiness::default(),
        );

        let response = credential_status_list_response(&state, &record).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/statuslist+jwt")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("status list body reads");
        let jwt = std::str::from_utf8(&body).expect("status list JWT is UTF-8");
        let header = decode_jwt_header(jwt);
        let payload = decode_jwt_payload(jwt);
        assert_eq!(header["typ"], json!("statuslist+jwt"));
        assert_eq!(header["kid"], json!("did:web:issuer.example#key-1"));
        assert_eq!(
            payload["sub"],
            json!("https://issuer.example/v1/credentials/credential-1/status")
        );
        assert_eq!(payload["ttl"], json!(300));
        assert_eq!(payload["status_list"]["bits"], json!(8));
        assert_eq!(payload["status_list"]["lst"], json!("eJxjAAAAAQAB"));
    }

    #[tokio::test]
    async fn credential_status_list_response_reuses_cached_signature() {
        let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            ..CredentialStatusConfig::default()
        })
        .expect("credential status builds");
        let issued_at = OffsetDateTime::now_utc();
        credential_status
            .record_issued(
                "credential-cache".to_string(),
                "did:web:issuer.example".to_string(),
                "civil_status_sd_jwt".to_string(),
                issued_at,
                issued_at + time::Duration::seconds(600),
            )
            .await
            .expect("status record writes");
        let record = credential_status
            .get("credential-cache")
            .await
            .expect("status record reads")
            .expect("status record exists");
        let sign_count = Arc::new(AtomicUsize::new(0));
        let state = RegistryNotaryApiState::new_with_runtime_blocks(
            Arc::new(evidence_config()),
            Arc::new(SelfAttestationConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            None,
            AuditKeyHasher::unkeyed_dev_only(),
            ReplayStores::memory(),
            credential_status,
            Arc::new(AppMetrics::default()),
            Arc::new(CountingSource::default()),
            Arc::new(EvidenceStore::default()),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
            SignerReadiness::default(),
        );

        let first = credential_status_list_response(&state, &record).await;
        let second = credential_status_list_response(&state, &record).await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(sign_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_list_jwt_cache_does_not_hold_lock_while_signing() {
        let cache = Arc::new(StatusListJwtCache::default());
        let nested_cache = Arc::clone(&cache);
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(60);

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_insert_with("outer".to_string(), now, expires_at, || async move {
                nested_cache
                    .get_or_insert_with("inner".to_string(), now, expires_at, || async {
                        Ok("inner-token".to_string())
                    })
                    .await?;
                Ok("outer-token".to_string())
            }),
        )
        .await
        .expect("cache lookup should not block behind its own signing future")
        .expect("outer token signs");

        assert_eq!(result, "outer-token");
    }

    #[test]
    fn accepts_status_list_jwt_matches_exact_media_type() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/statuslist+jwt; q=0.8"),
        );
        assert!(accepts_status_list_jwt(&headers));

        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("Application/StatusList+JWT"),
        );
        assert!(accepts_status_list_jwt(&headers));

        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/statuslist+jwt-seq"),
        );
        assert!(!accepts_status_list_jwt(&headers));
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
                        policy_hash: Some(
                            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                                .to_string(),
                        ),
                        evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
                        ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
                        ecosystem_binding_version: Some("2026-06-19".to_string()),
                        pack_id: Some("baseline-dpi/v1".to_string()),
                        pack_version: Some("2026-06-19".to_string()),
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
        let audit_request = BatchEvaluateRequest {
            items: vec![
                BatchEvaluateItemRequest {
                    requester: Some(EvidenceEntity::with_identifier(
                        "Person",
                        "national_id",
                        "NID-REQUESTER",
                    )),
                    target: EvidenceEntity::with_identifier("Person", "national_id", "NID-1"),
                    relationship: None,
                    on_behalf_of: None,
                    purpose: None,
                },
                BatchEvaluateItemRequest {
                    requester: None,
                    target: EvidenceEntity::with_identifier("Person", "national_id", "NID-2"),
                    relationship: None,
                    on_behalf_of: None,
                    purpose: None,
                },
            ],
            claims: vec![ClaimRef::from("person-is-alive")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-a".to_string()),
        };
        let evidence = EvidenceConfig::default();
        attach_evidence_audit(
            &mut response,
            "batch_evaluate",
            None,
            &["person-is-alive".to_string()],
            Some(2),
        );

        attach_batch_evaluate_response_audit(
            &mut response,
            &keys,
            &evidence,
            &audit_request,
            &result,
            None,
        )
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
        assert_eq!(
            items[0].ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(
            items[0].ecosystem_binding_version.as_deref(),
            Some("2026-06-19")
        );
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
    fn batch_audit_preserves_policy_identity_for_matching_policy_rejections() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let evidence: EvidenceConfig = serde_json::from_value(json!({
            "enabled": true,
            "ecosystem_bindings": {
                "baseline-dpi/v1": {
                    "profile": "odrl:v1",
                    "policy_id": "baseline-dpi-policy",
                    "policy_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "2026-06",
                "subject_type": "person",
                "source_bindings": {
                    "aa_wrong": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "sources.aa_wrong.alive",
                            "field": "alive",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": {
                                "policy_id": "wrong-policy",
                                "policy_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            }
                        }
                    },
                    "zz_civil": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": { "id": "baseline-dpi/v1" }
                        }
                    }
                },
                "rule": { "type": "extract", "source": "zz_civil", "field": "alive" }
            }]
        }))
        .expect("evidence config parses");
        let request = BatchEvaluateRequest {
            items: vec![BatchEvaluateItemRequest {
                requester: None,
                target: EvidenceEntity::with_identifier("person", "national_id", "NID-TARGET"),
                relationship: None,
                on_behalf_of: None,
                purpose: Some("program-a".to_string()),
            }],
            claims: vec![ClaimRef::with_version("person-is-alive", "2026-06")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        };
        let result = registry_notary_core::BatchEvaluateResponse {
            batch_id: "batch-1".to_string(),
            status: registry_notary_core::BatchStatus::Completed,
            claims: vec!["person-is-alive".to_string()],
            items: vec![registry_notary_core::BatchItemResponse {
                input_index: 0,
                target_ref: registry_notary_core::TargetRefView {
                    entity_type: "person".to_string(),
                    handle: "rnref:v1:target-handle".to_string(),
                    identifier_schemes: vec!["national_id".to_string()],
                    profile: None,
                },
                requester_ref: None,
                matching: None,
                evaluation_id: None,
                status: registry_notary_core::BatchItemStatus::Failed,
                claim_results: Vec::new(),
                errors: vec![registry_notary_core::BatchItemError {
                    code: "target.matching_policy_rejected".to_string(),
                    title: "Target matching policy rejected".to_string(),
                    retryable: false,
                    audit_code: None,
                }],
            }],
            summary: registry_notary_core::BatchSummary {
                succeeded: 0,
                failed: 1,
            },
        };
        let mut response = StatusCode::OK.into_response();
        attach_evidence_audit(
            &mut response,
            "batch_evaluate",
            None,
            &["person-is-alive".to_string()],
            Some(1),
        );

        attach_batch_evaluate_response_audit(
            &mut response,
            &keys,
            &evidence,
            &request,
            &result,
            None,
        )
        .expect("batch audit context attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        let item = audit
            .batch_items
            .as_ref()
            .and_then(|items| items.first())
            .expect("batch item audit is captured");
        assert_eq!(item.matching_outcome.as_deref(), Some("error"));
        assert_eq!(
            item.matching_error_code.as_deref(),
            Some("target.matching_policy_rejected")
        );
        assert_eq!(
            item.matching_policy_id.as_deref(),
            Some("baseline-dpi-policy")
        );
        assert_eq!(
            item.matching_policy_hash.as_ref().map(Hashed::as_str),
            Some("sha256:3333333333333333333333333333333333333333333333333333333333333333")
        );
        assert_eq!(
            item.matching_evaluated_rule_ids.as_deref(),
            Some(&["source-binding-policy:person".to_string()][..])
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
            policy_hash: Some(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ),
            evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
            ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
            ecosystem_binding_version: Some("2026-06-19".to_string()),
            pack_id: Some("baseline-dpi/v1".to_string()),
            pack_version: Some("2026-06-19".to_string()),
        });
        let mut response = StatusCode::OK.into_response();
        attach_evidence_audit(
            &mut response,
            "evaluate",
            Some("eval-1".to_string()),
            &["person-is-alive".to_string()],
            Some(1),
        );

        attach_evaluate_request_audit(&mut response, &keys, &request, Some(&result), None, None)
            .expect("audit context attaches");

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(
            audit.purposes.as_deref(),
            Some(&["program-a".to_string()][..])
        );
        assert_eq!(audit.target_type.as_deref(), Some("Person"));
        assert_eq!(audit.requester_type.as_deref(), Some("Person"));
        assert_eq!(audit.matching_policy_id.as_deref(), Some("policy-v1"));
        assert_eq!(
            audit.matching_policy_hash.as_ref().map(Hashed::as_str),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(
            audit.matching_evaluated_rule_ids.as_deref(),
            Some(&["source-binding-policy:person".to_string()][..])
        );
        assert_eq!(
            audit.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(
            audit.ecosystem_binding_version.as_deref(),
            Some("2026-06-19")
        );
        assert_eq!(audit.pack_id.as_deref(), Some("baseline-dpi/v1"));
        assert_eq!(audit.pack_version.as_deref(), Some("2026-06-19"));
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
    fn redacted_fields_audit_unions_all_result_redactions() {
        let mut response = StatusCode::OK.into_response();
        attach_evidence_audit(
            &mut response,
            "evaluate",
            Some("eval-1".to_string()),
            &["opencrvs-age-band".to_string(), "opencrvs-sex".to_string()],
            Some(1),
        );
        let mut age_band = claim_result_view("eval-1", "opencrvs-age-band");
        age_band.disclosure = "redacted".to_string();
        age_band.redacted_fields = vec!["opencrvs-age-band".to_string()];
        let mut sex = claim_result_view("eval-1", "opencrvs-sex");
        sex.disclosure = "redacted".to_string();
        sex.redacted_fields = vec!["opencrvs-sex".to_string()];

        attach_redacted_fields_audit(&mut response, &[sex, age_band]);

        let audit = response
            .extensions()
            .get::<EvidenceAuditContext>()
            .expect("audit context is attached");
        assert_eq!(
            audit.redacted_fields.as_deref(),
            Some(&["opencrvs-age-band".to_string(), "opencrvs-sex".to_string()][..])
        );
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
            policy_hash: None,
            evaluated_rule_ids: Vec::new(),
            ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
            ecosystem_binding_version: Some("2026-06-19".to_string()),
            pack_id: Some("baseline-dpi/v1".to_string()),
            pack_version: Some("2026-06-19".to_string()),
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
                purposes: Some(vec!["citizen_self_attestation".to_string()]),
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
        assert_eq!(
            audit.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(
            audit.ecosystem_binding_version.as_deref(),
            Some("2026-06-19")
        );
        assert_eq!(audit.pack_id.as_deref(), Some("baseline-dpi/v1"));
        assert_eq!(audit.pack_version.as_deref(), Some("2026-06-19"));
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
            Some("target.matching_policy_rejected"),
            Some(&MatchingPolicyAuditIdentity {
                policy_id: "notary.source_binding.default.civil.person".to_string(),
                policy_hash:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ecosystem_binding_id: None,
                ecosystem_binding_version: None,
                pack_id: None,
                pack_version: None,
                evaluated_rule_ids: vec!["source-binding-policy:person".to_string()],
            }),
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
            Some("target.matching_policy_rejected")
        );
        assert_eq!(
            audit.matching_policy_id.as_deref(),
            Some("notary.source_binding.default.civil.person")
        );
        assert_eq!(
            audit.matching_policy_hash.as_ref().map(Hashed::as_str),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(
            audit.matching_evaluated_rule_ids.as_deref(),
            Some(&["source-binding-policy:person".to_string()][..])
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

    #[test]
    fn denied_matching_policy_audit_identity_uses_requested_claim_binding() {
        let evidence: EvidenceConfig = serde_json::from_value(json!({
            "enabled": true,
            "ecosystem_bindings": {
                "baseline-dpi/v1": {
                    "profile": "odrl:v1",
                    "policy_id": "baseline-dpi-policy",
                    "policy_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "2026-06",
                "subject_type": "person",
                "source_bindings": {
                    "aa_wrong": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": {
                                "policy_id": "wrong-policy",
                                "policy_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            }
                        }
                    },
                    "zz_civil": {
                        "connector": "registry_data_api",
                        "dataset": "civil",
                        "entity": "person",
                        "lookup": {
                            "input": "target.identifiers.national_id",
                            "field": "national_id",
                            "op": "eq",
                            "cardinality": "one"
                        },
                        "fields": {
                            "alive": {
                                "field": "alive",
                                "type": "boolean",
                                "required": true
                            }
                        },
                        "matching": {
                            "ecosystem_binding": { "id": "baseline-dpi/v1" }
                        }
                    }
                },
                "rule": { "type": "extract", "source": "zz_civil", "field": "alive" }
            }]
        }))
        .expect("evidence config parses");
        let request = EvaluateRequest {
            requester: None,
            target: Some(EvidenceEntity::with_identifier(
                "person",
                "national_id",
                "NID-TARGET",
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::with_version("person-is-alive", "2026-06")],
            disclosure: None,
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-a".to_string()),
        };

        let policy = denied_matching_policy_audit_identity(
            &evidence,
            &request,
            Some("pdp.assurance_insufficient"),
        )
        .expect("matching policy identity is resolved");

        assert_eq!(policy.policy_id, "baseline-dpi-policy");
        assert_eq!(
            policy.policy_hash,
            "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(
            policy.evaluated_rule_ids,
            vec!["source-binding-policy:person".to_string()]
        );
        assert_eq!(
            policy.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
        assert_eq!(policy.pack_id.as_deref(), Some("baseline-dpi/v1"));
        assert_eq!(policy.pack_version.as_deref(), Some("v1"));
        assert!(
            denied_matching_policy_audit_identity(
                &evidence,
                &request,
                Some("target.matching_policy_rejected")
            )
            .is_some(),
            "legacy matching policy denials still carry policy provenance"
        );
        assert!(
            denied_matching_policy_audit_identity(&evidence, &request, Some("auth.scope_denied"))
                .is_none(),
            "non-matching errors must not claim matching policy provenance"
        );
        assert!(
            denied_matching_policy_audit_identity(
                &evidence,
                &request,
                Some("target.attributes_insufficient")
            )
            .is_none(),
            "pre-policy input errors must not claim PDP provenance"
        );
        assert!(
            denied_matching_policy_audit_identity(&evidence, &request, Some("purpose.not_allowed"))
                .is_none(),
            "purpose denials happen before PDP matching policy evaluation"
        );
    }

    #[test]
    fn matching_policy_audit_identity_from_error_uses_pdp_audit_payload() {
        let mut evidence = EvidenceConfig::default();
        evidence.ecosystem_bindings.insert(
            "baseline-dpi/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "actual-policy".to_string(),
                policy_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );
        let error = EvidenceError::PolicyDenied {
            code: "pdp.assurance_insufficient",
            policy_id: Some("actual-policy".to_string()),
            policy_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            evaluated_rule_ids: vec!["actual-rule".to_string()],
        };

        let policy = matching_policy_audit_identity_from_error(&evidence, &error)
            .expect("PDP error audit identity is available");

        assert_eq!(policy.policy_id, "actual-policy");
        assert_eq!(
            policy.policy_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(policy.evaluated_rule_ids, vec!["actual-rule".to_string()]);
        assert_eq!(
            policy.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
        assert_eq!(policy.pack_id.as_deref(), Some("baseline-dpi/v1"));
        assert_eq!(policy.pack_version.as_deref(), Some("v1"));
    }

    #[test]
    fn merge_matching_policy_audit_identity_preserves_pdp_rules_and_adds_binding() {
        let policy = merge_matching_policy_audit_identity(
            Some(MatchingPolicyAuditIdentity {
                policy_id: "actual-policy".to_string(),
                policy_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ecosystem_binding_id: None,
                ecosystem_binding_version: None,
                pack_id: None,
                pack_version: None,
                evaluated_rule_ids: vec!["actual-rule".to_string()],
            }),
            Some(MatchingPolicyAuditIdentity {
                policy_id: "selected-policy".to_string(),
                policy_hash:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                ecosystem_binding_id: Some("baseline-dpi/v1".to_string()),
                ecosystem_binding_version: Some("v1".to_string()),
                pack_id: Some("baseline-dpi/v1".to_string()),
                pack_version: Some("v1".to_string()),
                evaluated_rule_ids: vec!["selected-rule".to_string()],
            }),
        )
        .expect("merged policy exists");

        assert_eq!(policy.policy_id, "actual-policy");
        assert_eq!(
            policy.policy_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(policy.evaluated_rule_ids, vec!["actual-rule".to_string()]);
        assert_eq!(
            policy.ecosystem_binding_id.as_deref(),
            Some("baseline-dpi/v1")
        );
        assert_eq!(policy.ecosystem_binding_version.as_deref(), Some("v1"));
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

    fn test_federation_runtime(generation: &str) -> Arc<crate::federation::FederationRuntimeState> {
        let secret_env = format!(
            "TEST_ATOMIC_FEDERATION_SECRET_{}",
            generation.to_uppercase()
        );
        std::env::set_var(&secret_env, format!("{generation}-pairwise-secret"));
        let federation: FederationConfig = serde_norway::from_str(&format!(
            r#"
enabled: true
node_id: did:web:{generation}.notary.example
issuer: https://{generation}.notary.example
jwks_uri: https://{generation}.notary.example/federation/jwks.json
federation_api: https://{generation}.notary.example/federation/v1
supported_protocol_versions:
  - registry-notary-federation/v0.1
signing:
  signing_key: federation-key
pairwise_subject_hash:
  secret_env: {secret_env}
replay:
  storage: in_process_single_instance_only
  max_entries: 100
  eviction: expire_oldest
response_shaping:
  minimum_denial_latency_ms: 1
peers:
  - node_id: did:web:peer.{generation}.example
    issuer: https://peer.{generation}.example
    jwks_uri: http://127.0.0.1:9/{generation}/jwks.json
    allow_insecure_localhost: true
    allowed_protocol_versions:
      - registry-notary-federation/v0.1
    allowed_purposes:
      - https://purpose.example.test/eligibility
    allowed_profiles:
      - person_alive
    source_scopes:
      - civil_registry:evidence_verification
evaluation_profiles:
  - id: person_alive
    ruleset: person-alive-v1
    claim_id: person-is-alive
    subject_id_type: national_id
"#
        ))
        .expect("federation config parses");
        let signer_jwk = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": format!("{generation}-federation-key"),
                "d": ISSUER_PRIV_D_B64,
                "x": ISSUER_PUB_X_B64,
                "alg": "EdDSA"
            })
            .to_string(),
        )
        .expect("federation signer JWK parses");
        let signer: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(signer_jwk).expect("federation signer builds"));
        Arc::new(
            crate::federation::FederationRuntimeState::from_config(
                &federation,
                signer,
                None,
                ReplayStores::memory().store(),
                Arc::new(AppMetrics::default()),
            )
            .expect("federation runtime builds"),
        )
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
            claim_refs: Vec::new(),
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
            redacted_fields: Vec::new(),
            format: FORMAT_SD_JWT_VC.to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: registry_notary_core::ClaimProvenance::new(
                "test".to_string(),
                "eval-test".to_string(),
                "claim".to_string(),
                "1".to_string(),
                registry_notary_core::ProvenanceUsed {
                    source_count: 0,
                    source_versions: std::collections::BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
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

    fn decode_jwt_header(jwt: &str) -> Value {
        decode_jwt_segment(jwt, 0)
    }

    fn decode_jwt_payload(jwt: &str) -> Value {
        decode_jwt_segment(jwt, 1)
    }

    fn decode_jwt_segment(jwt: &str, index: usize) -> Value {
        let segment = jwt.split('.').nth(index).expect("jwt segment exists");
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segment)
                .expect("jwt segment is base64url"),
        )
        .expect("jwt segment is JSON")
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
            claim_refs: Vec::new(),
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
            authorization_details: None,
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
                purpose: None,
                holder: Some(HolderRequest {
                    binding: Some("did".to_string()),
                    id: Some(holder_did_jwk()),
                    proof: None,
                }),
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

    #[tokio::test]
    async fn issue_credential_rejects_purpose_mismatch() {
        let evidence = credential_issue_evidence_config();
        let store = Arc::new(EvidenceStore::default());
        let sign_count = Arc::new(AtomicUsize::new(0));
        store.insert(registry_notary_core::StoredEvaluation {
            client_id: "caseworker".to_string(),
            purpose: "benefits".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            claim_refs: Vec::new(),
            disclosure: "predicate".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: vec![claim_result_view(
                "eval-purpose-mismatch",
                "person-is-alive",
            )],
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            self_attestation: None,
        });
        let state = Arc::new(
            RegistryNotaryApiState::new_with_federation(
                Arc::new(evidence),
                Arc::new(SelfAttestationConfig::default()),
                Arc::new(Oid4vciConfig::default()),
                Arc::new(FederationConfig::default()),
                AuditKeyHasher::unkeyed_dev_only(),
                None,
                ReplayStores::memory(),
                CredentialStatusStore::disabled(),
                Arc::new(AppMetrics::default()),
                Arc::new(CountingSource::default()),
                Arc::clone(&store),
                Arc::new(CountingIssuerResolver {
                    sign_count: Arc::clone(&sign_count),
                }),
                None,
            )
            .expect("state builds"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let response = issue_credential(
            HeaderMap::new(),
            Some(Extension(state)),
            Some(Extension(principal)),
            Ok(Json(CredentialIssueRequest {
                evaluation_id: "eval-purpose-mismatch".to_string(),
                credential_profile: Some("civil_status_sd_jwt".to_string()),
                format: Some(FORMAT_SD_JWT_VC.to_string()),
                claims: Some(vec!["person-is-alive".to_string()]),
                disclosure: Some("predicate".to_string()),
                purpose: Some("appeals".to_string()),
                holder: None,
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let body: Value = serde_json::from_slice(&body).expect("problem body parses");
        assert_eq!(body["code"], json!("evaluation.binding_mismatch"));
        assert_eq!(
            sign_count.load(Ordering::SeqCst),
            0,
            "purpose mismatch must be denied before credential signing"
        );
    }

    #[test]
    fn evaluation_access_uses_stored_claim_version_scope() {
        let mut evidence = evidence_config();
        let mut older_claim = evidence.claims[0].clone();
        older_claim.version = "1.0".to_string();
        let mut newer_claim = older_claim.clone();
        newer_claim.version = "2.0".to_string();
        evidence.claims = vec![older_claim, newer_claim];
        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "caseworker".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            claim_refs: vec![ClaimRef::with_version("person-is-alive", "2.0")],
            disclosure: "predicate".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            self_attestation: None,
        };
        let source = VersionScopedSource;
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["person-is-alive:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let err = require_evaluation_access(&evidence, &source, &principal, &evaluation)
            .expect_err("version 1 scope must not authorize stored version 2 evaluation");
        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "person-is-alive:2.0"
        ));

        let principal = EvidencePrincipal {
            scopes: vec!["person-is-alive:2.0".to_string()],
            ..principal
        };
        require_evaluation_access(&evidence, &source, &principal, &evaluation)
            .expect("version 2 scope authorizes stored version 2 evaluation");
    }

    fn issue_request() -> CredentialIssueRequest {
        CredentialIssueRequest {
            evaluation_id: "eval-1".to_string(),
            credential_profile: Some("profile-a".to_string()),
            format: None,
            claims: None,
            disclosure: None,
            purpose: None,
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
