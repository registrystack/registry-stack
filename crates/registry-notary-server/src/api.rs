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
mod state;
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
#[cfg(test)]
use state::{ApiRuntimeSnapshot, IssuerRuntimeBundle};
pub use state::{EvidenceIssuerResolver, RegistryNotaryApiState};

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
    EvaluateRequest, EvaluationCapability, EvidenceActor, EvidenceAuditEvent,
    EvidenceBatchItemAuditEvent, EvidenceConfig, EvidenceEntity, EvidenceEntityReference,
    EvidenceError, EvidenceOnBehalfOf, EvidencePrincipal, EvidenceRelationship, FederationConfig,
    Hashed, HolderRequest, Oid4vciConfig, Oid4vciCredentialClaimMode,
    Oid4vciCredentialConfigurationConfig, Oid4vciDisplayImageConfig, Oid4vciIssuerDisplayConfig,
    PolicyIdentifier, RateLimitBucket, RegistryNotaryAdminListenerMode, RenderEvaluationRequest,
    SelfAttestationConfig, SelfAttestationDelegatedRelationshipConfig, SelfAttestationDenialCode,
    SelfAttestationScopePolicy, StandaloneRegistryNotaryConfig, StoredSelfAttestationMetadata,
    SubjectRequest, VerifiedClaimValue, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
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
    preauth_state::{LoginState, PreauthorizationStateError},
    replay::{require_replay_insert, ReplayReadiness, ReplayStores},
    runtime::{
        claim_ids, claim_semantics_metadata, validate_batch_subject_limit, EvaluationAuditSnapshot,
    },
    standalone::{
        generate_numeric_tx_code, generate_opaque_token, pkce_s256_challenge, pre_auth_audit_event,
        AuthAuditState, PreAuthAuditFields, PreAuthRuntime, SignerReadiness,
    },
    BatchEvaluateOptions, EvidenceStore, MachineQuotaLimiter, RegistryNotaryRuntime,
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter,
};

pub(crate) use crate::digest::evidence_claim_hash;
use crate::digest::{sha256_canonical_json, sha256_json};
pub(crate) use crate::problem::{evidence_detail, evidence_status, evidence_title};
pub use crate::response_context::{EvidenceAuditContext, EvidenceErrorCodeContext};
pub use oid4vci::oid4vci_proof_precheck_middleware;

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

#[cfg(test)]
mod tests;
