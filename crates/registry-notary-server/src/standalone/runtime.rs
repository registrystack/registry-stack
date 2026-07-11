// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary assembly, auth, audit, and HTTP source connectors.

#[path = "sidecar_assurance.rs"]
mod sidecar_assurance;
#[path = "signing/mod.rs"]
mod signing;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Mutex, OnceCell, Semaphore};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::Algorithm;
use registry_notary_core::deployment::{
    evaluate_gates, EvaluatedFinding, EvaluatedWaiver, GateEvaluation,
};
use registry_notary_core::sd_jwt::EvidenceIssuer;
use registry_notary_core::{
    AccessMode, BoundedCorrelationId, BoundedVerifiedClaims, BulkMode, ConfigAuditEvent,
    DciSourceConnectionConfig, EvidenceAuditEvent, EvidenceAuthMode, EvidenceAuthorizationDetails,
    EvidenceConfig, EvidenceCredentialConfig, EvidenceEntity, EvidenceError, EvidencePrincipal,
    EvidenceRequestContext, ExpectedSidecarConfig, Hashed, Oauth2ClientCredentialsSourceAuthConfig,
    PrincipalIdentifier, RateLimitBucket, RegistryNotaryAdminListenerMode, RequestIdentifier,
    SelfAttestationAssuranceClaimSource, SelfAttestationClaimSource, SelfAttestationDenialCode,
    SigningKeyConfig, SigningKeyProviderConfig, SourceAuthConfig, SourceBindingConfig,
    SourceConnectionConfig, SourceConnectorKind, SourceRuntimeAssurance, SourceRuntimeSummary,
    StandaloneRegistryNotaryConfig, SubjectRequest, VerifiedClaimName, VerifiedClaimValue,
    SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR,
};
use registry_platform_audit::{
    AuditError, AuditKeyHasher, AuditProfile, AuditSink as PlatformAuditSink, ChainState,
    JsonlFileSink, JsonlStdoutSink, SyslogSink,
};
use registry_platform_authcommon::{
    parse_bearer_token, verify_api_key, CredentialFingerprintRefError, FingerprintFormatError,
};
use registry_platform_crypto::{
    sign, verify, KeyReadiness, LocalJwkSigner, PrivateJwk, PublicJwk, SigningProvider,
};
use registry_platform_httputil::{
    read_bounded, url as httputil_url, FetchUrlError, FetchUrlPolicy, ValidatedFetchUrl,
};
use registry_platform_oidc::{
    fetch_userinfo_jwt_with_policy, Audience, JwksFetcher, JwksFetcherConfig, OidcError,
    TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use registry_platform_ops::{AckObservation, ConfigProvenance, ConfigSource};
use registry_platform_replay::{ReplayKey, ReplayScope};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use ulid::Ulid;
use zeroize::Zeroizing;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::{CelWorker, CelWorkerConfig};
#[cfg(feature = "registry-notary-cel")]
use crate::runtime::validate_cel_claims_for_startup;
use crate::{
    api::METRICS_SCOPE,
    config_governed::ConfigGovernanceContext,
    credential_status::{CredentialStatusBuildError, CredentialStatusStore},
    metrics::{metrics_handler, metrics_middleware, AppMetrics},
    posture::PostureContext,
    replay::{require_replay_insert, ReplayBuildError, ReplayStores},
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver, EvidenceStore,
    RegistryNotaryApiState, SelfAttestationRateLimitKeys, SelfAttestationRateLimiter, SourceReader,
};

#[path = "assembly.rs"]
mod assembly;
#[path = "auth/mod.rs"]
mod auth;
#[path = "connectors/mod.rs"]
mod connectors;
#[path = "cors.rs"]
mod cors;
#[path = "deployment.rs"]
mod deployment;
#[path = "preauth.rs"]
mod preauth;
#[path = "sources/mod.rs"]
mod sources;
#[path = "transport/mod.rs"]
mod transport;

pub use assembly::*;
use auth::*;
pub use auth::{find_credential, ResolvedCredential};
pub(crate) use auth::{AuditPipeline, AuthAuditState};
use connectors::*;
use cors::*;
pub(crate) use deployment::*;
use preauth::*;
pub(crate) use preauth::{
    constant_time_eq, generate_numeric_tx_code, generate_opaque_token, pkce_s256_challenge,
    pre_auth_audit_event, PreAuthAuditFields, PreAuthRuntime,
};
use sidecar_assurance::*;
pub use signing::providers::EvidenceIssuerRegistry;
use signing::providers::*;
pub(crate) use signing::providers::{signing_key_public_jwk_from_config, SignerReadiness};
pub use sources::HttpEvidenceSources;
use sources::*;
pub(crate) use transport::audit_error_response;
use transport::*;

const SOURCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const FILE_WATCH_METADATA_CHECK_INTERVAL: Duration = Duration::from_millis(250);
const MAX_REQUEST_URI_BYTES: usize = 8 * 1024;
const MAX_SOURCE_JSON_BYTES: usize = 1024 * 1024;
const MAX_INBOUND_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const PREAUTH_LOGIN_STATE_MAX_ENTRIES: usize = 4096;
const SELF_ATTESTATION_CORS_METHODS: &str = "GET,POST,OPTIONS";
const OIDC_ID_TOKEN_HEADER: &str = "x-registry-notary-oidc-id-token";
const SELF_ATTESTATION_CORS_DEFAULT_HEADERS: &str =
    "authorization,content-type,x-registry-notary-oidc-id-token";
const DEPLOYMENT_PROFILE_REQUIRED_ACTION: &str =
    "set deployment.profile: local for development, or production/evidence_grade for deployment";
#[cfg(test)]
mod tests {
    include!("tests/support.inc");
    include!("tests/assembly.inc");
    include!("tests/auth.inc");
    include!("tests/audit.inc");
    include!("tests/preauth.inc");
    include!("tests/signing.inc");
    include!("tests/sources_transport.inc");
}
