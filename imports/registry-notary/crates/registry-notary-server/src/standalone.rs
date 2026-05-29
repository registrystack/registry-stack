// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary assembly, auth, audit, and HTTP source connectors.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OnceCell, Semaphore};

use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::Algorithm;
use registry_notary_core::sd_jwt::EvidenceIssuer;
use registry_notary_core::{
    AccessMode, BoundedCorrelationId, BoundedVerifiedClaims, BulkMode, DciSourceConnectionConfig,
    EvidenceAuditEvent, EvidenceConfig, EvidenceCredentialConfig, EvidenceError, EvidencePrincipal,
    Hashed, Oauth2ClientCredentialsSourceAuthConfig, PrincipalIdentifier, RateLimitBucket,
    SelfAttestationAssuranceClaimSource, SelfAttestationClaimSource, SelfAttestationDenialCode,
    SigningKeyConfig, SigningKeyProviderConfig, SourceAuthConfig, SourceBindingConfig,
    SourceConnectionConfig, SourceConnectorKind, StandaloneRegistryNotaryConfig, SubjectRequest,
    VerifiedClaimName, VerifiedClaimValue,
};
use registry_platform_audit::{
    AuditError, AuditKeyHasher, AuditSink as PlatformAuditSink, ChainState, JsonlFileSink,
    JsonlStdoutSink, SyslogSink,
};
use registry_platform_authcommon::{
    parse_bearer_token, parse_fingerprint, verify_api_key, FingerprintFormatError,
};
use registry_platform_crypto::{
    sign, verify, LocalJwkSigner, PrivateJwk, PublicJwk, SigningProvider,
};
use registry_platform_httputil::{
    read_bounded, url as httputil_url, FetchUrlPolicy, OutboundClientBuilder,
};
use registry_platform_oidc::{
    fetch_userinfo_jwt_with_policy, Audience, JwksFetcher, JwksFetcherConfig, OidcError,
    TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    credential_status::{CredentialStatusBuildError, CredentialStatusStore},
    metrics::{metrics_handler, metrics_middleware, AppMetrics},
    replay::{ReplayBuildError, ReplayStores},
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver, EvidenceStore,
    RegistryNotaryApiState, SelfAttestationRateLimitKeys, SelfAttestationRateLimiter, SourceReader,
};

const SOURCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SOURCE_JSON_BYTES: usize = 1024 * 1024;
const MAX_INBOUND_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const SELF_ATTESTATION_CORS_METHODS: &str = "GET,POST,OPTIONS";
const OIDC_ID_TOKEN_HEADER: &str = "x-registry-notary-oidc-id-token";
const SELF_ATTESTATION_CORS_DEFAULT_HEADERS: &str =
    "authorization,content-type,x-registry-notary-oidc-id-token";

tokio::task_local! {
    static REQUEST_CORRELATION_ID: BoundedCorrelationId;
}

pub(crate) async fn with_request_correlation_id<F>(
    correlation_id: BoundedCorrelationId,
    future: F,
) -> F::Output
where
    F: Future,
{
    REQUEST_CORRELATION_ID.scope(correlation_id, future).await
}

pub fn standalone_router(
    config: StandaloneRegistryNotaryConfig,
) -> Result<Router, StandaloneServerError> {
    config.validate()?;
    let evidence = Arc::new(config.evidence.clone());
    let self_attestation = Arc::new(config.self_attestation.clone());
    let oid4vci = Arc::new(config.oid4vci.clone());
    let federation = Arc::new(config.federation.clone());
    let metrics = Arc::new(AppMetrics::default());
    let replay = ReplayStores::from_config(&config.replay)?;
    let credential_status = CredentialStatusStore::from_config(&config.credential_status)?;
    if config.federation.enabled
        && config.replay.storage == registry_notary_core::REPLAY_STORAGE_IN_MEMORY
    {
        tracing::warn!(
            target: "registry_notary::federation",
            "replay store is in-memory single-instance only; do not deploy federation active-active"
        );
    }
    let source = Arc::new(HttpEvidenceSources::from_config(
        &config.evidence,
        Arc::clone(&metrics),
    )?);
    let store = Arc::new(EvidenceStore::default());
    let signing_keys = Arc::new(SigningKeyRegistry::from_config(&config.evidence)?);
    let issuers = Arc::new(EvidenceIssuerRegistry::from_signing_keys(
        &config.evidence,
        &signing_keys,
    )?);
    let federation_signing_provider = if config.federation.enabled {
        Some(
            signing_keys
                .signing_provider(config.federation.signing.signing_key.as_str())
                .ok_or_else(|| {
                    invalid_signing_key(
                        config.federation.signing.signing_key.as_str(),
                        "active federation signing key was not built",
                    )
                })?,
        )
    } else {
        None
    };
    let cors_policy = registry_platform_httpsec::CorsPolicy {
        allowed_origins: config.server.cors.allowed_origins.clone(),
        allowed_methods: Vec::new(),
        allowed_headers: Vec::new(),
        allow_credentials: config.server.cors.allow_credentials,
    };
    cors_policy.validate()?;
    let wallet_cors_policy = SelfAttestationWalletCorsPolicy::from_config(&config);
    let auth_state = Arc::new(AuthAuditState::from_config(&config, Arc::clone(&metrics))?);
    let api_state = Arc::new(RegistryNotaryApiState::new_with_federation(
        evidence,
        self_attestation,
        oid4vci,
        federation,
        auth_state.audit.hasher.clone(),
        config.federation.enabled.then(|| auth_state.audit.clone()),
        replay,
        credential_status,
        Arc::clone(&metrics),
        source,
        store,
        issuers,
        federation_signing_provider,
    )?);
    let mut routes = router();
    if config.federation.enabled {
        routes = routes.merge(crate::api::federation_router());
    }
    routes = routes.route(
        "/metrics",
        get(metrics_handler).with_state(Arc::clone(&metrics)),
    );

    Ok(routes
        .layer(from_fn_with_state(Arc::clone(&metrics), metrics_middleware))
        .layer(axum::Extension(Arc::clone(&api_state)))
        .layer(from_fn_with_state(auth_state, auth_audit_middleware))
        .layer(from_fn_with_state(
            api_state,
            crate::api::oid4vci_proof_precheck_middleware,
        ))
        .layer(registry_platform_httpsec::security_headers(
            registry_platform_httpsec::CspBuilder::restrictive(),
        ))
        .layer(cors_policy.layer())
        .layer(from_fn_with_state(
            wallet_cors_policy,
            self_attestation_wallet_cors_middleware,
        ))
        .layer(registry_platform_httpsec::corp_conditional())
        .layer(registry_platform_httpsec::request_body_limit(
            MAX_INBOUND_REQUEST_BODY_BYTES,
        ))
        .layer(axum::middleware::from_fn(rewrite_payload_too_large_problem)))
}

#[derive(Debug, Clone)]
struct SelfAttestationWalletCorsPolicy {
    enabled: bool,
    allowed_origins: Vec<String>,
    allow_credentials: bool,
}

impl SelfAttestationWalletCorsPolicy {
    fn from_config(config: &StandaloneRegistryNotaryConfig) -> Self {
        Self {
            enabled: config.self_attestation.enabled,
            allowed_origins: config.self_attestation.allowed_wallet_origins.clone(),
            allow_credentials: config.server.cors.allow_credentials,
        }
    }

    fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|allowed| allowed.as_str() == origin)
    }
}

async fn self_attestation_wallet_cors_middleware(
    State(policy): State<SelfAttestationWalletCorsPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.enabled || !is_self_attestation_wallet_cors_path(request.uri().path()) {
        return next.run(request).await;
    }

    let origin = request.headers().get(header::ORIGIN).cloned();
    let Some(origin) = origin else {
        return next.run(request).await;
    };
    let origin_allowed = origin
        .to_str()
        .is_ok_and(|origin| policy.allows_origin(origin));
    let requested_headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    if is_preflight {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if origin_allowed {
            apply_self_attestation_wallet_cors_headers(
                response.headers_mut(),
                origin,
                requested_headers.as_ref(),
                policy.allow_credentials,
            );
        }
        return response;
    }

    let mut response = next.run(request).await;
    if origin_allowed {
        apply_self_attestation_wallet_cors_headers(
            response.headers_mut(),
            origin,
            requested_headers.as_ref(),
            policy.allow_credentials,
        );
    } else {
        remove_access_control_headers(response.headers_mut());
    }
    response
}

fn is_self_attestation_wallet_cors_path(path: &str) -> bool {
    matches!(
        path,
        "/.well-known/evidence-service"
            | "/.well-known/evidence/jwks.json"
            | "/.well-known/openid-credential-issuer"
            | "/oid4vci/credential-offer"
            | "/oid4vci/nonce"
            | "/oid4vci/credential"
            | "/formats"
            | "/evidence/render"
            | "/credentials/issue"
    ) || path == "/claims"
        || path.starts_with("/claims/")
        || path.starts_with("/credentials/status/")
}

fn apply_self_attestation_wallet_cors_headers(
    headers: &mut HeaderMap,
    origin: HeaderValue,
    requested_headers: Option<&HeaderValue>,
    allow_credentials: bool,
) {
    remove_access_control_headers(headers);
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(SELF_ATTESTATION_CORS_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        requested_headers
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static(SELF_ATTESTATION_CORS_DEFAULT_HEADERS)),
    );
    if allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "origin, access-control-request-method, access-control-request-headers",
        ),
    );
}

fn remove_access_control_headers(headers: &mut HeaderMap) {
    headers.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.remove(header::ACCESS_CONTROL_ALLOW_METHODS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_HEADERS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
}

#[derive(Debug, thiserror::Error)]
pub enum StandaloneServerError {
    #[error(transparent)]
    Config(#[from] registry_notary_core::EvidenceConfigError),
    #[error("configured credential environment variable is missing or empty: {0}")]
    MissingCredentialEnv(String),
    #[error(
        "configured credential hash environment variable contains an invalid fingerprint: {0}"
    )]
    InvalidCredentialHash(String, #[source] FingerprintFormatError),
    #[error("configured source token environment variable is missing or empty: {0}")]
    MissingSourceTokenEnv(String),
    #[error("invalid source auth configuration: {0}")]
    InvalidSourceAuth(String),
    #[error("signing key '{key}' is invalid: {reason}")]
    InvalidSigningKey { key: String, reason: String },
    #[error("signing key provider '{provider}' is not enabled")]
    SigningKeyProviderUnavailable { provider: String },
    #[error("federation secret environment variable is missing or empty: {0}")]
    MissingFederationSecretEnv(String),
    #[error("audit sink path is required when sink=file or sink=jsonl")]
    MissingAuditPath,
    #[error("audit.hash_secret_env is required")]
    MissingAuditHashSecretEnv,
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Cors(#[from] registry_platform_httpsec::CorsValidationError),
    #[error("unsupported audit sink: {0}")]
    InvalidAuditSink(String),
    #[error("invalid audit configuration: {0}")]
    InvalidAuditConfig(String),
    #[error(transparent)]
    Replay(#[from] ReplayBuildError),
    #[error(transparent)]
    CredentialStatus(#[from] CredentialStatusBuildError),
    #[error("failed to build HTTP source client")]
    HttpClient(#[source] reqwest::Error),
    #[error("invalid OIDC auth configuration: {0}")]
    InvalidOidcConfig(String),
    #[error("invalid federation configuration: {0}")]
    InvalidFederationConfig(String),
}

#[derive(Clone)]
struct ResolvedEvidenceSourceConnection {
    id: String,
    base_url: String,
    auth: SourceAuthRuntime,
    fetch_url_policy: FetchUrlPolicy,
    dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound calls to this connection.
    /// Permits are acquired in `read_one` and held across retries so a flaky
    /// upstream cannot temporarily exceed the politeness cap by quick retry.
    semaphore: Arc<Semaphore>,
    max_in_flight: usize,
    retry_on_5xx: bool,
    /// Bulk-read mode for this connection. See `BulkMode` for the available
    /// strategies. `None` disables bulk specialization and the runtime never
    /// invokes the specialized `read_many` path for this connection.
    bulk_mode: BulkMode,
    /// Upper bound for the per-call timeout used by `read_many`.
    bulk_timeout_max: Duration,
}

#[derive(Clone)]
enum SourceAuthRuntime {
    StaticBearer(Arc<str>),
    Oauth2ClientCredentials(Arc<Oauth2ClientCredentialsRuntime>),
}

impl std::fmt::Debug for SourceAuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceAuthRuntime::StaticBearer(_) => f.write_str("StaticBearer(<redacted>)"),
            SourceAuthRuntime::Oauth2ClientCredentials(_) => {
                f.write_str("Oauth2ClientCredentials(<redacted>)")
            }
        }
    }
}

struct Oauth2ClientCredentialsRuntime {
    token_url: reqwest::Url,
    client_id: String,
    client_secret: String,
    request_format: String,
    scope: String,
    refresh_skew: Duration,
    cache: Mutex<Option<CachedSourceToken>>,
}

impl std::fmt::Debug for Oauth2ClientCredentialsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oauth2ClientCredentialsRuntime")
            .field("token_url", &self.token_url)
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .field("request_format", &self.request_format)
            .field("scope", &self.scope)
            .field("refresh_skew", &self.refresh_skew)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct CachedSourceToken {
    access_token: String,
    refresh_after: Instant,
}

impl SourceAuthRuntime {
    async fn bearer_token(
        &self,
        client: &reqwest::Client,
        fetch_url_policy: &FetchUrlPolicy,
        force_refresh: bool,
    ) -> Result<String, EvidenceError> {
        match self {
            SourceAuthRuntime::StaticBearer(token) => Ok(token.to_string()),
            SourceAuthRuntime::Oauth2ClientCredentials(runtime) => {
                runtime
                    .bearer_token(client, fetch_url_policy, force_refresh)
                    .await
            }
        }
    }

    fn can_refresh(&self) -> bool {
        matches!(self, SourceAuthRuntime::Oauth2ClientCredentials(_))
    }
}

impl Oauth2ClientCredentialsRuntime {
    async fn bearer_token(
        &self,
        client: &reqwest::Client,
        fetch_url_policy: &FetchUrlPolicy,
        force_refresh: bool,
    ) -> Result<String, EvidenceError> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        if !force_refresh {
            if let Some(token) = cache.as_ref() {
                if token.refresh_after > now {
                    return Ok(token.access_token.clone());
                }
            }
        }
        let token = self.fetch_token(client, fetch_url_policy).await?;
        let access_token = token.access_token.clone();
        *cache = Some(token);
        Ok(access_token)
    }

    async fn fetch_token(
        &self,
        client: &reqwest::Client,
        fetch_url_policy: &FetchUrlPolicy,
    ) -> Result<CachedSourceToken, EvidenceError> {
        if let Err(error) = fetch_url_policy.validate(&self.token_url) {
            tracing::warn!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                error = %error,
                "source OAuth token URL rejected by fetch policy",
            );
            return Err(EvidenceError::SourceUnavailable);
        }
        let mut request = client
            .post(self.token_url.clone())
            .timeout(SOURCE_REQUEST_TIMEOUT)
            .header("accept", "application/json");
        let mut params = BTreeMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", self.client_id.as_str());
        params.insert("client_secret", self.client_secret.as_str());
        if !self.scope.trim().is_empty() {
            params.insert("scope", self.scope.as_str());
        }
        request = match self.request_format.as_str() {
            "json" => request.json(&params),
            "form" => request.form(&params),
            _ => return Err(EvidenceError::SourceUnavailable),
        };
        let response = request.send().await.map_err(|error| {
            tracing::error!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                path = self.token_url.path(),
                error = %error,
                "source OAuth token request failed",
            );
            EvidenceError::SourceUnavailable
        })?;
        if !response.status().is_success() {
            let status = response.status();
            tracing::error!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                path = self.token_url.path(),
                status = %status,
                "source OAuth token endpoint returned error status",
            );
            return Err(EvidenceError::SourceUnavailable);
        }
        let body = match read_source_json(response).await {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    path = self.token_url.path(),
                    "source OAuth token response could not be parsed",
                );
                return Err(error);
            }
        };
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    path = self.token_url.path(),
                    "source OAuth token response was missing access_token",
                );
                EvidenceError::SourceUnavailable
            })?
            .to_string();
        let expires_in = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(300);
        let ttl = Duration::from_secs(expires_in);
        let refresh_after = Instant::now()
            + ttl
                .checked_sub(self.refresh_skew)
                .unwrap_or_else(|| Duration::from_secs(0));
        Ok(CachedSourceToken {
            access_token,
            refresh_after,
        })
    }
}

impl std::fmt::Debug for ResolvedEvidenceSourceConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedEvidenceSourceConnection")
            .field("id", &self.id)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("fetch_url_policy", &self.fetch_url_policy)
            .field("dci", &self.dci)
            .field("max_in_flight", &self.max_in_flight)
            .field("retry_on_5xx", &self.retry_on_5xx)
            .field("bulk_mode", &self.bulk_mode)
            .field("bulk_timeout_max", &self.bulk_timeout_max)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct HttpEvidenceSources {
    client: reqwest::Client,
    request_timeout: Duration,
    source_connections: BTreeMap<String, ResolvedEvidenceSourceConnection>,
    metrics: Arc<AppMetrics>,
}

impl HttpEvidenceSources {
    pub(crate) fn from_config(
        config: &EvidenceConfig,
        metrics: Arc<AppMetrics>,
    ) -> Result<Self, StandaloneServerError> {
        let mut source_connections = BTreeMap::new();
        for (id, connection) in &config.source_connections {
            let auth = resolve_source_auth(connection)?;
            source_connections.insert(
                id.clone(),
                ResolvedEvidenceSourceConnection {
                    id: id.clone(),
                    base_url: connection.base_url.clone(),
                    auth,
                    fetch_url_policy: source_fetch_url_policy(connection),
                    dci: connection.effective_dci()?,
                    semaphore: Arc::new(Semaphore::new(connection.max_in_flight)),
                    max_in_flight: connection.max_in_flight,
                    retry_on_5xx: connection.retry_on_5xx,
                    bulk_mode: connection.bulk_mode,
                    bulk_timeout_max: Duration::from_millis(connection.bulk_timeout_max_ms),
                },
            );
        }
        let client = OutboundClientBuilder::new()
            .timeout(SOURCE_REQUEST_TIMEOUT)
            .user_agent("registry-notary/0.2")
            .build();
        Ok(Self {
            client,
            request_timeout: SOURCE_REQUEST_TIMEOUT,
            source_connections,
            metrics,
        })
    }

    fn source_connection(
        &self,
        binding: &SourceBindingConfig,
    ) -> Option<&ResolvedEvidenceSourceConnection> {
        binding
            .connection
            .as_deref()
            .and_then(|connection| self.source_connections.get(connection))
    }
}

fn resolve_source_auth(
    connection: &SourceConnectionConfig,
) -> Result<SourceAuthRuntime, StandaloneServerError> {
    if let Some(source_auth) = &connection.source_auth {
        return match source_auth {
            SourceAuthConfig::Oauth2ClientCredentials(config) => {
                Ok(SourceAuthRuntime::Oauth2ClientCredentials(Arc::new(
                    resolve_oauth_source_auth(config)?,
                )))
            }
        };
    }
    let bearer_token = env::var(&connection.token_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(connection.token_env.clone())
        })?;
    Ok(SourceAuthRuntime::StaticBearer(Arc::from(
        bearer_token.into_boxed_str(),
    )))
}

fn resolve_oauth_source_auth(
    config: &Oauth2ClientCredentialsSourceAuthConfig,
) -> Result<Oauth2ClientCredentialsRuntime, StandaloneServerError> {
    let client_id = env::var(&config.client_id_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(config.client_id_env.clone())
        })?;
    let client_secret = env::var(&config.client_secret_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(config.client_secret_env.clone())
        })?;
    let token_url = reqwest::Url::parse(&config.token_url)
        .map_err(|_| StandaloneServerError::InvalidSourceAuth("invalid token_url".to_string()))?;
    Ok(Oauth2ClientCredentialsRuntime {
        token_url,
        client_id,
        client_secret,
        request_format: config.request_format.clone(),
        scope: config.scope.clone(),
        refresh_skew: Duration::from_secs(config.refresh_skew_seconds),
        cache: Mutex::new(None),
    })
}

fn source_fetch_url_policy(connection: &SourceConnectionConfig) -> FetchUrlPolicy {
    if connection.allow_insecure_private_network {
        FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: true,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    } else if connection.allow_insecure_localhost {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    }
}

impl SourceReader for HttpEvidenceSources {
    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            let connection = self
                .source_connection(binding)
                .ok_or(EvidenceError::SourceUnavailable)?;
            match binding.connector {
                SourceConnectorKind::RegistryDataApi => {
                    read_remote_registry_data_api_one(self, connection, binding, subject, purpose)
                        .await
                }
                SourceConnectorKind::Dci => {
                    read_external_dci_http_one(self, connection, binding, subject, purpose).await
                }
            }
        })
    }

    fn read_many<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if bindings.is_empty() {
                return Vec::new();
            }
            // Determine the bulk mode from the first binding's connection.
            // The runtime guarantees every binding in this batch shares the
            // same (connection_id, dataset, entity, lookup_field, fields)
            // tuple, so they share `bulk_mode` too.
            let connection = match self.source_connection(&bindings[0].0) {
                Some(c) => c,
                None => {
                    return bindings
                        .iter()
                        .map(|_| Err(EvidenceError::SourceUnavailable))
                        .collect();
                }
            };
            tracing::info!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                bulk_mode = ?connection.bulk_mode,
                bulk_request_size = bindings.len(),
                "bulk_request_size",
            );
            let outcome: Vec<Result<Value, EvidenceError>> = match connection.bulk_mode {
                BulkMode::None => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "fallback",
                        "bulk_vs_fallback",
                    );
                    fallback_concurrent_read_one(self, &bindings, purpose).await
                }
                BulkMode::RdaInFilter => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_remote_registry_data_api_many(self, connection, &bindings, purpose).await
                }
                BulkMode::DciBatchedSearch => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_external_dci_http_many(self, connection, &bindings, purpose).await
                }
            };
            outcome
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        let mut scopes = Vec::new();
        collect_claim_required_scopes(evidence, claim_id, &mut scopes)?;
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}

/// Run `read_one` concurrently for each binding (collision-fallback path for
/// bulk specializations and the BulkMode::None branch).
async fn fallback_concurrent_read_one(
    sources: &HttpEvidenceSources,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = bindings
        .iter()
        .map(|(binding, subject)| Some(sources.read_one(binding, subject, purpose)))
        .collect();
    let mut results: Vec<Option<Result<Value, EvidenceError>>> =
        (0..futures.len()).map(|_| None).collect();
    std::future::poll_fn(move |cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(std::mem::take(&mut results))
        } else {
            Poll::Pending
        }
    })
    .await
    .into_iter()
    .map(|slot| slot.expect("every slot populated"))
    .collect()
}

/// Batch-aware timeout budget: scale the per-call timeout with N up to a
/// configured cap. Default RDA/DCI single-call timeout is
/// `SOURCE_REQUEST_TIMEOUT` (10s); a 100-subject bulk call gets 10 * ceil(100/10)
/// = 100s, capped at `bulk_timeout_max` (30s by default).
fn bulk_timeout(connection: &ResolvedEvidenceSourceConnection, batch_size: usize) -> Duration {
    let base = SOURCE_REQUEST_TIMEOUT.as_millis() as u64;
    let factor = batch_size.div_ceil(10).max(1) as u64;
    let scaled = Duration::from_millis(base.saturating_mul(factor));
    scaled.min(connection.bulk_timeout_max)
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceIssuerRegistry {
    issuers: BTreeMap<String, EvidenceIssuer>,
    public_jwks: Vec<Value>,
}

impl EvidenceIssuerRegistry {
    pub fn from_config(config: &EvidenceConfig) -> Result<Self, StandaloneServerError> {
        let signing_keys = SigningKeyRegistry::from_config(config)?;
        Self::from_signing_keys(config, &signing_keys)
    }

    fn from_signing_keys(
        config: &EvidenceConfig,
        signing_keys: &SigningKeyRegistry,
    ) -> Result<Self, StandaloneServerError> {
        let mut issuers = BTreeMap::new();
        for (profile_id, profile) in &config.credential_profiles {
            let issuer = signing_keys
                .issuer(profile.signing_key.as_str())
                .ok_or_else(|| {
                    invalid_signing_key(
                        profile.signing_key.as_str(),
                        "active signing key was not built",
                    )
                })?;
            issuers.insert(profile_id.clone(), issuer.clone());
        }
        Ok(Self {
            issuers,
            public_jwks: signing_keys.public_jwks(),
        })
    }
}

impl EvidenceIssuerResolver for EvidenceIssuerRegistry {
    fn issuer(&self, profile_id: &str) -> Result<EvidenceIssuer, EvidenceError> {
        self.issuers
            .get(profile_id)
            .cloned()
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)
    }

    fn public_jwks(&self, _evidence: &EvidenceConfig) -> Result<Vec<Value>, EvidenceError> {
        Ok(self.public_jwks.clone())
    }
}

#[derive(Clone, Default)]
struct SigningKeyRegistry {
    issuers: BTreeMap<String, EvidenceIssuer>,
    providers: BTreeMap<String, Arc<dyn SigningProvider>>,
    public_jwks: Vec<Value>,
}

impl SigningKeyRegistry {
    fn from_config(config: &EvidenceConfig) -> Result<Self, StandaloneServerError> {
        let mut issuers = BTreeMap::new();
        let mut providers = BTreeMap::new();
        let mut public_jwks_by_kid = BTreeMap::new();
        for (key_id, key) in &config.signing_keys {
            if !key.status.may_publish() {
                continue;
            }
            let public_jwk = match key.provider {
                SigningKeyProviderConfig::LocalJwkEnv => {
                    if key.status.may_sign() {
                        let provider: Arc<dyn SigningProvider> =
                            Arc::new(build_local_jwk_signer(key_id, key)?);
                        let issuer = EvidenceIssuer::from_signing_provider(Arc::clone(&provider))
                            .map_err(|_| {
                            invalid_signing_key(key_id, "local signer failed self-test")
                        })?;
                        let public_jwk = issuer.public_jwk();
                        issuers.insert(key_id.clone(), issuer);
                        providers.insert(key_id.clone(), provider);
                        public_jwk
                    } else {
                        build_public_jwk_value(key_id, key)?
                    }
                }
                SigningKeyProviderConfig::Pkcs11 => {
                    if key.status.may_sign() {
                        #[cfg(feature = "pkcs11")]
                        {
                            let provider: Arc<dyn SigningProvider> =
                                Arc::new(pkcs11::Pkcs11SigningProvider::from_config(key_id, key)?);
                            let issuer =
                                EvidenceIssuer::from_signing_provider(Arc::clone(&provider))
                                    .map_err(|_| {
                                        invalid_signing_key(
                                            key_id,
                                            "PKCS#11 signer failed self-test",
                                        )
                                    })?;
                            let public_jwk = issuer.public_jwk();
                            issuers.insert(key_id.clone(), issuer);
                            providers.insert(key_id.clone(), provider);
                            public_jwk
                        }
                        #[cfg(not(feature = "pkcs11"))]
                        {
                            return Err(StandaloneServerError::SigningKeyProviderUnavailable {
                                provider: "pkcs11".to_string(),
                            });
                        }
                    } else {
                        build_public_jwk_value(key_id, key)?
                    }
                }
                SigningKeyProviderConfig::LocalPkcs12File => {
                    return Err(StandaloneServerError::SigningKeyProviderUnavailable {
                        provider: "local_pkcs12_file".to_string(),
                    });
                }
            };
            public_jwks_by_kid.insert(key.kid.clone(), public_jwk);
        }
        Ok(Self {
            issuers,
            providers,
            public_jwks: public_jwks_by_kid.into_values().collect(),
        })
    }

    fn issuer(&self, key_id: &str) -> Option<&EvidenceIssuer> {
        self.issuers.get(key_id)
    }

    fn public_jwks(&self) -> Vec<Value> {
        self.public_jwks.clone()
    }

    fn signing_provider(&self, key_id: &str) -> Option<Arc<dyn SigningProvider>> {
        self.providers.get(key_id).cloned()
    }
}

fn build_local_jwk_signer(
    key_id: &str,
    key: &SigningKeyConfig,
) -> Result<LocalJwkSigner, StandaloneServerError> {
    let raw = Zeroizing::new(
        env::var(&key.private_jwk_env)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_signing_key(key_id, "private_jwk_env is missing or empty"))?,
    );
    let mut jwk = PrivateJwk::parse(raw.as_str()).map_err(|_| {
        invalid_signing_key(
            key_id,
            "private_jwk_env does not contain a valid private JWK",
        )
    })?;
    if jwk.kid.as_deref().is_some_and(|kid| kid != key.kid) {
        return Err(invalid_signing_key(
            key_id,
            "private JWK kid does not match configured kid",
        ));
    }
    if jwk.alg.as_deref().is_some_and(|alg| alg != key.alg) {
        return Err(invalid_signing_key(
            key_id,
            "private JWK alg does not match configured alg",
        ));
    }
    jwk.kid = Some(key.kid.clone());
    jwk.alg = Some(key.alg.clone());
    let public = jwk.public();
    let signature = sign(b"registry-notary signing self-test", &jwk)
        .map_err(|_| invalid_signing_key(key_id, "local signer self-test failed"))?;
    verify(b"registry-notary signing self-test", &signature, &public)
        .map_err(|_| invalid_signing_key(key_id, "local signer self-test verification failed"))?;
    LocalJwkSigner::new(jwk)
        .map_err(|_| invalid_signing_key(key_id, "local signer could not be constructed"))
}

fn build_public_jwk_value(
    key_id: &str,
    key: &SigningKeyConfig,
) -> Result<Value, StandaloneServerError> {
    let raw = env::var(&key.public_jwk_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_signing_key(key_id, "public_jwk_env is missing or empty"))?;
    let public = PublicJwk::parse(&raw).map_err(|_| {
        invalid_signing_key(key_id, "public_jwk_env does not contain a valid public JWK")
    })?;
    if public.kid.as_deref() != Some(key.kid.as_str()) {
        return Err(invalid_signing_key(
            key_id,
            "public JWK kid does not match configured kid",
        ));
    }
    if public.alg.as_deref() != Some(key.alg.as_str()) {
        return Err(invalid_signing_key(
            key_id,
            "public JWK alg does not match configured alg",
        ));
    }
    serde_json::to_value(public)
        .map_err(|_| invalid_signing_key(key_id, "public JWK could not be serialized"))
}

fn invalid_signing_key(key: &str, reason: &str) -> StandaloneServerError {
    StandaloneServerError::InvalidSigningKey {
        key: key.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(feature = "pkcs11")]
mod pkcs11 {
    use std::fmt;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CryptokiError, RvError};
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
    use cryptoki::mechanism::{Mechanism, MechanismType};
    use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use registry_notary_core::SigningKeyConfig;
    use registry_platform_crypto::{
        verify, PublicJwk, SigningAlgorithm, SigningError, SigningProvider,
    };
    use tokio::sync::Semaphore;
    use zeroize::Zeroizing;

    use super::{invalid_signing_key, StandaloneServerError};

    const SELF_TEST_PAYLOAD: &[u8] = b"registry-notary pkcs11 signing self-test";
    const SIGN_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Clone)]
    pub(super) struct Pkcs11SigningProvider {
        key_id: String,
        public_jwk: PublicJwk,
        context: Arc<Pkcs11>,
        slot: Slot,
        pin: Arc<Zeroizing<String>>,
        session: Arc<std::sync::Mutex<Pkcs11SessionState>>,
        sign_permit: Arc<Semaphore>,
        key_label: String,
        key_id_bytes: Vec<u8>,
    }

    struct Pkcs11SessionState {
        session: Session,
        private_key: ObjectHandle,
    }

    impl Pkcs11SigningProvider {
        pub(super) fn from_config(
            config_key_id: &str,
            config: &SigningKeyConfig,
        ) -> Result<Self, StandaloneServerError> {
            let public_raw = Zeroizing::new(read_required_env(
                config_key_id,
                &config.public_jwk_env,
                "public_jwk_env",
            )?);
            let public_jwk = PublicJwk::parse(public_raw.as_str()).map_err(|_| {
                invalid_signing_key(config_key_id, "public_jwk_env is not a valid public JWK")
            })?;
            if public_jwk.kid.as_deref() != Some(config.kid.as_str()) {
                return Err(invalid_signing_key(
                    config_key_id,
                    "public JWK kid does not match configured kid",
                ));
            }
            if public_jwk.alg.as_deref() != Some(config.alg.as_str()) {
                return Err(invalid_signing_key(
                    config_key_id,
                    "public JWK alg does not match configured alg",
                ));
            }

            let pin = Arc::new(Zeroizing::new(read_required_env(
                config_key_id,
                &config.pin_env,
                "pin_env",
            )?));
            let key_id_bytes = hex::decode(&config.key_id_hex)
                .map_err(|_| invalid_signing_key(config_key_id, "key_id_hex is not valid hex"))?;
            let context = Pkcs11::new(&config.module_path)
                .map_err(|_| invalid_signing_key(config_key_id, "could not load PKCS#11 module"))?;
            match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
                Ok(()) | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
                Err(_) => {
                    return Err(invalid_signing_key(
                        config_key_id,
                        "could not initialize PKCS#11 module",
                    ));
                }
            }
            let slot = find_token_slot(&context, config_key_id, &config.token_label)?;
            ensure_eddsa_mechanism(&context, slot, config_key_id)?;
            let session = open_logged_in_session(&context, slot, &pin, config_key_id)?;
            let private_key =
                find_private_key(&session, &config.key_label, &key_id_bytes, config_key_id)?;

            let provider = Self {
                key_id: config.kid.clone(),
                public_jwk,
                context: Arc::new(context),
                slot,
                pin,
                session: Arc::new(std::sync::Mutex::new(Pkcs11SessionState {
                    session,
                    private_key,
                })),
                sign_permit: Arc::new(Semaphore::new(1)),
                key_label: config.key_label.clone(),
                key_id_bytes,
            };
            provider.self_test(config_key_id)?;
            Ok(provider)
        }

        fn self_test(&self, config_key_id: &str) -> Result<(), StandaloneServerError> {
            let signature = self.sign_sync(SELF_TEST_PAYLOAD).map_err(|_| {
                invalid_signing_key(config_key_id, "PKCS#11 signer self-test failed")
            })?;
            verify(SELF_TEST_PAYLOAD, &signature, &self.public_jwk).map_err(|_| {
                invalid_signing_key(
                    config_key_id,
                    "PKCS#11 signer self-test verification failed",
                )
            })
        }

        fn sign_sync(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            if let Ok(signature) = self.sign_with_current_session(payload) {
                return Ok(signature);
            }

            let session = open_logged_in_session_for_signing(&self.context, self.slot, &self.pin)?;
            let private_key =
                find_private_key_for_signing(&session, &self.key_label, &self.key_id_bytes)?;
            {
                let mut state = self
                    .session
                    .lock()
                    .map_err(|_| SigningError::external("PKCS#11 session lock poisoned"))?;
                state.session = session;
                state.private_key = private_key;
            }
            self.sign_with_current_session(payload)
        }

        fn sign_with_current_session(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            let session = self
                .session
                .lock()
                .map_err(|_| SigningError::external("PKCS#11 session lock poisoned"))?;
            let mechanism = eddsa_mechanism();
            session
                .session
                .sign(&mechanism, session.private_key, payload)
                .map_err(|_| SigningError::external("PKCS#11 sign failed"))
        }
    }

    impl fmt::Debug for Pkcs11SigningProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Pkcs11SigningProvider")
                .field("kid", &self.key_id)
                .field("key_label", &self.key_label)
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl SigningProvider for Pkcs11SigningProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            &self.key_id
        }

        fn public_jwk(&self) -> PublicJwk {
            self.public_jwk.clone()
        }

        async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            let permit =
                tokio::time::timeout(SIGN_TIMEOUT, self.sign_permit.clone().acquire_owned())
                    .await
                    .map_err(|_| SigningError::external("PKCS#11 sign timed out"))?
                    .map_err(|_| SigningError::external("PKCS#11 signing gate was closed"))?;
            let provider = self.clone();
            let payload = payload.to_vec();
            let task = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                provider.sign_sync(&payload)
            });
            tokio::time::timeout(SIGN_TIMEOUT, task)
                .await
                .map_err(|_| SigningError::external("PKCS#11 sign timed out"))?
                .map_err(|_| SigningError::external("PKCS#11 sign task failed"))?
        }
    }

    fn read_required_env(
        config_key_id: &str,
        env_name: &str,
        field: &str,
    ) -> Result<String, StandaloneServerError> {
        std::env::var(env_name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                invalid_signing_key(config_key_id, &format!("{field} is missing or empty"))
            })
    }

    fn find_token_slot(
        context: &Pkcs11,
        config_key_id: &str,
        token_label: &str,
    ) -> Result<Slot, StandaloneServerError> {
        let matches = context
            .get_slots_with_token()
            .map_err(|_| invalid_signing_key(config_key_id, "could not list PKCS#11 slots"))?
            .into_iter()
            .filter(|slot| {
                context
                    .get_token_info(*slot)
                    .map(|info| info.label().trim() == token_label)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [slot] => Ok(*slot),
            [] => Err(invalid_signing_key(
                config_key_id,
                "PKCS#11 token was not found",
            )),
            _ => Err(invalid_signing_key(
                config_key_id,
                "multiple PKCS#11 tokens matched token_label",
            )),
        }
    }

    fn ensure_eddsa_mechanism(
        context: &Pkcs11,
        slot: Slot,
        config_key_id: &str,
    ) -> Result<(), StandaloneServerError> {
        let supported = context
            .get_mechanism_list(slot)
            .map_err(|_| invalid_signing_key(config_key_id, "could not list PKCS#11 mechanisms"))?;
        if supported.contains(&MechanismType::EDDSA) {
            Ok(())
        } else {
            Err(invalid_signing_key(
                config_key_id,
                "PKCS#11 token does not support CKM_EDDSA",
            ))
        }
    }

    fn open_logged_in_session(
        context: &Pkcs11,
        slot: Slot,
        pin: &Zeroizing<String>,
        config_key_id: &str,
    ) -> Result<Session, StandaloneServerError> {
        let session = context
            .open_ro_session(slot)
            .map_err(|_| invalid_signing_key(config_key_id, "PKCS#11 session open failed"))?;
        let auth_pin = AuthPin::new(pin.as_str().to_string().into_boxed_str());
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) => Ok(session),
            Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(_) => Err(invalid_signing_key(config_key_id, "PKCS#11 login failed")),
        }
    }

    fn find_private_key(
        session: &Session,
        key_label: &str,
        key_id_bytes: &[u8],
        config_key_id: &str,
    ) -> Result<ObjectHandle, StandaloneServerError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
            Attribute::Id(key_id_bytes.to_vec()),
        ];
        let matches = session
            .find_objects(&template)
            .map_err(|_| invalid_signing_key(config_key_id, "PKCS#11 private-key lookup failed"))?;
        match matches.as_slice() {
            [handle] => Ok(*handle),
            [] => Err(invalid_signing_key(
                config_key_id,
                "PKCS#11 private key was not found",
            )),
            _ => Err(invalid_signing_key(
                config_key_id,
                "multiple PKCS#11 private keys matched lookup",
            )),
        }
    }

    fn open_logged_in_session_for_signing(
        context: &Pkcs11,
        slot: Slot,
        pin: &Zeroizing<String>,
    ) -> Result<Session, SigningError> {
        let session = context
            .open_ro_session(slot)
            .map_err(|_| SigningError::external("PKCS#11 session open failed"))?;
        let auth_pin = AuthPin::new(pin.as_str().to_string().into_boxed_str());
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) => Ok(session),
            Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(_) => Err(SigningError::external("PKCS#11 login failed")),
        }
    }

    fn find_private_key_for_signing(
        session: &Session,
        key_label: &str,
        key_id_bytes: &[u8],
    ) -> Result<ObjectHandle, SigningError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
            Attribute::Id(key_id_bytes.to_vec()),
        ];
        let matches = session
            .find_objects(&template)
            .map_err(|_| SigningError::external("PKCS#11 private-key lookup failed"))?;
        match matches.as_slice() {
            [handle] => Ok(*handle),
            [] => Err(SigningError::external("PKCS#11 private key was not found")),
            _ => Err(SigningError::external(
                "multiple PKCS#11 private keys matched lookup",
            )),
        }
    }

    fn eddsa_mechanism() -> Mechanism<'static> {
        Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519))
    }
}

/// Bench-internal: exposed only so `benches/auth_bench.rs` can construct
/// fixtures. Production code goes through `resolve_credentials`, which reads
/// the fingerprint from `EvidenceCredentialConfig::hash_env`. Not part of the
/// public API; do not depend on this shape from outside the workspace.
#[doc(hidden)]
#[derive(Clone)]
pub struct ResolvedCredential {
    pub id: String,
    pub fingerprint: String,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("id", &self.id)
            .field("fingerprint", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Debug)]
struct AuthAuditState {
    authenticator: Authenticator,
    audit: AuditPipeline,
    metrics: Arc<AppMetrics>,
    self_attestation_invalid_token_limiter: Option<Arc<SelfAttestationRateLimiter>>,
    self_attestation_rate_keys: Option<Arc<SelfAttestationRateLimitKeys>>,
}

#[derive(Debug, Clone, Default)]
struct RequestCredentials {
    api_key: Option<String>,
    authorization_present: bool,
    bearer_token: Option<String>,
    id_token: Option<String>,
}

impl RequestCredentials {
    fn credential_type_count(&self) -> usize {
        usize::from(self.api_key.is_some())
            + usize::from(self.authorization_present || self.bearer_token.is_some())
    }
}

#[derive(Debug)]
enum Authenticator {
    Static {
        api_keys: Vec<ResolvedCredential>,
        bearer_tokens: Vec<ResolvedCredential>,
    },
    Oidc {
        verifier: Arc<TokenVerifier>,
        fetch_url_policy: FetchUrlPolicy,
        principal_claim: String,
        subject_binding_claim: Option<String>,
        subject_binding_claim_source: SelfAttestationClaimSource,
        assurance_claim_source: SelfAttestationAssuranceClaimSource,
        userinfo_endpoint: Option<String>,
        userinfo_issuers: Vec<String>,
    },
}

impl AuthAuditState {
    fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        metrics: Arc<AppMetrics>,
    ) -> Result<Self, StandaloneServerError> {
        let audit = AuditPipeline::from_config(&config.audit)?;
        let self_attestation_invalid_token_limiter = config.self_attestation.enabled.then(|| {
            Arc::new(SelfAttestationRateLimiter::new(
                config.self_attestation.rate_limits.clone(),
            ))
        });
        let self_attestation_rate_keys = config
            .self_attestation
            .enabled
            .then(|| Arc::new(SelfAttestationRateLimitKeys::new(audit.hasher.clone())));
        Ok(Self {
            authenticator: Authenticator::from_config(config)?,
            audit,
            metrics,
            self_attestation_invalid_token_limiter,
            self_attestation_rate_keys,
        })
    }

    async fn authenticate(
        &self,
        credentials: RequestCredentials,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        self.authenticator.authenticate(credentials).await
    }
}

impl Authenticator {
    fn from_config(config: &StandaloneRegistryNotaryConfig) -> Result<Self, StandaloneServerError> {
        match config.auth.mode.as_str() {
            "api_key" => Ok(Self::Static {
                api_keys: resolve_credentials(&config.auth.api_keys)?,
                bearer_tokens: resolve_credentials(&config.auth.bearer_tokens)?,
            }),
            "oidc" => {
                let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
                    StandaloneServerError::InvalidOidcConfig(
                        "auth.oidc is required when auth.mode = oidc".to_string(),
                    )
                })?;
                let allowed_algorithms = oidc
                    .allowed_algorithms
                    .iter()
                    .map(|algorithm| parse_oidc_algorithm(algorithm))
                    .collect::<Result<Vec<_>, _>>()?;
                let scope_separator = oidc.scope_separator.chars().next().ok_or_else(|| {
                    StandaloneServerError::InvalidOidcConfig(
                        "scope_separator must be exactly one character".to_string(),
                    )
                })?;
                let fetch_url_policy = if oidc.allow_insecure_localhost {
                    FetchUrlPolicy::dev()
                } else {
                    FetchUrlPolicy::strict()
                };
                let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
                    oidc.jwks_uri.clone(),
                    JwksFetcherConfig::defaults(),
                    fetch_url_policy.clone(),
                ));
                let verifier = TokenVerifier::new(
                    TokenVerifierConfig {
                        issuer: oidc.issuer.clone(),
                        audiences: oidc.audiences.clone(),
                        allowed_algorithms,
                        allowed_typ: oidc.allowed_typ.clone(),
                        scope_claim: oidc.scope_claim.clone(),
                        scope_separator,
                        scope_map: Some(
                            oidc.scope_map
                                .iter()
                                .map(|(from, to)| (from.clone(), to.clone()))
                                .collect::<HashMap<_, _>>(),
                        )
                        .filter(|scope_map| !scope_map.is_empty()),
                        allowed_clients: oidc.allowed_clients.clone(),
                        leeway: Duration::from_secs(oidc.leeway_seconds),
                    },
                    fetcher,
                );
                let userinfo_issuers = if oidc.userinfo_issuers.is_empty() {
                    vec![oidc.issuer.clone()]
                } else {
                    oidc.userinfo_issuers.clone()
                };
                Ok(Self::Oidc {
                    verifier: Arc::new(verifier),
                    fetch_url_policy,
                    principal_claim: oidc.principal_claim.clone(),
                    subject_binding_claim: config
                        .self_attestation
                        .enabled
                        .then(|| config.self_attestation.subject_binding.token_claim.clone())
                        .filter(|claim| !claim.is_empty()),
                    subject_binding_claim_source: config
                        .self_attestation
                        .subject_binding
                        .claim_source,
                    assurance_claim_source: config
                        .self_attestation
                        .token_policy
                        .assurance_claim_source,
                    userinfo_endpoint: oidc.userinfo_endpoint.clone(),
                    userinfo_issuers,
                })
            }
            mode => Err(StandaloneServerError::InvalidOidcConfig(format!(
                "unsupported auth.mode '{mode}'"
            ))),
        }
    }

    async fn authenticate(
        &self,
        credentials: RequestCredentials,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        if credentials.credential_type_count() > 1 {
            return Err(EvidenceError::MultipleCredentials);
        }
        match self {
            Self::Static {
                api_keys,
                bearer_tokens,
            } => authenticate_static(&credentials, api_keys, bearer_tokens),
            Self::Oidc {
                verifier,
                fetch_url_policy,
                principal_claim,
                subject_binding_claim,
                subject_binding_claim_source,
                assurance_claim_source,
                userinfo_endpoint,
                userinfo_issuers,
            } => {
                authenticate_oidc(
                    &credentials,
                    verifier,
                    fetch_url_policy,
                    principal_claim,
                    subject_binding_claim.as_deref(),
                    *subject_binding_claim_source,
                    *assurance_claim_source,
                    userinfo_endpoint.as_deref(),
                    userinfo_issuers,
                )
                .await
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuditPipeline {
    sink: Arc<dyn PlatformAuditSink>,
    chain: Arc<OnceCell<ChainState>>,
    hasher: AuditKeyHasher,
}

impl std::fmt::Debug for AuditPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditPipeline")
            .field("sink", &"<redacted>")
            .field("hasher", &self.hasher)
            .finish()
    }
}

impl AuditPipeline {
    fn from_config(
        config: &registry_notary_core::EvidenceAuditConfig,
    ) -> Result<Self, StandaloneServerError> {
        let hash_secret_env = config
            .hash_secret_env
            .as_deref()
            .ok_or(StandaloneServerError::MissingAuditHashSecretEnv)?;
        let hasher = AuditKeyHasher::from_env(hash_secret_env)?;
        let sink: Arc<dyn PlatformAuditSink> = match config.sink.as_str() {
            "stdout" => {
                validate_no_file_audit_fields(config, "stdout")?;
                validate_no_syslog_audit_fields(config, "stdout")?;
                Arc::new(JsonlStdoutSink::new())
            }
            "file" | "jsonl" => {
                validate_no_syslog_audit_fields(config, config.sink.as_str())?;
                if config.max_files == Some(0) {
                    return Err(StandaloneServerError::InvalidAuditConfig(
                        "audit.max_files must be at least 1 when set".to_string(),
                    ));
                }
                let path = config
                    .path
                    .as_deref()
                    .ok_or(StandaloneServerError::MissingAuditPath)?;
                Arc::new(JsonlFileSink::with_rotation(
                    path,
                    config.max_size_bytes(),
                    config.max_files(),
                ))
            }
            "syslog" => {
                validate_no_file_audit_fields(config, "syslog")?;
                let sink = match config.syslog_socket_path.as_deref() {
                    Some(path) => SyslogSink::with_socket_path(path),
                    None => SyslogSink::new(),
                };
                Arc::new(sink)
            }
            sink => return Err(StandaloneServerError::InvalidAuditSink(sink.to_string())),
        };
        Ok(Self {
            sink,
            chain: Arc::new(OnceCell::new()),
            hasher,
        })
    }

    #[cfg(test)]
    fn for_sink_dev_only(sink: Arc<dyn PlatformAuditSink>) -> Self {
        Self {
            sink,
            chain: Arc::new(OnceCell::new()),
            hasher: AuditKeyHasher::unkeyed_dev_only(),
        }
    }

    pub(crate) fn hash_principal(&self, value: &str) -> Hashed<PrincipalIdentifier> {
        Hashed::from_hash(self.hasher.hash(value))
    }

    pub(crate) async fn emit(&self, event: &EvidenceAuditEvent) -> Result<(), AuditError> {
        let chain = self
            .chain
            .get_or_try_init(|| async { ChainState::bootstrap(self.sink.as_ref()).await })
            .await?;
        let record = serde_json::to_value(event).map_err(AuditError::Json)?;
        chain.append(self.sink.as_ref(), record).await?;
        Ok(())
    }
}

fn validate_no_file_audit_fields(
    config: &registry_notary_core::EvidenceAuditConfig,
    sink: &str,
) -> Result<(), StandaloneServerError> {
    if config.path.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.path is only valid when audit.sink is file or jsonl, not {sink}"
        )));
    }
    if config.max_size_bytes.is_some() || config.max_files.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.max_size_bytes and audit.max_files are only valid when audit.sink is file or jsonl, not {sink}"
        )));
    }
    Ok(())
}

fn validate_no_syslog_audit_fields(
    config: &registry_notary_core::EvidenceAuditConfig,
    sink: &str,
) -> Result<(), StandaloneServerError> {
    if config.syslog_socket_path.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.syslog_socket_path is only valid when audit.sink is syslog, not {sink}"
        )));
    }
    Ok(())
}

async fn auth_audit_middleware(
    State(state): State<Arc<AuthAuditState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = audit_path(&request);
    let correlation_id = correlation_id_from_headers(request.headers());
    if is_public_probe_path(&path) {
        return next.run(request).await;
    }
    let credentials = request_credentials(&request);
    let client_address = client_address_identifier(&request);
    if let Err(rate_error) =
        maybe_rate_limit_invalid_token_before_auth(&state, &credentials, client_address.as_str())
    {
        let mut response = crate::api::evidence_error_response(rate_error.evidence_error());
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_id: None,
            verification_decision: Some("auth_rate_limited".to_string()),
            claim_hash: None,
            purposes: None,
            row_count: None,
            access_mode: Some(AccessMode::Unknown),
            denial_code: Some(SelfAttestationDenialCode::RateLimited),
            token_claim_name: None,
            credential_profile: None,
            protocol: None,
            credential_configuration_id: None,
            holder_binding_mode: None,
            rate_limit_bucket: rate_error
                .bucket()
                .and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
            policy_hash: None,
        });
        let audit_event = build_audit_event(
            None,
            &state.audit.hasher,
            &method,
            &path,
            correlation_id.clone(),
            &response,
        );
        return emit_audit_or_error(&state, audit_event, response).await;
    }
    let principal = match state.authenticate(credentials.clone()).await {
        Ok(principal) => principal,
        Err(error) => {
            if let Err(rate_error) = consume_invalid_token_after_auth_failure(
                &state,
                &credentials,
                client_address.as_str(),
            ) {
                let mut response = crate::api::evidence_error_response(rate_error.evidence_error());
                response.extensions_mut().insert(EvidenceAuditContext {
                    verification_id: None,
                    verification_decision: Some("auth_rate_limited".to_string()),
                    claim_hash: None,
                    purposes: None,
                    row_count: None,
                    access_mode: Some(AccessMode::Unknown),
                    denial_code: Some(SelfAttestationDenialCode::RateLimited),
                    token_claim_name: None,
                    credential_profile: None,
                    protocol: None,
                    credential_configuration_id: None,
                    holder_binding_mode: None,
                    rate_limit_bucket: rate_error
                        .bucket()
                        .and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
                    policy_hash: None,
                });
                let audit_event = build_audit_event(
                    None,
                    &state.audit.hasher,
                    &method,
                    &path,
                    correlation_id.clone(),
                    &response,
                );
                return emit_audit_or_error(&state, audit_event, response).await;
            }
            let response = crate::api::evidence_error_response(error);
            let audit_event = build_audit_event(
                None,
                &state.audit.hasher,
                &method,
                &path,
                correlation_id.clone(),
                &response,
            );
            return emit_audit_or_error(&state, audit_event, response).await;
        }
    };
    request.extensions_mut().insert(principal.clone());
    request.extensions_mut().insert(correlation_id.clone());
    let response = with_request_correlation_id(correlation_id.clone(), next.run(request)).await;
    let audit_event = build_audit_event(
        Some(&principal),
        &state.audit.hasher,
        &method,
        &path,
        correlation_id,
        &response,
    );
    emit_audit_or_error(&state, audit_event, response).await
}

async fn emit_audit_or_error(
    state: &AuthAuditState,
    audit_event: EvidenceAuditEvent,
    response: Response,
) -> Response {
    match state.audit.emit(&audit_event).await {
        Ok(()) => {
            state.metrics.record_audit_event("success");
            response
        }
        Err(error) => {
            state.metrics.record_audit_event("failure");
            audit_error_response(error)
        }
    }
}

fn audit_path(request: &Request) -> String {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string())
}

fn client_address_identifier(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown-client-address".to_string())
}

fn maybe_rate_limit_invalid_token_before_auth(
    state: &AuthAuditState,
    credentials: &RequestCredentials,
    client_address: &str,
) -> Result<(), crate::SelfAttestationRateLimitError> {
    if credentials.bearer_token.is_none() {
        return Ok(());
    }
    let (Some(limiter), Some(keys)) = (
        state.self_attestation_invalid_token_limiter.as_ref(),
        state.self_attestation_rate_keys.as_ref(),
    ) else {
        return Ok(());
    };
    let client_address = keys.client_address(client_address)?;
    limiter.check_invalid_token_for_client_address_available(&client_address)
}

fn consume_invalid_token_after_auth_failure(
    state: &AuthAuditState,
    credentials: &RequestCredentials,
    client_address: &str,
) -> Result<(), crate::SelfAttestationRateLimitError> {
    if credentials.bearer_token.is_none() {
        return Ok(());
    }
    let (Some(limiter), Some(keys)) = (
        state.self_attestation_invalid_token_limiter.as_ref(),
        state.self_attestation_rate_keys.as_ref(),
    ) else {
        return Ok(());
    };
    let client_address = keys.client_address(client_address)?;
    limiter.check_invalid_token_for_client_address(&client_address)
}

fn is_public_probe_path(path: &str) -> bool {
    matches!(
        path,
        "/healthz"
            | "/ready"
            | "/.well-known/openid-credential-issuer"
            | "/metrics"
            | "/oid4vci/credential-offer"
            | "/oid4vci/nonce"
            | "/federation/v1/evaluations"
    ) || path.starts_with("/credentials/status/")
}

fn build_audit_event(
    principal: Option<&EvidencePrincipal>,
    hasher: &AuditKeyHasher,
    method: &str,
    path: &str,
    correlation_id: BoundedCorrelationId,
    response: &Response,
) -> EvidenceAuditEvent {
    let audit = response.extensions().get::<EvidenceAuditContext>();
    let error = response.extensions().get::<EvidenceErrorCodeContext>();
    let verification_id = audit.and_then(|context| context.verification_id.clone());
    let claim_hash = audit.and_then(|context| context.claim_hash.clone());
    let purposes = audit.and_then(|context| context.purposes.clone());
    let row_count = audit.and_then(|context| context.row_count);
    let access_mode = audit
        .and_then(|context| context.access_mode)
        .or_else(|| principal.map(EvidencePrincipal::access_mode));
    let denial_code = audit.and_then(|context| context.denial_code);
    let token_claim_name = audit.and_then(|context| context.token_claim_name.clone());
    let credential_profile = audit.and_then(|context| context.credential_profile.clone());
    let protocol = audit.and_then(|context| context.protocol.clone());
    let credential_configuration_id =
        audit.and_then(|context| context.credential_configuration_id.clone());
    let holder_binding_mode = audit.and_then(|context| context.holder_binding_mode.clone());
    let rate_limit_bucket = audit.and_then(|context| context.rate_limit_bucket.clone());
    let policy_hash = audit.and_then(|context| context.policy_hash.clone());
    let error_code = error.map(|context| context.0.clone());
    let decision = audit
        .and_then(|context| context.verification_decision.clone())
        .unwrap_or_else(|| {
            if response.status().is_success() {
                "allowed".to_string()
            } else {
                "denied".to_string()
            }
        });
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id_hash: principal.map(|principal| {
            Hashed::<PrincipalIdentifier>::from_hash(hasher.hash(&principal.principal_id))
        }),
        decision,
        method: method.to_string(),
        path: path.to_string(),
        status: response.status().as_u16(),
        verification_id,
        claim_hash,
        purposes,
        row_count,
        error_code,
        access_mode,
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti: None,
        federation_subject_ref_hash: None,
        denial_code,
        token_claim_name,
        correlation_id: Some(correlation_id),
        credential_profile,
        protocol,
        credential_configuration_id,
        holder_binding_mode,
        rate_limit_bucket,
        policy_version: None,
        policy_hash,
    }
}

fn correlation_id_from_headers(headers: &HeaderMap) -> BoundedCorrelationId {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("x-correlation-id"))
        .and_then(header_str)
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty()
                || !trimmed
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return None;
            }
            BoundedCorrelationId::new(trimmed).ok()
        })
        .unwrap_or_else(|| {
            BoundedCorrelationId::new(Ulid::new().to_string())
                .expect("generated correlation id is bounded")
        })
}

fn resolve_credentials(
    credentials: &[EvidenceCredentialConfig],
) -> Result<Vec<ResolvedCredential>, StandaloneServerError> {
    credentials
        .iter()
        .map(|credential| {
            let fingerprint = env::var(&credential.hash_env)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    StandaloneServerError::MissingCredentialEnv(credential.hash_env.clone())
                })?;
            parse_fingerprint(&fingerprint).map_err(|error| {
                StandaloneServerError::InvalidCredentialHash(credential.hash_env.clone(), error)
            })?;
            Ok(ResolvedCredential {
                id: credential.id.clone(),
                fingerprint,
                scopes: credential.scopes.clone(),
            })
        })
        .collect()
}

fn request_credentials(request: &Request) -> RequestCredentials {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(header_str);
    RequestCredentials {
        api_key: request
            .headers()
            .get("x-api-key")
            .and_then(header_str)
            .map(ToOwned::to_owned),
        authorization_present: authorization.is_some(),
        bearer_token: authorization
            .and_then(|raw| parse_bearer_token(raw).ok())
            .map(ToOwned::to_owned),
        id_token: request
            .headers()
            .get(OIDC_ID_TOKEN_HEADER)
            .and_then(header_str)
            .map(ToOwned::to_owned),
    }
}

fn authenticate_static(
    credentials: &RequestCredentials,
    api_keys: &[ResolvedCredential],
    bearer_tokens: &[ResolvedCredential],
) -> Result<EvidencePrincipal, EvidenceError> {
    if let Some(value) = credentials.api_key.as_deref() {
        if let Some(credential) = find_credential(api_keys, value) {
            return Ok(principal_from_credential(credential));
        }
    }
    if let Some(value) = credentials.bearer_token.as_deref() {
        if let Some(credential) = find_credential(bearer_tokens, value) {
            return Ok(principal_from_credential(credential));
        }
    }
    Err(EvidenceError::MissingCredential)
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_oidc(
    credentials: &RequestCredentials,
    verifier: &TokenVerifier,
    fetch_url_policy: &FetchUrlPolicy,
    principal_claim: &str,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
    userinfo_endpoint: Option<&str>,
    userinfo_issuers: &[String],
) -> Result<EvidencePrincipal, EvidenceError> {
    let Some(token) = credentials.bearer_token.as_deref() else {
        return Err(EvidenceError::MissingCredential);
    };
    let verified = verifier.verify(token).await.map_err(oidc_auth_error)?;
    let verified_userinfo = match (subject_binding_claim, subject_binding_claim_source) {
        (Some(_), SelfAttestationClaimSource::Userinfo) => {
            let endpoint = userinfo_endpoint.ok_or(EvidenceError::MissingCredential)?;
            let userinfo_jwt = fetch_userinfo_jwt_with_policy(
                endpoint,
                token,
                fetch_url_policy,
                Duration::from_secs(5),
                64 * 1024,
            )
            .await
            .map_err(oidc_auth_error)?;
            let accepted_issuers = userinfo_issuers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let accepted_audiences = verified
                .matched_client
                .as_ref()
                .and_then(|matched| matched.split_once(':'))
                .map(|(_, client)| vec![client.to_string()])
                .unwrap_or_default();
            Some(
                verifier
                    .verify_userinfo_jwt_with_claims_policy(
                        &userinfo_jwt,
                        &verified,
                        &accepted_issuers,
                        &accepted_audiences,
                    )
                    .await
                    .map_err(oidc_auth_error)?,
            )
        }
        _ => None,
    };
    let verified_id_token = match assurance_claim_source {
        SelfAttestationAssuranceClaimSource::AccessToken => None,
        SelfAttestationAssuranceClaimSource::IdToken => {
            let Some(id_token) = credentials.id_token.as_deref() else {
                return Err(EvidenceError::MissingCredential);
            };
            let id_token = verifier
                .verify_related_token(id_token)
                .await
                .map_err(oidc_auth_error)?;
            if id_token.claims.sub != verified.claims.sub {
                return Err(EvidenceError::MissingCredential);
            }
            Some(id_token)
        }
    };
    let token_type = jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|header| header.typ)
        .and_then(|typ| verified_claim_value(&typ));
    principal_from_oidc(
        &verified,
        verified_userinfo.as_ref(),
        verified_id_token.as_ref(),
        token_type,
        principal_claim,
        subject_binding_claim,
        subject_binding_claim_source,
        assurance_claim_source,
    )
    .ok_or(EvidenceError::MissingCredential)
}

#[allow(clippy::too_many_arguments)]
fn principal_from_oidc(
    verified: &VerifiedToken,
    userinfo: Option<&registry_platform_oidc::Claims>,
    id_token: Option<&VerifiedToken>,
    token_type: Option<VerifiedClaimValue>,
    principal_claim: &str,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
) -> Option<EvidencePrincipal> {
    let principal_id = if principal_claim == "sub" {
        verified.claims.sub.clone()
    } else {
        verified
            .claims
            .extra
            .get(principal_claim)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
    .or_else(|| verified.matched_client.clone())?;
    Some(EvidencePrincipal {
        principal_id,
        scopes: verified.scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: bounded_verified_claims_from_oidc(
            verified,
            userinfo,
            id_token,
            token_type,
            subject_binding_claim,
            subject_binding_claim_source,
            assurance_claim_source,
        ),
    })
}

fn bounded_verified_claims_from_oidc(
    verified: &VerifiedToken,
    userinfo: Option<&registry_platform_oidc::Claims>,
    id_token: Option<&VerifiedToken>,
    token_type: Option<VerifiedClaimValue>,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
) -> Option<BoundedVerifiedClaims> {
    let issuer = verified
        .claims
        .iss
        .as_deref()
        .and_then(verified_claim_value)?;
    let (subject_binding_claim, subject_binding_value) = if let Some(subject_binding_claim) =
        subject_binding_claim
    {
        let claim_name = VerifiedClaimName::new(subject_binding_claim).ok()?;
        let claim_value = match subject_binding_claim_source {
            SelfAttestationClaimSource::AccessToken => claim_string(verified, claim_name.as_str()),
            SelfAttestationClaimSource::Userinfo => {
                userinfo.and_then(|claims| claim_string_from_claims(claims, claim_name.as_str()))
            }
        }
        .and_then(verified_claim_value)?;
        (Some(claim_name), Some(claim_value))
    } else {
        (None, None)
    };
    let assurance_claims = match assurance_claim_source {
        SelfAttestationAssuranceClaimSource::AccessToken => &verified.claims,
        SelfAttestationAssuranceClaimSource::IdToken => &id_token?.claims,
    };
    Some(BoundedVerifiedClaims {
        issuer,
        audiences: bounded_audience(verified.claims.aud.as_ref()),
        client_id: verified_client(verified),
        token_type,
        scopes: bounded_scopes(&verified.scopes),
        subject: verified
            .claims
            .sub
            .as_deref()
            .and_then(verified_claim_value),
        subject_binding_claim,
        subject_binding_value,
        acr: assurance_claims
            .extra
            .get("acr")
            .and_then(Value::as_str)
            .and_then(verified_claim_value),
        auth_time: numeric_claim(&assurance_claims.extra, "auth_time"),
        exp: verified.claims.exp,
        iat: verified.claims.iat,
        nbf: verified.claims.nbf,
    })
}

fn claim_string<'a>(verified: &'a VerifiedToken, claim: &str) -> Option<&'a str> {
    if claim == "sub" {
        return verified.claims.sub.as_deref();
    }
    claim_string_from_claims(&verified.claims, claim)
}

fn claim_string_from_claims<'a>(
    claims: &'a registry_platform_oidc::Claims,
    claim: &str,
) -> Option<&'a str> {
    if claim == "sub" {
        return claims.sub.as_deref();
    }
    claims.extra.get(claim).and_then(Value::as_str)
}

fn verified_claim_value(value: &str) -> Option<VerifiedClaimValue> {
    VerifiedClaimValue::new(value).ok()
}

fn bounded_audience(audience: Option<&Audience>) -> Vec<VerifiedClaimValue> {
    let values: Vec<&str> = match audience {
        Some(Audience::One(value)) => vec![value.as_str()],
        Some(Audience::Many(values)) => values.iter().map(String::as_str).collect(),
        None => Vec::new(),
    };
    values
        .into_iter()
        .filter_map(verified_claim_value)
        .collect()
}

fn verified_client(verified: &VerifiedToken) -> Option<VerifiedClaimValue> {
    let client = verified
        .claims
        .azp
        .as_deref()
        .map(|azp| format!("azp:{azp}"))
        .or_else(|| {
            verified
                .claims
                .client_id
                .as_deref()
                .map(|client_id| format!("client_id:{client_id}"))
        })
        .or_else(|| verified.matched_client.clone())?;
    verified_claim_value(&client)
}

fn bounded_scopes(scopes: &[String]) -> Vec<VerifiedClaimValue> {
    scopes
        .iter()
        .filter_map(|scope| verified_claim_value(scope))
        .collect()
}

fn numeric_claim(extra: &Map<String, Value>, claim: &str) -> Option<i64> {
    extra.get(claim).and_then(Value::as_i64)
}

fn oidc_auth_error(error: OidcError) -> EvidenceError {
    tracing::debug!(
        target: "registry_notary_server::auth",
        error_code = oidc_internal_error_code(&error),
        error = ?error,
        "OIDC token verification failed"
    );
    EvidenceError::MissingCredential
}

fn oidc_internal_error_code(error: &OidcError) -> &'static str {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk => "auth.oidc_unavailable",
        OidcError::IssuerMismatch { .. }
        | OidcError::MalformedToken
        | OidcError::AlgorithmNotAllowed
        | OidcError::TokenTypeNotAllowed
        | OidcError::MissingKid
        | OidcError::KidTooLong
        | OidcError::UnknownKid
        | OidcError::TokenExpired
        | OidcError::TokenNotYetValid
        | OidcError::AudienceMismatch
        | OidcError::SignatureInvalid
        | OidcError::InvalidToken
        | OidcError::ClientNotAllowed => "auth.invalid_token",
        _ => "auth.invalid_token",
    }
}

fn parse_oidc_algorithm(algorithm: &str) -> Result<Algorithm, StandaloneServerError> {
    match algorithm {
        "EdDSA" => Ok(Algorithm::EdDSA),
        "RS256" => Ok(Algorithm::RS256),
        "PS256" => Ok(Algorithm::PS256),
        other => Err(StandaloneServerError::InvalidOidcConfig(format!(
            "unsupported OIDC signing algorithm '{other}'"
        ))),
    }
}

/// Bench-internal: exposed only for `benches/auth_bench.rs`. Not part of the
/// public API.
#[doc(hidden)]
pub fn find_credential<'a>(
    credentials: &'a [ResolvedCredential],
    token: &str,
) -> Option<&'a ResolvedCredential> {
    credentials
        .iter()
        .find(|credential| verify_api_key(token, &credential.fingerprint).unwrap_or(false))
}

fn principal_from_credential(credential: &ResolvedCredential) -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: credential.id.clone(),
        scopes: credential.scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
    }
}

fn header_str(value: &axum::http::HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

async fn rewrite_payload_too_large_problem(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE {
        return response;
    }
    let is_problem_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/problem+json"));
    if is_problem_json {
        return response;
    }
    registry_platform_httpsec::body_limit_problem_response(Request::new(Body::empty())).await
}

pub(crate) fn audit_error_response(error: AuditError) -> Response {
    tracing::error!(target: "registry_notary_server::audit", error = %error, "audit event write failed");
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/audit/write_failed", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Audit write failed",
            "status": status.as_u16(),
            "detail": "audit event could not be written",
            "code": "audit.write_failed",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json".parse().unwrap(),
    );
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext("audit.write_failed".to_string()));
    response
}

fn add_correlation_header(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(correlation_id) = REQUEST_CORRELATION_ID.try_with(|id| id.as_str().to_string()) {
        builder.header("x-request-id", correlation_id)
    } else {
        builder
    }
}

async fn read_remote_registry_data_api_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_field = binding.lookup.field.clone();
    let lookup_value = lookup_value(binding, subject)?;
    let fields = projected_source_fields_with_lookup(binding, &lookup_field);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
        (lookup_field.clone(), value_query_string(&lookup_value)?),
    ];
    let request_url = url.clone();
    let body = send_request_with_retry(sources, connection, "rda", &url, move |token| {
        add_correlation_header(
            sources
                .client
                .get(request_url.clone())
                .timeout(sources.request_timeout)
                .bearer_auth(token)
                .header("accept", "application/json")
                .header("data-purpose", purpose),
        )
        .query(&query_pairs)
    })
    .await?;
    let rows = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => rows
            .first()
            .cloned()
            .ok_or(EvidenceError::SourceUnavailable),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

async fn read_external_dci_http_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_value = lookup_value(binding, subject)?;
    let url = source_url(&connection.base_url, &connection.dci.search_path)?;
    let request_body = dci_search_request_body(&connection.dci, binding, &lookup_value)?;
    let request_url = url.clone();
    let body = send_request_with_retry(sources, connection, "dci", &url, move |token| {
        add_correlation_header(
            sources
                .client
                .post(request_url.clone())
                .timeout(sources.request_timeout)
                .bearer_auth(token)
                .header("accept", "application/json")
                .header("content-type", "application/json")
                .header("data-purpose", purpose),
        )
        .json(&request_body)
    })
    .await?;
    let rows = match get_json_path(&body, &connection.dci.records_path).and_then(Value::as_array) {
        Some(rows) => rows,
        None if dci_search_response_not_found(&body) => return Err(EvidenceError::SourceNotFound),
        None => return Err(EvidenceError::SourceUnavailable),
    };
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => project_dci_record(connection, binding, &lookup_value, &rows[0]),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

/// RDA bulk specialization: one collection GET with an `.in` filter carrying
/// all subjects' lookup values, then split rows back to subjects by lookup
/// field equality.
///
/// If the response exceeds N rows we fall back to per-subject `read_one` for
/// the whole batch (a `bulk_collision_fallback` tracing event flags the
/// misconfiguration). This preserves correctness when an operator has
/// attested uniqueness but the upstream data violates it.
async fn read_remote_registry_data_api_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let first_binding = &bindings[0].0;
    let lookup_field = first_binding.lookup.field.clone();
    let fields = projected_source_fields_with_lookup(first_binding, &lookup_field);
    let url = match registry_data_api_url(&connection.base_url, first_binding) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Compute per-subject lookup values up front. If any subject's lookup
    // cannot be derived (e.g. unsupported op), surface that error for that
    // position and exclude it from the bulk request.
    let mut lookup_values: Vec<Result<String, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        let lv = lookup_value(binding, subject)
            .and_then(|v| value_query_string(&v).map_err(|_| EvidenceError::InvalidRequest));
        lookup_values.push(lv);
    }
    // Build the in-filter CSV from the successfully-derived lookup values.
    let in_values: Vec<String> = lookup_values
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    if in_values.is_empty() {
        // Every position carries an Err already; preserve it. We can't run
        // a bulk request against an empty `.in` set.
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(invalid) => Err(invalid),
                Ok(_) => Err(EvidenceError::InvalidRequest),
            })
            .collect();
    }
    let n = in_values.len();
    // Relay parses `<field>.in=v1,v2,...` (see registry-relay/src/api/entity.rs
    // parse_filter_name). We replicate that wire format rather than the
    // value-prefix variant.
    let filter_name = format!("{}.in", lookup_field);
    let query_pairs = vec![
        ("limit".to_string(), (n + 1).to_string()),
        ("fields".to_string(), fields.join(",")),
        (filter_name, in_values.join(",")),
    ];
    let timeout_budget = bulk_timeout(connection, n);
    let request_url = url.clone();
    let body_result =
        send_request_with_retry(sources, connection, "rda_bulk", &url, move |token| {
            add_correlation_header(
                sources
                    .client
                    .get(request_url.clone())
                    .timeout(timeout_budget)
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("data-purpose", purpose),
            )
            .query(&query_pairs)
        })
        .await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            // Bulk call failed: log the underlying error once and surface
            // SourceUnavailable for every subject with a valid lookup;
            // preserve per-subject InvalidRequest for lookups that could
            // not be derived. We can't fan the same EvidenceError value
            // out (it isn't Clone), but the bulk failure mode is always
            // wire-level for connection scope, so SourceUnavailable is
            // the right discriminant for each affected position.
            tracing::warn!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "rda_bulk_request_failed",
            );
            return lookup_values
                .into_iter()
                .map(|r| match r {
                    Err(invalid) => Err(invalid),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    let rows: Vec<Value> = body
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Collision fallback: more rows than subjects means the upstream data
    // violates the operator's uniqueness attestation. Switch to per-subject
    // reads so each subject can still surface its own ambiguity error.
    if rows.len() > n {
        tracing::warn!(
            target: "registry_notary_server::bulk",
            connection_id = %connection.id,
            batch_size = n,
            row_count = rows.len(),
            "bulk_collision_fallback",
        );
        return fallback_concurrent_read_one(sources, bindings, purpose).await;
    }
    // Bucket rows by lookup field equality against each subject's lookup
    // value. The `data[i][lookup_field]` is compared against the string
    // form of the subject's lookup value.
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for lv_result in lookup_values {
        match lv_result {
            Err(e) => results.push(Err(e)),
            Ok(lv) => {
                let mut matching: Vec<&Value> = rows
                    .iter()
                    .filter(|row| {
                        row.get(&lookup_field)
                            .map(|val| value_query_string(val).ok().as_deref() == Some(lv.as_str()))
                            .unwrap_or(false)
                    })
                    .collect();
                let outcome = match matching.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => Ok(matching.remove(0).clone()),
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

/// DCI bulk specialization: one POST with N `search_request` entries, each
/// carrying a unique `reference_id`. Responses are matched back to subjects
/// by `reference_id`; per-entry projection runs through
/// `dci.bulk_records_path` (defaults to `/data/reg_records` inside one
/// `search_response[i]` entry).
async fn read_external_dci_http_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let url = match source_url(&connection.base_url, &connection.dci.search_path) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Resolve per-subject lookup values; subjects with bad lookups produce
    // an Err in the corresponding position and are excluded from the wire
    // request.
    let mut lookup_values: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        lookup_values.push(lookup_value(binding, subject));
    }
    // Build (reference_id, search_criteria) entries for each valid subject.
    let mut entry_ids: Vec<Option<String>> = Vec::with_capacity(bindings.len());
    let mut search_request: Vec<Value> = Vec::new();
    let n_valid = lookup_values.iter().filter(|r| r.is_ok()).count();
    let timestamp = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(ts) => ts,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    for (idx, lv_result) in lookup_values.iter().enumerate() {
        match lv_result {
            Err(_) => entry_ids.push(None),
            Ok(lv) => {
                let binding = &bindings[idx].0;
                let reference_id = Ulid::new().to_string();
                let criteria = match dci_search_criteria(&connection.dci, binding, lv, n_valid) {
                    Ok(c) => c,
                    Err(_) => {
                        entry_ids.push(None);
                        continue;
                    }
                };
                search_request.push(json!({
                    "reference_id": reference_id,
                    "timestamp": timestamp,
                    "search_criteria": criteria,
                }));
                entry_ids.push(Some(reference_id));
            }
        }
    }
    if search_request.is_empty() {
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(e) => Err(e),
                Ok(_) => Err(EvidenceError::SourceUnavailable),
            })
            .collect();
    }
    let message_id = Ulid::new().to_string();
    let mut request_body = json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": connection.dci.sender_id,
            "total_count": search_request.len(),
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": search_request,
        },
    });
    add_dci_envelope_options(&connection.dci, &mut request_body);
    let timeout_budget = bulk_timeout(connection, n_valid);
    let request_url = url.clone();
    let body_result =
        send_request_with_retry(sources, connection, "dci_bulk", &url, move |token| {
            add_correlation_header(
                sources
                    .client
                    .post(request_url.clone())
                    .timeout(timeout_budget)
                    .bearer_auth(token)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .header("data-purpose", purpose),
            )
            .json(&request_body)
        })
        .await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            tracing::warn!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "dci_bulk_request_failed",
            );
            return lookup_values
                .into_iter()
                .map(|r| match r {
                    Err(invalid) => Err(invalid),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    // Walk message.search_response[] and index by reference_id.
    let response_entries = body
        .pointer("/message/search_response")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by_ref: BTreeMap<String, &Value> = BTreeMap::new();
    for entry in &response_entries {
        if let Some(rid) = entry.get("reference_id").and_then(Value::as_str) {
            by_ref.insert(rid.to_string(), entry);
        }
    }
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (idx, lv_result) in lookup_values.into_iter().enumerate() {
        match (lv_result, entry_ids.get(idx).cloned().flatten()) {
            (Err(e), _) => results.push(Err(e)),
            (Ok(_), None) => results.push(Err(EvidenceError::SourceUnavailable)),
            (Ok(lookup_value_for_subject), Some(reference_id)) => {
                let binding = &bindings[idx].0;
                let entry = match by_ref.get(reference_id.as_str()) {
                    Some(e) => *e,
                    None => {
                        results.push(Err(EvidenceError::SourceNotFound));
                        continue;
                    }
                };
                let rows = get_json_path(entry, &connection.dci.bulk_records_path)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let outcome = match rows.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => {
                        project_dci_record(connection, binding, &lookup_value_for_subject, &rows[0])
                    }
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

/// Shared helper for building one DCI `search_criteria` object. Extracted
/// from `dci_search_request_body` so the batched path can produce N entries
/// without duplicating the query-shape logic. `page_size` is set to
/// `max(dci.max_results, batch_size)` so the upstream does not truncate
/// N-subject responses.
fn dci_search_criteria(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    batch_size: usize,
) -> Result<Value, EvidenceError> {
    let query = match dci.query_type.as_str() {
        "idtype-value" => json!({
            "type": binding.lookup.field,
            "value": lookup_value,
        }),
        "expression" => json!({
            binding.lookup.field.clone(): {
                binding.lookup.op.clone(): lookup_value,
            },
        }),
        "predicate" => json!([{
            "expression1": {
                "attribute_name": binding.lookup.field,
                "operator": binding.lookup.op,
                "attribute_value": lookup_value,
            },
        }]),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let mut search_criteria = Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(batch_size), "page_number": 1 }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(registry_event_type) = &dci.registry_event_type {
        search_criteria.insert(
            "reg_event_type".to_string(),
            Value::String(registry_event_type.clone()),
        );
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    Ok(Value::Object(search_criteria))
}

/// Send an outbound HTTP request to a `source_connection`, holding the
/// connection's process-global semaphore permit for the full duration of the
/// call including any retries. Single retry on transport error or HTTP 5xx,
/// with 50-150ms jittered backoff. Reads the response body into a JSON value
/// on success; treats >=400 responses as `SourceUnavailable`.
async fn send_request_with_retry(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    connector: &'static str,
    url: &reqwest::Url,
    build_request: impl Fn(String) -> reqwest::RequestBuilder,
) -> Result<Value, EvidenceError> {
    if let Err(error) = connection.fetch_url_policy.validate(url) {
        tracing::warn!(
            target: "registry_notary_server::outbound",
            connection_id = %connection.id,
            connector = connector,
            scheme = url.scheme(),
            host = url.host_str().unwrap_or("<missing>"),
            error = %error,
            "source URL rejected by fetch policy",
        );
        return Err(EvidenceError::SourceUnavailable);
    }
    let permit = connection
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let available = connection.semaphore.available_permits();
    let in_flight = connection.max_in_flight.saturating_sub(available);
    sources
        .metrics
        .set_source_in_flight(connector, in_flight as u64);
    tracing::info!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight,
        max_in_flight = connection.max_in_flight,
        "outbound permit acquired",
    );
    let start = Instant::now();
    let mut attempt: u32 = 0;
    let max_attempts = if connection.retry_on_5xx { 2 } else { 1 };
    let mut refreshed_after_401 = false;
    let mut force_refresh_next = false;
    let result = loop {
        attempt += 1;
        let force_refresh = force_refresh_next;
        force_refresh_next = false;
        let token = match connection
            .auth
            .bearer_token(&sources.client, &connection.fetch_url_policy, force_refresh)
            .await
        {
            Ok(token) => token,
            Err(error) => break Err(error),
        };
        let outcome = build_request(token).send().await;
        let retryable = match &outcome {
            Err(_) => true,
            Ok(response) => response.status().is_server_error(),
        };
        if let Ok(response) = &outcome {
            if response.status() == StatusCode::UNAUTHORIZED
                && connection.auth.can_refresh()
                && !refreshed_after_401
            {
                refreshed_after_401 = true;
                force_refresh_next = true;
                sources.metrics.record_source_retry(connector);
                tracing::info!(
                    target: "registry_notary_server::outbound",
                    connection_id = %connection.id,
                    connector = connector,
                    attempt = attempt,
                    "oauth_refresh_after_401",
                );
                continue;
            }
        }
        if attempt < max_attempts && retryable {
            sources.metrics.record_source_retry(connector);
            tracing::info!(
                target: "registry_notary_server::outbound",
                connection_id = %connection.id,
                connector = connector,
                attempt = attempt,
                "retry_attempted",
            );
            tokio::time::sleep(retry_backoff()).await;
            continue;
        }
        match outcome {
            Err(_) => break Err(EvidenceError::SourceUnavailable),
            Ok(response) => {
                if !response.status().is_success() {
                    break Err(EvidenceError::SourceUnavailable);
                }
                break read_source_json(response).await;
            }
        }
    };
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = match &result {
        Ok(_) => "success",
        Err(_) => "error",
    };
    sources
        .metrics
        .record_source_request(connector, status, latency_ms);
    tracing::debug!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        latency_ms = latency_ms,
        attempts = attempt,
        outcome = status,
        "outbound completed",
    );
    drop(permit);
    let available_after = connection.semaphore.available_permits();
    let in_flight_after = connection.max_in_flight.saturating_sub(available_after);
    sources
        .metrics
        .set_source_in_flight(connector, in_flight_after as u64);
    tracing::info!(
        target: "registry_notary_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight_after,
        max_in_flight = connection.max_in_flight,
        "outbound permit released",
    );
    result
}

/// Backoff duration for the single permitted retry. Uniform jitter in
/// [50ms, 150ms) to spread retries across concurrent failures.
fn retry_backoff() -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Hash to a value in [0, 100ms) then offset by 50ms.
    let jitter_ms = (nanos as u64) % 100;
    Duration::from_millis(50 + jitter_ms)
}

async fn read_source_json(response: reqwest::Response) -> Result<Value, EvidenceError> {
    let body = read_bounded(response, MAX_SOURCE_JSON_BYTES as u64)
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    serde_json::from_slice(&body).map_err(|_| EvidenceError::SourceUnavailable)
}

fn registry_data_api_url(
    base_url: &str,
    binding: &SourceBindingConfig,
) -> Result<reqwest::Url, EvidenceError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    httputil_url::append_path_segments(
        &base,
        &[
            "datasets",
            binding.dataset.as_str(),
            binding.entity.as_str(),
        ],
    )
    .map_err(|_| EvidenceError::SourceUnavailable)
}

fn source_url(base_url: &str, path: &str) -> Result<reqwest::Url, EvidenceError> {
    if reqwest::Url::parse(path).is_ok() {
        return Err(EvidenceError::SourceUnavailable);
    }
    let base = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(base);
    }
    let segments = trimmed.split('/').collect::<Vec<_>>();
    httputil_url::append_path_segments(&base, &segments)
        .map_err(|_| EvidenceError::SourceUnavailable)
}

fn dci_search_request_body(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
) -> Result<Value, EvidenceError> {
    let message_id = Ulid::new().to_string();
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let query = match dci.query_type.as_str() {
        "idtype-value" => json!({
            "type": binding.lookup.field,
            "value": lookup_value,
        }),
        "expression" => json!({
            binding.lookup.field.clone(): {
                binding.lookup.op.clone(): lookup_value,
            },
        }),
        "predicate" => json!([{
            "expression1": {
                "attribute_name": binding.lookup.field,
                "operator": binding.lookup.op,
                "attribute_value": lookup_value,
            },
        }]),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let mut search_criteria = Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(2), "page_number": 1 }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(registry_event_type) = &dci.registry_event_type {
        search_criteria.insert(
            "reg_event_type".to_string(),
            Value::String(registry_event_type.clone()),
        );
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    let mut body = json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": dci.sender_id,
            "total_count": 1,
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": [{
                "reference_id": message_id,
                "timestamp": timestamp,
                "search_criteria": Value::Object(search_criteria),
            }],
        },
    });
    add_dci_envelope_options(dci, &mut body);
    Ok(body)
}

fn add_dci_envelope_options(dci: &DciSourceConnectionConfig, body: &mut Value) {
    if let Some(receiver_id) = &dci.receiver_id {
        if let Some(header) = body.pointer_mut("/header").and_then(Value::as_object_mut) {
            header.insert(
                "receiver_id".to_string(),
                Value::String(receiver_id.clone()),
            );
        }
    }
    if let Some(signature) = &dci.signature {
        if let Some(object) = body.as_object_mut() {
            object.insert("signature".to_string(), Value::String(signature.clone()));
        }
    }
}

fn dci_search_response_not_found(body: &Value) -> bool {
    body.pointer("/message/search_response/0")
        .is_some_and(dci_entry_not_found)
}

fn dci_entry_not_found(entry: &Value) -> bool {
    let status = entry.get("status").and_then(Value::as_str);
    let reason_code = entry.get("status_reason_code").and_then(Value::as_str);
    let reason_message = entry
        .get("status_reason_message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    status == Some("rjct")
        && (reason_code == Some("REG-ERR-001")
            || reason_message.contains("register_not_found")
            || reason_message.contains("not found"))
}

fn project_dci_record(
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    record: &Value,
) -> Result<Value, EvidenceError> {
    let mut row = Map::new();
    insert_row_path(&mut row, &binding.lookup.field, lookup_value.clone());
    for (alias, field) in &binding.fields {
        let path = connection
            .dci
            .field_paths
            .get(&field.field)
            .or_else(|| connection.dci.field_paths.get(alias))
            .map(String::as_str)
            .unwrap_or(field.field.as_str());
        let value = get_json_path(record, path).cloned().unwrap_or(Value::Null);
        insert_row_path(&mut row, &field.field, value);
    }
    Ok(Value::Object(row))
}

pub(crate) fn get_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        return value.pointer(path);
    }
    let mut current = value;
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        current = match current {
            Value::Array(values) => values.get(part.parse::<usize>().ok()?)?,
            _ => current.get(part)?,
        };
    }
    Some(current)
}

fn insert_row_path(row: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts = path.split('.').filter(|part| !part.is_empty()).peekable();
    let Some(first) = parts.next() else {
        return;
    };
    if parts.peek().is_none() {
        row.insert(first.to_string(), value);
        return;
    }
    let mut current = row
        .entry(first.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if let Value::Object(object) = current {
                object.insert(part.to_string(), value);
            }
            return;
        }
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        current = current
            .as_object_mut()
            .expect("object was just initialized")
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

fn value_query_string(value: &Value) -> Result<String, EvidenceError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn lookup_value(
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match binding.lookup.input.as_str() {
        "subject_id" | "subject.id" => Ok(Value::String(subject.id.clone())),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn collect_claim_required_scopes(
    evidence: &EvidenceConfig,
    claim_id: &str,
    scopes: &mut Vec<String>,
) -> Result<(), EvidenceError> {
    let claim = crate::find_claim(evidence, claim_id)?;
    for binding in claim.source_bindings.values() {
        if let Some(scope) = binding.required_scope.as_deref() {
            scopes.push(scope.to_string());
        } else {
            scopes.push(format!("{}:evidence_verification", binding.dataset));
        }
    }
    for dep in &claim.depends_on {
        collect_claim_required_scopes(evidence, dep, scopes)?;
    }
    Ok(())
}

fn projected_source_fields_with_lookup(
    binding: &SourceBindingConfig,
    lookup_field: &str,
) -> Vec<String> {
    let mut fields = vec![lookup_field.to_string()];
    for field in binding.fields.values() {
        fields.push(field.field.clone());
    }
    fields.sort();
    fields.dedup();
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::response::Redirect;
    use axum::routing::get;
    use axum_test::TestServer;
    #[cfg(feature = "pkcs11")]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(feature = "pkcs11")]
    use base64::Engine;
    use registry_notary_core::{
        EvaluateRequest, SelfAttestationDenialCode, SelfAttestationRateLimitsConfig,
        SourceConnectionConfig, SourceLookupConfig, FORMAT_CLAIM_RESULT_JSON,
    };
    use registry_notary_openfn_sidecar::{sidecar_router, SidecarConfig};

    const OPENFN_SIDECAR_TOKEN_ENV: &str = "TEST_OPENFN_SIDECAR_TOKEN";
    const OPENFN_SIDECAR_TOKEN_HASH_ENV: &str = "TEST_OPENFN_SIDECAR_TOKEN_HASH";
    const OPENFN_SIDECAR_TOKEN: &str = "openfn-sidecar-token";
    const OPENFN_SIDECAR_TOKEN_HASH: &str =
        "sha256:42f3b7ab760b221b8a166aad9d82b76286e310f878e2d6cbac7583586ca1e225";
    const OPENFN_SPIKE_PURPOSE: &str = "https://purpose.example.test/eligibility";
    const TEST_AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_NOTARY_TEST_AUDIT_HASH_SECRET";
    const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
    const TEST_OLD_ISSUER_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#old"}"##;
    const TEST_OLD_HSM_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm-old"}"##;
    #[cfg(feature = "pkcs11")]
    static SOFTHSM_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn audit_event() -> EvidenceAuditEvent {
        EvidenceAuditEvent {
            event_id: "01HX0000000000000000000000".to_string(),
            occurred_at: "2026-05-22T00:00:00Z".to_string(),
            principal_id_hash: Some(Hashed::from_hash("sha256:caseworker")),
            decision: "allowed".to_string(),
            method: "GET".to_string(),
            path: "/claims".to_string(),
            status: 200,
            verification_id: None,
            claim_hash: None,
            purposes: None,
            row_count: None,
            error_code: None,
            access_mode: Some(AccessMode::MachineClient),
            federation_peer_id_hash: None,
            federation_issuer: None,
            federation_profile: None,
            federation_purpose: None,
            federation_request_jti: None,
            federation_subject_ref_hash: None,
            denial_code: None,
            token_claim_name: None,
            correlation_id: None,
            credential_profile: None,
            protocol: None,
            credential_configuration_id: None,
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_version: None,
            policy_hash: None,
        }
    }

    fn auth_state(audit: AuditPipeline) -> Arc<AuthAuditState> {
        Arc::new(AuthAuditState {
            authenticator: Authenticator::Static {
                api_keys: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: Vec::new(),
                }],
                bearer_tokens: Vec::new(),
            },
            audit,
            metrics: Arc::new(AppMetrics::default()),
            self_attestation_invalid_token_limiter: None,
            self_attestation_rate_keys: None,
        })
    }

    #[test]
    fn issuer_registry_uses_active_key_and_publishes_rotated_keys_once() {
        unsafe {
            std::env::set_var("TEST_ACTIVE_SIGNING_JWK", TEST_ISSUER_JWK);
            std::env::set_var("TEST_OLD_SIGNING_PUBLIC_JWK", TEST_OLD_ISSUER_PUBLIC_JWK);
            std::env::set_var("TEST_OLD_HSM_PUBLIC_JWK", TEST_OLD_HSM_PUBLIC_JWK);
            std::env::set_var("TEST_DISABLED_SIGNING_JWK", TEST_ISSUER_JWK);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_ACTIVE_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
  old-key:
    provider: local_jwk_env
    public_jwk_env: TEST_OLD_SIGNING_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#old
    status: publish_only
  old-hsm-key:
    provider: pkcs11
    public_jwk_env: TEST_OLD_HSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm-old
    status: publish_only
  disabled-key:
    provider: local_jwk_env
    private_jwk_env: TEST_DISABLED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#disabled
    status: disabled
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
"#,
        )
        .expect("evidence config parses");
        let registry = EvidenceIssuerRegistry::from_config(&evidence).expect("registry builds");

        assert!(registry.issuer("profile-a").is_ok());
        assert!(registry.issuer("profile-b").is_ok());
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 3);
        assert!(jwks.iter().all(|jwk| jwk.get("d").is_none()));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#active"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#old"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#hsm-old"));
        assert!(!jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#disabled"));
    }

    #[test]
    fn local_jwk_signing_key_rejects_mismatched_embedded_kid() {
        let jwk = r#"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#wrong","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
        unsafe {
            std::env::set_var("TEST_MISMATCHED_SIGNING_JWK", jwk);
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  active-key:
    provider: local_jwk_env
    private_jwk_env: TEST_MISMATCHED_SIGNING_JWK
    alg: EdDSA
    kid: did:web:issuer.example#active
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: active-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("mismatched key id must fail startup");
        assert!(
            err.to_string().contains("kid does not match"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn pkcs11_signing_key_fails_closed_when_feature_is_disabled() {
        unsafe {
            std::env::set_var(
                "TEST_PKCS11_PUBLIC_JWK",
                r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
            );
            std::env::set_var("TEST_PKCS11_PIN", "1234");
        }
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: registry-notary
    pin_env: TEST_PKCS11_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_PKCS11_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#hsm
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
"#,
        )
        .expect("evidence config parses");

        let err = EvidenceIssuerRegistry::from_config(&evidence)
            .expect_err("PKCS#11 must fail closed without feature");
        assert!(
            err.to_string().contains("provider 'pkcs11' is not enabled"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn pkcs11_signing_key_signs_with_softhsm_when_available() {
        let _guard = SOFTHSM_ENV_LOCK.lock().expect("SoftHSM env lock");
        let Some(module_path) = softhsm_module_path() else {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but softhsm2-util is not available"
            );
            eprintln!("skipping SoftHSM signing test: softhsm2-util is not available");
            return;
        };
        if command_output(std::process::Command::new("openssl").arg("version")).is_none() {
            assert!(
                !require_softhsm(),
                "REGISTRY_NOTARY_REQUIRE_SOFTHSM=1 but openssl is not available"
            );
            eprintln!("skipping SoftHSM signing test: openssl is not available");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let token_dir = tmp.path().join("tokens");
        std::fs::create_dir(&token_dir).expect("token dir is created");
        let softhsm_conf = tmp.path().join("softhsm2.conf");
        std::fs::write(
            &softhsm_conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                token_dir.display()
            ),
        )
        .expect("SoftHSM config is written");

        let token_label = format!("registry-notary-test-{}", std::process::id());
        let pin = "1234";
        unsafe {
            std::env::set_var("SOFTHSM2_CONF", &softhsm_conf);
        }
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--init-token")
                .arg("--free")
                .arg("--label")
                .arg(&token_label)
                .arg("--so-pin")
                .arg("123456")
                .arg("--pin")
                .arg(pin),
        );

        let key_path = tmp.path().join("issuer-ed25519.pem");
        run_command(
            std::process::Command::new("openssl")
                .arg("genpkey")
                .arg("-algorithm")
                .arg("ED25519")
                .arg("-out")
                .arg(&key_path),
        );
        run_command(
            std::process::Command::new("softhsm2-util")
                .arg("--import")
                .arg(&key_path)
                .arg("--token")
                .arg(&token_label)
                .arg("--pin")
                .arg(pin)
                .arg("--label")
                .arg("issuer-signing-key")
                .arg("--id")
                .arg("01ab23cd")
                .arg("--force"),
        );

        let public_der = command_output(
            std::process::Command::new("openssl")
                .arg("pkey")
                .arg("-in")
                .arg(&key_path)
                .arg("-pubout")
                .arg("-outform")
                .arg("DER"),
        )
        .expect("openssl exports public key");
        assert!(
            public_der.len() >= 32,
            "Ed25519 SubjectPublicKeyInfo has key bytes"
        );
        let x = URL_SAFE_NO_PAD.encode(&public_der[public_der.len() - 32..]);
        let public_jwk_primary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm"
        })
        .to_string();
        let public_jwk_secondary = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": "did:web:issuer.example#softhsm-secondary"
        })
        .to_string();
        unsafe {
            std::env::set_var("TEST_SOFTHSM_PIN", pin);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK", public_jwk_primary);
            std::env::set_var("TEST_SOFTHSM_PUBLIC_JWK_SECONDARY", public_jwk_secondary);
        }

        let evidence: EvidenceConfig = serde_norway::from_str(&format!(
            r#"
enabled: true
signing_keys:
  hsm-key:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK
    alg: EdDSA
    kid: did:web:issuer.example#softhsm
    status: active
  hsm-key-secondary:
    provider: pkcs11
    module_path: {module_path}
    token_label: {token_label}
    pin_env: TEST_SOFTHSM_PIN
    key_label: issuer-signing-key
    key_id_hex: 01ab23cd
    public_jwk_env: TEST_SOFTHSM_PUBLIC_JWK_SECONDARY
    alg: EdDSA
    kid: did:web:issuer.example#softhsm-secondary
    status: active
credential_profiles:
  profile-a:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key
    vct: https://issuer.example/credentials/a
    allowed_claims: [claim-a]
  profile-b:
    format: application/dc+sd-jwt
    issuer: did:web:issuer.example
    signing_key: hsm-key-secondary
    vct: https://issuer.example/credentials/b
    allowed_claims: [claim-b]
"#,
        ))
        .expect("evidence config parses");

        let registry =
            EvidenceIssuerRegistry::from_config(&evidence).expect("SoftHSM signer builds");
        let jwks = registry.public_jwks(&evidence).expect("JWKS builds");
        assert_eq!(jwks.len(), 2);
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm"));
        assert!(jwks
            .iter()
            .any(|jwk| jwk["kid"] == "did:web:issuer.example#softhsm-secondary"));
        assert!(registry.issuer("profile-a").is_ok());
        assert!(registry.issuer("profile-b").is_ok());
    }

    #[cfg(feature = "pkcs11")]
    fn softhsm_module_path() -> Option<String> {
        if let Some(path) = command_output(
            std::process::Command::new("softhsm2-util")
                .arg("--show-config")
                .arg("default-pkcs11-lib"),
        )
        .and_then(|output| String::from_utf8(output).ok())
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty() && std::path::Path::new(path).is_absolute())
        {
            return Some(path);
        }

        [
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so",
            "/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .map(str::to_string)
    }

    #[cfg(feature = "pkcs11")]
    fn require_softhsm() -> bool {
        std::env::var("REGISTRY_NOTARY_REQUIRE_SOFTHSM")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    #[cfg(feature = "pkcs11")]
    fn command_output(command: &mut std::process::Command) -> Option<Vec<u8>> {
        let output = command.output().ok()?;
        output.status.success().then_some(output.stdout)
    }

    #[cfg(feature = "pkcs11")]
    fn run_command(command: &mut std::process::Command) {
        let output = command.output().expect("command starts");
        assert!(
            output.status.success(),
            "command failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn test_audit_config(sink: &str) -> registry_notary_core::EvidenceAuditConfig {
        std::env::set_var(
            TEST_AUDIT_HASH_SECRET_ENV,
            "0123456789abcdef0123456789abcdef",
        );
        registry_notary_core::EvidenceAuditConfig {
            sink: sink.to_string(),
            hash_secret_env: Some(TEST_AUDIT_HASH_SECRET_ENV.to_string()),
            ..registry_notary_core::EvidenceAuditConfig::default()
        }
    }

    #[test]
    fn audit_event_carries_self_attestation_context_fields() {
        let principal = EvidencePrincipal {
            principal_id: "citizen".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };
        let mut response = StatusCode::FORBIDDEN.into_response();
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_id: None,
            verification_decision: Some("evaluate_denied".to_string()),
            claim_hash: Some("sha256:claim-hash".to_string()),
            purposes: None,
            row_count: None,
            access_mode: Some(AccessMode::SelfAttestation),
            denial_code: Some(SelfAttestationDenialCode::SubjectMismatch),
            token_claim_name: Some(
                registry_notary_core::ConfigMetadata::new("national_id").expect("bounded"),
            ),
            credential_profile: None,
            protocol: Some(
                registry_notary_core::ConfigMetadata::new("openid4vci").expect("bounded"),
            ),
            credential_configuration_id: Some(
                registry_notary_core::ConfigMetadata::new("person_is_alive_sd_jwt")
                    .expect("bounded"),
            ),
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_hash: None,
        });

        let event = build_audit_event(
            Some(&principal),
            &AuditKeyHasher::unkeyed_dev_only(),
            "POST",
            "/claims/evaluate",
            BoundedCorrelationId::new("req-123").expect("test correlation id is bounded"),
            &response,
        );

        assert_eq!(event.decision, "evaluate_denied");
        assert_eq!(event.claim_hash.as_deref(), Some("sha256:claim-hash"));
        assert_eq!(event.access_mode, Some(AccessMode::SelfAttestation));
        assert!(event.principal_id_hash.is_some());
        assert_eq!(
            event
                .correlation_id
                .as_ref()
                .map(BoundedCorrelationId::as_str),
            Some("req-123")
        );
        assert_eq!(
            event.denial_code,
            Some(SelfAttestationDenialCode::SubjectMismatch)
        );
        assert_eq!(
            event.protocol.as_ref().map(|value| value.as_str()),
            Some("openid4vci")
        );
        assert_eq!(
            event
                .credential_configuration_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("person_is_alive_sd_jwt")
        );
    }

    fn test_binding(dataset: &str, entity: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: Some("registry".to_string()),
            required_scope: None,
            dataset: dataset.to_string(),
            entity: entity.to_string(),
            lookup: SourceLookupConfig {
                input: "subject_id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            fields: BTreeMap::new(),
        }
    }

    fn test_source_config(base_url: &str, allow_insecure_localhost: bool) -> EvidenceConfig {
        EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: base_url.to_string(),
                    allow_insecure_localhost,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_POLICY_TOKEN".to_string(),
                    source_auth: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        }
    }

    fn openfn_sidecar_spike_config(base_url: &str) -> EvidenceConfig {
        let raw = format!(
            r#"
enabled: true
service_id: spike.registry-notary
source_connections:
  openfn_crvs:
    base_url: "{base_url}"
    allow_insecure_localhost: true
    retry_on_5xx: false
    token_env: {OPENFN_SIDECAR_TOKEN_ENV}
claims:
  - id: date-of-birth
    title: Date of birth
    version: 2026-05
    subject_type: person
    value:
      type: date
    inputs:
      - name: subject_id
        type: string
    source_bindings:
      crvs:
        connector: registry_data_api
        connection: openfn_crvs
        required_scope: civil_registry:evidence_verification
        dataset: civil_registry
        entity: civil_person
        lookup:
          input: subject_id
          field: national_id
          op: eq
          cardinality: one
        fields:
          birth_date:
            field: birth_date
            type: date
            required: true
    rule:
      type: extract
      source: crvs
      field: birth_date
    disclosure:
      default: value
      allowed:
        - value
        - redacted
    formats:
      - "{FORMAT_CLAIM_RESULT_JSON}"
"#
        );
        serde_norway::from_str(&raw).expect("spike config parses")
    }

    fn openfn_sidecar_test_config(attempt_log: std::path::PathBuf) -> SidecarConfig {
        std::env::set_var(OPENFN_SIDECAR_TOKEN_HASH_ENV, OPENFN_SIDECAR_TOKEN_HASH);
        let sidecar_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../registry-notary-openfn-sidecar");
        let worker = sidecar_root.join("tests/fixtures/contract_worker.sh");
        let job = sidecar_root.join("tests/fixtures/jobs/opencrvs-person-lookup.js");
        let raw = format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: "{OPENFN_SIDECAR_TOKEN_HASH_ENV}"
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  max_worker_memory_mb: 256
openfn:
  cli_build_tool: "1.36.0"
  runtime: "1.36.0"
worker:
  command: "/bin/sh"
  args:
    - "{}"
    - "{}"
sources:
  openfn_crvs:
    dataset: civil_registry
    entity: civil_person
    workflow:
      steps:
        - id: lookup
          expression: "{}"
          adaptors:
            - "@openfn/language-http@7.2.0"
    credential_env: TEST_OPENCRVS_READER_CREDENTIAL_JSON
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
            worker.display(),
            attempt_log.display(),
            job.display()
        );
        serde_norway::from_str(&raw).expect("sidecar test config parses")
    }

    #[test]
    fn source_fetch_url_policy_private_network_escape_hatch_keeps_metadata_denial() {
        let config = test_source_config("http://registry-relay:8080", false);
        let mut connection = config
            .source_connections
            .get("registry")
            .expect("source connection")
            .clone();
        connection.allow_insecure_private_network = true;

        let policy = source_fetch_url_policy(&connection);

        assert_eq!(policy.allowed_schemes, ["http", "https"]);
        assert!(policy.allow_localhost);
        assert!(policy.allow_http_private_network);
        assert!(!policy.deny_private_ranges);
        assert!(policy.deny_cloud_metadata);
    }

    #[test]
    fn source_fetch_url_policy_defaults_to_strict() {
        let config = test_source_config("https://registry.example.test", false);
        let connection = config
            .source_connections
            .get("registry")
            .expect("source connection");

        assert_eq!(
            source_fetch_url_policy(connection),
            FetchUrlPolicy::strict()
        );
    }

    #[tokio::test]
    async fn audit_pipeline_emits_chained_jsonl() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let output = std::fs::read_to_string(path).expect("audit output is readable");
        assert!(output.ends_with('\n'));
        assert_eq!(output.lines().count(), 1);

        let line: Value = serde_json::from_str(output.trim_end()).expect("audit line is JSON");
        assert!(line["envelope_id"].as_str().is_some());
        assert_eq!(
            line["record"]["event_id"],
            json!("01HX0000000000000000000000")
        );
        assert!(line["record"]["principal_id_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(line["record"].get("principal_id").is_none());
        assert!(line["record"].get("fields").is_none());
        assert!(line["record"].get("audit").is_none());
    }

    #[tokio::test]
    async fn audit_pipeline_file_sink_uses_configured_rotation() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let mut config = test_audit_config("file");
        config.path = Some(path.display().to_string());
        config.max_size_bytes = Some(1);
        config.max_files = Some(2);
        let audit = AuditPipeline::from_config(&config).expect("audit config builds");

        for _ in 0..3 {
            audit
                .emit(&audit_event())
                .await
                .expect("audit write succeeds");
        }

        assert!(path.exists(), "active audit file should exist");
        assert!(
            tmp.path().join("audit.jsonl.1").exists(),
            "rotated audit file should exist"
        );
        assert!(
            !tmp.path().join("audit.jsonl.2").exists(),
            "rotation should retain only the configured number of files"
        );
    }

    #[test]
    fn audit_pipeline_accepts_syslog_sink_config() {
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some("/tmp/registry-notary-test-syslog.sock".to_string());

        AuditPipeline::from_config(&config).expect("syslog audit config builds");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn audit_pipeline_syslog_sink_writes_to_configured_socket() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let socket_path = tmp.path().join("audit.sock");
        let socket = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some(socket_path.display().to_string());
        let audit = AuditPipeline::from_config(&config).expect("syslog audit config builds");

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let mut buffer = vec![0; 8192];
        let bytes = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("syslog datagram is received")
            .expect("syslog socket receives datagram");
        let frame = std::str::from_utf8(&buffer[..bytes]).expect("syslog frame is UTF-8");
        assert!(frame.starts_with("<134>1 "));
        assert!(frame.contains("registry-platform-audit"));
        assert!(frame.contains(r#""event_id":"01HX0000000000000000000000""#));
    }

    #[test]
    fn audit_pipeline_rejects_zero_file_retention() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut config = test_audit_config("file");
        config.path = Some(tmp.path().join("audit.jsonl").display().to_string());
        config.max_files = Some(0);

        let error = AuditPipeline::from_config(&config).expect_err("zero retention is rejected");

        assert!(matches!(
            error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
        assert!(
            error.to_string().contains("max_files"),
            "error should name the invalid field"
        );
    }

    #[test]
    fn audit_pipeline_rejects_sink_specific_fields_on_wrong_sink() {
        let mut stdout_config = test_audit_config("stdout");
        stdout_config.max_size_bytes = Some(1024);
        let stdout_error = AuditPipeline::from_config(&stdout_config)
            .expect_err("stdout cannot accept file rotation");
        assert!(matches!(
            stdout_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));

        let mut file_config = test_audit_config("file");
        file_config.path = Some("/tmp/audit.jsonl".to_string());
        file_config.syslog_socket_path = Some("/tmp/syslog.sock".to_string());
        let file_error =
            AuditPipeline::from_config(&file_config).expect_err("file cannot accept syslog path");
        assert!(matches!(
            file_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
    }

    #[tokio::test]
    async fn openfn_sidecar_rda_facade_can_source_single_item_attestation() {
        std::env::set_var(OPENFN_SIDECAR_TOKEN_ENV, OPENFN_SIDECAR_TOKEN);
        std::env::set_var(
            "TEST_OPENCRVS_READER_CREDENTIAL_JSON",
            r#"{"apiToken":"fixture-token"}"#,
        );
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sidecar = sidecar_router(openfn_sidecar_test_config(
            tmp.path().join("attempts.jsonl"),
        ))
        .await
        .expect("sidecar router builds");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(openfn_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };

        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    subject: SubjectRequest {
                        id: "person-123".to_string(),
                        id_type: None,
                    },
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(OPENFN_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await
            .expect("OpenFn sidecar facade sources the claim");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "date-of-birth");
        assert_eq!(results[0].value, Some(json!("1990-01-01")));
        assert_eq!(results[0].provenance.source_count, 1);
    }

    #[tokio::test]
    async fn openfn_sidecar_rda_failures_are_not_retried_by_notary() {
        std::env::set_var(OPENFN_SIDECAR_TOKEN_ENV, OPENFN_SIDECAR_TOKEN);
        std::env::set_var(
            "TEST_OPENCRVS_READER_CREDENTIAL_JSON",
            r#"{"apiToken":"fixture-token"}"#,
        );
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let attempt_log = tmp.path().join("attempts.jsonl");
        let sidecar = sidecar_router(openfn_sidecar_test_config(attempt_log.clone()))
            .await
            .expect("sidecar router builds");
        let server = TestServer::builder().http_transport().build(sidecar);
        let evidence = Arc::new(openfn_sidecar_spike_config(
            server
                .server_address()
                .expect("HTTP transport exposes sidecar address")
                .as_str(),
        ));
        let source = Arc::new(
            HttpEvidenceSources::from_config(&evidence, Arc::new(AppMetrics::default()))
                .expect("source config"),
        );
        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["civil_registry:evidence_verification".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };

        let result = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source,
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    subject: SubjectRequest {
                        id: "retry-sentinel".to_string(),
                        id_type: None,
                    },
                    claims: vec![registry_notary_core::ClaimRef::from("date-of-birth")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some(OPENFN_SPIKE_PURPOSE.to_string()),
                },
                None,
            )
            .await;

        assert!(result.is_err());
        let attempts = std::fs::read_to_string(attempt_log)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("retry-sentinel"))
            .count();
        assert_eq!(attempts, 1, "Notary must not retry sidecar failures");
    }

    #[tokio::test]
    async fn audit_sink_emit_surfaces_file_write_errors() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));

        let error = audit
            .emit(&audit_event())
            .await
            .expect_err("file write error is returned");

        assert!(matches!(error, AuditError::Io(_)));
    }

    #[tokio::test]
    async fn audit_write_failure_replaces_authorized_response_with_request_error() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(auth_state(audit), auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let response = server.get("/ok").add_header("x-api-key", "api-token").await;

        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("audit.write_failed"));
    }

    #[tokio::test]
    async fn invalid_bearer_tokens_are_rate_limited_when_self_attestation_is_enabled() {
        let rate_limits = SelfAttestationRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 1,
            per_principal_per_minute: 1,
            subject_mismatch_per_principal_per_hour: 1,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 1,
            ..SelfAttestationRateLimitsConfig::default()
        };
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new()));
        let state = Arc::new(AuthAuditState {
            authenticator: Authenticator::Static {
                api_keys: Vec::new(),
                bearer_tokens: Vec::new(),
            },
            audit: audit.clone(),
            metrics: Arc::new(AppMetrics::default()),
            self_attestation_invalid_token_limiter: Some(Arc::new(
                SelfAttestationRateLimiter::new(rate_limits),
            )),
            self_attestation_rate_keys: Some(Arc::new(SelfAttestationRateLimitKeys::new(
                audit.hasher.clone(),
            ))),
        });
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state, auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let first = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        first.assert_status(StatusCode::UNAUTHORIZED);

        let second = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        second.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: Value = second.json();
        assert_eq!(body["code"], json!("self_attestation.rate_limited"));
    }

    #[tokio::test]
    async fn auth_state_accepts_case_insensitive_bearer_scheme() {
        let state = AuthAuditState {
            authenticator: Authenticator::Static {
                api_keys: Vec::new(),
                bearer_tokens: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: vec!["farmer_registry:evidence_verification".to_string()],
                }],
            },
            audit: AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new())),
            metrics: Arc::new(AppMetrics::default()),
            self_attestation_invalid_token_limiter: None,
            self_attestation_rate_keys: None,
        };
        let request = Request::builder()
            .uri("/claims")
            .header(header::AUTHORIZATION, "BEARER api-token")
            .body(Body::empty())
            .expect("request builds");

        let principal = state
            .authenticate(request_credentials(&request))
            .await
            .expect("bearer auth succeeds");

        assert_eq!(principal.principal_id, "caseworker");
    }

    #[tokio::test]
    async fn static_auth_rejects_multiple_credential_headers() {
        let authenticator = Authenticator::Static {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
            }],
            bearer_tokens: vec![ResolvedCredential {
                id: "bearer-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("bearer-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
            }],
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };

        let err = authenticator
            .authenticate(request)
            .await
            .expect_err("multiple credentials must fail");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[tokio::test]
    async fn static_auth_rejects_api_key_with_malformed_authorization_header() {
        let authenticator = Authenticator::Static {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
            }],
            bearer_tokens: Vec::new(),
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        let err = authenticator
            .authenticate(request)
            .await
            .expect_err("ambiguous credentials must not fall back to api key");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[test]
    fn oidc_id_token_is_supplemental_not_a_separate_auth_mode() {
        let oidc_request = RequestCredentials {
            api_key: None,
            authorization_present: true,
            bearer_token: Some("access-token".to_string()),
            id_token: Some("id-token".to_string()),
        };
        let api_key_and_bearer = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };
        let api_key_and_malformed_authorization = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        assert_eq!(oidc_request.credential_type_count(), 1);
        assert_eq!(api_key_and_bearer.credential_type_count(), 2);
        assert_eq!(
            api_key_and_malformed_authorization.credential_type_count(),
            2
        );
    }

    #[test]
    fn static_credentials_have_machine_access_and_no_verified_claims() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };

        let authenticated =
            authenticate_static(&request, &[credential], &[]).expect("static auth succeeds");

        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "caseworker");
        assert_eq!(
            authenticated.scopes,
            vec!["farmer_registry:evidence_verification".to_string()]
        );
        assert!(authenticated.verified_claims.is_none());
    }

    #[test]
    fn oidc_principal_carries_bounded_verified_claims() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let mut extra = Map::new();
        extra.insert("scope".to_string(), json!("openid evidence:self_attest"));
        extra.insert(subject_binding_claim.to_string(), json!("NAT-123"));
        extra.insert("acr".to_string(), json!("loa3"));
        extra.insert("auth_time".to_string(), json!(1_700_000_000_i64));
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::Many(vec![
                    "registry-notary".to_string(),
                    "citizen-portal".to_string(),
                ])),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: Some("fallback-client".to_string()),
                extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "evidence:self_attest".to_string()],
        };

        let authenticated = principal_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            subject_binding_claim,
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "NAT-123");
        assert_eq!(
            verified_claims.issuer.as_str(),
            "https://issuer.example.test"
        );
        assert_eq!(
            verified_claims
                .audiences
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["registry-notary", "citizen-portal"]
        );
        assert_eq!(
            verified_claims
                .client_id
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("azp:citizen-client")
        );
        assert_eq!(
            verified_claims
                .token_type
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("JWT")
        );
        assert_eq!(
            verified_claims
                .scopes
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["openid", "evidence:self_attest"]
        );
        assert_eq!(
            verified_claims
                .subject
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("login-subject-123")
        );
        assert_eq!(
            verified_claims
                .subject_binding_claim
                .as_ref()
                .map(VerifiedClaimName::as_str),
            Some(subject_binding_claim)
        );
        assert_eq!(
            verified_claims
                .subject_binding_value
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("NAT-123")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("loa3")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_000));
        assert_eq!(verified_claims.exp, Some(1_700_003_600));
        assert_eq!(verified_claims.iat, Some(1_700_000_000));
        assert_eq!(verified_claims.nbf, Some(1_699_999_900));
    }

    #[test]
    fn oidc_principal_can_bind_userinfo_claims_and_id_token_assurance() {
        let mut access_extra = Map::new();
        access_extra.insert("scope".to_string(), json!("openid self_attestation"));
        let access_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: None,
                azp: Some("citizen-client".to_string()),
                client_id: Some("citizen-client".to_string()),
                extra: access_extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "self_attestation".to_string()],
        };
        let mut userinfo_extra = Map::new();
        userinfo_extra.insert("individual_id".to_string(), json!("NID-1001"));
        let userinfo = registry_platform_oidc::Claims {
            sub: Some("pairwise-subject".to_string()),
            iss: Some("https://issuer.example.test".to_string()),
            aud: None,
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra: userinfo_extra,
        };
        let mut id_token_extra = Map::new();
        id_token_extra.insert("acr".to_string(), json!("mosip:idp:acr:generated-code"));
        id_token_extra.insert("auth_time".to_string(), json!(1_700_000_010_i64));
        let id_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_010),
                nbf: None,
                azp: None,
                client_id: None,
                extra: id_token_extra,
            },
            matched_client: None,
            scopes: Vec::new(),
        };

        let authenticated = principal_from_oidc(
            &access_token,
            Some(&userinfo),
            Some(&id_token),
            verified_claim_value("JWT"),
            "sub",
            Some("individual_id"),
            SelfAttestationClaimSource::Userinfo,
            SelfAttestationAssuranceClaimSource::IdToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(authenticated.principal_id, "pairwise-subject");
        assert_eq!(
            verified_claims.subject_binding_value("individual_id"),
            Some("NID-1001")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("mosip:idp:acr:generated-code")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_010));
    }

    #[test]
    fn oidc_verified_claims_fail_closed_without_string_subject_binding_claim() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("registry-notary".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: None,
                extra: Map::new(),
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["evidence:self_attest".to_string()],
        };

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .is_none());

        let mut verified = verified;
        verified
            .claims
            .extra
            .insert(subject_binding_claim.to_string(), json!(12345));

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SelfAttestationClaimSource::AccessToken,
            SelfAttestationAssuranceClaimSource::AccessToken,
        )
        .is_none());
    }

    #[test]
    fn oidc_validation_errors_are_internal_invalid_token_auth_failures() {
        assert_eq!(
            oidc_internal_error_code(&OidcError::TokenExpired),
            "auth.invalid_token"
        );
        assert!(matches!(
            oidc_auth_error(OidcError::TokenExpired),
            EvidenceError::MissingCredential
        ));
    }

    #[test]
    fn resolved_credential_debug_output_is_redacted() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
        };
        let connection = ResolvedEvidenceSourceConnection {
            id: "registry".to_string(),
            base_url: "https://registry.example.test".to_string(),
            auth: SourceAuthRuntime::StaticBearer(Arc::from("source-token")),
            fetch_url_policy: FetchUrlPolicy::strict(),
            dci: DciSourceConnectionConfig::default(),
            semaphore: Arc::new(Semaphore::new(8)),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_timeout_max: Duration::from_secs(30),
        };

        let debug = format!("{credential:?} {connection:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("api-token"));
        assert!(!debug.contains("source-token"));
    }

    #[test]
    fn registry_data_api_url_percent_encodes_dataset_and_entity_segments() {
        let binding = test_binding("farmer/registry", "farmer?active");

        let url = registry_data_api_url("https://registry.example.test/api", &binding)
            .expect("url builds");

        assert_eq!(
            url.as_str(),
            "https://registry.example.test/api/datasets/farmer%2Fregistry/farmer%3Factive"
        );
    }

    #[test]
    fn dci_source_url_rejects_absolute_search_paths() {
        assert!(source_url(
            "https://registry.example.test",
            "https://attacker.example.test/dci/search"
        )
        .is_err());
        assert!(source_url("https://registry.example.test", "file:///tmp/search").is_err());
        assert_eq!(
            source_url("https://registry.example.test/base", "/dci/search")
                .expect("relative path is accepted")
                .as_str(),
            "https://registry.example.test/base/dci/search"
        );
    }

    #[tokio::test]
    async fn source_json_reader_rejects_oversized_body() {
        let app = Router::new().route(
            "/too-large",
            get(|| async { "x".repeat(MAX_SOURCE_JSON_BYTES + 1) }),
        );
        let server = TestServer::builder().http_transport().build(app);
        let url = format!(
            "{}too-large",
            server
                .server_address()
                .expect("HTTP transport exposes upstream address")
        );
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client builds")
            .get(url)
            .send()
            .await
            .expect("request succeeds");

        let error = read_source_json(response)
            .await
            .expect_err("oversized body is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_do_not_follow_upstream_redirects() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN", "source-token");
        let app = Router::new()
            .route(
                "/datasets/farmer_registry/farmer",
                get(|| async { Redirect::temporary("/redirect-target") }),
            )
            .route(
                "/redirect-target",
                get(|| async {
                    Json(json!({
                        "data": [{
                            "id": "person-1",
                            "total_farmed_area": 3.5
                        }]
                    }))
                }),
            );
        let server = TestServer::builder().http_transport().build(app);
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: server
                        .server_address()
                        .expect("HTTP transport exposes upstream address")
                        .to_string(),
                    allow_insecure_localhost: true,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN".to_string(),
                    source_auth: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };
        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");
        let mut binding = test_binding("farmer_registry", "farmer");
        binding.fields.insert(
            "total_farmed_area".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "total_farmed_area".to_string(),
                field_type: Some("number".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("redirect response is not followed");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_private_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("https://10.0.0.1", false),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("private source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_reject_cloud_metadata_source_urls_before_fetch() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_POLICY_TOKEN", "source-token");
        let sources = HttpEvidenceSources::from_config(
            &test_source_config("http://169.254.169.254", true),
            Arc::new(AppMetrics::default()),
        )
        .expect("source config resolves");
        let binding = test_binding("farmer_registry", "farmer");
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("metadata source URL is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[test]
    fn http_sources_from_config_sets_finite_request_timeout() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN", "source-token");
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                registry_notary_core::SourceConnectionConfig {
                    base_url: "https://registry.example.test".to_string(),
                    allow_insecure_localhost: false,
                    allow_insecure_private_network: false,
                    token_env: "TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN".to_string(),
                    source_auth: None,
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    retry_on_5xx: true,
                    bulk_mode: registry_notary_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };

        let sources = HttpEvidenceSources::from_config(&config, Arc::new(AppMetrics::default()))
            .expect("source config resolves");

        assert_eq!(sources.request_timeout, SOURCE_REQUEST_TIMEOUT);
        assert!(sources.request_timeout > Duration::ZERO);
    }
}
