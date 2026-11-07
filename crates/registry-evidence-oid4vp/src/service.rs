//! The HTTP service: portal endpoints authenticated by an applicant token, the
//! wallet endpoints that serve the signed request object and take the
//! encrypted response, the Evidence endpoint that reads a received
//! presentation, and the operational routes.

use std::{
    future::{Future, IntoFuture},
    io,
    sync::Arc,
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware::{from_fn, from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, SecondsFormat, Utc};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{
    normalize_framework_rejection, request_body_limit, security_headers, CspBuilder,
    FrameworkRejection, Problem, TraceContext,
};
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use registry_platform_yaml::Diagnostic;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use tokio::{net::TcpListener, sync::watch};
use zeroize::Zeroizing;

use crate::{
    audit::{AuditFailure, Pending, SessionAudit},
    auth::{AuthError, TokenAuthenticator},
    client_identifier::RequestIdentity,
    config::{Oid4vpConfig, PolicyConfig},
    metrics::{metrics_app, Event, Metrics},
    problem::ProblemCode,
    request_object,
    response::{self, Refusal, Submission},
    session::{
        spawn_cleanup, system_clock, Claim, Clock, Digest32, Held, NewSession, Outcome, Principal,
        Prior, Reserve, SessionStatus, SessionStore, StoreError,
    },
};

/// Create a session.
pub const SESSIONS_PATH: &str = "/v1/sessions";
/// Read a session's status.
pub const SESSION_PATH: &str = "/v1/sessions/{reference}";
/// The wallet fetches its request object here.
pub const REQUEST_PATH: &str = "/v1/requests/{request_id}";
/// The prefix of the response URI (`direct_post.jwt`) a request names.
pub const RESPONSE_PATH_PREFIX: &str = "/v1/responses/";
/// The wallet posts its encrypted response here (OpenID4VP 1.0 section 8.3.1).
pub const RESPONSE_PATH: &str = "/v1/responses/{request_id}";
/// The DID document of a `did:web` client identifier. Served only when the
/// deployment configures one.
pub const DID_DOCUMENT_PATH: &str = "/.well-known/did.json";
/// The public keys of the EdDSA client identifiers, the `jwks_uri` a wallet
/// operator registers. Served only when the deployment configures one.
pub const JWKS_PATH: &str = "/v1/jwks";
/// Evidence reads a received presentation here. The session reference travels
/// in the body so it stays out of access logs.
pub const READ_PATH: &str = "/v1/presentations/read";
pub const HEALTH_PATH: &str = "/health";
pub const READY_PATH: &str = "/ready";

/// The wallet invocation scheme (OpenID4VP 1.0 section 13.1 custom URL
/// scheme).
const WALLET_SCHEME: &str = "openid4vp://authorize";

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// How long a caller is told to wait when the session store is full.
const CAPACITY_RETRY_SECONDS: u64 = 30;
/// How long a cache may keep the DID document and the key set. Short, so a
/// key change reaches wallets within minutes.
const IDENTITY_DOCUMENT_CACHE: &str = "public, max-age=300";

/// The service could not start. Carries the diagnostic that names what to fix.
#[derive(Debug)]
pub struct StartupError {
    diagnostic: Box<Diagnostic>,
}

impl StartupError {
    fn new(
        code: &'static str,
        pointer: &'static str,
        message: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            diagnostic: Box::new(Diagnostic::error(code, pointer, message, action)),
        }
    }

    /// The diagnostic in the shared shape.
    #[must_use]
    pub fn diagnostic(&self) -> &Diagnostic {
        &self.diagnostic
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.diagnostic.code, self.diagnostic.path, self.diagnostic.message
        )
    }
}

impl std::error::Error for StartupError {}

impl StartupError {
    fn from_identity(error: &crate::client_identifier::IdentityError, index: usize) -> Self {
        Self {
            diagnostic: Box::new(error.diagnostic(index)),
        }
    }
}

/// Everything the handlers share.
pub struct VerifierService {
    config: Oid4vpConfig,
    store: Arc<SessionStore>,
    identities: Vec<RequestIdentity>,
    /// The serialized DID document, when a `did:web` identifier is configured.
    did_document: Option<String>,
    /// The serialized key set, when an EdDSA identifier is configured.
    jwks: Option<String>,
    applicants: TokenAuthenticator,
    evidence_credentials: TokenAuthenticator,
    audit: SessionAudit,
    metrics: Arc<Metrics>,
    session_limiter: TokenBucketLimiter,
    wallet_limiter: TokenBucketLimiter,
    response_limiter: TokenBucketLimiter,
    response_request_limiter: TokenBucketLimiter,
    read_limiter: TokenBucketLimiter,
    /// The client identifiers whose certificate expiry has been logged.
    expiry_warned: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl std::fmt::Debug for VerifierService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifierService")
            .field("public_base_url", &self.config.public_base_url)
            .finish_non_exhaustive()
    }
}

impl VerifierService {
    /// Resolve every secret and key source and open the audit destination.
    pub async fn load(config: Oid4vpConfig) -> Result<Self, StartupError> {
        Self::load_with_clock(config, system_clock()).await
    }

    /// [`Self::load`] with the clock supplied, so a test controls expiry.
    pub async fn load_with_clock(config: Oid4vpConfig, clock: Clock) -> Result<Self, StartupError> {
        let resolver = config.secret_providers.resolver().map_err(|_| {
            StartupError::new(
                "evidence.oid4vp.secret-providers",
                "/secretProviders",
                "the secret providers could not be set up",
                "Declare secretProviders.file with an absolute root, or secretProviders.environment as {}.",
            )
        })?;
        let mut identities: Vec<RequestIdentity> = Vec::new();
        for (index, identifier) in config.client_identifiers.iter().enumerate() {
            let identity =
                RequestIdentity::resolve(identifier, &config.public_host, &resolver, clock())
                    .map_err(|error| StartupError::from_identity(&error, index))?;
            if identities
                .iter()
                .any(|other| other.client_id() == identity.client_id())
            {
                return Err(StartupError::from_identity(
                    &crate::client_identifier::IdentityError::DuplicateClientId,
                    index,
                ));
            }
            identities.push(identity);
        }
        let did_document = identities
            .iter()
            .find_map(RequestIdentity::did_document)
            .map(serde_json::Value::to_string);
        let keys: Vec<serde_json::Value> = identities
            .iter()
            .filter_map(RequestIdentity::jwks_entry)
            .collect();
        let jwks = (!keys.is_empty()).then(|| json!({ "keys": keys }).to_string());
        let applicants = TokenAuthenticator::build(&config.applicant_tokens, &resolver)
            .await
            .map_err(|_| issuer_unavailable("/applicantTokens"))?;
        let evidence_credentials =
            TokenAuthenticator::build(&config.evidence_credentials, &resolver)
                .await
                .map_err(|_| issuer_unavailable("/evidenceCredentials"))?;

        let audit_key = resolver
            .resolve_binary_reference(&config.audit.key.hash_key_ref)
            .map_err(|_| {
                StartupError::new(
                    "evidence.oid4vp.secret-unavailable",
                    "/audit/hashKeyRef",
                    "the audit hash key secret could not be read",
                    "Provide the audit hash key at the referenced secret.",
                )
            })?;
        let destination = config.audit.destination().map_err(|_| {
            StartupError::new(
                "evidence.oid4vp.invalid-audit",
                "/audit",
                "the audit destination settings are invalid",
                "Use stdout without file settings, or an absolute file path.",
            )
        })?;
        let audit = SessionAudit::initialize(
            destination,
            Zeroizing::new(audit_key.expose_secret().to_vec()),
        )
        .await
        .map_err(|_: AuditFailure| {
            StartupError::new(
                "evidence.oid4vp.audit-unavailable",
                "/audit",
                "the audit destination could not be opened",
                "Check the audit destination is writable and not locked by another process.",
            )
        })?;

        let limits = &config.rate_limits;
        let limiter = |requests_per_minute, burst| {
            TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute,
                burst,
            })
            .map_err(|_| {
                StartupError::new(
                    "evidence.oid4vp.rate-limits",
                    "/rateLimits",
                    "the rate limits are invalid",
                    "Use positive requests-per-minute and burst values.",
                )
            })
        };
        let session_limiter = limiter(
            limits.session_creations_per_principal_per_minute,
            limits.session_creation_burst,
        )?;
        let wallet_limiter = limiter(
            limits.wallet_requests_per_minute,
            limits.wallet_request_burst,
        )?;
        let response_limiter = limiter(
            limits.wallet_responses_per_minute,
            limits.wallet_response_burst,
        )?;
        let response_request_limiter = limiter(
            limits.responses_per_request_per_minute,
            limits.response_burst_per_request,
        )?;
        let read_limiter = limiter(limits.evidence_reads_per_minute, limits.evidence_read_burst)?;
        let metrics = Arc::new(Metrics::new().map_err(|_| {
            StartupError::new(
                "evidence.oid4vp.metrics",
                "/metricsListener",
                "the metrics could not be set up",
                "Report this as a defect.",
            )
        })?);
        let store = Arc::new(SessionStore::new(
            config.sessions.maximum_live_sessions,
            config.sessions.maximum_held_presentation_bytes,
            clock,
        ));
        Ok(Self {
            config,
            store,
            identities,
            did_document,
            jwks,
            applicants,
            evidence_credentials,
            audit,
            metrics,
            session_limiter,
            wallet_limiter,
            response_limiter,
            response_request_limiter,
            read_limiter,
            expiry_warned: std::sync::Mutex::default(),
        })
    }

    /// The validated configuration.
    #[must_use]
    pub const fn config(&self) -> &Oid4vpConfig {
        &self.config
    }

    /// The session store.
    #[must_use]
    pub const fn store(&self) -> &Arc<SessionStore> {
        &self.store
    }

    /// The verifier for the Evidence service credential, used by the result
    /// read route.
    #[must_use]
    pub const fn evidence_credentials(&self) -> &TokenAuthenticator {
        &self.evidence_credentials
    }

    /// The service metrics.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The identity the policy's client identifier resolves to.
    fn identity_for(&self, policy: &PolicyConfig) -> Option<&RequestIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.id() == policy.client_identifier)
    }

    /// Whether a client identifier certificate has passed its `notAfter`. Each
    /// identifier that has is warned of once, naming the identifier and
    /// nothing of the certificate.
    fn certificate_expired(&self) -> bool {
        let now = self.store.now();
        let mut expired = false;
        for identity in &self.identities {
            if identity.expires_at().is_some_and(|end| now >= end) {
                expired = true;
                let first = self
                    .expiry_warned
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(identity.id().to_owned());
                if first {
                    tracing::warn!(
                        client_identifier = identity.id(),
                        "a client identifier certificate has expired; wallets refuse its request objects and the service reports not ready"
                    );
                }
            }
        }
        expired
    }

    fn request_uri(&self, request_id: &str) -> String {
        format!("{}/v1/requests/{request_id}", self.config.public_base_url)
    }

    fn response_uri(&self, request_id: &str) -> String {
        format!(
            "{}{RESPONSE_PATH_PREFIX}{request_id}",
            self.config.public_base_url
        )
    }
}

fn issuer_unavailable(pointer: &'static str) -> StartupError {
    StartupError::new(
        "evidence.oid4vp.issuer-unavailable",
        pointer,
        "the token issuer or its key source could not be set up",
        "Check the issuer, its key source, and that the service can reach it.",
    )
}

/// The router for the public listener.
///
/// The wallet response route reads a larger body than the rest: an encrypted
/// presentation is far above the listener's request bound. Its bound is fixed
/// by the response size limits, not by configuration.
pub fn build_app(service: Arc<VerifierService>) -> Router {
    let body_limit = service.config.listener.maximum_request_bytes as usize;
    let timeout = Duration::from_millis(service.config.listener.request_timeout_milliseconds);
    let general = Router::new()
        .route(HEALTH_PATH, get(health))
        .route(READY_PATH, get(ready))
        .route(SESSIONS_PATH, post(create_session))
        .route(SESSION_PATH, get(session_status))
        .route(REQUEST_PATH, get(fetch_request))
        .route(READ_PATH, post(read_presentation))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(request_body_limit(body_limit));
    let mut general = general;
    if service.did_document.is_some() {
        general = general.route(DID_DOCUMENT_PATH, get(did_document));
    }
    if service.jwks.is_some() {
        general = general.route(JWKS_PATH, get(jwks));
    }
    let responses = Router::new()
        .route(RESPONSE_PATH, post(receive_response))
        .layer(DefaultBodyLimit::max(response::MAX_BODY_BYTES))
        .layer(request_body_limit(response::MAX_BODY_BYTES));
    general
        .merge(responses)
        .fallback(unknown_route)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(service)
        .layer(from_fn_with_state(timeout, bound_request_time))
        .layer(from_fn(normalize_rejections))
        .layer(security_headers(CspBuilder::deny_by_default()))
        .layer(from_fn(apply_trace_context))
}

/// The outermost layer: every response, whichever layer or handler produced
/// it, answers with one canonical `traceparent`. A valid inbound one keeps its
/// trace id; anything else gets a server-created trace, and `tracestate` is
/// never answered.
async fn apply_trace_context(request: Request, next: Next) -> Response {
    let trace = TraceContext::from_headers(request.headers());
    let mut response = next.run(request).await;
    trace.apply(response.headers_mut());
    response
}

async fn bound_request_time(
    State(timeout): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => problem(
            ProblemCode::RequestTimeout,
            "the request took longer than this service waits",
        ),
    }
}

async fn normalize_rejections(request: Request, next: Next) -> Response {
    let wallet_route = request.uri().path().starts_with(RESPONSE_PATH_PREFIX);
    let response = next.run(request).await;
    // The wallet route answers in the OAuth error shape (OpenID4VP 1.0 section
    // 8.5). Its own JSON answers pass through; a framework rejection there,
    // which is never JSON, still becomes a problem.
    let own_json = wallet_route
        && response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));
    let mut response = if own_json {
        response
    } else {
        normalize_framework_rejection(response, |kind| match kind {
            FrameworkRejection::Invalid | FrameworkRejection::Unprocessable => {
                problem(ProblemCode::InvalidRequest, "the request is malformed")
            }
            FrameworkRejection::BodyTooLarge => problem(
                ProblemCode::BodyTooLarge,
                "the request body exceeds the limit",
            ),
            FrameworkRejection::UnsupportedMediaType => {
                problem(ProblemCode::UnsupportedMediaType, "send application/json")
            }
        })
    };
    // A route that sets its own cache policy (the public identity documents)
    // keeps it; everything else is not to be stored.
    response
        .headers_mut()
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

fn problem(code: ProblemCode, detail: &str) -> Response {
    let status =
        StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Problem::new(&code.type_uri(), code.title(), status)
        .detail(detail)
        .into_response()
}

fn retry_after(mut response: Response, seconds: u64) -> Response {
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    response
}

async fn unknown_route() -> Response {
    problem(ProblemCode::NotFound, "no such route")
}

async fn method_not_allowed() -> Response {
    problem(
        ProblemCode::MethodNotAllowed,
        "the route does not accept this method",
    )
}

/// A static public JSON document.
fn identity_document(body: &str) -> Response {
    (
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, IDENTITY_DOCUMENT_CACHE),
        ],
        Body::from(body.to_owned()),
    )
        .into_response()
}

/// The DID document of the `did:web` client identifier.
async fn did_document(State(service): State<Arc<VerifierService>>) -> Response {
    service
        .did_document
        .as_deref()
        .map_or_else(unknown_route_response, identity_document)
}

/// The public keys of the EdDSA client identifiers.
async fn jwks(State(service): State<Arc<VerifierService>>) -> Response {
    service
        .jwks
        .as_deref()
        .map_or_else(unknown_route_response, identity_document)
}

fn unknown_route_response() -> Response {
    problem(ProblemCode::NotFound, "no such route")
}

async fn health() -> Response {
    Json(json!({"status": "ok"})).into_response()
}

/// Readiness tracks required local state: a stopped audit destination makes
/// every releasable operation unavailable, and so does a client identifier
/// certificate past its `notAfter`, which wallets refuse the request objects of.
async fn ready(State(service): State<Arc<VerifierService>>) -> Response {
    if service.audit.ready().await && !service.certificate_expired() {
        Json(json!({"status": "ready"})).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
            .into_response()
    }
}

/// Authenticate the applicant, or return the response that refuses them.
async fn applicant(service: &VerifierService, headers: &HeaderMap) -> Result<Principal, Response> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    match service.applicants.authenticate(authorization).await {
        Ok(principal) => Ok(principal),
        Err(AuthError::KeySource) => {
            service.metrics.record(Event::SessionRefusedUnavailable);
            Err(retry_after(
                problem(
                    ProblemCode::IssuerUnavailable,
                    "the token issuer is unavailable",
                ),
                5,
            ))
        }
        Err(AuthError::Missing | AuthError::Refused) => {
            service.metrics.record(Event::SessionRefusedAuthentication);
            let mut response = problem(
                ProblemCode::Unauthorized,
                "a valid bearer token is required",
            );
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            Err(response)
        }
    }
}

/// A caller's JSON body as `T`, or `None` when the media type is not JSON, the
/// body repeats an object member, or it does not have `T`'s shape. The body
/// is already bounded by the listener's request limit.
fn strict_json_body<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Option<T> {
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return None;
    }
    let value = parse_json_strict(body).ok()?;
    serde_json::from_value(value).ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSession {
    policy: String,
}

async fn create_session(
    State(service): State<Arc<VerifierService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let principal = match applicant(&service, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    if let Err(response) = admit(
        &service.session_limiter,
        &principal.rate_key(),
        &service.metrics,
        Event::SessionRefusedRate,
    )
    .await
    {
        return response;
    }
    let Some(body) = strict_json_body::<CreateSession>(&headers, &body) else {
        return problem(
            ProblemCode::InvalidRequest,
            "the body must be a JSON object with a policy member",
        );
    };
    let Some(policy) = service.config.policy(&body.policy) else {
        service.metrics.record(Event::SessionRefusedPolicy);
        return problem(
            ProblemCode::UnknownPolicy,
            "no presentation policy has this identifier",
        );
    };

    let Some(identity) = service.identity_for(policy) else {
        tracing::error!("a policy names no resolved client identifier");
        return internal_error();
    };

    let created = match service.store.create(&NewSession {
        policy_id: &policy.id,
        principal: principal.clone(),
        response_uri_for: &|request_id| service.response_uri(request_id),
        ttl_seconds: service.config.sessions.session_ttl_seconds,
    }) {
        Ok(created) => created,
        Err(StoreError::Full) => {
            service.metrics.record(Event::SessionRefusedCapacity);
            return retry_after(
                problem(
                    ProblemCode::Capacity,
                    "the service is holding as many sessions as it allows",
                ),
                CAPACITY_RETRY_SECONDS,
            );
        }
        Err(StoreError::Entropy) => {
            tracing::error!("session secrets could not be generated");
            return internal_error();
        }
    };

    // The audit entry is written before the session is released. A session the
    // journal did not accept is discarded, so nothing is usable unrecorded.
    let audit = service
        .audit
        .begin_session_creation(&created.audit_ref, &policy.id, &principal)
        .await;
    let recorded = match audit {
        Ok(pending) => pending.finish("created").await,
        Err(error) => Err(error),
    };
    if recorded.is_err() {
        service.store.discard(&created.reference);
        service.metrics.record(Event::SessionRefusedUnavailable);
        tracing::warn!("the audit destination did not accept a session creation");
        return audit_unavailable();
    }

    service.metrics.record(Event::SessionCreated);
    let request_uri = service.request_uri(&created.request_id);
    let wallet_invocation = wallet_invocation(identity.client_id(), &request_uri);
    (
        StatusCode::CREATED,
        [(CACHE_CONTROL, "no-store")],
        Json(json!({
            "reference": created.reference,
            "requestUri": request_uri,
            "walletInvocation": wallet_invocation,
            "expiresAt": rfc3339(created.expires_at),
        })),
    )
        .into_response()
}

/// `openid4vp://authorize?client_id=...&request_uri=...` (OpenID4VP 1.0 section
/// 5.10: the wallet is invoked with `client_id` and `request_uri`).
fn wallet_invocation(client_id: &str, request_uri: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("request_uri", request_uri)
        .finish();
    format!("{WALLET_SCHEME}?{query}")
}

fn rfc3339(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map_or_else(String::new, |time| {
            time.to_rfc3339_opts(SecondsFormat::Secs, true)
        })
}

async fn session_status(
    State(service): State<Arc<VerifierService>>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match applicant(&service, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    // Unknown, expired, and not-yours read identically.
    let found = service
        .store
        .with_by_reference(&reference, |session| {
            (session.principal == principal).then(|| {
                (
                    session.status(),
                    session.policy_id.clone(),
                    session.expires_at,
                    match session.outcome() {
                        Outcome::Failed(category) => Some(category.as_str()),
                        Outcome::Pending | Outcome::Received { .. } => None,
                    },
                )
            })
        })
        .flatten();
    match found {
        Some((status, policy, expires_at, failure_category)) => {
            service.metrics.record(Event::StatusRead);
            let mut body = json!({
                "status": status.as_str(),
                "policy": policy,
                "expiresAt": rfc3339(expires_at),
            });
            if let Some(category) = failure_category {
                body["failureCategory"] = json!(category);
            }
            ([(CACHE_CONTROL, "no-store")], Json(body)).into_response()
        }
        None => {
            service.metrics.record(Event::StatusNotFound);
            problem(ProblemCode::SessionNotFound, "no such session")
        }
    }
}

async fn fetch_request(
    State(service): State<Arc<VerifierService>>,
    Path(request_id): Path<String>,
) -> Response {
    if let Err(response) = admit(
        &service.wallet_limiter,
        "wallet",
        &service.metrics,
        Event::RequestRefusedRate,
    )
    .await
    {
        return response;
    }
    let now = service.store.now();
    let prepared = service.store.with_by_request_id(&request_id, |session| {
        let policy = service.config.policy(&session.policy_id)?;
        let identity = service.identity_for(policy)?;
        let status = session.status();
        (status == SessionStatus::Pending).then(|| {
            (
                request_object::claims(identity, session, policy, now),
                identity.clone(),
                session.audit_ref.clone(),
                session.policy_id.clone(),
            )
        })
    });
    let Some(Some((claims, identity, audit_ref, policy_id))) = prepared else {
        service.metrics.record(Event::RequestNotFound);
        return problem(ProblemCode::RequestNotFound, "no such request");
    };

    let pending: Pending = match service
        .audit
        .begin_request_fetch(&audit_ref, &policy_id)
        .await
    {
        Ok(pending) => pending,
        Err(_) => {
            service.metrics.record(Event::RequestFailed);
            tracing::warn!("the audit destination did not accept a request fetch");
            return audit_unavailable();
        }
    };
    let signed = match request_object::sign(&identity, &claims).await {
        Ok(signed) => signed,
        Err(_) => {
            service.metrics.record(Event::RequestFailed);
            tracing::error!("the request object could not be signed");
            // Dropping `pending` records the fetch as unfinished.
            return internal_error();
        }
    };
    if pending.finish("served").await.is_err() {
        service.metrics.record(Event::RequestFailed);
        return audit_unavailable();
    }
    service.metrics.record(Event::RequestServed);
    (
        [
            (CONTENT_TYPE, request_object::CONTENT_TYPE),
            (CACHE_CONTROL, "no-store"),
        ],
        Body::from(signed),
    )
        .into_response()
}

/// The OAuth error body of RFC 6749 section 5.2, the shape OpenID4VP 1.0
/// section 8.5 builds on. No description is ever sent.
fn oauth_error(status: StatusCode, error: &'static str) -> Response {
    (
        status,
        [(CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error })),
    )
        .into_response()
}

fn response_refused() -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
}

fn response_unavailable(wait_seconds: u64) -> Response {
    retry_after(
        oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        wait_seconds,
    )
}

/// Admit one wallet response attempt, or the OAuth-shaped refusal.
async fn admit_response(limiter: &TokenBucketLimiter, key: &str) -> Result<(), Response> {
    match limiter.check(key, 1).await {
        Ok(()) => Ok(()),
        Err(TokenBucketError::Exceeded { retry_after: wait }) => Err(retry_after(
            oauth_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable"),
            wait.as_secs() + 1,
        )),
        Err(_) => Err(response_unavailable(CAPACITY_RETRY_SECONDS)),
    }
}

/// Releases a reserved response unless the handler disarms it, so a request
/// that is cancelled or refused midway leaves the session pending.
struct Reservation {
    store: Arc<SessionStore>,
    request_id: String,
    digest: Digest32,
    armed: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            self.store.with_reserved_mut(&self.request_id, |session| {
                session.release(&self.digest);
            });
        }
    }
}

/// What the session lock decided about a wallet response.
enum Verdict {
    /// The identical response was already accepted.
    Answered,
    /// The identical response is being recorded.
    Busy,
    Refused(Refusal),
    /// Holding the presentation would pass the store's byte budget.
    OverBudget,
    /// The response is reserved; the category is set for a wallet error.
    Reserved(Option<crate::session::FailureCategory>),
}

/// The wallet's `direct_post.jwt` response (OpenID4VP 1.0 sections 8.2, 8.3.1).
async fn receive_response(
    State(service): State<Arc<VerifierService>>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = admit_response(&service.response_limiter, "wallet-response").await {
        service.metrics.record(Event::ResponseRefusedRate);
        return response;
    }
    let is_form = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| {
            media
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    let submission = match Submission::parse(&body) {
        Ok(submission) if is_form => submission,
        _ => {
            service.metrics.record(Event::ResponseRefused);
            return response_refused();
        }
    };
    // Unknown, expired, and settled-elsewhere sessions read as one refusal.
    let Some((audit_ref, policy_id)) = service.store.with_by_request_id(&request_id, |session| {
        (session.audit_ref.clone(), session.policy_id.clone())
    }) else {
        service.metrics.record(Event::ResponseRefused);
        return response_refused();
    };
    if let Err(response) = admit_response(&service.response_request_limiter, &audit_ref).await {
        service.metrics.record(Event::ResponseRefusedRate);
        return response;
    }
    let Some(policy) = service.config.policy(&policy_id) else {
        service.metrics.record(Event::ResponseRefused);
        return response_refused();
    };

    let digest = submission.digest();
    let now = service.store.now();
    // One acceptance per session, decided under the session lock.
    let decide = || {
        service
            .store
            .with_by_request_id_mut(&request_id, |session| match session.prior(&digest) {
                Prior::Same => Verdict::Answered,
                Prior::InFlight => Verdict::Busy,
                Prior::Different => Verdict::Refused(Refusal::AlreadySettled),
                Prior::None => match response::evaluate(session, policy, &submission) {
                    Ok(held) => {
                        let category = match &held {
                            Held::WalletError(category) => Some(*category),
                            Held::Presentation(_) => None,
                        };
                        match session.reserve(digest, held, now) {
                            Reserve::Reserved => Verdict::Reserved(category),
                            Reserve::OverBudget => Verdict::OverBudget,
                            Reserve::AlreadyTaken => Verdict::Refused(Refusal::AlreadySettled),
                        }
                    }
                    Err(refusal) => Verdict::Refused(refusal),
                },
            })
    };
    let mut verdict = decide();
    // Results past their hold release their bytes when swept. Sweep before
    // refusing for the budget, so a store full of expired results is not
    // refused for them.
    if matches!(verdict, Some(Verdict::OverBudget)) && service.store.cleanup() > 0 {
        verdict = decide();
    }
    match verdict {
        None => {
            service.metrics.record(Event::ResponseRefused);
            response_refused()
        }
        Some(Verdict::Answered) => accepted_answer(),
        Some(Verdict::Busy) => response_unavailable(1),
        Some(Verdict::OverBudget) => {
            service.metrics.record(Event::ResponseRefusedCapacity);
            if service
                .audit
                .record_response_refusal(&audit_ref, &policy_id, "held_presentation_budget")
                .await
                .is_err()
            {
                tracing::warn!("the audit destination did not accept a response refusal");
            }
            response_unavailable(CAPACITY_RETRY_SECONDS)
        }
        Some(Verdict::Refused(refusal)) => {
            service.metrics.record(Event::ResponseRefused);
            if service
                .audit
                .record_response_refusal(&audit_ref, &policy_id, refusal.category())
                .await
                .is_err()
            {
                tracing::warn!("the audit destination did not accept a response refusal");
            }
            response_refused()
        }
        Some(Verdict::Reserved(category)) => {
            let reservation = Reservation {
                store: Arc::clone(&service.store),
                request_id,
                digest,
                armed: true,
            };
            settle(&service, reservation, &audit_ref, &policy_id, category).await
        }
    }
}

/// Record a reserved response durably, then make it the session's result. An
/// audit failure refuses the response and leaves the session pending.
async fn settle(
    service: &VerifierService,
    mut reservation: Reservation,
    audit_ref: &str,
    policy_id: &str,
    category: Option<crate::session::FailureCategory>,
) -> Response {
    let (pending, outcome) = match category {
        Some(category) => (
            service
                .audit
                .begin_wallet_error(audit_ref, policy_id, category.as_str())
                .await,
            category.as_str(),
        ),
        None => (
            service
                .audit
                .begin_response_acceptance(audit_ref, policy_id)
                .await,
            "accepted",
        ),
    };
    let recorded = match pending {
        Ok(pending) => pending.finish(outcome).await,
        Err(error) => Err(error),
    };
    if recorded.is_err() {
        service.metrics.record(Event::ResponseUnavailable);
        tracing::warn!("the audit destination did not accept a wallet response");
        return response_unavailable(5);
    }
    let now = service.store.now();
    let ttl = service.config.sessions.result_ttl_seconds;
    let digest = reservation.digest;
    // The reservation was made inside the exchange window, and the record
    // above is already written as accepted, so the window closing in between
    // does not undo it.
    let confirmed = service
        .store
        .with_reserved_mut(&reservation.request_id, |session| {
            session.confirm(&digest, now, ttl)
        });
    if confirmed != Some(true) {
        // The reservation is gone: the session was discarded meanwhile.
        service.metrics.record(Event::ResponseRefused);
        return response_refused();
    }
    reservation.armed = false;
    service.metrics.record(if category.is_some() {
        Event::WalletError
    } else {
        Event::ResponseAccepted
    });
    accepted_answer()
}

/// Section 8.2: a processed response is answered with HTTP 200 and a JSON
/// object. A same-device flow adds `redirect_uri` to it.
fn accepted_answer() -> Response {
    ([(CACHE_CONTROL, "no-store")], Json(json!({}))).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    reference: String,
    principal: ReadPrincipal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPrincipal {
    issuer: String,
    subject: String,
}

/// What the session lock found for a read.
enum ReadVerdict {
    NotFound,
    PrincipalMismatch,
    Pending,
    Failed(&'static str),
    Received(Box<serde_json::Value>),
}

/// Gives a claimed result back unless the handler disarms it, so a read that
/// is cancelled or whose audit record is refused leaves the result readable.
struct Claimed {
    store: Arc<SessionStore>,
    reference: String,
    armed: bool,
}

impl Drop for Claimed {
    fn drop(&mut self) {
        if self.armed {
            self.store
                .with_by_reference_mut(&self.reference, |session| {
                    session.unclaim();
                });
        }
    }
}

/// Evidence reads the presentation a wallet returned, on behalf of the
/// applicant who created the session. The first successful read consumes the
/// result; a later read of the reference is a not found.
async fn read_presentation(
    State(service): State<Arc<VerifierService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let reader = match service
        .evidence_credentials
        .authenticate(authorization)
        .await
    {
        Ok(reader) => reader,
        Err(AuthError::KeySource) => {
            service.metrics.record(Event::ReadUnavailable);
            return retry_after(
                problem(
                    ProblemCode::IssuerUnavailable,
                    "the token issuer is unavailable",
                ),
                5,
            );
        }
        Err(AuthError::Missing | AuthError::Refused) => {
            service.metrics.record(Event::ReadRefusedAuthentication);
            let mut response = problem(
                ProblemCode::Unauthorized,
                "a valid bearer token is required",
            );
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return response;
        }
    };
    if let Err(response) = admit(
        &service.read_limiter,
        &reader.rate_key(),
        &service.metrics,
        Event::ReadRefusedRate,
    )
    .await
    {
        return response;
    }
    let Some(request) = strict_json_body::<ReadRequest>(&headers, &body) else {
        return problem(
            ProblemCode::InvalidRequest,
            "the body must name a reference and the applicant principal",
        );
    };

    let audit_ref = crate::session::audit_ref(&request.reference);
    // The claim is decided under the session lock, so of two concurrent reads
    // exactly one takes the result and the other finds it gone.
    let found = service
        .store
        .with_by_reference_mut(&request.reference, |session| {
            let verdict = if session.principal.issuer != request.principal.issuer
                || session.principal.subject.as_deref() != Some(request.principal.subject.as_str())
            {
                ReadVerdict::PrincipalMismatch
            } else {
                claim_for_read(&service, session)
            };
            (verdict, session.policy_id.clone())
        });
    let (verdict, policy_id) = match found {
        Some((verdict, policy_id)) => (verdict, Some(policy_id)),
        None => (ReadVerdict::NotFound, None),
    };
    let claimed =
        matches!(verdict, ReadVerdict::Failed(_) | ReadVerdict::Received(_)).then(|| Claimed {
            store: Arc::clone(&service.store),
            reference: request.reference.clone(),
            armed: true,
        });
    let policy_for_audit = match verdict {
        ReadVerdict::PrincipalMismatch | ReadVerdict::NotFound => None,
        _ => policy_id.as_deref(),
    };
    let outcome = match &verdict {
        ReadVerdict::NotFound => "not_found",
        ReadVerdict::PrincipalMismatch => "principal_mismatch",
        ReadVerdict::Pending => "pending",
        ReadVerdict::Failed(_) => "failed_and_consumed",
        ReadVerdict::Received(_) => "delivered_and_consumed",
    };
    // The entry is written before anything is released; a failed entry
    // releases nothing, and the dropped claim leaves the result readable.
    let recorded = match service
        .audit
        .begin_evidence_read(&audit_ref, policy_for_audit, &reader)
        .await
    {
        Ok(pending) => pending.finish(outcome).await,
        Err(error) => Err(error),
    };
    if recorded.is_err() {
        service.metrics.record(Event::ReadUnavailable);
        tracing::warn!("the audit destination did not accept an Evidence read");
        return audit_unavailable();
    }
    if let Some(mut claimed) = claimed {
        claimed.armed = false;
        service
            .store
            .with_by_reference_mut(&request.reference, crate::session::Session::consume);
    }
    match verdict {
        // A principal that is not the creator reads exactly as an unknown
        // reference.
        ReadVerdict::NotFound | ReadVerdict::PrincipalMismatch => {
            service.metrics.record(Event::ReadNotFound);
            problem(ProblemCode::SessionNotFound, "no such session")
        }
        ReadVerdict::Pending => {
            service.metrics.record(Event::ReadPending);
            problem(
                ProblemCode::NotYetPresented,
                "the wallet has not presented yet",
            )
        }
        ReadVerdict::Failed(category) => {
            service.metrics.record(Event::ReadFailed);
            Problem::new(
                &ProblemCode::WalletError.type_uri(),
                ProblemCode::WalletError.title(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .detail("the wallet reported an error instead of presenting")
            .with_extra("category", json!(category))
            .into_response()
        }
        ReadVerdict::Received(body) => {
            service.metrics.record(Event::ReadDelivered);
            ([(CACHE_CONTROL, "no-store")], Json(*body)).into_response()
        }
    }
}

/// Claim the session's result for a read by its creator. A result that cannot
/// be described to Evidence is left unclaimed and reads as not found.
fn claim_for_read(service: &VerifierService, session: &mut crate::session::Session) -> ReadVerdict {
    match session.claim() {
        Claim::Pending => ReadVerdict::Pending,
        Claim::Gone => ReadVerdict::NotFound,
        Claim::Failed(category) => ReadVerdict::Failed(category.as_str()),
        Claim::Presentation {
            vp_token,
            received_at,
        } => match read_context(service, session, received_at) {
            Some(context) => ReadVerdict::Received(Box::new(json!({
                "presentation": vp_token,
                "context": context,
            }))),
            None => {
                session.unclaim();
                ReadVerdict::NotFound
            }
        },
    }
}

/// The session context Evidence needs to verify the presentation: the values
/// the key binding must echo and the response key the wallet encrypted to.
fn read_context(
    service: &VerifierService,
    session: &crate::session::Session,
    received_at: u64,
) -> Option<serde_json::Value> {
    let thumbprint = session.encryption_key.thumbprint().ok()?;
    let policy = service.config.policy(&session.policy_id)?;
    let identity = service.identity_for(policy)?;
    Some(json!({
        "nonce": session.nonce,
        "clientId": identity.client_id(),
        "responseUri": session.response_uri,
        "responseKeyThumbprint": thumbprint,
        "policyId": session.policy_id,
        "createdBy": {
            "issuer": session.principal.issuer,
            "subject": session.principal.subject,
        },
        "receivedAt": rfc3339(received_at),
    }))
}

async fn admit(
    limiter: &TokenBucketLimiter,
    key: &str,
    metrics: &Metrics,
    refused: Event,
) -> Result<(), Response> {
    match limiter.check(key, 1).await {
        Ok(()) => Ok(()),
        Err(TokenBucketError::Exceeded { retry_after: wait }) => {
            metrics.record(refused);
            Err(retry_after(
                problem(ProblemCode::RateLimited, "too many requests; retry later"),
                wait.as_secs() + 1,
            ))
        }
        Err(_) => {
            metrics.record(refused);
            Err(retry_after(
                problem(ProblemCode::Capacity, "the service is at capacity"),
                CAPACITY_RETRY_SECONDS,
            ))
        }
    }
}

fn audit_unavailable() -> Response {
    retry_after(
        problem(
            ProblemCode::AuditUnavailable,
            "the service cannot record this operation right now",
        ),
        5,
    )
}

fn internal_error() -> Response {
    problem(
        ProblemCode::InternalError,
        "the request could not be completed",
    )
}

/// Bind the configured listeners and serve until `shutdown` resolves.
pub async fn serve<F>(service: Arc<VerifierService>, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(service.config.listener.bind).await?;
    let metrics_listener = match &service.config.metrics_listener {
        Some(config) => Some(TcpListener::bind(config.bind).await?),
        None => None,
    };
    tracing::info!(target: "registry_evidence_oid4vp::service", "verifier service listening");
    let cleanup = spawn_cleanup(&service.store, CLEANUP_INTERVAL);
    let app = build_app(Arc::clone(&service));
    let metrics_router = metrics_app(Arc::clone(&service.metrics), Arc::clone(&service.store));
    let (stop, stopped) = watch::channel(false);
    let public_stopped = stopped.clone();
    let metrics_stopped = stopped;

    let public = axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_stop(public_stopped))
        .into_future();
    let metrics = async move {
        match metrics_listener {
            Some(listener) => {
                axum::serve(listener, metrics_router)
                    .with_graceful_shutdown(wait_for_stop(metrics_stopped))
                    .into_future()
                    .await
            }
            None => {
                wait_for_stop(metrics_stopped).await;
                Ok(())
            }
        }
    };
    tokio::pin!(public);
    tokio::pin!(metrics);
    tokio::pin!(shutdown);

    let result = tokio::select! {
        result = &mut public => {
            let _ = stop.send(true);
            let _ = (&mut metrics).await;
            result
        }
        result = &mut metrics => {
            let _ = stop.send(true);
            let _ = (&mut public).await;
            result
        }
        () = &mut shutdown => {
            let _ = stop.send(true);
            let (public, metrics) = tokio::join!(&mut public, &mut metrics);
            public.and(metrics)
        }
    };
    cleanup.abort();
    result
}

async fn wait_for_stop(mut stopped: watch::Receiver<bool>) {
    while !*stopped.borrow() {
        if stopped.changed().await.is_err() {
            break;
        }
    }
}
