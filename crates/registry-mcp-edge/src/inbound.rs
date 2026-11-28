// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_authcommon::{
    parse_bearer_token, record_refusal, BearerParseError, DeclaredScope, FailedCheck, RefusalNote,
    RefusalRecorder,
};
use registry_platform_httputil::loopback::loopback_host;
pub use registry_platform_oidc::AccessTokenAlgorithm;
use registry_platform_oidc::{
    access_token_typ_set, JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::server::{problem, METADATA_PREFIX};

const MAXIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(86_400);

/// The least time between two log lines for a request the gateway could not
/// admit because of its own fault.
const ADMIT_FAULT_LOG_WINDOW: Duration = Duration::from_secs(60);

/// Complete product-neutral inbound resource-server settings.
#[derive(Clone, Debug)]
pub struct ResourceServerOptions {
    /// Exact protected-resource identifier used for JWT audience validation
    /// and protected-resource metadata. URL parsing validates this value but
    /// must not normalize it, because JWT audience matching is exact.
    pub resource: String,
    /// Exact authorization-server issuer identifier used for JWT validation
    /// and protected-resource metadata. URL parsing validates this value but
    /// must not normalize it, because JWT issuer matching is exact.
    pub issuer: String,
    /// Permit a non-loopback HTTP issuer when the process declares development.
    pub allow_insecure_http: bool,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    pub allowed_clients: Vec<String>,
    pub required_scopes: Vec<String>,
    pub scope_claim: String,
    pub maximum_token_lifetime: Duration,
    pub resource_name: String,
    /// Keyed audit-reference namespace for the authenticated principal.
    pub principal_audit_namespace: String,
    /// Keyed audit-reference namespace for the calling client.
    pub client_audit_namespace: String,
}

impl ResourceServerOptions {
    /// Validates resource admission settings without constructing a verifier,
    /// acquiring credentials, or opening a socket.
    pub fn validate(&self) -> Result<(), ResourceServerError> {
        validate_options(self, None)
    }
    pub fn validate_with_posture(
        &self,
        posture: registry_platform_config::Posture,
    ) -> Result<(), ResourceServerError> {
        validate_options(self, Some(posture))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBucketOptions {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitOptions {
    pub per_principal: TokenBucketOptions,
    pub per_client: TokenBucketOptions,
}

/// Authenticated caller attached by the edge middleware.
///
/// Its fields are private. Providers can inspect the verified identity and
/// pseudonymous context, while the delegation implementation inside this crate
/// alone can read the inbound token.
pub struct VerifiedCaller {
    issuer: String,
    subject: String,
    token: Zeroizing<String>,
    expires_at: i64,
    principal_pseudonym: String,
    client_pseudonym: String,
}

impl VerifiedCaller {
    #[must_use]
    pub const fn context(&self) -> CallerContext<'_> {
        CallerContext { caller: self }
    }

    /// Returns the verified issuer and subject without exposing the bearer.
    ///
    /// Product providers use this identity to preserve existing owner and
    /// idempotency bindings. It must not be serialized into logs or responses.
    #[must_use]
    pub const fn identity(&self) -> VerifiedIdentity<'_> {
        VerifiedIdentity { caller: self }
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub(crate) fn principal_pseudonym(&self) -> &str {
        &self.principal_pseudonym
    }

    pub(crate) fn client_pseudonym(&self) -> &str {
        &self.client_pseudonym
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn for_test(
        issuer: &str,
        subject: &str,
        _client: &str,
        token: &str,
        expires_at: i64,
        principal_pseudonym: &str,
        client_pseudonym: &str,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            token: Zeroizing::new(token.to_owned()),
            expires_at,
            principal_pseudonym: principal_pseudonym.to_owned(),
            client_pseudonym: client_pseudonym.to_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_internal(
        issuer: &str,
        subject: &str,
        client: &str,
        token: &str,
        expires_at: i64,
        principal_pseudonym: &str,
        client_pseudonym: &str,
    ) -> Self {
        Self::for_test(
            issuer,
            subject,
            client,
            token,
            expires_at,
            principal_pseudonym,
            client_pseudonym,
        )
    }
}

impl fmt::Debug for VerifiedCaller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCaller")
            .field("principal", &self.principal_pseudonym)
            .field("client", &self.client_pseudonym)
            .finish_non_exhaustive()
    }
}

/// Read-only identity claims from the verified inbound access token.
#[derive(Clone, Copy)]
pub struct VerifiedIdentity<'a> {
    caller: &'a VerifiedCaller,
}

impl VerifiedIdentity<'_> {
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.caller.issuer
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.caller.subject
    }
}

impl fmt::Debug for VerifiedIdentity<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentity")
            .finish_non_exhaustive()
    }
}

/// Public, non-identifying provider view of a verified caller.
#[derive(Clone, Copy, Debug)]
pub struct CallerContext<'a> {
    caller: &'a VerifiedCaller,
}

impl CallerContext<'_> {
    #[must_use]
    pub fn principal_pseudonym(&self) -> &str {
        &self.caller.principal_pseudonym
    }

    #[must_use]
    pub fn client_pseudonym(&self) -> &str {
        &self.caller.client_pseudonym
    }
}

/// What the edge answers, and for the answers that carry a check, the check
/// that failed. The check is operator-side only and never reaches a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Missing(FailedCheck),
    InvalidToken(FailedCheck),
    InsufficientScope,
    KeySource,
    RateLimited { retry_after_seconds: u64 },
    Unavailable,
}

pub struct ResourceServer {
    verifier: TokenVerifier,
    issuer: String,
    required_scopes: Vec<String>,
    hasher: AuditKeyHasher,
    principal_namespace: String,
    client_namespace: String,
    per_principal: TokenBucketLimiter,
    per_client: TokenBucketLimiter,
    challenge: String,
    scope_challenge: String,
    metadata: Value,
    refusals: Arc<RefusalRecorder>,
    /// When the gateway last logged that it could not admit a request, and
    /// how many requests failed the same way since.
    admit_fault_logged: Mutex<AdmitFaultLog>,
    /// The configured claim and scopes a scope refusal line names.
    declared_scope: DeclaredScope,
}

#[derive(Default)]
struct AdmitFaultLog {
    logged: Option<Instant>,
    suppressed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResourceServerError {
    #[error("the protected resource URL is not usable")]
    Resource,
    #[error("the issuer URL is not usable")]
    Issuer,
    #[error("the resource-server options are incomplete")]
    Options,
    #[error("the {0} rate limit is not usable")]
    RateLimit(&'static str),
    #[error("the refusal recorder is not usable")]
    Recorder,
}

impl ResourceServer {
    pub fn new(
        options: &ResourceServerOptions,
        verifier: TokenVerifier,
        hasher: AuditKeyHasher,
        limits: RateLimitOptions,
    ) -> Result<Self, ResourceServerError> {
        options.validate()?;
        Self::build(options, verifier, hasher, limits)
    }

    pub fn new_with_posture(
        options: &ResourceServerOptions,
        verifier: TokenVerifier,
        hasher: AuditKeyHasher,
        limits: RateLimitOptions,
        posture: registry_platform_config::Posture,
    ) -> Result<Self, ResourceServerError> {
        options.validate_with_posture(posture)?;
        Self::build(options, verifier, hasher, limits)
    }

    fn build(
        options: &ResourceServerOptions,
        verifier: TokenVerifier,
        hasher: AuditKeyHasher,
        limits: RateLimitOptions,
    ) -> Result<Self, ResourceServerError> {
        let resource = Url::parse(&options.resource).map_err(|_| ResourceServerError::Resource)?;
        let metadata_url = metadata_url(&resource).ok_or(ResourceServerError::Resource)?;
        let challenge = format!("Bearer resource_metadata=\"{metadata_url}\"");
        let scope_challenge = format!(
            "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{metadata_url}\"",
            options.required_scopes.join(" ")
        );
        let per_principal = limiter(limits.per_principal)
            .map_err(|_| ResourceServerError::RateLimit("perPrincipal"))?;
        let per_client =
            limiter(limits.per_client).map_err(|_| ResourceServerError::RateLimit("perClient"))?;
        let refusals =
            Arc::new(RefusalRecorder::new("mcp_edge").map_err(|_| ResourceServerError::Recorder)?);
        let metadata = json!({
            "resource": options.resource.as_str(),
            "authorization_servers": [options.issuer.as_str()],
            "bearer_methods_supported": ["header"],
            "scopes_supported": &options.required_scopes,
            "resource_name": options.resource_name.as_str(),
        });
        Ok(Self {
            verifier,
            issuer: options.issuer.clone(),
            required_scopes: options.required_scopes.clone(),
            hasher,
            principal_namespace: options.principal_audit_namespace.clone(),
            client_namespace: options.client_audit_namespace.clone(),
            per_principal,
            per_client,
            challenge,
            scope_challenge,
            metadata,
            refusals,
            admit_fault_logged: Mutex::new(AdmitFaultLog::default()),
            declared_scope: DeclaredScope::new(&options.scope_claim)
                .with_required_scope(options.required_scopes.join(" ")),
        })
    }

    /// Counts every refusal by the check that failed. The edge has no metrics
    /// listener, so the counter is read in tests and the log line is the
    /// operator's signal.
    pub(crate) const fn refusal_recorder(&self) -> &Arc<RefusalRecorder> {
        &self.refusals
    }

    #[must_use]
    pub const fn metadata(&self) -> &Value {
        &self.metadata
    }

    #[cfg(test)]
    pub(crate) fn caller_for_test(
        &self,
        verified: &VerifiedToken,
        token: &str,
    ) -> Result<VerifiedCaller, Refusal> {
        self.caller(verified, token)
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedCaller, Refusal> {
        let token = bearer_token(headers)?;
        let verified = match self.verifier.verify(token).await {
            Ok(verified) => verified,
            Err(error) if is_key_source_failure(&error) => return Err(Refusal::KeySource),
            Err(error) => return Err(Refusal::InvalidToken(error.failed_check())),
        };
        let caller = self.caller(&verified, token)?;
        admit(&self.per_principal, caller.principal_pseudonym()).await?;
        admit(&self.per_client, caller.client_pseudonym()).await?;
        Ok(caller)
    }

    fn caller(&self, verified: &VerifiedToken, token: &str) -> Result<VerifiedCaller, Refusal> {
        let claims = &verified.claims;
        if claims.extra.contains_key("act") || claims.extra.contains_key("may_act") {
            return Err(Refusal::InvalidToken(FailedCheck::Delegation));
        }
        let subject = claims
            .sub
            .as_deref()
            .filter(|subject| !subject.is_empty())
            .ok_or(Refusal::InvalidToken(FailedCheck::TokenClaims))?;
        let client = verified
            .matched_client_id()
            .ok()
            .flatten()
            .ok_or(Refusal::InvalidToken(FailedCheck::TokenClient))?;
        let expires_at = claims
            .exp
            .ok_or(Refusal::InvalidToken(FailedCheck::TokenClaims))?;
        let present: HashSet<&str> = verified.scopes.iter().map(String::as_str).collect();
        if !self
            .required_scopes
            .iter()
            .all(|scope| present.contains(scope.as_str()))
        {
            return Err(Refusal::InsufficientScope);
        }
        Ok(VerifiedCaller {
            issuer: self.issuer.clone(),
            subject: subject.to_owned(),
            token: Zeroizing::new(token.to_owned()),
            expires_at,
            principal_pseudonym: self.pseudonym(&self.principal_namespace, subject)?,
            client_pseudonym: self.pseudonym(&self.client_namespace, client)?,
        })
    }

    fn pseudonym(&self, namespace: &str, value: &str) -> Result<String, Refusal> {
        self.hasher
            .audit_reference_hash(namespace, "", &json!([self.issuer, value]).to_string())
            .map_err(|_| Refusal::Unavailable)
    }

    /// Counts and logs the refusal, then builds its answer.
    pub(crate) fn refuse(&self, refusal: Refusal) -> Response {
        match refusal.failed_check() {
            Some(check) => record_refusal!(
                self.refusals,
                RefusalNote::new(check),
                declared = Some(&self.declared_scope)
            ),
            // The gateway could not derive a pseudonym or run its limiter.
            // That is a fault of this service, not a check a caller failed.
            None => {
                if let Some(suppressed) = self.admit_fault_due(Instant::now()) {
                    tracing::error!(suppressed, "the gateway could not admit a request");
                }
            }
        }
        self.refusal_response(refusal)
    }

    /// `Some` at most once per `ADMIT_FAULT_LOG_WINDOW`, so a limiter that has
    /// reached its capacity cannot write a line for every request. The value
    /// is how many requests failed the same way since the last line.
    fn admit_fault_due(&self, now: Instant) -> Option<u64> {
        let mut log = self
            .admit_fault_logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if log
            .logged
            .is_some_and(|logged| now.saturating_duration_since(logged) < ADMIT_FAULT_LOG_WINDOW)
        {
            log.suppressed = log.suppressed.saturating_add(1);
            return None;
        }
        log.logged = Some(now);
        Some(std::mem::take(&mut log.suppressed))
    }

    fn refusal_response(&self, refusal: Refusal) -> Response {
        let (status, challenge) = match refusal {
            Refusal::Missing(_) => (StatusCode::UNAUTHORIZED, Some(self.challenge.clone())),
            Refusal::InvalidToken(_) => (
                StatusCode::UNAUTHORIZED,
                Some(
                    self.challenge
                        .replacen("Bearer ", "Bearer error=\"invalid_token\", ", 1),
                ),
            ),
            Refusal::InsufficientScope => {
                (StatusCode::FORBIDDEN, Some(self.scope_challenge.clone()))
            }
            Refusal::KeySource | Refusal::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, None),
            Refusal::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, None),
        };
        let mut response = problem(status, refusal.code(), refusal.detail());
        let headers = response.headers_mut();
        if let Some(challenge) = challenge.and_then(|value| HeaderValue::from_str(&value).ok()) {
            headers.insert(header::WWW_AUTHENTICATE, challenge);
        }
        if let Refusal::RateLimited {
            retry_after_seconds,
        } = refusal
        {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(retry_after_seconds));
        }
        response
    }
}

fn validate_options(
    options: &ResourceServerOptions,
    posture: Option<registry_platform_config::Posture>,
) -> Result<(), ResourceServerError> {
    let Ok(resource) = Url::parse(&options.resource) else {
        return Err(ResourceServerError::Resource);
    };
    if !valid_protected_url(&resource, posture) || resource.path() != crate::MCP_PATH {
        return Err(ResourceServerError::Resource);
    }
    let Ok(issuer) = Url::parse(&options.issuer) else {
        return Err(ResourceServerError::Issuer);
    };
    if (posture == Some(registry_platform_config::Posture::Production)
        && (options.allow_insecure_http || issuer.scheme() != "https"))
        || !valid_issuer_url(&issuer, options.allow_insecure_http)
    {
        return Err(ResourceServerError::Issuer);
    }
    if options.algorithms.is_empty()
        || options.allowed_clients.is_empty()
        || options.required_scopes.is_empty()
        || options.scope_claim.is_empty()
        || options.maximum_token_lifetime.is_zero()
        || options.maximum_token_lifetime > MAXIMUM_TOKEN_LIFETIME
        || options.resource_name.is_empty()
        || options.principal_audit_namespace.is_empty()
        || options.client_audit_namespace.is_empty()
    {
        return Err(ResourceServerError::Options);
    }
    Ok(())
}

fn valid_protected_url(url: &Url, posture: Option<registry_platform_config::Posture>) -> bool {
    use registry_platform_config::Posture;
    let http_allowed = match posture {
        Some(Posture::Development) => true,
        Some(Posture::Production) => false,
        None => loopback(url),
    };
    url.host().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || url.scheme() == "http" && http_allowed)
}

fn valid_issuer_url(url: &Url, allow_insecure_http: bool) -> bool {
    url.host().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || url.scheme() == "http" && (allow_insecure_http || loopback(url)))
}

fn loopback(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| loopback_host(host).is_some())
}

fn limiter(options: TokenBucketOptions) -> Result<TokenBucketLimiter, TokenBucketError> {
    TokenBucketLimiter::new(TokenBucketConfig {
        requests_per_minute: options.requests_per_minute,
        burst: options.burst,
    })
}

impl Refusal {
    /// The check a caller failed, or `None` for a fault of this service.
    #[deny(clippy::wildcard_enum_match_arm)]
    const fn failed_check(self) -> Option<FailedCheck> {
        match self {
            Self::Missing(check) | Self::InvalidToken(check) => Some(check),
            Self::InsufficientScope => Some(FailedCheck::Scope),
            Self::KeySource => Some(FailedCheck::KeySourceUnavailable),
            Self::RateLimited { .. } => Some(FailedCheck::RateLimit),
            Self::Unavailable => None,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Missing(_) => "unauthorized",
            Self::InvalidToken(_) => "invalid-token",
            Self::InsufficientScope => "insufficient-scope",
            Self::KeySource | Self::Unavailable => "temporarily-unavailable",
            Self::RateLimited { .. } => "rate-limited",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::Missing(_) => "A bearer access token is required.",
            Self::InvalidToken(_) => "The access token is not valid for this resource.",
            Self::InsufficientScope => "The access token lacks a required scope.",
            Self::KeySource | Self::Unavailable => {
                "The gateway cannot verify the request right now."
            }
            Self::RateLimited { .. } => "Too many requests; retry after the indicated delay.",
        }
    }
}

pub(crate) async fn require_caller(
    State(server): State<Arc<ResourceServer>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match server.authenticate(request.headers()).await {
        Ok(caller) => {
            request.headers_mut().remove(header::AUTHORIZATION);
            request.extensions_mut().insert(Arc::new(caller));
            next.run(request).await
        }
        Err(refusal) => server.refuse(refusal),
    }
}

async fn admit(limiter: &TokenBucketLimiter, key: &str) -> Result<(), Refusal> {
    match limiter.check(key, 1).await {
        Ok(()) => Ok(()),
        Err(TokenBucketError::Exceeded { retry_after }) => Err(Refusal::RateLimited {
            retry_after_seconds: retry_after_seconds(retry_after),
        }),
        Err(
            TokenBucketError::Configuration
            | TokenBucketError::Capacity
            | TokenBucketError::CostExceedsBurst,
        ) => Err(Refusal::Unavailable),
    }
}

pub(crate) fn retry_after_seconds(retry_after: Duration) -> u64 {
    (retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0)).max(1)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, Refusal> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(Refusal::Missing(FailedCheck::CredentialMissing))?;
    if values.next().is_some() {
        return Err(Refusal::InvalidToken(FailedCheck::CredentialMalformed));
    }
    let value = value
        .to_str()
        .map_err(|_| Refusal::InvalidToken(FailedCheck::CredentialMalformed))?;
    parse_bearer_token(value).map_err(|error| match error {
        BearerParseError::InvalidScheme => Refusal::Missing(FailedCheck::CredentialMissing),
        BearerParseError::Malformed => Refusal::Missing(FailedCheck::CredentialMalformed),
        _ => Refusal::InvalidToken(FailedCheck::CredentialMalformed),
    })
}

#[must_use]
pub fn metadata_url(resource: &Url) -> Option<Url> {
    let mut url = resource.clone();
    let path = resource.path().trim_end_matches('/');
    url.set_path(&format!("{METADATA_PREFIX}{path}"));
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

#[must_use]
pub fn token_verifier(options: &ResourceServerOptions, fetcher: Arc<JwksFetcher>) -> TokenVerifier {
    TokenVerifier::new(verifier_config(options), fetcher)
}

fn verifier_config(options: &ResourceServerOptions) -> TokenVerifierConfig {
    TokenVerifierConfig::access_token_profile(
        options.issuer.clone(),
        vec![options.resource.clone()],
        options
            .algorithms
            .iter()
            .map(|algorithm| algorithm.to_jsonwebtoken())
            .collect(),
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim(options.scope_claim.clone())
    .with_allowed_clients(options.allowed_clients.clone())
    .with_max_token_lifetime(Some(options.maximum_token_lifetime))
}

fn is_key_source_failure(error: &OidcError) -> bool {
    matches!(
        error,
        OidcError::Transport(_)
            | OidcError::BoundedRead(_)
            | OidcError::FetchUrl(_)
            | OidcError::HttpStatus(_)
            | OidcError::InvalidUrl
            | OidcError::Parse
            | OidcError::InvalidJwk
            | OidcError::EmptyKeySet
            | OidcError::MissingIssuer
    )
}

#[cfg(test)]
mod refusal_tests;
