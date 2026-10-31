// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_authcommon::{parse_bearer_token, BearerParseError};
use registry_platform_oidc::{
    access_token_typ_set, JwksFetcher, OidcError, TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use serde_json::{json, Value};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::server::{problem, METADATA_PREFIX};

const MAXIMUM_TOKEN_LIFETIME: Duration = Duration::from_secs(86_400);

/// An asymmetric access-token signature algorithm.
#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AccessTokenAlgorithm {
    RS256,
    RS384,
    ES256,
    ES384,
    EdDSA,
}

impl AccessTokenAlgorithm {
    pub const fn jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::RS384 => jsonwebtoken::Algorithm::RS384,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::ES384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

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
    /// Permit a non-loopback HTTP issuer for an explicitly insecure deployment.
    /// The protected resource URL remains HTTPS or loopback HTTP only.
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
        validate_options(self)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Missing,
    InvalidToken,
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
}

impl ResourceServer {
    pub fn new(
        options: &ResourceServerOptions,
        verifier: TokenVerifier,
        hasher: AuditKeyHasher,
        limits: RateLimitOptions,
    ) -> Result<Self, ResourceServerError> {
        options.validate()?;
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
        })
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
    ) -> Result<VerifiedCaller, ()> {
        self.caller(verified, token).map_err(|_| ())
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedCaller, Refusal> {
        let token = bearer_token(headers)?;
        let verified = match self.verifier.verify(token).await {
            Ok(verified) => verified,
            Err(error) if is_key_source_failure(&error) => {
                tracing::warn!("the access-token key set is unavailable");
                return Err(Refusal::KeySource);
            }
            Err(_) => return Err(Refusal::InvalidToken),
        };
        let caller = self.caller(&verified, token)?;
        admit(&self.per_principal, caller.principal_pseudonym()).await?;
        admit(&self.per_client, caller.client_pseudonym()).await?;
        Ok(caller)
    }

    fn caller(&self, verified: &VerifiedToken, token: &str) -> Result<VerifiedCaller, Refusal> {
        let claims = &verified.claims;
        if claims.extra.contains_key("act") || claims.extra.contains_key("may_act") {
            return Err(Refusal::InvalidToken);
        }
        let subject = claims
            .sub
            .as_deref()
            .filter(|subject| !subject.is_empty())
            .ok_or(Refusal::InvalidToken)?;
        let client = verified
            .matched_client_id()
            .ok()
            .flatten()
            .ok_or(Refusal::InvalidToken)?;
        let expires_at = claims.exp.ok_or(Refusal::InvalidToken)?;
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

    pub(crate) fn refusal_response(&self, refusal: Refusal) -> Response {
        let (status, challenge) = match refusal {
            Refusal::Missing => (StatusCode::UNAUTHORIZED, Some(self.challenge.clone())),
            Refusal::InvalidToken => (
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

fn validate_options(options: &ResourceServerOptions) -> Result<(), ResourceServerError> {
    let Ok(resource) = Url::parse(&options.resource) else {
        return Err(ResourceServerError::Resource);
    };
    if !valid_protected_url(&resource) || resource.path() != crate::MCP_PATH {
        return Err(ResourceServerError::Resource);
    }
    let Ok(issuer) = Url::parse(&options.issuer) else {
        return Err(ResourceServerError::Issuer);
    };
    if !valid_issuer_url(&issuer, options.allow_insecure_http) {
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

fn valid_protected_url(url: &Url) -> bool {
    url.host().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || url.scheme() == "http" && loopback(url))
}

fn valid_issuer_url(url: &Url, allow_insecure_http: bool) -> bool {
    url.host().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || url.scheme() == "http" && (allow_insecure_http || loopback(url)))
}

fn loopback(url: &Url) -> bool {
    matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost"))
}

fn limiter(options: TokenBucketOptions) -> Result<TokenBucketLimiter, TokenBucketError> {
    TokenBucketLimiter::new(TokenBucketConfig {
        requests_per_minute: options.requests_per_minute,
        burst: options.burst,
    })
}

impl Refusal {
    const fn code(self) -> &'static str {
        match self {
            Self::Missing => "unauthorized",
            Self::InvalidToken => "invalid-token",
            Self::InsufficientScope => "insufficient-scope",
            Self::KeySource | Self::Unavailable => "temporarily-unavailable",
            Self::RateLimited { .. } => "rate-limited",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::Missing => "A bearer access token is required.",
            Self::InvalidToken => "The access token is not valid for this resource.",
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
        Err(refusal) => server.refusal_response(refusal),
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
    let value = values.next().ok_or(Refusal::Missing)?;
    if values.next().is_some() {
        return Err(Refusal::InvalidToken);
    }
    let value = value.to_str().map_err(|_| Refusal::InvalidToken)?;
    parse_bearer_token(value).map_err(|error| match error {
        BearerParseError::Malformed | BearerParseError::InvalidScheme => Refusal::Missing,
        _ => Refusal::InvalidToken,
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
            .map(|algorithm| algorithm.jsonwebtoken())
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
