// SPDX-License-Identifier: Apache-2.0

//! The inbound resource-server half of the gateway.
//!
//! Every request to the MCP endpoint must carry an access token the configured
//! issuer signed for this gateway's resource, on the strict RFC 9068 profile:
//! an exact issuer, this resource as audience, a closed algorithm list, an
//! access-token `typ`, a lifetime ceiling, an admitted chat-host client, and the
//! required scopes. The verified token is the only source of the citizen's
//! identity. Nothing here reads the gateway's own client key or its registry
//! configuration; the outbound half in [`crate::outbound`] owns both.

use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use serde_json::{json, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::config::{RateLimitsConfig, ResourceServerConfig};

/// The two spellings RFC 9068 permits for a JWT access token.
const ACCESS_TOKEN_TYPES: [&str; 2] = ["at+jwt", "application/at+jwt"];

/// The audit reference class of a citizen's pseudonym.
const PRINCIPAL_CLASS: &str = "breg-mcp-principal-v1";
/// The audit reference class of a chat-host client's pseudonym.
const CLIENT_CLASS: &str = "breg-mcp-client-v1";

/// The RFC 9728 well-known prefix.
pub(crate) const METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";

/// The citizen a verified request acts for, and the chat host presenting it.
///
/// Built only from a token the resource server verified. The token is retained
/// solely as the subject of the outbound exchange and is never logged, audited,
/// or sent to the registry.
pub(crate) struct VerifiedCaller {
    issuer: String,
    subject: String,
    token: Zeroizing<String>,
    expires_at: i64,
    citizen_pseudonym: String,
    client_pseudonym: String,
}

impl VerifiedCaller {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    /// The inbound access token, for the outbound exchange only.
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub(crate) fn citizen_pseudonym(&self) -> &str {
        &self.citizen_pseudonym
    }

    pub(crate) fn client_pseudonym(&self) -> &str {
        &self.client_pseudonym
    }
}

impl std::fmt::Debug for VerifiedCaller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedCaller")
            .field("citizen", &self.citizen_pseudonym)
            .field("client", &self.client_pseudonym)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl VerifiedCaller {
    pub(crate) fn for_test(
        issuer: &str,
        subject: &str,
        client: &str,
        token: &str,
        expires_at: i64,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            token: Zeroizing::new(token.to_owned()),
            expires_at,
            citizen_pseudonym: test_pseudonym("citizen", subject),
            client_pseudonym: test_pseudonym("client", client),
        }
    }
}

/// A stand-in pseudonym that, like the keyed one, never contains its input.
#[cfg(test)]
fn test_pseudonym(kind: &str, value: &str) -> String {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{kind}-{:016x}", hasher.finish())
}

/// Why a request was not admitted. None of the variants carries token bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No usable bearer credential: the caller must discover how to get one.
    Missing,
    /// The token was refused.
    InvalidToken,
    /// The token was valid but lacks a required scope.
    InsufficientScope,
    /// The configured key source could not be read.
    KeySource,
    /// A rate limit was exceeded.
    RateLimited { retry_after_seconds: u64 },
    /// The limiter could not admit the request, or the caller's pseudonyms
    /// could not be derived.
    Unavailable,
}

/// The configured resource server: verification, scopes, rate limits, and the
/// RFC 9728 metadata a refused caller is pointed at.
pub(crate) struct ResourceServer {
    verifier: TokenVerifier,
    issuer: String,
    required_scopes: Vec<String>,
    hasher: AuditKeyHasher,
    per_citizen: TokenBucketLimiter,
    per_client: TokenBucketLimiter,
    challenge: String,
    scope_challenge: String,
    metadata: Value,
}

/// Why the resource server could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ResourceServerError {
    #[error("resourceServer.resource is not a usable URL")]
    Resource,
    #[error("rateLimits.{0} is not a usable token bucket")]
    RateLimit(&'static str),
}

impl ResourceServer {
    pub(crate) fn new(
        config: &ResourceServerConfig,
        resource_name: &str,
        verifier: TokenVerifier,
        hasher: AuditKeyHasher,
        limits: RateLimitsConfig,
    ) -> Result<Self, ResourceServerError> {
        let resource = Url::parse(&config.resource).map_err(|_| ResourceServerError::Resource)?;
        let metadata_url = metadata_url(&resource).ok_or(ResourceServerError::Resource)?;
        let challenge = format!("Bearer resource_metadata=\"{metadata_url}\"");
        let scope_challenge = format!(
            "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{metadata_url}\"",
            config.required_scopes.join(" ")
        );
        let per_citizen = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: limits.per_citizen.requests_per_minute,
            burst: limits.per_citizen.burst,
        })
        .map_err(|_| ResourceServerError::RateLimit("perCitizen"))?;
        let per_client = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: limits.per_client.requests_per_minute,
            burst: limits.per_client.burst,
        })
        .map_err(|_| ResourceServerError::RateLimit("perClient"))?;
        let metadata = json!({
            "resource": config.resource,
            "authorization_servers": [config.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": config.required_scopes,
            "resource_name": resource_name,
        });
        Ok(Self {
            verifier,
            issuer: config.issuer.clone(),
            required_scopes: config.required_scopes.clone(),
            hasher,
            per_citizen,
            per_client,
            challenge,
            scope_challenge,
            metadata,
        })
    }

    /// The RFC 9728 protected-resource metadata document.
    pub(crate) const fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Verify the request's bearer token and charge both rate limits. The
    /// citizen's own limit is charged first, so a citizen already over it is
    /// refused without spending the chat host's shared allowance.
    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedCaller, Refusal> {
        let token = bearer_token(headers)?;
        let verified = match self.verifier.verify(token).await {
            Ok(verified) => verified,
            Err(error) if is_key_source_failure(&error) => {
                tracing::warn!(
                    target: "registry_breg_mcp::inbound",
                    "the access-token key set is unavailable"
                );
                return Err(Refusal::KeySource);
            }
            Err(_) => return Err(Refusal::InvalidToken),
        };
        let caller = self.caller(&verified, token)?;
        admit(&self.per_citizen, caller.citizen_pseudonym()).await?;
        admit(&self.per_client, caller.client_pseudonym()).await?;
        Ok(caller)
    }

    fn caller(&self, verified: &VerifiedToken, token: &str) -> Result<VerifiedCaller, Refusal> {
        let claims = &verified.claims;
        // A token that already names an actor was issued to someone acting for
        // the citizen. The gateway acts only on the citizen's own grant to the
        // chat host.
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
            citizen_pseudonym: self.pseudonym(PRINCIPAL_CLASS, subject)?,
            client_pseudonym: self.pseudonym(CLIENT_CLASS, client)?,
        })
    }

    /// The keyed pseudonym of one party at the configured issuer: the shared
    /// audit reference hash over `[issuer, value]`, derived exactly as the
    /// citizen review page derives its own.
    fn pseudonym(&self, class: &str, value: &str) -> Result<String, Refusal> {
        self.hasher
            .audit_reference_hash(class, "", &json!([self.issuer, value]).to_string())
            .map_err(|_| Refusal::Unavailable)
    }

    fn refusal_response(&self, refusal: Refusal) -> Response {
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
        let mut response = (status, axum::Json(json!({ "error": refusal.code() }))).into_response();
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
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl Refusal {
    const fn code(self) -> &'static str {
        match self {
            Self::Missing => "unauthorized",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::KeySource | Self::Unavailable => "temporarily_unavailable",
            Self::RateLimited { .. } => "rate_limited",
        }
    }
}

/// Axum middleware: admit the request and attach the verified caller.
pub(crate) async fn require_caller(
    State(server): State<Arc<ResourceServer>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match server.authenticate(request.headers()).await {
        Ok(caller) => {
            // The verified caller holds the token for the exchange; the
            // header goes no further, so nothing behind this layer can log,
            // echo, or forward it.
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
            retry_after_seconds: retry_after.as_secs().max(1),
        }),
        Err(TokenBucketError::Configuration | TokenBucketError::Capacity) => {
            Err(Refusal::Unavailable)
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, Refusal> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(Refusal::Missing)?;
    if values.next().is_some() {
        return Err(Refusal::InvalidToken);
    }
    let value = value.to_str().map_err(|_| Refusal::InvalidToken)?;
    let (scheme, token) = value.split_once(' ').ok_or(Refusal::Missing)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Refusal::Missing);
    }
    let token = token.trim_start_matches(' ');
    if token.is_empty() || token.contains(' ') {
        return Err(Refusal::InvalidToken);
    }
    Ok(token)
}

/// The RFC 9728 metadata URL for a resource: the well-known prefix inserted
/// between the origin and the resource path.
pub(crate) fn metadata_url(resource: &Url) -> Option<Url> {
    let mut url = resource.clone();
    let path = resource.path().trim_end_matches('/');
    url.set_path(&format!("{METADATA_PREFIX}{path}"));
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

/// The access-token profile inbound tokens are verified under.
pub(crate) fn verifier_config(config: &ResourceServerConfig) -> TokenVerifierConfig {
    TokenVerifierConfig::access_token_profile(
        config.issuer.clone(),
        vec![config.resource.clone()],
        config
            .algorithms
            .iter()
            .map(|algorithm| algorithm.jsonwebtoken())
            .collect(),
        ACCESS_TOKEN_TYPES
            .iter()
            .map(|typ| (*typ).to_owned())
            .collect(),
    )
    .with_scope_claim(config.scope_claim.clone())
    .with_allowed_clients(config.allowed_clients.clone())
    .with_denied_kids(HashSet::new())
    .with_max_token_lifetime(Some(Duration::from_secs(config.max_token_lifetime_seconds)))
}

/// Build a verifier over an already constructed key source.
pub(crate) fn verifier(config: &ResourceServerConfig, fetcher: Arc<JwksFetcher>) -> TokenVerifier {
    TokenVerifier::new(verifier_config(config), fetcher)
}

/// A fetcher for a published key set. Plain HTTP only under development
/// loopback, when both the issuer and the key set are on `127.0.0.1`.
pub(crate) fn uri_fetcher(
    config: &ResourceServerConfig,
    uri: &str,
    development_loopback: bool,
) -> JwksFetcher {
    let local = development_loopback
        && config.issuer.starts_with("http://127.0.0.1:")
        && uri.starts_with("http://127.0.0.1:");
    let policy = if local {
        FetchUrlPolicy {
            allowed_schemes: vec!["http".to_owned()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: true,
            deny_cloud_metadata: true,
        }
    } else {
        FetchUrlPolicy {
            allowed_schemes: vec!["https".to_owned()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    };
    JwksFetcher::new_with_fetch_url_policy(uri.to_owned(), JwksFetcherConfig::defaults(), policy)
}

/// Whether a verification failure was the deployment's key source rather than
/// the caller's token. A variant this code has never seen is the caller's.
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
mod tests {
    use axum::{routing::post, Extension, Router};
    use registry_platform_audit::AuditProfile;
    use registry_platform_oidc::Claims;
    use registry_platform_testing::{TestAuthorizationServer, TestClient};
    use tower::ServiceExt;

    use super::*;
    use crate::config::{AccessTokenAlgorithm, JwksSource, RateLimitConfig};

    const RESOURCE: &str = "https://gateway.example.test/mcp";
    const CHAT_HOST: &str = "chat-host";
    const SCOPE: &str = "address-correction:self";
    const METADATA: &str = "https://gateway.example.test/.well-known/oauth-protected-resource/mcp";

    fn config(issuer: &str, jwks: &str) -> ResourceServerConfig {
        ResourceServerConfig {
            resource: RESOURCE.to_owned(),
            issuer: issuer.to_owned(),
            jwks: JwksSource::Uri {
                uri: jwks.to_owned(),
            },
            algorithms: vec![AccessTokenAlgorithm::EdDSA],
            allowed_clients: vec![CHAT_HOST.to_owned()],
            required_scopes: vec![SCOPE.to_owned()],
            scope_claim: "scope".to_owned(),
            max_token_lifetime_seconds: 3600,
        }
    }

    fn limits(citizen_burst: u32, client_burst: u32) -> RateLimitsConfig {
        RateLimitsConfig {
            per_citizen: RateLimitConfig {
                requests_per_minute: 1,
                burst: citizen_burst,
            },
            per_client: RateLimitConfig {
                requests_per_minute: 1,
                burst: client_burst,
            },
        }
    }

    fn hasher() -> AuditKeyHasher {
        AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![5; 32]))
            .expect("profile")
            .key_hasher()
    }

    async fn authorization_server() -> TestAuthorizationServer {
        TestAuthorizationServer::builder()
            .client(TestClient::new(CHAT_HOST))
            .client(TestClient::new("another-host"))
            .start()
            .await
    }

    fn server_for(authorization: &TestAuthorizationServer, limits: RateLimitsConfig) -> Router {
        let config = config(&authorization.issuer(), &authorization.jwks_uri());
        let fetcher = Arc::new(uri_fetcher(&config, &authorization.jwks_uri(), true));
        let server = Arc::new(
            ResourceServer::new(
                &config,
                "Address correction",
                verifier(&config, fetcher),
                hasher(),
                limits,
            )
            .expect("resource server"),
        );
        Router::new()
            .route(
                "/mcp",
                post(
                    |Extension(caller): Extension<Arc<VerifiedCaller>>,
                     headers: axum::http::HeaderMap| async move {
                        axum::Json(json!({
                            "authorization": headers.contains_key(header::AUTHORIZATION),
                            "subject": caller.subject(),
                            "client": caller.client_pseudonym(),
                            "citizen": caller.citizen_pseudonym(),
                            "debug": format!("{caller:?}"),
                        }))
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(server, require_caller))
    }

    fn now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
        )
        .expect("time fits")
    }

    async fn call(router: &Router, token: Option<&str>) -> Response {
        let mut request = Request::post("/mcp");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response")
    }

    fn challenge(response: &Response) -> String {
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("challenge")
            .to_str()
            .expect("ascii")
            .to_owned()
    }

    async fn body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn a_request_without_a_token_is_pointed_at_the_resource_metadata() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let response = call(&router, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge(&response),
            format!("Bearer resource_metadata=\"{METADATA}\"")
        );
    }

    #[tokio::test]
    async fn a_token_for_another_audience_is_refused_as_invalid() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let token = authorization.issue_access_token(
            CHAT_HOST,
            "citizen-a",
            "urn:breg:citizen-address-correction",
            SCOPE,
            now() + 300,
        );
        let response = call(&router, Some(&token)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge(&response),
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{METADATA}\"")
        );
    }

    #[tokio::test]
    async fn a_client_that_is_not_admitted_is_refused() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let token = authorization.issue_access_token(
            "another-host",
            "citizen-a",
            RESOURCE,
            SCOPE,
            now() + 300,
        );
        assert_eq!(
            call(&router, Some(&token)).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_token_without_the_required_scope_is_forbidden() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let token = authorization.issue_access_token(
            CHAT_HOST,
            "citizen-a",
            RESOURCE,
            "openid",
            now() + 300,
        );
        let response = call(&router, Some(&token)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(challenge(&response).starts_with(&format!(
            "Bearer error=\"insufficient_scope\", scope=\"{SCOPE}\""
        )));
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let token =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() - 120);
        assert_eq!(
            call(&router, Some(&token)).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_verified_caller_carries_only_its_token_identity() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 10));
        let token =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
        let response = call(&router, Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body(response).await;
        assert_eq!(body["subject"], "citizen-a");
        // Only the verified caller travels on: the MCP layer behind the
        // middleware never sees the chat host's bearer token.
        assert_eq!(body["authorization"], false);
        // The pseudonyms are the shared audit reference hashes the review
        // page derives too, so one citizen reads the same in both journals.
        let issuer = authorization.issuer();
        assert_eq!(
            body["client"],
            hasher()
                .audit_reference_hash(
                    "breg-mcp-client-v1",
                    "",
                    &json!([issuer, CHAT_HOST]).to_string()
                )
                .expect("client pseudonym")
        );
        assert_eq!(
            body["citizen"],
            hasher()
                .audit_reference_hash(
                    "breg-mcp-principal-v1",
                    "",
                    &json!([issuer, "citizen-a"]).to_string()
                )
                .expect("principal pseudonym")
        );
        let citizen = body["citizen"].as_str().expect("pseudonym");
        assert!(!citizen.contains("citizen-a"));
        let debug = body["debug"].as_str().expect("debug");
        assert!(!debug.contains(&token));
        assert!(!debug.contains("citizen-a"));
    }

    #[tokio::test]
    async fn each_citizen_has_its_own_rate_limit() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(1, 10));
        let first =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
        let second =
            authorization.issue_access_token(CHAT_HOST, "citizen-b", RESOURCE, SCOPE, now() + 300);
        assert_eq!(call(&router, Some(&first)).await.status(), StatusCode::OK);
        let limited = call(&router, Some(&first)).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(call(&router, Some(&second)).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn each_client_has_its_own_rate_limit() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(10, 1));
        let first =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
        let second =
            authorization.issue_access_token(CHAT_HOST, "citizen-b", RESOURCE, SCOPE, now() + 300);
        assert_eq!(call(&router, Some(&first)).await.status(), StatusCode::OK);
        assert_eq!(
            call(&router, Some(&second)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// A citizen over their own limit is refused before the chat host's
    /// shared bucket is charged, so their repeated calls cost the other
    /// citizens on the same client nothing.
    #[tokio::test]
    async fn an_over_limit_citizen_does_not_drain_the_shared_client_limit() {
        let authorization = authorization_server().await;
        let router = server_for(&authorization, limits(1, 3));
        let noisy =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
        let quiet =
            authorization.issue_access_token(CHAT_HOST, "citizen-b", RESOURCE, SCOPE, now() + 300);
        assert_eq!(call(&router, Some(&noisy)).await.status(), StatusCode::OK);
        for _ in 0..5 {
            assert_eq!(
                call(&router, Some(&noisy)).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        // The client bucket held three; the noisy citizen spent one.
        assert_eq!(call(&router, Some(&quiet)).await.status(), StatusCode::OK);
        let third =
            authorization.issue_access_token(CHAT_HOST, "citizen-c", RESOURCE, SCOPE, now() + 300);
        assert_eq!(call(&router, Some(&third)).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unreachable_key_set_is_the_operators_failure() {
        let authorization = authorization_server().await;
        let token =
            authorization.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let closed = format!(
            "http://{}/jwks.json",
            listener.local_addr().expect("address")
        );
        drop(listener);
        let config = config(&authorization.issuer(), &closed);
        let fetcher = Arc::new(uri_fetcher(&config, &closed, true));
        let server = ResourceServer::new(
            &config,
            "x",
            verifier(&config, fetcher),
            hasher(),
            limits(10, 10),
        )
        .expect("server");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        assert_eq!(
            server.authenticate(&headers).await.err(),
            Some(Refusal::KeySource)
        );
    }

    #[tokio::test]
    async fn a_token_that_already_names_an_actor_is_refused() {
        let authorization = authorization_server().await;
        let config = config(&authorization.issuer(), &authorization.jwks_uri());
        let fetcher = Arc::new(uri_fetcher(&config, &authorization.jwks_uri(), true));
        let server = ResourceServer::new(
            &config,
            "x",
            verifier(&config, fetcher),
            hasher(),
            limits(10, 10),
        )
        .expect("server");
        let mut claims: Claims = serde_json::from_value(json!({
            "sub": "citizen-a",
            "exp": now() + 300,
            "client_id": CHAT_HOST,
            "act": {"sub": "someone-else"},
        }))
        .expect("claims");
        let delegated = VerifiedToken {
            claims: claims.clone(),
            matched_client: Some(format!("client_id:{CHAT_HOST}")),
            scopes: vec![SCOPE.to_owned()],
        };
        assert_eq!(
            server.caller(&delegated, "t").err(),
            Some(Refusal::InvalidToken)
        );
        claims.extra.remove("act");
        claims.sub = None;
        let anonymous = VerifiedToken {
            claims,
            matched_client: Some(format!("client_id:{CHAT_HOST}")),
            scopes: vec![SCOPE.to_owned()],
        };
        assert_eq!(
            server.caller(&anonymous, "t").err(),
            Some(Refusal::InvalidToken)
        );
    }

    #[test]
    fn the_metadata_url_inserts_the_well_known_prefix() {
        let resource = Url::parse(RESOURCE).expect("url");
        assert_eq!(
            metadata_url(&resource).expect("metadata").as_str(),
            METADATA
        );
    }

    #[test]
    fn a_malformed_authorization_header_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), Err(Refusal::Missing));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer a b"),
        );
        assert_eq!(bearer_token(&headers), Err(Refusal::InvalidToken));
    }
}
