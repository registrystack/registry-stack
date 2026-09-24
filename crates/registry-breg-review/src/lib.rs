// SPDX-License-Identifier: Apache-2.0

//! A server-rendered page where a signed-in person reviews and submits their
//! own Base Registry Engine change request.
//!
//! The page is an OpenID Connect relying party and a confidential OAuth
//! client. It signs a person in with the authorization code flow, keeps the
//! person's access token server-side in a bounded in-memory session, reads
//! the draft and the record it changes under that token, and submits exactly
//! the action it rendered. It has no authority of its own: every read and
//! every submit is the registry's decision about the signed-in person.

// A handler step that refuses answers with the rendered refusal page itself,
// so its error is an HTTP response, carried to the handler once and returned.
#![allow(clippy::result_large_err)]

mod config;
mod journal;
mod pages;
mod registry;
mod session;
mod signin;
mod templates;

pub use config::{RuntimeConfig, RuntimeConfigError};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};
use axum::Router;
use clap::{value_parser, Arg, Command};
use jsonwebtoken::Algorithm;
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use registry_platform_audit::{AuditProfile, DurableSegmentedAuditLog};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httpsec::{security_headers, CspBuilder};
use registry_platform_httputil::client::{PrivateKeyJwt, PrivateKeyJwtConfig};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
    TokenVerifier, TokenVerifierConfig,
};
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::config::{allowed_discovered_endpoint, describe_secret_failure, RateConfig};
use crate::journal::Journal;
use crate::session::{well_formed_token, Store};
use crate::templates::Templates;

/// The one key of the global sign-in limit.
const GLOBAL_SIGN_IN_KEY: &str = "global";
/// The largest form body the page reads.
const MAXIMUM_FORM_BYTES: usize = 16 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MAXIMUM_DISCOVERY_BYTES: u64 = 64 * 1024;
/// Clock skew tolerated on an ID token's time claims.
const ID_TOKEN_LEEWAY: Duration = Duration::from_secs(60);
/// The asymmetric algorithms an ID token may be signed with.
const ID_TOKEN_ALGORITHMS: [Algorithm; 5] = [
    Algorithm::EdDSA,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::PS256,
];

/// The complete clap command tree, built so help and the CLI reference can
/// render it.
#[must_use]
pub fn command() -> Command {
    Command::new("breg-review")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Serve the citizen review page for Base Registry Engine change requests")
        .arg(
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("FILE")
                .help("Absolute path to the review page runtime configuration")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
    #[error("{0}")]
    Secret(String),
    #[error("signIn.clientKeyRef does not hold a private JWK the page can sign with")]
    ClientKey,
    #[error("the provider's OpenID discovery document could not be used: {0}")]
    Discovery(String),
    #[error("the confidential sign-in client could not be configured: {0}")]
    SignInClient(String),
    #[error("the registry client could not be configured: {0}")]
    Registry(String),
    #[error("the audit journal could not be opened: {0}")]
    Audit(String),
    #[error("the page templates could not be compiled: {0}")]
    Templates(String),
    #[error("limits could not be configured")]
    Limits,
}

/// Cookie names and attributes for the declared transport.
pub(crate) struct Cookies {
    pub session: &'static str,
    pub sign_in: &'static str,
    pub secure: bool,
}

impl Cookies {
    fn for_mode(development: bool) -> Self {
        if development {
            // Plain loopback HTTP cannot carry a Secure cookie, and a
            // `__Host-` name requires one.
            Self {
                session: "breg-review-session",
                sign_in: "breg-review-signin",
                secure: false,
            }
        } else {
            Self {
                session: "__Host-breg-review-session",
                sign_in: "__Host-breg-review-signin",
                secure: true,
            }
        }
    }

    pub(crate) fn set(
        &self,
        name: &str,
        value: &str,
        max_age: u64,
        same_site: &str,
    ) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite={same_site}{secure}"
        ))
        .expect("cookie names, tokens, and attributes are header-safe")
    }

    pub(crate) fn clear(&self, name: &str, same_site: &str) -> HeaderValue {
        self.set(name, "", 0, same_site)
    }
}

/// Everything a request handler shares.
pub(crate) struct App {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: String,
    pub entity: String,
    pub target_field: String,
    pub access_profile: String,
    pub authorization_endpoint: Url,
    /// Whether the provider promises an `iss` parameter on every
    /// authorization response (RFC 9207), which then becomes required.
    pub requires_iss: bool,
    pub redirect_uri: Url,
    pub sign_in_client: PrivateKeyJwt,
    pub verifier: TokenVerifier,
    pub registry: BaseRegistryClient,
    pub templates: Templates,
    pub sessions: Store,
    pub journal: Journal,
    /// Keyed by the signed-in person a session names.
    pub per_citizen: TokenBucketLimiter,
    /// One bucket for everyone on the unauthenticated sign-in routes.
    pub global_sign_in: TokenBucketLimiter,
    pub cookies: Cookies,
    pub maximum_session: Duration,
    pub sign_in_lifetime: Duration,
}

/// A stable machine-readable refusal, rendered as an HTML page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Problem {
    NotFound,
    MethodNotAllowed,
    RequestTooLarge,
    FormRefused,
    CsrfRefused,
    ReturnPathRefused,
    SignInRefused,
    SignInUnavailable,
    SessionsExhausted,
    SignInsExhausted,
    AuditUnavailable,
    RegistryUnavailable,
    RequestConflict,
    RateLimited,
    Internal,
}

impl Problem {
    const fn parts(self) -> (StatusCode, &'static str, &'static str, &'static str) {
        match self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not-found",
                "Not found",
                "There is no request to review here. Check the link you were given.",
            ),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method-not-allowed",
                "Not allowed",
                "This page does not accept that kind of request.",
            ),
            Self::RequestTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request-too-large",
                "Request too large",
                "The form sent was larger than this page accepts.",
            ),
            Self::FormRefused => (
                StatusCode::BAD_REQUEST,
                "form-refused",
                "Form not accepted",
                "The form sent was not one this page rendered. Open the request again.",
            ),
            Self::CsrfRefused => (
                StatusCode::FORBIDDEN,
                "csrf-refused",
                "Form expired",
                "This form is no longer valid. Open the request again and submit from there.",
            ),
            Self::ReturnPathRefused => (
                StatusCode::BAD_REQUEST,
                "return-path-refused",
                "Sign-in link not accepted",
                "Sign-in can only return to a request page. Use the link you were given.",
            ),
            Self::SignInRefused => (
                StatusCode::BAD_REQUEST,
                "sign-in-refused",
                "Sign-in did not complete",
                "Sign-in could not be completed. Open the link you were given and sign in again.",
            ),
            Self::SignInUnavailable => (
                StatusCode::BAD_GATEWAY,
                "sign-in-unavailable",
                "Sign-in unavailable",
                "Sign-in is not available right now. Try again later.",
            ),
            Self::SessionsExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                "sessions-exhausted",
                "Busy",
                "Too many people are signed in right now. Try again later.",
            ),
            Self::SignInsExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                "sign-ins-exhausted",
                "Busy",
                "Too many sign-ins are in progress right now. Try again in a few minutes.",
            ),
            Self::AuditUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "audit-unavailable",
                "Unavailable",
                "This page cannot record what it does right now, so it does nothing. Try again later.",
            ),
            Self::RegistryUnavailable => (
                StatusCode::BAD_GATEWAY,
                "registry-unavailable",
                "Registry unavailable",
                "The registry did not answer as expected. Try again later.",
            ),
            Self::RequestConflict => (
                StatusCode::CONFLICT,
                "request-conflict",
                "Request changed",
                "This request changed while it was being submitted. Open it again.",
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate-limited",
                "Too many requests",
                "Too many requests arrived. Wait a moment and try again.",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unexpected",
                "Something went wrong",
                "This page could not answer. Try again later.",
            ),
        }
    }
}

pub(crate) fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

impl App {
    pub(crate) fn problem(&self, problem: Problem) -> Response {
        let (status, code, title, message) = problem.parts();
        match self.templates.error(code, title, message) {
            Ok(body) => html(status, body),
            Err(error) => {
                tracing::error!(%error, "the error page could not be rendered");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the page could not answer",
                )
                    .into_response()
            }
        }
    }

    pub(crate) fn rendered(
        &self,
        status: StatusCode,
        rendered: Result<String, minijinja::Error>,
    ) -> Response {
        match rendered {
            Ok(body) => html(status, body),
            Err(error) => {
                tracing::error!(%error, "a page could not be rendered");
                self.problem(Problem::Internal)
            }
        }
    }

    /// Admit a request to a sign-in route against the one limit everyone
    /// shares. The page cannot tell browsers apart before sign-in, so a
    /// per-client limit on these routes belongs at the edge proxy.
    pub(crate) async fn admit_sign_in(&self) -> Result<(), Response> {
        self.admit(&self.global_sign_in, GLOBAL_SIGN_IN_KEY).await
    }

    pub(crate) async fn admit_citizen(&self, citizen: &str) -> Result<(), Response> {
        self.admit(&self.per_citizen, citizen).await
    }

    async fn admit(&self, limiter: &TokenBucketLimiter, key: &str) -> Result<(), Response> {
        match limiter.check(key, 1).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut response = self.problem(Problem::RateLimited);
                if let TokenBucketError::Exceeded { retry_after } = error {
                    let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
                } else {
                    tracing::warn!(%error, "a rate limit refused a request");
                }
                Err(response)
            }
        }
    }
}

/// The one value of cookie `name` a request presents, when it presents
/// exactly one value of the shape this page issues.
pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((candidate, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if candidate == name {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found.filter(|value| well_formed_token(value))
}

/// Whether `value` is a UUID in the one canonical form the page links to:
/// lowercase and hyphenated.
pub(crate) fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn resolve_secret(
    resolver: &registry_platform_config::SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, RuntimeError> {
    resolver
        .resolve(reference)
        .map_err(|error| RuntimeError::Secret(describe_secret_failure(field, reference, &error)))
}

fn limiter(rate: RateConfig) -> Result<TokenBucketLimiter, RuntimeError> {
    TokenBucketLimiter::new(TokenBucketConfig {
        requests_per_minute: rate.requests_per_minute,
        burst: rate.burst,
    })
    .map_err(|_| RuntimeError::Limits)
}

fn discovered_endpoint(
    document: &registry_platform_oidc::DiscoveryDocument,
    member: &str,
    development: bool,
) -> Result<Url, RuntimeError> {
    document
        .extra
        .get(member)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Url::parse(value).ok())
        .filter(|url| allowed_discovered_endpoint(url, development))
        .ok_or_else(|| {
            RuntimeError::Discovery(format!(
                "{member} is missing or is not an endpoint this runtime may call"
            ))
        })
}

/// Build the page from a validated runtime configuration. Startup reads the
/// secrets, fetches the provider's discovery document, opens the audit
/// journal, and compiles the templates, and fails on the first fault.
pub async fn router(config: RuntimeConfig) -> Result<Router, RuntimeError> {
    config.check()?;
    let development = config.development();
    let policy = if development {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    };
    let secrets = config.secret_resolver()?;
    let client_key = resolve_secret(
        &secrets,
        "signIn.clientKeyRef",
        &config.sign_in.client_key_ref,
    )?;
    let client_key = std::str::from_utf8(client_key.expose_secret())
        .ok()
        .and_then(|text| PrivateJwk::parse(text).ok())
        .ok_or(RuntimeError::ClientKey)?;
    let audit_key = resolve_secret(&secrets, "audit.hashKeyRef", &config.audit.hash_key_ref)?;
    let audit_profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(
        audit_key.expose_secret().to_vec(),
    ))
    .map_err(|error| RuntimeError::Audit(error.to_string()))?;
    drop(audit_key);

    let issuer = config.sign_in.issuer.clone();
    let discovery = fetch_discovery_with_policy(
        &OidcDiscoveryConfig {
            issuer: issuer.clone(),
            jwks_uri_override: None,
            discovery_timeout: DISCOVERY_TIMEOUT,
            max_doc_bytes: MAXIMUM_DISCOVERY_BYTES,
        },
        &policy,
    )
    .await
    .map_err(|error| RuntimeError::Discovery(error.to_string()))?;
    let authorization_endpoint =
        discovered_endpoint(&discovery, "authorization_endpoint", development)?;
    let token_endpoint = discovered_endpoint(&discovery, "token_endpoint", development)?;
    let requires_iss = discovery
        .extra
        .get("authorization_response_iss_parameter_supported")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let jwks = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        discovery.jwks_uri.clone(),
        JwksFetcherConfig::defaults(),
        policy.clone(),
    ));
    // The verifier accepts ID tokens only: with no access-token `typ`
    // allowed, it refuses every access token, which the page never reads.
    let verifier = TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            issuer.clone(),
            vec![config.sign_in.client_id.clone()],
            ID_TOKEN_ALGORITHMS.to_vec(),
            Vec::new(),
        )
        .with_allowed_clients(vec![config.sign_in.client_id.clone()])
        .with_leeway(ID_TOKEN_LEEWAY),
        jwks,
    );
    let sign_in_client = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(token_endpoint, config.sign_in.client_id.clone(), client_key)
            .with_audience(issuer.clone())
            .with_resource(config.registry.resource.clone())
            .with_fetch_url_policy(policy),
    )
    .map_err(|error| RuntimeError::SignInClient(error.to_string()))?;

    let base_url = Url::parse(&config.registry.base_url)
        .map_err(|_| RuntimeError::Config(RuntimeConfigError::InvalidRegistry))?;
    let registry = BaseRegistryClient::new(BaseRegistryClientConfig::new(base_url))
        .map_err(|error| RuntimeError::Registry(error.to_string()))?;

    let log = DurableSegmentedAuditLog::initialize(
        config.audit.path.clone(),
        journal::MAXIMUM_SEGMENT_BYTES,
        audit_profile.chain_hasher(),
    )
    .await
    .map_err(|error| RuntimeError::Audit(error.to_string()))?;
    let journal = Journal::new(
        log,
        audit_profile.key_hasher(),
        &issuer,
        &config.sign_in.client_id,
    )
    .map_err(|_| RuntimeError::Audit("the client pseudonym could not be derived".to_owned()))?;

    let templates =
        Templates::load().map_err(|error| RuntimeError::Templates(error.to_string()))?;
    let app = Arc::new(App {
        issuer,
        client_id: config.sign_in.client_id.clone(),
        scopes: config.sign_in.scopes.clone(),
        resource: config.registry.resource.clone(),
        entity: config.registry.entity.clone(),
        target_field: config.registry.target_field.clone(),
        access_profile: config.registry.access_profile.clone(),
        authorization_endpoint,
        requires_iss,
        redirect_uri: config.redirect_uri()?,
        sign_in_client,
        verifier,
        registry,
        templates,
        sessions: Store::new(
            config.session.maximum_sessions,
            config.session.maximum_pending_sign_ins,
        ),
        journal,
        per_citizen: limiter(config.limits.per_citizen)?,
        global_sign_in: limiter(config.limits.global_sign_in)?,
        cookies: Cookies::for_mode(development),
        maximum_session: Duration::from_secs(config.session.maximum_lifetime_seconds),
        sign_in_lifetime: Duration::from_secs(config.session.sign_in_lifetime_seconds),
    });

    let csp = CspBuilder::deny_by_default()
        .with_style_src(&["'self'"])
        .with_form_action(&["'self'"]);
    let mut headers = security_headers(csp);
    if development {
        headers = headers.without_hsts();
    }
    Ok(Router::new()
        .route("/health", guarded(get(health)))
        .route("/ready", guarded(get(ready)))
        .route("/review.css", guarded(get(stylesheet)))
        .route("/signin", guarded(get(signin::start)))
        .route("/signin/callback", guarded(get(signin::callback)))
        .route("/signout", guarded(post(pages::sign_out)))
        .route("/requests/{request_id}", guarded(get(pages::review)))
        .route(
            "/requests/{request_id}/submit",
            guarded(post(pages::submit)),
        )
        .fallback(not_found)
        .with_state(app)
        .layer(middleware::map_response(no_store))
        .layer(headers))
}

/// Answer every method a route does not serve with the HTML refusal.
fn guarded(route: MethodRouter<Arc<App>>) -> MethodRouter<Arc<App>> {
    route.fallback(method_not_allowed)
}

async fn not_found(axum::extract::State(app): axum::extract::State<Arc<App>>) -> Response {
    app.problem(Problem::NotFound)
}

async fn method_not_allowed(axum::extract::State(app): axum::extract::State<Arc<App>>) -> Response {
    app.problem(Problem::MethodNotAllowed)
}

/// Nothing the page answers may be stored, except the stylesheet, which
/// sets its own policy.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

async fn health() -> Response {
    json_status(StatusCode::OK, "{\"status\":\"alive\"}")
}

async fn ready(axum::extract::State(app): axum::extract::State<Arc<App>>) -> Response {
    if app.journal.ready().await {
        json_status(StatusCode::OK, "{\"status\":\"ready\"}")
    } else {
        json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"status\":\"not-ready\"}",
        )
    }
}

fn json_status(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

async fn stylesheet() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        templates::STYLESHEET,
    )
        .into_response()
}

/// Serve `router` on `listener`.
pub async fn serve(listener: tokio::net::TcpListener, router: Router) -> std::io::Result<()> {
    axum::serve(listener, router).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_lowercase_hyphenated_uuids_are_canonical() {
        let id = "3f6c8a3e-0b8e-4c52-9d0e-6a4f1c2b7d10";
        assert!(canonical_uuid(id));
        assert!(!canonical_uuid(&id.to_ascii_uppercase()));
        assert!(!canonical_uuid(&format!("{{{id}}}")));
        assert!(!canonical_uuid(&id.replace('-', "")));
        assert!(!canonical_uuid(&format!("urn:uuid:{id}")));
    }

    #[test]
    fn a_repeated_or_malformed_cookie_is_absent() {
        let token = "A".repeat(43);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; name={token}")).unwrap(),
        );
        assert_eq!(cookie(&headers, "name"), Some(token.as_str()));
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("name={token}")).unwrap(),
        );
        assert_eq!(cookie(&headers, "name"), None);
        let mut malformed = HeaderMap::new();
        malformed.insert(header::COOKIE, HeaderValue::from_static("name=<script>"));
        assert_eq!(cookie(&malformed, "name"), None);
    }

    #[test]
    fn a_full_sign_in_store_answers_its_own_refusal() {
        let (status, code, _, message) = Problem::SignInsExhausted.parts();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "sign-ins-exhausted");
        assert!(message.contains("sign-ins are in progress"), "{message}");
    }

    #[test]
    fn production_cookies_are_host_prefixed_and_secure() {
        let cookies = Cookies::for_mode(false);
        let value = cookies.set(cookies.session, &"A".repeat(43), 60, "Strict");
        let value = value.to_str().unwrap();
        assert!(value.starts_with("__Host-breg-review-session="));
        assert!(value.ends_with("; HttpOnly; SameSite=Strict; Secure"));
        assert!(!value.contains("Domain"));
    }
}
