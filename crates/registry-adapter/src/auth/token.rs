// SPDX-License-Identifier: Apache-2.0

//! The OAuth2 machinery of section 10.2: rendering the fixed token
//! request, reading the answer as Evidence reads it, the clamped cache,
//! the per-exchange budget, and the 401 rule's decisions.
//!
//! The token endpoint is a fixed destination bound in the runtime
//! config, never derived from a response. The send itself is the
//! engine's: [`TokenSend`] hands one rendered request to the endpoint's
//! own outbound client, which carries the endpoint's trust profile and
//! mTLS identity. Acquisition holds the endpoint's cache lock across
//! the send, which is the single-flight refresh: concurrent exchanges
//! over one endpoint serialize behind one token request, and a waiter
//! wakes to a fresh credential. Waiters queue for at most
//! [`TOKEN_ADMISSION_TIMEOUT`]; past that bound a waiter refuses with a
//! transport timeout instead of parking an engine worker behind a
//! stalled authorization server.
//!
//! Token responses are read as Evidence reads them: `token_type` must be
//! `Bearer` in any case; a missing `expires_in` takes the operator's
//! `assumedLifetimeSeconds` and fails as a credential error without one;
//! the lifetime is anchored when the request is sent, not when the reply
//! arrives; the cache is clamped to `maximumCacheSeconds`; unknown
//! members are ignored; scope narrowing is refused.

use crate::auth::{
    json::{parse_object, JsonMember},
    material::{basic_value, form_body, AuthHeader, ProtectedText},
    AuthError, AuthEvent,
};
use registry_adapter_core::CredentialPlacement;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::{
    TransportKind, DEFAULT_ASSERTION_LIFETIME_SECONDS, MAXIMUM_TOKEN_RESPONSE_BYTES,
};
use registry_platform_yaml::{ExternalId, SecretReference};
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// What a token request accepts, fixed.
pub const TOKEN_REQUEST_ACCEPT: &str = "application/json";
/// What a token request body always is, fixed.
pub const TOKEN_REQUEST_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
/// The RFC 7523 client-assertion type indicator, fixed.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The longest token request body this layer renders; the members it
/// carries are operator configuration and one credential, and a body
/// beyond this bound is a misconfiguration, not a sendable request.
pub const MAXIMUM_TOKEN_REQUEST_BYTES: usize = 16 * 1024;
/// The longest credential a token response may carry, matching the
/// platform's bearer bound.
pub(crate) const MAXIMUM_CREDENTIAL_BYTES: usize = 8 * 1024;
/// The longest scope member a token response may state, Evidence's
/// bound; a stated scope must equal the requested scope exactly.
pub(crate) const MAXIMUM_RESPONSE_SCOPE_BYTES: usize = 512;
/// The fixed name for an OAuth 2.0 error code outside the RFC 6749 and
/// RFC 8707 registered sets; the server's own spelling never crosses
/// into a diagnostic.
pub const UNREGISTERED_ERROR_CODE: &str = "unregistered-error-code";
/// How long one waiter may queue for the endpoint's cache lock behind an
/// in-flight refresh before its own acquisition refuses, the admission
/// bound of the single-flight refresh: a stalled authorization server
/// must not park every engine worker that shares the endpoint.
pub(crate) const TOKEN_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The registered RFC 6749 and RFC 8707 code names.
const REGISTERED_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
];

/// The fixed code name for one wire spelling: the registered name, or
/// [`UNREGISTERED_ERROR_CODE`] for anything else.
fn error_code_name(wire: &str) -> &'static str {
    REGISTERED_ERROR_CODES
        .iter()
        .find(|code| **code == wire)
        .copied()
        .unwrap_or(UNREGISTERED_ERROR_CODE)
}

/// Why the token endpoint did not yield a credential. Every rendering is
/// fixed text; the registered code names are the RFC spellings, and an
/// unregistered spelling collapses to one fixed name, never server
/// text. The HTTP status decides the fault before any body is read, so
/// no gateway error page can masquerade as a malformed response and no
/// outage as a rejected credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFault {
    /// The token request did not complete on the transport.
    Transport {
        /// The coarse transport failure kind.
        kind: TransportKind,
    },
    /// The token endpoint declined to issue a credential.
    Refused {
        /// The registered RFC 6749 or RFC 8707 code name, or the fixed
        /// name for an unregistered spelling.
        code: &'static str,
    },
    /// The token endpoint answered with a redirect, which this client
    /// never follows: the token endpoint is a fixed destination, never
    /// one a response derives.
    Redirect,
    /// The token endpoint is unavailable: 429 or a server error, which
    /// is catchable and retryable, not a judgment on the credential.
    Unavailable {
        /// The HTTP status.
        status: u16,
    },
    /// The answer's body is not a JSON object this layer can read.
    Unreadable,
    /// The token response stated a scope that does not include every
    /// scope the deployment requested.
    ScopeNarrowed,
    /// The answer stated no `expires_in` and the deployment set no
    /// `assumedLifetimeSeconds`; the credential arrangement is unusable,
    /// which is a credential error, not a protocol one.
    NoLifetime,
    /// The credential in the answer is not presentable: missing, empty,
    /// out of bounds, or not the visible ASCII a header carries.
    Invalid,
}

impl fmt::Display for TokenFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { kind } => {
                write!(formatter, "the token request did not complete: {kind}")
            }
            Self::Refused { code } => {
                write!(
                    formatter,
                    "the token endpoint declined to issue a token: {code}"
                )
            }
            Self::Redirect => formatter.write_str("the token endpoint answered with a redirect"),
            Self::Unavailable { status } => {
                write!(
                    formatter,
                    "the token endpoint is unavailable: status {status}"
                )
            }
            Self::Unreadable => {
                formatter.write_str("the token response body is not a readable JSON object")
            }
            Self::ScopeNarrowed => {
                formatter.write_str("the token response does not include every requested scope")
            }
            Self::NoLifetime => formatter
                .write_str("the token response stated no lifetime and the deployment assumes none"),
            Self::Invalid => formatter
                .write_str("the token response carries no credential this client can present"),
        }
    }
}

/// One rendered token request: the fixed destination, the optional
/// Basic client authentication, and the form body, which carries every
/// other credential. The transport adds the fixed `accept` and
/// `content-type` headers and never logs the body. No `PartialEq`: the
/// body is a secret buffer, and equality of secrets is never asked.
#[derive(Debug)]
pub struct TokenRequest {
    /// The fixed token endpoint, absolute.
    pub url: String,
    /// The Basic client authentication, for the `basic-header`
    /// placement.
    pub authorization: Option<AuthHeader>,
    /// The `application/x-www-form-urlencoded` body.
    pub body: ProtectedText,
}

/// What came back from one token send. The body is the caller's to
/// bound; this layer refuses one beyond
/// [`MAXIMUM_TOKEN_RESPONSE_BYTES`]. Deliberately not `Clone`: the body
/// carries an issued credential, and the one buffer it arrives in is
/// zeroizing, erased the moment the answer is read.
pub struct TokenWire {
    /// The HTTP status.
    pub status: u16,
    /// The media type without parameters, as the transport read it;
    /// `None` when the response carried no usable `content-type`.
    pub media_type: Option<String>,
    /// The response body bytes in a zeroizing buffer.
    pub body: Zeroizing<Vec<u8>>,
}

/// Why a token send did not reach a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailure {
    /// The coarse transport failure kind.
    pub kind: TransportKind,
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the token request did not complete: {}",
            self.kind
        )
    }
}

/// Sends one token request through the endpoint's own outbound client:
/// the same trust profile and the same mTLS identity as the endpoint's
/// data sends.
///
/// The send is asynchronous and its future must be `Send`: the
/// acquisition polls it while holding the endpoint's cache lock, and the
/// engine polls many acquisitions at once. Waiters queue for that lock
/// for at most [`TOKEN_ADMISSION_TIMEOUT`]; past the bound a waiter
/// fails with a transport timeout rather than block its caller, so an
/// implementation may take as long as its own request timeout but never
/// longer than that plus the admission bound holds anyone else.
pub trait TokenSend: Send + Sync {
    /// Send one rendered token request.
    fn send<'a>(
        &'a self,
        request: &'a TokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>;
}

/// The inputs of one RFC 7523 client assertion, everything the signer
/// needs and nothing it does not: the client id, the audience compared
/// by Simple String Comparison, the resolved private key, and the
/// assertion's issuance instant and lifetime.
pub struct ClientAssertion<'a> {
    /// The client id the assertion names.
    pub client_id: &'a str,
    /// The audience the assertion is bound to.
    pub audience: &'a str,
    /// The resolved private key, in the signer's hands only.
    pub key: &'a ProtectedText,
    /// When the assertion was issued, Unix seconds.
    pub issued_at_unix: i64,
    /// How long the assertion is good for.
    pub lifetime_seconds: i64,
}

/// Signs one RFC 7523 client assertion from the resolved private key.
/// The engine provides the implementation; the adapter's concrete
/// signer is the platform's client-assertion routine, which the runtime
/// crate links once its manifest carries the crypto dependency. The
/// signer runs inside an acquisition's asynchronous context, so it must
/// be shareable across threads.
pub trait ClientAssertionSigner: Send + Sync {
    /// Sign one client assertion; the returned text is the JWS the token
    /// request carries as its `client_assertion`.
    fn sign_client_assertion(
        &self,
        request: ClientAssertion<'_>,
    ) -> Result<ProtectedText, AuthError>;
}

/// What the engine does with one upstream status, by the 401 rule of
/// section 10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamStatusAction {
    /// No credential action; the send's own status rules apply.
    Continue,
    /// An OAuth2 kind's cached credential was invalidated; repeat the
    /// send once with a fresh one.
    RetryWithFreshCredential,
    /// The uncatchable `credential.rejected`: the upstream refused the
    /// deployment's credential after the single refresh, or the kind is
    /// static and holds nothing to refresh.
    CredentialRejected,
}

/// How the client proves its identity at the token endpoint.
#[derive(Debug, Clone, PartialEq)]
enum ClientAuthentication {
    /// The shared secret, by placement.
    ClientSecret {
        secret_ref: SecretReference,
        placement: CredentialPlacement,
    },
    /// The signed assertion; the audience is resolved at compile time,
    /// defaulting to the token endpoint exactly as the operator wrote
    /// it, because RFC 7523 section 3 compares it by Simple String
    /// Comparison against the endpoint the server published.
    PrivateKeyJwt {
        key_ref: SecretReference,
        audience: String,
    },
}

/// The optional token-request parameters an OAuth2 credential may carry,
/// validated at compile time and rendered in a fixed order.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct TokenRequestParameters {
    /// The `scope` form parameter.
    pub(crate) scope: Option<String>,
    /// The `audience` form parameter.
    pub(crate) audience: Option<String>,
    /// The RFC 8707 `resource` form parameter.
    pub(crate) resource: Option<String>,
}

/// One endpoint's fixed token endpoint plan, owning that endpoint's
/// token cache. The cache lives in the plan, not in the caller's
/// context, so a credential cached for one endpoint can never be served
/// to another: the pairing of cache and endpoint is structural, and
/// every clone of a plan shares its one cache.
pub struct TokenEndpointPlan {
    endpoint: ExternalId,
    url: String,
    client_id_ref: SecretReference,
    client_authentication: ClientAuthentication,
    parameters: TokenRequestParameters,
    maximum_cache: Duration,
    assumed_lifetime: Option<Duration>,
    cache: Arc<TokenCache>,
}

impl fmt::Debug for TokenEndpointPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cache is omitted from every rendering: it holds an issued
        // credential.
        formatter
            .debug_struct("TokenEndpointPlan")
            .field("endpoint", &self.endpoint)
            .field("url", &self.url)
            .field("client_id_ref", &self.client_id_ref)
            .field("client_authentication", &self.client_authentication)
            .field("parameters", &self.parameters)
            .field("maximum_cache", &self.maximum_cache)
            .field("assumed_lifetime", &self.assumed_lifetime)
            .finish()
    }
}

impl Clone for TokenEndpointPlan {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            url: self.url.clone(),
            client_id_ref: self.client_id_ref.clone(),
            client_authentication: self.client_authentication.clone(),
            parameters: self.parameters.clone(),
            maximum_cache: self.maximum_cache,
            assumed_lifetime: self.assumed_lifetime,
            cache: Arc::clone(&self.cache),
        }
    }
}

/// The operator's cache bounds of one OAuth2 credential: the ceiling a
/// response's lifetime is clamped to and the lifetime assumed when the
/// response states none. Bundled so the plan constructors stay within
/// the argument-count bound.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CacheBounds {
    /// The `maximumCacheSeconds` ceiling.
    pub(crate) maximum: Duration,
    /// The `assumedLifetimeSeconds` stand-in.
    pub(crate) assumed: Option<Duration>,
}

impl TokenEndpointPlan {
    /// Plan the shared-secret kind. Every field arrives validated by
    /// [`crate::auth::AuthPlan::compile`].
    #[must_use]
    pub(crate) fn client_secret(
        endpoint: ExternalId,
        url: String,
        client_id_ref: SecretReference,
        secret_ref: SecretReference,
        placement: CredentialPlacement,
        parameters: TokenRequestParameters,
        bounds: CacheBounds,
    ) -> Self {
        Self {
            endpoint,
            url,
            client_id_ref,
            client_authentication: ClientAuthentication::ClientSecret {
                secret_ref,
                placement,
            },
            parameters,
            maximum_cache: bounds.maximum,
            assumed_lifetime: bounds.assumed,
            cache: Arc::new(TokenCache::new()),
        }
    }

    /// Plan the signed-assertion kind; the assertion audience arrives
    /// resolved, because the default is the token endpoint exactly as
    /// the operator wrote it.
    #[must_use]
    pub(crate) fn private_key_jwt(
        endpoint: ExternalId,
        url: String,
        client_id_ref: SecretReference,
        key_ref: SecretReference,
        assertion_audience: String,
        parameters: TokenRequestParameters,
        bounds: CacheBounds,
    ) -> Self {
        Self {
            endpoint,
            url,
            client_id_ref,
            client_authentication: ClientAuthentication::PrivateKeyJwt {
                key_ref,
                audience: assertion_audience,
            },
            parameters,
            maximum_cache: bounds.maximum,
            assumed_lifetime: bounds.assumed,
            cache: Arc::new(TokenCache::new()),
        }
    }

    /// The endpoint this plan's cache and budget allowance are keyed by.
    #[must_use]
    pub fn endpoint(&self) -> &ExternalId {
        &self.endpoint
    }

    /// The fixed destination, absolute, as the runtime config bound it.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The endpoint's token cache this plan owns; every clone of the
    /// plan shares it.
    #[must_use]
    pub fn cache(&self) -> &TokenCache {
        &self.cache
    }

    /// The cache ceiling the operator set.
    #[must_use]
    pub fn maximum_cache(&self) -> Duration {
        self.maximum_cache
    }

    /// Render one token request from resolved secrets.
    ///
    /// Every resolved secret is folded into the rendered request and
    /// dropped here; nothing the caller keeps outlives the request
    /// except the request itself. The client id is identifying, not
    /// authenticating, and travels as text, in the body or as the Basic
    /// username; under the Basic placement the body omits it, because
    /// RFC 6749 section 2.3.1 allows one client authentication method
    /// per request and Evidence's `token_request` omits it there too.
    /// The secret and the private key stay in zeroizing buffers from
    /// resolution to the wire.
    fn render(
        &self,
        resolver: &SecretResolver,
        signer: &dyn ClientAssertionSigner,
    ) -> Result<TokenRequest, AuthError> {
        let client_id = resolve_text(resolver, &self.client_id_ref)?;
        let mut authorization = None;
        let mut secret = None;
        let mut assertion = None;
        if let ClientAuthentication::ClientSecret {
            secret_ref,
            placement,
        } = &self.client_authentication
        {
            match placement {
                CredentialPlacement::BasicHeader => {
                    let resolved = resolve_protected(resolver, secret_ref)?;
                    let value = basic_value(client_id.as_bytes(), resolved.as_bytes())
                        .map_err(|_| AuthError::Credential)?;
                    authorization = Some(AuthHeader::new("authorization", value));
                }
                CredentialPlacement::FormBody => {
                    secret = Some(resolve_protected(resolver, secret_ref)?)
                }
            }
        }
        if let ClientAuthentication::PrivateKeyJwt { key_ref, audience } =
            &self.client_authentication
        {
            let key = resolve_binary(resolver, key_ref)?;
            let issued_at_unix = unix_now()?;
            assertion = Some(signer.sign_client_assertion(ClientAssertion {
                client_id: &client_id,
                audience,
                key: &key,
                issued_at_unix,
                lifetime_seconds: DEFAULT_ASSERTION_LIFETIME_SECONDS,
            })?);
        }
        let secret_text = secret
            .as_ref()
            .map(|secret| str::from_utf8(secret.as_bytes()))
            .transpose()
            .map_err(|_| AuthError::Credential)?;
        let assertion_text = assertion
            .as_ref()
            .map(|assertion| str::from_utf8(assertion.as_bytes()))
            .transpose()
            .map_err(|_| AuthError::Credential)?;
        let mut pairs: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
        if let Some(scope) = self.parameters.scope.as_deref() {
            pairs.push(("scope", scope));
        }
        if let Some(audience) = self.parameters.audience.as_deref() {
            pairs.push(("audience", audience));
        }
        if let Some(resource) = self.parameters.resource.as_deref() {
            pairs.push(("resource", resource));
        }
        // RFC 6749 section 2.3.1 allows one client authentication
        // method per request: the Basic placement names the client in
        // the header alone, so the body omits client_id there.
        let authenticates_by_basic_header = matches!(
            &self.client_authentication,
            ClientAuthentication::ClientSecret {
                placement: CredentialPlacement::BasicHeader,
                ..
            }
        );
        if !authenticates_by_basic_header {
            pairs.push(("client_id", &client_id));
        }
        if let Some(secret) = secret_text {
            pairs.push(("client_secret", secret));
        }
        if let Some(assertion) = assertion_text {
            pairs.push(("client_assertion_type", CLIENT_ASSERTION_TYPE));
            pairs.push(("client_assertion", assertion));
        }
        let body = form_body(&pairs);
        if body.len() > MAXIMUM_TOKEN_REQUEST_BYTES {
            return Err(AuthError::Credential);
        }
        Ok(TokenRequest {
            url: self.url.clone(),
            authorization,
            body,
        })
    }
}

/// The current instant as Unix seconds, for the client assertion's
/// `iat`. A clock the platform reports before the epoch refuses rather
/// than signing an assertion stamped `iat = 0`, which the server would
/// reject as a confusing token refusal.
fn unix_now() -> Result<i64, AuthError> {
    unix_instant(SystemTime::now())
}

/// The Unix seconds of one instant, the pure half of [`unix_now`] so
/// the refusals are testable. A `SystemTime` on the platforms this
/// builds for can neither precede the epoch nor overflow `i64` seconds;
/// a platform that reports either refuses rather than sign a false
/// instant.
fn unix_instant(now: SystemTime) -> Result<i64, AuthError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Credential)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| AuthError::Credential)
}

/// How many token sends one endpoint's allowance holds per exchange.
const TOKEN_SENDS_PER_EXCHANGE: u8 = 2;

/// The exchange's token budget: at most [`TOKEN_SENDS_PER_EXCHANGE`]
/// token sends per endpoint per exchange, outside `maximumUpstreamCalls`
/// and bounded separately (`products/adapter/CONCEPT.md` section 10.2).
/// Keyed by endpoint: one endpoint's refreshes never spend another
/// endpoint's allowance.
#[derive(Debug, Default)]
pub struct TokenBudget {
    remaining: BTreeMap<ExternalId, u8>,
}

impl TokenBudget {
    /// A fresh exchange's budget.
    #[must_use]
    pub const fn new_exchange() -> Self {
        Self {
            remaining: BTreeMap::new(),
        }
    }

    /// Sends left for one endpoint in this exchange.
    #[must_use]
    pub fn remaining(&self, endpoint: &ExternalId) -> u8 {
        self.remaining
            .get(endpoint)
            .copied()
            .unwrap_or(TOKEN_SENDS_PER_EXCHANGE)
    }

    fn consume(&mut self, endpoint: &ExternalId) -> Result<(), AuthError> {
        let allowance = self
            .remaining
            .entry(endpoint.clone())
            .or_insert(TOKEN_SENDS_PER_EXCHANGE);
        if *allowance == 0 {
            return Err(AuthError::BudgetExhausted);
        }
        *allowance -= 1;
        Ok(())
    }
}

/// One cached credential, erased when dropped, with the instant it
/// stops being fresh and the generation that names its issuance.
struct CachedToken {
    token: ProtectedText,
    expires_at: Instant,
    generation: u64,
}

/// The guarded cache state: the cached issuance, if any, and the
/// generation counter every store advances. The counter lives under the
/// same lock as the store, so generations are handed out in store
/// order, and an issuance's name survives its own replacement.
#[derive(Default)]
struct CacheState {
    cached: Option<CachedToken>,
    generation: u64,
}

impl CacheState {
    /// Store one issued credential under the next generation; returns
    /// the generation stored. The acquisition calls this on its success
    /// path, holding the guard it kept across the send.
    fn store_next(&mut self, token: ProtectedText, expires_at: Instant) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.cached = Some(CachedToken {
            token,
            expires_at,
            generation,
        });
        generation
    }
}

/// One endpoint's token cache, owned by that endpoint's
/// [`TokenEndpointPlan`] and shared by every exchange over it: every
/// binding with the same credential shares freshness, because the
/// deployment holds one client identity per endpoint. The lock never
/// poisons: a send that panics releases it, and the next waiter starts
/// a fresh acquisition.
pub struct TokenCache {
    state: Mutex<CacheState>,
    admission_timeout: Duration,
}

impl TokenCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            admission_timeout: TOKEN_ADMISSION_TIMEOUT,
        }
    }

    /// Discard the cached credential only when it is still the issuance
    /// `sent` names, the 401 rule's compare-and-invalidate: the send
    /// that drew the 401 clears its own issuance, and a concurrent
    /// refresh's fresher issuance survives it. `None` clears
    /// unconditionally, the fallback for an engine that lost track of
    /// what it sent.
    ///
    /// The lock wait is one handoff, never a queue: the lock is held
    /// only across one in-flight token send, whose own request timeout
    /// bounds it, and one 401 cannot accumulate waiters behind it. That
    /// is why this call takes no admission bound; a bounded give-up
    /// would skip the invalidation and strand the credential that just
    /// drew the 401.
    pub async fn invalidate_if(&self, sent: Option<u64>) {
        let mut guard = self.state.lock().await;
        let matches = match sent {
            Some(sent) => guard
                .cached
                .as_ref()
                .is_some_and(|cached| cached.generation == sent),
            None => true,
        };
        if matches {
            guard.cached = None;
        }
    }

    /// How much cached freshness remains, for operators and tests;
    /// `None` when nothing is cached. The lock wait is one handoff, for
    /// the same reason as [`TokenCache::invalidate_if`]: a single
    /// operator query cannot form the queue the acquisition's admission
    /// bound exists to break.
    pub async fn remaining_lifetime(&self) -> Option<Duration> {
        self.state
            .lock()
            .await
            .cached
            .as_ref()
            .map(|cached| cached.expires_at.saturating_duration_since(Instant::now()))
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Acquire one credential, from cache or from the fixed token endpoint.
///
/// The acquisition holds the endpoint's cache lock from the miss through
/// the store, which is the single-flight refresh: concurrent exchanges
/// serialize behind the one request in flight, each waiting for the lock
/// for at most the cache's admission bound before refusing with a
/// transport timeout. The lifetime anchor is taken just before the send,
/// the earliest moment the issuer could have issued, so a cached
/// credential can never outlive its real expiry. An issuance that earns
/// no cache lifetime is never stored, Evidence's rule, so the returned
/// generation is `None` for it and a 401 about that send invalidates
/// nothing.
pub(crate) async fn acquire_token(
    plan: &TokenEndpointPlan,
    budget: &mut TokenBudget,
    resolver: &SecretResolver,
    send: &dyn TokenSend,
    signer: &dyn ClientAssertionSigner,
    events: &mut Vec<AuthEvent>,
) -> Result<(ProtectedText, Option<u64>), AuthError> {
    let cache = plan.cache.as_ref();
    let mut guard = match timeout(cache.admission_timeout, cache.state.lock()).await {
        Ok(guard) => guard,
        Err(_elapsed) => {
            events.push(AuthEvent::TokenTransportFailed {
                kind: TransportKind::Timeout.kind(),
            });
            return Err(AuthError::Token(TokenFault::Transport {
                kind: TransportKind::Timeout,
            }));
        }
    };
    if let Some(cached) = guard.cached.as_ref() {
        if Instant::now() < cached.expires_at {
            events.push(AuthEvent::TokenCacheHit);
            return Ok((cached.token.clone(), Some(cached.generation)));
        }
    }
    // The allowance is spent only once the request actually renders: a
    // secret that cannot resolve never spends a send that never went out.
    let request = plan.render(resolver, signer)?;
    budget
        .consume(&plan.endpoint)
        .inspect_err(|_| events.push(AuthEvent::TokenBudgetExhausted))?;
    let anchored = Instant::now();
    events.push(AuthEvent::TokenRequested);
    let wire = match send.send(&request).await {
        Ok(wire) => wire,
        Err(failure) => {
            events.push(AuthEvent::TokenTransportFailed {
                kind: failure.kind.kind(),
            });
            return Err(AuthError::Token(TokenFault::Transport {
                kind: failure.kind,
            }));
        }
    };
    match read_answer(
        wire,
        plan.parameters.scope.as_deref(),
        plan.assumed_lifetime,
    ) {
        Ok((token, lifetime)) => {
            let cache_lifetime = clamped_lifetime(lifetime, plan.maximum_cache);
            // Evidence's rule: an issuance that earns no cache lifetime
            // is never stored, so an already-expired credential does not
            // linger in memory for nothing.
            let generation = if cache_lifetime.is_zero() {
                None
            } else {
                let expires_at = anchored + cache_lifetime;
                Some(guard.store_next(token.clone(), expires_at))
            };
            events.push(AuthEvent::TokenIssued);
            Ok((token, generation))
        }
        Err(fault) => {
            match fault {
                TokenFault::Refused { code } => {
                    events.push(AuthEvent::TokenRefused { code });
                }
                TokenFault::Transport { kind } => {
                    events.push(AuthEvent::TokenTransportFailed { kind: kind.kind() });
                }
                TokenFault::Redirect => {
                    events.push(AuthEvent::TokenRedirected);
                }
                TokenFault::Unavailable { status } => {
                    events.push(AuthEvent::TokenUnavailable { status });
                }
                TokenFault::Unreadable
                | TokenFault::ScopeNarrowed
                | TokenFault::NoLifetime
                | TokenFault::Invalid => {
                    events.push(AuthEvent::TokenProtocolRefused);
                }
            }
            Err(AuthError::Token(fault))
        }
    }
}

/// Read one answer: the status decides the fault class before any body
/// is read, then the media type, then the body as Evidence reads it.
fn read_answer(
    wire: TokenWire,
    expected_scope: Option<&str>,
    assumed_lifetime: Option<Duration>,
) -> Result<(ProtectedText, Duration), TokenFault> {
    if (300..=399).contains(&wire.status) {
        return Err(TokenFault::Redirect);
    }
    if wire.status == 400 || wire.status == 401 {
        let code = parse_object(&wire.body, MAXIMUM_TOKEN_RESPONSE_BYTES as usize)
            .ok()
            .and_then(|members| {
                members
                    .iter()
                    .find_map(|(name, member)| match (name.as_str(), member) {
                        ("error", JsonMember::Text(code)) => Some(error_code_name(code)),
                        _ => None,
                    })
            })
            .unwrap_or(UNREGISTERED_ERROR_CODE);
        return Err(TokenFault::Refused { code });
    }
    if wire.status == 429 || (500..=599).contains(&wire.status) {
        return Err(TokenFault::Unavailable {
            status: wire.status,
        });
    }
    if !(200..300).contains(&wire.status) {
        // Any other status (403, 404, 405, 1xx, ...) says the token
        // endpoint is misconfigured for this deployment, which is a
        // deployment credential fault, so it is uncatchable.
        return Err(TokenFault::Refused {
            code: UNREGISTERED_ERROR_CODE,
        });
    }
    let media_is_json = wire
        .media_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !media_is_json {
        return Err(TokenFault::Unreadable);
    }
    parse_token_response(&wire.body, expected_scope, assumed_lifetime)
}

/// Read one token response body as Evidence reads it.
pub(crate) fn parse_token_response(
    bytes: &[u8],
    expected_scope: Option<&str>,
    assumed_lifetime: Option<Duration>,
) -> Result<(ProtectedText, Duration), TokenFault> {
    let members = parse_object(bytes, MAXIMUM_TOKEN_RESPONSE_BYTES as usize)
        .map_err(|_| TokenFault::Unreadable)?;
    let token = member_text(&members, "access_token")?.ok_or(TokenFault::Invalid)?;
    if token.is_empty()
        || token.len() > MAXIMUM_CREDENTIAL_BYTES
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(TokenFault::Invalid);
    }
    let token_type = member_text(&members, "token_type")?.ok_or(TokenFault::Invalid)?;
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(TokenFault::Invalid);
    }
    let lifetime = match member_unsigned(&members, "expires_in")? {
        Some(seconds) if seconds > 0 => Duration::from_secs(seconds),
        Some(_) => return Err(TokenFault::Invalid),
        None => assumed_lifetime.ok_or(TokenFault::NoLifetime)?,
    };
    if let Some(scope) = member_text(&members, "scope")? {
        if scope.is_empty() || scope.len() > MAXIMUM_RESPONSE_SCOPE_BYTES {
            return Err(TokenFault::Invalid);
        }
        if expected_scope.is_some_and(|expected| scope != expected) {
            return Err(TokenFault::ScopeNarrowed);
        }
    }
    Ok((ProtectedText::from_str_value(token), lifetime))
}

/// One member read as text: absent is `None`, present but not a string is
/// [`TokenFault::Invalid`].
fn member_text<'a>(
    members: &'a [(Zeroizing<String>, JsonMember)],
    name: &str,
) -> Result<Option<&'a str>, TokenFault> {
    match members.iter().find(|(member, _)| member.as_str() == name) {
        Some((_, JsonMember::Text(value))) => Ok(Some(value.as_str())),
        Some((_, _)) => Err(TokenFault::Invalid),
        None => Ok(None),
    }
}

/// One member read as an unsigned count, the same way.
fn member_unsigned(
    members: &[(Zeroizing<String>, JsonMember)],
    name: &str,
) -> Result<Option<u64>, TokenFault> {
    match members.iter().find(|(member, _)| member.as_str() == name) {
        Some((_, JsonMember::Unsigned(value))) => Ok(Some(*value)),
        Some((_, _)) => Err(TokenFault::Invalid),
        None => Ok(None),
    }
}

/// The cache lifetime a response earns: the response's own lifetime,
/// clamped to the operator's ceiling.
fn clamped_lifetime(lifetime: Duration, maximum: Duration) -> Duration {
    lifetime.min(maximum)
}

/// Resolve one reference to identifying text, the client id: it names the
/// client and never authenticates it, so it travels as text. A value that
/// is not UTF-8 is a misconfigured file rather than a credential.
fn resolve_text(
    resolver: &SecretResolver,
    reference: &SecretReference,
) -> Result<String, AuthError> {
    let secret = resolver
        .resolve(reference.as_str())
        .map_err(|_| AuthError::Credential)?;
    str::from_utf8(secret.expose_secret())
        .map_err(|_| AuthError::Credential)
        .map(str::to_owned)
}

/// Resolve one reference to a zeroizing buffer; every authenticating
/// value enters the layer this way.
pub(crate) fn resolve_protected(
    resolver: &SecretResolver,
    reference: &SecretReference,
) -> Result<ProtectedText, AuthError> {
    let secret = resolver
        .resolve(reference.as_str())
        .map_err(|_| AuthError::Credential)?;
    Ok(ProtectedText::from_bytes(secret.expose_secret()))
}

/// Resolve one reference to bounded bytes, for private key material,
/// which may carry any byte.
pub(crate) fn resolve_binary(
    resolver: &SecretResolver,
    reference: &SecretReference,
) -> Result<ProtectedText, AuthError> {
    let parsed = registry_platform_config::SecretReference::parse(reference.as_str())
        .map_err(|_| AuthError::Credential)?;
    let secret = resolver
        .resolve_binary_reference(&parsed)
        .map_err(|_| AuthError::Credential)?;
    Ok(ProtectedText::from_bytes(secret.expose_secret()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_yaml::SecretProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn secret(name: &str) -> SecretReference {
        SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
    }

    fn resolver() -> SecretResolver {
        SecretResolver::new([SecretProvider::Environment], "").expect("resolver")
    }

    fn endpoint_id(name: &str) -> ExternalId {
        ExternalId::new(name).expect("endpoint id")
    }

    fn client_secret_plan(
        placement: CredentialPlacement,
        cache_seconds: u64,
        assumed: Option<u64>,
        id_env: &str,
        secret_env: &str,
    ) -> TokenEndpointPlan {
        TokenEndpointPlan::client_secret(
            endpoint_id("case-api"),
            "https://token.example.invalid/token".to_owned(),
            secret(id_env),
            secret(secret_env),
            placement,
            TokenRequestParameters::default(),
            CacheBounds {
                maximum: Duration::from_secs(cache_seconds),
                assumed: assumed.map(Duration::from_secs),
            },
        )
    }

    /// A signer that binds the resolved key into its assertion, the way
    /// a real signature is bound to its key; the bound text lets tests
    /// prove where key material travels.
    struct FixedSigner;

    impl ClientAssertionSigner for FixedSigner {
        fn sign_client_assertion(
            &self,
            request: ClientAssertion<'_>,
        ) -> Result<ProtectedText, AuthError> {
            let key = String::from_utf8_lossy(request.key.as_bytes());
            Ok(ProtectedText::from_str_value(&format!(
                "assertion.{}.{}.{}",
                request.client_id, request.audience, key
            )))
        }
    }

    /// Replays one fixed response and records the destinations asked.
    struct ScriptedSend {
        status: u16,
        media_type: Option<&'static str>,
        body: &'static str,
        requests: std::sync::Mutex<Vec<String>>,
    }

    impl ScriptedSend {
        fn always(status: u16, media_type: Option<&'static str>, body: &'static str) -> Self {
            Self {
                status,
                media_type,
                body,
                requests: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn token_request_count(&self) -> usize {
            self.requests.lock().expect("requests").len()
        }
    }

    impl TokenSend for ScriptedSend {
        fn send<'a>(
            &'a self,
            request: &'a TokenRequest,
        ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
        {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("requests")
                    .push(request.url.clone());
                Ok(TokenWire {
                    status: self.status,
                    media_type: self.media_type.map(str::to_owned),
                    body: Zeroizing::new(self.body.as_bytes().to_vec()),
                })
            })
        }
    }

    /// One token response reads exactly as Evidence reads one: bearer in
    /// any case, a positive integer `expires_in`, unknown members
    /// ignored, scope matching when configured.
    #[test]
    fn token_responses_read_as_evidence_reads_them() {
        let (token, lifetime) = parse_token_response(
            br#"{"access_token":"at","token_type":"bEaReR","expires_in":600,"ext":"ignored"}"#,
            None,
            None,
        )
        .expect("a readable response");
        assert_eq!(token.as_bytes(), b"at");
        assert_eq!(lifetime, Duration::from_secs(600));

        parse_token_response(
            br#"{"access_token":"at","token_type":"BEARER"}"#,
            None,
            None,
        )
        .expect_err("missing expires_in without an assumed lifetime refuses");
        assert_eq!(
            parse_token_response(
                br#"{"access_token":"at","token_type":"Bearer"}"#,
                None,
                None
            )
            .unwrap_err(),
            TokenFault::NoLifetime,
            "the missing lifetime is a credential error, not a protocol one"
        );
        let (_, lifetime) = parse_token_response(
            br#"{"access_token":"at","token_type":"Bearer"}"#,
            None,
            Some(Duration::from_secs(60)),
        )
        .expect("the assumed lifetime stands in");
        assert_eq!(lifetime, Duration::from_secs(60));
    }

    /// A present but unusable `expires_in` is never rescued by the
    /// assumed lifetime: zero, negatives, fractions, and strings all
    /// refuse.
    #[test]
    fn unusable_expires_in_never_takes_the_assumed_lifetime() {
        let bodies: [&[u8]; 5] = [
            br#"{"access_token":"at","token_type":"Bearer","expires_in":0}"#,
            br#"{"access_token":"at","token_type":"Bearer","expires_in":-1}"#,
            br#"{"access_token":"at","token_type":"Bearer","expires_in":600.0}"#,
            br#"{"access_token":"at","token_type":"Bearer","expires_in":"600"}"#,
            br#"{"access_token":"at","token_type":"Bearer","expires_in":1e3}"#,
        ];
        for body in bodies {
            assert_eq!(
                parse_token_response(body, None, Some(Duration::from_secs(60))).unwrap_err(),
                TokenFault::Invalid,
                "{} must refuse",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The credential itself must be presentable: a string of visible
    /// ASCII within the platform bound; `token_type` must be bearer.
    #[test]
    fn credentials_must_be_presentable() {
        let bodies: [&[u8]; 7] = [
            br#"{"token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":"","token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":7,"token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":"has space","token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":"folded\ncred","token_type":"Bearer","expires_in":60}"#,
            br#"{"access_token":"at","token_type":"MAC","expires_in":60}"#,
            br#"{"access_token":"at","expires_in":60}"#,
        ];
        for body in bodies {
            assert_eq!(
                parse_token_response(body, None, None).unwrap_err(),
                TokenFault::Invalid,
                "{} must refuse",
                String::from_utf8_lossy(body)
            );
        }
        let long = format!(
            "{{\"access_token\":\"{}\",\"token_type\":\"Bearer\",\"expires_in\":60}}",
            "a".repeat(MAXIMUM_CREDENTIAL_BYTES + 1)
        );
        assert_eq!(
            parse_token_response(long.as_bytes(), None, None).unwrap_err(),
            TokenFault::Invalid
        );
    }

    /// A stated scope must include every scope the deployment requested,
    /// be non-empty, and stay within Evidence's bound; a response
    /// without scope is fine.
    #[test]
    fn scope_narrowing_refuses() {
        assert_eq!(
            parse_token_response(
                br#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"read"}"#,
                Some("read write"),
                None,
            )
            .unwrap_err(),
            TokenFault::ScopeNarrowed
        );
        parse_token_response(
            br#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":"read write"}"#,
            Some("read write"),
            None,
        )
        .expect("an equal scope is fine");
        assert_eq!(
            parse_token_response(
                br#"{"access_token":"at","token_type":"Bearer","expires_in":60,"scope":""}"#,
                None,
                None,
            )
            .unwrap_err(),
            TokenFault::Invalid
        );
        let long = format!(
            "{{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"{}\"}}",
            "s".repeat(513)
        );
        assert_eq!(
            parse_token_response(long.as_bytes(), None, None).unwrap_err(),
            TokenFault::Invalid
        );
    }

    /// A body beyond the platform bound refuses, as does one that is
    /// not one JSON object.
    #[test]
    fn unreadable_bodies_refuse() {
        let oversized = vec![b' '; MAXIMUM_TOKEN_RESPONSE_BYTES as usize + 1];
        assert_eq!(
            parse_token_response(&oversized, None, None).unwrap_err(),
            TokenFault::Unreadable
        );
        assert_eq!(
            parse_token_response(b"[]", None, None).unwrap_err(),
            TokenFault::Unreadable
        );
        assert_eq!(
            parse_token_response(br#"{"a":1,"a":2}"#, None, None).unwrap_err(),
            TokenFault::Unreadable
        );
    }

    /// Registered error codes keep their spelling and unregistered
    /// spellings collapse to the one fixed name.
    #[test]
    fn error_codes_map_to_fixed_names() {
        assert_eq!(error_code_name("invalid_client"), "invalid_client");
        assert_eq!(error_code_name("invalid_target"), "invalid_target");
        assert_eq!(error_code_name("canary_extension"), UNREGISTERED_ERROR_CODE);
        assert_eq!(error_code_name(""), UNREGISTERED_ERROR_CODE);
    }

    /// The cache lifetime a response earns is the response's own,
    /// clamped to the operator's ceiling, and a zero ceiling caches
    /// nothing.
    #[test]
    fn cache_lifetimes_clamp() {
        assert_eq!(
            clamped_lifetime(Duration::from_secs(600), Duration::from_secs(3600)),
            Duration::from_secs(600)
        );
        assert_eq!(
            clamped_lifetime(Duration::from_secs(600), Duration::from_secs(60)),
            Duration::from_secs(60)
        );
        assert_eq!(
            clamped_lifetime(Duration::from_secs(600), Duration::ZERO),
            Duration::ZERO
        );
    }

    /// A budget starts at two for an endpoint and refuses the third; the
    /// allowance is the endpoint's own, so spending one leaves the other
    /// untouched.
    #[test]
    fn budgets_hold_two_sends_per_endpoint() {
        let case_api = endpoint_id("case-api");
        let audit_api = endpoint_id("audit-api");
        let mut budget = TokenBudget::new_exchange();
        assert_eq!(budget.remaining(&case_api), 2);
        budget
            .consume(&case_api)
            .expect("the first send is in budget");
        budget
            .consume(&case_api)
            .expect("the second send is in budget");
        assert_eq!(budget.remaining(&case_api), 0);
        assert_eq!(
            budget.consume(&case_api).unwrap_err(),
            AuthError::BudgetExhausted
        );
        assert_eq!(
            budget.remaining(&audit_api),
            2,
            "another endpoint's allowance is untouched"
        );
        budget
            .consume(&audit_api)
            .expect("the other endpoint still sends");
    }

    /// One acquisition, one cache hit: the second send under the same
    /// plan's cache asks the endpoint nothing.
    #[tokio::test]
    async fn the_cache_answers_the_second_send() {
        std::env::set_var("ADAPTER_TEST_CACHE_ID", "cid-cache");
        std::env::set_var("ADAPTER_TEST_CACHE_SECRET", "csecret-cache");
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let plan = client_secret_plan(
            CredentialPlacement::BasicHeader,
            3600,
            None,
            "ADAPTER_TEST_CACHE_ID",
            "ADAPTER_TEST_CACHE_SECRET",
        );
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let (first, _) = acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .expect("the first acquisition issues");
        assert_eq!(first.as_bytes(), b"at");
        let (second, _) = acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .expect("the cache answers");
        assert_eq!(second.as_bytes(), b"at");
        assert_eq!(send.token_request_count(), 1);
        assert!(events.contains(&AuthEvent::TokenCacheHit));
        assert!(events.contains(&AuthEvent::TokenIssued));
    }

    /// A zero cache ceiling never caches: every acquisition sends, and
    /// no issuance is stored to linger already expired.
    #[tokio::test]
    async fn a_zero_ceiling_never_caches() {
        std::env::set_var("ADAPTER_TEST_ZERO_ID", "cid-zero");
        std::env::set_var("ADAPTER_TEST_ZERO_SECRET", "csecret-zero");
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let plan = client_secret_plan(
            CredentialPlacement::FormBody,
            0,
            None,
            "ADAPTER_TEST_ZERO_ID",
            "ADAPTER_TEST_ZERO_SECRET",
        );
        let (_, generation) = acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .expect("the first acquisition issues");
        assert!(
            generation.is_none(),
            "an issuance with no cache lifetime stores nothing"
        );
        assert!(plan.cache().remaining_lifetime().await.is_none());
        acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .expect("the second acquisition sends again");
        assert_eq!(send.token_request_count(), 2);
    }

    /// A render failure never spends the send's allowance: the budget
    /// is consumed only after the request renders, so a secret that
    /// cannot resolve is charged nothing for a send that never went out.
    #[tokio::test]
    async fn a_render_failure_spends_no_allowance() {
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        // No test sets these environment names, so resolution fails.
        let plan = TokenEndpointPlan::client_secret(
            endpoint_id("case-api"),
            "https://token.example.invalid/token".to_owned(),
            secret("ADAPTER_TEST_RENDER_MISSING_ID"),
            secret("ADAPTER_TEST_RENDER_MISSING_SECRET"),
            CredentialPlacement::FormBody,
            TokenRequestParameters::default(),
            CacheBounds {
                maximum: Duration::from_secs(3600),
                assumed: None,
            },
        );
        let error = acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .unwrap_err();
        assert_eq!(error, AuthError::Credential);
        assert_eq!(
            budget.remaining(&endpoint_id("case-api")),
            TOKEN_SENDS_PER_EXCHANGE,
            "the failed render spent nothing"
        );
        assert_eq!(send.token_request_count(), 0, "nothing was sent");
        assert!(
            !events.contains(&AuthEvent::TokenBudgetExhausted),
            "the budget was never consulted with a failure"
        );
    }

    /// A refused token endpoint surfaces the registered code name and
    /// nothing else; a redirect and a wrong media type are protocol
    /// failures that name only their status.
    #[tokio::test]
    async fn refusals_surface_fixed_names() {
        std::env::set_var("ADAPTER_TEST_REFUSED_ID", "cid-refused");
        std::env::set_var("ADAPTER_TEST_REFUSED_SECRET", "csecret-refused");
        let refused = ScriptedSend::always(
            401,
            Some("application/json"),
            r#"{"error":"invalid_client","error_description":"server text about the credential"}"#,
        );
        let mut events = Vec::new();
        let error = acquire_token(
            &client_secret_plan(
                CredentialPlacement::BasicHeader,
                3600,
                None,
                "ADAPTER_TEST_REFUSED_ID",
                "ADAPTER_TEST_REFUSED_SECRET",
            ),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &refused,
            &FixedSigner,
            &mut events,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(TokenFault::Refused {
                code: "invalid_client"
            })
        );
        assert!(!error.to_string().contains("server text"), "{error}");
        assert_eq!(
            events,
            vec![
                AuthEvent::TokenRequested,
                AuthEvent::TokenRefused {
                    code: "invalid_client"
                },
            ]
        );

        let redirect = ScriptedSend::always(302, Some("application/json"), "");
        let error = acquire_token(
            &client_secret_plan(
                CredentialPlacement::BasicHeader,
                3600,
                None,
                "ADAPTER_TEST_REFUSED_ID",
                "ADAPTER_TEST_REFUSED_SECRET",
            ),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &redirect,
            &FixedSigner,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, AuthError::Token(TokenFault::Redirect));

        let html = ScriptedSend::always(
            200,
            Some("text/html"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":60}"#,
        );
        let error = acquire_token(
            &client_secret_plan(
                CredentialPlacement::BasicHeader,
                3600,
                None,
                "ADAPTER_TEST_REFUSED_ID",
                "ADAPTER_TEST_REFUSED_SECRET",
            ),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &html,
            &FixedSigner,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, AuthError::Token(TokenFault::Unreadable));
    }

    /// The status decides the fault and its class before any body is
    /// read: a redirect is a redirect, an outage is catchable
    /// `upstream.http`, an unparseable 400/401 body is still the
    /// uncatchable credential rejection, and a 2xx that is not a usable
    /// token response is a credential fault.
    #[tokio::test]
    async fn statuses_decide_the_fault_and_class() {
        use super::super::CREDENTIAL_REJECTED_CLASS;
        std::env::set_var("ADAPTER_TEST_STATUS_ID", "cid-status");
        std::env::set_var("ADAPTER_TEST_STATUS_SECRET", "csecret-status");
        async fn fault_of(
            status: u16,
            media_type: Option<&'static str>,
            body: &'static str,
        ) -> AuthError {
            let send = ScriptedSend::always(status, media_type, body);
            acquire_token(
                &client_secret_plan(
                    CredentialPlacement::BasicHeader,
                    3600,
                    None,
                    "ADAPTER_TEST_STATUS_ID",
                    "ADAPTER_TEST_STATUS_SECRET",
                ),
                &mut TokenBudget::new_exchange(),
                &resolver(),
                &send,
                &FixedSigner,
                &mut Vec::new(),
            )
            .await
            .unwrap_err()
        }
        let cases: [(u16, Option<&'static str>, &'static str, TokenFault, &str); 10] = [
            // A 401 with an empty body is still the credential rejection.
            (
                401,
                Some("application/json"),
                "",
                TokenFault::Refused {
                    code: UNREGISTERED_ERROR_CODE,
                },
                CREDENTIAL_REJECTED_CLASS,
            ),
            // So is a 401 whose body is a gateway's HTML error page.
            (
                401,
                Some("text/html"),
                "<html>bad gateway</html>",
                TokenFault::Refused {
                    code: UNREGISTERED_ERROR_CODE,
                },
                CREDENTIAL_REJECTED_CLASS,
            ),
            // A 400 with a registered code keeps its name.
            (
                400,
                Some("application/json"),
                r#"{"error":"invalid_client"}"#,
                TokenFault::Refused {
                    code: "invalid_client",
                },
                CREDENTIAL_REJECTED_CLASS,
            ),
            // A 503 outage with an error body is unavailable, not a
            // judged credential; the body is not read.
            (
                503,
                Some("application/json"),
                r#"{"error":"temporarily_unavailable"}"#,
                TokenFault::Unavailable { status: 503 },
                "upstream.http",
            ),
            (
                429,
                Some("application/json"),
                "",
                TokenFault::Unavailable { status: 429 },
                "upstream.http",
            ),
            // A redirect is a redirect, with or without a body.
            (
                302,
                Some("application/json"),
                r#"{"error":"invalid_client"}"#,
                TokenFault::Redirect,
                "upstream.redirect",
            ),
            (
                302,
                Some("application/json"),
                "",
                TokenFault::Redirect,
                "upstream.redirect",
            ),
            // A misconfigured token endpoint answering 404 is a
            // deployment credential fault, uncatchable.
            (
                404,
                Some("application/json"),
                "",
                TokenFault::Refused {
                    code: UNREGISTERED_ERROR_CODE,
                },
                CREDENTIAL_REJECTED_CLASS,
            ),
            // A 2xx that is not a usable token response is a credential
            // fault, not a malformed one.
            (
                200,
                Some("application/json"),
                r#"{"access_token":"at","token_type":"mac","expires_in":60}"#,
                TokenFault::Invalid,
                CREDENTIAL_REJECTED_CLASS,
            ),
            (
                200,
                Some("application/json"),
                r#"{"access_token":"at","token_type":"Bearer","expires_in":0}"#,
                TokenFault::Invalid,
                CREDENTIAL_REJECTED_CLASS,
            ),
        ];
        for (status, media_type, body, fault, class) in cases {
            let error = fault_of(status, media_type, body).await;
            assert_eq!(error, AuthError::Token(fault), "status {status}");
            assert_eq!(error.class(), class, "status {status}");
        }
    }

    /// Concurrent acquisitions over one endpoint's cache make exactly one
    /// token request: the refresh is single-flight, and clones of the
    /// plan share the one cache.
    #[tokio::test(flavor = "current_thread")]
    async fn acquisition_is_single_flight() {
        std::env::set_var("ADAPTER_TEST_FLIGHT_ID", "cid-flight");
        std::env::set_var("ADAPTER_TEST_FLIGHT_SECRET", "csecret-flight");
        struct SlowSend {
            in_flight: AtomicUsize,
            peak: AtomicUsize,
            requests: AtomicUsize,
        }
        impl TokenSend for SlowSend {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async move {
                    let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    self.peak.fetch_max(current, Ordering::SeqCst);
                    self.requests.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    self.in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(TokenWire {
                        status: 200,
                        media_type: Some("application/json".to_owned()),
                        body: Zeroizing::new(
                            br#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#
                                .to_vec(),
                        ),
                    })
                })
            }
        }
        let send = std::sync::Arc::new(SlowSend {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        });
        let plan = std::sync::Arc::new(client_secret_plan(
            CredentialPlacement::BasicHeader,
            3600,
            None,
            "ADAPTER_TEST_FLIGHT_ID",
            "ADAPTER_TEST_FLIGHT_SECRET",
        ));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            // Clones share the endpoint's one cache.
            let plan = std::sync::Arc::clone(&plan);
            let send = std::sync::Arc::clone(&send);
            tasks.push(tokio::spawn(async move {
                let signer = FixedSigner;
                let mut budget = TokenBudget::new_exchange();
                let mut events = Vec::new();
                acquire_token(
                    &plan,
                    &mut budget,
                    &resolver(),
                    send.as_ref(),
                    &signer,
                    &mut events,
                )
                .await
                .expect("every waiter acquires")
            }));
        }
        for task in tasks {
            task.await.expect("joined");
        }
        assert_eq!(send.requests.load(Ordering::SeqCst), 1, "one token request");
        assert_eq!(send.peak.load(Ordering::SeqCst), 1, "no concurrent sends");
    }

    /// The 401 rule's compare-and-invalidate: only the generation the
    /// send carried clears; a concurrent refresh's fresher issuance
    /// survives a stale 401, an unknown generation clears nothing, and
    /// `None` clears unconditionally. The counter keeps advancing past
    /// invalidations, so a stale generation can never alias a future
    /// issuance.
    #[tokio::test]
    async fn invalidate_if_only_clears_the_matching_issuance() {
        async fn store(cache: &TokenCache, token: &str) -> u64 {
            let mut guard = cache.state.lock().await;
            guard.store_next(
                ProtectedText::from_str_value(token),
                Instant::now() + Duration::from_secs(600),
            )
        }
        let cache = TokenCache::new();
        let gen1 = store(&cache, "token-one").await;
        let gen2 = store(&cache, "token-two").await;
        assert_eq!(gen1, 1);
        assert_eq!(gen2, 2, "every store advances the counter");
        // Exchange X drew the 401 on its issuance while exchange Y had
        // already refreshed past it: X's invalidation names gen1 and
        // must leave Y's gen2 in place.
        cache.invalidate_if(Some(gen1)).await;
        assert!(
            cache.remaining_lifetime().await.is_some(),
            "the fresher issuance survives a stale 401"
        );
        cache.invalidate_if(Some(99)).await;
        assert!(
            cache.remaining_lifetime().await.is_some(),
            "a generation the cache never issued clears nothing"
        );
        cache.invalidate_if(Some(gen2)).await;
        assert!(
            cache.remaining_lifetime().await.is_none(),
            "the generation the cache holds clears"
        );
        let gen3 = store(&cache, "token-three").await;
        assert_eq!(gen3, 3, "the counter survives invalidation");
        cache.invalidate_if(None).await;
        assert!(
            cache.remaining_lifetime().await.is_none(),
            "None is the unconditional fallback"
        );
    }

    /// A waiter queued behind a stalled refresh gives up at the
    /// admission bound instead of parking its caller: the refusal is a
    /// transport timeout, no request was sent, and no budget was spent.
    #[tokio::test]
    async fn waiters_give_up_at_the_admission_bound() {
        std::env::set_var("ADAPTER_TEST_WAIT_ID", "cid-wait");
        std::env::set_var("ADAPTER_TEST_WAIT_SECRET", "csecret-wait");
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let mut plan = client_secret_plan(
            CredentialPlacement::BasicHeader,
            3600,
            None,
            "ADAPTER_TEST_WAIT_ID",
            "ADAPTER_TEST_WAIT_SECRET",
        );
        plan.cache = Arc::new(TokenCache {
            state: Mutex::new(CacheState::default()),
            admission_timeout: Duration::from_millis(30),
        });
        // Hold the cache lock the way a stalled refresh would.
        let held = plan.cache.state.lock().await;
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let error = acquire_token(
            &plan,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(TokenFault::Transport {
                kind: TransportKind::Timeout
            })
        );
        assert_eq!(
            events,
            vec![AuthEvent::TokenTransportFailed { kind: "timeout" }]
        );
        assert_eq!(send.token_request_count(), 0);
        assert_eq!(
            budget.remaining(plan.endpoint()),
            2,
            "no budget was spent waiting"
        );
        drop(held);
    }

    /// The private-key-jwt request carries the assertion in the form
    /// body, with the client id beside it, the fixed assertion type, and
    /// no Basic header; the key's text travels only inside the
    /// assertion.
    #[test]
    fn private_key_jwt_renders_its_assertion_in_the_body() {
        std::env::set_var("ADAPTER_TEST_PKJWT_ID", "cid-pkjwt");
        std::env::set_var("ADAPTER_TEST_PKJWT_KEY", "key-pem");
        let url = "https://token.example.invalid/token";
        let plan = TokenEndpointPlan::private_key_jwt(
            endpoint_id("case-api"),
            url.to_owned(),
            secret("ADAPTER_TEST_PKJWT_ID"),
            secret("ADAPTER_TEST_PKJWT_KEY"),
            url.to_owned(),
            TokenRequestParameters::default(),
            CacheBounds {
                maximum: Duration::from_secs(3600),
                assumed: None,
            },
        );
        let request = plan
            .render(&resolver(), &FixedSigner)
            .expect("a rendered request");
        assert_eq!(request.url, url);
        assert!(
            request.authorization.is_none(),
            "the assertion kind has no Basic header"
        );
        assert_eq!(
            str::from_utf8(request.body.as_bytes()).expect("form bytes"),
            "grant_type=client_credentials&client_id=cid-pkjwt\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion=assertion.cid-pkjwt.https%3A%2F%2Ftoken.example.invalid%2Ftoken.key-pem"
        );
    }

    /// A clock before the epoch refuses outright: the assertion is
    /// never signed with `iat = 0`, and the refusal's rendering is
    /// fixed text that carries no time value.
    #[test]
    fn a_pre_epoch_clock_refuses_without_signing() {
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        let error = unix_instant(before_epoch).unwrap_err();
        assert_eq!(error, AuthError::Credential);
        assert_eq!(
            error.to_string(),
            "the deployment's credential is unusable",
            "the rendering carries no time value"
        );
    }

    /// The assertion's issuance instant is the real current Unix time:
    /// a clock the platform reports before the epoch refuses instead of
    /// signing `iat = 0`, and the signed instant tracks the clock.
    #[test]
    fn the_assertion_is_stamped_with_the_current_unix_instant() {
        let now = unix_now().expect("a clock the platform reports after the epoch");
        assert!(
            now > 1_600_000_000,
            "a plausible present instant, not the epoch: {now}"
        );
        // The signed instant is pinned below by a signer that records
        // it.
        let before = unix_now().expect("a second reading");
        std::env::set_var("ADAPTER_TEST_PKJWT_STAMP_ID", "cid-stamp");
        std::env::set_var("ADAPTER_TEST_PKJWT_STAMP_KEY", "key-pem");
        struct StampsIat(std::sync::Mutex<Vec<i64>>);
        impl ClientAssertionSigner for StampsIat {
            fn sign_client_assertion(
                &self,
                request: ClientAssertion<'_>,
            ) -> Result<ProtectedText, AuthError> {
                self.0.lock().expect("stamps").push(request.issued_at_unix);
                Ok(ProtectedText::from_str_value("assertion"))
            }
        }
        let stamps = std::sync::Arc::new(StampsIat(std::sync::Mutex::new(Vec::new())));
        let url = "https://token.example.invalid/token";
        let plan = TokenEndpointPlan::private_key_jwt(
            endpoint_id("case-api"),
            url.to_owned(),
            secret("ADAPTER_TEST_PKJWT_STAMP_ID"),
            secret("ADAPTER_TEST_PKJWT_STAMP_KEY"),
            url.to_owned(),
            TokenRequestParameters::default(),
            CacheBounds {
                maximum: Duration::from_secs(3600),
                assumed: None,
            },
        );
        plan.render(&resolver(), stamps.as_ref())
            .expect("a rendered request");
        let recorded = stamps.0.lock().expect("stamps").clone();
        assert_eq!(recorded.len(), 1);
        assert!(
            recorded[0] >= before.saturating_sub(1) && recorded[0] <= before + 5,
            "the signed iat is the render-time instant, not zero: {} vs {before}",
            recorded[0]
        );
    }

    /// The Basic placement names the client in the header alone: the
    /// body carries no client_id, because RFC 6749 section 2.3.1 allows
    /// one authentication method per request. The form-body placement
    /// carries client_id beside the secret, with no header.
    #[test]
    fn the_body_carries_client_id_except_under_the_basic_placement() {
        std::env::set_var("ADAPTER_TEST_BODY_ID", "cid-body");
        std::env::set_var("ADAPTER_TEST_BODY_SECRET", "csecret-body");
        let basic = client_secret_plan(
            CredentialPlacement::BasicHeader,
            3600,
            None,
            "ADAPTER_TEST_BODY_ID",
            "ADAPTER_TEST_BODY_SECRET",
        )
        .render(&resolver(), &FixedSigner)
        .expect("a rendered request");
        assert!(
            basic.authorization.is_some(),
            "the Basic header carries the pair"
        );
        let body = str::from_utf8(basic.body.as_bytes()).expect("form bytes");
        assert!(body.contains("grant_type=client_credentials"), "{body}");
        assert!(
            !body.contains("client_id"),
            "the Basic placement never repeats the client id in the body: {body}"
        );

        let form = client_secret_plan(
            CredentialPlacement::FormBody,
            3600,
            None,
            "ADAPTER_TEST_BODY_ID",
            "ADAPTER_TEST_BODY_SECRET",
        )
        .render(&resolver(), &FixedSigner)
        .expect("a rendered request");
        assert!(
            form.authorization.is_none(),
            "the form placement has no header"
        );
        let body = str::from_utf8(form.body.as_bytes()).expect("form bytes");
        assert!(
            body.contains("client_id=cid-body&client_secret=csecret-body"),
            "the form placement names the client beside its secret: {body}"
        );
    }

    /// A rendered body beyond the bound refuses rather than sends.
    #[test]
    fn oversized_renders_refuse() {
        std::env::set_var("ADAPTER_TEST_OVERSIZE_ID", "cid");
        std::env::set_var("HUGE_CLIENT_SECRET", "k".repeat(20 * 1024));
        let plan = TokenEndpointPlan::client_secret(
            endpoint_id("case-api"),
            "https://token.example.invalid/token".to_owned(),
            secret("ADAPTER_TEST_OVERSIZE_ID"),
            secret("HUGE_CLIENT_SECRET"),
            CredentialPlacement::FormBody,
            TokenRequestParameters::default(),
            CacheBounds {
                maximum: Duration::from_secs(3600),
                assumed: None,
            },
        );
        assert_eq!(
            plan.render(&resolver(), &FixedSigner).unwrap_err(),
            AuthError::Credential
        );
    }
}
