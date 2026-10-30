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
//! wakes to a fresh credential.
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
use registry_platform_yaml::SecretReference;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
/// text.
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
    /// The answer was not a token response this layer can use: an
    /// unexpected status or media type, an unreadable body, or a member
    /// that does not satisfy the contract.
    Protocol {
        /// The unexpected HTTP status, zero when the body failed.
        status: u16,
    },
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
            Self::Protocol { status } => write!(
                formatter,
                "the token response does not satisfy the OAuth 2.0 contract: status {status}"
            ),
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
/// `content-type` headers and never logs the body.
#[derive(Debug, PartialEq)]
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
/// carries an issued credential, and copies stay inside zeroizing
/// buffers.
pub struct TokenWire {
    /// The HTTP status.
    pub status: u16,
    /// The media type without parameters, as the transport read it;
    /// `None` when the response carried no usable `content-type`.
    pub media_type: Option<String>,
    /// The response body bytes.
    pub body: Vec<u8>,
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
/// data sends. The implementation may block; it runs under the
/// endpoint's cache lock, so a slow authorization server holds the
/// refresh, not the callers.
pub trait TokenSend {
    /// Send one rendered token request.
    fn send(&self, request: &TokenRequest) -> Result<TokenWire, TransportFailure>;
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
/// crate links once its manifest carries the crypto dependency.
pub trait ClientAssertionSigner {
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

/// One endpoint's fixed token endpoint plan.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenEndpointPlan {
    url: String,
    client_id_ref: SecretReference,
    client_authentication: ClientAuthentication,
    parameters: TokenRequestParameters,
    maximum_cache: Duration,
    assumed_lifetime: Option<Duration>,
}

impl TokenEndpointPlan {
    /// Plan the shared-secret kind. Every field arrives validated by
    /// [`crate::auth::AuthPlan::compile`].
    #[must_use]
    pub(crate) fn client_secret(
        url: String,
        client_id_ref: SecretReference,
        secret_ref: SecretReference,
        placement: CredentialPlacement,
        parameters: TokenRequestParameters,
        maximum_cache: Duration,
        assumed_lifetime: Option<Duration>,
    ) -> Self {
        Self {
            url,
            client_id_ref,
            client_authentication: ClientAuthentication::ClientSecret {
                secret_ref,
                placement,
            },
            parameters,
            maximum_cache,
            assumed_lifetime,
        }
    }

    /// Plan the signed-assertion kind; the assertion audience arrives
    /// resolved, because the default is the token endpoint exactly as
    /// the operator wrote it.
    #[must_use]
    pub(crate) fn private_key_jwt(
        url: String,
        client_id_ref: SecretReference,
        key_ref: SecretReference,
        assertion_audience: String,
        parameters: TokenRequestParameters,
        maximum_cache: Duration,
        assumed_lifetime: Option<Duration>,
    ) -> Self {
        Self {
            url,
            client_id_ref,
            client_authentication: ClientAuthentication::PrivateKeyJwt {
                key_ref,
                audience: assertion_audience,
            },
            parameters,
            maximum_cache,
            assumed_lifetime,
        }
    }

    /// The fixed destination, absolute, as the runtime config bound it.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
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
    /// authenticating, and travels as text; the secret and the private
    /// key stay in zeroizing buffers from resolution to the wire.
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
            let issued_at_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or_default();
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
        pairs.push(("client_id", &client_id));
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

/// The exchange's token budget: at most two token sends per endpoint per
/// exchange, outside `maximumUpstreamCalls` and bounded separately
/// (`products/adapter/CONCEPT.md` section 10.2).
#[derive(Debug)]
pub struct TokenBudget {
    remaining: u8,
}

impl TokenBudget {
    /// A fresh exchange's budget.
    #[must_use]
    pub const fn new_exchange() -> Self {
        Self { remaining: 2 }
    }

    /// Sends left in this exchange.
    #[must_use]
    pub const fn remaining(&self) -> u8 {
        self.remaining
    }

    fn consume(&mut self) -> Result<(), AuthError> {
        if self.remaining == 0 {
            return Err(AuthError::BudgetExhausted);
        }
        self.remaining -= 1;
        Ok(())
    }
}

/// One cached credential, erased when dropped, with the instant it
/// stops being fresh.
struct CachedToken {
    token: ProtectedText,
    expires_at: Instant,
}

/// The endpoint's token cache, shared by every exchange. One cache per
/// endpoint: every binding with the same credential shares freshness,
/// because the deployment holds one client identity per endpoint.
pub struct TokenCache {
    state: Mutex<Option<CachedToken>>,
}

impl TokenCache {
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Discard any cached credential; the 401 rule calls this before
    /// the single refresh.
    pub fn invalidate(&self) {
        *self.state.lock().expect("the endpoint's token cache lock") = None;
    }

    /// How much cached freshness remains, for operators and tests;
    /// `None` when nothing is cached.
    #[must_use]
    pub fn remaining_lifetime(&self) -> Option<Duration> {
        let guard = self.state.lock().expect("the endpoint's token cache lock");
        guard
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
/// serialize behind the one request in flight. The lifetime anchor is
/// taken just before the send, the earliest moment the issuer could
/// have issued, so a cached credential can never outlive its real
/// expiry.
pub(crate) fn acquire_token(
    plan: &TokenEndpointPlan,
    cache: &TokenCache,
    budget: &mut TokenBudget,
    resolver: &SecretResolver,
    send: &dyn TokenSend,
    signer: &dyn ClientAssertionSigner,
    events: &mut Vec<AuthEvent>,
) -> Result<ProtectedText, AuthError> {
    let mut guard = cache.state.lock().expect("the endpoint's token cache lock");
    if let Some(cached) = guard.as_ref() {
        if Instant::now() < cached.expires_at {
            events.push(AuthEvent::TokenCacheHit);
            return Ok(cached.token.clone());
        }
    }
    budget
        .consume()
        .inspect_err(|_| events.push(AuthEvent::TokenBudgetExhausted))?;
    let request = plan.render(resolver, signer)?;
    let anchored = Instant::now();
    events.push(AuthEvent::TokenRequested);
    let wire = match send.send(&request) {
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
            let expires_at = anchored + clamped_lifetime(lifetime, plan.maximum_cache);
            *guard = Some(CachedToken {
                token: token.clone(),
                expires_at,
            });
            events.push(AuthEvent::TokenIssued);
            Ok(token)
        }
        Err(fault) => {
            match fault {
                TokenFault::Refused { code } => {
                    events.push(AuthEvent::TokenRefused { code });
                }
                TokenFault::Transport { kind } => {
                    events.push(AuthEvent::TokenTransportFailed { kind: kind.kind() });
                }
                TokenFault::Protocol { .. }
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

/// Read one answer: the status, the media type, then the body as Evidence
/// reads it.
fn read_answer(
    wire: TokenWire,
    expected_scope: Option<&str>,
    assumed_lifetime: Option<Duration>,
) -> Result<(ProtectedText, Duration), TokenFault> {
    if !(200..300).contains(&wire.status) {
        if let Ok(members) = parse_object(&wire.body, MAXIMUM_TOKEN_RESPONSE_BYTES as usize) {
            if let Some((_, JsonMember::Text(code))) =
                members.iter().find(|(name, _)| name == "error")
            {
                return Err(TokenFault::Refused {
                    code: error_code_name(code),
                });
            }
        }
        return Err(TokenFault::Protocol {
            status: wire.status,
        });
    }
    let media_is_json = wire
        .media_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !media_is_json {
        return Err(TokenFault::Protocol {
            status: wire.status,
        });
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
        .map_err(|_| TokenFault::Protocol { status: 0 })?;
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
    members: &'a [(String, JsonMember)],
    name: &str,
) -> Result<Option<&'a str>, TokenFault> {
    match members.iter().find(|(member, _)| member == name) {
        Some((_, JsonMember::Text(value))) => Ok(Some(value.as_str())),
        Some((_, _)) => Err(TokenFault::Invalid),
        None => Ok(None),
    }
}

/// One member read as an unsigned count, the same way.
fn member_unsigned(
    members: &[(String, JsonMember)],
    name: &str,
) -> Result<Option<u64>, TokenFault> {
    match members.iter().find(|(member, _)| member == name) {
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

    fn client_secret_plan(
        placement: CredentialPlacement,
        cache_seconds: u64,
        assumed: Option<u64>,
    ) -> TokenEndpointPlan {
        TokenEndpointPlan::client_secret(
            "https://token.example.invalid/token".to_owned(),
            secret("CLIENT_ID"),
            secret("CLIENT_SECRET"),
            placement,
            TokenRequestParameters::default(),
            Duration::from_secs(cache_seconds),
            assumed.map(Duration::from_secs),
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
        fn send(&self, request: &TokenRequest) -> Result<TokenWire, TransportFailure> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.url.clone());
            Ok(TokenWire {
                status: self.status,
                media_type: self.media_type.map(str::to_owned),
                body: self.body.as_bytes().to_vec(),
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
            ),
            Err(TokenFault::NoLifetime),
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
                parse_token_response(body, None, Some(Duration::from_secs(60))),
                Err(TokenFault::Invalid),
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
                parse_token_response(body, None, None),
                Err(TokenFault::Invalid),
                "{} must refuse",
                String::from_utf8_lossy(body)
            );
        }
        let long = format!(
            "{{\"access_token\":\"{}\",\"token_type\":\"Bearer\",\"expires_in\":60}}",
            "a".repeat(MAXIMUM_CREDENTIAL_BYTES + 1)
        );
        assert_eq!(
            parse_token_response(long.as_bytes(), None, None),
            Err(TokenFault::Invalid)
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
            ),
            Err(TokenFault::ScopeNarrowed)
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
            ),
            Err(TokenFault::Invalid)
        );
        let long = format!(
            "{{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"{}\"}}",
            "s".repeat(513)
        );
        assert_eq!(
            parse_token_response(long.as_bytes(), None, None),
            Err(TokenFault::Invalid)
        );
    }

    /// A body beyond the platform bound refuses, as does one that is
    /// not one JSON object.
    #[test]
    fn unreadable_bodies_refuse() {
        let oversized = vec![b' '; MAXIMUM_TOKEN_RESPONSE_BYTES as usize + 1];
        assert_eq!(
            parse_token_response(&oversized, None, None),
            Err(TokenFault::Protocol { status: 0 })
        );
        assert_eq!(
            parse_token_response(b"[]", None, None),
            Err(TokenFault::Protocol { status: 0 })
        );
        assert_eq!(
            parse_token_response(br#"{"a":1,"a":2}"#, None, None),
            Err(TokenFault::Protocol { status: 0 })
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

    /// A budget starts at two and refuses the third.
    #[test]
    fn budgets_hold_two_sends() {
        let mut budget = TokenBudget::new_exchange();
        assert_eq!(budget.remaining(), 2);
        budget.consume().expect("the first send is in budget");
        budget.consume().expect("the second send is in budget");
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.consume().unwrap_err(), AuthError::BudgetExhausted);
    }

    /// One acquisition, one cache hit: the second send under the same
    /// cache asks the endpoint nothing.
    #[test]
    fn the_cache_answers_the_second_send() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let cache = TokenCache::new();
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let first = acquire_token(
            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
            &cache,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .expect("the first acquisition issues");
        assert_eq!(first.as_bytes(), b"at");
        let second = acquire_token(
            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
            &cache,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .expect("the cache answers");
        assert_eq!(second.as_bytes(), b"at");
        assert_eq!(send.token_request_count(), 1);
        assert!(events.contains(&AuthEvent::TokenCacheHit));
        assert!(events.contains(&AuthEvent::TokenIssued));
    }

    /// A zero cache ceiling never caches: every acquisition sends.
    #[test]
    fn a_zero_ceiling_never_caches() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");
        let send = ScriptedSend::always(
            200,
            Some("application/json"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#,
        );
        let cache = TokenCache::new();
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let plan = client_secret_plan(CredentialPlacement::FormBody, 0, None);
        acquire_token(
            &plan,
            &cache,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .expect("the first acquisition issues");
        acquire_token(
            &plan,
            &cache,
            &mut budget,
            &resolver(),
            &send,
            &FixedSigner,
            &mut events,
        )
        .expect("the second acquisition sends again");
        assert_eq!(send.token_request_count(), 2);
    }

    /// A refused token endpoint surfaces the registered code name and
    /// nothing else; a redirect and a wrong media type are protocol
    /// failures that name only their status.
    #[test]
    fn refusals_surface_fixed_names() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");
        let refused = ScriptedSend::always(
            401,
            Some("application/json"),
            r#"{"error":"invalid_client","error_description":"server text about the credential"}"#,
        );
        let mut events = Vec::new();
        let error = acquire_token(
            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
            &TokenCache::new(),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &refused,
            &FixedSigner,
            &mut events,
        )
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
            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
            &TokenCache::new(),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &redirect,
            &FixedSigner,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(TokenFault::Protocol { status: 302 })
        );

        let html = ScriptedSend::always(
            200,
            Some("text/html"),
            r#"{"access_token":"at","token_type":"Bearer","expires_in":60}"#,
        );
        let error = acquire_token(
            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
            &TokenCache::new(),
            &mut TokenBudget::new_exchange(),
            &resolver(),
            &html,
            &FixedSigner,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(TokenFault::Protocol { status: 200 })
        );
    }

    /// Concurrent acquisitions over one cache make exactly one token
    /// request: the refresh is single-flight.
    #[test]
    fn acquisition_is_single_flight() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");
        struct SlowSend {
            in_flight: AtomicUsize,
            peak: AtomicUsize,
            requests: AtomicUsize,
        }
        impl TokenSend for SlowSend {
            fn send(&self, _request: &TokenRequest) -> Result<TokenWire, TransportFailure> {
                let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(current, Ordering::SeqCst);
                self.requests.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(60));
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(TokenWire {
                    status: 200,
                    media_type: Some("application/json".to_owned()),
                    body: br#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#
                        .to_vec(),
                })
            }
        }
        let send = SlowSend {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        };
        let cache = TokenCache::new();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        let mut budget = TokenBudget::new_exchange();
                        let mut events = Vec::new();
                        acquire_token(
                            &client_secret_plan(CredentialPlacement::BasicHeader, 3600, None),
                            &cache,
                            &mut budget,
                            &resolver(),
                            &send,
                            &FixedSigner,
                            &mut events,
                        )
                        .expect("every waiter acquires")
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("joined");
            }
        });
        assert_eq!(send.requests.load(Ordering::SeqCst), 1, "one token request");
        assert_eq!(send.peak.load(Ordering::SeqCst), 1, "no concurrent sends");
    }

    /// The private-key-jwt request carries the assertion in the form
    /// body, with the client id beside it, the fixed assertion type, and
    /// no Basic header; the key's text travels only inside the
    /// assertion.
    #[test]
    fn private_key_jwt_renders_its_assertion_in_the_body() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("ASSERTION_KEY", "key-pem");
        let url = "https://token.example.invalid/token";
        let plan = TokenEndpointPlan::private_key_jwt(
            url.to_owned(),
            secret("CLIENT_ID"),
            secret("ASSERTION_KEY"),
            url.to_owned(),
            TokenRequestParameters::default(),
            Duration::from_secs(3600),
            None,
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
            "grant_type=client_credentials&client_id=cid\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion=assertion.cid.https%3A%2F%2Ftoken.example.invalid%2Ftoken.key-pem"
        );
    }

    /// A rendered body beyond the bound refuses rather than sends.
    #[test]
    fn oversized_renders_refuse() {
        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("HUGE_CLIENT_SECRET", "k".repeat(20 * 1024));
        let plan = TokenEndpointPlan::client_secret(
            "https://token.example.invalid/token".to_owned(),
            secret("CLIENT_ID"),
            secret("HUGE_CLIENT_SECRET"),
            CredentialPlacement::FormBody,
            TokenRequestParameters::default(),
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(
            plan.render(&resolver(), &FixedSigner),
            Err(AuthError::Credential)
        );
    }
}
