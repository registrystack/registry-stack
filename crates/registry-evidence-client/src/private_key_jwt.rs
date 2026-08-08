//! Token acquisition with a signed client assertion.
//!
//! This is the OAuth 2.0 `client_credentials` grant with the `private_key_jwt`
//! client authentication method of RFC 7523 section 2.2: the client proves who it
//! is by signing a short-lived assertion with a key only it holds, so no shared
//! secret ever leaves the process or sits in a deployment's configuration.
//!
//! It is plain OAuth. Nothing here knows which authorization server it is talking
//! to, and the provider carries no claim, route, or vocabulary belonging to any
//! particular issuer. The request body carries only `grant_type`,
//! `client_assertion_type`, and `client_assertion`; a server that also requires a
//! scope, a resource indicator, or a body `client_id` on this grant needs support
//! this provider does not offer.
//!
//! # What is cached, and for how long
//!
//! An access token is reused until it has less life left than the refresh margin,
//! at which point the next caller acquires a replacement. The margin exists
//! because a credential that is valid when the request is built may have expired
//! by the time the deployment reads it. A server that states no lifetime has given
//! nothing to cache against, so each request acquires its own credential. The
//! deadline is measured against a reading that only moves forward, so correcting
//! the host clock cannot extend how long a credential is presented for.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use registry_platform_crypto::{PrivateJwk, SigningAlgorithm};
use registry_platform_httputil::read_bounded;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT},
    outbound::{
        self, base_url_without_userinfo, transport_protects_the_credential, OutboundOptions,
    },
    problem::essence,
    token::{BearerToken, OAuthErrorCode, TokenError, TokenProvider},
};

/// Lifetime of one client assertion, when the integrator states none.
///
/// The assertion is presented once, immediately, to one endpoint. Seconds are
/// enough, and a short window is what limits what a captured assertion is worth.
pub const DEFAULT_ASSERTION_LIFETIME_SECONDS: i64 = 60;

/// Longest assertion lifetime this provider will sign.
///
/// Authorization servers bound what they accept, and a request signed outside
/// that bound is refused with a code that says nothing about the reason.
pub const MAXIMUM_ASSERTION_LIFETIME_SECONDS: i64 = 300;

/// What the constructor signs to prove the client key can sign at all.
///
/// It carries a space and no `.`, so it cannot be read as the
/// `base64url(header).base64url(claims)` a client assertion is signed over. The
/// signature is discarded, and could not stand in for one even if it were not.
const CLIENT_KEY_PROBE: &[u8] = b"registry-evidence-client client key usability probe";

/// How much of an access token's remaining life is treated as already spent.
pub const DEFAULT_REFRESH_MARGIN_SECONDS: i64 = 30;

/// Longest an issuer's stated `expires_in` is trusted for, when deciding how
/// long to cache the credential it came with.
///
/// `expires_in` is a remote-controlled value. An authorization server that
/// reports one far longer than any real access token lives, whether by a bug
/// or by intent, must not be able to keep a credential cached, and therefore
/// live in memory, for the life of the process with no way for the integrator
/// to evict it. Re-acquiring a token earlier than an issuer's stated lifetime
/// requires is always safe, so clamping to 86400 seconds (24 hours) cannot
/// break a correct deployment.
pub const MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS: i64 = 86_400;
// Ties the doc comment above to the constant, so the two cannot drift apart.
const _: () = assert!(MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS == 86_400);

/// The grant this provider asks for. The client authenticates as itself, on its
/// own behalf, which is the only grant an Evidence relying party needs.
const GRANT_TYPE: &str = "client_credentials";

/// The client authentication method of RFC 7523 section 2.2.
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_MEDIA_TYPE: &str = "application/json";

/// The only token type an `Authorization: Bearer` request can present. Compared
/// without case, as RFC 6749 section 5.1 requires.
const BEARER_TOKEN_TYPE: &str = "bearer";

/// Longest token response this provider will read. A token response is a small
/// JSON object; anything larger is not one.
const MAXIMUM_TOKEN_RESPONSE_BYTES: u64 = 16 * 1024;

/// The two readings the provider reasons about.
///
/// They are separate because they answer different questions. An assertion claim
/// is a wall-clock time the authorization server checks against its own clock,
/// so nothing else will do there. A cache deadline is only ever compared against
/// a later reading of the same clock, and a wall-clock one would move whenever
/// the host clock is corrected. Both come from one source a test can drive,
/// rather than from readings of the host taken wherever they are needed.
pub(crate) trait Clock: Send + Sync {
    fn unix_seconds(&self) -> i64;

    /// A reading that only ever moves forward, however the host clock is set.
    fn monotonic(&self) -> Instant;
}

/// The host clock.
struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> i64 {
        Utc::now().timestamp()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// What an integrator decides before the provider can authenticate.
pub struct PrivateKeyJwtConfig {
    token_endpoint: Url,
    client_id: String,
    client_key: PrivateJwk,
    audience: Option<String>,
    assertion_lifetime_seconds: i64,
    refresh_margin_seconds: i64,
    request_timeout: Duration,
    connect_timeout: Duration,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
}

impl PrivateKeyJwtConfig {
    /// Authenticate as `client_id` at `token_endpoint`, signing with
    /// `client_key`.
    ///
    /// `client_key` may sign with EdDSA, ES256, or RS256, and must carry a key
    /// identifier: the identifier is how the authorization server selects the
    /// registered public key to check the assertion against. The assertion
    /// header names whichever of the three the key states, so the server needs
    /// that algorithm among the ones it accepts.
    #[must_use]
    pub fn new(token_endpoint: Url, client_id: impl Into<String>, client_key: PrivateJwk) -> Self {
        Self {
            token_endpoint,
            client_id: client_id.into(),
            client_key,
            audience: None,
            assertion_lifetime_seconds: DEFAULT_ASSERTION_LIFETIME_SECONDS,
            refresh_margin_seconds: DEFAULT_REFRESH_MARGIN_SECONDS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
        }
    }

    /// State the assertion audience the authorization server expects.
    ///
    /// The default is the token endpoint URL, which is what RFC 7523 section 3
    /// recommends. Set this only when the server published a different value: an
    /// assertion whose audience the server does not recognize is refused as an
    /// authentication failure, with no indication of which claim was wrong.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Must be within `1..=MAXIMUM_ASSERTION_LIFETIME_SECONDS`; an out-of-range
    /// value is refused when the provider is built rather than here.
    #[must_use]
    pub fn with_assertion_lifetime_seconds(mut self, seconds: i64) -> Self {
        self.assertion_lifetime_seconds = seconds;
        self
    }

    /// Treat this much of an access token's remaining life as already spent.
    ///
    /// Must not be negative; a negative value is refused when the provider is
    /// built rather than here.
    #[must_use]
    pub fn with_refresh_margin_seconds(mut self, seconds: i64) -> Self {
        self.refresh_margin_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Trust exactly these PEM-encoded certificate authorities for the token
    /// endpoint's TLS certificate, instead of the platform's own store.
    #[must_use]
    pub fn with_trusted_root_certificates(mut self, pem_bundle: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificates = Some(Zeroizing::new(pem_bundle.into()));
        self
    }
}

impl fmt::Debug for PrivateKeyJwtConfig {
    /// The client key and the pinned certificate material are withheld, as is any
    /// userinfo in the token endpoint. Only the operational choices and the public
    /// identifiers are rendered.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKeyJwtConfig")
            .field(
                "token_endpoint",
                &base_url_without_userinfo(&self.token_endpoint),
            )
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .field(
                "assertion_lifetime_seconds",
                &self.assertion_lifetime_seconds,
            )
            .field("refresh_margin_seconds", &self.refresh_margin_seconds)
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

/// An access token, and the monotonic instant it stops being worth presenting.
struct CachedToken {
    token: BearerToken,
    expires_at: Instant,
}

/// A [`TokenProvider`] that authenticates with a signed assertion and caches what
/// it is issued.
pub struct PrivateKeyJwt {
    http: reqwest::Client,
    token_endpoint: Url,
    client_id: String,
    audience: String,
    assertion_lifetime_seconds: i64,
    refresh_margin_seconds: i64,
    client_key: PrivateJwk,
    key_id: String,
    /// The JOSE name of what `client_key` signs with, resolved once at
    /// construction so the header cannot disagree with the key.
    algorithm: &'static str,
    clock: Arc<dyn Clock>,
    /// The credential in hand, if it is still worth presenting.
    cached: RwLock<Option<CachedToken>>,
    /// Held for the length of one token request, so concurrent callers wait for
    /// that request instead of opening one each.
    refresh_lock: Mutex<()>,
}

impl PrivateKeyJwt {
    /// Refuse a configuration that cannot authenticate, cannot protect its
    /// assertion in transit, or cannot produce an assertion the server it
    /// registered with can verify.
    ///
    /// Every one of these would otherwise fail once per request, as an
    /// authentication refusal whose code says nothing about which part was wrong.
    pub fn new(config: PrivateKeyJwtConfig) -> Result<Self, TokenError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    pub(crate) fn with_clock(
        config: PrivateKeyJwtConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TokenError> {
        let refuse = |reason: &'static str| TokenError::Configuration { reason };

        if config.client_id.trim().is_empty() {
            return Err(refuse("the client identifier must not be empty"));
        }
        if !config.token_endpoint.username().is_empty()
            || config.token_endpoint.password().is_some()
            || config.token_endpoint.fragment().is_some()
        {
            return Err(refuse(
                "the token endpoint must carry no credentials or fragment",
            ));
        }
        // The assertion authenticates the client, so it is as sensitive in transit
        // as the access token it is exchanged for, and the same transport rule
        // applies to both.
        if !transport_protects_the_credential(&config.token_endpoint) {
            return Err(refuse(
                "the token endpoint must use HTTPS, or HTTP with a loopback host",
            ));
        }
        // The header names the algorithm so the server can verify without
        // guessing, which means it must state what this key actually signs with
        // rather than one fixed name. Restricting the client to a single
        // algorithm would refuse keys a conforming authorization server accepts:
        // `token_endpoint_auth_signing_alg_values_supported` is the server's
        // choice to publish, not this client's to narrow. Parsing a `PrivateJwk`
        // already refuses anything outside these three, so the last arm is a
        // floor rather than a path a caller can reach.
        let algorithm = match config.client_key.algorithm() {
            Ok(SigningAlgorithm::EdDsa) => "EdDSA",
            Ok(SigningAlgorithm::Es256) => "ES256",
            Ok(SigningAlgorithm::Rs256) => "RS256",
            Err(_) => {
                return Err(refuse(
                    "the client key must state a supported signing algorithm",
                ))
            }
        };
        let key_id = config
            .client_key
            .kid
            .clone()
            .filter(|kid| !kid.trim().is_empty())
            .ok_or_else(|| refuse("the client key must carry a key identifier"))?;
        // Stating an algorithm is not the same as being able to sign with it. A
        // P-256 scalar of zero and an RSA key whose components disagree are both
        // well-formed enough to parse, and are rejected only where the key is
        // imported, which is at signing time. Signing once here keeps the promise
        // this constructor makes: a key that cannot sign is refused now rather
        // than once per request, as an authentication failure that names nothing.
        // EdDSA never reaches this, since every 32-byte string is a valid Ed25519
        // seed, which is why signing with EdDSA alone hid the gap.
        //
        // The probe is deliberately not shaped like a JWS signing input, so the
        // signature it discards could not be presented as a client assertion.
        let probe = registry_platform_crypto::sign(CLIENT_KEY_PROBE, &config.client_key)
            .map_err(|_| refuse("the client key cannot sign a client assertion"))?;
        // Signing reads only the private half, so a JWK carrying one pair's `d`
        // beside another pair's public fields signs perfectly well and produces
        // assertions no server can verify: the public half an adopter registers
        // is derived from those fields. Nothing downstream would catch it, since
        // the server sees a valid signature over a key it was never given.
        // Verifying the probe against this key's own public half is what proves
        // the two belong together.
        registry_platform_crypto::verify(CLIENT_KEY_PROBE, &probe, &config.client_key.public())
            .map_err(|_| refuse("the client key's halves belong to different key pairs"))?;
        // Ties the message below to the constant, so the constant cannot drift
        // from the number the message states.
        const _: () = assert!(MAXIMUM_ASSERTION_LIFETIME_SECONDS == 300);
        if !(1..=MAXIMUM_ASSERTION_LIFETIME_SECONDS).contains(&config.assertion_lifetime_seconds) {
            return Err(refuse(
                "the assertion lifetime must be within 1..=300 seconds",
            ));
        }
        if config.refresh_margin_seconds < 0 {
            return Err(refuse("the refresh margin must not be negative"));
        }
        if config.request_timeout.is_zero() || config.connect_timeout.is_zero() {
            return Err(refuse("the timeouts must be greater than zero"));
        }

        let http = outbound::build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_ref()
                .map(|pem| pem.as_slice()),
        })
        .map_err(refuse)?;

        Ok(Self {
            http,
            audience: config
                .audience
                .unwrap_or_else(|| config.token_endpoint.as_str().to_owned()),
            token_endpoint: config.token_endpoint,
            client_id: config.client_id,
            assertion_lifetime_seconds: config.assertion_lifetime_seconds,
            refresh_margin_seconds: config.refresh_margin_seconds,
            client_key: config.client_key,
            key_id,
            algorithm,
            clock,
            cached: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        })
    }

    /// The cached credential, if it has more life left than the refresh margin.
    ///
    /// The deadline and `monotonic_now` are both readings of a clock that only
    /// moves forward, so a host clock stepping backward cannot present a spent
    /// credential as a fresh one.
    async fn usable_cached_token(&self, monotonic_now: Instant) -> Option<BearerToken> {
        // A negative margin was refused at construction, so this is the margin
        // the integrator configured.
        let margin = Duration::from_secs(self.refresh_margin_seconds.unsigned_abs());
        let cached = self.cached.read().await;
        cached
            .as_ref()
            .filter(|entry| entry.expires_at.saturating_duration_since(monotonic_now) > margin)
            .map(|entry| entry.token.clone())
    }

    /// One client assertion, valid from `now` for the configured lifetime.
    fn sign_assertion(&self, now: i64) -> Result<Zeroizing<String>, TokenError> {
        let header = json!({
            "alg": self.algorithm,
            "typ": "JWT",
            // The server selects the registered public key by this identifier.
            "kid": self.key_id,
        });
        let claims = json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "iat": now,
            "exp": now.saturating_add(self.assertion_lifetime_seconds),
            // Every assertion is single use. A server that caches identifiers to
            // refuse a replay needs each request to bring its own, so one is
            // generated per request and never reused.
            "jti": Ulid::new().to_string(),
        });

        let encode = |value: &Value| -> Result<String, TokenError> {
            serde_json::to_vec(value)
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
                .map_err(|_| TokenError::Configuration {
                    reason: "the client assertion cannot be serialized",
                })
        };
        let signing_input = format!("{}.{}", encode(&header)?, encode(&claims)?);
        // The algorithm was resolved at construction, so this reports a key that
        // parsed and named an algorithm yet cannot sign with it. It stays an
        // explicit failure rather than a retry, because no later request would
        // sign either.
        let signature = registry_platform_crypto::sign(signing_input.as_bytes(), &self.client_key)
            .map_err(|_| TokenError::Configuration {
                reason: "the client key cannot sign a client assertion",
            })?;
        Ok(Zeroizing::new(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }

    /// Exchange one fresh assertion for an access token.
    ///
    /// `now` dates the assertion the authorization server validates, and
    /// `monotonic_now` is what the cache deadline of whatever it issues is
    /// measured from.
    async fn acquire(&self, now: i64, monotonic_now: Instant) -> Result<AcquiredToken, TokenError> {
        let assertion = self.sign_assertion(now)?;
        // The assertion is a credential, so it lives in a scrubbed buffer here.
        // The body reqwest owns afterwards cannot be wiped, which is why the
        // assertion is single use and its lifetime is bounded.
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", GRANT_TYPE)
                .append_pair("client_assertion_type", CLIENT_ASSERTION_TYPE)
                .append_pair("client_assertion", &assertion)
                .finish(),
        );

        let response = self
            .http
            .post(self.token_endpoint.clone())
            .header(CONTENT_TYPE, FORM_MEDIA_TYPE)
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .body(body.as_str().to_owned())
            .send()
            .await
            .map_err(|error| TokenError::Transport {
                kind: outbound::send_failure_kind(&error),
            })?;

        let status = response.status().as_u16();
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = match read_bounded(response, MAXIMUM_TOKEN_RESPONSE_BYTES).await {
            // The response carries a credential, so the buffer it was read into is
            // wiped when this exchange ends.
            Ok(body) => Zeroizing::new(body),
            // The status arrived before the body did, and for a refusal it is the
            // whole of what this crate would have reported anyway.
            Err(_) if !(200..300).contains(&status) => return Err(TokenError::Protocol { status }),
            Err(error) => {
                return Err(TokenError::Transport {
                    kind: outbound::read_failure_kind(&error),
                })
            }
        };

        if !(200..300).contains(&status) {
            return Err(declined(status, media_type.as_deref(), &body));
        }
        if status != 200
            || !media_type
                .as_deref()
                .is_some_and(|value| essence(value).eq_ignore_ascii_case(JSON_MEDIA_TYPE))
        {
            return Err(TokenError::Protocol { status });
        }
        let Ok(issued) = serde_json::from_slice::<IssuedToken>(&body) else {
            return Err(TokenError::Protocol { status });
        };
        if !issued.token_type.eq_ignore_ascii_case(BEARER_TOKEN_TYPE) {
            return Err(TokenError::Protocol { status });
        }
        Ok(AcquiredToken {
            // Moved rather than copied, so the credential ends up in the buffer
            // `BearerToken` wipes on drop.
            token: BearerToken::new(issued.access_token)?,
            // A stated lifetime is what makes caching possible. Without one, or
            // with one already elapsed, the credential is used once and dropped.
            // A lifetime longer than this provider will trust is clamped before
            // it ever reaches the cache arithmetic below.
            expires_at: issued
                .expires_in
                .filter(|seconds| *seconds > 0)
                .map(|seconds| seconds.min(MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS))
                // What reaches this point is within
                // 1..=MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS, so the deadline is
                // an instant at most a day ahead of the reading it is built on.
                .map(|seconds| monotonic_now + Duration::from_secs(seconds.unsigned_abs())),
        })
    }
}

#[async_trait]
impl TokenProvider for PrivateKeyJwt {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        if let Some(token) = self.usable_cached_token(self.clock.monotonic()).await {
            return Ok(token);
        }
        // The refresh lock serializes acquisition: one caller holds it and
        // performs a token request while the rest wait their turn for it. The
        // freshness check below spares a waiter its own request only when the
        // caller ahead of it cached something; a credential that could not be
        // cached, or a failed request, sends the next waiter to acquire its own
        // in turn. A wait is therefore bounded by the number of callers ahead of
        // it times the configured request timeout, not by that timeout alone.
        let _refreshing = self.refresh_lock.lock().await;
        let now = self.clock.unix_seconds();
        let monotonic_now = self.clock.monotonic();
        if let Some(token) = self.usable_cached_token(monotonic_now).await {
            return Ok(token);
        }

        let acquired = self.acquire(now, monotonic_now).await?;
        let mut cached = self.cached.write().await;
        // An uncacheable credential clears the cache rather than leaving a stale
        // entry behind it.
        *cached = acquired.expires_at.map(|expires_at| CachedToken {
            token: acquired.token.clone(),
            expires_at,
        });
        Ok(acquired.token)
    }
}

impl fmt::Debug for PrivateKeyJwt {
    /// The client key and the cached credential are withheld. What is rendered is
    /// what an operator needs to recognize which provider this is.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKeyJwt")
            .field("token_endpoint", &self.token_endpoint.as_str())
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .field(
                "assertion_lifetime_seconds",
                &self.assertion_lifetime_seconds,
            )
            .field("refresh_margin_seconds", &self.refresh_margin_seconds)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// A credential and what may be assumed about how long it lasts.
struct AcquiredToken {
    token: BearerToken,
    expires_at: Option<Instant>,
}

/// The success response of RFC 6749 section 5.1, in the members this client uses.
#[derive(Deserialize)]
struct IssuedToken {
    access_token: String,
    token_type: String,
    expires_in: Option<i64>,
}

/// The error response of RFC 6749 section 5.2.
///
/// Only the code is read. `error_description` and `error_uri` are server-authored
/// text about a failed authentication attempt, so they stay in the buffer this
/// exchange is about to drop.
#[derive(Deserialize)]
struct DeclinedToken {
    error: String,
}

/// Map a refused token request onto the code it reported.
///
/// RFC 6749 section 5.2 puts a decision about the client at 400, and an
/// authentication failure at 401. Any other status is the server reporting
/// something about itself, which is not a statement this client can act on as a
/// refusal. A body is read as a refusal only when it arrives in the media type
/// the request asked for; an intermediary answering in some other media type,
/// or none at all, never reached the authorization server's own refusal logic,
/// so it is reported as a protocol failure instead.
fn declined(status: u16, media_type: Option<&str>, body: &[u8]) -> TokenError {
    if !matches!(status, 400 | 401)
        || !media_type.is_some_and(|value| essence(value).eq_ignore_ascii_case(JSON_MEDIA_TYPE))
    {
        return TokenError::Protocol { status };
    }
    match serde_json::from_slice::<DeclinedToken>(body) {
        Ok(declined) => TokenError::Refused {
            code: OAuthErrorCode::from_wire(&declined.error),
        },
        Err(_) => TokenError::Protocol { status },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicI64, AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    use registry_platform_crypto::{verify, PrivateJwk, PublicJwk};
    use serde_json::{json, Value};
    use url::Url;
    use wiremock::{
        matchers::{body_string_contains, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::{
        error::TransportKind,
        token::{OAuthErrorCode, TokenError, TokenProvider},
    };

    /// The instant the offline assertions in this module are centered on.
    const NOW: i64 = 1_785_000_000;
    const CLIENT_ID: &str = "urn:example:client:relying-party";
    const KEY_ID: &str = "client-key-2026-01";
    const TOKEN_PATH: &str = "/token";
    /// A credential text no server in this module ever varies, so a test can
    /// assert on which credential a caller received.
    const ISSUED_CREDENTIAL: &str = "issued-access-token";
    const TOKEN_LIFETIME_SECONDS: i64 = 300;

    /// A clock a test moves by hand, so cache arithmetic is asserted rather than
    /// waited out.
    ///
    /// Both readings move together under [`TestClock::set`], as they do on a host
    /// whose clock nothing is correcting. A test that needs them to disagree,
    /// which is what a correction looks like, moves the wall reading on its own.
    struct TestClock {
        unix_seconds: AtomicI64,
        unix_origin: i64,
        monotonic_origin: Instant,
        monotonic_elapsed_seconds: AtomicU64,
    }

    impl TestClock {
        fn new(now: i64) -> Self {
            Self {
                unix_seconds: AtomicI64::new(now),
                unix_origin: now,
                monotonic_origin: Instant::now(),
                monotonic_elapsed_seconds: AtomicU64::new(0),
            }
        }

        /// Both readings are now at `now`, which is what time passing looks like.
        fn set(&self, now: i64) {
            self.unix_seconds.store(now, Ordering::Relaxed);
            let elapsed = u64::try_from(now - self.unix_origin)
                .expect("a test moves this clock forward from where it started");
            self.monotonic_elapsed_seconds
                .store(elapsed, Ordering::Relaxed);
        }

        /// Move the wall reading back, leaving the monotonic reading where it is.
        /// That is what an NTP correction, a virtual machine resume, or an
        /// operator setting the clock by hand does to a running process.
        fn step_wall_clock_backward(&self, seconds: i64) {
            self.unix_seconds.fetch_sub(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn unix_seconds(&self) -> i64 {
            self.unix_seconds.load(Ordering::Relaxed)
        }

        fn monotonic(&self) -> Instant {
            self.monotonic_origin
                + Duration::from_secs(self.monotonic_elapsed_seconds.load(Ordering::Relaxed))
        }
    }

    /// A fresh EdDSA client key, generated here so no test carries key material
    /// in the tree.
    fn client_key(key_id: Option<&str>) -> PrivateJwk {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the test host supplies randomness");
        let key = SigningKey::from_bytes(&seed);
        let mut document = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        });
        if let Some(key_id) = key_id {
            document["kid"] = json!(key_id);
        }
        PrivateJwk::parse(&document.to_string()).expect("the test key parses")
    }

    /// A fresh ES256 client key, in the shape `evidencectl access client add
    /// --generate-local-key` writes, which is what an adopter following the
    /// tutorial actually holds.
    fn es256_client_key(key_id: Option<&str>) -> PrivateJwk {
        let key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let mut document = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("an uncompressed P-256 point has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("an uncompressed P-256 point has y")),
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        });
        if let Some(key_id) = key_id {
            document["kid"] = json!(key_id);
        }
        PrivateJwk::parse(&document.to_string()).expect("the test key parses")
    }

    /// A test-only 2048-bit RSA client key. RSA keys are too slow to generate per
    /// test and the workspace carries no RSA generator, so unlike the EdDSA and
    /// ES256 keys above this one is a constant. It is the same test-only key
    /// `registry-platform-crypto` already pins for its RS256 tests, so it puts no
    /// new key material in the tree. It authenticates nothing.
    const RSA_CLIENT_JWK: &str = r#"{"kty":"RSA","kid":"registry-evidence-client-rs256-test","alg":"RS256","n":"yIgEn3IXWI3CRyUY0gvZ-kJ55EC36MRFvj-ICsitN1-50phRS4CKMBRwbHwjgeTkbMDndOCmVfIbyKhJjOMIPxAzIHeMn9oWj5i-s8nlSgjHZpvCTnRbwZhbq6mEVoHJliX36IfV_iUopcwSL5lPd2wZmJ-msUmZFs6CTRExu0JGUJScOwFO5dqxBwiKyh7yGEPXI3u4tc3_47SZYxyde7fb-o3wl2RBJ28upa2jVRP9r-WjOGjE6tbZ35HnVUY4ECdYWzsiotg_XA9QVWa-pAKXV2Flr-gocCQ9E2qrSYjEbNXuFjPtMnuL6AHi0o5PiwT1dllcl925hpKd7Xt60w","e":"AQAB","d":"ATDtMhpe_z1-GTUV7NLO3V_Z0kb8W1YXkC7JbJTAdcE-FdKJrtu84Q87WpxG0tPcutFPLqW12QAQp2fbmxhZ6VrfVYneeOlEjO14ukqM_g35Z-eRDmYhwoFYrEWGqlH9XrZysHhKFZyKHW_G0lJV-Ks8Na_RFNNIXeVedVMQiytAFXibTHvdAdIrBGtt0M4tlQOCeRwnuoAQU-a5VB7rKGpxnJtUA7F_jjeX6jQPnUhkOXs20pPRey-i-jxwBbsF4XijHgTnGwAo5uOoY9b0kOmOb3Hs5TVqZCb3a4JoYAqZBbWrkKxccJTGMqLHCe0MBgQzKqP5KyrHRgQdzlmTnQ","p":"5xhkHe5lD7tUYJAFffHiRpy4unHfKDvTEASu8RBgWvHP2Hu5XLQU5n6DvI47LsW42swTcT6Ce1pWB2LK3SjKcw9FPEEGg8m5-tmfixaRq4DBaK0hj17763HmnYR0eQC0n_5y-My8WSC1y80T-AhKHJ_3xTtLXQd5Z9bf9MEiKS8","q":"3iRoiwbnn8oRJMjZUZhqKB-GVa7AJV0SUqXiUsBAJnqtbhuIESbkJKpt5eULeUQgdNkoG65KD-jXFUipWX1zlentc1FliCaB46jntqtxUsui8LNwKw_eb3nujQO7H1He4NJ5pfaLfRcmBOLwB-u2Z1cxrRDWhIgiHtGaAdQ7F50","dp":"j4h9vn1wNbozaRpq3tPap-L1dY_-e93UdPGDuuRiBHqGjr4h3itXg-X2aqmopp9V9kekl8SshHMSVdoNiBmqzJYieY8lvbsQkXaTem8VIQGCn0JRQtxK-eyvwQwgz3sZtPn0bQW0wmLnp2KD0Z1McsUEvnLalzhqNo2mYj2Guy8","dq":"0T6ySuLCIz2PUHrwWW-b7xdizirBS3CT5c3jldcJljVQT7sXPDDKDc-LnVVWrW-Csw4qPYi6sqm8j4vWGTmWOswSouE1Jj4_c1aSjPqI0FiIrvoW2jkkaRUNoz60cBgKPPOFKtNFKRs48LljJ9LcChOT81U8-7HPkgAVdUuYLfE","qi":"PnMeCE0dvWDLp2Dn1wsxtl-a0qjpkT9cp8EkvHYjCvVqqWqrVv84CoEo-1wA9j_VDvCG6T4n0UO9K0jfBf5yvPnahSQCLJk2nw-2uZ9YzBZKwkm21wU6hTknPst5Vk5ZbYJmzqXsCqEB5T2Bn5vqeXMe3SOB5hD2CbTFFfp3TC4"}"#;

    fn rs256_client_key() -> PrivateJwk {
        PrivateJwk::parse(RSA_CLIENT_JWK).expect("the test key parses")
    }

    /// An ES256 key that parses and states its algorithm, yet cannot sign: zero
    /// is a well-formed 32-byte scalar and an invalid P-256 private key.
    ///
    /// There is no EdDSA counterpart, because every 32-byte string is a valid
    /// Ed25519 seed. That asymmetry is why signing with EdDSA alone never
    /// exposed the gap this case covers.
    fn unsignable_es256_client_key() -> PrivateJwk {
        let mut key = es256_client_key(Some(KEY_ID));
        key.d = Some(URL_SAFE_NO_PAD.encode([0u8; 32]));
        key
    }

    /// An RS256 key that parses and states its algorithm, yet cannot sign: each
    /// component is well-formed on its own, but `p` no longer divides `n`.
    fn unsignable_rs256_client_key() -> PrivateJwk {
        let mut key = rs256_client_key();
        key.p = key.q.clone();
        key
    }

    /// An EdDSA key whose two halves belong to different key pairs. It signs,
    /// and nothing it signs verifies against the public half an adopter would
    /// register from this same document.
    fn mismatched_eddsa_client_key() -> PrivateJwk {
        let mut key = client_key(Some(KEY_ID));
        key.x = client_key(None).x.clone();
        key
    }

    /// The ES256 counterpart: `d` from one pair, `x` and `y` from another.
    fn mismatched_es256_client_key() -> PrivateJwk {
        let mut key = es256_client_key(Some(KEY_ID));
        let other = es256_client_key(None);
        key.x = other.x.clone();
        key.y = other.y.clone();
        key
    }

    fn endpoint(base: &str) -> Url {
        format!("{base}{TOKEN_PATH}")
            .parse()
            .expect("the token endpoint parses")
    }

    fn config(token_endpoint: Url, client_key: PrivateJwk) -> PrivateKeyJwtConfig {
        PrivateKeyJwtConfig::new(token_endpoint, CLIENT_ID, client_key)
    }

    /// A provider on a test clock, against a token endpoint that answers with one
    /// credential.
    fn provider(token_endpoint: Url, clock: &Arc<TestClock>) -> PrivateKeyJwt {
        PrivateKeyJwt::with_clock(
            config(token_endpoint, client_key(Some(KEY_ID))),
            clock.clone(),
        )
        .expect("the provider is usable as configured")
    }

    /// The token response a compliant authorization server returns.
    fn issued(expires_in: Option<i64>) -> ResponseTemplate {
        let mut body = json!({
            "access_token": ISSUED_CREDENTIAL,
            "token_type": "Bearer",
        });
        if let Some(expires_in) = expires_in {
            body["expires_in"] = json!(expires_in);
        }
        ResponseTemplate::new(200).set_body_json(body)
    }

    async fn token_endpoint_serving(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn token_requests(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("the mock server records its requests")
            .len()
    }

    fn parts(assertion: &str) -> (Value, Value, Vec<u8>) {
        let segments: Vec<&str> = assertion.split('.').collect();
        assert_eq!(segments.len(), 3, "an assertion carries three segments");
        let decode = |segment: &str| {
            let bytes = URL_SAFE_NO_PAD
                .decode(segment)
                .expect("the segment is base64url");
            serde_json::from_slice::<Value>(&bytes).expect("the segment carries JSON")
        };
        let signature = URL_SAFE_NO_PAD
            .decode(segments[2])
            .expect("the signature is base64url");
        (decode(segments[0]), decode(segments[1]), signature)
    }

    fn signing_input(assertion: &str) -> &str {
        let boundary = assertion
            .rfind('.')
            .expect("an assertion carries three segments");
        &assertion[..boundary]
    }

    /// RFC 7523 section 2.2 fixes the claim set the token endpoint reads. The
    /// header names the key so the server can select it without guessing.
    #[test]
    fn an_assertion_carries_the_claims_the_token_endpoint_requires() {
        let key = client_key(Some(KEY_ID));
        let public: PublicJwk = key.public();
        let secret = key
            .d
            .clone()
            .expect("the test key carries private material");
        let token_endpoint = endpoint("https://tokens.example.org");
        let clock = Arc::new(TestClock::new(NOW));
        let provider =
            PrivateKeyJwt::with_clock(config(token_endpoint.clone(), key), clock.clone())
                .expect("the provider is usable as configured");

        let assertion = provider
            .sign_assertion(NOW)
            .expect("the assertion is signed");
        let (header, claims, signature) = parts(&assertion);

        assert_eq!(header, json!({"alg": "EdDSA", "typ": "JWT", "kid": KEY_ID}));
        assert_eq!(claims["iss"], json!(CLIENT_ID));
        assert_eq!(claims["sub"], json!(CLIENT_ID));
        assert_eq!(claims["aud"], json!(token_endpoint.as_str()));
        assert_eq!(claims["iat"], json!(NOW));
        assert_eq!(
            claims["exp"],
            json!(NOW + DEFAULT_ASSERTION_LIFETIME_SECONDS)
        );
        assert_eq!(
            claims["jti"]
                .as_str()
                .expect("the assertion carries a jti")
                .len(),
            26,
            "the jti is a ULID"
        );
        let members: std::collections::BTreeSet<&str> = claims
            .as_object()
            .expect("the claims are an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            ["aud", "exp", "iat", "iss", "jti", "sub"]
                .into_iter()
                .collect(),
            "the assertion carries exactly the claims the profile fixes"
        );
        verify(signing_input(&assertion).as_bytes(), &signature, &public)
            .expect("the assertion verifies under the client key");
        assert!(
            !assertion.contains(&secret),
            "the assertion carries the private key"
        );
    }

    /// The header must name the algorithm the key actually signs with, for every
    /// algorithm the stack registers. A server selects the verification algorithm
    /// from this header, so a fixed `alg` would either refuse the key outright or
    /// present a signature under a name that does not describe it.
    ///
    /// ES256 is the case an adopter meets first: it is what `evidencectl` writes
    /// for a locally generated client key.
    #[test]
    fn an_assertion_names_the_algorithm_the_client_key_states() {
        for (expected_alg, key) in [
            ("EdDSA", client_key(Some(KEY_ID))),
            ("ES256", es256_client_key(Some(KEY_ID))),
            ("RS256", rs256_client_key()),
        ] {
            let key_id = key.kid.clone().expect("the test key carries a kid");
            let public: PublicJwk = key.public();
            let clock = Arc::new(TestClock::new(NOW));
            let provider = PrivateKeyJwt::with_clock(
                config(endpoint("https://tokens.example.org"), key),
                clock,
            )
            .unwrap_or_else(|error| {
                panic!("a {expected_alg} client key is usable as configured: {error}")
            });

            let assertion = provider
                .sign_assertion(NOW)
                .unwrap_or_else(|error| panic!("the {expected_alg} assertion is signed: {error}"));
            let (header, _, signature) = parts(&assertion);

            assert_eq!(
                header,
                json!({"alg": expected_alg, "typ": "JWT", "kid": key_id})
            );
            verify(signing_input(&assertion).as_bytes(), &signature, &public).unwrap_or_else(
                |error| {
                    panic!("the {expected_alg} assertion verifies under the client key: {error}")
                },
            );
        }
    }

    /// A replay-checking token endpoint refuses a repeated `jti`, so a fresh one
    /// per request is what makes a second token request possible at all.
    #[test]
    fn every_assertion_gets_its_own_jti() {
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint("https://tokens.example.org"), &clock);

        let first = provider
            .sign_assertion(NOW)
            .expect("the assertion is signed");
        let second = provider
            .sign_assertion(NOW)
            .expect("the assertion is signed");

        let (_, first_claims, _) = parts(&first);
        let (_, second_claims, _) = parts(&second);
        assert_ne!(first_claims["jti"], second_claims["jti"]);
        assert_eq!(first_claims["iat"], second_claims["iat"]);
    }

    /// A deployment whose token endpoint expects an audience of its own name says
    /// so, and the default is the endpoint URL.
    #[test]
    fn the_assertion_audience_can_be_overridden() {
        let clock = Arc::new(TestClock::new(NOW));
        let provider = PrivateKeyJwt::with_clock(
            config(
                endpoint("https://tokens.example.org"),
                client_key(Some(KEY_ID)),
            )
            .with_audience("https://tokens.example.org/"),
            clock.clone(),
        )
        .expect("the provider is usable as configured");

        let assertion = provider
            .sign_assertion(NOW)
            .expect("the assertion is signed");
        let (_, claims, _) = parts(&assertion);
        assert_eq!(claims["aud"], json!("https://tokens.example.org/"));
    }

    /// The request the token endpoint receives is the form-encoded grant the
    /// profile fixes, and it carries the assertion rather than a secret.
    #[tokio::test]
    async fn the_token_request_states_the_grant_and_the_authentication_method() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(header("accept", "application/json"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("client_assertion="))
            .respond_with(issued(Some(TOKEN_LIFETIME_SECONDS)))
            .mount(&server)
            .await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint(&server.uri()), &clock);

        let token = provider
            .bearer_token()
            .await
            .expect("the token endpoint issued a credential");

        assert_eq!(token.expose(), ISSUED_CREDENTIAL);
        assert_eq!(token_requests(&server).await, 1);
    }

    /// A credential is reused while it has more life left than the refresh margin,
    /// and a caller arriving inside the margin gets a fresh one instead of a
    /// credential that may expire in flight.
    #[tokio::test]
    async fn a_cached_credential_is_reused_until_the_refresh_margin() {
        let server = token_endpoint_serving(issued(Some(TOKEN_LIFETIME_SECONDS))).await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint(&server.uri()), &clock);

        provider.bearer_token().await.expect("a first credential");
        assert_eq!(token_requests(&server).await, 1);

        // Well inside the cached lifetime.
        clock.set(NOW + TOKEN_LIFETIME_SECONDS - DEFAULT_REFRESH_MARGIN_SECONDS - 1);
        provider
            .bearer_token()
            .await
            .expect("the cached credential");
        assert_eq!(
            token_requests(&server).await,
            1,
            "a usable cached credential was discarded"
        );

        // The first instant inside the refresh margin.
        clock.set(NOW + TOKEN_LIFETIME_SECONDS - DEFAULT_REFRESH_MARGIN_SECONDS);
        provider
            .bearer_token()
            .await
            .expect("a replacement credential");
        assert_eq!(
            token_requests(&server).await,
            2,
            "a credential inside the refresh margin was reused"
        );
    }

    /// A host clock steps backward for ordinary reasons: an NTP correction, a
    /// virtual machine resuming, an operator setting it by hand. A credential
    /// whose deadline was a wall-clock time would look fresh again for as long as
    /// the step was wide, and the provider would keep presenting a credential the
    /// authorization server has already expired.
    #[tokio::test]
    async fn a_cached_credential_is_not_reused_after_the_host_clock_steps_backward() {
        let server = token_endpoint_serving(issued(Some(TOKEN_LIFETIME_SECONDS))).await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint(&server.uri()), &clock);

        provider.bearer_token().await.expect("a first credential");
        assert_eq!(token_requests(&server).await, 1);

        // The whole stated lifetime really elapsed, so the credential is spent.
        clock.set(NOW + TOKEN_LIFETIME_SECONDS);
        // Then the host clock is corrected far enough backward that its reading
        // is before the credential was issued at all.
        clock.step_wall_clock_backward(TOKEN_LIFETIME_SECONDS * 2);
        assert!(
            clock.unix_seconds() < NOW,
            "the correction lands before the credential was issued"
        );

        provider
            .bearer_token()
            .await
            .expect("a replacement credential");
        assert_eq!(
            token_requests(&server).await,
            2,
            "a spent credential was replayed after the host clock stepped backward"
        );
    }

    /// A stated lifetime the issuer never bounded, such as `i64::MAX`, must not
    /// keep a credential cached for the life of the process. The provider clamps
    /// it to its own configured maximum before caching.
    #[tokio::test]
    async fn an_unbounded_stated_lifetime_is_clamped_to_the_configured_maximum() {
        let server = token_endpoint_serving(issued(Some(i64::MAX))).await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint(&server.uri()), &clock);

        provider.bearer_token().await.expect("a first credential");
        assert_eq!(token_requests(&server).await, 1);

        // Well inside the clamped lifetime, despite the issuer stating an
        // effectively unbounded one.
        clock.set(NOW + MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS - DEFAULT_REFRESH_MARGIN_SECONDS - 1);
        provider
            .bearer_token()
            .await
            .expect("the cached credential");
        assert_eq!(
            token_requests(&server).await,
            1,
            "a usable cached credential was discarded"
        );

        // The first instant inside the refresh margin of the clamped lifetime.
        clock.set(NOW + MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS - DEFAULT_REFRESH_MARGIN_SECONDS);
        provider
            .bearer_token()
            .await
            .expect("a replacement credential");
        assert_eq!(
            token_requests(&server).await,
            2,
            "an unbounded stated lifetime was cached past the configured maximum"
        );
    }

    /// A server that states no lifetime, or one that is already zero or
    /// negative, has told the client nothing it may cache against, so every
    /// request acquires its own credential rather than writing an unusable one
    /// into the cache.
    #[tokio::test]
    async fn a_credential_without_a_stated_lifetime_is_not_cached() {
        for expires_in in [None, Some(0), Some(-1)] {
            let server = token_endpoint_serving(issued(expires_in)).await;
            let clock = Arc::new(TestClock::new(NOW));
            let provider = provider(endpoint(&server.uri()), &clock);

            provider.bearer_token().await.expect("a first credential");
            provider.bearer_token().await.expect("a second credential");

            assert_eq!(
                token_requests(&server).await,
                2,
                "expires_in {expires_in:?} was cached"
            );
        }
    }

    /// Many callers starting at once must not each open a token request. The
    /// first one performs it and the rest use what it cached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_make_one_token_request() {
        let server = token_endpoint_serving(
            issued(Some(TOKEN_LIFETIME_SECONDS)).set_delay(Duration::from_millis(50)),
        )
        .await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = Arc::new(provider(endpoint(&server.uri()), &clock));

        let callers: Vec<_> = (0..20)
            .map(|_| {
                let provider = provider.clone();
                tokio::spawn(async move { provider.bearer_token().await })
            })
            .collect();
        for caller in callers {
            let token = caller
                .await
                .expect("the caller task ran")
                .expect("every caller received a credential");
            assert_eq!(token.expose(), ISSUED_CREDENTIAL);
        }

        assert_eq!(
            token_requests(&server).await,
            1,
            "concurrent callers stampeded the token endpoint"
        );
    }

    /// Tokio's asynchronous mutex is not poisoned when a guard is dropped
    /// mid-await, unlike `std::sync::Mutex`. A caller abandoned while it holds
    /// the refresh lock, whether by cancellation or a panic elsewhere in the
    /// same task, must still let the next caller acquire the lock and receive
    /// a credential rather than waiting on a lock nothing will ever release.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_acquisition_releases_the_refresh_lock_for_the_next_caller() {
        let server = token_endpoint_serving(
            issued(Some(TOKEN_LIFETIME_SECONDS)).set_delay(Duration::from_millis(200)),
        )
        .await;
        let clock = Arc::new(TestClock::new(NOW));
        let provider = Arc::new(provider(endpoint(&server.uri()), &clock));

        let abandoned = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.bearer_token().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        abandoned.abort();
        let _ = abandoned.await;

        let token = tokio::time::timeout(Duration::from_secs(2), provider.bearer_token())
            .await
            .expect("the refresh lock was not left held by the abandoned acquisition")
            .expect("a subsequent caller still receives a credential");
        assert_eq!(token.expose(), ISSUED_CREDENTIAL);
        // The abandoned task's own request reaching the server proves it was
        // past the lock acquisition, and the response delay of four times the
        // abort delay proves it was still awaiting that request, so still
        // holding the lock, when the abort landed.
        assert_eq!(
            token_requests(&server).await,
            2,
            "the abandoned task never reached the token request it would have held the lock for"
        );
    }

    /// A declined request reports the registered code and nothing else. The
    /// description is server-authored text about a failed authentication, so it
    /// must not reach the caller's diagnostic.
    #[tokio::test]
    async fn a_declined_token_request_reports_only_the_registered_code() {
        let cases = [
            (
                400,
                json!({"error": "invalid_request"}).to_string(),
                JSON_MEDIA_TYPE,
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidRequest,
                },
            ),
            (
                401,
                json!({"error": "invalid_client", "error_description": "canary assertion detail"})
                    .to_string(),
                JSON_MEDIA_TYPE,
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidClient,
                },
            ),
            (
                400,
                json!({"error": "canary_extension_code"}).to_string(),
                JSON_MEDIA_TYPE,
                TokenError::Refused {
                    code: OAuthErrorCode::Other,
                },
            ),
            (
                400,
                "canary not json at all".to_owned(),
                JSON_MEDIA_TYPE,
                TokenError::Protocol { status: 400 },
            ),
            (
                403,
                json!({"error": "invalid_client"}).to_string(),
                JSON_MEDIA_TYPE,
                TokenError::Protocol { status: 403 },
            ),
            (
                500,
                json!({"error": "server_error"}).to_string(),
                JSON_MEDIA_TYPE,
                TokenError::Protocol { status: 500 },
            ),
            // A real authorization server states a charset parameter on its
            // JSON responses; the essence the gate compares against must
            // still match with one present.
            (
                400,
                json!({"error": "invalid_request"}).to_string(),
                "application/json; charset=utf-8",
                TokenError::Refused {
                    code: OAuthErrorCode::InvalidRequest,
                },
            ),
        ];

        for (status, body, media_type, expected) in cases {
            let server = token_endpoint_serving(
                ResponseTemplate::new(status).set_body_raw(body.clone(), media_type),
            )
            .await;
            let clock = Arc::new(TestClock::new(NOW));
            let provider = provider(endpoint(&server.uri()), &clock);

            let error = provider
                .bearer_token()
                .await
                .expect_err("the token endpoint declined");
            assert_eq!(error, expected, "status {status}");
            let rendered = error.to_string();
            assert!(!rendered.contains("canary"), "{rendered}");
        }
    }

    /// A 400 or 401 body is read as a refusal only when it is announced in the
    /// media type the request asked for. An intermediary that answers in a
    /// different media type, or none at all, never reached the authorization
    /// server's own refusal logic, so it must be reported as a protocol failure
    /// rather than as a refusal the adopter cannot act on.
    #[tokio::test]
    async fn a_declined_status_in_the_wrong_media_type_is_a_protocol_failure() {
        let refusal = json!({"error": "invalid_request"}).to_string();
        let cases = [
            (
                400,
                ResponseTemplate::new(400).set_body_bytes(refusal.clone()),
                "absent content type",
            ),
            (
                401,
                ResponseTemplate::new(401).set_body_raw(refusal.clone(), "text/plain"),
                "wrong content type",
            ),
        ];

        for (status, response, label) in cases {
            let server = token_endpoint_serving(response).await;
            let clock = Arc::new(TestClock::new(NOW));
            let provider = provider(endpoint(&server.uri()), &clock);

            let error = provider
                .bearer_token()
                .await
                .expect_err("the answer is not a usable refusal");
            assert_eq!(error, TokenError::Protocol { status }, "{label}");
        }
    }

    /// An answer that is not a usable token response is a protocol failure, never
    /// a credential. Each of these would otherwise become a request the deployment
    /// refuses for a reason the adopter cannot see.
    #[tokio::test]
    async fn an_unusable_token_response_is_refused() {
        let cases = [
            (
                "a success in the wrong media type",
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_string(
                        json!({"access_token": "canary", "token_type": "Bearer"}).to_string(),
                    ),
            ),
            (
                "a success carrying no credential",
                ResponseTemplate::new(200).set_body_json(json!({"token_type": "Bearer"})),
            ),
            (
                "a credential the Evidence request cannot present",
                ResponseTemplate::new(200).set_body_json(
                    json!({"access_token": "canary", "token_type": "mac", "expires_in": 300}),
                ),
            ),
            (
                "a credential that is not header safe",
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token": "canary token", "token_type": "Bearer"})),
            ),
            (
                "an unreadable success body",
                ResponseTemplate::new(200).set_body_raw("{", "application/json"),
            ),
            (
                "a redirect instead of an answer",
                ResponseTemplate::new(302).insert_header("location", "https://elsewhere.invalid/"),
            ),
        ];

        for (description, response) in cases {
            let server = token_endpoint_serving(response).await;
            let clock = Arc::new(TestClock::new(NOW));
            let provider = provider(endpoint(&server.uri()), &clock);

            let error = provider
                .bearer_token()
                .await
                .expect_err("the answer is not a usable token response");
            let rendered = error.to_string();
            assert!(!rendered.contains("canary"), "{description}: {rendered}");
            assert!(
                matches!(
                    error,
                    TokenError::Protocol { .. } | TokenError::Invalid { .. }
                ),
                "{description}: {error:?}"
            );
        }
    }

    /// A token endpoint that never answers is reported as a transport failure, so
    /// a caller can tell an unreachable server from a refusal.
    #[tokio::test]
    async fn a_token_endpoint_that_cannot_be_reached_reports_a_transport_failure() {
        // The port is reserved and released, so the connection attempt is refused
        // rather than answered.
        let reservation =
            TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port is available");
        let port = reservation
            .local_addr()
            .expect("the reservation has an address")
            .port();
        drop(reservation);
        let clock = Arc::new(TestClock::new(NOW));
        let provider = provider(endpoint(&format!("http://127.0.0.1:{port}")), &clock);

        let error = provider
            .bearer_token()
            .await
            .expect_err("nothing is listening");
        assert_eq!(
            error,
            TokenError::Transport {
                kind: TransportKind::Connect
            }
        );
    }

    /// A provider that could not authenticate, could not protect its assertion in
    /// transit, or could not sign at all fails at construction rather than once
    /// per request.
    #[test]
    fn an_unusable_provider_configuration_is_refused() {
        let cases: Vec<(&str, PrivateKeyJwtConfig)> = vec![
            (
                "the client identifier must not be empty",
                PrivateKeyJwtConfig::new(
                    endpoint("https://tokens.example.org"),
                    "   ",
                    client_key(Some(KEY_ID)),
                ),
            ),
            (
                "the token endpoint must use HTTPS, or HTTP with a loopback host",
                config(
                    endpoint("http://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                ),
            ),
            (
                "the token endpoint must carry no credentials or fragment",
                config(
                    "https://client:canary@tokens.example.org/token"
                        .parse()
                        .expect("the endpoint parses"),
                    client_key(Some(KEY_ID)),
                ),
            ),
            (
                "the token endpoint must carry no credentials or fragment",
                config(
                    "https://tokens.example.org/token#canary"
                        .parse()
                        .expect("the endpoint parses"),
                    client_key(Some(KEY_ID)),
                ),
            ),
            (
                "the client key must carry a key identifier",
                config(endpoint("https://tokens.example.org"), client_key(None)),
            ),
            (
                "the client key must carry a key identifier",
                config(endpoint("https://tokens.example.org"), {
                    let mut key = es256_client_key(None);
                    key.kid = None;
                    key
                }),
            ),
            (
                "the assertion lifetime must be within 1..=300 seconds",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_assertion_lifetime_seconds(0),
            ),
            (
                "the assertion lifetime must be within 1..=300 seconds",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_assertion_lifetime_seconds(MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1),
            ),
            (
                "the refresh margin must not be negative",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_refresh_margin_seconds(-1),
            ),
            (
                "the timeouts must be greater than zero",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_request_timeout(Duration::ZERO),
            ),
            (
                "the client key cannot sign a client assertion",
                config(
                    endpoint("https://tokens.example.org"),
                    unsignable_es256_client_key(),
                ),
            ),
            (
                "the client key cannot sign a client assertion",
                config(
                    endpoint("https://tokens.example.org"),
                    unsignable_rs256_client_key(),
                ),
            ),
            (
                "the client key's halves belong to different key pairs",
                config(
                    endpoint("https://tokens.example.org"),
                    mismatched_eddsa_client_key(),
                ),
            ),
            (
                "the client key's halves belong to different key pairs",
                config(
                    endpoint("https://tokens.example.org"),
                    mismatched_es256_client_key(),
                ),
            ),
            (
                "the pinned certificate authority bundle carries no certificate",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_trusted_root_certificates(Vec::new()),
            ),
            (
                "the pinned certificate authority bundle is not readable PEM",
                config(
                    endpoint("https://tokens.example.org"),
                    client_key(Some(KEY_ID)),
                )
                .with_trusted_root_certificates(
                    b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_vec(),
                ),
            ),
        ];

        for (reason, candidate) in cases {
            let error = PrivateKeyJwt::new(candidate).expect_err(reason);
            assert_eq!(error, TokenError::Configuration { reason });
        }
    }

    /// A key, a cached credential, and an assertion are all secrets. None of them
    /// may reach a rendering.
    #[tokio::test]
    async fn debug_output_never_carries_the_client_key_or_the_credential() {
        let server = token_endpoint_serving(issued(Some(TOKEN_LIFETIME_SECONDS))).await;
        let key = client_key(Some(KEY_ID));
        let secret = key
            .d
            .clone()
            .expect("the test key carries private material");
        let candidate = config(endpoint(&server.uri()), key);
        let rendered = format!("{candidate:?}");
        assert!(!rendered.contains(&secret), "{rendered}");

        let clock = Arc::new(TestClock::new(NOW));
        let provider = PrivateKeyJwt::with_clock(candidate, clock.clone())
            .expect("the provider is usable as configured");
        provider.bearer_token().await.expect("a credential");
        let rendered = format!("{provider:?}");
        assert!(!rendered.contains(&secret), "{rendered}");
        assert!(!rendered.contains(ISSUED_CREDENTIAL), "{rendered}");
        assert!(rendered.contains(KEY_ID), "the key identifier is public");
    }

    /// A caller can put userinfo in the token endpoint it names, and a rendering
    /// that carried it through would print that credential wherever the
    /// configuration is rendered: a wider `Debug`, a panic message, a tracing
    /// field.
    #[test]
    fn debug_output_withholds_userinfo_the_caller_put_in_the_token_endpoint() {
        let candidate = config(
            endpoint("https://client:s3cr3t@issuer.example.org"),
            client_key(Some(KEY_ID)),
        );

        let rendered = format!("{candidate:?}");

        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        // The separator is what makes a userinfo component one, and no other
        // field of this rendering carries it, so its absence is what proves none
        // was rendered under any spelling.
        assert!(!rendered.contains('@'), "{rendered}");
        // The endpoint still has to be recognizable, or the rendering is no use
        // for telling one misconfigured deployment from another.
        assert!(rendered.contains("issuer.example.org/token"), "{rendered}");
    }
}
