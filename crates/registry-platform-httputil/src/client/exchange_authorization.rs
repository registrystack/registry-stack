//! Context-bound RFC 8693 authorization for service clients.
//!
//! The host supplies one immutable, already verified context. A first-party
//! source signs that context once; a remote source may obtain a fresh assertion
//! from its owning authority on every refresh; an upstream source presents,
//! once, an access token the host has already verified, optionally beside the
//! service's own client-credentials token as the actor. No source can extend
//! the context deadline. A new person or grant requires a new provider
//! instance.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::PrivateJwk;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    outbound::{build_client, read_failure_kind, send_failure_kind, OutboundOptions},
    private_key_jwt::{PrivateKeyJwt, SubjectTokenType},
    token::{BearerToken, TokenError, TokenProvider},
    ServiceBaseUrl,
};

const MAX_CONTEXT_TEXT_BYTES: usize = 512;
const MAX_ATTRIBUTES_BYTES: usize = 4096;
const MAX_ASSERTION_BYTES: usize = 32 * 1024;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 60;
/// Longest any exchanged token remains cached, even when its verified outer
/// context lasts longer or the token issuer states no lifetime.
const MAX_EXCHANGE_CACHE_SECONDS: u64 =
    super::private_key_jwt::MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS as u64;
const REFRESH_MARGIN: Duration = Duration::from_secs(5);
const MAX_REMOTE_ASSERTION_RESPONSE_BYTES: u64 = 40 * 1024;

fn now_seconds() -> Result<i64, TokenError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::Unavailable)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| TokenError::Unavailable)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTEXT_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

/// Immutable authority identity and host verification generation.
///
/// `generation` must change whenever the host's verified source facts change.
/// The provider refuses after `deadline` even if the issuer returns a token
/// with a later expiry. Construct a new context only after fresh host checks.
pub struct ExchangeContext {
    issuer: String,
    subject: String,
    audience: String,
    generation: String,
    deadline: i64,
    grant_id: Option<String>,
}

impl ExchangeContext {
    pub fn first_party(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
        generation: impl Into<String>,
        deadline: i64,
    ) -> Result<Self, TokenError> {
        Self::build(
            issuer.into(),
            subject.into(),
            audience.into(),
            generation.into(),
            deadline,
            None,
        )
    }

    pub fn grant(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
        generation: impl Into<String>,
        deadline: i64,
        grant_id: impl Into<String>,
    ) -> Result<Self, TokenError> {
        Self::build(
            issuer.into(),
            subject.into(),
            audience.into(),
            generation.into(),
            deadline,
            Some(grant_id.into()),
        )
    }

    fn build(
        issuer: String,
        subject: String,
        audience: String,
        generation: String,
        deadline: i64,
        grant_id: Option<String>,
    ) -> Result<Self, TokenError> {
        let now = now_seconds()?;
        if ![&issuer, &subject, &audience, &generation]
            .into_iter()
            .all(|value| valid_text(value))
            || grant_id.as_ref().is_some_and(|value| !valid_text(value))
            || deadline <= now
        {
            return Err(TokenError::Invalid {
                reason: "the verified exchange context is incomplete or expired",
            });
        }
        Ok(Self {
            issuer,
            subject,
            audience,
            generation,
            deadline,
            grant_id,
        })
    }

    pub fn deadline(&self) -> i64 {
        self.deadline
    }
    pub fn grant_id(&self) -> Option<&str> {
        self.grant_id.as_deref()
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
}

impl fmt::Debug for ExchangeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeContext")
            .field("grant_present", &self.grant_id.is_some())
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// One assertion returned by a trusted source. Its bytes are never logged.
pub struct SignedExchangeAssertion {
    jwt: Zeroizing<String>,
    expires_at: i64,
}

impl SignedExchangeAssertion {
    pub fn new(jwt: impl Into<String>, expires_at: i64) -> Result<Self, TokenError> {
        let jwt = Zeroizing::new(jwt.into());
        if jwt.is_empty()
            || jwt.len() > MAX_ASSERTION_BYTES
            || !jwt.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TokenError::Invalid {
                reason: "the exchange assertion is not a bounded JWT",
            });
        }
        Ok(Self { jwt, expires_at })
    }
}

/// A subject token another authorization server issued, which the host has
/// already verified, together with the expiry the host read from it.
///
/// The token text is held in a buffer wiped on drop and never rendered.
/// `expires_at` must be the verified token's own `exp`: an upstream exchange
/// refuses a context that would outlive it.
pub struct UpstreamSubjectToken {
    token: Zeroizing<String>,
    token_type: SubjectTokenType,
    expires_at: i64,
}

impl UpstreamSubjectToken {
    pub fn new(
        token: impl Into<String>,
        token_type: SubjectTokenType,
        expires_at: i64,
    ) -> Result<Self, TokenError> {
        let token = Zeroizing::new(token.into());
        if token.is_empty()
            || token.len() > MAX_ASSERTION_BYTES
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TokenError::Invalid {
                reason: "the upstream subject token must be bounded non-empty visible ASCII",
            });
        }
        if expires_at <= now_seconds()? {
            return Err(TokenError::Invalid {
                reason: "the upstream subject token has expired",
            });
        }
        Ok(Self {
            token,
            token_type,
            expires_at,
        })
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl fmt::Debug for UpstreamSubjectToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamSubjectToken")
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Where the subject token of one exchange comes from.
enum SubjectSource {
    /// An assertion from a trusted source, checked against the context.
    Assertion(Arc<dyn ExchangeAssertionSource>),
    /// An access token the host verified, and the service's own provider for
    /// the actor token, if the exchange presents one.
    Upstream {
        subject: UpstreamSubjectToken,
        actor: Option<Arc<PrivateKeyJwt>>,
    },
}

/// A trusted authority that obtains a new assertion from its owning source.
/// The provider validates its binding before contacting the token endpoint.
#[async_trait]
pub trait ExchangeAssertionSource: Send + Sync {
    async fn assertion(
        &self,
        context: &ExchangeContext,
    ) -> Result<SignedExchangeAssertion, TokenError>;
}

/// A configured authority endpoint that accepts the agent's narrow bootstrap
/// credential on one empty POST and returns a closed assertion response.
/// A product client owns construction of the exact route and its DTO contract.
pub struct RemoteAssertionSource {
    endpoint: ServiceBaseUrl,
    bootstrap: PrivateKeyJwt,
    http: reqwest::Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoteAssertionResponse {
    assertion: String,
    expires_at: i64,
    grant_expires_at: i64,
}

impl RemoteAssertionSource {
    pub fn new(
        endpoint: url::Url,
        bootstrap: PrivateKeyJwt,
        expected_bootstrap_resource: &str,
        expected_bootstrap_scope: &str,
        options: OutboundOptions<'_>,
    ) -> Result<Self, TokenError> {
        let endpoint = ServiceBaseUrl::new(endpoint).map_err(|_| TokenError::Configuration {
            reason: "the remote assertion endpoint is not a protected fixed destination",
        })?;
        let (resource, scopes) = bootstrap.configured_resource_and_scopes();
        if !super::private_key_jwt::valid_resource_uri(expected_bootstrap_resource)
            || !super::private_key_jwt::valid_scope_token(expected_bootstrap_scope)
            || resource != Some(expected_bootstrap_resource)
            || scopes != [expected_bootstrap_scope]
        {
            return Err(TokenError::Configuration {
                reason:
                    "the remote assertion bootstrap does not match its approved resource and scope",
            });
        }
        let http = build_client(options).map_err(|_| TokenError::Configuration {
            reason: "the remote assertion HTTP options are unusable",
        })?;
        Ok(Self {
            endpoint,
            bootstrap,
            http,
        })
    }
}

#[async_trait]
impl ExchangeAssertionSource for RemoteAssertionSource {
    async fn assertion(
        &self,
        context: &ExchangeContext,
    ) -> Result<SignedExchangeAssertion, TokenError> {
        if context.grant_id.is_none() || now_seconds()? >= context.deadline {
            return Err(TokenError::Unavailable);
        }
        let bootstrap = self.bootstrap.bearer_token().await?;
        let response = self
            .http
            .post(self.endpoint.as_url().clone())
            .header(AUTHORIZATION, bootstrap.authorization_header_value())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| TokenError::Transport {
                kind: send_failure_kind(&error),
            })?;
        let status = response.status().as_u16();
        if crate::validate_response_headers(response.headers()).is_err() {
            return Err(TokenError::Protocol { status });
        }
        if status != 200 {
            return Err(TokenError::Protocol { status });
        }
        let mut media = response.headers().get_all(CONTENT_TYPE).iter();
        if !matches!((media.next(), media.next()), (Some(value), None) if value.as_bytes() == b"application/json")
        {
            return Err(TokenError::Protocol { status });
        }
        let body = Zeroizing::new(
            crate::read_bounded(response, MAX_REMOTE_ASSERTION_RESPONSE_BYTES)
                .await
                .map_err(|error| TokenError::Transport {
                    kind: read_failure_kind(&error),
                })?,
        );
        let value: RemoteAssertionResponse =
            serde_json::from_slice(&body).map_err(|_| TokenError::Protocol { status })?;
        if value.grant_expires_at != context.deadline {
            return Err(TokenError::Invalid {
                reason: "the remote authority changed the grant deadline",
            });
        }
        SignedExchangeAssertion::new(value.assertion, value.expires_at)
    }
}

/// First-party signer for a host-verified person context. Attributes are
/// reviewed deployment inputs, never raw browser claims.
pub struct FirstPartyAssertionSource {
    key: PrivateJwk,
    attributes: Map<String, Value>,
    scopes: Vec<String>,
}

impl FirstPartyAssertionSource {
    pub fn new(
        key: PrivateJwk,
        attributes: Map<String, Value>,
        scopes: Vec<String>,
    ) -> Result<Self, TokenError> {
        if key.kid.as_deref().is_none_or(|value| !valid_text(value)) || key.algorithm().is_err() {
            return Err(TokenError::Configuration {
                reason: "the first-party assertion key is not usable",
            });
        }
        let probe = registry_platform_crypto::sign(b"first-party assertion key probe", &key)
            .map_err(|_| TokenError::Configuration {
                reason: "the first-party assertion key cannot sign",
            })?;
        registry_platform_crypto::verify(b"first-party assertion key probe", &probe, &key.public())
            .map_err(|_| TokenError::Configuration {
                reason: "the first-party assertion key halves disagree",
            })?;
        if attributes.is_empty()
            || serde_json::to_vec(&attributes)
                .map_or(true, |bytes| bytes.len() > MAX_ATTRIBUTES_BYTES)
            || attributes.keys().any(|name| {
                !valid_text(name)
                    || matches!(
                        name.as_str(),
                        "iss" | "sub" | "aud" | "iat" | "nbf" | "exp" | "jti" | "scope" | "act"
                    )
                    || name.starts_with("registry_grant")
            })
            || attributes
                .get("registry_actor_kind")
                .and_then(Value::as_str)
                != Some("human")
        {
            return Err(TokenError::Configuration {
                reason: "the first-party assertion attributes are not a bounded human context",
            });
        }
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|value| !super::private_key_jwt::valid_scope_token(value))
        {
            return Err(TokenError::Configuration {
                reason: "the first-party assertion scopes are invalid",
            });
        }
        let mut pending: Vec<(&Value, usize)> =
            attributes.values().map(|value| (value, 1)).collect();
        let mut nodes = 0;
        while let Some((value, depth)) = pending.pop() {
            nodes += 1;
            if nodes > 128 || depth > 8 {
                return Err(TokenError::Configuration {
                    reason: "the first-party assertion attributes exceed the structure bound",
                });
            }
            match value {
                Value::Array(values) => {
                    pending.extend(values.iter().map(|value| (value, depth + 1)))
                }
                Value::Object(values) => {
                    pending.extend(values.values().map(|value| (value, depth + 1)))
                }
                _ => {}
            }
        }
        Ok(Self {
            key,
            attributes,
            scopes,
        })
    }
}

#[async_trait]
impl ExchangeAssertionSource for FirstPartyAssertionSource {
    async fn assertion(
        &self,
        context: &ExchangeContext,
    ) -> Result<SignedExchangeAssertion, TokenError> {
        if context.grant_id.is_some() {
            return Err(TokenError::Configuration {
                reason: "first-party assertions cannot carry task grants",
            });
        }
        let now = now_seconds()?;
        if now >= context.deadline {
            return Err(TokenError::Unavailable);
        }
        let exp = context
            .deadline
            .min(now.saturating_add(MAX_ASSERTION_LIFETIME_SECONDS));
        let mut claims = self.attributes.clone();
        claims.insert("iss".into(), json!(context.issuer));
        claims.insert("sub".into(), json!(context.subject));
        claims.insert("aud".into(), json!(context.audience));
        claims.insert("iat".into(), json!(now));
        claims.insert("nbf".into(), json!(now));
        claims.insert("exp".into(), json!(exp));
        claims.insert("jti".into(), json!(Uuid::new_v4().to_string()));
        claims.insert("scope".into(), json!(self.scopes.join(" ")));
        let header = json!({"alg": self.key.algorithm().map_err(|_| TokenError::Unavailable)?.jwa_name(), "kid": self.key.kid, "typ": "JWT"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).map_err(|_| TokenError::Unavailable)?),
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).map_err(|_| TokenError::Unavailable)?)
        );
        let signature = registry_platform_crypto::sign(input.as_bytes(), &self.key)
            .map_err(|_| TokenError::Unavailable)?;
        SignedExchangeAssertion::new(
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            exp,
        )
    }
}

struct CachedExchange {
    token: BearerToken,
    expires_at: Instant,
}

/// One client, resource, scope set and immutable verified context.
///
/// First-party and upstream instances exchange once and must be reconstructed
/// after the issued token expires. Remote sources may renew only by obtaining
/// a new assertion from their owning authority, which can refuse a revoked
/// grant.
pub struct ExchangeAuthorization {
    exchange: PrivateKeyJwt,
    context: ExchangeContext,
    source: SubjectSource,
    renewable: bool,
    cached: RwLock<Option<CachedExchange>>,
    refresh_lock: Mutex<bool>,
}

impl ExchangeAuthorization {
    /// Apply DNS-pinned fetch rules before this provider joins a
    /// discovery-driven client. Any token obtained under the prior policy is
    /// discarded, so a previously used provider cannot bypass the new rules.
    #[must_use]
    pub fn with_fetch_url_policy(mut self, policy: crate::FetchUrlPolicy) -> Self {
        self.exchange.set_fetch_url_policy(policy);
        self.cached = RwLock::new(None);
        // Discarding that token also returns the one exchange a non-renewable
        // context allows. This method consumes the provider, so the client
        // built from what it returns still performs at most one exchange, and
        // it performs that one under the policy just applied.
        self.refresh_lock = Mutex::new(false);
        self
    }

    /// Compare the immutable exchange target and requested authority with a
    /// profile and the service's freshly checked authorization metadata.
    /// No token is acquired while making this comparison.
    #[must_use]
    pub fn matches_discovered_binding(
        &self,
        client_id: &str,
        token_endpoint: &Url,
        issuer: &str,
        assertion_audience: Option<&str>,
        resource: &str,
        scopes: &[String],
    ) -> bool {
        self.context.audience == issuer
            && self.exchange.matches_discovered_binding(
                client_id,
                token_endpoint,
                assertion_audience,
                resource,
                scopes,
            )
    }

    pub fn first_party(
        exchange: PrivateKeyJwt,
        context: ExchangeContext,
        source: FirstPartyAssertionSource,
    ) -> Result<Self, TokenError> {
        if context.grant_id.is_some() {
            return Err(TokenError::Configuration {
                reason: "a first-party context cannot contain a grant",
            });
        }
        if exchange.exchange_binding()?.2 != source.scopes.as_slice() {
            return Err(TokenError::Configuration {
                reason: "the first-party assertion scopes must match the exchange scopes",
            });
        }
        Self::build(
            exchange,
            context,
            SubjectSource::Assertion(Arc::new(source)),
            false,
        )
    }

    /// Exchange an access token the host has already verified, once, for a
    /// token bound to this provider's resource and scopes.
    ///
    /// `context` is a first-party context whose subject is the verified
    /// token's subject and whose deadline is no later than that token's
    /// `exp`, so nothing this provider hands out outlives the subject token.
    /// The upstream token is not parsed here. The host must already have
    /// verified its signature, issuer, expiry and, above all, its audience:
    /// an authorization server re-validates the subject token on exchange but
    /// need not check whom it was issued for, so a token minted for another
    /// service would otherwise be exchanged as readily as one minted for this
    /// host.
    ///
    /// The issued token is handed out until the earlier of its stated expiry
    /// and the context deadline, whatever lifetime the issuer gives it. A token
    /// response that states a scope must include every requested scope; one
    /// that omits it is taken to grant the scope requested, as RFC 6749 section
    /// 5.1 defines, so the resource server's own scope check stays the
    /// authority.
    ///
    /// `actor` is the service's own client-credentials provider. Its token is
    /// acquired and presented as `actor_token` inside the exchange and never
    /// reaches the caller. It must authenticate as the same client at the same
    /// token endpoint as `exchange`, and is shared across contexts so its
    /// cached credential serves every exchange. Configure it without a
    /// resource or scopes, so that credential is not itself a standing token
    /// for the downstream service; its outbound policy is set when it is
    /// constructed, because [`Self::with_fetch_url_policy`] applies to the
    /// exchange provider only.
    pub fn upstream(
        exchange: PrivateKeyJwt,
        context: ExchangeContext,
        subject: UpstreamSubjectToken,
        actor: Option<Arc<PrivateKeyJwt>>,
    ) -> Result<Self, TokenError> {
        if context.grant_id.is_some() {
            return Err(TokenError::Configuration {
                reason: "an upstream subject token cannot carry a grant context",
            });
        }
        if context.deadline > subject.expires_at {
            return Err(TokenError::Invalid {
                reason: "the verified exchange context outlives the upstream subject token",
            });
        }
        if actor
            .as_deref()
            .is_some_and(|actor| !exchange.is_same_client(actor))
        {
            return Err(TokenError::Configuration {
                reason:
                    "the actor token provider must be the exchanging client at its token endpoint",
            });
        }
        Self::build(
            exchange,
            context,
            SubjectSource::Upstream { subject, actor },
            false,
        )
    }

    pub fn from_authority(
        exchange: PrivateKeyJwt,
        context: ExchangeContext,
        source: Arc<dyn ExchangeAssertionSource>,
    ) -> Result<Self, TokenError> {
        if context.grant_id.is_none() {
            return Err(TokenError::Configuration {
                reason: "an authority source requires a grant context",
            });
        }
        Self::build(exchange, context, SubjectSource::Assertion(source), true)
    }

    fn build(
        exchange: PrivateKeyJwt,
        context: ExchangeContext,
        source: SubjectSource,
        renewable: bool,
    ) -> Result<Self, TokenError> {
        let _ = exchange.exchange_binding()?;
        if context.deadline <= now_seconds()? {
            return Err(TokenError::Unavailable);
        }
        Ok(Self {
            exchange,
            context,
            source,
            renewable,
            cached: RwLock::new(None),
            refresh_lock: Mutex::new(false),
        })
    }

    fn validate_assertion(
        &self,
        assertion: &SignedExchangeAssertion,
        now: i64,
    ) -> Result<(), TokenError> {
        let mut segments = assertion.jwt.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(TokenError::Invalid {
                reason: "the authority assertion is not a compact JWT",
            });
        };
        if signature.is_empty()
            || assertion.expires_at <= now
            || assertion.expires_at > self.context.deadline
            || assertion.expires_at > now + MAX_ASSERTION_LIFETIME_SECONDS
        {
            return Err(TokenError::Invalid {
                reason: "the authority assertion is expired or extends its context",
            });
        }
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| TokenError::Invalid {
                reason: "the authority assertion header is malformed",
            })?;
        let header: Value =
            serde_json::from_slice(&header_bytes).map_err(|_| TokenError::Invalid {
                reason: "the authority assertion header is malformed",
            })?;
        if header
            .get("alg")
            .and_then(Value::as_str)
            .is_none_or(|value| !matches!(value, "EdDSA" | "ES256" | "RS256" | "ES384" | "RS384"))
            || header
                .get("kid")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_text(value))
            || header.get("typ").and_then(Value::as_str) != Some("JWT")
        {
            return Err(TokenError::Invalid {
                reason: "the authority assertion header is not supported",
            });
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TokenError::Invalid {
                reason: "the authority assertion claims are malformed",
            })?;
        let claims: Value = serde_json::from_slice(&bytes).map_err(|_| TokenError::Invalid {
            reason: "the authority assertion claims are malformed",
        })?;
        let (client, resource, requested_scopes) = self.exchange.exchange_binding()?;
        let scope = claims
            .get("scope")
            .and_then(Value::as_str)
            .ok_or(TokenError::Invalid {
                reason: "the authority assertion does not state the requested scopes",
            })?;
        let stated: Vec<&str> = scope.split(' ').collect();
        if claims.get("iss").and_then(Value::as_str) != Some(self.context.issuer.as_str())
            || claims.get("sub").and_then(Value::as_str) != Some(self.context.subject.as_str())
            || claims.get("aud").and_then(Value::as_str) != Some(self.context.audience.as_str())
            || claims.get("exp").and_then(Value::as_i64) != Some(assertion.expires_at)
            || claims
                .get("iat")
                .and_then(Value::as_i64)
                .is_none_or(|issued| issued > now || issued < now - MAX_ASSERTION_LIFETIME_SECONDS)
            || claims
                .get("nbf")
                .is_some_and(|value| value.as_i64().is_none_or(|start| start > now))
            || claims
                .get("jti")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_text(value))
            || claims.get("registry_actor_kind").and_then(Value::as_str)
                != Some(if self.context.grant_id.is_some() {
                    "agent"
                } else {
                    "human"
                })
            || stated.len() != requested_scopes.len()
            || requested_scopes
                .iter()
                .any(|value| !stated.contains(&value.as_str()))
            || self.context.grant_id.as_deref()
                != claims.get("registry_grant_id").and_then(Value::as_str)
            || self.context.grant_id.as_ref().is_some_and(|_| {
                claims.get("registry_grant_client").and_then(Value::as_str) != Some(client)
                    || claims
                        .get("registry_grant_resource")
                        .and_then(Value::as_str)
                        != Some(resource)
                    || claims.get("registry_grant_exp").and_then(Value::as_i64)
                        != Some(self.context.deadline)
            })
        {
            return Err(TokenError::Invalid {
                reason: "the authority assertion does not match the verified exchange context",
            });
        }
        Ok(())
    }

    /// The held token, when it is still one this provider may hand out.
    ///
    /// The refresh margin is the room to obtain a replacement before a token
    /// dies in flight. A provider that is not renewable has no replacement to
    /// reach for: it holds the one token its one exchange produced. Withholding
    /// that token over the closing seconds of a short issuer lifetime does not
    /// protect the request, it is the only thing that fails it. So the margin
    /// applies where a refresh is available, and elsewhere the token serves
    /// until it actually expires.
    async fn held_token(&self, now: Instant) -> Option<BearerToken> {
        let margin = if self.renewable {
            REFRESH_MARGIN
        } else {
            Duration::ZERO
        };
        self.cached
            .read()
            .await
            .as_ref()
            .filter(|entry| entry.expires_at.saturating_duration_since(now) > margin)
            .map(|entry| entry.token.clone())
    }
}

#[async_trait]
impl TokenProvider for ExchangeAuthorization {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        if now_seconds()? >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        let now = Instant::now();
        if let Some(token) = self.held_token(now).await {
            return Ok(token);
        }
        let mut attempted = self.refresh_lock.lock().await;
        let now = Instant::now();
        if let Some(token) = self.held_token(now).await {
            return Ok(token);
        }
        if !self.renewable && *attempted {
            return Err(TokenError::Unavailable);
        }
        // First-party verification is a snapshot of host-owned source facts.
        // A failed exchange must also require a new snapshot.
        *attempted = true;
        let wall_now = now_seconds()?;
        if wall_now >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        // The verified context deadline bounds every token this provider hands
        // out. A non-renewable, first-party exchange also uses it as the bound
        // for a token whose issuer states no lifetime, so one verified context
        // can serve the several requests an operation makes. A renewable remote
        // source must instead fetch a fresh assertion on the next request: with
        // no issuer lifetime there is no safe refresh instant, and retaining the
        // token until the outer context deadline would bypass the authority's
        // current grant check. The outer context may legitimately last longer
        // than the token-cache ceiling, so calculate its remaining lifetime in
        // checked form and clamp only the cache deadline.
        let context_remaining = self
            .context
            .deadline
            .checked_sub(wall_now)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .ok_or(TokenError::Unavailable)?;
        let context_cache_deadline = now
            .checked_add(Duration::from_secs(
                context_remaining.min(MAX_EXCHANGE_CACHE_SECONDS),
            ))
            .ok_or(TokenError::Unavailable)?;
        let acquired = match &self.source {
            SubjectSource::Assertion(source) => {
                let assertion = source.assertion(&self.context).await?;
                // The authority may issue this assertion after waiting on HTTP
                // or its current grant check. Compare iat to the time of
                // receipt, not the time before acquisition began.
                self.validate_assertion(&assertion, now_seconds()?)?;
                self.exchange
                    .exchange_acquired(&assertion.jwt, SubjectTokenType::Jwt, None)
                    .await?
            }
            SubjectSource::Upstream { subject, actor } => {
                // The actor's own credential comes from its cache, or from one
                // client-credentials request, before the subject token is sent
                // anywhere. The context deadline is re-read after that wait.
                let actor_token = match actor {
                    Some(actor) => Some(actor.bearer_token().await?),
                    None => None,
                };
                if now_seconds()? >= self.context.deadline {
                    return Err(TokenError::Unavailable);
                }
                // An issuer may narrow an exchange to the scopes the upstream
                // token carried without refusing it. The exchange provider
                // refuses a stated scope missing a requested one. An omitted
                // scope means the scope requested (RFC 6749 section 5.1), and
                // the resource server still enforces the scopes it requires on
                // the token itself.
                self.exchange
                    .exchange_acquired(&subject.token, subject.token_type, actor_token.as_ref())
                    .await?
            }
        };
        if now_seconds()? >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        // An issuer that states a lifetime is believed about it, including
        // when it states one that has already run out: `PrivateKeyJwt` reports
        // that as no deadline at all, and a credential the issuer calls spent
        // is used once and dropped. The context deadline answers an issuer's
        // silence, never an issuer's own accounting.
        let expires_at = match acquired.expires_at {
            Some(issued) => Some(issued.min(context_cache_deadline)),
            None if acquired.lifetime_stated => None,
            None if self.renewable => None,
            None => Some(context_cache_deadline),
        };
        if let Some(expires_at) = expires_at {
            *self.cached.write().await = Some(CachedExchange {
                token: acquired.token.clone(),
                expires_at,
            });
        }
        Ok(acquired.token)
    }
}

impl fmt::Debug for ExchangeAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeAuthorization")
            .field("exchange", &self.exchange)
            .field("context", &self.context)
            .field("renewable", &self.renewable)
            .field(
                "upstream_actor_present",
                &matches!(&self.source, SubjectSource::Upstream { actor: Some(_), .. }),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use wiremock::{
        matchers::{body_string_contains, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn key() -> PrivateJwk {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing = SigningKey::from_bytes(&seed);
        PrivateJwk::parse(
            &json!({
                "kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "kid":"test-key",
                "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                "d": URL_SAFE_NO_PAD.encode(signing.to_bytes()),
            })
            .to_string(),
        )
        .unwrap()
    }

    fn exchange(server: &MockServer, resource: &str, scopes: &[&str]) -> PrivateKeyJwt {
        let endpoint = format!("{}/token", server.uri()).parse().unwrap();
        PrivateKeyJwt::new(
            super::super::private_key_jwt::PrivateKeyJwtConfig::new(
                endpoint,
                "portal-client",
                key(),
            )
            .with_resource(resource)
            .with_scopes(scopes.iter().copied()),
        )
        .unwrap()
    }

    fn context(subject: &str, deadline: i64) -> ExchangeContext {
        ExchangeContext::first_party(
            "https://portal.example",
            subject,
            "https://issuer.example",
            "verified-source-revision-1",
            deadline,
        )
        .unwrap()
    }

    fn source(scopes: &[&str]) -> FirstPartyAssertionSource {
        FirstPartyAssertionSource::new(
            key(),
            json!({"registry_actor_kind":"human", "identity":{"person_reference":"person-1"}})
                .as_object()
                .unwrap()
                .clone(),
            scopes.iter().map(|value| (*value).into()).collect(),
        )
        .unwrap()
    }

    /// Waits until the wall clock has just crossed a whole-second boundary.
    ///
    /// `now_seconds()` truncates to whole seconds, so a deadline built as
    /// `now_seconds() + N` at an arbitrary instant buys anywhere from just
    /// over `N - 1` to a full `N` seconds of real headroom, depending on how
    /// far into the current second the call happened to land. At `N` of two
    /// that is the difference between one second and two. Aligning to a
    /// fresh boundary first makes that headroom a near-constant `N` seconds,
    /// which is what the short-deadline tests below need: the deadline has to
    /// stay far enough away for context and provider construction to clear
    /// their own "not already expired" checks, while still being close enough
    /// that the test does not sit around waiting.
    async fn wait_for_second_boundary() {
        let nanos_into_second = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let remaining = Duration::from_secs(1) - Duration::from_nanos(u64::from(nanos_into_second));
        // A short cushion after the boundary keeps the next `now_seconds()`
        // call from landing a hair before it, which would buy a full second
        // less than intended.
        tokio::time::sleep(remaining + Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn discovered_binding_requires_every_profile_and_issuer_pin() {
        let server = MockServer::start().await;
        let token_endpoint = Url::parse(&format!("{}/token", server.uri())).unwrap();
        let authorization = ExchangeAuthorization::first_party(
            exchange(&server, "urn:registry:evidence", &["evidence:invoke"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["evidence:invoke"]),
        )
        .unwrap();
        let matches = |client_id: &str,
                       endpoint: &Url,
                       issuer: &str,
                       audience: Option<&str>,
                       resource: &str,
                       scopes: &[String]| {
            authorization
                .matches_discovered_binding(client_id, endpoint, issuer, audience, resource, scopes)
        };
        let scopes = vec!["evidence:invoke".to_owned()];
        let other_endpoint = Url::parse("https://other.example/token").unwrap();
        assert!(matches(
            "portal-client",
            &token_endpoint,
            "https://issuer.example",
            None,
            "urn:registry:evidence",
            &scopes,
        ));
        assert!(!matches(
            "other-client",
            &token_endpoint,
            "https://issuer.example",
            None,
            "urn:registry:evidence",
            &scopes
        ));
        assert!(!matches(
            "portal-client",
            &other_endpoint,
            "https://issuer.example",
            None,
            "urn:registry:evidence",
            &scopes
        ));
        assert!(!matches(
            "portal-client",
            &token_endpoint,
            "https://other.example",
            None,
            "urn:registry:evidence",
            &scopes
        ));
        assert!(!matches(
            "portal-client",
            &token_endpoint,
            "https://issuer.example",
            Some("https://other.example/token"),
            "urn:registry:evidence",
            &scopes
        ));
        assert!(!matches(
            "portal-client",
            &token_endpoint,
            "https://issuer.example",
            None,
            "urn:registry:other",
            &scopes
        ));
        assert!(!matches(
            "portal-client",
            &token_endpoint,
            "https://issuer.example",
            None,
            "urn:registry:evidence",
            &["other:scope".to_owned()]
        ));
    }

    #[tokio::test]
    async fn discovered_binding_reads_the_token_endpoint_as_a_url() {
        // A published token endpoint is a URL, not a byte string. An issuer may
        // state a default port or an uppercase host and mean the endpoint the
        // profile configured, so the comparison is made between URLs. Refusing
        // the spelling would refuse a correctly configured deployment.
        let configured = Url::parse("https://issuer.example:443/token").unwrap();
        let authorization = ExchangeAuthorization::first_party(
            PrivateKeyJwt::new(
                super::super::private_key_jwt::PrivateKeyJwtConfig::new(
                    configured,
                    "portal-client",
                    key(),
                )
                .with_resource("urn:registry:evidence")
                .with_scopes(["evidence:invoke"]),
            )
            .unwrap(),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["evidence:invoke"]),
        )
        .unwrap();
        let scopes = vec!["evidence:invoke".to_owned()];
        for spelling in [
            "https://issuer.example/token",
            "https://issuer.example:443/token",
            "https://ISSUER.example/token",
        ] {
            assert!(
                authorization.matches_discovered_binding(
                    "portal-client",
                    &Url::parse(spelling).unwrap(),
                    "https://issuer.example",
                    None,
                    "urn:registry:evidence",
                    &scopes,
                ),
                "{spelling} was refused as a different token endpoint"
            );
        }
        assert!(!authorization.matches_discovered_binding(
            "portal-client",
            &Url::parse("https://issuer.example/other").unwrap(),
            "https://issuer.example",
            None,
            "urn:registry:evidence",
            &scopes,
        ));
    }

    async fn endpoint(server: &MockServer, expires_in: Option<i64>) {
        endpoint_stating(server, expires_in.map(|value| json!(value))).await;
    }

    /// Mount a token endpoint whose `expires_in` member is absent, present and
    /// JSON null, or present and a number. The three are distinct statements
    /// about a credential's lifetime, so a test needs to make each of them.
    async fn endpoint_stating(server: &MockServer, expires_in: Option<serde_json::Value>) {
        let mut body = json!({"access_token":"issued-credential", "token_type":"Bearer",
            "issued_token_type":"urn:ietf:params:oauth:token-type:access_token", "scope":"records:read"});
        if let Some(value) = expires_in {
            body["expires_in"] = value;
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn first_party_cache_is_bound_to_one_verified_context_and_one_exchange() {
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
        let deadline = now_seconds().unwrap() + 120;
        let first = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            source(&["records:read"]),
        )
        .unwrap();
        let (left, right) = tokio::join!(first.bearer_token(), first.bearer_token());
        assert!(left.is_ok() && right.is_ok());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let other = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-2", deadline),
            source(&["records:read"]),
        )
        .unwrap();
        other.bearer_token().await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let subjects: Vec<String> = requests
            .iter()
            .map(|request| {
                let body: std::collections::BTreeMap<_, _> =
                    url::form_urlencoded::parse(&request.body)
                        .into_owned()
                        .collect();
                let payload = body["subject_token"].split('.').nth(1).unwrap();
                let claims: Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
                assert_eq!(claims["scope"], "records:read");
                assert_eq!(claims["registry_actor_kind"], "human");
                assert!(claims.get("registry_grant_id").is_none());
                claims["sub"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(subjects, ["person-1", "person-2"]);
    }

    #[tokio::test]
    async fn no_issuer_lifetime_is_bounded_by_the_verified_context_deadline() {
        // RFC 6749 section 5.1 makes `expires_in` optional, so an issuer that
        // states no lifetime is a legitimate deployment, not a broken one. A
        // caller performs more than one request inside one verified context,
        // so the token has to survive between them. The verified context
        // deadline is the bound this provider already refuses past, and it is
        // the one such a token is held to.
        let server = MockServer::start().await;
        endpoint(&server, None).await;
        let first = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read"]),
        )
        .unwrap();
        let held = first.bearer_token().await.unwrap();
        let again = first.bearer_token().await.unwrap();
        assert_eq!(
            held.authorization_header_value(),
            again.authorization_header_value()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn short_issuer_lifetime_still_serves_the_second_request_of_one_operation() {
        // A published-contracts operation asks this provider twice: once for
        // the definitions and once for the assertion. An issuer is entitled to
        // state a lifetime shorter than the refresh margin, and a first-party
        // provider has no second exchange to reach for. The token it holds has
        // to answer both requests for as long as it is actually valid.
        let server = MockServer::start().await;
        endpoint(&server, Some(3)).await;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read"]),
        )
        .unwrap();
        let held = provider.bearer_token().await.unwrap();
        let again = provider.bearer_token().await.unwrap();
        assert_eq!(
            held.authorization_header_value(),
            again.authorization_header_value()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_stated_lifetime_already_elapsed_is_never_cached() {
        // `expires_in: 0` states that the credential is spent, and
        // `PrivateKeyJwt` maps that to the same absent deadline it uses for an
        // omitted lifetime. The two are not the same here: the verified context
        // deadline answers an issuer's silence, never an issuer saying the
        // token has already run out.
        for expires_in in [0, -1] {
            let server = MockServer::start().await;
            endpoint(&server, Some(expires_in)).await;
            let provider = ExchangeAuthorization::first_party(
                exchange(&server, "urn:records", &["records:read"]),
                context("person-1", now_seconds().unwrap() + 120),
                source(&["records:read"]),
            )
            .unwrap();
            provider.bearer_token().await.unwrap();
            assert!(
                matches!(provider.bearer_token().await, Err(TokenError::Unavailable)),
                "expires_in {expires_in} was cached"
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn a_null_lifetime_is_an_issuer_speaking_not_an_issuer_silent() {
        // `"expires_in": null` is malformed against RFC 6749 section 5.1 and
        // common all the same. The member is present, so the issuer did speak
        // about this credential's lifetime, and what it said names no usable
        // one. That is the issuer's own accounting, not the silence the
        // verified context deadline answers, so the credential is used once
        // and dropped.
        let server = MockServer::start().await;
        endpoint_stating(&server, Some(serde_json::Value::Null)).await;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read"]),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn discovered_binding_reads_scopes_as_the_set_they_are() {
        // RFC 6749 section 3.3 makes the scope parameter a set carried as a
        // space-delimited list, and both sides of this comparison refuse a
        // repeated value where they are built. A profile naming the same
        // scopes in another order than the provider was configured with names
        // the same request, so refusing that spelling would refuse a correctly
        // configured deployment.
        let server = MockServer::start().await;
        let token_endpoint = Url::parse(&format!("{}/token", server.uri())).unwrap();
        let authorization = ExchangeAuthorization::first_party(
            exchange(
                &server,
                "urn:registry:evidence",
                &["records:read", "evidence:invoke"],
            ),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read", "evidence:invoke"]),
        )
        .unwrap();
        let matches = |scopes: &[String]| {
            authorization.matches_discovered_binding(
                "portal-client",
                &token_endpoint,
                "https://issuer.example",
                None,
                "urn:registry:evidence",
                scopes,
            )
        };
        assert!(matches(&[
            "records:read".to_owned(),
            "evidence:invoke".to_owned(),
        ]));
        assert!(matches(&[
            "evidence:invoke".to_owned(),
            "records:read".to_owned(),
        ]));
        assert!(!matches(&["records:read".to_owned()]));
        assert!(!matches(&[
            "evidence:invoke".to_owned(),
            "records:read".to_owned(),
            "other:scope".to_owned(),
        ]));
    }

    #[tokio::test]
    async fn a_context_deadline_beyond_the_cache_ceiling_is_accepted_safely() {
        // The outer verified authorization and an access-token cache have
        // different lifetimes. Casework grants may outlive the one-day cache
        // ceiling, and even an extreme valid deadline must not overflow the
        // monotonic cache calculation or extend the cached token past a day.
        let server = MockServer::start().await;
        endpoint(&server, None).await;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", i64::MAX),
            source(&["records:read"]),
        )
        .unwrap();

        provider.bearer_token().await.unwrap();
        let remaining = provider
            .cached
            .read()
            .await
            .as_ref()
            .unwrap()
            .expires_at
            .saturating_duration_since(Instant::now());
        assert!(remaining <= Duration::from_secs(MAX_EXCHANGE_CACHE_SECONDS));
        provider.bearer_token().await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_new_fetch_policy_rearms_the_one_exchange_it_discards() {
        // Applying the client's DNS-pinned rules discards any token obtained
        // under the previous ones. A discarded token must not also consume the
        // single exchange a first-party context allows, or the client built
        // from this provider could never obtain one under the rules it just
        // applied.
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read"]),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        let provider = provider.with_fetch_url_policy(crate::FetchUrlPolicy::dev());
        provider.bearer_token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn cached_person_token_stops_at_verified_context_deadline() {
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
        wait_for_second_boundary().await;
        let deadline_set_at = Instant::now();
        // Read the deadline before building the exchange client: that build
        // loads trust roots and can take most of a second under a parallel
        // test run, which would move the deadline a whole second later.
        let deadline = now_seconds().unwrap() + 2;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            source(&["records:read"]),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        // Sleep to a fixed point relative to `deadline_set_at` rather than a
        // fixed duration from here, so a slow key generation or token round
        // trip above cannot eat into the margin past the deadline: whatever
        // that took, the sleep below still lands about 250ms past it.
        let past_deadline = Duration::from_millis(2250).saturating_sub(deadline_set_at.elapsed());
        tokio::time::sleep(past_deadline).await;
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mismatched_scope_and_expired_context_refuse_before_token_request() {
        let server = MockServer::start().await;
        let exchange = exchange(&server, "urn:records", &["records:read"]);
        let result = ExchangeAuthorization::first_party(
            exchange,
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:write"]),
        );
        assert!(matches!(result, Err(TokenError::Configuration { .. })));
        assert!(matches!(
            ExchangeContext::first_party(
                "issuer",
                "person",
                "audience",
                "generation",
                now_seconds().unwrap() - 1
            ),
            Err(TokenError::Invalid { .. })
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    struct BrokenAuthority;

    struct GrantAuthority;

    #[async_trait]
    impl ExchangeAssertionSource for GrantAuthority {
        async fn assertion(
            &self,
            context: &ExchangeContext,
        ) -> Result<SignedExchangeAssertion, TokenError> {
            let now = now_seconds()?;
            let exp = context.deadline.min(now + 60);
            let claims = json!({"iss":context.issuer, "sub":context.subject, "aud":context.audience,
                "iat":now, "exp":exp, "jti":"grant-assertion", "scope":"records:read",
                "registry_actor_kind":"agent", "registry_grant_id":context.grant_id,
                "registry_grant_client":"portal-client", "registry_grant_resource":"urn:records",
                "registry_grant_exp":context.deadline});
            let header = json!({"alg":"EdDSA", "kid":"test-key", "typ":"JWT"});
            SignedExchangeAssertion::new(
                format!(
                    "{}.{}.signature",
                    URL_SAFE_NO_PAD.encode(header.to_string()),
                    URL_SAFE_NO_PAD.encode(claims.to_string())
                ),
                exp,
            )
        }
    }

    struct DelayedAuthority;

    #[async_trait]
    impl ExchangeAssertionSource for DelayedAuthority {
        async fn assertion(
            &self,
            context: &ExchangeContext,
        ) -> Result<SignedExchangeAssertion, TokenError> {
            tokio::time::sleep(Duration::from_millis(1100)).await;
            GrantAuthority.assertion(context).await
        }
    }

    #[tokio::test]
    async fn assertion_issued_after_acquisition_starts_is_valid_at_receipt() {
        let server = MockServer::start().await;
        endpoint(&server, Some(30)).await;
        let context = ExchangeContext::grant(
            "https://casework.example",
            "agent-1",
            "https://issuer.example",
            "grant-generation-1",
            now_seconds().unwrap() + 120,
            "grant-one",
        )
        .unwrap();
        let provider = ExchangeAuthorization::from_authority(
            exchange(&server, "urn:records", &["records:read"]),
            context,
            Arc::new(DelayedAuthority),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cached_grant_token_stops_at_immutable_grant_deadline() {
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
        wait_for_second_boundary().await;
        let deadline_set_at = Instant::now();
        let grant = ExchangeContext::grant(
            "https://casework.example",
            "agent-1",
            "https://issuer.example",
            "grant-generation-1",
            now_seconds().unwrap() + 2,
            "grant-one",
        )
        .unwrap();
        let provider = ExchangeAuthorization::from_authority(
            exchange(&server, "urn:records", &["records:read"]),
            grant,
            Arc::new(GrantAuthority),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        // Sleep to a fixed point relative to `deadline_set_at` rather than a
        // fixed duration from here, so a slow key generation or token round
        // trip above cannot eat into the margin past the deadline: whatever
        // that took, the sleep below still lands about 250ms past it.
        let past_deadline = Duration::from_millis(2250).saturating_sub(deadline_set_at.elapsed());
        tokio::time::sleep(past_deadline).await;
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn lifetime_less_grant_token_requires_fresh_authority_check() {
        // A remote authority source is renewable specifically so every refresh
        // can re-check whether the grant remains active. Without an issuer
        // lifetime there is no safe refresh instant, so the next request must
        // obtain a fresh assertion instead of keeping the token until the
        // immutable outer context deadline.
        let server = MockServer::start().await;
        endpoint(&server, None).await;
        let grant = ExchangeContext::grant(
            "https://casework.example",
            "agent-1",
            "https://issuer.example",
            "grant-generation-1",
            now_seconds().unwrap() + 120,
            "grant-one",
        )
        .unwrap();
        let provider = ExchangeAuthorization::from_authority(
            exchange(&server, "urn:records", &["records:read"]),
            grant,
            Arc::new(GrantAuthority),
        )
        .unwrap();

        provider.bearer_token().await.unwrap();
        provider.bearer_token().await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[async_trait]
    impl ExchangeAssertionSource for BrokenAuthority {
        async fn assertion(
            &self,
            context: &ExchangeContext,
        ) -> Result<SignedExchangeAssertion, TokenError> {
            let claims = json!({"iss":context.issuer, "sub":context.subject, "aud":context.audience,
                "iat":now_seconds().unwrap(), "exp":now_seconds().unwrap()+60, "jti":"one",
                "scope":"records:read", "registry_actor_kind":"agent", "registry_grant_id":"other-grant",
                "registry_grant_client":"portal-client", "registry_grant_resource":"urn:records",
                "registry_grant_exp":context.deadline});
            let header = json!({"alg":"EdDSA", "kid":"test-key", "typ":"JWT"});
            let jwt = format!(
                "{}.{}.signature",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            SignedExchangeAssertion::new(jwt, claims["exp"].as_i64().unwrap())
        }
    }

    #[tokio::test]
    async fn mismatched_grant_refuses_before_exchange() {
        let server = MockServer::start().await;
        let context = ExchangeContext::grant(
            "https://casework.example",
            "agent-1",
            "https://issuer.example",
            "grant-generation-1",
            now_seconds().unwrap() + 120,
            "expected-grant",
        )
        .unwrap();
        let provider = ExchangeAuthorization::from_authority(
            exchange(&server, "urn:records", &["records:read"]),
            context,
            Arc::new(BrokenAuthority),
        )
        .unwrap();
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Invalid { .. })
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    const SUBJECT_CANARY: &str = "citizen-subject-canary-token";
    const ACTOR_CANARY: &str = "service-actor-canary-token";
    const ACCESS_TOKEN_URN: &str = "urn:ietf:params:oauth:token-type:access_token";

    fn form(request: &wiremock::Request) -> std::collections::BTreeMap<String, String> {
        url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect()
    }

    /// The service's own client-credentials provider: the same client at the
    /// same token endpoint as the exchange, with no resource or scope of its
    /// own, so the credential it caches is not a standing downstream token.
    fn actor(server: &MockServer, client_id: &str) -> Arc<PrivateKeyJwt> {
        Arc::new(unscoped(server, client_id))
    }

    fn unscoped(server: &MockServer, client_id: &str) -> PrivateKeyJwt {
        let endpoint = format!("{}/token", server.uri()).parse().unwrap();
        PrivateKeyJwt::new(super::super::private_key_jwt::PrivateKeyJwtConfig::new(
            endpoint,
            client_id,
            key(),
        ))
        .unwrap()
    }

    fn upstream_subject(token_type: SubjectTokenType, expires_at: i64) -> UpstreamSubjectToken {
        UpstreamSubjectToken::new(SUBJECT_CANARY, token_type, expires_at).unwrap()
    }

    /// Mount the service's client-credentials grant and the token exchange on
    /// one endpoint, as one authorization server serves both.
    async fn upstream_endpoints(server: &MockServer, exchange_expires_in: i64) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACTOR_CANARY, "token_type": "Bearer", "expires_in": 300
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("token-exchange"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "issued-credential", "token_type": "Bearer",
                "issued_token_type": ACCESS_TOKEN_URN, "scope": "records:read",
                "expires_in": exchange_expires_in
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn upstream_exchange_presents_the_access_token_subject_and_the_service_actor() {
        let server = MockServer::start().await;
        upstream_endpoints(&server, 300).await;
        let deadline = now_seconds().unwrap() + 120;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::AccessToken, deadline),
            Some(actor(&server, "portal-client")),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let service = form(&requests[0]);
        assert_eq!(service["grant_type"], "client_credentials");
        assert_eq!(service["client_id"], "portal-client");
        for absent in ["subject_token", "actor_token", "resource", "scope"] {
            assert!(!service.contains_key(absent), "{absent} on the actor grant");
        }
        let exchanged = form(&requests[1]);
        assert_eq!(
            exchanged["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(exchanged["client_id"], "portal-client");
        assert_eq!(exchanged["subject_token"], SUBJECT_CANARY);
        assert_eq!(exchanged["subject_token_type"], ACCESS_TOKEN_URN);
        assert_eq!(exchanged["requested_token_type"], ACCESS_TOKEN_URN);
        assert_eq!(exchanged["actor_token"], ACTOR_CANARY);
        assert_eq!(exchanged["actor_token_type"], ACCESS_TOKEN_URN);
        assert_eq!(exchanged["resource"], "urn:records");
        assert_eq!(exchanged["scope"], "records:read");
        assert!(exchanged.contains_key("client_assertion"));
    }

    #[tokio::test]
    async fn upstream_exchange_without_an_actor_sends_no_actor_parameters() {
        let server = MockServer::start().await;
        upstream_endpoints(&server, 300).await;
        let deadline = now_seconds().unwrap() + 120;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::AccessToken, deadline),
            None,
        )
        .unwrap();
        provider.bearer_token().await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let exchanged = form(&requests[0]);
        assert_eq!(exchanged["subject_token_type"], ACCESS_TOKEN_URN);
        assert!(!exchanged.contains_key("actor_token"));
        assert!(!exchanged.contains_key("actor_token_type"));
    }

    #[tokio::test]
    async fn upstream_subject_token_type_is_the_callers_closed_choice() {
        let server = MockServer::start().await;
        upstream_endpoints(&server, 300).await;
        let deadline = now_seconds().unwrap() + 120;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::Jwt, deadline),
            None,
        )
        .unwrap();
        provider.bearer_token().await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            form(&requests[0])["subject_token_type"],
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(
            SubjectTokenType::Jwt.as_urn(),
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(SubjectTokenType::AccessToken.as_urn(), ACCESS_TOKEN_URN);
    }

    #[tokio::test]
    async fn one_service_actor_token_serves_many_upstream_contexts() {
        let server = MockServer::start().await;
        upstream_endpoints(&server, 300).await;
        let deadline = now_seconds().unwrap() + 120;
        let service = actor(&server, "portal-client");
        for person in ["person-1", "person-2"] {
            ExchangeAuthorization::upstream(
                exchange(&server, "urn:records", &["records:read"]),
                context(person, deadline),
                upstream_subject(SubjectTokenType::AccessToken, deadline),
                Some(Arc::clone(&service)),
            )
            .unwrap()
            .bearer_token()
            .await
            .unwrap();
        }

        let grants: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| form(request)["grant_type"].clone())
            .collect();
        assert_eq!(
            grants,
            [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ]
        );
    }

    #[test]
    fn upstream_subject_token_must_be_bounded_visible_ascii_and_unexpired() {
        let live = now_seconds().unwrap() + 120;
        let oversized = format!("{SUBJECT_CANARY}{}", "a".repeat(32 * 1024));
        for candidate in [
            String::new(),
            oversized,
            format!("{SUBJECT_CANARY} space"),
            format!("{SUBJECT_CANARY}\nnewline"),
            format!("{SUBJECT_CANARY}\u{00e9}"),
        ] {
            let error = UpstreamSubjectToken::new(candidate, SubjectTokenType::AccessToken, live)
                .expect_err("an unusable subject token is refused");
            assert!(matches!(error, TokenError::Invalid { .. }));
            assert!(!error.to_string().contains(SUBJECT_CANARY));
            assert!(!format!("{error:?}").contains(SUBJECT_CANARY));
        }
        let expired = UpstreamSubjectToken::new(
            SUBJECT_CANARY,
            SubjectTokenType::AccessToken,
            now_seconds().unwrap(),
        )
        .expect_err("an expired subject token is refused");
        assert!(matches!(expired, TokenError::Invalid { .. }));
        let accepted = upstream_subject(SubjectTokenType::AccessToken, live);
        assert_eq!(accepted.expires_at(), live);
        assert!(!format!("{accepted:?}").contains(SUBJECT_CANARY));
    }

    #[tokio::test]
    async fn an_upstream_context_cannot_outlive_its_subject_or_carry_a_grant() {
        let server = MockServer::start().await;
        let now = now_seconds().unwrap();
        let outlives = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now + 120),
            upstream_subject(SubjectTokenType::AccessToken, now + 60),
            None,
        );
        assert!(matches!(outlives, Err(TokenError::Invalid { .. })));

        let grant = ExchangeContext::grant(
            "https://casework.example",
            "agent-1",
            "https://issuer.example",
            "grant-generation-1",
            now + 60,
            "grant-1",
        )
        .unwrap();
        let granted = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            grant,
            upstream_subject(SubjectTokenType::AccessToken, now + 60),
            None,
        );
        assert!(matches!(granted, Err(TokenError::Configuration { .. })));

        let unscoped = ExchangeAuthorization::upstream(
            unscoped(&server, "portal-client"),
            context("person-1", now + 60),
            upstream_subject(SubjectTokenType::AccessToken, now + 60),
            None,
        );
        assert!(matches!(unscoped, Err(TokenError::Configuration { .. })));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_actor_of_another_client_or_endpoint_is_refused() {
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        let deadline = now_seconds().unwrap() + 120;
        for foreign in [
            actor(&server, "other-client"),
            actor(&elsewhere, "portal-client"),
        ] {
            let result = ExchangeAuthorization::upstream(
                exchange(&server, "urn:records", &["records:read"]),
                context("person-1", deadline),
                upstream_subject(SubjectTokenType::AccessToken, deadline),
                Some(foreign),
            );
            assert!(matches!(result, Err(TokenError::Configuration { .. })));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(elsewhere.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_upstream_token_is_not_held_past_the_subject_token_expiry() {
        // The issuer states five minutes, but the subject token the host
        // verified ends in two seconds. The context deadline is that expiry,
        // and the exchanged token is never handed out beyond it.
        let server = MockServer::start().await;
        upstream_endpoints(&server, 300).await;
        wait_for_second_boundary().await;
        let deadline_set_at = Instant::now();
        let subject_expiry = now_seconds().unwrap() + 2;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", subject_expiry),
            upstream_subject(SubjectTokenType::AccessToken, subject_expiry),
            None,
        )
        .unwrap();
        let held = provider.bearer_token().await.unwrap();
        let again = provider.bearer_token().await.unwrap();
        assert_eq!(
            held.authorization_header_value(),
            again.authorization_header_value()
        );
        let past_deadline = Duration::from_millis(2250).saturating_sub(deadline_set_at.elapsed());
        tokio::time::sleep(past_deadline).await;
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn upstream_failures_never_echo_token_material_and_exchange_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": ACTOR_CANARY, "token_type": "Bearer", "expires_in": 300
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("token-exchange"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": format!("rejected {SUBJECT_CANARY} acting as {ACTOR_CANARY}")
            })))
            .mount(&server)
            .await;
        let deadline = now_seconds().unwrap() + 120;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::AccessToken, deadline),
            Some(actor(&server, "portal-client")),
        )
        .unwrap();
        let error = provider.bearer_token().await.unwrap_err();
        assert!(matches!(error, TokenError::Refused { .. }));
        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            format!("{provider:?}"),
        ] {
            assert!(!rendered.contains(SUBJECT_CANARY), "{rendered}");
            assert!(!rendered.contains(ACTOR_CANARY), "{rendered}");
        }
        // A refused exchange spends the context: the verified subject token
        // is not presented a second time.
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// An upstream exchange whose token response carries `scope`, if given.
    async fn upstream_with_stated_scope(
        server: &MockServer,
        stated: Option<&str>,
    ) -> ExchangeAuthorization {
        let mut body = json!({"access_token": "issued-credential", "token_type": "Bearer",
            "issued_token_type": ACCESS_TOKEN_URN, "expires_in": 300});
        if let Some(scope) = stated {
            body["scope"] = json!(scope);
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
        let deadline = now_seconds().unwrap() + 120;
        ExchangeAuthorization::upstream(
            exchange(server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::AccessToken, deadline),
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_upstream_exchange_whose_scope_is_unstated_is_accepted() {
        // RFC 6749 section 5.1: an omitted scope is the scope requested. The
        // resource server still enforces the scopes it requires on the token.
        let server = MockServer::start().await;
        let provider = upstream_with_stated_scope(&server, None).await;
        assert!(provider.bearer_token().await.is_ok());
    }

    #[tokio::test]
    async fn an_upstream_exchange_whose_stated_scope_is_narrowed_is_refused() {
        // An issuer may drop requested scopes the subject token did not carry
        // and still answer 200. A stated scope missing a requested one is
        // refused.
        let server = MockServer::start().await;
        let provider = upstream_with_stated_scope(&server, Some("other:read")).await;
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::ScopeNarrowed)
        ));
    }

    #[tokio::test]
    async fn a_refused_actor_grant_stops_before_the_subject_token_is_sent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"})),
            )
            .mount(&server)
            .await;
        let deadline = now_seconds().unwrap() + 120;
        let provider = ExchangeAuthorization::upstream(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", deadline),
            upstream_subject(SubjectTokenType::AccessToken, deadline),
            Some(actor(&server, "portal-client")),
        )
        .unwrap();
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Refused { .. })
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!form(&requests[0]).contains_key("subject_token"));
    }
}
