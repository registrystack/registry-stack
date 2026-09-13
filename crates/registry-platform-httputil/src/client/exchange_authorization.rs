//! Context-bound RFC 8693 authorization for service clients.
//!
//! The host supplies one immutable, already verified context. A first-party
//! source signs that context once; a remote source may obtain a fresh assertion
//! from its owning authority on every refresh. Neither source can extend the
//! context deadline. A new person or grant requires a new provider instance.

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
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    outbound::{build_client, read_failure_kind, send_failure_kind, OutboundOptions},
    private_key_jwt::PrivateKeyJwt,
    token::{BearerToken, TokenError, TokenProvider},
    ServiceBaseUrl,
};

const MAX_CONTEXT_TEXT_BYTES: usize = 512;
const MAX_ATTRIBUTES_BYTES: usize = 4096;
const MAX_ASSERTION_BYTES: usize = 32 * 1024;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 60;
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
        if ![&issuer, &subject, &audience, &generation]
            .into_iter()
            .all(|value| valid_text(value))
            || grant_id.as_ref().is_some_and(|value| !valid_text(value))
            || deadline <= now_seconds()?
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
/// First-party instances exchange once and must be reconstructed after the
/// issued token expires. Remote sources may renew only by obtaining a new
/// assertion from their owning authority, which can refuse a revoked grant.
pub struct ExchangeAuthorization {
    exchange: PrivateKeyJwt,
    context: ExchangeContext,
    source: Arc<dyn ExchangeAssertionSource>,
    renewable: bool,
    cached: RwLock<Option<CachedExchange>>,
    refresh_lock: Mutex<bool>,
}

impl ExchangeAuthorization {
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
        Self::build(exchange, context, Arc::new(source), false)
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
        Self::build(exchange, context, source, true)
    }

    fn build(
        exchange: PrivateKeyJwt,
        context: ExchangeContext,
        source: Arc<dyn ExchangeAssertionSource>,
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
}

#[async_trait]
impl TokenProvider for ExchangeAuthorization {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        if now_seconds()? >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        let now = Instant::now();
        if let Some(token) = self
            .cached
            .read()
            .await
            .as_ref()
            .filter(|entry| entry.expires_at.saturating_duration_since(now) > REFRESH_MARGIN)
            .map(|entry| entry.token.clone())
        {
            return Ok(token);
        }
        let mut attempted = self.refresh_lock.lock().await;
        let now = Instant::now();
        if let Some(token) = self
            .cached
            .read()
            .await
            .as_ref()
            .filter(|entry| entry.expires_at.saturating_duration_since(now) > REFRESH_MARGIN)
            .map(|entry| entry.token.clone())
        {
            return Ok(token);
        }
        if !self.renewable && *attempted {
            return Err(TokenError::Unavailable);
        }
        // First-party verification is a snapshot of host-owned source facts.
        // A failed or uncacheable exchange must also require a new snapshot.
        *attempted = true;
        let wall_now = now_seconds()?;
        if wall_now >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        let assertion = self.source.assertion(&self.context).await?;
        self.validate_assertion(&assertion, wall_now)?;
        let acquired = self.exchange.exchange_acquired(&assertion.jwt).await?;
        if now_seconds()? >= self.context.deadline {
            return Err(TokenError::Unavailable);
        }
        let deadline = acquired.expires_at.map(|issued| {
            issued.min(now + Duration::from_secs((self.context.deadline - wall_now) as u64))
        });
        if let Some(expires_at) = deadline {
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
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use wiremock::{
        matchers::{method, path},
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

    async fn endpoint(server: &MockServer, expires_in: Option<i64>) {
        let mut body = json!({"access_token":"issued-credential", "token_type":"Bearer",
            "issued_token_type":"urn:ietf:params:oauth:token-type:access_token", "scope":"records:read"});
        if let Some(value) = expires_in {
            body["expires_in"] = json!(value);
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
    async fn no_issuer_lifetime_requires_fresh_host_context_after_first_exchange() {
        let server = MockServer::start().await;
        endpoint(&server, None).await;
        let first = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 120),
            source(&["records:read"]),
        )
        .unwrap();
        first.bearer_token().await.unwrap();
        assert!(matches!(
            first.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cached_person_token_stops_at_verified_context_deadline() {
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
        let provider = ExchangeAuthorization::first_party(
            exchange(&server, "urn:records", &["records:read"]),
            context("person-1", now_seconds().unwrap() + 2),
            source(&["records:read"]),
        )
        .unwrap();
        provider.bearer_token().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
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

    #[tokio::test]
    async fn cached_grant_token_stops_at_immutable_grant_deadline() {
        let server = MockServer::start().await;
        endpoint(&server, Some(300)).await;
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
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(
            provider.bearer_token().await,
            Err(TokenError::Unavailable)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
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
}
