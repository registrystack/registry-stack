// SPDX-License-Identifier: Apache-2.0
//! Token-exchange primitives for minting Notary-bound transaction tokens.

use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use http::{header, HeaderValue, StatusCode};
use registry_platform_crypto::{
    verify, PublicJwk, SigningAlgorithm, SigningError, SigningProvider,
};
use registry_platform_oidc::{TokenVerifier, VerifiedToken};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;

pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const NOTARY_TRANSACTION_JWT_TYP: &str = "at+jwt";
pub const NOTARY_AUTHORIZATION_DETAILS_TYPE: &str = "registry_notary_evidence_transaction";
pub const NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION: &str =
    "registry-notary-authorization-details/v1";

#[derive(Clone, Debug)]
pub struct TokenExchangeConfig {
    pub issuer: String,
    pub notary_audience: String,
    pub allowed_subject_token_types: Vec<String>,
    pub requested_token_type: String,
    pub issued_token_type: String,
    pub jwt_typ: String,
    pub default_lifetime: Duration,
    pub max_lifetime: Duration,
    pub required_scopes: Vec<String>,
    pub sender_constraint: SenderConstraintPolicy,
    pub require_session_binding: bool,
    pub session_binding_secret: Option<String>,
    pub subject_binding_claim: Option<String>,
    pub audit_hash_secret: String,
}

impl TokenExchangeConfig {
    #[must_use]
    pub fn notary_transaction_token(
        issuer: impl Into<String>,
        notary_audience: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            notary_audience: notary_audience.into(),
            allowed_subject_token_types: vec![ACCESS_TOKEN_TYPE.to_string()],
            requested_token_type: ACCESS_TOKEN_TYPE.to_string(),
            issued_token_type: ACCESS_TOKEN_TYPE.to_string(),
            jwt_typ: NOTARY_TRANSACTION_JWT_TYP.to_string(),
            default_lifetime: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(600),
            required_scopes: vec!["registry_notary:self_attestation".to_string()],
            sender_constraint: SenderConstraintPolicy::Disabled,
            require_session_binding: true,
            session_binding_secret: None,
            subject_binding_claim: None,
            audit_hash_secret: "registry-platform-sts-local-audit".to_string(),
        }
    }

    #[must_use]
    pub fn with_session_binding_secret(mut self, secret: impl Into<String>) -> Self {
        self.session_binding_secret = Some(secret.into());
        self
    }

    #[must_use]
    pub fn with_subject_binding_claim(mut self, claim: impl Into<String>) -> Self {
        self.subject_binding_claim = Some(claim.into());
        self
    }

    #[must_use]
    pub fn with_audit_hash_secret(mut self, secret: impl Into<String>) -> Self {
        self.audit_hash_secret = secret.into();
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderConstraintPolicy {
    Required,
    Optional,
    Disabled,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<NotaryAuthorizationDetails>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_token_type: Option<String>,
}

impl fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeRequest")
            .field("grant_type", &self.grant_type)
            .field("subject_token", &RedactedLen(self.subject_token.len()))
            .field("subject_token_type", &self.subject_token_type)
            .field("requested_token_type", &self.requested_token_type)
            .field("audience", &self.audience)
            .field("resource", &self.resource)
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .field(
                "actor_token",
                &self.actor_token.as_ref().map(|s| RedactedLen(s.len())),
            )
            .field("actor_token_type", &self.actor_token_type)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryAuthorizationDetails {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<NotaryClaimRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<NotaryAuthorizationSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryClaimRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryAuthorizationSubject {
    pub binding_claim: String,
    pub id_type: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl fmt::Debug for TokenExchangeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeResponse")
            .field("access_token", &RedactedLen(self.access_token.len()))
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExchangeContext {
    pub client_id: Option<String>,
    pub tenant: Option<String>,
    pub session_id: Option<String>,
    pub correlation_id: Option<String>,
    pub subject_id_hash: Option<String>,
    pub actor_id_hash: Option<String>,
    pub delegation_ref: Option<String>,
    pub session_binding: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSubjectToken {
    pub subject: String,
    pub issuer: String,
    pub scopes: Vec<String>,
    pub confirmation: Option<Value>,
    pub actor: Option<TokenActor>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TokenActor {
    pub actor_id_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
}

#[async_trait]
pub trait SubjectTokenVerifier: Send + Sync {
    async fn verify_subject_token(&self, token: &str) -> Result<VerifiedSubjectToken, StsError>;
}

pub struct OidcSubjectTokenVerifier {
    verifier: Arc<TokenVerifier>,
    subject_claim: String,
}

impl OidcSubjectTokenVerifier {
    #[must_use]
    pub fn new(verifier: Arc<TokenVerifier>, subject_claim: impl Into<String>) -> Self {
        Self {
            verifier,
            subject_claim: subject_claim.into(),
        }
    }
}

impl fmt::Debug for OidcSubjectTokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcSubjectTokenVerifier")
            .field("subject_claim", &self.subject_claim)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SubjectTokenVerifier for OidcSubjectTokenVerifier {
    async fn verify_subject_token(&self, token: &str) -> Result<VerifiedSubjectToken, StsError> {
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| StsError::SubjectTokenInvalid)?;
        verified_subject_from_oidc(verified, &self.subject_claim)
    }
}

fn verified_subject_from_oidc(
    verified: VerifiedToken,
    subject_claim: &str,
) -> Result<VerifiedSubjectToken, StsError> {
    let subject = if subject_claim == "sub" {
        verified.claims.sub.clone()
    } else {
        verified
            .claims
            .extra
            .get(subject_claim)
            .and_then(Value::as_str)
            .map(str::to_string)
    }
    .filter(|value| !value.trim().is_empty())
    .ok_or(StsError::SubjectBindingMissing)?;

    let confirmation = verified.claims.extra.get("cnf").cloned();
    Ok(VerifiedSubjectToken {
        subject,
        issuer: verified.claims.iss.unwrap_or_default(),
        scopes: verified.scopes,
        confirmation,
        actor: None,
    })
}

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check_and_increment(
        &self,
        scope: &RateLimitScope,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        now: OffsetDateTime,
    ) -> Result<RateLimitOutcome, RateLimitError>;
}

#[async_trait]
pub trait StsAuditSink: Send + Sync {
    async fn record_token_mint(&self, event: TokenMintAuditEvent) -> Result<(), StsAuditError>;
}

#[derive(Debug, Default)]
pub struct NoopStsAuditSink;

#[async_trait]
impl StsAuditSink for NoopStsAuditSink {
    async fn record_token_mint(&self, _event: TokenMintAuditEvent) -> Result<(), StsAuditError> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenMintAuditEvent {
    pub event_type: String,
    pub issuer: String,
    pub audience: String,
    pub client_id: Option<String>,
    pub subject_hash: String,
    pub jti_hash: String,
    pub authorization_details_hash: String,
    pub session_id: Option<String>,
    pub correlation_id: Option<String>,
    pub actor_id_hash: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Error)]
pub enum StsAuditError {
    #[error("audit sink unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RateLimitScope(String);

impl RateLimitScope {
    pub fn new(value: impl Into<String>) -> Result<Self, RateLimitError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RateLimitError::InvalidKey);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RateLimitKey(String);

impl RateLimitKey {
    pub fn new(value: impl Into<String>) -> Result<Self, RateLimitError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RateLimitError::InvalidKey);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub max_requests: u32,
    pub window: Duration,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed { remaining: u32 },
    Denied { retry_after: Duration },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("rate limit key is invalid")]
    InvalidKey,
    #[error("rate limit store unavailable")]
    StoreUnavailable,
}

#[derive(Debug, Default)]
pub struct InMemoryRateLimitStore {
    state: Mutex<RateLimitState>,
}

const RATE_LIMIT_CLEANUP_BATCH: usize = 64;

#[derive(Debug, Default)]
struct RateLimitState {
    counters: HashMap<(RateLimitScope, RateLimitKey), WindowCounter>,
    expirations: BinaryHeap<Reverse<WindowExpiry>>,
}

#[derive(Debug, Clone)]
struct WindowCounter {
    window_start: i64,
    expires_at: i64,
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowExpiry {
    expires_at: i64,
    scope: RateLimitScope,
    key: RateLimitKey,
}

impl Ord for WindowExpiry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.scope.0.cmp(&other.scope.0))
            .then_with(|| self.key.0.cmp(&other.key.0))
    }
}

impl PartialOrd for WindowExpiry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl RateLimitState {
    fn prune_expired(&mut self, now_unix: i64, max_popped: usize) {
        let mut popped = 0;
        while popped < max_popped {
            let Some(Reverse(expiry)) = self.expirations.peek() else {
                break;
            };
            if expiry.expires_at > now_unix {
                break;
            }
            let Reverse(expiry) = self
                .expirations
                .pop()
                .expect("peek confirmed an expiry entry");
            popped += 1;
            let counter_key = (expiry.scope, expiry.key);
            if self
                .counters
                .get(&counter_key)
                .is_some_and(|counter| counter.expires_at == expiry.expires_at)
            {
                self.counters.remove(&counter_key);
            }
        }
    }
}

#[async_trait]
impl RateLimitStore for InMemoryRateLimitStore {
    async fn check_and_increment(
        &self,
        scope: &RateLimitScope,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        now: OffsetDateTime,
    ) -> Result<RateLimitOutcome, RateLimitError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RateLimitError::StoreUnavailable)?;
        let now_unix = now.unix_timestamp();
        let window_secs = policy.window.as_secs().max(1) as i64;
        state.prune_expired(now_unix, RATE_LIMIT_CLEANUP_BATCH);
        let counter_key = (scope.clone(), key.clone());
        let mut queue_expiry = None;
        let outcome = {
            let counter = state
                .counters
                .entry(counter_key.clone())
                .or_insert_with(|| {
                    let expires_at = now_unix.saturating_add(window_secs);
                    queue_expiry = Some(expires_at);
                    WindowCounter {
                        window_start: now_unix,
                        expires_at,
                        count: 0,
                    }
                });
            if now_unix >= counter.expires_at {
                let expires_at = now_unix.saturating_add(window_secs);
                counter.window_start = now_unix;
                counter.expires_at = expires_at;
                counter.count = 0;
                queue_expiry = Some(expires_at);
            }
            if counter.count >= policy.max_requests {
                let retry_after = counter.expires_at.saturating_sub(now_unix) as u64;
                RateLimitOutcome::Denied {
                    retry_after: Duration::from_secs(retry_after.max(1)),
                }
            } else {
                counter.count += 1;
                RateLimitOutcome::Allowed {
                    remaining: policy.max_requests.saturating_sub(counter.count),
                }
            }
        };
        if let Some(expires_at) = queue_expiry {
            state.expirations.push(Reverse(WindowExpiry {
                expires_at,
                scope: scope.clone(),
                key: key.clone(),
            }));
        }
        Ok(outcome)
    }
}

pub struct TokenExchangeService {
    verifier: Arc<dyn SubjectTokenVerifier>,
    signer: Arc<dyn SigningProvider>,
    rate_limiter: Arc<dyn RateLimitStore>,
    audit_sink: Arc<dyn StsAuditSink>,
    config: TokenExchangeConfig,
    rate_limit_policy: RateLimitPolicy,
}

impl TokenExchangeService {
    #[must_use]
    pub fn new(
        verifier: Arc<dyn SubjectTokenVerifier>,
        signer: Arc<dyn SigningProvider>,
        rate_limiter: Arc<dyn RateLimitStore>,
        config: TokenExchangeConfig,
    ) -> Self {
        Self {
            verifier,
            signer,
            rate_limiter,
            audit_sink: Arc::new(NoopStsAuditSink),
            config,
            rate_limit_policy: RateLimitPolicy::default(),
        }
    }

    #[must_use]
    pub fn with_audit_sink(mut self, audit_sink: Arc<dyn StsAuditSink>) -> Self {
        self.audit_sink = audit_sink;
        self
    }

    #[must_use]
    pub fn with_rate_limit_policy(mut self, policy: RateLimitPolicy) -> Self {
        self.rate_limit_policy = policy;
        self
    }

    pub async fn exchange(
        &self,
        request: TokenExchangeRequest,
        context: ExchangeContext,
        now: OffsetDateTime,
    ) -> Result<TokenExchangeResponse, StsError> {
        validate_request(&request, &self.config)?;
        validate_exchange_context_shape(&context, &self.config)?;
        let rate_key_material = context
            .client_id
            .as_deref()
            .unwrap_or(request.subject_token.as_str());
        self.check_rate_limit("client", rate_key_material, now)
            .await?;
        let subject = self
            .verifier
            .verify_subject_token(&request.subject_token)
            .await?;
        self.check_rate_limit("subject", &subject.subject, now)
            .await?;
        self.exchange_verified(request, context, subject, now).await
    }

    async fn exchange_verified(
        &self,
        request: TokenExchangeRequest,
        context: ExchangeContext,
        subject: VerifiedSubjectToken,
        now: OffsetDateTime,
    ) -> Result<TokenExchangeResponse, StsError> {
        validate_request(&request, &self.config)?;
        validate_exchange_context(&context, &self.config, &subject)?;
        validate_sender_constraint(&subject, self.config.sender_constraint)?;
        let scopes = requested_scopes(&request, &self.config, &subject)?;
        let authorization_details = validate_authorization_details(&request, &self.config)?;
        let authorization_details_json = serde_json::to_string(&authorization_details)?;
        let lifetime = self.config.default_lifetime.min(self.config.max_lifetime);
        let iat = now.unix_timestamp();
        let exp = now
            .checked_add(duration_to_time(lifetime)?)
            .ok_or(StsError::ClockOverflow)?
            .unix_timestamp();
        let jti = Ulid::new().to_string();
        let jwt = self
            .sign_transaction_token(
                &subject,
                &context,
                &scopes,
                &authorization_details,
                iat,
                exp,
                &jti,
            )
            .await?;
        self.audit_sink
            .record_token_mint(TokenMintAuditEvent {
                event_type: "registry-platform-sts.token_minted".to_string(),
                issuer: self.config.issuer.clone(),
                audience: self.config.notary_audience.clone(),
                client_id: context.client_id.clone(),
                subject_hash: hmac_sha256_label(&self.config.audit_hash_secret, &subject.subject),
                jti_hash: hmac_sha256_label(&self.config.audit_hash_secret, &jti),
                authorization_details_hash: hmac_sha256_label(
                    &self.config.audit_hash_secret,
                    &authorization_details_json,
                ),
                session_id: context.session_id.clone(),
                correlation_id: context.correlation_id.clone(),
                actor_id_hash: subject
                    .actor
                    .as_ref()
                    .map(|actor| actor.actor_id_hash.clone())
                    .or_else(|| context.actor_id_hash.clone()),
                issued_at: iat,
                expires_at: exp,
            })
            .await?;
        Ok(TokenExchangeResponse {
            access_token: jwt,
            issued_token_type: self.config.issued_token_type.clone(),
            token_type: "Bearer".to_string(),
            expires_in: lifetime.as_secs(),
            scope: Some(scopes.join(" ")),
        })
    }

    #[must_use]
    pub fn public_jwks(&self) -> Value {
        public_jwks(self.signer.as_ref())
    }

    #[must_use]
    pub fn authorization_server_metadata(&self, token_endpoint: &str, jwks_uri: &str) -> Value {
        authorization_server_metadata(&self.config, token_endpoint, jwks_uri)
    }

    async fn check_rate_limit(
        &self,
        scope_name: &str,
        key_material: &str,
        now: OffsetDateTime,
    ) -> Result<(), StsError> {
        let scope =
            RateLimitScope::new(format!("registry-platform-sts/token-exchange/{scope_name}"))?;
        let key = RateLimitKey::new(sha256_hex(key_material))?;
        match self
            .rate_limiter
            .check_and_increment(&scope, &key, self.rate_limit_policy, now)
            .await?
        {
            RateLimitOutcome::Allowed { .. } => Ok(()),
            RateLimitOutcome::Denied { retry_after } => Err(StsError::RateLimited { retry_after }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_transaction_token(
        &self,
        subject: &VerifiedSubjectToken,
        context: &ExchangeContext,
        scopes: &[String],
        authorization_details: &[NotaryAuthorizationDetails],
        iat: i64,
        exp: i64,
        jti: &str,
    ) -> Result<String, StsError> {
        let alg = jwt_alg(self.signer.algorithm());
        let header = json!({
            "alg": alg,
            "kid": self.signer.key_id(),
            "typ": self.config.jwt_typ,
        });
        let mut payload = Map::new();
        payload.insert("iss".to_string(), json!(self.config.issuer));
        payload.insert("aud".to_string(), json!(self.config.notary_audience));
        payload.insert("sub".to_string(), json!(subject.subject));
        if let Some(client_id) = context.client_id.as_ref() {
            payload.insert("client_id".to_string(), json!(client_id));
        }
        if let Some(tenant) = context.tenant.as_ref() {
            payload.insert("tenant".to_string(), json!(tenant));
        }
        if let Some(session_id) = context.session_id.as_ref() {
            payload.insert("sid".to_string(), json!(session_id));
        }
        if let Some(correlation_id) = context.correlation_id.as_ref() {
            payload.insert("correlation_id".to_string(), json!(correlation_id));
        }
        payload.insert("iat".to_string(), json!(iat));
        payload.insert("nbf".to_string(), json!(iat));
        payload.insert("exp".to_string(), json!(exp));
        payload.insert("jti".to_string(), json!(jti));
        payload.insert("scope".to_string(), json!(scopes.join(" ")));
        payload.insert(
            "authorization_details".to_string(),
            serde_json::to_value(authorization_details)?,
        );
        if self.config.sender_constraint != SenderConstraintPolicy::Disabled {
            if let Some(cnf) = &subject.confirmation {
                payload.insert("cnf".to_string(), cnf.clone());
            }
        }
        if let Some(actor) = subject.actor.as_ref() {
            payload.insert("act".to_string(), serde_json::to_value(actor)?);
        } else if let Some(actor_id_hash) = context.actor_id_hash.as_ref() {
            let actor = TokenActor {
                actor_id_hash: actor_id_hash.clone(),
                assurance: None,
                delegation_ref: context.delegation_ref.clone(),
            };
            payload.insert("act".to_string(), serde_json::to_value(actor)?);
        }
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let public_jwk = self.signer.public_jwk();
        if public_jwk.kid.as_deref() != Some(self.signer.key_id()) {
            return Err(StsError::Signing(SigningError::KeyIdMismatch));
        }
        let signature = self.signer.sign(signing_input.as_bytes()).await?;
        verify(signing_input.as_bytes(), &signature, &public_jwk)
            .map_err(|err| StsError::Signing(SigningError::Crypto(err)))?;
        Ok(format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

impl fmt::Debug for TokenExchangeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeService")
            .field("config", &self.config)
            .field("signer_kid", &self.signer.key_id())
            .field("signer_alg", &self.signer.algorithm())
            .field("rate_limit_policy", &self.rate_limit_policy)
            .finish_non_exhaustive()
    }
}

fn validate_exchange_context_shape(
    context: &ExchangeContext,
    config: &TokenExchangeConfig,
) -> Result<(), StsError> {
    if config.require_session_binding
        && (context
            .session_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            || context
                .correlation_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty()))
    {
        return Err(StsError::SessionBindingMissing);
    }
    Ok(())
}

fn validate_exchange_context(
    context: &ExchangeContext,
    config: &TokenExchangeConfig,
    subject: &VerifiedSubjectToken,
) -> Result<(), StsError> {
    validate_exchange_context_shape(context, config)?;
    if let Some(secret) = config.session_binding_secret.as_deref() {
        let session_id = context
            .session_id
            .as_deref()
            .ok_or(StsError::SessionBindingMissing)?;
        let correlation_id = context
            .correlation_id
            .as_deref()
            .ok_or(StsError::SessionBindingMissing)?;
        let subject_id_hash = context
            .subject_id_hash
            .as_deref()
            .ok_or(StsError::SubjectBindingMissing)?;
        let client_id = context.client_id.as_deref().unwrap_or("");
        let tenant = context.tenant.as_deref().unwrap_or("");
        let actor_id_hash = effective_actor_id_hash(context, subject).unwrap_or("");
        let delegation_ref = effective_delegation_ref(context, subject).unwrap_or("");
        let expected = session_binding_mac(
            secret,
            SessionBindingMacInput {
                session_id,
                correlation_id,
                verified_subject: &subject.subject,
                subject_id_hash,
                client_id,
                tenant,
                actor_id_hash,
                delegation_ref,
            },
        );
        let provided = context.session_binding.as_deref().unwrap_or("");
        if expected.len() != provided.len()
            || expected.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1
        {
            return Err(StsError::SessionBindingInvalid);
        }
    }
    Ok(())
}

fn validate_request(
    request: &TokenExchangeRequest,
    config: &TokenExchangeConfig,
) -> Result<(), StsError> {
    if request.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return Err(StsError::InvalidGrantType);
    }
    if request.subject_token.trim().is_empty() {
        return Err(StsError::SubjectTokenMissing);
    }
    if !config
        .allowed_subject_token_types
        .iter()
        .any(|value| value == &request.subject_token_type)
    {
        return Err(StsError::UnsupportedSubjectTokenType);
    }
    if request
        .requested_token_type
        .as_deref()
        .is_some_and(|value| value != config.requested_token_type)
    {
        return Err(StsError::UnsupportedRequestedTokenType);
    }
    if request
        .audience
        .as_deref()
        .is_some_and(|value| value != config.notary_audience)
        || request
            .resource
            .as_deref()
            .is_some_and(|value| value != config.notary_audience)
    {
        return Err(StsError::AudienceMismatch);
    }
    Ok(())
}

fn validate_authorization_details(
    request: &TokenExchangeRequest,
    config: &TokenExchangeConfig,
) -> Result<Vec<NotaryAuthorizationDetails>, StsError> {
    let details = request
        .authorization_details
        .as_ref()
        .filter(|details| !details.is_empty())
        .ok_or(StsError::AuthorizationDetailsMissing)?;
    if details.len() != 1 {
        return Err(StsError::AuthorizationDetailsInvalid);
    }
    let detail = &details[0];
    if detail.detail_type != NOTARY_AUTHORIZATION_DETAILS_TYPE
        || detail.schema_version != NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
        || detail.actions.as_slice() != ["evaluate"]
        || detail.locations.len() != 1
        || detail.locations.first() != Some(&config.notary_audience)
        || detail.claims.is_empty()
        || detail.access_mode.as_deref() != Some("self_attestation")
    {
        return Err(StsError::AuthorizationDetailsInvalid);
    }

    let mut seen_claim_ids = HashSet::new();
    let mut claims = Vec::with_capacity(detail.claims.len());
    for claim in &detail.claims {
        let id = canonical_claim_field(&claim.id)?;
        if !seen_claim_ids.insert(id.clone()) {
            return Err(StsError::AuthorizationDetailsInvalid);
        }
        let version = claim
            .version
            .as_deref()
            .ok_or(StsError::AuthorizationDetailsInvalid)
            .and_then(canonical_claim_field)?;
        claims.push(NotaryClaimRef {
            id,
            version: Some(version),
        });
    }
    claims.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.version.cmp(&right.version))
    });

    let purpose = canonical_required_text(detail.purpose.as_deref())?;
    let disclosure = canonical_required_text(detail.disclosure.as_deref())?;
    let format = canonical_required_text(detail.format.as_deref())?;
    let subject = detail
        .subject
        .as_ref()
        .ok_or(StsError::AuthorizationDetailsInvalid)?;
    let binding_claim = canonical_claim_field(&subject.binding_claim)?;
    let id_type = canonical_claim_field(&subject.id_type)?;
    if config
        .subject_binding_claim
        .as_deref()
        .is_some_and(|expected| binding_claim != expected)
    {
        return Err(StsError::SubjectBindingMismatch);
    }
    Ok(vec![NotaryAuthorizationDetails {
        detail_type: NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION.to_string(),
        actions: vec!["evaluate".to_string()],
        locations: vec![config.notary_audience.clone()],
        claims,
        disclosure: Some(disclosure),
        format: Some(format),
        purpose: Some(purpose),
        subject: Some(NotaryAuthorizationSubject {
            binding_claim,
            id_type,
        }),
        access_mode: Some("self_attestation".to_string()),
    }])
}

fn effective_actor_id_hash<'a>(
    context: &'a ExchangeContext,
    subject: &'a VerifiedSubjectToken,
) -> Option<&'a str> {
    subject
        .actor
        .as_ref()
        .map(|actor| actor.actor_id_hash.as_str())
        .or(context.actor_id_hash.as_deref())
}

fn effective_delegation_ref<'a>(
    context: &'a ExchangeContext,
    subject: &'a VerifiedSubjectToken,
) -> Option<&'a str> {
    if let Some(actor) = subject.actor.as_ref() {
        actor.delegation_ref.as_deref()
    } else {
        context.delegation_ref.as_deref()
    }
}

fn canonical_required_text(value: Option<&str>) -> Result<String, StsError> {
    let value = value.ok_or(StsError::AuthorizationDetailsInvalid)?.trim();
    if value.is_empty() {
        return Err(StsError::AuthorizationDetailsInvalid);
    }
    Ok(value.to_string())
}

fn canonical_claim_field(value: &str) -> Result<String, StsError> {
    let canonical = value.trim();
    if canonical.is_empty() || canonical != value {
        return Err(StsError::AuthorizationDetailsInvalid);
    }
    Ok(canonical.to_string())
}

fn validate_sender_constraint(
    subject: &VerifiedSubjectToken,
    policy: SenderConstraintPolicy,
) -> Result<(), StsError> {
    if policy == SenderConstraintPolicy::Required && subject.confirmation.is_none() {
        return Err(StsError::SenderConstraintMissing);
    }
    Ok(())
}

fn requested_scopes(
    request: &TokenExchangeRequest,
    config: &TokenExchangeConfig,
    subject: &VerifiedSubjectToken,
) -> Result<Vec<String>, StsError> {
    let scopes = request
        .scope
        .as_deref()
        .map(split_scope)
        .unwrap_or_else(|| config.required_scopes.clone());
    if !config
        .required_scopes
        .iter()
        .all(|required| scopes.contains(required))
    {
        return Err(StsError::RequiredScopeMissing);
    }
    if !scopes.iter().all(|scope| subject.scopes.contains(scope)) {
        return Err(StsError::ScopeNotGranted);
    }
    Ok(scopes)
}

fn split_scope(value: &str) -> Vec<String> {
    value
        .split_ascii_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect()
}

fn duration_to_time(value: Duration) -> Result<time::Duration, StsError> {
    time::Duration::try_from(value).map_err(|_| StsError::ClockOverflow)
}

fn jwt_alg(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::Rs256 => "RS256",
    }
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex_bytes(&digest)
}

type HmacSha256 = Hmac<Sha256>;

#[must_use]
pub struct SessionBindingMacInput<'a> {
    pub session_id: &'a str,
    pub correlation_id: &'a str,
    pub verified_subject: &'a str,
    pub subject_id_hash: &'a str,
    pub client_id: &'a str,
    pub tenant: &'a str,
    pub actor_id_hash: &'a str,
    pub delegation_ref: &'a str,
}

#[must_use]
pub fn session_binding_mac(secret: &str, input: SessionBindingMacInput<'_>) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any non-empty key length");
    update_mac_field(&mut mac, input.session_id);
    update_mac_field(&mut mac, input.correlation_id);
    update_mac_field(&mut mac, input.verified_subject);
    update_mac_field(&mut mac, input.subject_id_hash);
    update_mac_field(&mut mac, input.client_id);
    update_mac_field(&mut mac, input.tenant);
    update_mac_field(&mut mac, input.actor_id_hash);
    update_mac_field(&mut mac, input.delegation_ref);
    format!("hmac-sha256:{}", hex_bytes(&mac.finalize().into_bytes()))
}

fn update_mac_field(mac: &mut HmacSha256, value: &str) {
    mac.update(value.len().to_string().as_bytes());
    mac.update(b":");
    mac.update(value.as_bytes());
}

fn hmac_sha256_label(secret: &str, value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any non-empty key length");
    mac.update(value.as_bytes());
    format!("hmac-sha256:{}", hex_bytes(&mac.finalize().into_bytes()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Debug, Error)]
pub enum StsError {
    #[error("unsupported grant_type")]
    InvalidGrantType,
    #[error("subject_token is required")]
    SubjectTokenMissing,
    #[error("unsupported subject_token_type")]
    UnsupportedSubjectTokenType,
    #[error("unsupported requested_token_type")]
    UnsupportedRequestedTokenType,
    #[error("audience or resource does not match the configured Notary audience")]
    AudienceMismatch,
    #[error("subject token is invalid")]
    SubjectTokenInvalid,
    #[error("subject binding claim is missing")]
    SubjectBindingMissing,
    #[error("subject binding metadata does not match STS policy")]
    SubjectBindingMismatch,
    #[error("required scope is missing")]
    RequiredScopeMissing,
    #[error("requested scope was not granted to subject token")]
    ScopeNotGranted,
    #[error("sender constraint is required")]
    SenderConstraintMissing,
    #[error("authorization_details is required")]
    AuthorizationDetailsMissing,
    #[error("authorization_details is invalid")]
    AuthorizationDetailsInvalid,
    #[error("assisted access session binding is required")]
    SessionBindingMissing,
    #[error("assisted access session binding is invalid")]
    SessionBindingInvalid,
    #[error("rate limited; retry after {retry_after:?}")]
    RateLimited { retry_after: Duration },
    #[error("rate limit error: {0}")]
    RateLimit(#[from] RateLimitError),
    #[error("audit failed: {0}")]
    Audit(#[from] StsAuditError),
    #[error("signing failed: {0}")]
    Signing(#[from] SigningError),
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("token timestamp overflow")]
    ClockOverflow,
}

#[derive(Clone, Copy)]
struct RedactedLen(usize);

impl fmt::Debug for RedactedLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("redacted").field("len", &self.0).finish()
    }
}

#[must_use]
pub fn public_jwks(signer: &dyn SigningProvider) -> Value {
    let jwk: PublicJwk = signer.public_jwk();
    json!({ "keys": [jwk] })
}

#[must_use]
pub fn authorization_server_metadata(
    config: &TokenExchangeConfig,
    token_endpoint: &str,
    jwks_uri: &str,
) -> Value {
    json!({
        "issuer": config.issuer,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "grant_types_supported": [TOKEN_EXCHANGE_GRANT_TYPE],
        "subject_token_types_supported": config.allowed_subject_token_types.clone(),
        "requested_token_types_supported": [config.requested_token_type.clone()],
        "issued_token_types_supported": [config.issued_token_type.clone()],
        "authorization_details_types_supported": [NOTARY_AUTHORIZATION_DETAILS_TYPE],
    })
}

#[derive(Clone)]
pub struct StsHttpConfig {
    pub token_path: String,
    pub metadata_path: String,
    pub jwks_path: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl StsHttpConfig {
    #[must_use]
    pub fn local(issuer: &str) -> Self {
        Self {
            token_path: "/oauth/token".to_string(),
            metadata_path: "/.well-known/oauth-authorization-server".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            token_endpoint: format!("{issuer}/oauth/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        }
    }
}

#[derive(Clone)]
struct StsHttpState {
    service: Arc<TokenExchangeService>,
    metadata: Value,
    jwks: Value,
}

#[derive(Debug, Deserialize)]
struct HttpTokenExchangeRequest {
    #[serde(flatten)]
    token_exchange: TokenExchangeRequest,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    subject_id_hash: Option<String>,
    #[serde(default)]
    actor_id_hash: Option<String>,
    #[serde(default)]
    delegation_ref: Option<String>,
    #[serde(default)]
    session_binding: Option<String>,
}

impl HttpTokenExchangeRequest {
    fn into_parts(self) -> (TokenExchangeRequest, ExchangeContext) {
        (
            self.token_exchange,
            ExchangeContext {
                client_id: non_blank(self.client_id),
                tenant: non_blank(self.tenant),
                session_id: non_blank(self.session_id),
                correlation_id: non_blank(self.correlation_id),
                subject_id_hash: non_blank(self.subject_id_hash),
                actor_id_hash: non_blank(self.actor_id_hash),
                delegation_ref: non_blank(self.delegation_ref),
                session_binding: non_blank(self.session_binding),
            },
        )
    }
}

fn non_blank(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn sts_router(service: Arc<TokenExchangeService>, config: StsHttpConfig) -> Router {
    let state = StsHttpState {
        metadata: service.authorization_server_metadata(&config.token_endpoint, &config.jwks_uri),
        jwks: service.public_jwks(),
        service,
    };
    Router::new()
        .route(&config.token_path, post(http_token_exchange))
        .route(&config.metadata_path, get(http_metadata))
        .route(&config.jwks_path, get(http_jwks))
        .with_state(state)
}

async fn http_token_exchange(
    State(state): State<StsHttpState>,
    Json(request): Json<HttpTokenExchangeRequest>,
) -> Response {
    let (request, context) = request.into_parts();
    match state
        .service
        .exchange(request, context, OffsetDateTime::now_utc())
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => sts_error_response(error),
    }
}

async fn http_metadata(State(state): State<StsHttpState>) -> impl IntoResponse {
    Json(state.metadata)
}

async fn http_jwks(State(state): State<StsHttpState>) -> impl IntoResponse {
    Json(state.jwks)
}

fn sts_error_response(error: StsError) -> Response {
    let (status, code) = match &error {
        StsError::SubjectTokenInvalid => (StatusCode::BAD_REQUEST, "invalid_grant"),
        StsError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable"),
        StsError::Audit(_)
        | StsError::Signing(_)
        | StsError::Json(_)
        | StsError::ClockOverflow
        | StsError::RateLimit(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        _ => (StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let body = Json(json!({
        "error": code,
        "error_description": error.to_string(),
    }));
    if let StsError::RateLimited { retry_after } = error {
        let retry_after = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("1"));
        return (status, [(header::RETRY_AFTER, retry_after)], body).into_response();
    }
    (status, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use http::{Request, StatusCode};
    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
    use tower::ServiceExt;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:sts.test#key-1"}"#;

    #[derive(Debug)]
    struct StaticVerifier {
        subject: VerifiedSubjectToken,
    }

    #[derive(Default)]
    struct RecordingAuditSink {
        events: Mutex<Vec<TokenMintAuditEvent>>,
    }

    #[async_trait]
    impl StsAuditSink for RecordingAuditSink {
        async fn record_token_mint(&self, event: TokenMintAuditEvent) -> Result<(), StsAuditError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[async_trait]
    impl SubjectTokenVerifier for StaticVerifier {
        async fn verify_subject_token(
            &self,
            token: &str,
        ) -> Result<VerifiedSubjectToken, StsError> {
            if token == "invalid" {
                return Err(StsError::SubjectTokenInvalid);
            }
            Ok(self.subject.clone())
        }
    }

    fn service() -> TokenExchangeService {
        service_with_config(TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        ))
    }

    fn strict_service() -> TokenExchangeService {
        service_with_config(
            TokenExchangeConfig::notary_transaction_token(
                "https://sts.example.test",
                "https://notary.example.test",
            )
            .with_session_binding_secret("session-binding-secret")
            .with_subject_binding_claim("national_id")
            .with_audit_hash_secret("audit-secret"),
        )
    }

    fn service_with_config(config: TokenExchangeConfig) -> TokenExchangeService {
        let signer = Arc::new(LocalJwkSigner::new(PrivateJwk::parse(RAW_JWK).unwrap()).unwrap());
        let verifier = Arc::new(StaticVerifier {
            subject: verified_subject(),
        });
        TokenExchangeService::new(
            verifier,
            signer,
            Arc::new(InMemoryRateLimitStore::default()),
            config,
        )
    }

    fn verified_subject() -> VerifiedSubjectToken {
        VerifiedSubjectToken {
            subject: "hmac-sha256:subject".to_string(),
            issuer: "https://idp.example.test".to_string(),
            scopes: vec!["registry_notary:self_attestation".to_string()],
            confirmation: Some(json!({"jkt": "thumbprint"})),
            actor: Some(TokenActor {
                actor_id_hash: "hmac-sha256:actor".to_string(),
                assurance: Some("workforce-login".to_string()),
                delegation_ref: Some("delegation-123".to_string()),
            }),
        }
    }

    fn request() -> TokenExchangeRequest {
        TokenExchangeRequest {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_string(),
            subject_token: "subject.jwt".to_string(),
            subject_token_type: ACCESS_TOKEN_TYPE.to_string(),
            requested_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
            audience: Some("https://notary.example.test".to_string()),
            resource: None,
            scope: Some("registry_notary:self_attestation".to_string()),
            authorization_details: Some(vec![authorization_details()]),
            actor_token: None,
            actor_token_type: None,
        }
    }

    fn authorization_details() -> NotaryAuthorizationDetails {
        NotaryAuthorizationDetails {
            detail_type: NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
            schema_version: NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION.to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec!["https://notary.example.test".to_string()],
            claims: vec![NotaryClaimRef {
                id: "person-is-alive".to_string(),
                version: Some("1".to_string()),
            }],
            disclosure: Some("predicate".to_string()),
            format: Some("application/vnd.registry-notary.claim-result+json".to_string()),
            purpose: Some("citizen_self_attestation".to_string()),
            subject: Some(NotaryAuthorizationSubject {
                binding_claim: "national_id".to_string(),
                id_type: "national_id".to_string(),
            }),
            access_mode: Some("self_attestation".to_string()),
        }
    }

    fn context() -> ExchangeContext {
        ExchangeContext {
            client_id: Some("assisted-access-client".to_string()),
            tenant: Some("tenant-a".to_string()),
            session_id: Some("sess_123".to_string()),
            correlation_id: Some("corr_123".to_string()),
            subject_id_hash: None,
            actor_id_hash: None,
            delegation_ref: None,
            session_binding: None,
        }
    }

    fn bound_context() -> ExchangeContext {
        let mut context = context();
        context.subject_id_hash = Some("hmac-sha256:subject-id".to_string());
        context.session_binding = Some(session_binding_mac(
            "session-binding-secret",
            SessionBindingMacInput {
                session_id: "sess_123",
                correlation_id: "corr_123",
                verified_subject: "hmac-sha256:subject",
                subject_id_hash: "hmac-sha256:subject-id",
                client_id: "assisted-access-client",
                tenant: "tenant-a",
                actor_id_hash: "hmac-sha256:actor",
                delegation_ref: "delegation-123",
            },
        ));
        context
    }

    #[test]
    fn request_validation_rejects_wrong_shapes() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        );

        let mut wrong = request();
        wrong.grant_type = "client_credentials".to_string();
        assert!(matches!(
            validate_request(&wrong, &config),
            Err(StsError::InvalidGrantType)
        ));

        let mut wrong = request();
        wrong.subject_token_type = JWT_TOKEN_TYPE.to_string();
        assert!(matches!(
            validate_request(&wrong, &config),
            Err(StsError::UnsupportedSubjectTokenType)
        ));

        let mut wrong = request();
        wrong.audience = Some("https://other-notary.example.test".to_string());
        assert!(matches!(
            validate_request(&wrong, &config),
            Err(StsError::AudienceMismatch)
        ));

        let mut wrong = request();
        wrong.subject_token.clear();
        assert!(matches!(
            validate_request(&wrong, &config),
            Err(StsError::SubjectTokenMissing)
        ));
    }

    #[test]
    fn authorization_details_validation_rejects_missing_or_broadened_intent() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        );

        let mut wrong = request();
        wrong.authorization_details = None;
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsMissing)
        ));

        let mut wrong = request();
        wrong.authorization_details.as_mut().unwrap()[0].locations =
            vec!["https://other-notary.example.test".to_string()];
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsInvalid)
        ));

        let mut wrong = request();
        wrong.authorization_details.as_mut().unwrap()[0]
            .actions
            .push("admin".to_string());
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsInvalid)
        ));

        let mut wrong = request();
        wrong.authorization_details.as_mut().unwrap()[0]
            .claims
            .clear();
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsInvalid)
        ));

        let mut wrong = request();
        wrong.authorization_details.as_mut().unwrap()[0].claims[0].version = None;
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsInvalid)
        ));

        let mut wrong = request();
        wrong.authorization_details.as_mut().unwrap()[0]
            .claims
            .push(NotaryClaimRef {
                id: "person-is-alive".to_string(),
                version: Some("2".to_string()),
            });
        assert!(matches!(
            validate_authorization_details(&wrong, &config),
            Err(StsError::AuthorizationDetailsInvalid)
        ));
    }

    #[test]
    fn authorization_details_validation_returns_canonical_details() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        );
        let mut request = request();
        let details = request.authorization_details.as_mut().unwrap();
        details[0].claims = vec![
            NotaryClaimRef {
                id: "z-claim".to_string(),
                version: Some("2".to_string()),
            },
            NotaryClaimRef {
                id: "a-claim".to_string(),
                version: Some("1".to_string()),
            },
        ];
        details[0].purpose = Some(" citizen_self_attestation ".to_string());
        details[0].disclosure = Some(" predicate ".to_string());
        details[0].format = Some(" application/vnd.registry-notary.claim-result+json ".to_string());

        let canonical = validate_authorization_details(&request, &config).unwrap();

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].actions, ["evaluate"]);
        assert_eq!(canonical[0].locations, ["https://notary.example.test"]);
        assert_eq!(canonical[0].claims[0].id, "a-claim");
        assert_eq!(canonical[0].claims[1].id, "z-claim");
        assert_eq!(
            canonical[0].purpose.as_deref(),
            Some("citizen_self_attestation")
        );
        assert_eq!(canonical[0].disclosure.as_deref(), Some("predicate"));
        assert_eq!(
            canonical[0].format.as_deref(),
            Some("application/vnd.registry-notary.claim-result+json")
        );
    }

    #[test]
    fn authorization_details_deserialization_rejects_extra_or_duplicate_claim_fields() {
        let with_extra_field = json!({
            "type": NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["https://notary.example.test"],
            "claims": [{
                "id": "person-is-alive",
                "version": "1",
                "scope": "broadened"
            }],
            "disclosure": "predicate",
            "format": "application/vnd.registry-notary.claim-result+json",
            "purpose": "citizen_self_attestation",
            "subject": {
                "binding_claim": "national_id",
                "id_type": "national_id"
            },
            "access_mode": "self_attestation"
        });
        assert!(serde_json::from_value::<NotaryAuthorizationDetails>(with_extra_field).is_err());

        let duplicate_field = r#"{"id":"person-is-alive","id":"other","version":"1"}"#;
        assert!(serde_json::from_str::<NotaryClaimRef>(duplicate_field).is_err());
    }

    #[tokio::test]
    async fn exchange_mints_exact_audience_at_jwt() {
        let response = service()
            .exchange(request(), context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.issued_token_type, ACCESS_TOKEN_TYPE);
        assert_eq!(response.expires_in, 300);
        let (header, payload) = decode_unverified(&response.access_token);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], NOTARY_TRANSACTION_JWT_TYP);
        assert_eq!(header["kid"], "did:web:sts.test#key-1");
        assert_eq!(payload["iss"], "https://sts.example.test");
        assert_eq!(payload["aud"], "https://notary.example.test");
        assert_eq!(payload["sub"], "hmac-sha256:subject");
        assert_eq!(payload["client_id"], "assisted-access-client");
        assert_eq!(payload["tenant"], "tenant-a");
        assert_eq!(payload["sid"], "sess_123");
        assert_eq!(payload["correlation_id"], "corr_123");
        assert_eq!(payload["iat"], 0);
        assert_eq!(payload["nbf"], 0);
        assert_eq!(payload["exp"], 300);
        assert!(payload["jti"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(payload["scope"], "registry_notary:self_attestation");
        assert!(payload.get("cnf").is_none());
        assert_eq!(payload["act"]["actor_id_hash"], "hmac-sha256:actor");
        assert_eq!(payload["act"]["delegation_ref"], "delegation-123");
        assert_eq!(
            payload["authorization_details"][0]["type"],
            "registry_notary_evidence_transaction"
        );
        assert_eq!(
            payload["authorization_details"][0]["schema_version"],
            "registry-notary-authorization-details/v1"
        );
        assert_eq!(
            payload["authorization_details"][0]["claims"][0]["id"],
            "person-is-alive"
        );
        assert_eq!(
            payload["authorization_details"][0]["claims"][0]["version"],
            "1"
        );
        assert_eq!(
            payload["authorization_details"][0]["access_mode"],
            "self_attestation"
        );
        assert_eq!(
            payload["authorization_details"][0]["subject"]["binding_claim"],
            "national_id"
        );
    }

    #[tokio::test]
    async fn exchange_fails_closed_when_sender_constraint_missing() {
        let mut subject = verified_subject();
        subject.confirmation = None;
        let mut config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        );
        config.sender_constraint = SenderConstraintPolicy::Required;
        let signer = Arc::new(LocalJwkSigner::new(PrivateJwk::parse(RAW_JWK).unwrap()).unwrap());
        let service = TokenExchangeService::new(
            Arc::new(StaticVerifier { subject }),
            signer,
            Arc::new(InMemoryRateLimitStore::default()),
            config,
        );

        let err = service
            .exchange(request(), context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();

        assert!(matches!(err, StsError::SenderConstraintMissing));
    }

    #[tokio::test]
    async fn in_memory_rate_limit_denies_after_threshold() {
        let service = service().with_rate_limit_policy(RateLimitPolicy {
            max_requests: 1,
            window: Duration::from_secs(60),
        });
        service
            .exchange(request(), context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();

        let err = service
            .exchange(request(), context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();

        assert!(matches!(err, StsError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn in_memory_rate_limit_evicts_expired_counters() {
        let store = InMemoryRateLimitStore::default();
        let scope = RateLimitScope::new("client").unwrap();
        let first_key = RateLimitKey::new("client-a").unwrap();
        let second_key = RateLimitKey::new("client-b").unwrap();
        let policy = RateLimitPolicy {
            max_requests: 10,
            window: Duration::from_secs(60),
        };

        store
            .check_and_increment(&scope, &first_key, policy, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();
        store
            .check_and_increment(
                &scope,
                &second_key,
                policy,
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(61),
            )
            .await
            .unwrap();

        let state = store.state.lock().unwrap();
        assert!(!state.counters.contains_key(&(scope.clone(), first_key)));
        assert!(state.counters.contains_key(&(scope, second_key)));
    }

    #[tokio::test]
    async fn in_memory_rate_limit_cleans_stale_counters_in_bounded_batches() {
        let store = InMemoryRateLimitStore::default();
        let scope = RateLimitScope::new("client").unwrap();
        let policy = RateLimitPolicy {
            max_requests: 10,
            window: Duration::from_secs(60),
        };

        for index in 0..(RATE_LIMIT_CLEANUP_BATCH + 2) {
            let key = RateLimitKey::new(format!("client-{index}")).unwrap();
            store
                .check_and_increment(&scope, &key, policy, OffsetDateTime::UNIX_EPOCH)
                .await
                .unwrap();
        }

        let first_fresh_key = RateLimitKey::new("fresh-client-a").unwrap();
        store
            .check_and_increment(
                &scope,
                &first_fresh_key,
                policy,
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(61),
            )
            .await
            .unwrap();
        {
            let state = store.state.lock().unwrap();
            assert_eq!(state.counters.len(), 3);
            assert!(state
                .counters
                .contains_key(&(scope.clone(), first_fresh_key)));
        }

        let second_fresh_key = RateLimitKey::new("fresh-client-b").unwrap();
        store
            .check_and_increment(
                &scope,
                &second_fresh_key,
                policy,
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(61),
            )
            .await
            .unwrap();

        let state = store.state.lock().unwrap();
        assert_eq!(state.counters.len(), 2);
        assert!(state
            .counters
            .contains_key(&(scope.clone(), RateLimitKey::new("fresh-client-a").unwrap())));
        assert!(state.counters.contains_key(&(scope, second_fresh_key)));
    }

    #[tokio::test]
    async fn exchange_emits_redacted_mint_audit_event() {
        let audit = Arc::new(RecordingAuditSink::default());
        let service = strict_service().with_audit_sink(audit.clone());

        service
            .exchange(request(), bound_context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_type, "registry-platform-sts.token_minted");
        assert_eq!(event.issuer, "https://sts.example.test");
        assert_eq!(event.audience, "https://notary.example.test");
        assert_eq!(event.client_id.as_deref(), Some("assisted-access-client"));
        assert_eq!(event.correlation_id.as_deref(), Some("corr_123"));
        assert_eq!(event.session_id.as_deref(), Some("sess_123"));
        assert!(event.subject_hash.starts_with("hmac-sha256:"));
        assert!(event.jti_hash.starts_with("hmac-sha256:"));
        assert!(event.authorization_details_hash.starts_with("hmac-sha256:"));
        let serialized = serde_json::to_string(event).unwrap();
        assert!(!serialized.contains("subject.jwt"));
        assert!(!serialized.contains("hmac-sha256:subject"));
    }

    #[tokio::test]
    async fn exchange_requires_valid_session_binding_mac_when_configured() {
        let err = strict_service()
            .exchange(request(), context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();
        assert!(matches!(err, StsError::SubjectBindingMissing));

        let mut wrong = bound_context();
        wrong.session_binding = Some("hmac-sha256:wrong".to_string());
        let err = strict_service()
            .exchange(request(), wrong, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();
        assert!(matches!(err, StsError::SessionBindingInvalid));

        strict_service()
            .exchange(request(), bound_context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();
    }

    #[test]
    fn session_binding_mac_covers_signed_caller_context() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        )
        .with_session_binding_secret("session-binding-secret")
        .with_subject_binding_claim("national_id");
        let subject = verified_subject();
        let context = bound_context();

        validate_exchange_context(&context, &config, &subject).unwrap();

        let mut wrong = context.clone();
        wrong.client_id = Some("other-client".to_string());
        assert!(matches!(
            validate_exchange_context(&wrong, &config, &subject),
            Err(StsError::SessionBindingInvalid)
        ));

        let mut wrong = context.clone();
        wrong.tenant = Some("other-tenant".to_string());
        assert!(matches!(
            validate_exchange_context(&wrong, &config, &subject),
            Err(StsError::SessionBindingInvalid)
        ));

        let mut wrong_subject = subject.clone();
        wrong_subject.actor.as_mut().unwrap().actor_id_hash = "hmac-sha256:other-actor".to_string();
        assert!(matches!(
            validate_exchange_context(&context, &config, &wrong_subject),
            Err(StsError::SessionBindingInvalid)
        ));

        let mut wrong_subject = subject;
        wrong_subject.actor.as_mut().unwrap().delegation_ref = Some("other-delegation".to_string());
        assert!(matches!(
            validate_exchange_context(&context, &config, &wrong_subject),
            Err(StsError::SessionBindingInvalid)
        ));
    }

    #[test]
    fn session_binding_mac_matches_signed_actor_delegation_source() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        )
        .with_session_binding_secret("session-binding-secret")
        .with_subject_binding_claim("national_id");
        let mut subject = verified_subject();
        subject.actor.as_mut().unwrap().delegation_ref = None;
        let mut context = bound_context();
        context.delegation_ref = Some("context-delegation".to_string());
        context.session_binding = Some(session_binding_mac(
            "session-binding-secret",
            SessionBindingMacInput {
                session_id: "sess_123",
                correlation_id: "corr_123",
                verified_subject: "hmac-sha256:subject",
                subject_id_hash: "hmac-sha256:subject-id",
                client_id: "assisted-access-client",
                tenant: "tenant-a",
                actor_id_hash: "hmac-sha256:actor",
                delegation_ref: "",
            },
        ));

        validate_exchange_context(&context, &config, &subject).unwrap();

        context.session_binding = Some(session_binding_mac(
            "session-binding-secret",
            SessionBindingMacInput {
                session_id: "sess_123",
                correlation_id: "corr_123",
                verified_subject: "hmac-sha256:subject",
                subject_id_hash: "hmac-sha256:subject-id",
                client_id: "assisted-access-client",
                tenant: "tenant-a",
                actor_id_hash: "hmac-sha256:actor",
                delegation_ref: "context-delegation",
            },
        ));
        assert!(matches!(
            validate_exchange_context(&context, &config, &subject),
            Err(StsError::SessionBindingInvalid)
        ));
    }

    #[tokio::test]
    async fn exchange_rejects_authorization_details_with_wrong_subject_binding_claim() {
        let mut request = request();
        request.authorization_details.as_mut().unwrap()[0]
            .subject
            .as_mut()
            .unwrap()
            .binding_claim = "other_claim".to_string();

        let err = strict_service()
            .exchange(request, bound_context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();

        assert!(matches!(err, StsError::SubjectBindingMismatch));
    }

    #[tokio::test]
    async fn in_memory_rate_limit_applies_per_subject_across_clients() {
        let service = strict_service().with_rate_limit_policy(RateLimitPolicy {
            max_requests: 1,
            window: Duration::from_secs(60),
        });
        service
            .exchange(request(), bound_context(), OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();
        let mut second_context = bound_context();
        second_context.client_id = Some("different-assisted-access-client".to_string());

        let err = service
            .exchange(request(), second_context, OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();

        assert!(matches!(err, StsError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn exchange_requires_session_binding_by_default() {
        let err = service()
            .exchange(
                request(),
                ExchangeContext::default(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StsError::SessionBindingMissing));
    }

    #[test]
    fn debug_output_redacts_token_material() {
        let request = request();
        let debug = format!("{request:?}");

        assert!(!debug.contains("subject.jwt"));
        assert!(debug.contains("subject_token"));
    }

    #[test]
    fn public_jwks_excludes_private_fields() {
        let signer = LocalJwkSigner::new(PrivateJwk::parse(RAW_JWK).unwrap()).unwrap();
        let jwks = public_jwks(&signer);
        let text = serde_json::to_string(&jwks).unwrap();

        assert!(!text.contains("\"d\""));
        assert!(!text.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
        assert!(text.contains("did:web:sts.test#key-1"));
    }

    #[test]
    fn metadata_advertises_token_exchange_and_authorization_details() {
        let config = TokenExchangeConfig::notary_transaction_token(
            "https://sts.example.test",
            "https://notary.example.test",
        );

        let metadata = authorization_server_metadata(
            &config,
            "https://sts.example.test/oauth/token",
            "https://sts.example.test/.well-known/jwks.json",
        );

        assert_eq!(metadata["issuer"], "https://sts.example.test");
        assert_eq!(
            metadata["grant_types_supported"][0],
            TOKEN_EXCHANGE_GRANT_TYPE
        );
        assert_eq!(
            metadata["subject_token_types_supported"][0],
            ACCESS_TOKEN_TYPE
        );
        assert_eq!(
            metadata["authorization_details_types_supported"][0],
            NOTARY_AUTHORIZATION_DETAILS_TYPE
        );
    }

    #[tokio::test]
    async fn http_token_endpoint_maps_assisted_access_context_and_mints_token() {
        let app = sts_router(
            Arc::new(service()),
            StsHttpConfig::local("https://sts.example.test"),
        );
        let mut body = serde_json::to_value(request()).unwrap();
        body["client_id"] = json!("assisted-access-client");
        body["tenant"] = json!("tenant-a");
        body["session_id"] = json!("sess_http");
        body["correlation_id"] = json!("corr_http");

        let response = app
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: TokenExchangeResponse = serde_json::from_slice(&body).unwrap();
        let (_header, payload) = decode_unverified(&response.access_token);
        assert_eq!(payload["aud"], "https://notary.example.test");
        assert_eq!(payload["client_id"], "assisted-access-client");
        assert_eq!(payload["tenant"], "tenant-a");
        assert_eq!(payload["sid"], "sess_http");
        assert_eq!(payload["correlation_id"], "corr_http");
        assert_eq!(
            payload["authorization_details"][0]["locations"][0],
            "https://notary.example.test"
        );
    }

    #[tokio::test]
    async fn http_token_endpoint_rejects_missing_session_binding() {
        let app = sts_router(
            Arc::new(service()),
            StsHttpConfig::local("https://sts.example.test"),
        );
        let mut body = serde_json::to_value(request()).unwrap();
        body["client_id"] = json!("assisted-access-client");

        let response = app
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["error"], "invalid_request");
        assert!(problem["error_description"]
            .as_str()
            .unwrap()
            .contains("session binding"));
    }

    #[tokio::test]
    async fn http_metadata_and_jwks_are_served_without_private_key_material() {
        let app = sts_router(
            Arc::new(service()),
            StsHttpConfig::local("https://sts.example.test"),
        );

        let metadata_response = app
            .clone()
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata_response.status(), StatusCode::OK);
        let metadata_body = to_bytes(metadata_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let metadata: Value = serde_json::from_slice(&metadata_body).unwrap();
        assert_eq!(
            metadata["token_endpoint"],
            "https://sts.example.test/oauth/token"
        );
        assert_eq!(
            metadata["jwks_uri"],
            "https://sts.example.test/.well-known/jwks.json"
        );

        let jwks_response = app
            .oneshot(
                Request::get("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwks_response.status(), StatusCode::OK);
        let jwks_body = to_bytes(jwks_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks_text = String::from_utf8(jwks_body.to_vec()).unwrap();
        assert!(jwks_text.contains("did:web:sts.test#key-1"));
        assert!(!jwks_text.contains("\"d\""));
        assert!(!jwks_text.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    }

    fn decode_unverified(jwt: &str) -> (Value, Value) {
        let mut parts = jwt.split('.');
        let header = parts.next().unwrap();
        let payload = parts.next().unwrap();
        let header = URL_SAFE_NO_PAD.decode(header).unwrap();
        let payload = URL_SAFE_NO_PAD.decode(payload).unwrap();
        (
            serde_json::from_slice(&header).unwrap(),
            serde_json::from_slice(&payload).unwrap(),
        )
    }
}
