//! OIDC discovery, JWKS caching, and JWT verification for registry services.
//!
//! This crate is a verifier-side helper for resource servers. It validates
//! issuer, audience, token type, algorithm, key id, time bounds, optional client
//! identity, and scopes; it does not implement browser login, OAuth
//! authorization endpoints, PKCE, token minting, or refresh flows.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use registry_platform_httputil::{read_bounded, FetchUrlError, FetchUrlPolicy};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, RwLock};

const DEFAULT_DOC_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_KID_BYTES: usize = 1024;
const DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES: usize = 1024;
const MIN_RSA_MODULUS_BITS: usize = 2048;

#[derive(Debug, Clone)]
pub struct OidcDiscoveryConfig {
    pub issuer: String,
    /// Override the JWKS URI instead of fetching `/.well-known/openid-configuration`.
    ///
    /// **Security warning:** when this field is set, the normal discovery flow is
    /// skipped entirely. The `issuer` field in the returned `DiscoveryDocument` is
    /// taken verbatim from `OidcDiscoveryConfig::issuer` without verifying that the
    /// JWKS URI is bound to that issuer. JWT `iss` validation still happens at token
    /// verification time, but the binding between issuer and key endpoint is not
    /// checked here. Use this only for controlled deployments where the JWKS URI is
    /// known and trusted out-of-band (e.g. same-cluster key server, test fixtures).
    pub jwks_uri_override: Option<String>,
    pub discovery_timeout: Duration,
    pub max_doc_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub async fn fetch_discovery(cfg: &OidcDiscoveryConfig) -> Result<DiscoveryDocument, OidcError> {
    fetch_discovery_with_policy(cfg, &FetchUrlPolicy::strict()).await
}

pub async fn fetch_discovery_with_policy(
    cfg: &OidcDiscoveryConfig,
    fetch_url_policy: &FetchUrlPolicy,
) -> Result<DiscoveryDocument, OidcError> {
    if let Some(jwks_uri) = &cfg.jwks_uri_override {
        let url = Url::parse(jwks_uri).map_err(|_| OidcError::InvalidUrl)?;
        fetch_url_policy
            .validate_for_immediate_fetch_with_timeout(&url, cfg.discovery_timeout)
            .await?;
        return Ok(DiscoveryDocument {
            issuer: cfg.issuer.clone(),
            jwks_uri: jwks_uri.clone(),
            userinfo_endpoint: None,
            extra: Map::new(),
        });
    }
    let mut issuer = cfg.issuer.trim_end_matches('/').to_string();
    issuer.push_str("/.well-known/openid-configuration");
    let url = Url::parse(&issuer).map_err(|_| OidcError::InvalidUrl)?;
    let validated_url = fetch_url_policy
        .validate_for_immediate_fetch_with_timeout(&url, cfg.discovery_timeout)
        .await?;
    let resp = validated_url
        .immediate_get()?
        .timeout(cfg.discovery_timeout)
        .send()
        .await
        .map_err(OidcError::Transport)?;
    if !resp.status().is_success() {
        return Err(OidcError::HttpStatus(resp.status().as_u16()));
    }
    let body = read_bounded(resp, cfg.max_doc_bytes.max(1)).await?;
    let document: DiscoveryDocument =
        serde_json::from_slice(&body).map_err(|_| OidcError::Parse)?;
    if document.issuer != cfg.issuer {
        return Err(OidcError::IssuerMismatch {
            expected: cfg.issuer.clone(),
            actual: document.issuer,
        });
    }
    let jwks_uri = Url::parse(&document.jwks_uri).map_err(|_| OidcError::InvalidUrl)?;
    fetch_url_policy
        .validate_for_immediate_fetch_with_timeout(&jwks_uri, cfg.discovery_timeout)
        .await?;
    Ok(document)
}

#[derive(Debug, Clone)]
pub struct JwksFetcherConfig {
    pub cache_ttl: Duration,
    pub negative_cache_ttl: Duration,
    pub refresh_cooldown: Duration,
    pub max_doc_bytes: u64,
    pub request_timeout: Duration,
}

impl JwksFetcherConfig {
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            cache_ttl: Duration::from_secs(600),
            negative_cache_ttl: Duration::from_secs(60),
            refresh_cooldown: Duration::from_secs(30),
            max_doc_bytes: DEFAULT_DOC_BYTES,
            request_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Default)]
struct JwksState {
    keys: HashMap<String, Jwk>,
    fetched_at: Option<Instant>,
    last_forced_refresh: Option<Instant>,
    negative: HashMap<String, Instant>,
}

#[allow(clippy::large_enum_variant)]
enum JwksCacheLookup {
    Hit(CachedJwkKey),
    FreshMiss,
    StaleOrEmpty,
    NegativeMiss,
}

struct CachedJwkKey {
    decoding_key: DecodingKey,
    jwk: Jwk,
}

#[derive(Debug)]
pub struct JwksFetcher {
    jwks_uri: String,
    config: JwksFetcherConfig,
    fetch_url_policy: FetchUrlPolicy,
    state: RwLock<JwksState>,
    refresh_lock: Mutex<()>,
}

impl JwksFetcher {
    #[must_use]
    pub fn new(jwks_uri: String, config: JwksFetcherConfig) -> Self {
        Self::new_with_fetch_url_policy(jwks_uri, config, FetchUrlPolicy::strict())
    }

    #[must_use]
    pub fn new_with_fetch_url_policy(
        jwks_uri: String,
        config: JwksFetcherConfig,
        fetch_url_policy: FetchUrlPolicy,
    ) -> Self {
        Self {
            jwks_uri,
            config,
            fetch_url_policy,
            state: RwLock::new(JwksState::default()),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn key_for_kid(&self, kid: &str) -> Result<DecodingKey, OidcError> {
        if kid.is_empty() {
            return Err(OidcError::MissingKid);
        }
        if kid.len() > DEFAULT_MAX_KID_BYTES {
            return Err(OidcError::KidTooLong);
        }
        let now = Instant::now();
        match self.cached_key(kid, now).await? {
            JwksCacheLookup::Hit(key) => return Ok(key.decoding_key),
            JwksCacheLookup::NegativeMiss => {
                if self.should_force_refresh(now).await {
                    match self.refresh_and_cached_key(kid, true).await? {
                        JwksCacheLookup::Hit(key) => return Ok(key.decoding_key),
                        JwksCacheLookup::NegativeMiss
                        | JwksCacheLookup::FreshMiss
                        | JwksCacheLookup::StaleOrEmpty => {}
                    }
                }
                return Err(OidcError::UnknownKid);
            }
            JwksCacheLookup::FreshMiss => {}
            JwksCacheLookup::StaleOrEmpty => match self.refresh_and_cached_key(kid, false).await? {
                JwksCacheLookup::Hit(key) => return Ok(key.decoding_key),
                JwksCacheLookup::NegativeMiss => return Err(OidcError::UnknownKid),
                JwksCacheLookup::FreshMiss | JwksCacheLookup::StaleOrEmpty => {
                    self.remember_unknown_kid(kid).await;
                    return Err(OidcError::UnknownKid);
                }
            },
        }

        if self.should_force_refresh(Instant::now()).await {
            match self.refresh_and_cached_key(kid, true).await? {
                JwksCacheLookup::Hit(key) => return Ok(key.decoding_key),
                JwksCacheLookup::NegativeMiss => return Err(OidcError::UnknownKid),
                JwksCacheLookup::FreshMiss | JwksCacheLookup::StaleOrEmpty => {}
            }
        }
        self.remember_unknown_kid(kid).await;
        Err(OidcError::UnknownKid)
    }

    async fn key_for_kid_matching_alg(
        &self,
        kid: &str,
        header_alg: Algorithm,
    ) -> Result<DecodingKey, OidcError> {
        let key = self.cached_or_refreshed_key(kid).await?;
        validate_jwk_for_header(&key.jwk, header_alg)?;
        Ok(key.decoding_key)
    }

    async fn cached_or_refreshed_key(&self, kid: &str) -> Result<CachedJwkKey, OidcError> {
        if kid.is_empty() {
            return Err(OidcError::MissingKid);
        }
        if kid.len() > DEFAULT_MAX_KID_BYTES {
            return Err(OidcError::KidTooLong);
        }
        let now = Instant::now();
        match self.cached_key(kid, now).await? {
            JwksCacheLookup::Hit(key) => return Ok(key),
            JwksCacheLookup::NegativeMiss => {
                if self.should_force_refresh(now).await {
                    if let JwksCacheLookup::Hit(key) =
                        self.refresh_and_cached_key(kid, true).await?
                    {
                        return Ok(key);
                    }
                }
                return Err(OidcError::UnknownKid);
            }
            JwksCacheLookup::FreshMiss => {}
            JwksCacheLookup::StaleOrEmpty => {
                if let JwksCacheLookup::Hit(key) = self.refresh_and_cached_key(kid, false).await? {
                    return Ok(key);
                }
                self.remember_unknown_kid(kid).await;
                return Err(OidcError::UnknownKid);
            }
        }

        if self.should_force_refresh(Instant::now()).await {
            if let JwksCacheLookup::Hit(key) = self.refresh_and_cached_key(kid, true).await? {
                return Ok(key);
            }
        }
        self.remember_unknown_kid(kid).await;
        Err(OidcError::UnknownKid)
    }

    async fn should_force_refresh(&self, now: Instant) -> bool {
        let state = self.state.read().await;
        state
            .last_forced_refresh
            .map(|last| now.duration_since(last) >= self.config.refresh_cooldown)
            .unwrap_or(true)
    }

    async fn remember_unknown_kid(&self, kid: &str) {
        let now = Instant::now();
        let mut state = self.state.write().await;
        state
            .negative
            .retain(|_, seen| now.duration_since(*seen) < self.config.negative_cache_ttl);
        while state.negative.len() >= DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES
            && !state.negative.contains_key(kid)
        {
            evict_oldest_negative_entry(&mut state.negative);
        }
        state.negative.insert(kid.to_string(), now);
    }

    async fn cached_key(&self, kid: &str, now: Instant) -> Result<JwksCacheLookup, OidcError> {
        let state = self.state.read().await;
        if let Some(seen) = state.negative.get(kid) {
            if now.duration_since(*seen) < self.config.negative_cache_ttl {
                return Ok(JwksCacheLookup::NegativeMiss);
            }
        }
        if state
            .fetched_at
            .map(|fetched| now.duration_since(fetched) > self.config.cache_ttl)
            .unwrap_or(true)
        {
            return Ok(JwksCacheLookup::StaleOrEmpty);
        }
        state
            .keys
            .get(kid)
            .map_or(Ok(JwksCacheLookup::FreshMiss), |jwk| {
                validate_jwk(jwk)?;
                DecodingKey::from_jwk(jwk)
                    .map(|decoding_key| {
                        JwksCacheLookup::Hit(CachedJwkKey {
                            decoding_key,
                            jwk: jwk.clone(),
                        })
                    })
                    .map_err(|_| OidcError::InvalidJwk)
            })
    }

    async fn refresh_and_cached_key(
        &self,
        kid: &str,
        forced: bool,
    ) -> Result<JwksCacheLookup, OidcError> {
        let _guard = self.refresh_lock.lock().await;

        match self.cached_key(kid, Instant::now()).await? {
            JwksCacheLookup::Hit(key) => return Ok(JwksCacheLookup::Hit(key)),
            JwksCacheLookup::NegativeMiss if !forced => {
                return Ok(JwksCacheLookup::NegativeMiss);
            }
            JwksCacheLookup::NegativeMiss => {}
            JwksCacheLookup::FreshMiss if !forced => return Ok(JwksCacheLookup::FreshMiss),
            JwksCacheLookup::FreshMiss | JwksCacheLookup::StaleOrEmpty => {}
        }

        if forced && !self.should_force_refresh(Instant::now()).await {
            return self.cached_key(kid, Instant::now()).await;
        }

        self.refresh(forced).await?;
        self.cached_key(kid, Instant::now()).await
    }

    async fn refresh(&self, forced: bool) -> Result<(), OidcError> {
        let url = Url::parse(&self.jwks_uri).map_err(|_| OidcError::InvalidUrl)?;
        let validated_url = self
            .fetch_url_policy
            .validate_for_immediate_fetch_with_timeout(&url, self.config.request_timeout)
            .await?;
        let resp = validated_url
            .immediate_get()?
            .timeout(self.config.request_timeout)
            .send()
            .await
            .map_err(OidcError::Transport)?;
        if !resp.status().is_success() {
            return Err(OidcError::HttpStatus(resp.status().as_u16()));
        }
        let body = read_bounded(resp, self.config.max_doc_bytes.max(1)).await?;
        let jwks: JwkSet = serde_json::from_slice(&body).map_err(|_| OidcError::Parse)?;
        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|jwk| jwk.common.key_id.clone().map(|kid| (kid, jwk)))
            .collect();
        let mut state = self.state.write().await;
        state.keys = keys;
        state.fetched_at = Some(Instant::now());
        state.negative.clear();
        if forced {
            state.last_forced_refresh = Some(Instant::now());
        }
        Ok(())
    }
}

fn validate_jwk(jwk: &Jwk) -> Result<(), OidcError> {
    if let jsonwebtoken::jwk::AlgorithmParameters::RSA(parameters) = &jwk.algorithm {
        let modulus = URL_SAFE_NO_PAD
            .decode(parameters.n.as_bytes())
            .map_err(|_| OidcError::InvalidJwk)?;
        let first_non_zero = modulus
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(modulus.len());
        let significant = &modulus[first_non_zero..];
        let bit_len = significant
            .first()
            .map(|first| (significant.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
            .unwrap_or(0);
        if bit_len < MIN_RSA_MODULUS_BITS {
            return Err(OidcError::InvalidJwk);
        }
    }
    Ok(())
}

fn validate_jwk_for_header(jwk: &Jwk, header_alg: Algorithm) -> Result<(), OidcError> {
    validate_jwk(jwk)?;
    if jwk_family(jwk) != algorithm_family(header_alg) {
        return Err(OidcError::InvalidJwk);
    }
    if let Some(jwk_alg) = explicit_or_inferred_jwk_algorithm(jwk)? {
        if jwk_alg != header_alg {
            return Err(OidcError::InvalidJwk);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlgorithmFamilyKind {
    Hmac,
    Rsa,
    Ec,
    Ed,
}

fn algorithm_family(algorithm: Algorithm) -> AlgorithmFamilyKind {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamilyKind::Hmac,
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => AlgorithmFamilyKind::Rsa,
        Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamilyKind::Ec,
        Algorithm::EdDSA => AlgorithmFamilyKind::Ed,
    }
}

fn jwk_family(jwk: &Jwk) -> AlgorithmFamilyKind {
    match &jwk.algorithm {
        AlgorithmParameters::OctetKey(_) => AlgorithmFamilyKind::Hmac,
        AlgorithmParameters::RSA(_) => AlgorithmFamilyKind::Rsa,
        AlgorithmParameters::EllipticCurve(_) => AlgorithmFamilyKind::Ec,
        AlgorithmParameters::OctetKeyPair(parameters) => {
            if parameters.curve == EllipticCurve::Ed25519 {
                AlgorithmFamilyKind::Ed
            } else {
                AlgorithmFamilyKind::Ec
            }
        }
    }
}

fn explicit_or_inferred_jwk_algorithm(jwk: &Jwk) -> Result<Option<Algorithm>, OidcError> {
    if let Some(algorithm) = jwk.common.key_algorithm {
        return key_algorithm_to_jwt_algorithm(algorithm).map(Some);
    }
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(parameters) => match parameters.curve {
            EllipticCurve::P256 => Ok(Some(Algorithm::ES256)),
            EllipticCurve::P384 => Ok(Some(Algorithm::ES384)),
            _ => Ok(None),
        },
        AlgorithmParameters::OctetKeyPair(parameters)
            if parameters.curve == EllipticCurve::Ed25519 =>
        {
            Ok(Some(Algorithm::EdDSA))
        }
        _ => Ok(None),
    }
}

fn key_algorithm_to_jwt_algorithm(algorithm: KeyAlgorithm) -> Result<Algorithm, OidcError> {
    match algorithm {
        KeyAlgorithm::HS256 => Ok(Algorithm::HS256),
        KeyAlgorithm::HS384 => Ok(Algorithm::HS384),
        KeyAlgorithm::HS512 => Ok(Algorithm::HS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        KeyAlgorithm::RSA1_5
        | KeyAlgorithm::RSA_OAEP
        | KeyAlgorithm::RSA_OAEP_256
        | KeyAlgorithm::UNKNOWN_ALGORITHM => Err(OidcError::InvalidJwk),
    }
}

fn assert_algorithm_family_is_not_mixed(algorithms: &[Algorithm]) {
    let Some(first) = algorithms.first().copied() else {
        return;
    };
    let first_is_hmac = algorithm_family(first) == AlgorithmFamilyKind::Hmac;
    assert!(
        algorithms
            .iter()
            .all(
                |algorithm| (algorithm_family(*algorithm) == AlgorithmFamilyKind::Hmac)
                    == first_is_hmac
            ),
        "allowed_algorithms must not mix symmetric and asymmetric algorithms"
    );
}

fn evict_oldest_negative_entry(negative: &mut HashMap<String, Instant>) {
    if let Some(kid) = negative
        .iter()
        .min_by_key(|(_, seen)| **seen)
        .map(|(kid, _)| kid.clone())
    {
        negative.remove(&kid);
    }
}

#[derive(Debug, Clone)]
pub struct TokenVerifierConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub allowed_algorithms: Vec<Algorithm>,
    /// Allowed access-token `typ` header values. Empty means deny all access
    /// tokens because the token type policy is not configured.
    pub allowed_typ: Vec<String>,
    /// Allowed ID-token `typ` header values. Empty means deny all ID tokens.
    pub allowed_id_typ: Vec<String>,
    /// Allowed UserInfo JWT `typ` header values. Empty means deny all UserInfo JWTs.
    pub allowed_userinfo_typ: Vec<String>,
    pub userinfo_requires_exp: bool,
    pub scope_claim: String,
    pub scope_separator: char,
    pub scope_map: Option<HashMap<String, Vec<String>>>,
    pub allowed_clients: Vec<String>,
    pub leeway: Duration,
}

impl TokenVerifierConfig {
    /// Build the standard resource-server access-token profile.
    ///
    /// Access tokens must carry one of `allowed_typ`. Related ID tokens and
    /// UserInfo JWTs use the project defaults accepted by Relay and Notary:
    /// ID token `typ` values `JWT` and `id_token`, UserInfo JWT `typ` value
    /// `JWT`, and required UserInfo expiration by default.
    pub fn access_token_profile(
        issuer: impl Into<String>,
        audiences: Vec<String>,
        allowed_algorithms: Vec<Algorithm>,
        allowed_typ: Vec<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audiences,
            allowed_algorithms,
            allowed_typ,
            allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
            allowed_userinfo_typ: vec!["JWT".to_string()],
            userinfo_requires_exp: true,
            scope_claim: "scope".to_string(),
            scope_separator: ' ',
            scope_map: None,
            allowed_clients: Vec::new(),
            leeway: Duration::ZERO,
        }
    }

    /// Build a profile for project-specific typed request JWTs such as Notary
    /// federation requests.
    pub fn typed_request_profile(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        allowed_algorithms: Vec<Algorithm>,
        typ: impl Into<String>,
    ) -> Self {
        Self::access_token_profile(
            issuer,
            vec![audience.into()],
            allowed_algorithms,
            vec![typ.into()],
        )
    }

    /// Registry Relay access-token verifier profile.
    pub fn registry_relay_access_profile(
        issuer: impl Into<String>,
        audiences: Vec<String>,
        allowed_algorithms: Vec<Algorithm>,
        allowed_typ: Vec<String>,
    ) -> Self {
        Self::access_token_profile(issuer, audiences, allowed_algorithms, allowed_typ)
    }

    /// Registry Notary self-attestation access-token verifier profile.
    pub fn registry_notary_access_profile(
        issuer: impl Into<String>,
        audiences: Vec<String>,
        allowed_algorithms: Vec<Algorithm>,
        allowed_typ: Vec<String>,
    ) -> Self {
        Self::access_token_profile(issuer, audiences, allowed_algorithms, allowed_typ)
    }

    /// Registry Notary federation request JWT verifier profile.
    pub fn registry_notary_federation_request_profile(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        allowed_algorithms: Vec<Algorithm>,
        typ: impl Into<String>,
    ) -> Self {
        Self::typed_request_profile(issuer, audience, allowed_algorithms, typ)
    }

    #[must_use]
    pub fn with_scope_claim(mut self, scope_claim: impl Into<String>) -> Self {
        self.scope_claim = scope_claim.into();
        self
    }

    #[must_use]
    pub fn with_scope_separator(mut self, scope_separator: char) -> Self {
        self.scope_separator = scope_separator;
        self
    }

    #[must_use]
    pub fn with_scope_map(mut self, scope_map: Option<HashMap<String, Vec<String>>>) -> Self {
        self.scope_map = scope_map;
        self
    }

    #[must_use]
    pub fn with_allowed_clients(mut self, allowed_clients: Vec<String>) -> Self {
        self.allowed_clients = allowed_clients;
        self
    }

    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    #[must_use]
    pub fn with_related_token_typ(
        mut self,
        allowed_id_typ: Vec<String>,
        allowed_userinfo_typ: Vec<String>,
    ) -> Self {
        self.allowed_id_typ = allowed_id_typ;
        self.allowed_userinfo_typ = allowed_userinfo_typ;
        self
    }

    #[must_use]
    pub fn with_userinfo_requires_exp(mut self, userinfo_requires_exp: bool) -> Self {
        self.userinfo_requires_exp = userinfo_requires_exp;
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<Audience>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub claims: Claims,
    pub matched_client: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug)]
pub struct TokenVerifier {
    config: TokenVerifierConfig,
    fetcher: Arc<JwksFetcher>,
    allowed_clients: HashSet<String>,
    allowed_access_typ: HashSet<String>,
    allowed_id_typ: HashSet<String>,
    allowed_userinfo_typ: HashSet<String>,
}

impl TokenVerifier {
    #[must_use]
    pub fn new(config: TokenVerifierConfig, fetcher: Arc<JwksFetcher>) -> Self {
        assert_algorithm_family_is_not_mixed(&config.allowed_algorithms);
        let allowed_clients = config.allowed_clients.iter().cloned().collect();
        let allowed_access_typ = normalize_typ_set(&config.allowed_typ);
        let allowed_id_typ = normalize_typ_set(&config.allowed_id_typ);
        let allowed_userinfo_typ = normalize_typ_set(&config.allowed_userinfo_typ);
        Self {
            config,
            fetcher,
            allowed_clients,
            allowed_access_typ,
            allowed_id_typ,
            allowed_userinfo_typ,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        self.verify_access_token(token, true).await
    }

    pub async fn verify_related_token(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        self.verify_id_token(token).await
    }

    async fn verify_access_token(
        &self,
        token: &str,
        enforce_client: bool,
    ) -> Result<VerifiedToken, OidcError> {
        let header = decode_header(token).map_err(|_| OidcError::MalformedToken)?;
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(OidcError::AlgorithmNotAllowed);
        }
        enforce_typ(header.typ.as_deref(), &self.allowed_access_typ)?;
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let key = self
            .fetcher
            .key_for_kid_matching_alg(&kid, header.alg)
            .await?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&self.config.audiences);
        validation.leeway = self.config.leeway.as_secs();
        validation.validate_nbf = true;
        validation.required_spec_claims = ["iss", "aud", "exp"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|err| map_jwt_error(err, &self.config.issuer, token))?;
        let matched_client = if enforce_client {
            self.match_client(&data.claims)?
        } else {
            self.match_client(&data.claims).ok().flatten()
        };
        let scopes = self.scopes(&data.claims);
        Ok(VerifiedToken {
            claims: data.claims,
            matched_client,
            scopes,
        })
    }

    async fn verify_id_token(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        let header = decode_header(token).map_err(|_| OidcError::MalformedToken)?;
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(OidcError::AlgorithmNotAllowed);
        }
        enforce_optional_typ(header.typ.as_deref(), &self.allowed_id_typ)?;
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let key = self
            .fetcher
            .key_for_kid_matching_alg(&kid, header.alg)
            .await?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[self.config.issuer.as_str()]);
        let audiences = self.id_token_audiences();
        validation.set_audience(&audiences);
        validation.leeway = self.config.leeway.as_secs();
        validation.validate_nbf = true;
        validation.required_spec_claims = ["iss", "aud", "exp"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|err| map_jwt_error(err, &self.config.issuer, token))?;
        self.enforce_present_azp(&data.claims)?;
        self.enforce_multi_audience_azp(&data.claims, &audiences)?;
        let matched_client = self.match_client(&data.claims).ok().flatten();
        let scopes = self.scopes(&data.claims);
        Ok(VerifiedToken {
            claims: data.claims,
            matched_client,
            scopes,
        })
    }

    pub async fn verify_userinfo_jwt(
        &self,
        userinfo_jwt: &str,
        access_token: &VerifiedToken,
    ) -> Result<Claims, OidcError> {
        let issuers = [self.config.issuer.as_str()];
        self.verify_userinfo_jwt_with_claims_policy(
            userinfo_jwt,
            access_token,
            &issuers,
            &self.config.audiences,
        )
        .await
    }

    pub async fn verify_userinfo_jwt_with_claims_policy(
        &self,
        userinfo_jwt: &str,
        access_token: &VerifiedToken,
        accepted_issuers: &[&str],
        accepted_audiences: &[String],
    ) -> Result<Claims, OidcError> {
        let header = decode_header(userinfo_jwt).map_err(|_| OidcError::MalformedToken)?;
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(OidcError::AlgorithmNotAllowed);
        }
        enforce_optional_typ(header.typ.as_deref(), &self.allowed_userinfo_typ)?;
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let key = self
            .fetcher
            .key_for_kid_matching_alg(&kid, header.alg)
            .await?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.leeway = self.config.leeway.as_secs();
        validation.validate_nbf = true;
        validation.validate_aud = false;
        if self.config.userinfo_requires_exp {
            validation.required_spec_claims = ["exp"].iter().map(|s| (*s).to_string()).collect();
        } else {
            validation.required_spec_claims.clear();
        }
        let data = decode::<Claims>(userinfo_jwt, &key, &validation)
            .map_err(|err| map_jwt_error(err, &self.config.issuer, userinfo_jwt))?;
        let issuer = data
            .claims
            .iss
            .as_deref()
            .ok_or_else(|| OidcError::IssuerMismatch {
                expected: expected_issuers(accepted_issuers),
                actual: String::new(),
            })?;
        if !accepted_issuers.contains(&issuer) {
            return Err(OidcError::IssuerMismatch {
                expected: expected_issuers(accepted_issuers),
                actual: issuer.to_string(),
            });
        }
        let audience = data
            .claims
            .aud
            .as_ref()
            .ok_or(OidcError::AudienceMismatch)?;
        if !audience_intersects(audience, accepted_audiences) {
            return Err(OidcError::AudienceMismatch);
        }
        let Some(access_sub) = access_token.claims.sub.as_deref() else {
            return Err(OidcError::InvalidToken);
        };
        if data.claims.sub.as_deref() != Some(access_sub) {
            return Err(OidcError::InvalidToken);
        }
        Ok(data.claims)
    }

    fn id_token_audiences(&self) -> Vec<String> {
        if self.allowed_clients.is_empty() {
            return self.config.audiences.clone();
        }
        self.allowed_clients.iter().cloned().collect()
    }

    fn match_client(&self, claims: &Claims) -> Result<Option<String>, OidcError> {
        if self.allowed_clients.is_empty() {
            return Ok(None);
        }
        if let Some(azp) = &claims.azp {
            if self.allowed_clients.contains(azp) {
                return Ok(Some(format!("azp:{azp}")));
            }
            return Err(OidcError::ClientNotAllowed);
        }
        if let Some(client_id) = &claims.client_id {
            if self.allowed_clients.contains(client_id) {
                return Ok(Some(format!("client_id:{client_id}")));
            }
        }
        Err(OidcError::ClientNotAllowed)
    }

    fn enforce_present_azp(&self, claims: &Claims) -> Result<(), OidcError> {
        let Some(azp) = claims.azp.as_deref() else {
            return Ok(());
        };
        if self.allowed_clients.is_empty() || self.allowed_clients.contains(azp) {
            return Ok(());
        }
        Err(OidcError::ClientNotAllowed)
    }

    fn enforce_multi_audience_azp(
        &self,
        claims: &Claims,
        accepted_audiences: &[String],
    ) -> Result<(), OidcError> {
        let Some(Audience::Many(audiences)) = claims.aud.as_ref() else {
            return Ok(());
        };
        if audiences.len() <= 1 {
            return Ok(());
        }
        let azp = claims.azp.as_deref().ok_or(OidcError::ClientNotAllowed)?;
        if accepted_audiences.iter().any(|audience| audience == azp) {
            Ok(())
        } else {
            Err(OidcError::ClientNotAllowed)
        }
    }

    fn scopes(&self, claims: &Claims) -> Vec<String> {
        let raw = self.raw_scopes(claims);
        if let Some(scope_map) = &self.config.scope_map {
            raw.into_iter()
                .flat_map(|scope| {
                    scope_map
                        .get(&scope)
                        .cloned()
                        .unwrap_or_else(|| vec![scope])
                })
                .collect()
        } else {
            raw
        }
    }

    fn raw_scopes(&self, claims: &Claims) -> Vec<String> {
        if let Some(value) = claims.extra.get(&self.config.scope_claim) {
            return scope_values(value, self.config.scope_separator);
        }
        match self.config.scope_claim.as_str() {
            "sub" => claims.sub.iter().cloned().collect(),
            "client_id" => claims.client_id.iter().cloned().collect(),
            "azp" => claims.azp.iter().cloned().collect(),
            "aud" => match claims.aud.as_ref() {
                Some(Audience::One(value)) if self.config.audiences.contains(value) => {
                    vec![value.clone()]
                }
                Some(Audience::Many(values)) => values
                    .iter()
                    .filter(|value| self.config.audiences.contains(*value))
                    .cloned()
                    .collect(),
                None => Vec::new(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

fn scope_values(value: &Value, separator: char) -> Vec<String> {
    match value {
        Value::String(s) => s
            .split(separator)
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        Value::Object(_) => Vec::new(),
        _ => Vec::new(),
    }
}

pub async fn fetch_userinfo_jwt_with_policy(
    endpoint: &str,
    access_token: &str,
    fetch_url_policy: &FetchUrlPolicy,
    timeout: Duration,
    max_doc_bytes: u64,
) -> Result<String, OidcError> {
    let url = Url::parse(endpoint).map_err(|_| OidcError::InvalidUrl)?;
    let validated_url = fetch_url_policy
        .validate_for_immediate_fetch_with_timeout(&url, timeout)
        .await?;
    let resp = validated_url
        .immediate_get()?
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, "application/jwt")
        .timeout(timeout)
        .send()
        .await
        .map_err(OidcError::Transport)?;
    if !resp.status().is_success() {
        return Err(OidcError::HttpStatus(resp.status().as_u16()));
    }
    let body = read_bounded(resp, max_doc_bytes.max(1)).await?;
    String::from_utf8(body)
        .map(|value| value.trim().to_string())
        .map_err(|_| OidcError::Parse)
}

fn audience_intersects(audience: &Audience, accepted: &[String]) -> bool {
    match audience {
        Audience::One(value) => accepted.iter().any(|candidate| candidate == value),
        Audience::Many(values) => values
            .iter()
            .any(|value| accepted.iter().any(|candidate| candidate == value)),
    }
}

fn normalize_typ_set(values: &[String]) -> HashSet<String> {
    values.iter().map(|typ| typ.to_ascii_lowercase()).collect()
}

/// Case-insensitive membership test for a JOSE `typ` header against an
/// already-lowercased allow-list (see `normalize_typ_set`). `typ` is commonly
/// already lowercase (`"jwt"`, `"at+jwt"`), so try a direct hit before
/// allocating a lowercased copy for the fallback.
fn typ_in_allow_list(typ: &str, allowed: &HashSet<String>) -> bool {
    allowed.contains(typ) || allowed.contains(&typ.to_ascii_lowercase())
}

fn enforce_typ(typ: Option<&str>, allowed: &HashSet<String>) -> Result<(), OidcError> {
    if allowed.is_empty() {
        return Err(OidcError::TokenTypeNotAllowed);
    }
    let typ = typ.ok_or(OidcError::TokenTypeNotAllowed)?;
    if typ_in_allow_list(typ, allowed) {
        Ok(())
    } else {
        Err(OidcError::TokenTypeNotAllowed)
    }
}

/// Like [`enforce_typ`], but a MISSING `typ` header is accepted. The `typ`
/// header is OPTIONAL for ID Tokens and signed UserInfo responses (OpenID
/// Connect Core 1.0), and providers such as eSignet omit it. A present `typ`
/// must still be in the allow-list, and an empty allow-list still denies the
/// token type entirely (used to forbid a token class outright).
fn enforce_optional_typ(typ: Option<&str>, allowed: &HashSet<String>) -> Result<(), OidcError> {
    if allowed.is_empty() {
        return Err(OidcError::TokenTypeNotAllowed);
    }
    match typ {
        None => Ok(()),
        Some(typ) if typ_in_allow_list(typ, allowed) => Ok(()),
        Some(_) => Err(OidcError::TokenTypeNotAllowed),
    }
}

fn expected_issuers(accepted_issuers: &[&str]) -> String {
    accepted_issuers.join(",")
}

fn map_jwt_error(
    error: jsonwebtoken::errors::Error,
    expected_issuer: &str,
    token: &str,
) -> OidcError {
    match error.kind() {
        JwtErrorKind::ExpiredSignature => OidcError::TokenExpired,
        JwtErrorKind::ImmatureSignature => OidcError::TokenNotYetValid,
        JwtErrorKind::InvalidIssuer => OidcError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            actual: issuer_from_untrusted_payload(token).unwrap_or_default(),
        },
        JwtErrorKind::InvalidAudience => OidcError::AudienceMismatch,
        JwtErrorKind::InvalidSignature => OidcError::SignatureInvalid,
        _ => OidcError::InvalidToken,
    }
}

fn issuer_from_untrusted_payload(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Claims = serde_json::from_slice(&decoded).ok()?;
    claims.iss.filter(|issuer| !issuer.is_empty())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OidcError {
    #[error("transport error: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("bounded read failed: {0}")]
    BoundedRead(#[from] registry_platform_httputil::BoundedReadError),
    #[error("fetch URL denied: {0}")]
    FetchUrl(#[from] FetchUrlError),
    #[error("OIDC endpoint returned HTTP {0}")]
    HttpStatus(u16),
    #[error("invalid url")]
    InvalidUrl,
    #[error("OIDC document did not parse")]
    Parse,
    #[error("issuer mismatch: expected {expected}, actual {actual}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("token is malformed")]
    MalformedToken,
    #[error("token algorithm is not allowed")]
    AlgorithmNotAllowed,
    #[error("token type is not allowed")]
    TokenTypeNotAllowed,
    #[error("token header is missing kid")]
    MissingKid,
    #[error("token header kid is too long")]
    KidTooLong,
    #[error("kid is unknown")]
    UnknownKid,
    #[error("JWK is invalid")]
    InvalidJwk,
    #[error("token is expired")]
    TokenExpired,
    #[error("token is not yet valid")]
    TokenNotYetValid,
    #[error("token audience does not match")]
    AudienceMismatch,
    #[error("token signature is invalid")]
    SignatureInvalid,
    #[error("token is invalid")]
    InvalidToken,
    #[error("client is not allowed")]
    ClientNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    async fn serve_discovery(jwks_uri: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read listener addr");
        let issuer = format!("http://{addr}");
        let document = json!({
            "issuer": issuer,
            "jwks_uri": jwks_uri,
        });
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let document = document.clone();
                async move { Json(document) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        issuer
    }

    async fn serve_jwks(document: Arc<RwLock<Value>>, requests: Arc<AtomicUsize>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read listener addr");
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let document = Arc::clone(&document);
                let requests = Arc::clone(&requests);
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    Json(document.read().await.clone())
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        format!("http://{addr}/jwks")
    }

    fn jwks_with_kids(kids: &[&str]) -> Value {
        let keys: Vec<Value> = kids
            .iter()
            .map(|kid| {
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                    "alg": "EdDSA",
                    "kid": kid,
                })
            })
            .collect();
        json!({ "keys": keys })
    }

    fn jwks_test_config() -> JwksFetcherConfig {
        JwksFetcherConfig {
            cache_ttl: Duration::from_secs(3600),
            negative_cache_ttl: Duration::from_secs(3600),
            refresh_cooldown: Duration::from_secs(3600),
            max_doc_bytes: DEFAULT_DOC_BYTES,
            request_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn token_verifier_profiles_set_safe_related_token_defaults() {
        let config = TokenVerifierConfig::registry_relay_access_profile(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec![Algorithm::EdDSA],
            vec!["at+jwt".to_string()],
        )
        .with_scope_claim("permissions")
        .with_scope_separator(',')
        .with_allowed_clients(vec!["client-a".to_string()])
        .with_leeway(Duration::from_secs(30));

        assert_eq!(config.allowed_typ, vec!["at+jwt"]);
        assert_eq!(config.allowed_id_typ, vec!["JWT", "id_token"]);
        assert_eq!(config.allowed_userinfo_typ, vec!["JWT"]);
        assert!(config.userinfo_requires_exp);
        assert_eq!(config.scope_claim, "permissions");
        assert_eq!(config.scope_separator, ',');
        assert_eq!(config.allowed_clients, vec!["client-a"]);
        assert_eq!(config.leeway, Duration::from_secs(30));
    }

    #[test]
    fn federation_request_profile_binds_single_audience_and_type() {
        let config = TokenVerifierConfig::registry_notary_federation_request_profile(
            "https://peer.example",
            "did:web:agency-a.example.gov",
            vec![Algorithm::EdDSA],
            "registry-notary-federation+jwt",
        );

        assert_eq!(config.audiences, vec!["did:web:agency-a.example.gov"]);
        assert_eq!(config.allowed_typ, vec!["registry-notary-federation+jwt"]);
        assert_eq!(config.allowed_id_typ, vec!["JWT", "id_token"]);
        assert_eq!(config.allowed_userinfo_typ, vec!["JWT"]);
        assert!(config.userinfo_requires_exp);
    }

    fn rsa_jwk_with_modulus_bytes(kid: &str, modulus_bytes: usize) -> Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(vec![0xff; modulus_bytes]),
            "e": "AQAB",
        }))
        .expect("test RSA JWK parses")
    }

    fn rsa_jwk_with_modulus(kid: &str, modulus: Vec<u8>) -> Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(modulus),
            "e": "AQAB",
        }))
        .expect("test RSA JWK parses")
    }

    fn jwks_with_oct_key(kid: &str, secret: &[u8]) -> Value {
        json!({
            "keys": [{
                "kty": "oct",
                "kid": kid,
                "alg": "HS256",
                "k": URL_SAFE_NO_PAD.encode(secret),
            }]
        })
    }

    async fn hs256_test_verifier(
        issuer: &str,
        audiences: Vec<String>,
        allowed_clients: Vec<String>,
        kid: &str,
        secret: &[u8],
    ) -> TokenVerifier {
        hs256_test_verifier_with_userinfo_exp_policy(
            issuer,
            audiences,
            allowed_clients,
            kid,
            secret,
            true,
        )
        .await
    }

    async fn hs256_test_verifier_with_userinfo_exp_policy(
        issuer: &str,
        audiences: Vec<String>,
        allowed_clients: Vec<String>,
        kid: &str,
        secret: &[u8],
        userinfo_requires_exp: bool,
    ) -> TokenVerifier {
        let document = Arc::new(RwLock::new(jwks_with_oct_key(kid, secret)));
        let jwks_uri = serve_jwks(document, Arc::new(AtomicUsize::new(0))).await;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        ));
        TokenVerifier::new(
            TokenVerifierConfig {
                issuer: issuer.to_string(),
                audiences,
                allowed_algorithms: vec![Algorithm::HS256],
                allowed_typ: vec!["at+jwt".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp,
                scope_claim: "scope".to_string(),
                scope_separator: ' ',
                scope_map: None,
                allowed_clients,
                leeway: Duration::from_secs(60),
            },
            fetcher,
        )
    }

    fn signed_hs256_token(kid: &str, claims: Claims, secret: &[u8], typ: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        header.typ = typ.map(ToOwned::to_owned);
        let mut claims = serde_json::to_value(claims).expect("claims serialize");
        if let Value::Object(map) = &mut claims {
            map.retain(|_, value| !value.is_null());
        }
        encode(&header, &claims, &EncodingKey::from_secret(secret)).expect("sign HS256 test token")
    }

    fn unsigned_token(header: Value, claims: Value) -> String {
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[test]
    fn oidc_rsa_jwks_require_2048_bit_modulus() {
        let small = rsa_jwk_with_modulus_bytes("small", 128);
        let large = rsa_jwk_with_modulus_bytes("large", 256);
        let short_bit_length = rsa_jwk_with_modulus("short-bit-length", {
            let mut modulus = vec![0_u8; 256];
            modulus[0] = 0x01;
            modulus
        });

        assert!(matches!(validate_jwk(&small), Err(OidcError::InvalidJwk)));
        assert!(matches!(
            validate_jwk(&short_bit_length),
            Err(OidcError::InvalidJwk)
        ));
        validate_jwk(&large).expect("2048-bit RSA key is accepted");
    }

    #[test]
    #[should_panic(
        expected = "allowed_algorithms must not mix symmetric and asymmetric algorithms"
    )]
    fn oidc_verifier_rejects_mixed_symmetric_and_asymmetric_algorithms() {
        assert_algorithm_family_is_not_mixed(&[Algorithm::RS256, Algorithm::HS256]);
    }

    #[test]
    fn oidc_jwk_algorithm_must_match_header_algorithm() {
        let rsa = rsa_jwk_with_modulus_bytes("rsa", 256);
        validate_jwk_for_header(&rsa, Algorithm::RS256).expect("matching alg accepts");
        assert!(matches!(
            validate_jwk_for_header(&rsa, Algorithm::RS384),
            Err(OidcError::InvalidJwk)
        ));

        let oct: Jwk = serde_json::from_value(json!({
            "kty": "oct",
            "kid": "oct",
            "alg": "HS256",
            "k": URL_SAFE_NO_PAD.encode(b"secret"),
        }))
        .expect("oct JWK parses");
        validate_jwk_for_header(&oct, Algorithm::HS256).expect("matching alg accepts");
        assert!(matches!(
            validate_jwk_for_header(&oct, Algorithm::EdDSA),
            Err(OidcError::InvalidJwk)
        ));

        let p256: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF4k1JQWctzS0r8uXH6Gz-l4WfXccj5WHv0",
            "y": "x_FEzRu9dVvZt2pSuGQgH7u9tZxU7I5oUJu-4G8Azjo",
        }))
        .expect("P-256 JWK parses");
        validate_jwk_for_header(&p256, Algorithm::ES256).expect("matching curve accepts");
        assert!(matches!(
            validate_jwk_for_header(&p256, Algorithm::ES384),
            Err(OidcError::InvalidJwk)
        ));
    }

    fn verifier_for_header_tests() -> TokenVerifier {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        ));
        TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["registry-api".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp: true,
                scope_claim: "scope".to_string(),
                scope_separator: ' ',
                scope_map: None,
                allowed_clients: Vec::new(),
                leeway: Duration::from_secs(60),
            },
            fetcher,
        )
    }

    #[test]
    fn oidc_allowed_clients_matches_azp_then_client_id_never_sub() {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        ));
        let verifier = TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["aud".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp: true,
                scope_claim: "scope".to_string(),
                scope_separator: ' ',
                scope_map: None,
                allowed_clients: vec!["client-a".to_string()],
                leeway: Duration::from_secs(60),
            },
            fetcher,
        );
        let base_claims = Claims {
            sub: Some("client-a".to_string()),
            iss: None,
            aud: None,
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra: Map::new(),
        };
        assert!(matches!(
            verifier.match_client(&base_claims),
            Err(OidcError::ClientNotAllowed)
        ));
        let claims = Claims {
            client_id: Some("client-a".to_string()),
            ..base_claims.clone()
        };
        assert_eq!(
            verifier.match_client(&claims).unwrap(),
            Some("client_id:client-a".to_string())
        );
        let claims = Claims {
            azp: Some("client-b".to_string()),
            client_id: Some("client-a".to_string()),
            ..base_claims.clone()
        };
        assert!(matches!(
            verifier.match_client(&claims),
            Err(OidcError::ClientNotAllowed)
        ));
        let claims = Claims {
            azp: Some("client-a".to_string()),
            client_id: Some("client-b".to_string()),
            ..base_claims
        };
        assert_eq!(
            verifier.match_client(&claims).unwrap(),
            Some("azp:client-a".to_string())
        );
    }

    #[test]
    fn reserved_client_id_scope_claim_can_be_mapped() {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        ));
        let verifier = TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["aud".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp: true,
                scope_claim: "client_id".to_string(),
                scope_separator: ' ',
                scope_map: Some(HashMap::from([(
                    "registry-lab-api".to_string(),
                    vec!["social_protection_registry:rows".to_string()],
                )])),
                allowed_clients: Vec::new(),
                leeway: Duration::from_secs(60),
            },
            fetcher,
        );
        let claims = Claims {
            sub: Some("machine-user".to_string()),
            iss: None,
            aud: None,
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: Some("registry-lab-api".to_string()),
            extra: Map::new(),
        };
        assert_eq!(
            verifier.scopes(&claims),
            vec!["social_protection_registry:rows".to_string()]
        );
    }

    #[test]
    fn reserved_audience_scope_claim_can_be_mapped() {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        ));
        let verifier = TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["registry-lab-api".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp: true,
                scope_claim: "aud".to_string(),
                scope_separator: ' ',
                scope_map: Some(HashMap::from([(
                    "registry-lab-api".to_string(),
                    vec!["social_protection_registry:rows".to_string()],
                )])),
                allowed_clients: Vec::new(),
                leeway: Duration::from_secs(60),
            },
            fetcher,
        );
        let claims = Claims {
            sub: Some("machine-user".to_string()),
            iss: None,
            aud: Some(Audience::Many(vec![
                "registry-lab-api".to_string(),
                "other-audience".to_string(),
            ])),
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra: Map::new(),
        };
        assert_eq!(
            verifier.scopes(&claims),
            vec!["social_protection_registry:rows".to_string()]
        );
    }

    #[test]
    fn object_scope_claim_keys_do_not_grant_scopes() {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        ));
        let verifier = TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["registry-lab-api".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
                allowed_id_typ: vec!["JWT".to_string(), "id_token".to_string()],
                allowed_userinfo_typ: vec!["JWT".to_string()],
                userinfo_requires_exp: true,
                scope_claim: "realm_access".to_string(),
                scope_separator: ' ',
                scope_map: Some(HashMap::from([(
                    "admin:write".to_string(),
                    vec!["registry:admin".to_string()],
                )])),
                allowed_clients: Vec::new(),
                leeway: Duration::from_secs(60),
            },
            fetcher,
        );
        let mut extra = Map::new();
        extra.insert(
            "realm_access".to_string(),
            json!({
                "admin:write": false,
                "registry:read": true
            }),
        );
        let claims = Claims {
            sub: Some("machine-user".to_string()),
            iss: None,
            aud: Some(Audience::One("registry-lab-api".to_string())),
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra,
        };

        assert!(verifier.scopes(&claims).is_empty());
    }

    #[tokio::test]
    async fn oidc_rejects_unsigned_or_disallowed_algorithm() {
        let verifier = verifier_for_header_tests();
        let token = unsigned_token(
            json!({ "alg": "none", "typ": "JWT", "kid": "kid" }),
            json!({ "iss": "https://issuer.example", "aud": "registry-api", "exp": 4_102_444_800_i64 }),
        );

        assert!(matches!(
            verifier.verify(&token).await,
            Err(OidcError::AlgorithmNotAllowed | OidcError::MalformedToken)
        ));
    }

    #[tokio::test]
    async fn oidc_rejects_bad_typ_before_jwks_lookup() {
        let verifier = verifier_for_header_tests();
        let token = unsigned_token(
            json!({ "alg": "EdDSA", "typ": "at+jwt", "kid": "kid" }),
            json!({ "iss": "https://issuer.example", "aud": "registry-api", "exp": 4_102_444_800_i64 }),
        );

        assert!(matches!(
            verifier.verify(&token).await,
            Err(OidcError::TokenTypeNotAllowed)
        ));
    }

    #[tokio::test]
    async fn oidc_rejects_missing_access_typ_before_jwks_lookup() {
        let verifier = verifier_for_header_tests();
        let token = unsigned_token(
            json!({ "alg": "EdDSA", "kid": "kid" }),
            json!({ "iss": "https://issuer.example", "aud": "registry-api", "exp": 4_102_444_800_i64 }),
        );

        assert!(matches!(
            verifier.verify(&token).await,
            Err(OidcError::TokenTypeNotAllowed)
        ));
    }

    #[tokio::test]
    async fn oidc_rejects_missing_kid_before_jwks_lookup() {
        let verifier = verifier_for_header_tests();
        let token = unsigned_token(
            json!({ "alg": "EdDSA", "typ": "JWT" }),
            json!({ "iss": "https://issuer.example", "aud": "registry-api", "exp": 4_102_444_800_i64 }),
        );

        assert!(matches!(
            verifier.verify(&token).await,
            Err(OidcError::MissingKid)
        ));
    }

    fn test_claims(issuer: Option<&str>, audience: Option<&str>, subject: Option<&str>) -> Claims {
        Claims {
            sub: subject.map(ToOwned::to_owned),
            iss: issuer.map(ToOwned::to_owned),
            aud: audience.map(|aud| Audience::One(aud.to_string())),
            exp: Some(4_102_444_800_i64),
            iat: None,
            nbf: None,
            azp: Some("citizen-client".to_string()),
            client_id: None,
            extra: Map::new(),
        }
    }

    #[tokio::test]
    async fn oidc_userinfo_jwt_requires_issuer_audience_and_matching_subject() {
        let secret = b"registry-platform-oidc-test-secret";
        let verifier = hs256_test_verifier(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
        )
        .await;
        let access = VerifiedToken {
            claims: test_claims(
                Some("https://issuer.example"),
                Some("registry-api"),
                Some("subject-1"),
            ),
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: Vec::new(),
        };
        let accepted_issuers = ["https://issuer.example/userinfo"];
        let accepted_audiences = vec!["citizen-client".to_string()];

        let valid = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        verifier
            .verify_userinfo_jwt_with_claims_policy(
                &valid,
                &access,
                &accepted_issuers,
                &accepted_audiences,
            )
            .await
            .expect("valid signed UserInfo verifies");

        // A signed UserInfo response without a `typ` header verifies: the `typ`
        // header is OPTIONAL for UserInfo JWTs (OpenID Connect Core 1.0). eSignet
        // omits it.
        let missing_typ = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            None,
        );
        verifier
            .verify_userinfo_jwt_with_claims_policy(
                &missing_typ,
                &access,
                &accepted_issuers,
                &accepted_audiences,
            )
            .await
            .expect("UserInfo without a typ header verifies");

        // A present-but-disallowed `typ` is still rejected.
        let wrong_typ = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            Some("at+jwt"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &wrong_typ,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::TokenTypeNotAllowed)
        ));

        let mut missing_exp_claims = test_claims(
            Some("https://issuer.example/userinfo"),
            Some("citizen-client"),
            Some("subject-1"),
        );
        missing_exp_claims.exp = None;
        let missing_exp = signed_hs256_token("kid", missing_exp_claims, secret, Some("JWT"));
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &missing_exp,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::InvalidToken)
        ));

        let missing_issuer = signed_hs256_token(
            "kid",
            test_claims(None, Some("citizen-client"), Some("subject-1")),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &missing_issuer,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::IssuerMismatch { .. })
        ));

        let wrong_issuer = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://evil.example"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &wrong_issuer,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::IssuerMismatch { .. })
        ));

        let missing_audience = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                None,
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &missing_audience,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::AudienceMismatch)
        ));

        let wrong_audience = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                Some("other-client"),
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &wrong_audience,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::AudienceMismatch)
        ));

        let wrong_subject = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example/userinfo"),
                Some("citizen-client"),
                Some("subject-2"),
            ),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &wrong_subject,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn oidc_userinfo_optional_exp_still_rejects_expired_claim_when_present() {
        let secret = b"registry-platform-oidc-test-secret";
        let verifier = hs256_test_verifier_with_userinfo_exp_policy(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
            false,
        )
        .await;
        let access = VerifiedToken {
            claims: test_claims(
                Some("https://issuer.example"),
                Some("registry-api"),
                Some("subject-1"),
            ),
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: Vec::new(),
        };
        let accepted_issuers = ["https://issuer.example/userinfo"];
        let accepted_audiences = vec!["citizen-client".to_string()];

        let mut missing_exp_claims = test_claims(
            Some("https://issuer.example/userinfo"),
            Some("citizen-client"),
            Some("subject-1"),
        );
        missing_exp_claims.exp = None;
        let missing_exp = signed_hs256_token("kid", missing_exp_claims, secret, Some("JWT"));
        verifier
            .verify_userinfo_jwt_with_claims_policy(
                &missing_exp,
                &access,
                &accepted_issuers,
                &accepted_audiences,
            )
            .await
            .expect("optional exp policy accepts missing exp");

        let mut expired_claims = test_claims(
            Some("https://issuer.example/userinfo"),
            Some("citizen-client"),
            Some("subject-1"),
        );
        expired_claims.exp = Some(1);
        let expired = signed_hs256_token("kid", expired_claims, secret, Some("JWT"));
        assert!(matches!(
            verifier
                .verify_userinfo_jwt_with_claims_policy(
                    &expired,
                    &access,
                    &accepted_issuers,
                    &accepted_audiences,
                )
                .await,
            Err(OidcError::TokenExpired)
        ));
    }

    #[tokio::test]
    async fn oidc_related_id_token_rejects_access_token_type_and_uses_client_audience() {
        let secret = b"registry-platform-id-token-test-secret";
        let verifier = hs256_test_verifier(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
        )
        .await;

        let id_token = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        verifier
            .verify_related_token(&id_token)
            .await
            .expect("ID token audience is the OIDC client");

        let access_typed = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            Some("at+jwt"),
        );
        assert!(matches!(
            verifier.verify_related_token(&access_typed).await,
            Err(OidcError::TokenTypeNotAllowed)
        ));

        let resource_audience = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example"),
                Some("registry-api"),
                Some("subject-1"),
            ),
            secret,
            Some("JWT"),
        );
        assert!(matches!(
            verifier.verify_related_token(&resource_audience).await,
            Err(OidcError::AudienceMismatch)
        ));
    }

    #[tokio::test]
    async fn oidc_related_id_token_allows_missing_typ() {
        // OpenID Connect Core 1.0 makes the ID Token `typ` header OPTIONAL;
        // eSignet (and other IdPs) omit it. A missing `typ` must verify, while a
        // present-but-disallowed `typ` stays rejected (asserted in the test above).
        let secret = b"registry-platform-id-token-missing-typ-secret";
        let verifier = hs256_test_verifier(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
        )
        .await;

        let id_token = signed_hs256_token(
            "kid",
            test_claims(
                Some("https://issuer.example"),
                Some("citizen-client"),
                Some("subject-1"),
            ),
            secret,
            None,
        );
        verifier
            .verify_related_token(&id_token)
            .await
            .expect("ID token without a typ header verifies");
    }

    #[tokio::test]
    async fn oidc_related_id_token_enforces_azp_for_multi_audience_tokens() {
        let secret = b"registry-platform-id-token-azp-test-secret";
        let verifier = hs256_test_verifier(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
        )
        .await;
        let mut claims = test_claims(
            Some("https://issuer.example"),
            Some("citizen-client"),
            Some("subject-1"),
        );
        claims.aud = Some(Audience::Many(vec![
            "citizen-client".to_string(),
            "other-audience".to_string(),
        ]));
        claims.azp = None;
        let missing_azp = signed_hs256_token("kid", claims.clone(), secret, Some("JWT"));
        assert!(matches!(
            verifier.verify_related_token(&missing_azp).await,
            Err(OidcError::ClientNotAllowed)
        ));

        claims.azp = Some("other-audience".to_string());
        let wrong_azp = signed_hs256_token("kid", claims.clone(), secret, Some("JWT"));
        assert!(matches!(
            verifier.verify_related_token(&wrong_azp).await,
            Err(OidcError::ClientNotAllowed)
        ));

        claims.azp = Some("citizen-client".to_string());
        let valid = signed_hs256_token("kid", claims, secret, Some("JWT"));
        verifier
            .verify_related_token(&valid)
            .await
            .expect("azp matching client audience accepts");
    }

    #[tokio::test]
    async fn oidc_related_id_token_rejects_wrong_present_azp_for_single_audience_tokens() {
        let secret = b"registry-platform-id-token-single-aud-azp-test-secret";
        let verifier = hs256_test_verifier(
            "https://issuer.example",
            vec!["registry-api".to_string()],
            vec!["citizen-client".to_string()],
            "kid",
            secret,
        )
        .await;
        let mut claims = test_claims(
            Some("https://issuer.example"),
            Some("citizen-client"),
            Some("subject-1"),
        );
        claims.azp = Some("other-client".to_string());
        let wrong_azp = signed_hs256_token("kid", claims.clone(), secret, Some("JWT"));
        assert!(matches!(
            verifier.verify_related_token(&wrong_azp).await,
            Err(OidcError::ClientNotAllowed)
        ));

        claims.azp = Some("citizen-client".to_string());
        let valid = signed_hs256_token("kid", claims, secret, Some("JWT"));
        verifier
            .verify_related_token(&valid)
            .await
            .expect("single-audience ID token with allowed azp accepts");
    }

    #[test]
    fn issuer_from_untrusted_payload_extracts_issuer_for_diagnostics() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://actual.example"}"#);
        let token = format!("header.{payload}.signature");

        assert_eq!(
            issuer_from_untrusted_payload(&token).as_deref(),
            Some("https://actual.example")
        );
        assert_eq!(issuer_from_untrusted_payload("not-a-jwt"), None);
    }

    #[tokio::test]
    async fn discovery_validates_jwks_uri_override() {
        let cfg = OidcDiscoveryConfig {
            issuer: "https://issuer.example".to_string(),
            jwks_uri_override: Some("http://127.0.0.1/jwks".to_string()),
            discovery_timeout: Duration::from_secs(1),
            max_doc_bytes: DEFAULT_DOC_BYTES,
        };
        let err = fetch_discovery_with_policy(&cfg, &FetchUrlPolicy::strict())
            .await
            .expect_err("strict policy rejects http override");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::SchemeDenied { .. })
        ));

        let document = fetch_discovery_with_policy(&cfg, &FetchUrlPolicy::dev())
            .await
            .expect("dev policy accepts loopback override");
        assert_eq!(document.issuer, cfg.issuer);
        assert_eq!(document.jwks_uri, "http://127.0.0.1/jwks");
    }

    #[tokio::test]
    async fn discovery_validates_discovery_url_and_returned_jwks_uri() {
        let issuer = serve_discovery("http://10.0.0.1/jwks").await;
        let cfg = OidcDiscoveryConfig {
            issuer,
            jwks_uri_override: None,
            discovery_timeout: Duration::from_secs(1),
            max_doc_bytes: DEFAULT_DOC_BYTES,
        };
        let err = fetch_discovery(&cfg)
            .await
            .expect_err("strict policy rejects loopback discovery URL before fetch");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::SchemeDenied { .. })
        ));

        let err = fetch_discovery_with_policy(&cfg, &FetchUrlPolicy::dev())
            .await
            .expect_err("dev policy rejects returned private jwks_uri");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::PrivateRangeDenied { .. })
        ));
    }

    #[tokio::test]
    async fn jwks_fetcher_caches_keys_until_ttl() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["cached-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        );

        fetcher
            .key_for_kid("cached-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        *document.write().await = jwks_with_kids(&[]);
        fetcher
            .key_for_kid("cached-kid")
            .await
            .expect("cached key is reused while ttl is valid");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn jwks_fetcher_force_refresh_is_rate_limited_by_cooldown() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["known-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        );

        fetcher
            .key_for_kid("known-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let err = fetcher
            .key_for_kid("missing-kid-1")
            .await
            .expect_err("fresh unknown kid triggers one forced refresh");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        let err = fetcher
            .key_for_kid("missing-kid-2")
            .await
            .expect_err("forced refresh cooldown suppresses repeated refreshes");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn jwks_fetcher_negative_cache_remembers_unknown_kid() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["known-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        );

        fetcher
            .key_for_kid("known-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let err = fetcher
            .key_for_kid("missing-kid")
            .await
            .expect_err("unknown kid is remembered");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        let err = fetcher
            .key_for_kid("missing-kid")
            .await
            .expect_err("negative cache answers repeated unknown kid");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn jwks_fetcher_rejects_overlong_kid_and_bounds_negative_cache() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["known"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        );

        let overlong_kid = "x".repeat(DEFAULT_MAX_KID_BYTES + 1);
        let err = fetcher
            .key_for_kid(&overlong_kid)
            .await
            .expect_err("overlong kid is rejected before fetching");
        assert!(matches!(err, OidcError::KidTooLong));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert!(fetcher.state.read().await.negative.is_empty());

        fetcher
            .key_for_kid("known")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let now = Instant::now();
        {
            let mut state = fetcher.state.write().await;
            for index in 0..DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES {
                state.negative.insert(format!("miss-{index}"), now);
            }
        }
        fetcher.remember_unknown_kid("overflow").await;

        let state = fetcher.state.read().await;
        assert_eq!(state.negative.len(), DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES);
        assert!(state.negative.contains_key("overflow"));
        let retained_seed_entries = (0..DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES)
            .filter(|index| state.negative.contains_key(&format!("miss-{index}")))
            .count();
        assert_eq!(
            retained_seed_entries,
            DEFAULT_MAX_NEGATIVE_CACHE_ENTRIES - 1
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn jwks_fetcher_singleflights_concurrent_cold_refresh() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["cold-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        ));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let fetcher = Arc::clone(&fetcher);
            tasks.push(tokio::spawn(async move {
                fetcher
                    .key_for_kid("cold-kid")
                    .await
                    .expect("concurrent lookup gets key");
            }));
        }

        for task in tasks {
            task.await.expect("lookup task joins");
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn jwks_fetcher_singleflights_concurrent_stale_refresh() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["stale-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let mut config = jwks_test_config();
        config.cache_ttl = Duration::from_millis(500);
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            config,
            FetchUrlPolicy::dev(),
        ));

        fetcher
            .key_for_kid("stale-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(600)).await;

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let fetcher = Arc::clone(&fetcher);
            tasks.push(tokio::spawn(async move {
                fetcher
                    .key_for_kid("stale-kid")
                    .await
                    .expect("concurrent stale lookup gets key");
            }));
        }

        for task in tasks {
            task.await.expect("lookup task joins");
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn jwks_fetcher_forced_refresh_loads_rotated_key() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["old-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            jwks_uri,
            jwks_test_config(),
            FetchUrlPolicy::dev(),
        );

        fetcher
            .key_for_kid("old-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        *document.write().await = jwks_with_kids(&["rotated"]);
        fetcher
            .key_for_kid("rotated")
            .await
            .expect("fresh unknown kid forces refresh for key rotation");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn jwks_fetcher_retries_negative_kid_after_refresh_cooldown() {
        let document = Arc::new(RwLock::new(jwks_with_kids(&["old-kid"])));
        let requests = Arc::new(AtomicUsize::new(0));
        let jwks_uri = serve_jwks(Arc::clone(&document), Arc::clone(&requests)).await;
        let mut config = jwks_test_config();
        config.refresh_cooldown = Duration::from_millis(50);
        config.negative_cache_ttl = Duration::from_secs(3600);
        let fetcher =
            JwksFetcher::new_with_fetch_url_policy(jwks_uri, config, FetchUrlPolicy::dev());

        fetcher
            .key_for_kid("old-kid")
            .await
            .expect("initial lookup fetches key");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let err = fetcher
            .key_for_kid("attacker-miss")
            .await
            .expect_err("unknown kid triggers a forced refresh");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        *document.write().await = jwks_with_kids(&["rotated"]);
        let err = fetcher
            .key_for_kid("rotated")
            .await
            .expect_err("cooldown suppresses immediate repeated refresh");
        assert!(matches!(err, OidcError::UnknownKid));
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        tokio::time::sleep(Duration::from_millis(60)).await;
        fetcher
            .key_for_kid("rotated")
            .await
            .expect("negative kid is retried after refresh cooldown");
        assert_eq!(requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn jwks_refresh_validates_url_before_fetching() {
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            "http://10.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        );

        let err = fetcher
            .key_for_kid("kid")
            .await
            .expect_err("private jwks_uri rejected before transport");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::PrivateRangeDenied { .. })
        ));
    }
}
