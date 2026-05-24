use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use registry_platform_httputil::{read_bounded, FetchUrlError, FetchUrlPolicy};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::RwLock;

const DEFAULT_DOC_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct OidcDiscoveryConfig {
    pub issuer: String,
    pub jwks_uri_override: Option<String>,
    pub discovery_timeout: Duration,
    pub max_doc_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub async fn fetch_discovery(
    cfg: &OidcDiscoveryConfig,
    client: &reqwest::Client,
) -> Result<DiscoveryDocument, OidcError> {
    fetch_discovery_with_policy(cfg, client, &FetchUrlPolicy::strict()).await
}

pub async fn fetch_discovery_with_policy(
    cfg: &OidcDiscoveryConfig,
    _client: &reqwest::Client,
    fetch_url_policy: &FetchUrlPolicy,
) -> Result<DiscoveryDocument, OidcError> {
    if let Some(jwks_uri) = &cfg.jwks_uri_override {
        let url = Url::parse(jwks_uri).map_err(|_| OidcError::InvalidUrl)?;
        fetch_url_policy.validate_for_immediate_fetch(&url)?;
        return Ok(DiscoveryDocument {
            issuer: cfg.issuer.clone(),
            jwks_uri: jwks_uri.clone(),
            extra: Map::new(),
        });
    }
    let mut issuer = cfg.issuer.trim_end_matches('/').to_string();
    issuer.push_str("/.well-known/openid-configuration");
    let url = Url::parse(&issuer).map_err(|_| OidcError::InvalidUrl)?;
    let validated_url = fetch_url_policy.validate_for_immediate_fetch(&url)?;
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
    fetch_url_policy.validate_for_immediate_fetch(&jwks_uri)?;
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

enum JwksCacheLookup {
    Hit(DecodingKey),
    FreshMiss,
    StaleOrEmpty,
    NegativeMiss,
}

#[derive(Debug)]
pub struct JwksFetcher {
    jwks_uri: String,
    _client: reqwest::Client,
    config: JwksFetcherConfig,
    fetch_url_policy: FetchUrlPolicy,
    state: RwLock<JwksState>,
}

impl JwksFetcher {
    #[must_use]
    pub fn new(jwks_uri: String, client: reqwest::Client, config: JwksFetcherConfig) -> Self {
        Self::new_with_fetch_url_policy(jwks_uri, client, config, FetchUrlPolicy::strict())
    }

    #[must_use]
    pub fn new_with_fetch_url_policy(
        jwks_uri: String,
        client: reqwest::Client,
        config: JwksFetcherConfig,
        fetch_url_policy: FetchUrlPolicy,
    ) -> Self {
        Self {
            jwks_uri,
            _client: client,
            config,
            fetch_url_policy,
            state: RwLock::new(JwksState::default()),
        }
    }

    pub async fn key_for_kid(&self, kid: &str) -> Result<DecodingKey, OidcError> {
        if kid.is_empty() {
            return Err(OidcError::MissingKid);
        }
        match self.cached_key(kid, Instant::now()).await? {
            JwksCacheLookup::Hit(key) => return Ok(key),
            JwksCacheLookup::NegativeMiss => return Err(OidcError::UnknownKid),
            JwksCacheLookup::FreshMiss => {}
            JwksCacheLookup::StaleOrEmpty => {
                self.refresh(false).await?;
                match self.cached_key(kid, Instant::now()).await? {
                    JwksCacheLookup::Hit(key) => return Ok(key),
                    JwksCacheLookup::NegativeMiss => return Err(OidcError::UnknownKid),
                    JwksCacheLookup::FreshMiss | JwksCacheLookup::StaleOrEmpty => {
                        self.remember_unknown_kid(kid).await;
                        return Err(OidcError::UnknownKid);
                    }
                }
            }
        }

        if self.should_force_refresh(Instant::now()).await {
            self.refresh(true).await?;
            match self.cached_key(kid, Instant::now()).await? {
                JwksCacheLookup::Hit(key) => return Ok(key),
                JwksCacheLookup::NegativeMiss => return Err(OidcError::UnknownKid),
                JwksCacheLookup::FreshMiss | JwksCacheLookup::StaleOrEmpty => {}
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
        self.state
            .write()
            .await
            .negative
            .insert(kid.to_string(), Instant::now());
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
                DecodingKey::from_jwk(jwk)
                    .map(JwksCacheLookup::Hit)
                    .map_err(|_| OidcError::InvalidJwk)
            })
    }

    async fn refresh(&self, forced: bool) -> Result<(), OidcError> {
        let url = Url::parse(&self.jwks_uri).map_err(|_| OidcError::InvalidUrl)?;
        let validated_url = self.fetch_url_policy.validate_for_immediate_fetch(&url)?;
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

#[derive(Debug, Clone)]
pub struct TokenVerifierConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub allowed_algorithms: Vec<Algorithm>,
    pub allowed_typ: Vec<String>,
    pub scope_claim: String,
    pub scope_separator: char,
    pub scope_map: Option<HashMap<String, Vec<String>>>,
    pub allowed_clients: Vec<String>,
    pub leeway: Duration,
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
    allowed_typ: HashSet<String>,
}

impl TokenVerifier {
    #[must_use]
    pub fn new(config: TokenVerifierConfig, fetcher: Arc<JwksFetcher>) -> Self {
        let allowed_clients = config.allowed_clients.iter().cloned().collect();
        let allowed_typ = config
            .allowed_typ
            .iter()
            .map(|typ| typ.to_ascii_lowercase())
            .collect();
        Self {
            config,
            fetcher,
            allowed_clients,
            allowed_typ,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        let header = decode_header(token).map_err(|_| OidcError::MalformedToken)?;
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(OidcError::AlgorithmNotAllowed);
        }
        if !self.allowed_typ.is_empty() {
            let typ = header
                .typ
                .as_deref()
                .ok_or(OidcError::TokenTypeNotAllowed)?;
            if !self.allowed_typ.contains(&typ.to_ascii_lowercase()) {
                return Err(OidcError::TokenTypeNotAllowed);
            }
        }
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let key = self.fetcher.key_for_kid(&kid).await?;
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
        let matched_client = self.match_client(&data.claims)?;
        let scopes = self.scopes(&data.claims);
        Ok(VerifiedToken {
            claims: data.claims,
            matched_client,
            scopes,
        })
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

    fn scopes(&self, claims: &Claims) -> Vec<String> {
        let Some(value) = claims.extra.get(&self.config.scope_claim) else {
            return Vec::new();
        };
        let raw: Vec<String> = match value {
            Value::String(s) => s
                .split(self.config.scope_separator)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        };
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
    fn oidc_allowed_clients_matches_azp_then_client_id_never_sub() {
        let fetcher = Arc::new(JwksFetcher::new(
            "http://127.0.0.1/jwks".to_string(),
            reqwest::Client::new(),
            JwksFetcherConfig::defaults(),
        ));
        let verifier = TokenVerifier::new(
            TokenVerifierConfig {
                issuer: "https://issuer.example".to_string(),
                audiences: vec!["aud".to_string()],
                allowed_algorithms: vec![Algorithm::EdDSA],
                allowed_typ: vec!["JWT".to_string()],
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
        let client = reqwest::Client::new();

        let err = fetch_discovery_with_policy(&cfg, &client, &FetchUrlPolicy::strict())
            .await
            .expect_err("strict policy rejects http override");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::SchemeDenied { .. })
        ));

        let document = fetch_discovery_with_policy(&cfg, &client, &FetchUrlPolicy::dev())
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
        let client = reqwest::Client::new();

        let err = fetch_discovery(&cfg, &client)
            .await
            .expect_err("strict policy rejects loopback discovery URL before fetch");
        assert!(matches!(
            err,
            OidcError::FetchUrl(FetchUrlError::SchemeDenied { .. })
        ));

        let err = fetch_discovery_with_policy(&cfg, &client, &FetchUrlPolicy::dev())
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
            reqwest::Client::new(),
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
            reqwest::Client::new(),
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
            reqwest::Client::new(),
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
    async fn jwks_refresh_validates_url_before_fetching() {
        let fetcher = JwksFetcher::new_with_fetch_url_policy(
            "http://10.0.0.1/jwks".to_string(),
            reqwest::Client::new(),
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
