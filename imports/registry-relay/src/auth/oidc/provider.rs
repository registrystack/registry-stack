// SPDX-License-Identifier: Apache-2.0
//! [`OidcAuth`]: resource-server bearer-JWT verifier.
//!
//! ## Verification flow
//!
//! 1. Read `Authorization: Bearer <jwt>`. OIDC does not accept the
//!    `X-Api-Key` header; that header is the API-key provider's legacy
//!    surface only.
//! 2. Decode the JOSE header. Reject tokens whose `typ` is not in the
//!    configured allowlist (defaults to `JWT` / `at+jwt`), whose `alg`
//!    is not in the configured allowlist (defaults to RS256/ES256/EdDSA;
//!    HS\* and `none` are intentionally excluded), or that have no
//!    `kid`.
//! 3. Resolve the verifier key via [`super::jwks::JwksCache`]. On
//!    unknown `kid` the cache triggers one (rate-limited) refresh.
//! 4. Run [`jsonwebtoken::decode`] with a [`Validation`] configured for
//!    the configured issuer, audiences, leeway, and algorithm allowlist
//!    plus `validate_nbf = true`. Required spec claims are `iss`, `aud`,
//!    `exp`.
//! 5. Enforce the `allowed_clients` policy against `azp` (preferred)
//!    or `client_id`. Empty config list means any client.
//! 6. Build the [`super::super::Principal`]: `principal_id` is `sub` if
//!    present, else `client_id`, else `azp`. Scopes are extracted from
//!    the configured claim (string with whitespace separators or array
//!    of strings) and renamed through `scope_map`.
//!
//! ## What this module does *not* do
//!
//! * No token minting or refresh.
//! * No symmetric-key (`HS*`) or `none` signature acceptance; these
//!   shapes are absent from [`crate::config::OidcAlgorithm`].
//! * No persistent storage; all state is in-process. JWKS rotation
//!   propagation is the configured `jwks_cache_ttl` plus the
//!   refresh-on-unknown-kid path.

use std::collections::{BTreeMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderMap};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::config::{OidcAlgorithm, OidcConfig};
use crate::error::AuthError;

use super::super::{AuthMode, AuthProvider, Principal, ScopeSet};
use super::jwks::{JwksCache, JwksError, JwksFetcher};

/// HTTP authentication scheme accepted by the OIDC provider.
const BEARER_SCHEME: &str = "Bearer";

/// Bearer-JWT verifier built from one [`OidcConfig`] block.
///
/// One instance is built at startup and held behind
/// `Arc<dyn AuthProvider>`. The struct is `Send + Sync` so the same
/// instance serves every concurrent request.
pub struct OidcAuth {
    issuer: String,
    audience: Vec<String>,
    algorithms: Vec<Algorithm>,
    leeway: Duration,
    scope_claim: String,
    scope_map: BTreeMap<String, String>,
    /// `None` means no allowlist (any client accepted). `Some(set)`
    /// means the token's `azp` or `client_id` must be in the set.
    allowed_clients: Option<HashSet<String>>,
    /// Accepted JOSE `typ` values, normalised to lowercase for the
    /// case-insensitive match RFC 7515 prescribes.
    token_types: HashSet<String>,
    cache: Arc<JwksCache>,
}

impl OidcAuth {
    /// Build the provider from config plus a JWKS fetcher. The
    /// resulting provider owns a fresh [`JwksCache`].
    #[must_use]
    pub fn new(config: &OidcConfig, fetcher: Arc<dyn JwksFetcher>) -> Self {
        let cache = Arc::new(JwksCache::new(fetcher, config.jwks_cache_ttl));
        Self::with_cache(config, cache)
    }

    /// Build the provider on top of an existing cache. Used by tests
    /// that want to seed a cache and assert no extra fetches happen.
    #[must_use]
    pub fn with_cache(config: &OidcConfig, cache: Arc<JwksCache>) -> Self {
        let algorithms = config
            .algorithms
            .iter()
            .map(|alg| match alg {
                OidcAlgorithm::Rs256 => Algorithm::RS256,
                OidcAlgorithm::Es256 => Algorithm::ES256,
                OidcAlgorithm::EdDsa => Algorithm::EdDSA,
            })
            .collect();
        let allowed_clients = if config.allowed_clients.is_empty() {
            None
        } else {
            Some(config.allowed_clients.iter().cloned().collect())
        };
        let token_types: HashSet<String> = config
            .token_types
            .iter()
            .map(|t| t.to_ascii_lowercase())
            .collect();
        Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            algorithms,
            leeway: config.leeway,
            scope_claim: config.scope_claim.clone(),
            scope_map: config.scope_map.clone(),
            allowed_clients,
            token_types,
            cache,
        }
    }

    /// Number of cached JWKS keys. Operational signal for startup
    /// logs and tests; not on the verify hot path.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.cache.key_count()
    }

    async fn verify(&self, presented: &str) -> Result<Principal, AuthError> {
        let header = decode_header(presented).map_err(|err| {
            tracing::debug!(
                target: "registry_relay::auth",
                error = %err,
                "oidc: decode_header failed",
            );
            AuthError::MalformedCredential
        })?;

        match &header.typ {
            Some(typ) => {
                if !self.token_types.contains(&typ.to_ascii_lowercase()) {
                    tracing::debug!(
                        target: "registry_relay::auth",
                        typ = %typ,
                        "oidc: rejected token by typ",
                    );
                    return Err(AuthError::MalformedCredential);
                }
            }
            None => {
                // Absent `typ` is conventionally JWT. Honour it only if
                // the configured allowlist contains JWT.
                if !self.token_types.contains("jwt") {
                    tracing::debug!(
                        target: "registry_relay::auth",
                        "oidc: token missing typ and JWT not allowed",
                    );
                    return Err(AuthError::MalformedCredential);
                }
            }
        }

        if !self.algorithms.contains(&header.alg) {
            tracing::debug!(
                target: "registry_relay::auth",
                alg = ?header.alg,
                "oidc: rejected token by alg",
            );
            return Err(AuthError::InvalidCredential);
        }

        let kid = header.kid.ok_or_else(|| {
            tracing::debug!(
                target: "registry_relay::auth",
                "oidc: token header missing kid",
            );
            AuthError::MalformedCredential
        })?;

        let key = match self.cache.get(&kid).await {
            Ok(k) => k,
            Err(JwksError::UnknownKid) => {
                tracing::debug!(
                    target: "registry_relay::auth",
                    kid = %kid,
                    "oidc: kid not present in jwks",
                );
                return Err(AuthError::InvalidCredential);
            }
            Err(JwksError::Unavailable(msg)) => {
                tracing::warn!(
                    target: "registry_relay::auth",
                    error = %msg,
                    "oidc: jwks unavailable; rejecting token",
                );
                return Err(AuthError::InvalidCredential);
            }
        };

        // Validation uses the first configured algorithm as the
        // initial value, then replaces the algorithms vec with the
        // full allowlist. jsonwebtoken enforces the alg in the token
        // header is one of these.
        let mut validation = Validation::new(self.algorithms[0]);
        validation.algorithms = self.algorithms.clone();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);
        validation.leeway = self.leeway.as_secs();
        validation.validate_nbf = true;
        validation.required_spec_claims = ["iss", "aud", "exp"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let token_data =
            decode::<Claims>(presented, &key, &validation).map_err(|err| {
                tracing::debug!(
                    target: "registry_relay::auth",
                    error = %err,
                    "oidc: jwt validation failed",
                );
                AuthError::InvalidCredential
            })?;
        let claims = token_data.claims;

        if let Some(allowed) = &self.allowed_clients {
            let candidate = claims.azp.as_deref().or(claims.client_id.as_deref());
            match candidate {
                Some(c) if allowed.contains(c) => {}
                _ => {
                    tracing::debug!(
                        target: "registry_relay::auth",
                        "oidc: client not in allowed_clients",
                    );
                    return Err(AuthError::InvalidCredential);
                }
            }
        }

        let principal_id = claims
            .sub
            .or(claims.client_id)
            .or(claims.azp)
            .ok_or_else(|| {
                tracing::debug!(
                    target: "registry_relay::auth",
                    "oidc: token has no sub / client_id / azp",
                );
                AuthError::MalformedCredential
            })?;

        let scopes: ScopeSet = extract_scopes(&claims.extra, &self.scope_claim)
            .into_iter()
            .map(|s| self.scope_map.get(&s).cloned().unwrap_or(s))
            .collect();

        Ok(Principal {
            principal_id,
            scopes,
            auth_mode: AuthMode::Oidc,
        })
    }
}

impl AuthProvider for OidcAuth {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        _remote_addr: std::net::IpAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Principal, AuthError>> + Send + 'a>> {
        let parsed = extract_bearer(headers);
        Box::pin(async move {
            let token = parsed?;
            self.verify(&token).await
        })
    }
}

/// Claims parsed off the JWT. Spec-defined claims that jsonwebtoken
/// validates (`iss`, `aud`, `exp`, `nbf`, `iat`) end up in `extra`
/// because they are not consumed structurally here; the validation
/// step already enforced them. The struct only names the fields the
/// provider reads directly: `sub`, `azp`, `client_id`, and the
/// configured scope claim (resolved out of `extra`).
#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn extract_bearer(headers: &HeaderMap) -> Result<Zeroizing<String>, AuthError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingCredential)?;
    let raw = value.to_str().map_err(|_| AuthError::MalformedCredential)?;
    let token = raw
        .strip_prefix(BEARER_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(AuthError::MalformedCredential)?;
    if token.is_empty() {
        return Err(AuthError::MalformedCredential);
    }
    Ok(Zeroizing::new(token.to_string()))
}

/// Read scopes off the configured claim. RFC 8693 / RFC 9068 specify a
/// space-separated string; some IdPs (Auth0, Keycloak under certain
/// mappers) emit a JSON array of strings. Both are accepted.
fn extract_scopes(extra: &Map<String, Value>, claim_name: &str) -> Vec<String> {
    let Some(value) = extra.get(claim_name) else {
        return Vec::new();
    };
    match value {
        Value::String(s) => s.split_whitespace().map(String::from).collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::jwks::{static_fetcher, JwksFetcher};
    use crate::config::OidcConfig;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand_core::OsRng;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_ISSUER: &str = "https://idp.example.test/realms/demo";
    const TEST_AUDIENCE: &str = "registry-relay";
    const TEST_KID: &str = "test-kid";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs()
    }

    fn fresh_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn jwks_for(kid: &str, vk: &VerifyingKey) -> JwkSet {
        let x = URL_SAFE_NO_PAD.encode(vk.as_bytes());
        serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": x,
            }]
        }))
        .expect("jwks parses")
    }

    fn base_config() -> OidcConfig {
        OidcConfig {
            issuer: TEST_ISSUER.to_string(),
            audience: vec![TEST_AUDIENCE.to_string()],
            jwks_url: None,
            discovery_url: None,
            algorithms: vec![OidcAlgorithm::EdDsa],
            jwks_cache_ttl: Duration::from_secs(600),
            leeway: Duration::from_secs(60),
            scope_claim: "scope".to_string(),
            scope_map: BTreeMap::new(),
            allowed_clients: Vec::new(),
            token_types: vec!["JWT".to_string(), "at+jwt".to_string()],
        }
    }

    fn fetcher_for(jwks: JwkSet) -> Arc<dyn JwksFetcher> {
        static_fetcher(jwks)
    }

    fn provider_from(config: OidcConfig, jwks: JwkSet) -> OidcAuth {
        OidcAuth::new(&config, fetcher_for(jwks))
    }

    fn signing_to_encoding_key(signing: &SigningKey) -> EncodingKey {
        let der = signing
            .to_pkcs8_der()
            .expect("ed25519 pkcs8 encoding");
        EncodingKey::from_ed_der(der.as_bytes())
    }

    #[derive(Default)]
    struct TokenOpts {
        kid: Option<String>,
        typ: Option<String>,
        iss: Option<String>,
        aud: Option<Value>,
        sub: Option<String>,
        exp_delta_secs: Option<i64>,
        nbf_delta_secs: Option<i64>,
        extra: Map<String, Value>,
        algorithm: Option<Algorithm>,
        omit_kid: bool,
        omit_typ: bool,
        omit_sub: bool,
        omit_aud: bool,
        omit_iss: bool,
    }

    fn mint(signing: &SigningKey, opts: TokenOpts) -> String {
        let alg = opts.algorithm.unwrap_or(Algorithm::EdDSA);
        let mut header = Header::new(alg);
        if !opts.omit_kid {
            header.kid = Some(opts.kid.unwrap_or_else(|| TEST_KID.to_string()));
        }
        if !opts.omit_typ {
            header.typ = opts.typ.or_else(|| Some("JWT".to_string()));
        } else {
            header.typ = None;
        }

        let now = now_secs() as i64;
        let exp = now + opts.exp_delta_secs.unwrap_or(300);
        let mut claims_map = Map::new();
        if !opts.omit_iss {
            claims_map.insert(
                "iss".to_string(),
                Value::String(opts.iss.unwrap_or_else(|| TEST_ISSUER.to_string())),
            );
        }
        if !opts.omit_aud {
            let aud = opts
                .aud
                .unwrap_or_else(|| Value::String(TEST_AUDIENCE.to_string()));
            claims_map.insert("aud".to_string(), aud);
        }
        if !opts.omit_sub {
            claims_map.insert(
                "sub".to_string(),
                Value::String(opts.sub.unwrap_or_else(|| "user-1".to_string())),
            );
        }
        claims_map.insert("exp".to_string(), Value::from(exp));
        if let Some(nbf_delta) = opts.nbf_delta_secs {
            claims_map.insert("nbf".to_string(), Value::from(now + nbf_delta));
        }
        claims_map.insert("iat".to_string(), Value::from(now));
        for (k, v) in opts.extra {
            claims_map.insert(k, v);
        }

        let encoding_key = signing_to_encoding_key(signing);
        encode(&header, &Value::Object(claims_map), &encoding_key)
            .expect("encode jwt")
    }

    #[tokio::test]
    async fn valid_bearer_resolves_principal_with_scopes() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "scope".to_string(),
                    Value::String(
                        "social_registry:rows social_registry:metadata".to_string(),
                    ),
                )]),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());

        let principal = provider
            .authenticate(&headers, std::net::IpAddr::from([127, 0, 0, 1]))
            .await
            .expect("valid bearer authenticates");
        assert_eq!(principal.principal_id, "user-1");
        assert_eq!(principal.auth_mode, AuthMode::Oidc);
        assert!(principal.scopes.contains("social_registry:rows"));
        assert!(principal.scopes.contains("social_registry:metadata"));
    }

    #[tokio::test]
    async fn scope_array_form_is_accepted() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "scope".to_string(),
                    json!(["a", "b", "c"]),
                )]),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(principal.scopes.contains("a"));
        assert!(principal.scopes.contains("b"));
        assert!(principal.scopes.contains("c"));
    }

    #[tokio::test]
    async fn scope_map_renames_scopes() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "scope".to_string(),
                    Value::String("role:reader".to_string()),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config
            .scope_map
            .insert("role:reader".to_string(), "social_registry:rows".to_string());
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(principal.scopes.contains("social_registry:rows"));
        assert!(!principal.scopes.contains("role:reader"));
    }

    #[tokio::test]
    async fn custom_scope_claim_is_honoured() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "scp".to_string(),
                    json!(["one", "two"]),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "scp".to_string();
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(principal.scopes.contains("one"));
        assert!(principal.scopes.contains("two"));
    }

    #[tokio::test]
    async fn expired_token_is_rejected_as_invalid_credential() {
        let (sk, vk) = fresh_keypair();
        // Far enough in the past that no leeway in [0, 5m] saves it.
        let token = mint(
            &sk,
            TokenOpts {
                exp_delta_secs: Some(-3600),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("expired");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn audience_mismatch_is_rejected_as_invalid_credential() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                aud: Some(Value::String("someone-else".to_string())),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("aud mismatch");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn issuer_mismatch_is_rejected_as_invalid_credential() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                iss: Some("https://other.example.test/".to_string()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("iss mismatch");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected_as_invalid_credential() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                kid: Some("not-the-cached-kid".to_string()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("unknown kid");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn missing_kid_header_is_rejected_as_malformed() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                omit_kid: true,
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("missing kid");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[tokio::test]
    async fn wrong_typ_is_rejected_as_malformed() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                typ: Some("id+jwt".to_string()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("wrong typ");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[tokio::test]
    async fn at_plus_jwt_typ_is_accepted() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                typ: Some("at+jwt".to_string()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        provider.verify(&token).await.expect("at+jwt accepted");
    }

    #[tokio::test]
    async fn missing_typ_is_accepted_when_jwt_in_allowlist() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                omit_typ: true,
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        provider.verify(&token).await.expect("missing typ accepted");
    }

    #[tokio::test]
    async fn allowed_clients_admits_listed_client() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "azp".to_string(),
                    Value::String("statistics-office".to_string()),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.allowed_clients = vec!["statistics-office".to_string()];
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        provider
            .verify(&token)
            .await
            .expect("listed client admitted");
    }

    #[tokio::test]
    async fn allowed_clients_denies_unlisted_client() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "azp".to_string(),
                    Value::String("untrusted-app".to_string()),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.allowed_clients = vec!["statistics-office".to_string()];
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("denied");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn allowed_clients_falls_back_to_client_id() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "client_id".to_string(),
                    Value::String("statistics-office".to_string()),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.allowed_clients = vec!["statistics-office".to_string()];
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        provider
            .verify(&token)
            .await
            .expect("client_id fallback admitted");
    }

    #[tokio::test]
    async fn sub_missing_falls_back_to_client_id_for_principal_id() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                omit_sub: true,
                extra: Map::from_iter([(
                    "client_id".to_string(),
                    Value::String("svc-1".to_string()),
                )]),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert_eq!(principal.principal_id, "svc-1");
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_as_invalid_credential() {
        let (sk_real, vk_real) = fresh_keypair();
        let (sk_other, _vk_other) = fresh_keypair();
        // Token signed by sk_other but JWKS only has vk_real.
        let _ = sk_real;
        let token = mint(&sk_other, TokenOpts::default());
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk_real));
        let err = provider.verify(&token).await.expect_err("bad signature");
        assert!(matches!(err, AuthError::InvalidCredential));
    }

    #[tokio::test]
    async fn missing_authorization_header_is_missing_credential() {
        let (_sk, vk) = fresh_keypair();
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let headers = HeaderMap::new();
        let err = provider
            .authenticate(&headers, std::net::IpAddr::from([127, 0, 0, 1]))
            .await
            .expect_err("missing header");
        assert!(matches!(err, AuthError::MissingCredential));
    }

    #[tokio::test]
    async fn wrong_scheme_is_malformed_credential() {
        let (_sk, vk) = fresh_keypair();
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        let err = provider
            .authenticate(&headers, std::net::IpAddr::from([127, 0, 0, 1]))
            .await
            .expect_err("wrong scheme");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[tokio::test]
    async fn x_api_key_header_is_not_accepted_for_oidc() {
        let (sk, vk) = fresh_keypair();
        let token = mint(&sk, TokenOpts::default());
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", token.parse().unwrap());
        let err = provider
            .authenticate(&headers, std::net::IpAddr::from([127, 0, 0, 1]))
            .await
            .expect_err("x-api-key ignored for oidc");
        assert!(matches!(err, AuthError::MissingCredential));
    }

    #[tokio::test]
    async fn audience_list_intersection_admits() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                aud: Some(json!(["frontend", "registry-relay", "other"])),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        provider.verify(&token).await.expect("intersecting aud ok");
    }
}
