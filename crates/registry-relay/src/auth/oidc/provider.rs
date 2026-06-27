// SPDX-License-Identifier: Apache-2.0
//! [`OidcAuth`]: resource-server bearer-JWT verifier.
//!
//! ## Verification flow
//!
//! 1. Read `Authorization: Bearer <jwt>`. OIDC does not accept the
//!    `x-api-key` header; that header is the API-key provider's legacy
//!    surface only.
//! 2. Decode the JOSE header. Reject tokens whose `typ` is missing or not in
//!    the configured allowlist (defaults to `JWT` / `at+jwt`), whose `alg`
//!    is not in the configured allowlist (defaults to RS256/ES256/EdDSA;
//!    HS\* and `none` are intentionally excluded), or that have no
//!    `kid`.
//! 3. Resolve the verifier key via [`super::jwks::JwksCache`]. On
//!    unknown `kid` the cache triggers one (rate-limited) refresh.
//! 4. Run [`jsonwebtoken::decode`] with a [`jsonwebtoken::Validation`] configured for
//!    the configured issuer, audiences, leeway, and algorithm allowlist
//!    plus `validate_nbf = true`. Required spec claims are `iss`, `aud`,
//!    `exp`.
//! 5. Enforce the `allowed_clients` policy against `azp` (preferred)
//!    or `client_id`. Empty config list means any client.
//! 6. Build the [`super::super::Principal`]: `principal_id` is `sub` if
//!    present, else `client_id`, else `azp`. Scopes are extracted from
//!    the configured claim (string with whitespace separators, array of
//!    strings, object keys with configured active-value guards, or explicitly
//!    configured verified reserved claims such as `client_id`) and renamed
//!    through `scope_map`. The `aud` claim is validated as audience only and
//!    is never projected into Relay authorization scopes.
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

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode_header, Algorithm};
use registry_platform_oidc::{
    Claims, OidcError as PlatformOidcError, TokenVerifier, TokenVerifierConfig, VerifiedToken,
};
#[cfg(test)]
use serde_json::Map;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::{OidcAlgorithm, OidcConfig};
use crate::error::AuthError;

use super::super::{AuthMode, AuthProvider, Principal, ScopeSet};
use super::jwks::{JwksCache, JwksFetcher};

/// HTTP authentication scheme accepted by the OIDC provider.
const BEARER_SCHEME: &str = "Bearer";

/// Bearer-JWT verifier built from one [`OidcConfig`] block.
///
/// One instance is built at startup and held behind
/// `Arc<dyn AuthProvider>`. The struct is `Send + Sync` so the same
/// instance serves every concurrent request.
pub struct OidcAuth {
    algorithms: Vec<Algorithm>,
    audiences: HashSet<String>,
    scope_claim: String,
    scope_map: BTreeMap<String, String>,
    scope_object_required_keys: HashSet<String>,
    /// Accepted JOSE `typ` values, normalised to lowercase for the
    /// case-insensitive match RFC 7515 prescribes.
    token_types: HashSet<String>,
    cache: Arc<JwksCache>,
    verifier: TokenVerifier,
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
        let algorithms: Vec<Algorithm> = config
            .allowed_algorithms
            .iter()
            .map(|alg| match alg {
                OidcAlgorithm::Rs256 => Algorithm::RS256,
                OidcAlgorithm::Es256 => Algorithm::ES256,
                OidcAlgorithm::EdDsa => Algorithm::EdDSA,
            })
            .collect();
        let token_types: HashSet<String> = config
            .allowed_token_types
            .iter()
            .map(|t| t.to_ascii_lowercase())
            .collect();
        let audiences = config.audiences.iter().cloned().collect();
        let verifier = TokenVerifier::new(
            TokenVerifierConfig::registry_relay_access_profile(
                config.issuer.clone(),
                config.audiences.clone(),
                algorithms.clone(),
                config.allowed_token_types.clone(),
            )
            .with_related_token_typ(
                config.allowed_token_types.clone(),
                config.allowed_token_types.clone(),
            )
            .with_scope_claim(config.scope_claim.clone())
            .with_allowed_clients(config.allowed_clients.clone())
            .with_leeway(config.leeway),
            cache.platform_fetcher(),
        );
        Self {
            algorithms,
            audiences,
            scope_claim: config.scope_claim.clone(),
            scope_map: config.scope_map.clone(),
            scope_object_required_keys: config.scope_object_required_keys.iter().cloned().collect(),
            token_types,
            cache,
            verifier,
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
                tracing::debug!(
                    target: "registry_relay::auth",
                    "oidc: token missing typ",
                );
                return Err(AuthError::MalformedCredential);
            }
        }

        if !self.algorithms.contains(&header.alg) {
            tracing::debug!(
                target: "registry_relay::auth",
                alg = ?header.alg,
                "oidc: rejected token by alg",
            );
            return Err(AuthError::AlgorithmNotAllowed);
        }

        let kid = header.kid.ok_or_else(|| {
            tracing::debug!(
                target: "registry_relay::auth",
                "oidc: token header missing kid",
            );
            AuthError::MalformedCredential
        })?;
        if kid.len() > 1024 || kid.chars().any(char::is_control) {
            tracing::warn!(
                auth_error = "auth.malformed_credential",
                "oidc: token header kid rejected",
            );
            return Err(AuthError::MalformedCredential);
        }

        let verified = self.verifier.verify(presented).await.map_err(|err| {
            let mapped = map_platform_error(&err, presented);
            tracing::warn!(
                provider_error = platform_error_kind(&err),
                auth_error = auth_error_code(&mapped),
                "oidc: jwt validation failed",
            );
            mapped
        })?;
        self.cache_mark_observed(&kid).await;
        let VerifiedToken {
            claims,
            matched_client,
            scopes: _,
        } = verified;

        let scopes: ScopeSet = extract_scopes(
            &claims,
            &self.scope_claim,
            &self.audiences,
            &self.scope_object_required_keys,
        )
        .into_iter()
        .filter_map(|s| map_scope(&self.scope_claim, &self.scope_map, s))
        .collect();

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

        // Log the relationship between the matched client identifier (if an
        // allowlist was enforced) and the resolved principal_id. These may
        // differ when a service token carries both `azp` and `sub`.
        if let Some(client) = matched_client {
            tracing::debug!(
                target: "registry_relay::auth",
                matched_client = %client,
                principal_id = %principal_id,
                "oidc: allowlist passed",
            );
        }

        Ok(Principal {
            principal_id,
            scopes,
            auth_mode: AuthMode::Oidc,
        })
    }

    async fn cache_mark_observed(&self, kid: &str) {
        let _ = self.cache.get(kid).await;
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

fn extract_bearer(headers: &HeaderMap) -> Result<Zeroizing<String>, AuthError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingCredential)?;
    let raw = value.to_str().map_err(|_| AuthError::MalformedCredential)?;
    // RFC 7235 §2.1: auth scheme is case-insensitive. RFC 6750 §2.1 requires
    // exactly one SP between the scheme and the token.
    let scheme_len = BEARER_SCHEME.len();
    if raw.len() <= scheme_len
        || !raw[..scheme_len].eq_ignore_ascii_case(BEARER_SCHEME)
        || raw.as_bytes()[scheme_len] != b' '
    {
        return Err(AuthError::MalformedCredential);
    }
    let token = &raw[scheme_len + 1..];
    if token.is_empty() {
        return Err(AuthError::MalformedCredential);
    }
    // Reject two-space separators (scheme + two spaces + token). The check
    // above already ensured byte[scheme_len] == b' '; a second space would
    // mean the "token" starts with a space, which is not a valid token char.
    // This is implicitly handled: token is non-empty and the caller passes it
    // verbatim to JWT decode which will reject a leading-space value.
    // For explicitness, reject any token that starts with a space.
    if token.starts_with(' ') {
        return Err(AuthError::MalformedCredential);
    }
    Ok(Zeroizing::new(token.to_string()))
}

#[allow(unreachable_patterns)]
fn map_platform_error(err: &PlatformOidcError, token: &str) -> AuthError {
    match err {
        PlatformOidcError::Transport(_)
        | PlatformOidcError::BoundedRead(_)
        | PlatformOidcError::FetchUrl(_)
        | PlatformOidcError::HttpStatus(_)
        | PlatformOidcError::InvalidUrl
        | PlatformOidcError::Parse
        | PlatformOidcError::InvalidJwk => AuthError::JwksUnavailable,
        PlatformOidcError::IssuerMismatch { .. } => AuthError::IssuerMismatch,
        PlatformOidcError::MalformedToken
        | PlatformOidcError::TokenTypeNotAllowed
        | PlatformOidcError::MissingKid
        | PlatformOidcError::KidTooLong => AuthError::MalformedCredential,
        PlatformOidcError::AlgorithmNotAllowed => AuthError::AlgorithmNotAllowed,
        PlatformOidcError::UnknownKid => AuthError::KidUnknown,
        PlatformOidcError::TokenExpired => AuthError::TokenExpired,
        PlatformOidcError::TokenNotYetValid => AuthError::TokenNotYetValid,
        PlatformOidcError::AudienceMismatch => AuthError::AudienceMismatch,
        PlatformOidcError::SignatureInvalid => AuthError::TokenSignatureInvalid,
        PlatformOidcError::ClientNotAllowed => AuthError::ClientNotAllowed,
        PlatformOidcError::InvalidToken => classify_invalid_token(token),
        _ => AuthError::MalformedCredential,
    }
}

fn classify_invalid_token(token: &str) -> AuthError {
    let Some(claims) = unverified_payload(token) else {
        return AuthError::MalformedCredential;
    };
    if !claims.is_object()
        || claims.get("iss").is_none()
        || claims.get("aud").is_none()
        || claims.get("exp").is_none()
    {
        return AuthError::MalformedCredential;
    }
    AuthError::InvalidCredential
}

fn unverified_payload(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    if parts.next().is_none() || parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn platform_error_kind(err: &PlatformOidcError) -> &'static str {
    match err {
        PlatformOidcError::Transport(_) => "transport",
        PlatformOidcError::BoundedRead(_) => "bounded_read",
        PlatformOidcError::FetchUrl(_) => "fetch_url",
        PlatformOidcError::HttpStatus(_) => "http_status",
        PlatformOidcError::InvalidUrl => "invalid_url",
        PlatformOidcError::Parse => "parse",
        PlatformOidcError::InvalidJwk => "invalid_jwk",
        PlatformOidcError::IssuerMismatch { .. } => "issuer_mismatch",
        PlatformOidcError::MalformedToken => "malformed_token",
        PlatformOidcError::TokenTypeNotAllowed => "token_type_not_allowed",
        PlatformOidcError::MissingKid => "missing_kid",
        PlatformOidcError::KidTooLong => "kid_too_long",
        PlatformOidcError::AlgorithmNotAllowed => "algorithm_not_allowed",
        PlatformOidcError::UnknownKid => "unknown_kid",
        PlatformOidcError::TokenExpired => "token_expired",
        PlatformOidcError::TokenNotYetValid => "token_not_yet_valid",
        PlatformOidcError::AudienceMismatch => "audience_mismatch",
        PlatformOidcError::SignatureInvalid => "signature_invalid",
        PlatformOidcError::ClientNotAllowed => "client_not_allowed",
        PlatformOidcError::InvalidToken => "invalid_token",
        _ => "other",
    }
}

fn auth_error_code(err: &AuthError) -> &'static str {
    match err {
        AuthError::MissingCredential => "auth.missing_credential",
        AuthError::InvalidCredential => "auth.invalid_credential",
        AuthError::MalformedCredential => "auth.malformed_credential",
        AuthError::ScopeDenied { .. } => "auth.scope_denied",
        AuthError::PurposeRequired => "auth.purpose_required",
        AuthError::PurposeDenied => "auth.purpose_denied",
        AuthError::AdminRequired => "auth.admin_required",
        AuthError::TokenExpired => "auth.token_expired",
        AuthError::TokenNotYetValid => "auth.token_not_yet_valid",
        AuthError::TokenSignatureInvalid => "auth.token_signature_invalid",
        AuthError::IssuerMismatch => "auth.issuer_mismatch",
        AuthError::AudienceMismatch => "auth.audience_mismatch",
        AuthError::KidUnknown => "auth.kid_unknown",
        AuthError::AlgorithmNotAllowed => "auth.algorithm_not_allowed",
        AuthError::ClientNotAllowed => "auth.client_not_allowed",
        AuthError::JwksUnavailable => "auth.jwks_unavailable",
    }
}

/// Read scopes off the configured claim. Three shapes are accepted so the
/// same `scope_claim` field can target different IdP conventions:
///
/// * `String`: RFC 8693 / RFC 9068 space-separated scope string.
/// * `Array of strings`: Auth0, Keycloak (under certain mappers), and
///   IdPs that emit roles as a flat list.
/// * `Object`: Zitadel emits roles under
///   `urn:zitadel:iam:org:project:roles` as an object whose **keys** are
///   the role names. Role keys are returned only when the value contains one
///   of the configured required object keys and that nested value carries
///   active-grant semantics; `scope_map` then renames them into the relay's
///   `<dataset_id>:<level>` shape.
///
/// Reserved claims are accepted only when explicitly named as `scope_claim`.
/// They are verified by the OIDC library before Relay sees them, and are useful
/// for demo or provider setups where policy maps a principal or client to
/// local Relay scopes. `aud` remains a routing claim and is not a scope source.
/// Role/entitlement claims remain the production default.
fn extract_scopes(
    claims: &Claims,
    claim_name: &str,
    _accepted_audiences: &HashSet<String>,
    scope_object_required_keys: &HashSet<String>,
) -> Vec<String> {
    if let Some(value) = claims.extra.get(claim_name) {
        return extract_scope_values(value, scope_object_required_keys);
    }
    match claim_name {
        "sub" => claims.sub.iter().cloned().collect(),
        "client_id" => claims.client_id.iter().cloned().collect(),
        "azp" => claims.azp.iter().cloned().collect(),
        "aud" => Vec::new(),
        _ => Vec::new(),
    }
}

fn map_scope(
    scope_claim: &str,
    scope_map: &BTreeMap<String, String>,
    scope: String,
) -> Option<String> {
    if let Some(mapped) = scope_map.get(&scope) {
        Some(mapped.clone())
    } else if reserved_scope_claim_requires_mapping(scope_claim) {
        None
    } else {
        Some(scope)
    }
}

fn reserved_scope_claim_requires_mapping(scope_claim: &str) -> bool {
    matches!(scope_claim, "sub" | "client_id" | "azp" | "aud")
}

fn extract_scope_values(
    value: &Value,
    scope_object_required_keys: &HashSet<String>,
) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(String::from).collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        Value::Object(map) if !scope_object_required_keys.is_empty() => map
            .iter()
            .filter(|(_, value)| scope_object_value_is_active(value, scope_object_required_keys))
            .map(|(key, _)| key.clone())
            .collect(),
        Value::Object(_) => Vec::new(),
        _ => Vec::new(),
    }
}

fn scope_object_value_is_active(value: &Value, required_keys: &HashSet<String>) -> bool {
    if !required_keys.is_empty() {
        let Some(object) = value.as_object() else {
            return false;
        };
        return required_keys.iter().any(|key| {
            object
                .get(key)
                .is_some_and(scope_object_value_has_active_content)
        });
    }

    scope_object_value_has_active_content(value)
}

fn scope_object_value_has_active_content(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values.iter().any(scope_object_value_has_active_content),
        Value::Object(object) => {
            !object.is_empty() && object.values().any(scope_object_value_has_active_content)
        }
        Value::Null | Value::Number(_) => false,
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
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing_subscriber::fmt::MakeWriter;

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
            audiences: vec![TEST_AUDIENCE.to_string()],
            jwks_url: None,
            discovery_url: None,
            allow_dev_insecure_fetch_urls: false,
            allowed_algorithms: vec![OidcAlgorithm::EdDsa],
            jwks_cache_ttl: Duration::from_secs(600),
            leeway: Duration::from_secs(60),
            scope_claim: "scope".to_string(),
            scope_map: BTreeMap::new(),
            scope_object_required_keys: Vec::new(),
            allowed_clients: Vec::new(),
            allowed_token_types: vec!["JWT".to_string(), "at+jwt".to_string()],
        }
    }

    fn fetcher_for(jwks: JwkSet) -> Arc<dyn JwksFetcher> {
        static_fetcher(jwks)
    }

    fn provider_from(config: OidcConfig, jwks: JwkSet) -> OidcAuth {
        OidcAuth::new(&config, fetcher_for(jwks))
    }

    fn signing_to_encoding_key(signing: &SigningKey) -> EncodingKey {
        let der = signing.to_pkcs8_der().expect("ed25519 pkcs8 encoding");
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
        encode(&header, &Value::Object(claims_map), &encoding_key).expect("encode jwt")
    }

    fn unsigned_alg_none_token() -> String {
        let now = now_secs() as i64;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT","kid":"test-kid"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "sub": "user-1",
                "iat": now,
                "exp": now + 300,
            }))
            .expect("payload serializes"),
        );
        format!("{header}.{payload}.")
    }

    #[derive(Clone, Default)]
    struct SharedLog(Arc<Mutex<Vec<u8>>>);

    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for SharedLog {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(Arc::clone(&self.0))
        }
    }

    impl io::Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn valid_bearer_resolves_principal_with_scopes() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "scope".to_string(),
                    Value::String("social_registry:rows social_registry:metadata".to_string()),
                )]),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

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
    async fn scope_object_form_treats_keys_as_scopes() {
        // Zitadel's `urn:zitadel:iam:org:project:roles` shape: an object
        // keyed by role name with active per-org metadata as the value.
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "urn:zitadel:iam:org:project:roles".to_string(),
                    json!({
                        "social-registry-reader":    { "orgId-123": "zitadel.localhost" },
                        "social-registry-aggregate": { "orgId-123": "zitadel.localhost" },
                    }),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "urn:zitadel:iam:org:project:roles".to_string();
        config.scope_object_required_keys = vec!["orgId-123".to_string()];
        config.scope_map.insert(
            "social-registry-reader".to_string(),
            "social_registry:rows".to_string(),
        );
        config.scope_map.insert(
            "social-registry-aggregate".to_string(),
            "social_registry:aggregate".to_string(),
        );
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(principal.scopes.contains("social_registry:rows"));
        assert!(principal.scopes.contains("social_registry:aggregate"));
    }

    #[tokio::test]
    async fn scope_object_form_requires_active_values() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "urn:zitadel:iam:org:project:roles".to_string(),
                    json!({
                        "social-registry-reader": false,
                        "social-registry-aggregate": null,
                        "social-registry-metadata": {},
                    }),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "urn:zitadel:iam:org:project:roles".to_string();
        config.scope_object_required_keys = vec!["orgId-123".to_string()];
        config.scope_map.insert(
            "social-registry-reader".to_string(),
            "social_registry:rows".to_string(),
        );
        config.scope_map.insert(
            "social-registry-aggregate".to_string(),
            "social_registry:aggregate".to_string(),
        );
        config.scope_map.insert(
            "social-registry-metadata".to_string(),
            "social_registry:metadata".to_string(),
        );

        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_registry:rows"));
        assert!(!principal.scopes.contains("social_registry:aggregate"));
        assert!(!principal.scopes.contains("social_registry:metadata"));
    }

    #[tokio::test]
    async fn scope_object_form_requires_configured_keys() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "urn:zitadel:iam:org:project:roles".to_string(),
                    json!({
                        "social-registry-reader": { "orgId-123": "zitadel.localhost" },
                    }),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "urn:zitadel:iam:org:project:roles".to_string();
        config.scope_map.insert(
            "social-registry-reader".to_string(),
            "social_registry:rows".to_string(),
        );

        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_registry:rows"));
    }

    #[tokio::test]
    async fn custom_object_scope_claim_requires_configured_keys() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "permissions".to_string(),
                    json!({
                        "reader": true,
                    }),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "permissions".to_string();
        config
            .scope_map
            .insert("reader".to_string(), "social_registry:rows".to_string());

        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_registry:rows"));
    }

    #[tokio::test]
    async fn scope_object_form_requires_configured_org_key_when_set() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "urn:zitadel:iam:org:project:roles".to_string(),
                    json!({
                        "social-registry-reader": { "orgId-999": "zitadel.localhost" },
                        "social-registry-aggregate": { "orgId-123": "zitadel.localhost" },
                    }),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "urn:zitadel:iam:org:project:roles".to_string();
        config.scope_object_required_keys = vec!["orgId-123".to_string()];
        config.scope_map.insert(
            "social-registry-reader".to_string(),
            "social_registry:rows".to_string(),
        );
        config.scope_map.insert(
            "social-registry-aggregate".to_string(),
            "social_registry:aggregate".to_string(),
        );

        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_registry:rows"));
        assert!(principal.scopes.contains("social_registry:aggregate"));
    }

    #[tokio::test]
    async fn scope_array_form_is_accepted() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([("scope".to_string(), json!(["a", "b", "c"]))]),
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
        config.scope_map.insert(
            "role:reader".to_string(),
            "social_registry:rows".to_string(),
        );
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
                extra: Map::from_iter([("scp".to_string(), json!(["one", "two"]))]),
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
    async fn reserved_client_id_scope_claim_can_be_mapped() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                extra: Map::from_iter([(
                    "client_id".to_string(),
                    Value::String("registry-lab-api".to_string()),
                )]),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "client_id".to_string();
        config.scope_map.insert(
            "registry-lab-api".to_string(),
            "social_protection_registry:rows".to_string(),
        );
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(principal.scopes.contains("social_protection_registry:rows"));
    }

    #[tokio::test]
    async fn unmapped_reserved_scope_claim_values_do_not_grant_scopes() {
        let cases = [
            (
                "sub",
                TokenOpts {
                    sub: Some("social_protection_registry:rows".to_string()),
                    ..Default::default()
                },
            ),
            (
                "client_id",
                TokenOpts {
                    extra: Map::from_iter([(
                        "client_id".to_string(),
                        Value::String("social_protection_registry:rows".to_string()),
                    )]),
                    ..Default::default()
                },
            ),
            (
                "azp",
                TokenOpts {
                    extra: Map::from_iter([(
                        "azp".to_string(),
                        Value::String("social_protection_registry:rows".to_string()),
                    )]),
                    ..Default::default()
                },
            ),
        ];

        for (scope_claim, opts) in cases {
            let (sk, vk) = fresh_keypair();
            let token = mint(&sk, opts);
            let mut config = base_config();
            config.scope_claim = scope_claim.to_string();
            let provider = provider_from(config, jwks_for(TEST_KID, &vk));

            let principal = provider.verify(&token).await.expect("ok");
            assert!(
                !principal.scopes.contains("social_protection_registry:rows"),
                "{scope_claim} must require an explicit scope_map entry"
            );
        }
    }

    #[tokio::test]
    async fn reserved_audience_scope_claim_does_not_grant_scopes() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                aud: Some(json!(["registry-lab-api", TEST_AUDIENCE])),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.audiences.push("registry-lab-api".to_string());
        config.scope_claim = "aud".to_string();
        config.scope_map.insert(
            "registry-lab-api".to_string(),
            "social_protection_registry:rows".to_string(),
        );
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_protection_registry:rows"));
        assert!(!principal.scopes.contains("registry-lab-api"));
    }

    #[tokio::test]
    async fn reserved_audience_scope_claim_ignores_unaccepted_audiences() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                aud: Some(json!([TEST_AUDIENCE, "social_protection_registry:rows"])),
                ..Default::default()
            },
        );
        let mut config = base_config();
        config.scope_claim = "aud".to_string();
        let provider = provider_from(config, jwks_for(TEST_KID, &vk));
        let principal = provider.verify(&token).await.expect("ok");
        assert!(!principal.scopes.contains("social_protection_registry:rows"));
        assert!(!principal.scopes.contains(TEST_AUDIENCE));
    }

    #[tokio::test]
    async fn expired_token_is_rejected_as_token_expired() {
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
        assert!(matches!(err, AuthError::TokenExpired), "got {err:?}");
    }

    #[tokio::test]
    async fn not_yet_valid_token_is_rejected() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                nbf_delta_secs: Some(3600),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("nbf in future");
        assert!(matches!(err, AuthError::TokenNotYetValid), "got {err:?}");
    }

    #[tokio::test]
    async fn unsigned_alg_none_token_is_rejected() {
        let (_sk, vk) = fresh_keypair();
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider
            .verify(&unsigned_alg_none_token())
            .await
            .expect_err("alg none must not authenticate");
        assert!(matches!(err, AuthError::MalformedCredential), "got {err:?}");
    }

    #[tokio::test]
    async fn audience_mismatch_is_rejected_as_audience_mismatch() {
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
        assert!(matches!(err, AuthError::AudienceMismatch), "got {err:?}");
    }

    #[tokio::test]
    async fn issuer_mismatch_is_rejected_as_issuer_mismatch() {
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
        assert!(matches!(err, AuthError::IssuerMismatch), "got {err:?}");
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected_as_kid_unknown() {
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
        assert!(matches!(err, AuthError::KidUnknown), "got {err:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_char_kid_text_logs_do_not_include_raw_kid() {
        let (sk, vk) = fresh_keypair();
        let raw_kid = "not-the-cached-kid\nforged=true";
        let token = mint(
            &sk,
            TokenOpts {
                kid: Some(raw_kid.to_string()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let logs = SharedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs.clone())
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        let err = provider.verify(&token).await.expect_err("malformed kid");
        drop(guard);

        assert!(matches!(err, AuthError::MalformedCredential), "got {err:?}");
        let rendered = String::from_utf8(logs.0.lock().expect("log buffer lock").clone())
            .expect("logs are utf-8");
        assert!(
            rendered.contains("oidc: token header kid rejected"),
            "expected validation diagnostic in logs: {rendered}"
        );
        assert!(!rendered.contains(raw_kid), "raw kid reached text logs");
        assert!(
            !rendered.contains("forged=true"),
            "kid suffix reached text logs"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlong_kid_uses_stable_provider_error_code() {
        let (sk, vk) = fresh_keypair();
        let raw_kid = "k".repeat(1025);
        let token = mint(
            &sk,
            TokenOpts {
                kid: Some(raw_kid.clone()),
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let logs = SharedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs.clone())
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        let err = provider.verify(&token).await.expect_err("overlong kid");
        drop(guard);

        assert!(matches!(err, AuthError::MalformedCredential), "got {err:?}");
        let rendered = String::from_utf8(logs.0.lock().expect("log buffer lock").clone())
            .expect("logs are utf-8");
        assert!(
            rendered.contains("oidc: token header kid rejected"),
            "expected validation diagnostic in logs: {rendered}"
        );
        assert!(!rendered.contains(&raw_kid), "raw kid reached text logs");
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
    async fn missing_typ_is_rejected_even_when_jwt_in_allowlist() {
        let (sk, vk) = fresh_keypair();
        let token = mint(
            &sk,
            TokenOpts {
                omit_typ: true,
                ..Default::default()
            },
        );
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk));
        let err = provider.verify(&token).await.expect_err("missing typ");
        assert!(matches!(err, AuthError::MalformedCredential));
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
        assert!(matches!(err, AuthError::ClientNotAllowed), "got {err:?}");
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
    async fn bad_signature_is_rejected_as_token_signature_invalid() {
        let (sk_real, vk_real) = fresh_keypair();
        let (sk_other, _vk_other) = fresh_keypair();
        // Token signed by sk_other but JWKS only has vk_real.
        let _ = sk_real;
        let token = mint(&sk_other, TokenOpts::default());
        let provider = provider_from(base_config(), jwks_for(TEST_KID, &vk_real));
        let err = provider.verify(&token).await.expect_err("bad signature");
        assert!(
            matches!(err, AuthError::TokenSignatureInvalid),
            "got {err:?}"
        );
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

    // --- Fix S-M3: case-insensitive Bearer scheme ---

    fn bearer_headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn bearer_lowercase_scheme_is_accepted() {
        let headers = bearer_headers("bearer sometoken");
        let token = extract_bearer(&headers).expect("lowercase bearer accepted");
        assert_eq!(token.as_str(), "sometoken");
    }

    #[test]
    fn bearer_uppercase_scheme_is_accepted() {
        let headers = bearer_headers("BEARER sometoken");
        let token = extract_bearer(&headers).expect("uppercase bearer accepted");
        assert_eq!(token.as_str(), "sometoken");
    }

    #[test]
    fn bearer_mixed_case_scheme_is_accepted() {
        let headers = bearer_headers("Bearer sometoken");
        let token = extract_bearer(&headers).expect("mixed-case bearer accepted");
        assert_eq!(token.as_str(), "sometoken");
    }

    #[test]
    fn bearer_two_spaces_is_malformed() {
        // RFC 6750 §2.1 requires exactly one SP; two spaces is not valid.
        let headers = bearer_headers("Bearer  sometoken");
        let err = extract_bearer(&headers).expect_err("double space must be rejected");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn bearer_no_space_is_malformed() {
        let headers = bearer_headers("Bearersometoken");
        let err = extract_bearer(&headers).expect_err("no space must be rejected");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn bearer_empty_token_is_malformed() {
        let headers = bearer_headers("Bearer ");
        let err = extract_bearer(&headers).expect_err("empty token must be rejected");
        assert!(matches!(err, AuthError::MalformedCredential));
    }

    #[test]
    fn missing_authorization_header_returns_missing_credential() {
        let headers = HeaderMap::new();
        let err = extract_bearer(&headers).expect_err("missing header");
        assert!(matches!(err, AuthError::MissingCredential));
    }
}
