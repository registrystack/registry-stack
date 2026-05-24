// SPDX-License-Identifier: Apache-2.0
//! Relay-facing JWKS adapter for the OIDC auth provider.
//!
//! The relay keeps its small public OIDC surface and error taxonomy, but the
//! actual JWKS cache and refresh-on-unknown-kid behavior are delegated to
//! `registry-platform-oidc`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;
use registry_platform_oidc::{JwksFetcher as PlatformJwksFetcher, OidcError as PlatformOidcError};

use super::fetcher::platform_jwks_config;

/// Errors surfaced by the JWKS cache to callers.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// The requested `kid` is not present in the cache after platform refresh.
    #[error("unknown key id")]
    UnknownKid,
    /// The JWKS document could not be fetched or parsed.
    #[error("jwks unavailable: {0}")]
    Unavailable(String),
}

/// One fetch's worth of verifier keys.
///
/// Kept for compatibility with existing tests and imports. Production fetches
/// are now performed by `registry-platform-oidc`.
pub struct JwksFetchResult {
    pub jwks: JwkSet,
}

/// Errors returned while constructing relay JWKS fetchers.
#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    /// Network or transport failure (DNS, TCP, TLS, HTTP status, timeout).
    #[error("jwks transport failure: {0}")]
    Transport(String),
    /// Response body did not parse as a JWKS document.
    #[error("jwks response did not parse")]
    Parse,
    /// The `issuer` field in the OIDC discovery document does not match the
    /// operator-configured issuer.
    #[error("discovery issuer mismatch: expected {expected:?}, got {actual:?}")]
    IssuerMismatch { expected: String, actual: String },
}

/// Pluggable relay fetcher contract. Implementations build the concrete
/// platform fetcher used by `registry-platform-oidc::TokenVerifier`.
pub trait JwksFetcher: Send + Sync + 'static {
    fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher;
}

/// Relay compatibility wrapper around the platform JWKS cache.
pub struct JwksCache {
    fetcher: Arc<PlatformJwksFetcher>,
    observed_key_count: AtomicUsize,
}

impl JwksCache {
    /// Build an empty cache. The first lookup triggers a platform fetch.
    pub fn new(fetcher: Arc<dyn JwksFetcher>, cache_ttl: Duration) -> Self {
        Self::with_refresh_interval(fetcher, cache_ttl, Duration::from_secs(30))
    }

    /// Build a cache with a custom refresh-rate-limit interval.
    pub fn with_refresh_interval(
        fetcher: Arc<dyn JwksFetcher>,
        cache_ttl: Duration,
        refresh_min_interval: Duration,
    ) -> Self {
        Self {
            fetcher: Arc::new(fetcher.platform_fetcher(cache_ttl, refresh_min_interval)),
            observed_key_count: AtomicUsize::new(0),
        }
    }

    pub(crate) fn platform_fetcher(&self) -> Arc<PlatformJwksFetcher> {
        Arc::clone(&self.fetcher)
    }

    /// Fetch the verifier key for `kid`, using the platform JWKS cache.
    pub async fn get(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        match self.fetcher.key_for_kid(kid).await {
            Ok(key) => {
                self.observed_key_count.fetch_max(1, Ordering::Relaxed);
                Ok(Arc::new(key))
            }
            Err(err) => Err(map_platform_jwks_error(err)),
        }
    }

    /// Lower-bound operational signal for whether at least one key resolved.
    pub fn key_count(&self) -> usize {
        self.observed_key_count.load(Ordering::Relaxed)
    }
}

fn map_platform_jwks_error(err: PlatformOidcError) -> JwksError {
    match err {
        PlatformOidcError::MissingKid | PlatformOidcError::UnknownKid => JwksError::UnknownKid,
        other => JwksError::Unavailable(other.to_string()),
    }
}

/// Build a fetcher that serves the same in-memory [`JwkSet`] over a local
/// loopback HTTP endpoint. Useful for tests without reimplementing the JWKS
/// cache now owned by `registry-platform-oidc`.
pub fn static_fetcher(jwks: JwkSet) -> Arc<dyn JwksFetcher> {
    Arc::new(StaticFetcher { jwks })
}

struct StaticFetcher {
    jwks: JwkSet,
}

impl JwksFetcher for StaticFetcher {
    fn platform_fetcher(
        &self,
        cache_ttl: Duration,
        refresh_cooldown: Duration,
    ) -> PlatformJwksFetcher {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind static jwks test server");
        listener
            .set_nonblocking(true)
            .expect("set static jwks listener nonblocking");
        let addr = listener.local_addr().expect("static jwks listener addr");
        let body = Arc::new(serde_json::to_vec(&self.jwks).expect("serialize static jwks"));
        let listener =
            tokio::net::TcpListener::from_std(listener).expect("convert static jwks listener");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = Arc::clone(&body);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};

                    let mut buf = [0_u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        PlatformJwksFetcher::new_with_fetch_url_policy(
            format!("http://{addr}/jwks"),
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static jwks client"),
            platform_jwks_config(cache_ttl, refresh_cooldown),
            registry_platform_httputil::FetchUrlPolicy::dev(),
        )
    }
}

/// Convenience constructor for inspecting a [`JwkSet`] from JSON in tests.
#[cfg(test)]
pub fn jwks_from_json(value: serde_json::Value) -> JwkSet {
    serde_json::from_value(value).expect("valid jwks json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_ed25519_jwk(kid: &str) -> JwkSet {
        let raw = vec![0u8; 32];
        let x = base64_url(&raw);
        jwks_from_json(serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": x,
            }]
        }))
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[tokio::test]
    async fn first_lookup_triggers_platform_fetch_and_returns_key() {
        let cache = JwksCache::new(
            static_fetcher(one_ed25519_jwk("kid-1")),
            Duration::from_secs(60),
        );

        let key = cache.get("kid-1").await.expect("kid-1 resolves");
        assert!(Arc::strong_count(&key) >= 1);
        assert_eq!(cache.key_count(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_maps_to_unknown_kid() {
        let cache = JwksCache::new(
            static_fetcher(one_ed25519_jwk("kid-known")),
            Duration::from_secs(60),
        );

        let err = match cache.get("kid-mystery").await {
            Ok(_) => panic!("expected UnknownKid"),
            Err(e) => e,
        };
        assert!(matches!(err, JwksError::UnknownKid));
    }
}
