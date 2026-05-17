// SPDX-License-Identifier: Apache-2.0
//! JWKS cache for the OIDC auth provider.
//!
//! Holds the verifier keys for one issuer behind an
//! [`arc_swap::ArcSwap`] so the request path is lock-free in the steady
//! state. Refresh is serialised via a [`tokio::sync::Mutex`] and
//! triggered when either:
//!
//! 1. The cached snapshot is older than the configured TTL, or
//! 2. The request presents a `kid` that is not in the cache.
//!
//! Both conditions are also rate-limited by `refresh_min_interval`
//! (30 seconds by default) so an attacker cannot make the relay
//! hammer the IdP by sending random unknown `kid`s.
//!
//! The fetcher is abstracted behind the [`JwksFetcher`] trait so the
//! production path (HTTP via `reqwest`) and tests (in-process stub)
//! share the same cache logic.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;
use tokio::sync::Mutex;

/// Errors surfaced by the JWKS cache to callers.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    /// The requested `kid` is not present in the cache and a fresh
    /// fetch did not yield it (or the fetch attempt was rate-limited).
    /// Mapped to `auth.invalid_credential` (401) until Stage 4 adds a
    /// dedicated taxonomy code.
    #[error("unknown key id")]
    UnknownKid,
    /// The cache is empty and the most recent fetch failed. Mapped to
    /// `auth.invalid_credential` (401) for V1; Stage 4 promotes this
    /// to a 503 with a dedicated code so operators can distinguish
    /// transport outages from genuine bad tokens.
    #[error("jwks unavailable: {0}")]
    Unavailable(String),
}

/// One fetch's worth of verifier keys.
pub struct JwksFetchResult {
    pub jwks: JwkSet,
}

/// Errors returned from a [`JwksFetcher`] implementation. Kept as
/// strings here so transport-specific error types stay out of the
/// auth-module surface.
#[derive(Debug, thiserror::Error)]
pub enum JwksFetchError {
    /// Network or transport failure (DNS, TCP, TLS, HTTP status,
    /// timeout). Carries an operator-visible reason that the cache
    /// logs but never echoes to clients.
    #[error("jwks transport failure: {0}")]
    Transport(String),
    /// Response body did not parse as a JWKS document.
    #[error("jwks response did not parse")]
    Parse,
}

/// Pluggable fetcher contract. The cache calls `fetch` whenever a
/// refresh is due; implementations are responsible for the underlying
/// transport (HTTP / file / in-process stub).
pub trait JwksFetcher: Send + Sync + 'static {
    fn fetch<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<JwksFetchResult, JwksFetchError>> + Send + 'a>>;
}

/// One immutable snapshot of the cache.
struct JwksState {
    keys: HashMap<String, Arc<DecodingKey>>,
    /// When the snapshot's keys were last fetched. `None` means the
    /// cache has never successfully fetched (initial state); the very
    /// first lookup will trigger a refresh.
    fetched_at: Option<Instant>,
    /// When a fetch was last attempted (success or failure). Used to
    /// rate-limit retries when fetches keep failing or when callers
    /// keep presenting unknown `kid`s.
    last_attempt_at: Option<Instant>,
    /// Last fetch's error message, if any. Surfaced through
    /// [`JwksError::Unavailable`] only when the cache is empty.
    last_error: Option<String>,
}

impl JwksState {
    fn empty() -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: None,
            last_attempt_at: None,
            last_error: None,
        }
    }
}

/// Lock-free read, mutex-serialised refresh JWKS cache.
pub struct JwksCache {
    fetcher: Arc<dyn JwksFetcher>,
    cache_ttl: Duration,
    refresh_min_interval: Duration,
    state: ArcSwap<JwksState>,
    refresh_lock: Mutex<()>,
}

impl JwksCache {
    /// Build an empty cache. The first lookup triggers a fetch.
    pub fn new(fetcher: Arc<dyn JwksFetcher>, cache_ttl: Duration) -> Self {
        Self::with_refresh_interval(fetcher, cache_ttl, Duration::from_secs(30))
    }

    /// Build a cache with a custom refresh-rate-limit interval.
    /// Exposed for tests; production uses [`new`] which defaults to
    /// 30 seconds.
    pub fn with_refresh_interval(
        fetcher: Arc<dyn JwksFetcher>,
        cache_ttl: Duration,
        refresh_min_interval: Duration,
    ) -> Self {
        Self {
            fetcher,
            cache_ttl,
            refresh_min_interval,
            state: ArcSwap::from_pointee(JwksState::empty()),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Fetch the verifier key for `kid`, refreshing the JWKS document
    /// from the IdP when the cache is stale or the `kid` is unknown.
    pub async fn get(&self, kid: &str) -> Result<Arc<DecodingKey>, JwksError> {
        let snapshot = self.state.load_full();

        if let Some(key) = snapshot.keys.get(kid) {
            if snapshot
                .fetched_at
                .is_some_and(|at| at.elapsed() < self.cache_ttl)
            {
                return Ok(Arc::clone(key));
            }
        }

        // Either we have no key for this kid or the cache is stale.
        // Try a (rate-limited) refresh and look again.
        self.maybe_refresh(snapshot.as_ref()).await;

        let snapshot = self.state.load_full();
        if let Some(key) = snapshot.keys.get(kid) {
            return Ok(Arc::clone(key));
        }
        if snapshot.keys.is_empty() {
            return Err(JwksError::Unavailable(
                snapshot
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "jwks not yet fetched".to_string()),
            ));
        }
        Err(JwksError::UnknownKid)
    }

    /// Number of cached keys. Operational signal for tests and startup
    /// logs; not on the auth hot path.
    pub fn key_count(&self) -> usize {
        self.state.load().keys.len()
    }

    async fn maybe_refresh(&self, prior: &JwksState) {
        let _guard = self.refresh_lock.lock().await;

        // Re-read state inside the lock: another task may have already
        // refreshed past our snapshot.
        let current = self.state.load_full();
        if let (Some(prior_at), Some(current_at)) = (prior.fetched_at, current.fetched_at) {
            if current_at > prior_at {
                return;
            }
        } else if prior.fetched_at.is_none() && current.fetched_at.is_some() {
            return;
        }

        // Rate-limit retries on both success and failure paths.
        if current
            .last_attempt_at
            .is_some_and(|at| at.elapsed() < self.refresh_min_interval)
        {
            return;
        }

        let attempt = Instant::now();
        match self.fetcher.fetch().await {
            Ok(result) => {
                let keys = build_keys(&result.jwks);
                let new_state = JwksState {
                    keys,
                    fetched_at: Some(attempt),
                    last_attempt_at: Some(attempt),
                    last_error: None,
                };
                self.state.store(Arc::new(new_state));
            }
            Err(err) => {
                tracing::warn!(
                    target: "registry_relay::auth",
                    error = %err,
                    "jwks refresh failed; retaining {} cached key(s)",
                    current.keys.len()
                );
                let updated = JwksState {
                    keys: current.keys.clone(),
                    fetched_at: current.fetched_at,
                    last_attempt_at: Some(attempt),
                    last_error: Some(err.to_string()),
                };
                self.state.store(Arc::new(updated));
            }
        }
    }
}

fn build_keys(jwks: &JwkSet) -> HashMap<String, Arc<DecodingKey>> {
    let mut out = HashMap::with_capacity(jwks.keys.len());
    for jwk in &jwks.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            tracing::warn!(
                target: "registry_relay::auth",
                "jwks entry missing kid; skipping",
            );
            continue;
        };
        match DecodingKey::from_jwk(jwk) {
            Ok(key) => {
                out.insert(kid, Arc::new(key));
            }
            Err(err) => {
                tracing::warn!(
                    target: "registry_relay::auth",
                    %kid,
                    error = %err,
                    "jwks entry could not be converted to decoding key; skipping",
                );
            }
        }
    }
    out
}

/// Build a fetcher that returns the same in-memory [`JwkSet`] on every
/// call. Useful for tests and the local-dev path.
pub fn static_fetcher(jwks: JwkSet) -> Arc<dyn JwksFetcher> {
    Arc::new(StaticFetcher { jwks })
}

struct StaticFetcher {
    jwks: JwkSet,
}

impl JwksFetcher for StaticFetcher {
    fn fetch<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<JwksFetchResult, JwksFetchError>> + Send + 'a>> {
        let jwks = self.jwks.clone();
        Box::pin(async move {
            Ok(JwksFetchResult { jwks })
        })
    }
}

/// Convenience constructor for inspecting a [`Jwk`] from JSON in tests
/// without taking on a serde_json import at every call site.
#[cfg(test)]
pub fn jwks_from_json(value: serde_json::Value) -> JwkSet {
    serde_json::from_value(value).expect("valid jwks json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingFetcher {
        calls: AtomicUsize,
        response: JwkSet,
    }

    impl JwksFetcher for CountingFetcher {
        fn fetch<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<JwksFetchResult, JwksFetchError>> + Send + 'a>>
        {
            let calls = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let response = self.response.clone();
            Box::pin(async move {
                let _ = calls;
                Ok(JwksFetchResult { jwks: response })
            })
        }
    }

    fn one_ed25519_jwk(kid: &str) -> JwkSet {
        // x is a base64url-encoded 32-byte Ed25519 public key; for the
        // cache layer we only need the JWKS to parse and to surface
        // the kid back. The actual signature material is exercised in
        // the provider tests.
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
    async fn first_lookup_triggers_fetch_and_returns_key() {
        let fetcher = Arc::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            response: one_ed25519_jwk("kid-1"),
        });
        let cache = JwksCache::new(fetcher.clone(), Duration::from_secs(60));

        let key = cache.get("kid-1").await.expect("kid-1 resolves");
        assert!(Arc::strong_count(&key) >= 1);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn repeated_lookup_within_ttl_does_not_refetch() {
        let fetcher = Arc::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            response: one_ed25519_jwk("kid-1"),
        });
        let cache = JwksCache::new(fetcher.clone(), Duration::from_secs(60));

        let _ = cache.get("kid-1").await.unwrap();
        let _ = cache.get("kid-1").await.unwrap();
        let _ = cache.get("kid-1").await.unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_kid_triggers_one_refresh_then_returns_unknown_kid() {
        let fetcher = Arc::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            response: one_ed25519_jwk("kid-known"),
        });
        let cache = JwksCache::new(fetcher.clone(), Duration::from_secs(60));

        let err = match cache.get("kid-mystery").await {
            Ok(_) => panic!("expected UnknownKid"),
            Err(e) => e,
        };
        assert!(matches!(err, JwksError::UnknownKid));
        // First call returned UnknownKid but we still cached the
        // result of the fetch.
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        // Hot path: known kid resolves without refetch.
        let _ = cache.get("kid-known").await.unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_is_rate_limited_within_min_interval() {
        let fetcher = Arc::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            response: one_ed25519_jwk("kid-known"),
        });
        let cache = JwksCache::with_refresh_interval(
            fetcher.clone(),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );

        // First lookup populates the cache.
        let _ = cache.get("kid-known").await.unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Many lookups for unknown kids must not all trigger fetches.
        for _ in 0..5 {
            if cache.get("kid-x").await.is_ok() {
                panic!("expected error for unknown kid");
            }
        }
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    struct FailingFetcher;

    impl JwksFetcher for FailingFetcher {
        fn fetch<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<JwksFetchResult, JwksFetchError>> + Send + 'a>>
        {
            Box::pin(async move { Err(JwksFetchError::Transport("simulated".to_string())) })
        }
    }

    #[tokio::test]
    async fn empty_cache_with_failed_fetch_returns_unavailable() {
        let cache = JwksCache::new(Arc::new(FailingFetcher), Duration::from_secs(60));
        let err = match cache.get("any-kid").await {
            Ok(_) => panic!("expected Unavailable"),
            Err(e) => e,
        };
        assert!(matches!(err, JwksError::Unavailable(_)));
    }
}
