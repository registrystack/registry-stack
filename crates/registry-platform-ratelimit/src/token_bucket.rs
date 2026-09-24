//! A keyed token bucket: a smooth per-key request budget with burst.

use std::{collections::HashMap, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

use crate::{validate_key, MAX_TRACKED_KEYS};

/// A bucket idle for longer than this is dropped during pruning, independent
/// of the configured refill rate. This bounds memory held by keys that have
/// gone quiet, not the rate any active key is charged.
const IDLE_EVICTION: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy)]
pub struct TokenBucketConfig {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TokenBucketError {
    #[error("token bucket configuration is invalid")]
    Configuration,
    #[error("token bucket capacity is unavailable")]
    Capacity,
    #[error("token bucket rate exceeded, retry after {retry_after:?}")]
    Exceeded { retry_after: Duration },
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated_at: Instant,
}

/// A keyed token bucket limiter.
///
/// Each key gets its own bucket of size `burst`, refilling at
/// `requests_per_minute / 60` tokens per second, capped at `burst`. Admission
/// charges a caller-declared cost; a refusal leaves the bucket untouched (a
/// refused request never consumes partial tokens) and reports how long the
/// caller should wait before that same cost could be admitted.
#[derive(Debug)]
pub struct TokenBucketLimiter {
    config: TokenBucketConfig,
    buckets: tokio::sync::Mutex<HashMap<String, Bucket>>,
}

impl TokenBucketLimiter {
    pub fn new(config: TokenBucketConfig) -> Result<Self, TokenBucketError> {
        if config.requests_per_minute == 0 || config.burst == 0 {
            return Err(TokenBucketError::Configuration);
        }
        Ok(Self {
            config,
            buckets: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Check and, on success, admit `cost` tokens against `key`'s bucket.
    ///
    /// A cost of zero is charged as one, so a caller cannot make a request
    /// free by declaring no cost.
    pub async fn check(&self, key: &str, cost: u32) -> Result<(), TokenBucketError> {
        validate_key(key).map_err(|_| TokenBucketError::Configuration)?;
        let cost = f64::from(cost.max(1));
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        prune(&mut buckets, now);
        if !buckets.contains_key(key) && buckets.len() >= MAX_TRACKED_KEYS {
            return Err(TokenBucketError::Capacity);
        }
        let capacity = f64::from(self.config.burst);
        let refill_per_second = f64::from(self.config.requests_per_minute) / 60.0;
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: capacity,
            updated_at: now,
        });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(capacity);
        bucket.updated_at = now;
        if bucket.tokens < cost {
            let deficit = cost - bucket.tokens;
            let retry_after = Duration::from_secs_f64(deficit / refill_per_second);
            return Err(TokenBucketError::Exceeded { retry_after });
        }
        bucket.tokens -= cost;
        Ok(())
    }

    /// Total keys currently tracked, toward [`MAX_TRACKED_KEYS`].
    pub async fn tracked_key_count(&self) -> usize {
        self.buckets.lock().await.len()
    }
}

fn prune(buckets: &mut HashMap<String, Bucket>, now: Instant) {
    if buckets.len() < MAX_TRACKED_KEYS / 2 {
        return;
    }
    buckets.retain(|_, bucket| now.duration_since(bucket.updated_at) < IDLE_EVICTION);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> TokenBucketLimiter {
        TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 2,
        })
        .expect("limiter builds")
    }

    #[test]
    fn zero_requests_per_minute_is_refused_at_construction() {
        assert_eq!(
            TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute: 0,
                burst: 1,
            })
            .unwrap_err(),
            TokenBucketError::Configuration
        );
    }

    #[test]
    fn zero_burst_is_refused_at_construction() {
        assert_eq!(
            TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute: 1,
                burst: 0,
            })
            .unwrap_err(),
            TokenBucketError::Configuration
        );
    }

    #[tokio::test]
    async fn an_invalid_key_is_refused() {
        let limiter = limiter();
        assert_eq!(
            limiter.check("", 1).await.unwrap_err(),
            TokenBucketError::Configuration
        );
        assert_eq!(
            limiter.check("has space", 1).await.unwrap_err(),
            TokenBucketError::Configuration
        );
    }

    #[tokio::test]
    async fn burst_and_refill_are_enforced() {
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 6_000,
            burst: 2,
        })
        .expect("limiter builds");
        limiter.check("pseudonym-a", 1).await.expect("first");
        limiter.check("pseudonym-a", 1).await.expect("second");
        assert!(matches!(
            limiter.check("pseudonym-a", 1).await,
            Err(TokenBucketError::Exceeded { .. })
        ));
        tokio::time::sleep(Duration::from_millis(11)).await;
        limiter.check("pseudonym-a", 1).await.expect("refilled");
    }

    #[tokio::test]
    async fn budget_is_shared_by_every_check_of_the_same_key() {
        let limiter = limiter();
        let key = "stable-pseudonym";

        limiter.check(key, 1).await.expect("first has capacity");
        limiter.check(key, 1).await.expect("second has capacity");

        assert!(matches!(
            limiter.check(key, 1).await,
            Err(TokenBucketError::Exceeded { .. })
        ));
        limiter
            .check("other-pseudonym", 1)
            .await
            .expect("another key has an independent budget");
    }

    #[tokio::test]
    async fn multi_token_admission_is_atomic_when_the_whole_cost_does_not_fit() {
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 3,
        })
        .expect("limiter builds");

        assert!(matches!(
            limiter.check("batch-key", 4).await,
            Err(TokenBucketError::Exceeded { .. })
        ));
        limiter
            .check("batch-key", 3)
            .await
            .expect("a refused four-token admission consumed no partial tokens");
        assert!(matches!(
            limiter.check("batch-key", 1).await,
            Err(TokenBucketError::Exceeded { .. })
        ));
    }

    #[tokio::test]
    async fn a_cost_of_zero_is_charged_as_one() {
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 1,
        })
        .expect("limiter builds");
        limiter.check("key", 0).await.expect("charged as one");
        assert!(matches!(
            limiter.check("key", 0).await,
            Err(TokenBucketError::Exceeded { .. })
        ));
    }

    #[tokio::test]
    async fn retry_after_reflects_the_time_the_bucket_needs_to_refill_the_cost() {
        // One token per second, burst of one: after the only token is spent,
        // the bucket needs about one second before the next check admits.
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 1,
        })
        .expect("limiter builds");
        limiter.check("key", 1).await.expect("first admits");
        let retry_after = match limiter.check("key", 1).await {
            Err(TokenBucketError::Exceeded { retry_after }) => retry_after,
            other => panic!("expected an exceeded refusal, got {other:?}"),
        };
        let expected = Duration::from_secs(1);
        let tolerance = Duration::from_millis(100);
        assert!(
            retry_after.abs_diff(expected) < tolerance,
            "retry_after {retry_after:?} was not close to {expected:?}"
        );
    }

    #[tokio::test]
    async fn retry_after_scales_with_the_shortfall() {
        // Two tokens per second, burst of two: refusing a three-token request
        // right after emptying the bucket needs about 1.5 seconds (three
        // tokens short by one and a half, at two tokens per second).
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 120,
            burst: 2,
        })
        .expect("limiter builds");
        limiter.check("key", 2).await.expect("drains the bucket");
        let retry_after = match limiter.check("key", 3).await {
            Err(TokenBucketError::Exceeded { retry_after }) => retry_after,
            other => panic!("expected an exceeded refusal, got {other:?}"),
        };
        let expected = Duration::from_millis(1_500);
        let tolerance = Duration::from_millis(100);
        assert!(
            retry_after.abs_diff(expected) < tolerance,
            "retry_after {retry_after:?} was not close to {expected:?}"
        );
    }

    #[tokio::test]
    async fn tracked_key_count_reports_distinct_keys_and_ignores_reuse() {
        let limiter = limiter();
        assert_eq!(limiter.tracked_key_count().await, 0);

        limiter.check("pseudonym-a", 1).await.expect("first key");
        limiter.check("pseudonym-b", 1).await.expect("second key");
        assert_eq!(limiter.tracked_key_count().await, 2);

        limiter.check("pseudonym-a", 1).await.expect("existing key");
        assert_eq!(limiter.tracked_key_count().await, 2);
    }

    #[tokio::test]
    async fn a_new_key_is_refused_once_the_tracked_key_cap_is_reached() {
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 1,
        })
        .expect("limiter builds");
        {
            let mut buckets = limiter.buckets.lock().await;
            let now = Instant::now();
            for index in 0..crate::MAX_TRACKED_KEYS {
                buckets.insert(
                    format!("filler-{index}"),
                    Bucket {
                        tokens: 1.0,
                        updated_at: now,
                    },
                );
            }
        }
        assert_eq!(
            limiter.check("new-key", 1).await.unwrap_err(),
            TokenBucketError::Capacity
        );
        // An already-tracked key keeps working: the cap blocks new keys, not
        // continued use of ones already admitted.
        limiter
            .check("filler-0", 1)
            .await
            .expect("an already-tracked key is unaffected by the cap");
    }

    #[tokio::test]
    async fn pruning_evicts_idle_keys_once_the_map_is_half_full_of_the_cap() {
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: 60,
            burst: 1,
        })
        .expect("limiter builds");
        let stale_at = Instant::now()
            .checked_sub(IDLE_EVICTION + Duration::from_secs(1))
            .expect("test clock has enough headroom to subtract");
        {
            let mut buckets = limiter.buckets.lock().await;
            for index in 0..(crate::MAX_TRACKED_KEYS / 2) {
                buckets.insert(
                    format!("stale-{index}"),
                    Bucket {
                        tokens: 1.0,
                        updated_at: stale_at,
                    },
                );
            }
        }
        // Crossing the half-cap threshold on the next check prunes every
        // entry idle longer than the eviction bound before admitting the new
        // key, so tracked_key_count reflects only the fresh key afterward.
        limiter.check("fresh-key", 1).await.expect("fresh key");
        assert_eq!(limiter.tracked_key_count().await, 1);
    }
}
