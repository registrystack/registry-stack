//! In-memory pseudonym-keyed request and failed-selector rate limits.

use std::{collections::HashMap, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

const MAX_TRACKED_KEYS: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub requests_per_principal_per_minute: u32,
    pub burst_per_principal: u32,
    pub failed_selector_attempts_per_principal_authority_per_minute: u32,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("rate-limit configuration is invalid")]
    Configuration,
    #[error("request rate exceeded")]
    RequestExceeded,
    #[error("failed-selector rate exceeded")]
    FailedSelectorExceeded,
    #[error("rate-limit capacity is unavailable")]
    Capacity,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Debug)]
struct FixedWindow {
    started_at: Instant,
    count: u32,
}

#[derive(Debug)]
pub struct EvidenceRateLimiter {
    config: RateLimitConfig,
    requests: tokio::sync::Mutex<HashMap<String, TokenBucket>>,
    selector_failures: tokio::sync::Mutex<HashMap<String, FixedWindow>>,
}

impl EvidenceRateLimiter {
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        if config.requests_per_principal_per_minute == 0
            || config.burst_per_principal == 0
            || config.failed_selector_attempts_per_principal_authority_per_minute == 0
        {
            return Err(RateLimitError::Configuration);
        }
        Ok(Self {
            config,
            requests: tokio::sync::Mutex::new(HashMap::new()),
            selector_failures: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    pub async fn check_request(&self, principal_pseudonym: &str) -> Result<(), RateLimitError> {
        self.check_request_cost(principal_pseudonym, 1).await
    }

    /// Charge one request more than a single token.
    ///
    /// A batch release issues one credential per presented holder key, so it
    /// costs the deployment what that many single-credential requests cost. A
    /// cost of zero would make a request free, so it is charged as one.
    pub async fn check_request_cost(
        &self,
        principal_pseudonym: &str,
        cost: u32,
    ) -> Result<(), RateLimitError> {
        validate_pseudonym_key(principal_pseudonym)?;
        let cost = f64::from(cost.max(1));
        let now = Instant::now();
        let mut buckets = self.requests.lock().await;
        prune_buckets(&mut buckets, now);
        if !buckets.contains_key(principal_pseudonym) && buckets.len() >= MAX_TRACKED_KEYS {
            return Err(RateLimitError::Capacity);
        }
        let capacity = f64::from(self.config.burst_per_principal);
        let refill_per_second = f64::from(self.config.requests_per_principal_per_minute) / 60.0;
        let bucket = buckets
            .entry(principal_pseudonym.to_owned())
            .or_insert(TokenBucket {
                tokens: capacity,
                updated_at: now,
            });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(capacity);
        bucket.updated_at = now;
        if bucket.tokens < cost {
            return Err(RateLimitError::RequestExceeded);
        }
        bucket.tokens -= cost;
        Ok(())
    }

    /// Check the selector-failure budget before source access. Call
    /// [`Self::record_selector_failure`] only when selector validation or
    /// authorization actually fails.
    pub async fn check_selector_failure_budget(
        &self,
        principal_authority_pseudonym: &str,
    ) -> Result<(), RateLimitError> {
        validate_pseudonym_key(principal_authority_pseudonym)?;
        let now = Instant::now();
        let mut windows = self.selector_failures.lock().await;
        prune_windows(&mut windows, now);
        match windows.get(principal_authority_pseudonym) {
            Some(window)
                if now.duration_since(window.started_at) < Duration::from_secs(60)
                    && window.count
                        >= self
                            .config
                            .failed_selector_attempts_per_principal_authority_per_minute =>
            {
                Err(RateLimitError::FailedSelectorExceeded)
            }
            _ => Ok(()),
        }
    }

    pub async fn record_selector_failure(
        &self,
        principal_authority_pseudonym: &str,
    ) -> Result<(), RateLimitError> {
        validate_pseudonym_key(principal_authority_pseudonym)?;
        let now = Instant::now();
        let mut windows = self.selector_failures.lock().await;
        prune_windows(&mut windows, now);
        if !windows.contains_key(principal_authority_pseudonym) && windows.len() >= MAX_TRACKED_KEYS
        {
            return Err(RateLimitError::Capacity);
        }
        let window = windows
            .entry(principal_authority_pseudonym.to_owned())
            .or_insert(FixedWindow {
                started_at: now,
                count: 0,
            });
        if now.duration_since(window.started_at) >= Duration::from_secs(60) {
            window.started_at = now;
            window.count = 0;
        }
        window.count = window.count.saturating_add(1);
        if window.count
            > self
                .config
                .failed_selector_attempts_per_principal_authority_per_minute
        {
            return Err(RateLimitError::FailedSelectorExceeded);
        }
        Ok(())
    }

    /// Total pseudonym keys currently tracked across both maps, toward the
    /// shared [`MAX_TRACKED_KEYS`] capacity ceiling each map enforces.
    ///
    /// Each lock is held only long enough to read `.len()`; no other work
    /// happens in either critical section, since the request path contends
    /// on these same locks.
    pub async fn tracked_key_count(&self) -> usize {
        let requests_len = self.requests.lock().await.len();
        let selector_failures_len = self.selector_failures.lock().await.len();
        requests_len + selector_failures_len
    }
}

fn validate_pseudonym_key(key: &str) -> Result<(), RateLimitError> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_whitespace) {
        return Err(RateLimitError::Configuration);
    }
    Ok(())
}

fn prune_buckets(buckets: &mut HashMap<String, TokenBucket>, now: Instant) {
    if buckets.len() < MAX_TRACKED_KEYS / 2 {
        return;
    }
    buckets.retain(|_, bucket| now.duration_since(bucket.updated_at) < Duration::from_secs(600));
}

fn prune_windows(windows: &mut HashMap<String, FixedWindow>, now: Instant) {
    if windows.len() < MAX_TRACKED_KEYS / 2 {
        return;
    }
    windows.retain(|_, window| now.duration_since(window.started_at) < Duration::from_secs(120));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> EvidenceRateLimiter {
        EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: 60,
            burst_per_principal: 2,
            failed_selector_attempts_per_principal_authority_per_minute: 2,
        })
        .expect("limiter builds")
    }

    #[tokio::test]
    async fn request_burst_and_refill_are_enforced() {
        let limiter = EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: 6_000,
            burst_per_principal: 2,
            failed_selector_attempts_per_principal_authority_per_minute: 2,
        })
        .expect("limiter builds");
        limiter.check_request("pseudonym-a").await.expect("first");
        limiter.check_request("pseudonym-a").await.expect("second");
        assert_eq!(
            limiter.check_request("pseudonym-a").await,
            Err(RateLimitError::RequestExceeded)
        );
        tokio::time::sleep(Duration::from_millis(11)).await;
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("refilled");
    }

    #[tokio::test]
    async fn request_budget_is_shared_by_every_use_of_a_principal_key() {
        let limiter = limiter();
        let principal_key = "stable-principal-pseudonym";

        for _request_context in [
            ("adult", "service-enrolment", "audience-a"),
            ("residence", "benefit-eligibility", "audience-b"),
        ] {
            limiter
                .check_request(principal_key)
                .await
                .expect("shared principal budget has capacity");
        }

        assert_eq!(
            limiter.check_request(principal_key).await,
            Err(RateLimitError::RequestExceeded)
        );
        limiter
            .check_request("other-principal-pseudonym")
            .await
            .expect("another principal has an independent budget");
    }

    #[tokio::test]
    async fn selector_failure_budget_is_separate_and_authority_scoped() {
        let limiter = limiter();
        limiter
            .record_selector_failure("principal-authority-a")
            .await
            .expect("first failure");
        limiter
            .record_selector_failure("principal-authority-a")
            .await
            .expect("second failure");
        assert_eq!(
            limiter
                .check_selector_failure_budget("principal-authority-a")
                .await,
            Err(RateLimitError::FailedSelectorExceeded)
        );
        limiter
            .check_selector_failure_budget("principal-authority-b")
            .await
            .expect("other authority remains available");
    }

    #[tokio::test]
    async fn tracked_key_count_reports_the_total_across_both_maps() {
        let limiter = limiter();
        assert_eq!(limiter.tracked_key_count().await, 0);

        limiter
            .check_request("pseudonym-a")
            .await
            .expect("first principal");
        limiter
            .check_request("pseudonym-b")
            .await
            .expect("second principal");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");

        assert_eq!(limiter.tracked_key_count().await, 3);

        // Reusing an already-tracked key does not grow the count.
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("existing principal");
        assert_eq!(limiter.tracked_key_count().await, 3);
    }

    #[tokio::test]
    async fn selector_failure_budget_is_shared_across_request_contexts() {
        let limiter = limiter();
        let principal_authority_key = "stable-principal-authority-pseudonym";

        for _request_context in [
            ("service-enrolment", "audience-a"),
            ("benefit-eligibility", "audience-b"),
        ] {
            limiter
                .record_selector_failure(principal_authority_key)
                .await
                .expect("shared selector-failure budget has capacity");
        }

        assert_eq!(
            limiter
                .check_selector_failure_budget(principal_authority_key)
                .await,
            Err(RateLimitError::FailedSelectorExceeded)
        );
    }
}
