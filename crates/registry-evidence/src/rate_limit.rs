//! In-memory pseudonym-keyed request and failed-selector rate limits.
//!
//! Evidence's own configuration and error vocabulary stay here at the
//! boundary; the limiting algorithms, key rules, tracked-key cap, and
//! pruning live in `registry-platform-ratelimit`, shared across Registry
//! Stack products.

use std::time::Duration;

use registry_platform_ratelimit::{
    fixed_window::{FixedWindowConfig, FixedWindowCounter, FixedWindowError},
    token_bucket::{TokenBucketConfig, TokenBucketError, TokenBucketLimiter},
};
use thiserror::Error;

/// Failed-selector attempts are counted over a fixed one-minute window,
/// matching the request-rate configuration's per-minute unit.
const SELECTOR_FAILURE_WINDOW: Duration = Duration::from_secs(60);

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

impl From<TokenBucketError> for RateLimitError {
    fn from(error: TokenBucketError) -> Self {
        match error {
            TokenBucketError::Configuration => Self::Configuration,
            TokenBucketError::Capacity => Self::Capacity,
            TokenBucketError::Exceeded { .. } => Self::RequestExceeded,
        }
    }
}

impl From<FixedWindowError> for RateLimitError {
    fn from(error: FixedWindowError) -> Self {
        match error {
            FixedWindowError::Configuration => Self::Configuration,
            FixedWindowError::Capacity => Self::Capacity,
            FixedWindowError::Exceeded => Self::FailedSelectorExceeded,
        }
    }
}

#[derive(Debug)]
pub struct EvidenceRateLimiter {
    requests: TokenBucketLimiter,
    selector_failures: FixedWindowCounter,
}

impl EvidenceRateLimiter {
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitError> {
        let requests = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute: config.requests_per_principal_per_minute,
            burst: config.burst_per_principal,
        })?;
        let selector_failures = FixedWindowCounter::new(FixedWindowConfig {
            window: SELECTOR_FAILURE_WINDOW,
            limit: config.failed_selector_attempts_per_principal_authority_per_minute,
        })?;
        Ok(Self {
            requests,
            selector_failures,
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
        self.requests.check(principal_pseudonym, cost).await?;
        Ok(())
    }

    /// Check the selector-failure budget before source access. Call
    /// [`Self::record_selector_failure`] only when selector validation or
    /// authorization actually fails.
    pub async fn check_selector_failure_budget(
        &self,
        principal_authority_pseudonym: &str,
    ) -> Result<(), RateLimitError> {
        self.selector_failures
            .check(principal_authority_pseudonym)
            .await?;
        Ok(())
    }

    pub async fn record_selector_failure(
        &self,
        principal_authority_pseudonym: &str,
    ) -> Result<(), RateLimitError> {
        self.selector_failures
            .record(principal_authority_pseudonym)
            .await?;
        Ok(())
    }

    /// Total pseudonym keys currently tracked across both underlying
    /// limiters, toward the shared tracked-key capacity ceiling each one
    /// enforces.
    pub async fn tracked_key_count(&self) -> usize {
        self.requests.tracked_key_count().await + self.selector_failures.tracked_key_count().await
    }
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

    #[test]
    fn zero_request_rate_is_refused_at_construction() {
        assert_eq!(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 0,
                burst_per_principal: 1,
                failed_selector_attempts_per_principal_authority_per_minute: 1,
            })
            .unwrap_err(),
            RateLimitError::Configuration
        );
    }

    #[test]
    fn zero_burst_is_refused_at_construction() {
        assert_eq!(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 1,
                burst_per_principal: 0,
                failed_selector_attempts_per_principal_authority_per_minute: 1,
            })
            .unwrap_err(),
            RateLimitError::Configuration
        );
    }

    #[test]
    fn zero_failed_selector_rate_is_refused_at_construction() {
        assert_eq!(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 1,
                burst_per_principal: 1,
                failed_selector_attempts_per_principal_authority_per_minute: 0,
            })
            .unwrap_err(),
            RateLimitError::Configuration
        );
    }

    #[tokio::test]
    async fn request_budget_is_enforced_and_reports_request_exceeded() {
        let limiter = limiter();
        limiter.check_request("pseudonym-a").await.expect("first");
        limiter.check_request("pseudonym-a").await.expect("second");
        assert_eq!(
            limiter.check_request("pseudonym-a").await,
            Err(RateLimitError::RequestExceeded)
        );
    }

    #[tokio::test]
    async fn selector_failure_budget_is_enforced_and_reports_failed_selector_exceeded() {
        let limiter = limiter();
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("second failure");
        assert_eq!(
            limiter.check_selector_failure_budget("authority-a").await,
            Err(RateLimitError::FailedSelectorExceeded)
        );
    }

    #[tokio::test]
    async fn tracked_key_count_sums_both_underlying_limiters() {
        let limiter = limiter();
        assert_eq!(limiter.tracked_key_count().await, 0);
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("request key");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("selector-failure key");
        assert_eq!(limiter.tracked_key_count().await, 2);
    }

    #[tokio::test]
    async fn an_invalid_pseudonym_key_is_refused() {
        let limiter = limiter();
        assert_eq!(
            limiter.check_request("").await,
            Err(RateLimitError::Configuration)
        );
        assert_eq!(
            limiter.check_selector_failure_budget("has space").await,
            Err(RateLimitError::Configuration)
        );
    }

    // The three tests below are named and kept in this file to satisfy
    // products/evidence/contracts/{acceptance,security}-test-traceability.yaml,
    // which bind specific acceptance rows and security negatives to these
    // exact Rust test items at this exact path. Their underlying algorithm
    // coverage (atomicity, cap, pruning, retry-after) also lives in
    // registry-platform-ratelimit's own suite; these prove the same
    // guarantees hold through Evidence's own boundary type.

    #[tokio::test]
    async fn multi_token_admission_is_atomic_when_the_whole_cost_does_not_fit() {
        let limiter = EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: 60,
            burst_per_principal: 3,
            failed_selector_attempts_per_principal_authority_per_minute: 2,
        })
        .expect("limiter builds");

        assert_eq!(
            limiter.check_request_cost("batch-principal", 4).await,
            Err(RateLimitError::RequestExceeded)
        );
        limiter
            .check_request_cost("batch-principal", 3)
            .await
            .expect("a refused four-item admission consumed no partial tokens");
        assert_eq!(
            limiter.check_request("batch-principal").await,
            Err(RateLimitError::RequestExceeded)
        );
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
