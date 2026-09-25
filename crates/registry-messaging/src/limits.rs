// SPDX-License-Identifier: Apache-2.0

//! The in-memory limits: each access profile's request rate, keyed by the
//! caller's audit pseudonym, and each provider's send rate, keyed by the
//! provider id.
//!
//! Both are `registry-platform-ratelimit` token buckets, so both are per
//! process: one replica is the supported topology, and with more replicas
//! each one enforces its own limits. The one limit that must survive a
//! restart, an access profile's `dailyLimit`, is counted in the acceptance
//! transaction instead (see [`crate::messages`]).
//!
//! A caller's rate is charged once per submission, before its body is read,
//! so a caller cannot spend the runtime's rendering on requests it has no
//! budget for. A refusal carries how long the caller should wait.
//!
//! A provider's rate paces the worker: an attempt waits for the provider's
//! next send slot after it is leased and before anything reaches the
//! provider. Waiting attempts queue in turn, and the wait is bounded by the
//! pacing allowance added to the attempt's timeout, so pacing never eats
//! into the time the send itself is given. An attempt that cannot start in
//! that allowance is a transient failure: nothing was sent, and it is
//! retried under its policy.

use std::collections::BTreeMap;
use std::time::Duration;

use registry_messaging_core::AccessProfiles;
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use thiserror::Error;
use tokio::time::Instant;

/// The longest an attempt waits for its provider's next send slot.
pub const PACING_ALLOWANCE: Duration = Duration::from_secs(10);

/// Why a limit refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitRefusal {
    /// The budget is spent; it admits again after `retry_after`.
    Exceeded { retry_after: Duration },
    /// The limiter could not decide: its key population is at capacity, or
    /// it was asked about a profile it does not hold. Refusing is the safe
    /// answer.
    Unavailable,
}

impl From<TokenBucketError> for LimitRefusal {
    fn from(error: TokenBucketError) -> Self {
        match error {
            TokenBucketError::Exceeded { retry_after } => Self::Exceeded { retry_after },
            TokenBucketError::Configuration | TokenBucketError::Capacity => Self::Unavailable,
        }
    }
}

/// A limit whose configuration the token bucket refused.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("the {kind} rate limit of `{id}` is not a valid token bucket")]
pub struct LimitConfigurationError {
    kind: &'static str,
    id: String,
}

/// The request rate of every access profile of the active package.
#[derive(Debug)]
pub struct CallerLimits {
    by_profile: BTreeMap<String, TokenBucketLimiter>,
}

impl CallerLimits {
    /// One limiter per profile, at the profile's `requestsPerMinute` and
    /// `burst`.
    ///
    /// # Errors
    ///
    /// [`LimitConfigurationError`] for a profile whose rate the limiter
    /// refuses. The package already refuses a zero rate or burst.
    pub fn new(profiles: &AccessProfiles) -> Result<Self, LimitConfigurationError> {
        let by_profile = profiles
            .iter()
            .map(|profile| {
                TokenBucketLimiter::new(TokenBucketConfig {
                    requests_per_minute: profile.requests_per_minute,
                    burst: profile.burst,
                })
                .map(|limiter| (profile.id.clone(), limiter))
                .map_err(|_| LimitConfigurationError {
                    kind: "access profile",
                    id: profile.id.clone(),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { by_profile })
    }

    /// Charge one request by `principal_pseudonym` under `profile`.
    ///
    /// # Errors
    ///
    /// [`LimitRefusal::Exceeded`] when the caller's budget is spent, and
    /// [`LimitRefusal::Unavailable`] when the limiter cannot decide.
    pub async fn check(
        &self,
        profile: &str,
        principal_pseudonym: &str,
    ) -> Result<(), LimitRefusal> {
        let limiter = self
            .by_profile
            .get(profile)
            .ok_or(LimitRefusal::Unavailable)?;
        limiter.check(principal_pseudonym, 1).await?;
        Ok(())
    }
}

/// The sustained rate, per runtime process, at which each provider's
/// callbacks are admitted: one hundred a second.
pub const CALLBACK_REQUESTS_PER_MINUTE: u32 = 6_000;

/// How many callbacks one provider may send at once before the sustained
/// rate applies.
pub const CALLBACK_BURST: u32 = 600;

/// The one budget every callback path naming no receiving provider shares.
/// A provider id is a lowercase kebab identifier, so this key is never one.
const UNROUTED_CALLBACK_KEY: &str = "_unrouted";

/// The rate the unauthenticated callback routes admit, charged before a
/// callback is verified so a flood spends neither verification nor a
/// receipt script. Each receiving provider has its own budget, keyed by its
/// configured id, and every path naming no receiving provider shares one
/// more, so a refusal is the same for both and names no provider.
#[derive(Debug)]
pub struct CallbackLimits {
    limiter: TokenBucketLimiter,
}

impl CallbackLimits {
    /// # Errors
    ///
    /// [`LimitConfigurationError`] when the rate or the burst is zero.
    pub fn new(requests_per_minute: u32, burst: u32) -> Result<Self, LimitConfigurationError> {
        TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute,
            burst,
        })
        .map(|limiter| Self { limiter })
        .map_err(|_| LimitConfigurationError {
            kind: "provider callback",
            id: "every provider".to_owned(),
        })
    }

    /// Charge one callback to `provider`, a provider that receives
    /// callbacks, or to the shared budget when the path named none.
    ///
    /// # Errors
    ///
    /// [`LimitRefusal::Exceeded`] when the budget is spent, and
    /// [`LimitRefusal::Unavailable`] when the limiter cannot decide.
    pub async fn check(&self, provider: Option<&str>) -> Result<(), LimitRefusal> {
        self.limiter
            .check(provider.unwrap_or(UNROUTED_CALLBACK_KEY), 1)
            .await?;
        Ok(())
    }
}

/// One provider's send rate: at most one send starts every
/// `1 / ratePerSecond` seconds, and waiting attempts take their turn in the
/// order they arrived.
#[derive(Debug)]
pub struct ProviderPacer {
    provider: String,
    limiter: TokenBucketLimiter,
    turn: tokio::sync::Mutex<()>,
}

impl ProviderPacer {
    /// # Errors
    ///
    /// [`LimitConfigurationError`] when `rate_per_second` is zero or too
    /// large for the limiter.
    pub fn new(provider: &str, rate_per_second: u32) -> Result<Self, LimitConfigurationError> {
        let refused = || LimitConfigurationError {
            kind: "provider",
            id: provider.to_owned(),
        };
        let requests_per_minute = rate_per_second.checked_mul(60).ok_or_else(refused)?;
        let limiter = TokenBucketLimiter::new(TokenBucketConfig {
            requests_per_minute,
            burst: 1,
        })
        .map_err(|_| refused())?;
        Ok(Self {
            provider: provider.to_owned(),
            limiter,
            turn: tokio::sync::Mutex::new(()),
        })
    }

    /// Wait for the provider's next send slot, until `deadline`.
    ///
    /// # Errors
    ///
    /// [`LimitRefusal::Exceeded`] with the wait still needed when no slot
    /// opens before `deadline`, and [`LimitRefusal::Unavailable`] when the
    /// limiter cannot decide.
    pub async fn acquire(&self, deadline: Instant) -> Result<(), LimitRefusal> {
        let spent = LimitRefusal::Exceeded {
            retry_after: Duration::from_secs(1),
        };
        let Ok(_turn) = tokio::time::timeout_at(deadline, self.turn.lock()).await else {
            return Err(spent);
        };
        loop {
            match self.limiter.check(&self.provider, 1).await {
                Ok(()) => return Ok(()),
                Err(TokenBucketError::Exceeded { retry_after }) => {
                    let ready = Instant::now() + retry_after;
                    if ready > deadline {
                        return Err(LimitRefusal::Exceeded { retry_after });
                    }
                    tokio::time::sleep_until(ready).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_messaging_core::{AccessProfile, AccessRole};

    fn profile(id: &str, requests_per_minute: u32, burst: u32) -> AccessProfile {
        AccessProfile {
            id: id.to_owned(),
            principal_claim: "sub".to_owned(),
            required_scopes: Vec::new(),
            requester_clients: vec![format!("{id}-client")],
            actor_kind: None,
            role: AccessRole::Sender,
            sender_profiles: vec!["notices".to_owned()],
            templates: vec!["reminder".to_owned()],
            allow_direct_content: false,
            requests_per_minute,
            burst,
            daily_limit: None,
        }
    }

    fn limits() -> CallerLimits {
        CallerLimits::new(
            &AccessProfiles::new(vec![profile("narrow", 60, 2), profile("wide", 600, 5)]).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_caller_is_refused_past_its_profile_burst_with_the_wait_needed() {
        let limits = limits();
        limits.check("narrow", "pseudonym-a").await.unwrap();
        limits.check("narrow", "pseudonym-a").await.unwrap();
        let Err(LimitRefusal::Exceeded { retry_after }) =
            limits.check("narrow", "pseudonym-a").await
        else {
            panic!("the third request inside the burst is refused");
        };
        assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn callers_and_profiles_have_separate_budgets() {
        let limits = limits();
        for _ in 0..2 {
            limits.check("narrow", "pseudonym-a").await.unwrap();
        }
        limits.check("narrow", "pseudonym-b").await.unwrap();
        for _ in 0..5 {
            limits.check("wide", "pseudonym-a").await.unwrap();
        }
        assert!(limits.check("narrow", "pseudonym-a").await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_profile_or_an_unusable_key_is_refused_as_unavailable() {
        let limits = limits();
        assert_eq!(
            limits.check("absent", "pseudonym-a").await,
            Err(LimitRefusal::Unavailable)
        );
        assert_eq!(
            limits.check("narrow", "has space").await,
            Err(LimitRefusal::Unavailable)
        );
    }

    #[tokio::test]
    async fn each_callback_provider_and_the_unrouted_paths_have_separate_budgets() {
        let limits = CallbackLimits::new(60, 2).unwrap();
        for _ in 0..2 {
            limits.check(Some("sms-gateway")).await.unwrap();
            limits.check(None).await.unwrap();
        }
        let Err(LimitRefusal::Exceeded { retry_after }) = limits.check(Some("sms-gateway")).await
        else {
            panic!("the third callback inside the burst is refused");
        };
        assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(1));
        assert!(limits.check(None).await.is_err());
        limits.check(Some("mail-gateway")).await.unwrap();
    }

    #[test]
    fn a_zero_callback_rate_or_burst_is_refused() {
        assert!(CallbackLimits::new(0, 1).is_err());
        assert!(CallbackLimits::new(1, 0).is_err());
        assert!(CallbackLimits::new(CALLBACK_REQUESTS_PER_MINUTE, CALLBACK_BURST).is_ok());
    }

    #[test]
    fn a_zero_or_overflowing_provider_rate_is_refused() {
        assert!(ProviderPacer::new("gateway", 0).is_err());
        assert!(ProviderPacer::new("gateway", u32::MAX).is_err());
        assert!(ProviderPacer::new("gateway", 1_000).is_ok());
    }

    #[tokio::test]
    async fn a_provider_starts_one_send_per_interval() {
        let pacer = ProviderPacer::new("gateway", 20).unwrap();
        let started = Instant::now();
        for _ in 0..5 {
            pacer
                .acquire(Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();
        }
        // The first slot is free; the next four open 50 ms apart.
        assert!(started.elapsed() >= Duration::from_millis(195));
    }

    #[tokio::test]
    async fn a_slot_that_opens_after_the_deadline_is_refused_without_waiting() {
        let pacer = ProviderPacer::new("gateway", 1).unwrap();
        pacer.acquire(Instant::now()).await.unwrap();
        let started = Instant::now();
        let refusal = pacer
            .acquire(Instant::now() + Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(
            matches!(refusal, LimitRefusal::Exceeded { retry_after } if retry_after > Duration::from_millis(100))
        );
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
