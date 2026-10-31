//! An unkeyed rolling window limiter: one budget of at most `limit`
//! admissions inside a rolling `window`.

use std::{collections::VecDeque, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

/// The configuration of one rolling window.
#[derive(Debug, Clone, Copy)]
pub struct RollingWindowConfig {
    /// How long one admission stays counted.
    pub window: Duration,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RollingWindowError {
    #[error("rolling window configuration is invalid")]
    Configuration,
    /// The window is full; `retry_after` is how long until the oldest
    /// admission ages out and one more admission fits.
    #[error("rolling window limit is exceeded")]
    Exceeded { retry_after: Duration },
}

/// A rolling window limiter for one caller-chosen budget: at most
/// `limit` admissions inside the last `window`, where the caller passes
/// `limit` on each [`Self::acquire`] because a caller whose limit is
/// derived per call keeps one limiter for the window it paces over.
///
/// Unlike the keyed primitives beside it, this limiter holds one
/// budget, not one per key: it is the process-local pacing of one node
/// a caller designates, and the caller decides what that node is.
#[derive(Debug)]
pub struct RollingWindowLimiter {
    window: Duration,
    admissions: tokio::sync::Mutex<VecDeque<Instant>>,
}

impl RollingWindowLimiter {
    pub fn new(config: RollingWindowConfig) -> Result<Self, RollingWindowError> {
        if config.window.is_zero() {
            return Err(RollingWindowError::Configuration);
        }
        Ok(Self {
            window: config.window,
            admissions: tokio::sync::Mutex::new(VecDeque::new()),
        })
    }

    /// Admit one call under `limit` admissions per window. A refusal
    /// carries how long until the oldest admission ages out.
    pub async fn acquire(&self, limit: u32) -> Result<(), RollingWindowError> {
        if limit == 0 {
            return Err(RollingWindowError::Configuration);
        }
        let now = Instant::now();
        let mut admissions = self.admissions.lock().await;
        while admissions
            .front()
            .is_some_and(|admitted| now.duration_since(*admitted) >= self.window)
        {
            admissions.pop_front();
        }
        if admissions.len() < limit as usize {
            admissions.push_back(now);
            return Ok(());
        }
        // The oldest admission still counted is the front; the wait is
        // the rest of its window.
        let oldest = admissions
            .front()
            .expect("a full window holds its oldest admission");
        Err(RollingWindowError::Exceeded {
            retry_after: self.window - now.duration_since(*oldest),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(window: Duration) -> RollingWindowLimiter {
        RollingWindowLimiter::new(RollingWindowConfig { window }).expect("the limiter builds")
    }

    #[test]
    fn a_zero_window_is_refused_at_construction() {
        assert_eq!(
            RollingWindowLimiter::new(RollingWindowConfig {
                window: Duration::ZERO
            })
            .unwrap_err(),
            RollingWindowError::Configuration
        );
    }

    #[tokio::test]
    async fn a_zero_limit_is_refused() {
        let limiter = limiter(Duration::from_secs(60));
        assert_eq!(
            limiter.acquire(0).await.unwrap_err(),
            RollingWindowError::Configuration
        );
    }

    #[tokio::test]
    async fn calls_within_the_limit_are_admitted() {
        let limiter = limiter(Duration::from_secs(60));
        limiter.acquire(2).await.expect("the first admits");
        limiter.acquire(2).await.expect("the second admits");
    }

    #[tokio::test]
    async fn a_call_over_the_limit_is_refused_with_the_wait() {
        let limiter = limiter(Duration::from_secs(60));
        limiter.acquire(1).await.expect("the first admits");
        let RollingWindowError::Exceeded { retry_after } = limiter.acquire(1).await.unwrap_err()
        else {
            panic!("the second call is over the limit");
        };
        assert!(
            retry_after > Duration::from_secs(59) && retry_after <= Duration::from_secs(60),
            "the wait is the rest of the oldest admission's window, was {retry_after:?}"
        );
    }

    #[tokio::test]
    async fn the_window_rolls_as_each_admission_ages() {
        let limiter = limiter(Duration::from_millis(30));
        limiter.acquire(2).await.expect("the first admits");
        limiter.acquire(2).await.expect("the second admits");
        assert!(limiter.acquire(2).await.is_err(), "the window is full");
        tokio::time::sleep(Duration::from_millis(35)).await;
        // Both aged-out admissions left the window together, so two more
        // fit without waiting for a full period past the refusal.
        limiter.acquire(2).await.expect("the oldest aged out");
        limiter
            .acquire(2)
            .await
            .expect("the second after the roll admits");
        assert!(
            limiter.acquire(2).await.is_err(),
            "the window is full again"
        );
    }
}
