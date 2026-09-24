// SPDX-License-Identifier: Apache-2.0

//! Attempt-timeout bounds and the retry policy frozen with each job.

use std::time::{Duration, SystemTime};

use crate::outcome::{ConfigError, DispatchError};

/// The longest attempt timeout any consumer may allow.
pub const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// The attempt timeouts one consumer accepts from its captured policies.
///
/// A claimed job whose captured timeout falls outside the bound is refused
/// before it is leased, so no attempt ever runs under a timeout the consumer
/// did not agree to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptTimeoutBound {
    minimum: Duration,
    maximum: Duration,
}

impl AttemptTimeoutBound {
    /// Bound attempt timeouts to `minimum..=maximum`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::AttemptTimeoutBound`] when `minimum` is zero, exceeds
    /// `maximum`, or `maximum` exceeds [`MAX_ATTEMPT_TIMEOUT`].
    pub fn new(minimum: Duration, maximum: Duration) -> Result<Self, ConfigError> {
        if minimum.is_zero() || minimum > maximum || maximum > MAX_ATTEMPT_TIMEOUT {
            return Err(ConfigError::AttemptTimeoutBound);
        }
        Ok(Self { minimum, maximum })
    }

    #[must_use]
    pub const fn minimum(&self) -> Duration {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(&self) -> Duration {
        self.maximum
    }

    #[must_use]
    pub fn contains(&self, timeout: Duration) -> bool {
        (self.minimum..=self.maximum).contains(&timeout)
    }
}

/// How a backoff delay is spread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Jitter {
    /// Every job with the same profile retries after the same delay.
    None,
    /// Equal jitter: a uniform delay between half the base delay, rounded
    /// up, and the whole base delay.
    Equal,
}

/// An exponential backoff profile: `initial`, multiplied by `multiplier`
/// for every further attempt, capped at `maximum`, then jittered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backoff {
    pub initial: Duration,
    pub maximum: Duration,
    pub multiplier: u32,
    pub jitter: Jitter,
}

/// The retry delays a job was captured with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrySchedule {
    /// One captured delay in milliseconds per failed attempt, used exactly.
    /// A receiver's pause hint is ignored: the frozen profile is the whole
    /// contract.
    Frozen { delays_ms: Vec<i64> },
    /// A computed backoff that honours a receiver's pause hint up to its
    /// maximum.
    Backoff(Backoff),
}

impl RetrySchedule {
    /// Whether computing a delay consumes a random sample.
    #[must_use]
    pub const fn needs_sample(&self) -> bool {
        matches!(
            self,
            Self::Backoff(Backoff {
                jitter: Jitter::Equal,
                ..
            })
        )
    }

    /// The delay in milliseconds owed after failed `attempt` (counted from
    /// one), given the receiver's pause hint and a uniform random `sample`
    /// that only [`Jitter::Equal`] consumes.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] when the schedule has no positive delay
    /// for `attempt`.
    pub fn delay_after(
        &self,
        attempt: i16,
        retry_after: Option<Duration>,
        sample: u64,
    ) -> Result<i64, DispatchError> {
        match self {
            Self::Frozen { delays_ms } => frozen_retry_delay(delays_ms, attempt),
            Self::Backoff(backoff) => backoff_delay(backoff, attempt, retry_after, sample),
        }
    }

    fn is_valid(&self, maximum_attempts: i16) -> bool {
        match self {
            Self::Frozen { delays_ms } => {
                usize::try_from(maximum_attempts.saturating_sub(1))
                    .is_ok_and(|expected| delays_ms.len() >= expected)
                    && delays_ms.iter().all(|delay| *delay > 0)
            }
            Self::Backoff(backoff) => {
                backoff.initial >= Duration::from_millis(1)
                    && backoff.initial <= backoff.maximum
                    && backoff.multiplier >= 1
                    && i64::try_from(backoff.maximum.as_millis()).is_ok()
            }
        }
    }
}

/// What the core does with an attempt whose fate is unknown: a lease that
/// lapsed while the send was in flight, or a [`crate::SendOutcome::MaybeSent`]
/// answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncertainOutcome {
    /// Treat the attempt as a transient failure and retry it. Right for a
    /// receiver that deduplicates on the idempotency key.
    Retry,
    /// Stop in the `unknown` state and never send the job again unless an
    /// operator replays it. Right for a receiver that would act twice.
    Hold,
}

/// The dispatch policy one job was captured with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobPolicy {
    /// The whole budget of one attempt. The lease outlives it by a fixed
    /// finalization allowance.
    pub attempt_timeout: Duration,
    /// The attempts the job may use, counted from one.
    pub maximum_attempts: i16,
    pub retry: RetrySchedule,
    pub on_uncertain: UncertainOutcome,
    /// The instant after which the job must not be sent. A claim at or after
    /// it expires the job instead of leasing it, and a retry that would fall
    /// at or after it expires the job instead.
    pub expires_at: Option<SystemTime>,
}

impl JobPolicy {
    /// Whether the policy is internally consistent and its attempt timeout
    /// falls inside `bound`.
    #[must_use]
    pub fn is_valid(&self, bound: &AttemptTimeoutBound) -> bool {
        bound.contains(self.attempt_timeout)
            && self.maximum_attempts >= 1
            && self.retry.is_valid(self.maximum_attempts)
    }
}

/// The frozen delay owed after `attempt`, or a refusal when the captured
/// profile has no positive delay for it.
///
/// # Errors
///
/// [`DispatchError::Unavailable`] when `attempt` is not positive, runs past
/// the profile, or selects a non-positive delay.
pub fn frozen_retry_delay(retry_delays_ms: &[i64], attempt: i16) -> Result<i64, DispatchError> {
    let delay_index =
        usize::try_from(attempt.saturating_sub(1)).map_err(|_| DispatchError::Unavailable)?;
    if attempt < 1 {
        return Err(DispatchError::Unavailable);
    }
    retry_delays_ms
        .get(delay_index)
        .filter(|delay| **delay > 0)
        .copied()
        .ok_or(DispatchError::Unavailable)
}

fn backoff_delay(
    backoff: &Backoff,
    attempt: i16,
    retry_after: Option<Duration>,
    sample: u64,
) -> Result<i64, DispatchError> {
    let exponent = u32::try_from(attempt.checked_sub(1).ok_or(DispatchError::Unavailable)?)
        .map_err(|_| DispatchError::Unavailable)?;
    let initial =
        u64::try_from(backoff.initial.as_millis()).map_err(|_| DispatchError::Unavailable)?;
    let maximum =
        u64::try_from(backoff.maximum.as_millis()).map_err(|_| DispatchError::Unavailable)?;
    if initial == 0 || initial > maximum || backoff.multiplier == 0 {
        return Err(DispatchError::Unavailable);
    }
    let base = u64::from(backoff.multiplier)
        .checked_pow(exponent)
        .and_then(|factor| initial.checked_mul(factor))
        .map_or(maximum, |delay| delay.min(maximum));
    let jittered = match backoff.jitter {
        Jitter::None => base,
        Jitter::Equal => {
            let half = base / 2;
            base - half + sample % (half + 1)
        }
    };
    let hinted = retry_after.map_or(0, |hint| {
        u64::try_from(hint.as_millis()).map_or(maximum, |hint| hint.min(maximum))
    });
    i64::try_from(jittered.max(hinted)).map_err(|_| DispatchError::Unavailable)
}

/// Attempt budget still available for the send, or `None` once the captured
/// attempt timeout is spent.
///
/// The claim timestamp is the database clock and `now` is this process's clock,
/// so the two disagree by whatever offset separates the two hosts. An attempt
/// that appears to start in the local future has spent none of its budget, and
/// the send that follows still gets at most the captured attempt timeout.
#[must_use]
pub fn remaining_attempt_budget(
    attempt_timeout: Duration,
    attempt_started_at: SystemTime,
    now: SystemTime,
) -> Option<Duration> {
    let elapsed = now
        .duration_since(attempt_started_at)
        .unwrap_or(Duration::ZERO);
    attempt_timeout.checked_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backoff(jitter: Jitter) -> RetrySchedule {
        RetrySchedule::Backoff(Backoff {
            initial: Duration::from_millis(1_000),
            maximum: Duration::from_millis(10_000),
            multiplier: 2,
            jitter,
        })
    }

    #[test]
    fn the_scheduled_retry_delay_comes_from_the_captured_profile() {
        let delays = [500, 1_500];
        assert_eq!(frozen_retry_delay(&delays, 1), Ok(500));
        assert_eq!(frozen_retry_delay(&delays, 2), Ok(1_500));
        assert_eq!(
            frozen_retry_delay(&delays, 3),
            Err(DispatchError::Unavailable),
            "an attempt past the captured profile is refused"
        );
        assert_eq!(
            frozen_retry_delay(&[0], 1),
            Err(DispatchError::Unavailable),
            "a non-positive delay is refused"
        );
        assert_eq!(
            frozen_retry_delay(&delays, 0),
            Err(DispatchError::Unavailable)
        );
    }

    #[test]
    fn a_frozen_profile_ignores_the_receiver_pause_hint() {
        let schedule = RetrySchedule::Frozen {
            delays_ms: vec![500, 1_500],
        };
        assert_eq!(
            schedule.delay_after(1, Some(Duration::from_secs(30)), 7),
            Ok(500)
        );
        assert!(!schedule.needs_sample());
    }

    #[test]
    fn a_backoff_doubles_from_its_initial_delay_up_to_its_maximum() {
        let schedule = backoff(Jitter::None);
        let delays: Vec<_> = (1..=6)
            .map(|attempt| schedule.delay_after(attempt, None, 0))
            .collect();
        assert_eq!(
            delays,
            vec![
                Ok(1_000),
                Ok(2_000),
                Ok(4_000),
                Ok(8_000),
                Ok(10_000),
                Ok(10_000)
            ]
        );
        assert_eq!(
            schedule.delay_after(i16::MAX, None, 0),
            Ok(10_000),
            "an overflowing exponent saturates at the maximum"
        );
        assert_eq!(
            schedule.delay_after(0, None, 0),
            Err(DispatchError::Unavailable)
        );
    }

    #[test]
    fn equal_jitter_stays_between_half_and_all_of_the_base_delay() {
        let schedule = backoff(Jitter::Equal);
        assert!(schedule.needs_sample());
        for sample in [0, 1, 250, 499, 500, 501, 12_345, u64::MAX] {
            let delay = schedule
                .delay_after(1, None, sample)
                .expect("a jittered delay");
            assert!(
                (500..=1_000).contains(&delay),
                "sample {sample} gave {delay}"
            );
        }
        assert_eq!(schedule.delay_after(1, None, 0), Ok(500));
        assert_eq!(schedule.delay_after(1, None, 500), Ok(1_000));
        assert_eq!(
            schedule.delay_after(1, None, 501),
            Ok(500),
            "the sample wraps inside the jitter window"
        );
        // An odd base rounds its lower bound up.
        let odd = RetrySchedule::Backoff(Backoff {
            initial: Duration::from_millis(3),
            maximum: Duration::from_millis(3),
            multiplier: 1,
            jitter: Jitter::Equal,
        });
        let delays: Vec<_> = (0..4)
            .map(|sample| odd.delay_after(1, None, sample))
            .collect();
        assert_eq!(delays, vec![Ok(2), Ok(3), Ok(2), Ok(3)]);
    }

    #[test]
    fn a_pause_hint_is_honoured_up_to_the_maximum_backoff() {
        let schedule = backoff(Jitter::None);
        assert_eq!(
            schedule.delay_after(1, Some(Duration::from_secs(3_600)), 0),
            Ok(10_000),
            "a hint past the maximum is capped"
        );
        assert_eq!(
            schedule.delay_after(1, Some(Duration::from_millis(2_500)), 0),
            Ok(2_500)
        );
        assert_eq!(
            schedule.delay_after(1, Some(Duration::from_millis(10)), 0),
            Ok(1_000),
            "a hint never shortens the backoff"
        );
        assert_eq!(
            backoff(Jitter::Equal).delay_after(1, Some(Duration::from_millis(900)), 0),
            Ok(900),
            "a hint lifts a jittered delay"
        );
    }

    #[test]
    fn attempt_timeout_bounds_stop_at_sixty_seconds() {
        let bound = AttemptTimeoutBound::new(Duration::from_millis(100), Duration::from_secs(10))
            .expect("the hook bound is valid");
        assert!(bound.contains(Duration::from_millis(100)));
        assert!(bound.contains(Duration::from_secs(10)));
        assert!(!bound.contains(Duration::from_millis(99)));
        assert!(!bound.contains(Duration::from_millis(10_001)));
        assert!(AttemptTimeoutBound::new(Duration::from_secs(1), MAX_ATTEMPT_TIMEOUT).is_ok());
        for (minimum, maximum) in [
            (Duration::ZERO, Duration::from_secs(1)),
            (Duration::from_secs(2), Duration::from_secs(1)),
            (Duration::from_secs(1), Duration::from_secs(61)),
        ] {
            assert_eq!(
                AttemptTimeoutBound::new(minimum, maximum),
                Err(ConfigError::AttemptTimeoutBound)
            );
        }
    }

    #[test]
    fn a_policy_is_valid_only_inside_its_bound_and_with_a_usable_schedule() {
        let bound = AttemptTimeoutBound::new(Duration::from_millis(100), Duration::from_secs(60))
            .expect("bound");
        let policy = JobPolicy {
            attempt_timeout: Duration::from_secs(60),
            maximum_attempts: 3,
            retry: RetrySchedule::Frozen {
                delays_ms: vec![1_000, 2_000],
            },
            on_uncertain: UncertainOutcome::Retry,
            expires_at: None,
        };
        assert!(policy.is_valid(&bound));
        let too_long = JobPolicy {
            attempt_timeout: Duration::from_secs(61),
            ..policy.clone()
        };
        assert!(!too_long.is_valid(&bound));
        let short_profile = JobPolicy {
            retry: RetrySchedule::Frozen {
                delays_ms: vec![1_000],
            },
            ..policy.clone()
        };
        assert!(!short_profile.is_valid(&bound));
        let no_attempts = JobPolicy {
            maximum_attempts: 0,
            ..policy.clone()
        };
        assert!(!no_attempts.is_valid(&bound));
        let inverted = JobPolicy {
            retry: RetrySchedule::Backoff(Backoff {
                initial: Duration::from_secs(2),
                maximum: Duration::from_secs(1),
                multiplier: 2,
                jitter: Jitter::None,
            }),
            ..policy
        };
        assert!(!inverted.is_valid(&bound));
    }

    #[test]
    fn attempt_budget_is_measured_from_the_database_claim_clock() {
        let attempt_timeout = Duration::from_millis(2_000);
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            remaining_attempt_budget(attempt_timeout, started, started - Duration::from_millis(5)),
            Some(attempt_timeout)
        );
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                started,
                started + Duration::from_millis(1_500)
            ),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                started,
                started + Duration::from_millis(2_001)
            ),
            None
        );
    }
}
