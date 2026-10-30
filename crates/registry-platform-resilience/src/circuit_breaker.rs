//! A process-local circuit breaker state machine.
//!
//! The breaker moves between three phases over the calls and records its
//! caller makes; it owns no clock of its own and starts nothing. A
//! caller asks [`CircuitBreaker::acquire`] before a guarded call and
//! records the call's outcome and duration afterwards.
//!
//! - **Closed**: every call is permitted. Outcomes land in a fixed
//!   count-based window of the last `sliding_window_calls` calls; once
//!   the window holds at least `minimum_number_of_calls` of them, a
//!   failure rate at or above `failure_rate_threshold`, or a slow-call
//!   rate at or above `slow_call_rate_threshold` (a call at or above
//!   `slow_call_duration_threshold` in duration is slow), opens the
//!   breaker.
//! - **Open**: no call is permitted until `open_state_wait` elapses.
//!   The move to half-open is lazy: the first acquire after the wait
//!   makes it, so a breaker nobody calls again stays open, and a caller
//!   that never asked to observe the transition asynchronously observes
//!   the same behavior as one that did.
//! - **Half-open**: at most `maximum_half_open_calls` trial calls are
//!   permitted. A failing trial reopens the breaker with a fresh wait;
//!   once trials equal to `maximum_half_open_calls` have succeeded, the
//!   breaker closes with a fresh window.

use std::{collections::VecDeque, sync::Mutex, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

/// Whether one guarded call may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerAdmission {
    /// The call may run; record its outcome when it completes.
    Permitted,
    /// The call may not run; the caller refuses it its own way.
    Rejected,
}

/// The phase the breaker is in, advanced by any wait its own clock
/// already allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// The configuration of one breaker. Rates are percentages.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// The failure rate at or above which the breaker opens.
    pub failure_rate_threshold: f64,
    /// The slow-call rate at or above which the breaker opens.
    pub slow_call_rate_threshold: f64,
    /// A call at or above this duration is slow.
    pub slow_call_duration_threshold: Duration,
    /// The count-based window of recorded calls.
    pub sliding_window_calls: usize,
    /// Recorded calls in the window before the breaker judges.
    pub minimum_number_of_calls: usize,
    /// How long the breaker stays open before a trial is permitted.
    pub open_state_wait: Duration,
    /// The trials half-open admits before it closes again.
    pub maximum_half_open_calls: usize,
}

/// A breaker configuration failed validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BreakerError {
    #[error("circuit breaker configuration is invalid")]
    Configuration,
}

/// One recorded call of the closed window.
#[derive(Debug, Clone, Copy)]
struct Call {
    failed: bool,
    slow: bool,
}

#[derive(Debug)]
enum Phase {
    Closed { window: VecDeque<Call> },
    Open { opened_at: Instant },
    HalfOpen { permitted: usize, successes: usize },
}

/// One circuit breaker, process-local, shared by reference across the
/// calls it guards.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    inner: Mutex<Phase>,
}

impl CircuitBreaker {
    /// Build a breaker over a validated configuration.
    pub fn new(config: BreakerConfig) -> Result<Self, BreakerError> {
        let rate = |value: f64| value.is_finite() && (0.0..=100.0).contains(&value) && value > 0.0;
        if !rate(config.failure_rate_threshold)
            || !rate(config.slow_call_rate_threshold)
            || config.sliding_window_calls == 0
            || config.minimum_number_of_calls == 0
            || config.minimum_number_of_calls > config.sliding_window_calls
            || config.open_state_wait.is_zero()
            || config.maximum_half_open_calls == 0
        {
            return Err(BreakerError::Configuration);
        }
        Ok(Self {
            config,
            inner: Mutex::new(Phase::Closed {
                window: VecDeque::new(),
            }),
        })
    }

    /// Whether one guarded call may run. A permitted call must be
    /// recorded when it completes; a rejected call must not run.
    pub fn acquire(&self) -> BreakerAdmission {
        let now = Instant::now();
        let mut phase = self.inner.lock().expect("the breaker lock is not poisoned");
        match *phase {
            Phase::Closed { .. } => BreakerAdmission::Permitted,
            Phase::Open { opened_at } => {
                if now.duration_since(opened_at) >= self.config.open_state_wait {
                    // The first acquire after the wait is the first
                    // half-open trial.
                    *phase = Phase::HalfOpen {
                        permitted: 1,
                        successes: 0,
                    };
                    BreakerAdmission::Permitted
                } else {
                    BreakerAdmission::Rejected
                }
            }
            Phase::HalfOpen {
                permitted,
                successes,
            } => {
                if permitted < self.config.maximum_half_open_calls {
                    *phase = Phase::HalfOpen {
                        permitted: permitted + 1,
                        successes,
                    };
                    BreakerAdmission::Permitted
                } else {
                    BreakerAdmission::Rejected
                }
            }
        }
    }

    /// Record one completed permitted call. A duration at or above the
    /// slow threshold counts against the slow-call rate even when the
    /// call succeeded.
    pub fn record(&self, success: bool, duration: Duration) {
        let now = Instant::now();
        let mut phase = self.inner.lock().expect("the breaker lock is not poisoned");
        match &mut *phase {
            Phase::Closed { window } => {
                window.push_back(Call {
                    failed: !success,
                    slow: duration >= self.config.slow_call_duration_threshold,
                });
                while window.len() > self.config.sliding_window_calls {
                    window.pop_front();
                }
                let calls = window.len();
                if calls >= self.config.minimum_number_of_calls {
                    let failures = window.iter().filter(|call| call.failed).count();
                    let slows = window.iter().filter(|call| call.slow).count();
                    let failure_rate = 100.0 * failures as f64 / calls as f64;
                    let slow_rate = 100.0 * slows as f64 / calls as f64;
                    if failure_rate >= self.config.failure_rate_threshold
                        || slow_rate >= self.config.slow_call_rate_threshold
                    {
                        *phase = Phase::Open { opened_at: now };
                    }
                }
            }
            // A record for a permit issued before the breaker opened.
            Phase::Open { .. } => {}
            Phase::HalfOpen { successes, .. } => {
                if success {
                    *successes += 1;
                    if *successes >= self.config.maximum_half_open_calls {
                        *phase = Phase::Closed {
                            window: VecDeque::new(),
                        };
                    }
                } else {
                    // One failing trial is enough to reopen, with a
                    // fresh wait.
                    *phase = Phase::Open { opened_at: now };
                }
            }
        }
    }

    /// The phase the breaker is in, after any transition its own wait
    /// already allows. This observes without admitting anything.
    pub fn state(&self) -> BreakerState {
        let now = Instant::now();
        let phase = self.inner.lock().expect("the breaker lock is not poisoned");
        match *phase {
            Phase::Closed { .. } => BreakerState::Closed,
            Phase::Open { opened_at } => {
                if now.duration_since(opened_at) >= self.config.open_state_wait {
                    BreakerState::HalfOpen
                } else {
                    BreakerState::Open
                }
            }
            Phase::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BreakerConfig {
        BreakerConfig {
            failure_rate_threshold: 50.0,
            slow_call_rate_threshold: 60.0,
            slow_call_duration_threshold: Duration::from_secs(60),
            sliding_window_calls: 4,
            minimum_number_of_calls: 2,
            open_state_wait: Duration::from_millis(30),
            maximum_half_open_calls: 2,
        }
    }

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(config()).expect("the breaker builds")
    }

    #[test]
    fn invalid_configuration_is_refused() {
        let cases = [
            BreakerConfig {
                failure_rate_threshold: 0.0,
                ..config()
            },
            BreakerConfig {
                failure_rate_threshold: 100.5,
                ..config()
            },
            BreakerConfig {
                slow_call_rate_threshold: 0.0,
                ..config()
            },
            BreakerConfig {
                sliding_window_calls: 0,
                ..config()
            },
            BreakerConfig {
                minimum_number_of_calls: 0,
                ..config()
            },
            // A minimum above the window can never be reached inside it.
            BreakerConfig {
                minimum_number_of_calls: 5,
                sliding_window_calls: 4,
                ..config()
            },
            BreakerConfig {
                open_state_wait: Duration::ZERO,
                ..config()
            },
            BreakerConfig {
                maximum_half_open_calls: 0,
                ..config()
            },
        ];
        for case in cases {
            assert_eq!(
                CircuitBreaker::new(case).unwrap_err(),
                BreakerError::Configuration
            );
        }
        CircuitBreaker::new(config()).expect("the base configuration builds");
    }

    #[test]
    fn a_closed_breaker_permits_and_judges_only_from_the_minimum() {
        let mut config = config();
        config.minimum_number_of_calls = 3;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        // Two failures recorded, but the breaker judges only from three
        // recorded calls.
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Closed);
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[test]
    fn the_failure_rate_opens_the_breaker_at_the_threshold() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.acquire(), BreakerAdmission::Rejected);
    }

    #[test]
    fn failures_below_the_rate_leave_the_breaker_closed() {
        let mut config = config();
        config.failure_rate_threshold = 60.0;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        // Two failures of four recorded sit at fifty percent, below the
        // sixty percent threshold.
        for failed in [false, true, false, true] {
            breaker.record(!failed, Duration::from_millis(1));
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
    }

    #[test]
    fn slow_calls_open_through_their_own_rate() {
        let mut config = config();
        config.slow_call_duration_threshold = Duration::from_millis(20);
        config.slow_call_rate_threshold = 50.0;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        breaker.record(true, Duration::from_millis(40));
        breaker.record(true, Duration::from_millis(40));
        assert_eq!(
            breaker.state(),
            BreakerState::Open,
            "two slow successes of two recorded open the breaker"
        );
    }

    #[tokio::test]
    async fn an_open_breaker_permits_a_half_open_trial_after_the_wait() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.acquire(), BreakerAdmission::Rejected);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
    }

    #[tokio::test]
    async fn a_failing_trial_reopens_the_breaker_with_a_fresh_wait() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        assert_eq!(breaker.acquire(), BreakerAdmission::Rejected);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
    }

    #[tokio::test]
    async fn successful_trials_close_the_breaker_with_a_fresh_window() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        breaker.record(true, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        breaker.record(true, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Closed);
        // The closed window is fresh: one failure of a two-call minimum
        // does not open it again.
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test]
    async fn half_open_admits_no_more_than_the_maximum_trials() {
        let mut config = config();
        config.maximum_half_open_calls = 1;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(breaker.acquire(), BreakerAdmission::Permitted);
        // One trial is outstanding and unrecorded; a second is refused.
        assert_eq!(breaker.acquire(), BreakerAdmission::Rejected);
    }

    #[tokio::test]
    async fn state_reports_the_lazily_advanced_phase() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        tokio::time::sleep(Duration::from_millis(40)).await;
        // No call was made; the view still reports the wait as elapsed.
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
    }
}
