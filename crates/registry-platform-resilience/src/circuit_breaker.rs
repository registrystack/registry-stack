//! A process-local circuit breaker state machine.
//!
//! The breaker moves between three phases over the calls and records its
//! caller makes; it owns no clock of its own and starts nothing. A
//! caller asks [`CircuitBreaker::acquire`] before a guarded call and
//! records the call's outcome and duration through the permit it was
//! handed. A permit dropped without a record counts as a failed call
//! for its elapsed duration, so a caller whose future is abandoned
//! between the acquire and the record cannot strand a half-open
//! breaker: the trial goes back as a failure and the breaker reopens
//! with a fresh wait.
//!
//! Every phase change starts a new cycle, and a permit carries the
//! cycle it was admitted in: an outcome, or an abandoned permit, from
//! an earlier cycle is ignored, so a slow call of the closed window can
//! neither close nor fail a later recovery cycle.
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

use std::{cell::Cell, collections::VecDeque, sync::Mutex, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

/// Whether one guarded call may run: the call's permit, or a rejection
/// the caller refuses its own way.
#[derive(Debug)]
pub enum Acquired<'a> {
    /// The call may run; record its outcome through the permit when it
    /// completes, or drop the permit unrecorded to count the abandoned
    /// call as a failure.
    Permitted(BreakerPermit<'a>),
    /// The call may not run; the caller refuses it its own way.
    Rejected,
}

/// One admitted guarded call. The call's outcome and duration are
/// recorded through [`BreakerPermit::record`]; a permit dropped without
/// a record counts the call as failed for its elapsed duration, so an
/// abandoned trial can never hold a half-open breaker shut. The permit
/// carries the cycle it was admitted in, and an outcome that arrives
/// after the breaker has left that cycle lands nowhere.
#[derive(Debug)]
pub struct BreakerPermit<'a> {
    breaker: &'a CircuitBreaker,
    acquired_at: Instant,
    cycle: u64,
    recorded: Cell<bool>,
}

impl BreakerPermit<'_> {
    /// Record the completed call's outcome. A duration at or above the
    /// slow threshold counts against the slow-call rate even when the
    /// call succeeded. An outcome from a cycle the breaker has already
    /// left is ignored.
    pub fn record(self, success: bool, duration: Duration) {
        self.recorded.set(true);
        self.breaker
            .record_outcome(success, duration, Some(self.cycle));
    }

    /// Exclude a completed call from both failure and slow-call statistics.
    /// A same-cycle half-open trial releases its slot so a replacement can
    /// supply the outcome needed for recovery. This does not apply to an
    /// abandoned call, which still counts as failure when its permit drops.
    pub fn ignore(self) {
        self.recorded.set(true);
        let mut internals = self
            .breaker
            .inner
            .lock()
            .expect("the breaker lock is not poisoned");
        if internals.cycle == self.cycle {
            if let Phase::HalfOpen { permitted, .. } = &mut internals.phase {
                *permitted -= 1;
            }
        }
    }
}

impl Drop for BreakerPermit<'_> {
    fn drop(&mut self) {
        if !self.recorded.get() {
            // The call was abandoned before it completed: its outcome
            // is unknown, so it fails closed, and the elapsed duration
            // carries it into the slow-call rate. If the breaker has
            // left the call's cycle, the failure lands nowhere.
            self.breaker
                .record_outcome(false, self.acquired_at.elapsed(), Some(self.cycle));
        }
    }
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

/// The phase plus the cycle that phase belongs to. Every phase change
/// starts a new cycle, and an outcome from an earlier cycle is ignored:
/// a call admitted in one cycle can neither help nor hurt a later one.
#[derive(Debug)]
struct Internals {
    phase: Phase,
    cycle: u64,
}

/// One circuit breaker, process-local, shared by reference across the
/// calls it guards.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    inner: Mutex<Internals>,
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
            inner: Mutex::new(Internals {
                phase: Phase::Closed {
                    window: VecDeque::new(),
                },
                cycle: 0,
            }),
        })
    }

    /// Whether one guarded call may run. A permitted call holds its
    /// permit until the call completes and is recorded through it; a
    /// rejected call must not run.
    pub fn acquire(&self) -> Acquired<'_> {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("the breaker lock is not poisoned");
        let internals = &mut *guard;
        let permit = |cycle: u64| {
            Acquired::Permitted(BreakerPermit {
                breaker: self,
                acquired_at: now,
                cycle,
                recorded: Cell::new(false),
            })
        };
        match internals.phase {
            Phase::Closed { .. } => permit(internals.cycle),
            Phase::Open { opened_at } => {
                if now.duration_since(opened_at) >= self.config.open_state_wait {
                    // The first acquire after the wait is the first
                    // half-open trial, and it starts the cycle of that
                    // recovery attempt.
                    internals.cycle += 1;
                    internals.phase = Phase::HalfOpen {
                        permitted: 1,
                        successes: 0,
                    };
                    permit(internals.cycle)
                } else {
                    Acquired::Rejected
                }
            }
            Phase::HalfOpen {
                permitted,
                successes,
            } => {
                if permitted < self.config.maximum_half_open_calls {
                    internals.phase = Phase::HalfOpen {
                        permitted: permitted + 1,
                        successes,
                    };
                    permit(internals.cycle)
                } else {
                    Acquired::Rejected
                }
            }
        }
    }

    /// Record one completed permitted call. A duration at or above the
    /// slow threshold counts against the slow-call rate even when the
    /// call succeeded. The outcome lands in the breaker's current
    /// cycle; callers that hold a permit record through the permit, so
    /// an outcome from a cycle the breaker has left is ignored.
    pub fn record(&self, success: bool, duration: Duration) {
        self.record_outcome(success, duration, None);
    }

    /// Record one completed call's outcome, in the cycle the call's
    /// permit named when it held one. An outcome from a cycle the
    /// breaker has already left lands nowhere.
    fn record_outcome(&self, success: bool, duration: Duration, cycle: Option<u64>) {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("the breaker lock is not poisoned");
        let internals = &mut *guard;
        if cycle.is_some_and(|cycle| cycle != internals.cycle) {
            // The call belonged to a cycle the breaker has already
            // left; its outcome can neither help nor hurt the current
            // one.
            return;
        }
        match internals.phase {
            Phase::Closed { ref mut window } => {
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
                        // Opening starts a new cycle.
                        internals.cycle += 1;
                        internals.phase = Phase::Open { opened_at: now };
                    }
                }
            }
            // A record for a permit issued before the breaker opened.
            Phase::Open { .. } => {}
            Phase::HalfOpen {
                ref mut successes, ..
            } => {
                if success {
                    *successes += 1;
                    if *successes >= self.config.maximum_half_open_calls {
                        // Closing starts a new cycle with a fresh
                        // window.
                        internals.cycle += 1;
                        internals.phase = Phase::Closed {
                            window: VecDeque::new(),
                        };
                    }
                } else {
                    // One failing trial is enough to reopen, with a
                    // fresh wait and a fresh cycle.
                    internals.cycle += 1;
                    internals.phase = Phase::Open { opened_at: now };
                }
            }
        }
    }

    /// The phase the breaker is in, after any transition its own wait
    /// already allows. This observes without admitting anything.
    pub fn state(&self) -> BreakerState {
        let now = Instant::now();
        let guard = self.inner.lock().expect("the breaker lock is not poisoned");
        let internals = &*guard;
        match internals.phase {
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
        // The permitted call is held outstanding: admission alone adds
        // nothing to the window.
        let outstanding = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("a closed breaker permits the call"),
        };
        // Two failures recorded, but the breaker judges only from three
        // recorded calls.
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Closed);
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        drop(outstanding);
    }

    #[test]
    fn the_failure_rate_opens_the_breaker_at_the_threshold() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
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
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the breaker stays closed below the rate"),
        };
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
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
        tokio::time::sleep(Duration::from_millis(40)).await;
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the trial is permitted after the wait"),
        }
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
    }

    #[tokio::test]
    async fn a_failing_trial_reopens_the_breaker_with_a_fresh_wait() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(false, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the trial is permitted after the wait"),
        }
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            matches!(breaker.acquire(), Acquired::Permitted(_)),
            "a fresh trial is permitted after the fresh wait"
        );
    }

    #[tokio::test]
    async fn successful_trials_close_the_breaker_with_a_fresh_window() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the trial is permitted after the wait"),
        }
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the second trial is permitted"),
        }
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
        // The first trial is held outstanding and unrecorded.
        let trial = breaker.acquire();
        assert!(matches!(trial, Acquired::Permitted(_)));
        // One trial is outstanding and unrecorded; a second is refused.
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
    }

    #[test]
    fn an_ignored_call_does_not_count_in_the_closed_window() {
        let breaker = breaker();
        breaker.record(false, Duration::from_millis(1));
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.ignore(),
            Acquired::Rejected => panic!("the closed breaker admits the call"),
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[tokio::test]
    async fn an_ignored_trial_releases_its_slot_without_counting_as_success() {
        let mut config = config();
        config.maximum_half_open_calls = 1;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.ignore(),
            Acquired::Rejected => panic!("the recovery cycle admits its trial"),
        }
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the ignored trial released its slot"),
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[tokio::test]
    async fn an_ignored_stale_permit_does_not_release_a_current_trial() {
        let mut config = config();
        config.maximum_half_open_calls = 1;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        let stale = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("the closed breaker admits the call"),
        };
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        let trial = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("the recovery cycle admits its trial"),
        };
        stale.ignore();
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
        trial.record(true, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Closed);
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

    #[tokio::test]
    async fn an_abandoned_trial_does_not_strand_the_breaker() {
        let mut config = config();
        config.maximum_half_open_calls = 1;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(40)).await;
        // The trial's caller is dropped before the call completes, so no
        // record can ever arrive for it. The abandoned permit itself
        // must count the trial as failed, reopening the breaker with a
        // fresh wait instead of holding half-open shut.
        match breaker.acquire() {
            Acquired::Permitted(trial) => drop(trial),
            Acquired::Rejected => panic!("the breaker opened, so the trial is permitted"),
        }
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(matches!(breaker.acquire(), Acquired::Rejected));
        tokio::time::sleep(Duration::from_millis(40)).await;
        match breaker.acquire() {
            Acquired::Permitted(_) => {}
            Acquired::Rejected => {
                panic!("an abandoned trial must not strand the breaker in half-open")
            }
        };
    }

    #[tokio::test]
    async fn an_outcome_from_an_earlier_cycle_never_counts_in_a_later_one() {
        let mut config = config();
        config.maximum_half_open_calls = 1;
        let breaker = CircuitBreaker::new(config).expect("the breaker builds");
        // One call of the closed cycle is still outstanding when the
        // breaker opens and the recovery cycle begins.
        let outstanding = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("a closed breaker permits the call"),
        };
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let trial = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("the recovery cycle admits its trial"),
        };
        // The closed-cycle call completes successfully inside the
        // recovery cycle: its outcome must not be counted as the
        // trial's and close the breaker early.
        outstanding.record(true, Duration::from_millis(1));
        assert_eq!(
            breaker.state(),
            BreakerState::HalfOpen,
            "an outcome from the closed cycle does not close the recovery cycle"
        );
        trial.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[tokio::test]
    async fn a_permit_dropped_in_a_later_cycle_does_not_fail_that_cycle() {
        let breaker = breaker();
        let outstanding = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("a closed breaker permits the call"),
        };
        breaker.record(false, Duration::from_millis(1));
        breaker.record(false, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::Open);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let first_trial = match breaker.acquire() {
            Acquired::Permitted(permit) => permit,
            Acquired::Rejected => panic!("the recovery cycle admits its first trial"),
        };
        first_trial.record(true, Duration::from_millis(1));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        // The closed-cycle call is abandoned here, inside the recovery
        // cycle: its dropped permit must not fail the recovery cycle.
        drop(outstanding);
        assert_eq!(
            breaker.state(),
            BreakerState::HalfOpen,
            "an abandoned permit of the closed cycle does not reopen the breaker"
        );
        match breaker.acquire() {
            Acquired::Permitted(permit) => permit.record(true, Duration::from_millis(1)),
            Acquired::Rejected => panic!("the recovery cycle admits its second trial"),
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
    }
}
