// SPDX-License-Identifier: Apache-2.0

//! The interval trigger and the rescan gate
//! (`products/adapter/CONCEPT.md` section 17.2). A trigger decides only when a pass starts
//! and carries no data into it. The interval options port Camel's
//! scheduled polling consumer; the option names, defaults, and skip
//! semantics are read from `registry-adapter-core`'s [`JobTrigger`]
//! documentation, which cites the camel-4.23.0 sources, and this module
//! mirrors those semantics: once an idle or error threshold is met, the
//! next pass waits the delay multiplied by the backoff multiplier (Camel
//! skips one fewer poll than the multiplier, so its next attempt lands
//! that many delays after the last), and the finished backoff starts the
//! threshold count again, as Camel's `doRun` resets its idle counter and
//! rebases its error counter.

use std::time::{Duration, SystemTime};

use registry_adapter_core::{AdapterJob, JobTrigger};

/// The schedule-relevant state of one job, read from the item store's
/// job state row. The streak counters are the pass outcomes the backoff
/// thresholds compare: `idle_streak` counts consecutive completed passes
/// that read no items, `error_streak` counts consecutive passes that
/// stopped before the page settled.
#[derive(Clone, Debug, Default)]
pub struct JobState {
    /// The opaque page cursor the last settled pass saved; absent at a
    /// finite end or before the first pass.
    pub position: Option<serde_json::Value>,
    /// The projection digest the last pass ran under.
    pub projection_digest: Option<String>,
    /// When the row lease expires; a held lease refuses a new pass.
    pub lease_expires: Option<SystemTime>,
    /// When the last pass ran, settled or stopped.
    pub last_pass_at: Option<SystemTime>,
    /// Why the last pass stopped, value-free; absent after a pass that
    /// settled its page.
    pub last_pass_stop: Option<String>,
    /// When the last rescan pass started from the first page.
    pub last_rescan_at: Option<SystemTime>,
    /// Whether a rescan traversal is between its first page and its
    /// end; the loop keeps its rescan mode until it finishes.
    pub rescan_active: bool,
    /// Consecutive completed passes that read no items.
    pub idle_streak: u32,
    /// Consecutive passes that stopped before the page settled.
    pub error_streak: u32,
}

/// How the job's source reports edits to items the scan has already
/// read, copied from the pinned pack's source route declaration: an
/// `ordered` source moves an edited item past the position, a `rescan`
/// source can leave it behind the position, and the declared delay
/// starts an ordinary pass from the first page to find it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Edits {
    /// Edits move past the position; the position finds them again.
    Ordered,
    /// Edits can stay behind the position; a rescan pass from the first
    /// page finds them, at most once per declared delay.
    Rescan {
        /// The seconds between a rescan source's passes from the first
        /// page, the pack's `rescanDelaySeconds`.
        delay_seconds: u64,
    },
}

impl Edits {
    /// The source route's edit declaration, as the rescan gate reads
    /// it: the declaration the compiled program carries, so the host
    /// never re-reads the pack file. The job checks refuse a malformed
    /// declaration at compile; this surfaces one a compiled program
    /// still carries.
    ///
    /// # Errors
    ///
    /// A declaration that is neither `ordered` nor `rescan`, or a
    /// `rescan` with no delay.
    pub fn of(declared: &registry_adapter_core::SourceRouteDecl) -> Result<Self, String> {
        match declared.edits.as_deref() {
            Some("ordered") => Ok(Self::Ordered),
            Some("rescan") => {
                let delay_seconds = declared.rescan_delay_seconds.ok_or_else(|| {
                    "the source route declares edits: rescan with no rescanDelaySeconds".to_string()
                })?;
                Ok(Self::Rescan {
                    delay_seconds: delay_seconds.get(),
                })
            }
            other => Err(format!(
                "the source route declares edits {other:?}, which is neither ordered nor rescan; the job checks refuse it at compile"
            )),
        }
    }
}

/// The job's first `interval` trigger, the trigger the loop schedule
/// runs. A hook trigger starts a pass early or late; it never
/// substitutes for the interval, so the schedule reads only interval
/// triggers.
#[must_use]
pub fn interval_trigger(job: &AdapterJob) -> Option<&JobTrigger> {
    job.triggers
        .iter()
        .find(|trigger| trigger.kind == "interval")
}

/// How long from `now` until the job's next interval pass is due, from
/// the trigger's options and the job state. `Some(Duration::ZERO)` means
/// due now. `None` means the job declares no interval trigger, so the
/// loop has no schedule to run.
///
/// The semantics mirror the Camel port recorded on
/// [`JobTrigger`]: the delay separates two passes; the initial delay
/// separates the process's start from the first pass of a job that has
/// never run one, so the wait the loop recomputes counts down to one
/// fixed deadline instead of restarting with every look; and each time
/// the consecutive idle or error streak meets its threshold again, the
/// next delay is multiplied by the backoff multiplier, after which the
/// threshold counts afresh at the base delay. Greedy is
/// not a schedule property: a greedy trigger starts again immediately
/// after a pass that read at least one item, so the loop reads it from
/// the finished pass's report, not from this function.
#[must_use]
pub fn next_due(
    job: &AdapterJob,
    state: &JobState,
    now: SystemTime,
    started: SystemTime,
) -> Option<Duration> {
    let trigger = interval_trigger(job)?;
    let Some(last_pass_at) = state.last_pass_at else {
        return Some(remaining(
            now,
            started + Duration::from_millis(trigger.initial_delay_milliseconds),
        ));
    };
    let base = Duration::from_millis(trigger.delay_milliseconds);
    let effective = if in_backoff(trigger, state) {
        base.saturating_mul(trigger.backoff_multiplier)
    } else {
        base
    };
    let due_at = last_pass_at + effective;
    Some(remaining(now, due_at))
}

/// How the loop's previous pass ended, as the next step reads it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LastPass {
    /// No pass has run in this process yet.
    NotYet,
    /// The pass settled its page.
    Settled {
        /// The items the page carried.
        items_read: u32,
        /// Whether the pass ran in rescan mode.
        rescan: bool,
    },
    /// The pass stopped before its page settled: a page fault, a
    /// destination stop, or the refusal limit.
    Stopped,
    /// Another pass held the job's lease, so nothing ran.
    LeaseHeld,
}

/// What the loop does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Start a pass now, in rescan mode or not.
    Run {
        /// Whether the pass runs in rescan mode.
        rescan: bool,
    },
    /// Wait this long, then decide again from a fresh state read.
    Wait(Duration),
}

/// The loop's next step from the job state, freshly read, and how the
/// previous pass ended. `None` means the job declares no interval
/// trigger.
///
/// Only a settled page bypasses the schedule: an active rescan carries
/// on from its saved cursor at once, and a greedy trigger restarts at
/// once after an ordinary pass that read at least one item. Every other
/// step waits for the interval schedule ([`next_due`]), which honours
/// the initial delay and the backoff. A stopped pass or a held lease
/// never retries at once, even when the schedule reads due (a stop the
/// store could not record leaves the last pass time stale): it waits at
/// least one delay, and a held lease waits at least until it expires.
#[must_use]
pub fn next_step(
    job: &AdapterJob,
    edits: &Edits,
    state: &JobState,
    last: LastPass,
    now: SystemTime,
    started: SystemTime,
) -> Option<Step> {
    let trigger = interval_trigger(job)?;
    if let LastPass::Settled { items_read, rescan } = last {
        if state.rescan_active {
            return Some(Step::Run { rescan: true });
        }
        if trigger.greedy && items_read > 0 && !rescan {
            return Some(Step::Run { rescan: false });
        }
    }
    let mut wait = next_due(job, state, now, started)?;
    match last {
        LastPass::Stopped => {
            if wait.is_zero() {
                wait = Duration::from_millis(trigger.delay_milliseconds);
            }
        }
        LastPass::LeaseHeld => {
            let until_expiry = state
                .lease_expires
                .map_or(Duration::ZERO, |expires| remaining(now, expires));
            wait = wait.max(until_expiry);
            if wait.is_zero() {
                wait = Duration::from_millis(trigger.delay_milliseconds);
            }
        }
        LastPass::NotYet | LastPass::Settled { .. } => {}
    }
    if !wait.is_zero() {
        return Some(Step::Wait(wait));
    }
    Some(Step::Run {
        rescan: state.rescan_active || rescan_due(edits, state, now),
    })
}

/// Whether the next pass backs off: the streak has just met its
/// threshold, counted afresh after each finished backoff. Camel resets
/// its idle counter (and rebases its error counter) when a backoff
/// finishes and the attempt runs, so that attempt counts as the first
/// of the next threshold run; the streak meets the threshold again at
/// every whole multiple of it. A threshold of zero is off, Camel's
/// default.
fn in_backoff(trigger: &JobTrigger, state: &JobState) -> bool {
    meets(trigger.backoff_idle_threshold, state.idle_streak)
        || meets(trigger.backoff_error_threshold, state.error_streak)
}

/// Whether `streak` sits on a threshold boundary: at least one whole
/// threshold, and an exact multiple of it.
fn meets(threshold: u32, streak: u32) -> bool {
    threshold > 0 && streak >= threshold && streak.is_multiple_of(threshold)
}

/// Whether the job's source declares a rescan pass due at `now`: only a
/// `rescan` source ever rescans, and only once the declared delay has
/// passed since the last rescan pass ran. A source that never rescanned
/// is due the first time the pass runner asks.
#[must_use]
pub fn rescan_due(edits: &Edits, state: &JobState, now: SystemTime) -> bool {
    let Edits::Rescan { delay_seconds } = edits else {
        return false;
    };
    match state.last_rescan_at {
        None => true,
        Some(last_rescan_at) => now >= last_rescan_at + Duration::from_secs(*delay_seconds),
    }
}

/// The time from `now` until `due_at`, zero once `due_at` has passed.
fn remaining(now: SystemTime, due_at: SystemTime) -> Duration {
    due_at.duration_since(now).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::ReadBounds;

    /// The job of these tests: one interval trigger with the options each
    /// case names, over the minimal profile the reader accepts.
    fn job(trigger: JobTrigger) -> AdapterJob {
        AdapterJob {
            api_version: registry_adapter_core::ADAPTER_JOB_API_VERSION.to_string(),
            kind: registry_adapter_core::ADAPTER_JOB_KIND.to_string(),
            job: registry_adapter_core::JobIdentity {
                id: "job-test".parse().expect("a local id"),
                version: "1".to_string(),
            },
            source: job_source(),
            projection: registry_adapter_core::ProjectionDecl::default(),
            triggers: vec![trigger],
            profile: profile(),
        }
    }

    fn job_source() -> registry_adapter_core::JobSource {
        serde_json::from_value(serde_json::json!({
            "pack": {
                "id": "pack-test",
                "version": "1",
                "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
            },
            "route": "route"
        }))
        .expect("a job source")
    }

    fn profile() -> registry_adapter_core::JobProfile {
        registry_adapter_core::JobProfile {
            page_deadline_milliseconds: 60_000,
            maximum_response_bytes: 65_536,
            maximum_page_items: 100,
            maximum_page_bytes: 65_536,
            maximum_upstream_calls: 8,
            read: ReadBounds {
                maximum_file_bytes: 1_048_576,
                maximum_row_bytes: 65_536,
                maximum_field_bytes: 65_536,
                maximum_rows_per_page: 100,
            },
        }
    }

    fn trigger(
        delay_milliseconds: u64,
        initial_delay_milliseconds: u64,
        backoff_idle_threshold: u32,
        backoff_error_threshold: u32,
        backoff_multiplier: u32,
    ) -> JobTrigger {
        JobTrigger {
            kind: "interval".to_string(),
            delay_milliseconds,
            initial_delay_milliseconds,
            greedy: false,
            backoff_idle_threshold,
            backoff_error_threshold,
            backoff_multiplier,
            path: None,
        }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// The default delay is the Camel port's one-minute job default; the
    /// core pins 60000 where Camel's own field default is 500
    /// milliseconds, and the schedule reads the option as declared.
    #[test]
    fn the_first_pass_is_due_after_the_initial_delay() {
        let state = JobState::default();
        let due = next_due(
            &job(trigger(60_000, 5_000, 0, 0, 1)),
            &state,
            at(100),
            at(100),
        );
        assert_eq!(
            due,
            Some(Duration::from_secs(5)),
            "the initial delay separates now from the first pass"
        );
        // The wait the loop recomputes counts down to the one startup
        // deadline; it never restarts with every look.
        let due = next_due(
            &job(trigger(60_000, 5_000, 0, 0, 1)),
            &state,
            at(103),
            at(100),
        );
        assert_eq!(due, Some(Duration::from_secs(2)));
        // The job default initial delay is zero: the first pass is due now.
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(100), at(100));
        assert_eq!(due, Some(Duration::ZERO));
    }

    #[test]
    fn the_delay_separates_two_passes_from_the_last_pass() {
        let state = JobState {
            last_pass_at: Some(at(200)),
            ..JobState::default()
        };
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(230), at(230));
        assert_eq!(due, Some(Duration::from_secs(30)));
        // Once the delay has passed the pass is due now, never negative.
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(500), at(500));
        assert_eq!(due, Some(Duration::ZERO));
    }

    /// The skip semantics of the Camel port: once an idle or error
    /// threshold is met, the next attempt lands multiplier delays after
    /// the last pass, which this schedule realizes as a multiplied
    /// delay.
    #[test]
    fn a_met_backoff_threshold_multiplies_the_delay() {
        // The multiplier is the number of passes skipped, so the next
        // attempt lands multiplier delays after the last pass, not
        // multiplier times the time already gone.
        let mut state = JobState {
            last_pass_at: Some(at(200)),
            idle_streak: 3,
            ..JobState::default()
        };
        let due = next_due(&job(trigger(60_000, 0, 3, 0, 4)), &state, at(230), at(230));
        assert_eq!(
            due,
            Some(Duration::from_secs(240 - 30)),
            "the met idle threshold moves the due time to the last pass plus four delays"
        );
        // Below the threshold the base delay applies.
        state.idle_streak = 2;
        let due = next_due(&job(trigger(60_000, 0, 3, 0, 4)), &state, at(230), at(230));
        assert_eq!(due, Some(Duration::from_secs(30)));
        // An error streak meets its own threshold the same way.
        state.idle_streak = 0;
        state.error_streak = 3;
        let due = next_due(&job(trigger(60_000, 0, 3, 3, 4)), &state, at(230), at(230));
        assert_eq!(due, Some(Duration::from_secs(240 - 30)));
    }

    /// Camel resets its idle counter, and rebases its error counter,
    /// once a backoff finishes, so a streak that carries on past the
    /// threshold waits the base delay again until it meets the threshold
    /// once more: one multiplied gap every threshold passes, never a
    /// schedule that stays multiplied for the rest of the streak.
    #[test]
    fn a_finished_backoff_counts_the_threshold_again() {
        let job = job(trigger(60_000, 0, 3, 3, 4));
        let mut state = JobState {
            last_pass_at: Some(at(200)),
            ..JobState::default()
        };
        let mut gaps = Vec::new();
        for streak in 1..=7 {
            state.idle_streak = streak;
            gaps.push(next_due(&job, &state, at(200), at(200)).expect("an interval trigger"));
        }
        let base = Duration::from_secs(60);
        let backoff = Duration::from_secs(240);
        assert_eq!(
            gaps,
            vec![base, base, backoff, base, base, backoff, base],
            "the multiplied gap recurs once per threshold idle passes"
        );
        state.idle_streak = 0;
        state.error_streak = 4;
        assert_eq!(next_due(&job, &state, at(200), at(200)), Some(base));
        state.error_streak = 6;
        assert_eq!(next_due(&job, &state, at(200), at(200)), Some(backoff));
    }

    fn rescan_source() -> Edits {
        Edits::Rescan {
            delay_seconds: 3_600,
        }
    }

    /// A rescan source that has never rescanned is due a rescan at once,
    /// but the loop's first pass still honours the initial delay.
    #[test]
    fn the_first_rescan_honours_the_initial_delay() {
        let job = job(trigger(60_000, 5_000, 0, 0, 1));
        let state = JobState::default();
        let step = next_step(
            &job,
            &rescan_source(),
            &state,
            LastPass::NotYet,
            at(100),
            at(100),
        );
        assert_eq!(step, Some(Step::Wait(Duration::from_secs(5))));
        let step = next_step(
            &job,
            &rescan_source(),
            &state,
            LastPass::NotYet,
            at(105),
            at(100),
        );
        assert_eq!(step, Some(Step::Run { rescan: true }));
    }

    /// Only a settled page lets the loop bypass the schedule: an active
    /// rescan continues at once after a settled page, but after a stopped
    /// one it waits for its due time like any other pass.
    #[test]
    fn an_active_rescan_continues_at_once_only_after_a_settled_page() {
        let job = job(trigger(60_000, 0, 0, 0, 1));
        let state = JobState {
            last_pass_at: Some(at(200)),
            last_rescan_at: Some(at(100)),
            rescan_active: true,
            ..JobState::default()
        };
        let settled = LastPass::Settled {
            items_read: 3,
            rescan: true,
        };
        assert_eq!(
            next_step(&job, &rescan_source(), &state, settled, at(200), at(0)),
            Some(Step::Run { rescan: true })
        );
        let stopped = JobState {
            error_streak: 1,
            ..state.clone()
        };
        assert_eq!(
            next_step(
                &job,
                &rescan_source(),
                &stopped,
                LastPass::Stopped,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(60))),
            "a stopped rescan page waits for its due time"
        );
        assert_eq!(
            next_step(
                &job,
                &rescan_source(),
                &stopped,
                LastPass::NotYet,
                at(260),
                at(0)
            ),
            Some(Step::Run { rescan: true }),
            "once due, the active rescan continues from its saved cursor"
        );
    }

    /// A stopped pass backs off by its error streak, and a stop the
    /// store failed to record never spins: the loop waits one delay.
    #[test]
    fn a_stopped_pass_waits_and_backs_off() {
        let job = job(trigger(60_000, 0, 0, 2, 3));
        let mut state = JobState {
            last_pass_at: Some(at(200)),
            error_streak: 2,
            ..JobState::default()
        };
        assert_eq!(
            next_step(
                &job,
                &Edits::Ordered,
                &state,
                LastPass::Stopped,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(180)))
        );
        // The store failed to record the stop, so the last pass time is
        // stale and the schedule reads due now; the loop still waits.
        state.last_pass_at = Some(at(0));
        state.error_streak = 0;
        assert_eq!(
            next_step(
                &job,
                &Edits::Ordered,
                &state,
                LastPass::Stopped,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(60)))
        );
    }

    /// A held lease waits until the lease expires, or one delay when the
    /// expiry is already behind the clock; it never retries at once.
    #[test]
    fn a_held_lease_waits_for_its_expiry() {
        let job = job(trigger(60_000, 0, 0, 0, 1));
        let mut state = JobState {
            last_pass_at: Some(at(0)),
            lease_expires: Some(at(290)),
            ..JobState::default()
        };
        assert_eq!(
            next_step(
                &job,
                &Edits::Ordered,
                &state,
                LastPass::LeaseHeld,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(90)))
        );
        state.lease_expires = Some(at(150));
        assert_eq!(
            next_step(
                &job,
                &Edits::Ordered,
                &state,
                LastPass::LeaseHeld,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(60)))
        );
    }

    /// A greedy trigger restarts at once after a settled pass that read
    /// items, and only then; a rescan page never counts as greedy work.
    #[test]
    fn greedy_restarts_only_after_a_settled_pass_that_read_items() {
        let mut greedy = trigger(60_000, 0, 0, 0, 1);
        greedy.greedy = true;
        let job = job(greedy);
        let state = JobState {
            last_pass_at: Some(at(200)),
            ..JobState::default()
        };
        let read = LastPass::Settled {
            items_read: 2,
            rescan: false,
        };
        assert_eq!(
            next_step(&job, &Edits::Ordered, &state, read, at(200), at(0)),
            Some(Step::Run { rescan: false })
        );
        let empty = LastPass::Settled {
            items_read: 0,
            rescan: false,
        };
        assert_eq!(
            next_step(&job, &Edits::Ordered, &state, empty, at(200), at(0)),
            Some(Step::Wait(Duration::from_secs(60)))
        );
        let finished_rescan = LastPass::Settled {
            items_read: 2,
            rescan: true,
        };
        assert_eq!(
            next_step(
                &job,
                &Edits::Ordered,
                &state,
                finished_rescan,
                at(200),
                at(0)
            ),
            Some(Step::Wait(Duration::from_secs(60)))
        );
    }

    #[test]
    fn a_job_with_no_interval_trigger_has_no_schedule() {
        let mut hook = trigger(60_000, 0, 0, 0, 1);
        hook.kind = "hook".to_string();
        hook.path = Some("/hook".to_string());
        let state = JobState::default();
        assert_eq!(next_due(&job(hook), &state, at(100), at(100)), None);
    }

    #[test]
    fn a_rescan_source_is_due_after_its_declared_delay() {
        let edits = Edits::Rescan {
            delay_seconds: 3_600,
        };
        let mut state = JobState::default();
        assert!(
            rescan_due(&edits, &state, at(100)),
            "a source that never rescanned is due"
        );
        state.last_rescan_at = Some(at(100));
        assert!(
            !rescan_due(&edits, &state, at(1000)),
            "inside the delay no rescan is due"
        );
        assert!(
            rescan_due(&edits, &state, at(3_700)),
            "the delay elapsed, so a rescan is due"
        );
        // An ordered source never rescans; the position finds its edits.
        assert!(!rescan_due(&Edits::Ordered, &state, at(3_700)));
    }
}
