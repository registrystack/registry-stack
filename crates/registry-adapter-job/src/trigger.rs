// SPDX-License-Identifier: Apache-2.0

//! The interval trigger and the rescan gate
//! (`products/adapter/CONCEPT.md` section 17.2 and the governed-ingestion
//! concept sections 3 and 5). A trigger decides only when a pass starts
//! and carries no data into it. The interval options port Camel's
//! scheduled polling consumer; the option names, defaults, and skip
//! semantics are read from `registry-adapter-core`'s [`JobTrigger`]
//! documentation, which cites the camel-4.23.0 sources, and this module
//! mirrors those semantics exactly: once an idle or error threshold is
//! met, the delay is multiplied by the backoff multiplier, the number of
//! passes skipped before the next attempt, until a pass is neither idle
//! nor an error.

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
/// separates now from the first pass when the job has never run one; and
/// once the consecutive idle or error streak meets its threshold, the
/// delay is multiplied by the backoff multiplier (the passes skipped
/// before the next attempt) until a pass is neither idle nor an error.
/// Greedy is not a schedule property: a greedy trigger starts again
/// immediately after a pass that read at least one item, so the loop
/// reads it from the finished pass's report, not from this function.
#[must_use]
pub fn next_due(job: &AdapterJob, state: &JobState, now: SystemTime) -> Option<Duration> {
    let trigger = interval_trigger(job)?;
    let Some(last_pass_at) = state.last_pass_at else {
        return Some(remaining(
            now,
            now + Duration::from_millis(trigger.initial_delay_milliseconds),
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

/// Whether either backoff threshold is met: the configured consecutive
/// idle passes have run, or the configured consecutive error passes
/// have. A threshold of zero is off, Camel's default.
fn in_backoff(trigger: &JobTrigger, state: &JobState) -> bool {
    (trigger.backoff_idle_threshold > 0 && state.idle_streak >= trigger.backoff_idle_threshold)
        || (trigger.backoff_error_threshold > 0
            && state.error_streak >= trigger.backoff_error_threshold)
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
        let due = next_due(&job(trigger(60_000, 5_000, 0, 0, 1)), &state, at(100));
        assert_eq!(
            due,
            Some(Duration::from_secs(5)),
            "the initial delay separates now from the first pass"
        );
        // The job default initial delay is zero: the first pass is due now.
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(100));
        assert_eq!(due, Some(Duration::ZERO));
    }

    #[test]
    fn the_delay_separates_two_passes_from_the_last_pass() {
        let mut state = JobState::default();
        state.last_pass_at = Some(at(200));
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(230));
        assert_eq!(due, Some(Duration::from_secs(30)));
        // Once the delay has passed the pass is due now, never negative.
        let due = next_due(&job(trigger(60_000, 0, 0, 0, 1)), &state, at(500));
        assert_eq!(due, Some(Duration::ZERO));
    }

    /// The skip semantics of the Camel port: once an idle or error
    /// threshold is met, the multiplier is the number of passes skipped
    /// before the next attempt, which this schedule realizes as a
    /// multiplied delay until the streak clears.
    #[test]
    fn a_met_backoff_threshold_multiplies_the_delay() {
        // The multiplier is the number of passes skipped, so the next
        // attempt lands multiplier delays after the last pass, not
        // multiplier times the time already gone.
        let mut state = JobState::default();
        state.last_pass_at = Some(at(200));
        state.idle_streak = 3;
        let due = next_due(&job(trigger(60_000, 0, 3, 0, 4)), &state, at(230));
        assert_eq!(
            due,
            Some(Duration::from_secs(240 - 30)),
            "the met idle threshold moves the due time to the last pass plus four delays"
        );
        // Below the threshold the base delay applies.
        state.idle_streak = 2;
        let due = next_due(&job(trigger(60_000, 0, 3, 0, 4)), &state, at(230));
        assert_eq!(due, Some(Duration::from_secs(30)));
        // An error streak meets its own threshold the same way.
        state.idle_streak = 0;
        state.error_streak = 3;
        let due = next_due(&job(trigger(60_000, 0, 3, 3, 4)), &state, at(230));
        assert_eq!(due, Some(Duration::from_secs(240 - 30)));
    }

    #[test]
    fn a_job_with_no_interval_trigger_has_no_schedule() {
        let mut hook = trigger(60_000, 0, 0, 0, 1);
        hook.kind = "hook".to_string();
        hook.path = Some("/hook".to_string());
        let state = JobState::default();
        assert_eq!(next_due(&job(hook), &state, at(100)), None);
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
