// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Source-owned summary over the durable request, including correction drafts.
/// A later proposal must not replace the first submission or final completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTiming {
    pub first_submitted_at: DateTime<Utc>,
    /// Completed pause intervals. Final completion folds any open pause here.
    pub paused_milliseconds: i64,
    pub pause_started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetState {
    Running,
    Paused,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ElapsedBudget {
    pub state: BudgetState,
    pub elapsed_milliseconds: i64,
    pub remaining_milliseconds: i64,
    /// No due instant is predicted while the source says the clock is paused.
    pub due_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the source timing or elapsed budget is invalid")]
pub struct InvalidTiming;

/// Shared elapsed-time calculation for runtime reads, explain and simulation.
/// Local observation, assignment and restart timestamps are not inputs.
pub fn evaluate_elapsed_budget(
    timing: &ReviewTiming,
    budget_milliseconds: i64,
    now: DateTime<Utc>,
) -> Result<ElapsedBudget, InvalidTiming> {
    let end = timing.completed_at.unwrap_or(now);
    if budget_milliseconds <= 0
        || timing.paused_milliseconds < 0
        || timing.first_submitted_at > end
        || end > now
        || (timing.completed_at.is_some() && timing.pause_started_at.is_some())
    {
        return Err(InvalidTiming);
    }
    let current_pause = match timing.pause_started_at {
        Some(start) if start >= timing.first_submitted_at && start <= end => {
            (end - start).num_milliseconds()
        }
        Some(_) => return Err(InvalidTiming),
        None => 0,
    };
    let paused = timing
        .paused_milliseconds
        .checked_add(current_pause)
        .ok_or(InvalidTiming)?;
    let elapsed = (end - timing.first_submitted_at)
        .num_milliseconds()
        .checked_sub(paused)
        .filter(|elapsed| *elapsed >= 0)
        .ok_or(InvalidTiming)?;
    let state = if timing.completed_at.is_some() {
        BudgetState::Completed
    } else if timing.pause_started_at.is_some() {
        BudgetState::Paused
    } else {
        BudgetState::Running
    };
    let due_at = if state == BudgetState::Paused {
        None
    } else {
        let duration = budget_milliseconds
            .checked_add(paused)
            .ok_or(InvalidTiming)?;
        Some(
            timing
                .first_submitted_at
                .checked_add_signed(Duration::try_milliseconds(duration).ok_or(InvalidTiming)?)
                .ok_or(InvalidTiming)?,
        )
    };
    Ok(ElapsedBudget {
        state,
        elapsed_milliseconds: elapsed,
        remaining_milliseconds: budget_milliseconds.saturating_sub(elapsed).max(0),
        due_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3_600_000;

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn correction_pause_preserves_remaining_budget_and_resubmission_due_time() {
        let mut timing = ReviewTiming {
            first_submitted_at: instant("2026-09-10T09:00:00+07:00"),
            paused_milliseconds: 0,
            pause_started_at: Some(instant("2026-09-10T13:00:00+07:00")),
            completed_at: None,
        };
        let resumed_at = instant("2026-09-11T13:00:00+07:00");
        let paused = evaluate_elapsed_budget(&timing, 48 * HOUR, resumed_at).unwrap();
        assert_eq!(paused.state, BudgetState::Paused);
        assert_eq!(paused.remaining_milliseconds, 44 * HOUR);
        assert_eq!(paused.due_at, None);
        timing.paused_milliseconds = 24 * HOUR;
        timing.pause_started_at = None;
        let resumed = evaluate_elapsed_budget(&timing, 48 * HOUR, resumed_at).unwrap();
        assert_eq!(resumed.remaining_milliseconds, 44 * HOUR);
        assert_eq!(resumed.due_at, Some(instant("2026-09-13T09:00:00+07:00")));
        let restarted =
            evaluate_elapsed_budget(&timing, 48 * HOUR, resumed_at + Duration::hours(2)).unwrap();
        assert_eq!(restarted.due_at, resumed.due_at);
        assert_eq!(restarted.remaining_milliseconds, 42 * HOUR);
    }

    #[test]
    fn final_response_freezes_elapsed_time_including_cancellation_during_pause() {
        let timing = ReviewTiming {
            first_submitted_at: instant("2026-09-10T09:00:00Z"),
            paused_milliseconds: 24 * HOUR,
            pause_started_at: None,
            completed_at: Some(instant("2026-09-11T13:00:00Z")),
        };
        let first =
            evaluate_elapsed_budget(&timing, 48 * HOUR, timing.completed_at.unwrap()).unwrap();
        let later =
            evaluate_elapsed_budget(&timing, 48 * HOUR, instant("2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(first, later);
        assert_eq!(first.state, BudgetState::Completed);
        assert_eq!(first.elapsed_milliseconds, 4 * HOUR);
    }

    #[test]
    fn inconsistent_source_timing_is_a_diagnostic_not_a_reset_budget() {
        let mut timing = ReviewTiming {
            first_submitted_at: instant("2026-09-10T09:00:00Z"),
            paused_milliseconds: 5 * HOUR,
            pause_started_at: None,
            completed_at: None,
        };
        let now = instant("2026-09-10T13:00:00Z");
        assert_eq!(
            evaluate_elapsed_budget(&timing, 48 * HOUR, now),
            Err(InvalidTiming)
        );
        timing.paused_milliseconds = 0;
        timing.pause_started_at = Some(now + Duration::hours(1));
        assert_eq!(
            evaluate_elapsed_budget(&timing, 48 * HOUR, now),
            Err(InvalidTiming)
        );
        assert_eq!(evaluate_elapsed_budget(&timing, 0, now), Err(InvalidTiming));
        timing.pause_started_at = Some(now);
        timing.completed_at = Some(now);
        assert_eq!(
            evaluate_elapsed_budget(&timing, 48 * HOUR, now),
            Err(InvalidTiming)
        );
    }
}
