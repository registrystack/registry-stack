// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Casework-owned timing pinned to admission and terminal settlement.
/// A subject clock covers one request: source observations and assignment
/// changes cannot reset this budget, and a resubmission starts a new one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTiming {
    pub request_accepted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BudgetState {
    Running,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ElapsedBudget {
    pub state: BudgetState,
    pub elapsed_milliseconds: i64,
    pub remaining_milliseconds: i64,
    pub due_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the review timing or elapsed budget is invalid")]
pub struct InvalidTiming;

/// Shared elapsed-time calculation for runtime reads, explain and simulation.
/// Local observation, assignment and restart timestamps are not inputs.
pub fn evaluate_elapsed_budget(
    timing: &ReviewTiming,
    budget_milliseconds: i64,
    now: DateTime<Utc>,
) -> Result<ElapsedBudget, InvalidTiming> {
    let end = timing.completed_at.unwrap_or(now);
    if budget_milliseconds <= 0 || timing.request_accepted_at > end || end > now {
        return Err(InvalidTiming);
    }
    let elapsed = (end - timing.request_accepted_at).num_milliseconds();
    let state = if timing.completed_at.is_some() {
        BudgetState::Completed
    } else {
        BudgetState::Running
    };
    let due_at = timing
        .request_accepted_at
        .checked_add_signed(Duration::try_milliseconds(budget_milliseconds).ok_or(InvalidTiming)?)
        .ok_or(InvalidTiming)?;
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
    fn a_running_budget_counts_from_acceptance_and_keeps_its_due_time() {
        let timing = ReviewTiming {
            request_accepted_at: instant("2026-09-10T09:00:00+07:00"),
            completed_at: None,
        };
        let now = instant("2026-09-11T13:00:00+07:00");
        let running = evaluate_elapsed_budget(&timing, 48 * HOUR, now).unwrap();
        assert_eq!(running.state, BudgetState::Running);
        assert_eq!(running.remaining_milliseconds, 20 * HOUR);
        assert_eq!(running.due_at, instant("2026-09-12T09:00:00+07:00"));
        let later = evaluate_elapsed_budget(&timing, 48 * HOUR, now + Duration::hours(2)).unwrap();
        assert_eq!(later.due_at, running.due_at);
        assert_eq!(later.remaining_milliseconds, 18 * HOUR);
    }

    #[test]
    fn final_response_freezes_elapsed_time() {
        let timing = ReviewTiming {
            request_accepted_at: instant("2026-09-10T09:00:00Z"),
            completed_at: Some(instant("2026-09-11T13:00:00Z")),
        };
        let first =
            evaluate_elapsed_budget(&timing, 48 * HOUR, timing.completed_at.unwrap()).unwrap();
        let later =
            evaluate_elapsed_budget(&timing, 48 * HOUR, instant("2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(first, later);
        assert_eq!(first.state, BudgetState::Completed);
        assert_eq!(first.elapsed_milliseconds, 28 * HOUR);
    }

    #[test]
    fn inconsistent_review_timing_is_a_diagnostic_not_a_reset_budget() {
        let mut timing = ReviewTiming {
            request_accepted_at: instant("2026-09-10T09:00:00Z"),
            completed_at: None,
        };
        let now = instant("2026-09-10T13:00:00Z");
        assert_eq!(evaluate_elapsed_budget(&timing, 0, now), Err(InvalidTiming));
        timing.completed_at = Some(now + Duration::hours(1));
        assert_eq!(
            evaluate_elapsed_budget(&timing, 48 * HOUR, now),
            Err(InvalidTiming)
        );
        timing.completed_at = Some(timing.request_accepted_at - Duration::hours(1));
        assert_eq!(
            evaluate_elapsed_budget(&timing, 48 * HOUR, now),
            Err(InvalidTiming)
        );
    }
}
