// SPDX-License-Identifier: Apache-2.0

//! Policy-context resolution: the authored policy and the environment
//! records resolved into the concrete calendar intervals an evaluation, an
//! availability walk, or an offline replay runs against.
//!
//! This is the one place the product turns policy plus facts into openings
//! and closures, so the offline fixture replay and the live runtime expand
//! exactly the same intervals and can never disagree about what a location
//! published.

use chrono::{DateTime, Utc};
use registry_platform_calendar::{
    expand_weekly_openings, local_interval, CalendarEvaluationError, CalendarInterval,
    HolidaySetRevision, WeeklyOpeningPattern,
};

use crate::model::{ExceptionRecordKind, SchedulingFacts};
use crate::policy::SchedulingPolicy;

/// Resolution stopped because the policy and the facts do not fit together.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResolveError {
    #[error(
        "opening {opening} names holiday set {holiday_set}, which the policy does not declare"
    )]
    HolidaySetMissing {
        opening: String,
        holiday_set: String,
    },
    #[error("the calendar refused the configuration: {0}")]
    Calendar(#[from] CalendarEvaluationError),
}

/// Expand every authored opening at one location into concrete UTC intervals,
/// layering the location's dated exceptions and each opening's holiday set.
pub fn location_open_intervals(
    policy: &SchedulingPolicy,
    location_id: &str,
    timezone: &str,
    exceptions: &[registry_platform_calendar::CalendarException<'_>],
) -> Result<Vec<CalendarInterval>, ResolveError> {
    let mut all = Vec::new();
    for opening in policy.openings.iter().filter(|o| o.location == location_id) {
        // A holiday-set reference the policy does not declare is a policy
        // check finding; the calendar cannot expand against it, so resolution
        // stops with the opening that carries it instead of panicking.
        let Some(holiday_set) = policy.holiday_set(&opening.holiday_set) else {
            return Err(ResolveError::HolidaySetMissing {
                opening: opening.id.clone(),
                holiday_set: opening.holiday_set.clone(),
            });
        };
        let weekdays: Vec<chrono::Weekday> =
            opening.weekdays.iter().map(|day| day.to_chrono()).collect();
        let pattern = WeeklyOpeningPattern {
            id: &opening.id,
            timezone,
            weekdays: &weekdays,
            start_time: &opening.start_time,
            end_time: &opening.end_time,
            effective_from: &opening.effective_from,
            effective_until: &opening.effective_until,
        };
        let dates: Vec<&str> = holiday_set.dates.iter().map(String::as_str).collect();
        let revision = HolidaySetRevision {
            holiday_set: &holiday_set.id,
            revision: holiday_set.revision,
            dates: &dates,
        };
        all.extend(expand_weekly_openings(&pattern, exceptions, &revision)?);
    }
    Ok(all)
}

/// Whether the union of `intervals` covers the whole span `[start, end)`.
pub fn covers_span(
    intervals: &[CalendarInterval],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> bool {
    let mut overlapping: Vec<CalendarInterval> = intervals
        .iter()
        .filter(|interval| interval.start < end && start < interval.end)
        .copied()
        .collect();
    overlapping.sort_by_key(|interval| (interval.start, interval.end));

    let mut covered_until = start;
    for interval in overlapping {
        if interval.start > covered_until {
            return false;
        }
        covered_until = covered_until.max(interval.end);
        if covered_until >= end {
            return true;
        }
    }
    covered_until >= end
}

/// The dated closures recorded against one location, as concrete intervals.
pub fn location_closure_intervals(
    facts: &SchedulingFacts,
    location_id: &str,
    timezone: &str,
) -> Result<Vec<CalendarInterval>, ResolveError> {
    let mut closures = Vec::new();
    for exception in facts
        .exceptions
        .iter()
        .filter(|exception| exception.location == location_id)
    {
        if exception.kind == ExceptionRecordKind::Closure {
            closures.push(local_interval(
                &exception.date,
                &exception.start_time,
                &exception.end_time,
                timezone,
            )?);
        }
    }
    Ok(closures)
}
