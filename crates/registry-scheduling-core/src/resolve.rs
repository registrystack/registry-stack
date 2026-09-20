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
    apply_exceptions_to_openings, expand_weekly_openings, local_interval, CalendarEvaluationError,
    CalendarInterval, HolidaySetRevision, WeeklyOpeningPattern,
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
///
/// The result is the canonical published schedule: sorted, disjoint, and with
/// intervals that overlap or meet joined into one, so authoring order is
/// never observable. That matters twice over, because both answers an
/// evaluator reads from this list are properties of a single interval: an
/// appointment is served when one interval covers it, and its start grid is
/// anchored to the start of the interval that covers it. Concatenating each
/// pattern's own expansion would let the order two openings happen to be
/// listed in decide which starts a caller may book, and would refuse an
/// appointment running across two openings the location publishes as
/// continuous.
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
        all.extend(expand_weekly_openings(&pattern, &[], &revision)?);
    }
    apply_exceptions_to_openings(merge_intervals(all), timezone, exceptions).map_err(Into::into)
}

/// Sort intervals and join every pair that overlaps or meets into one.
///
/// Meeting counts as continuous: a location whose morning pattern ends where
/// its afternoon pattern begins never closed between them, and an hour of that
/// day is one published hour however many patterns authored it.
fn merge_intervals(mut intervals: Vec<CalendarInterval>) -> Vec<CalendarInterval> {
    intervals.sort_by_key(|interval| (interval.start, interval.end));
    let mut merged: Vec<CalendarInterval> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        match merged.last_mut() {
            Some(last) if interval.start <= last.end => last.end = last.end.max(interval.end),
            _ => merged.push(interval),
        }
    }
    merged
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy_yaml;
    use registry_platform_calendar::{CalendarException, CalendarExceptionKind};

    fn opening(id: &str, start: &str, end: &str) -> String {
        format!(
            "  - id: {id}\n    location: north-counter\n    holidaySet: office-holidays\n    weekdays: [mon]\n    startTime: \"{start}\"\n    endTime: \"{end}\"\n    effectiveFrom: \"2026-10-05\"\n    effectiveUntil: \"2026-10-05\"\n    because: Counter opening hours reviewed by the office manager.\n"
        )
    }

    fn policy_with(openings: &str) -> SchedulingPolicy {
        let text = format!(
            r#"
apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: registry-updates
  version: 1
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: north-counter
    because: A 30-minute update at an interchangeable station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 30
      pool: update-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: []
openings:
{openings}holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#
        );
        parse_policy_yaml(&text).expect("the policy parses")
    }

    fn resolve(policy: &SchedulingPolicy) -> Vec<CalendarInterval> {
        location_open_intervals(policy, "north-counter", "Asia/Bangkok", &[])
            .expect("the openings expand")
    }

    fn instant(value: &str) -> DateTime<Utc> {
        value.parse().expect("an RFC 3339 instant")
    }

    /// The start grid an offering publishes is anchored to the opening that
    /// covers the request, so the order two openings happen to be authored in
    /// may never decide which starts a caller can book.
    #[test]
    fn overlapping_openings_resolve_the_same_whichever_order_they_are_authored_in() {
        let early_first = policy_with(&format!(
            "{}{}",
            opening("early", "09:00", "17:00"),
            opening("late", "09:10", "17:00")
        ));
        let late_first = policy_with(&format!(
            "{}{}",
            opening("late", "09:10", "17:00"),
            opening("early", "09:00", "17:00")
        ));
        assert_eq!(resolve(&early_first), resolve(&late_first));
        // One covering interval anchored at the earliest published start.
        assert_eq!(
            resolve(&early_first),
            vec![CalendarInterval {
                start: instant("2026-10-05T02:00:00Z"),
                end: instant("2026-10-05T10:00:00Z"),
            }]
        );
    }

    /// A location that opens straight from one authored pattern into the next
    /// never closed between them, so the two resolve into one continuous
    /// interval and an appointment may run across the join.
    #[test]
    fn abutting_openings_resolve_into_one_continuous_interval() {
        let policy = policy_with(&format!(
            "{}{}",
            opening("morning", "09:00", "12:30"),
            opening("afternoon", "12:30", "17:00")
        ));
        assert_eq!(
            resolve(&policy),
            vec![CalendarInterval {
                start: instant("2026-10-05T02:00:00Z"),
                end: instant("2026-10-05T10:00:00Z"),
            }]
        );
    }

    /// Resolution answers the coverage question once. An evaluator asking for
    /// the single interval that covers an appointment and a fixture asking
    /// whether the union covers it read the same published schedule, so a span
    /// the union covers always lies inside one resolved interval.
    #[test]
    fn a_covered_span_always_lies_inside_one_resolved_interval() {
        let policy = policy_with(&format!(
            "{}{}",
            opening("morning", "09:00", "12:30"),
            opening("afternoon", "12:30", "17:00")
        ));
        let open = resolve(&policy);
        // 12:15 to 12:45 local Bangkok runs across the join between the two
        // authored patterns.
        let start = instant("2026-10-05T05:15:00Z");
        let end = instant("2026-10-05T05:45:00Z");
        assert!(covers_span(&open, start, end));
        assert!(open
            .iter()
            .any(|interval| interval.start <= start && end <= interval.end));

        // A span reaching past the published hours is covered by neither.
        let past_close = instant("2026-10-05T10:15:00Z");
        assert!(!covers_span(&open, start, past_close));
        assert!(!open
            .iter()
            .any(|interval| interval.start <= start && past_close <= interval.end));
    }

    /// Two openings the day apart stay two intervals: merging joins what a
    /// location publishes as continuous, never what it publishes as separate.
    #[test]
    fn openings_that_do_not_meet_stay_separate_intervals() {
        let policy = policy_with(&format!(
            "{}{}",
            opening("morning", "09:00", "12:00"),
            opening("afternoon", "13:00", "17:00")
        ));
        let open = resolve(&policy);
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].end, instant("2026-10-05T05:00:00Z"));
        assert_eq!(open[1].start, instant("2026-10-05T06:00:00Z"));
    }

    /// Exceptions apply to the location's combined published hours. A
    /// reopening inside the morning pattern must not be rejected merely
    /// because the same location also has a disjoint afternoon pattern.
    #[test]
    fn reopening_inside_one_of_two_disjoint_openings_resolves_the_combined_union() {
        let policy = policy_with(&format!(
            "{}{}",
            opening("morning", "09:00", "12:00"),
            opening("afternoon", "13:00", "17:00")
        ));
        let exceptions = [
            CalendarException {
                id: "morning-closure",
                kind: CalendarExceptionKind::Closure,
                date: "2026-10-05",
                start_time: "09:30",
                end_time: "11:30",
                reopens: None,
                authority: None,
            },
            CalendarException {
                id: "morning-reopening",
                kind: CalendarExceptionKind::Opening,
                date: "2026-10-05",
                start_time: "10:00",
                end_time: "10:30",
                reopens: Some("morning-closure"),
                authority: Some("office-manager"),
            },
        ];

        assert_eq!(
            location_open_intervals(&policy, "north-counter", "Asia/Bangkok", &exceptions)
                .expect("the combined location schedule accepts the morning reopening"),
            vec![
                CalendarInterval {
                    start: instant("2026-10-05T02:00:00Z"),
                    end: instant("2026-10-05T02:30:00Z"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T03:00:00Z"),
                    end: instant("2026-10-05T03:30:00Z"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T04:30:00Z"),
                    end: instant("2026-10-05T05:00:00Z"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T06:00:00Z"),
                    end: instant("2026-10-05T10:00:00Z"),
                },
            ]
        );
    }
}
