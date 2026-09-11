// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use chrono::{DateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};

use crate::{
    evaluate_elapsed_budget, evaluate_working_day_deadline, parse_elapsed_seconds, ElapsedBudget,
    ElapsedDuration, HolidaySetRevision, ReviewTiming, WorkingCalendar, WorkingDayDeadlineRule,
};

pub const MAXIMUM_CLOCKS: usize = 32;
pub const MAXIMUM_CALENDARS: usize = 16;
pub const MAXIMUM_CLOCK_REMINDERS: usize = 8;
pub const MAXIMUM_CLOCK_STEPS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarPolicy {
    pub id: String,
    pub timezone: String,
    pub working_weekdays: Vec<WorkingWeekday>,
    pub holiday_set: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkingWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl From<WorkingWeekday> for Weekday {
    fn from(value: WorkingWeekday) -> Self {
        match value {
            WorkingWeekday::Monday => Self::Mon,
            WorkingWeekday::Tuesday => Self::Tue,
            WorkingWeekday::Wednesday => Self::Wed,
            WorkingWeekday::Thursday => Self::Thu,
            WorkingWeekday::Friday => Self::Fri,
            WorkingWeekday::Saturday => Self::Sat,
            WorkingWeekday::Sunday => Self::Sun,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "scope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ClockPolicy {
    Subject {
        id: String,
        anchor: SubjectClockAnchor,
        complete_on: SubjectClockCompletion,
        after: ElapsedDuration,
        pause_while: Vec<SubjectClockPause>,
    },
    Activity {
        id: String,
        anchor: ActivityClockAnchor,
        calendar: String,
        after: WorkingDaysAfter,
        due_time: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_risk: Option<WorkingDaysBefore>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reminders: Vec<ClockReminder>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        steps: Vec<ClockStep>,
    },
}

impl ClockPolicy {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Subject { id, .. } | Self::Activity { id, .. } => id,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubjectClockAnchor {
    FirstSubmittedAt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubjectClockCompletion {
    ReviewCompleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubjectClockPause {
    AwaitingApplicant,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivityClockAnchor {
    StageEnteredAt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingDaysAfter {
    pub working_days: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingDaysBefore {
    pub working_days_before: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockReminder {
    pub id: String,
    pub working_days_before: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockStep {
    pub id: String,
    pub because: String,
    pub at: ClockStepInstant,
    pub action: ClockStepAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClockStepInstant {
    Due,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockStepAction {
    pub reassign: ClockReassignment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockReassignment {
    pub queue: String,
}

/// One live, revisioned holiday set supplied separately from deployed policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetDocument {
    pub holiday_set: String,
    pub revision: u64,
    pub dates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityClockEvaluation {
    pub due_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_risk_at: Option<DateTime<Utc>>,
    pub reminders: Vec<ReminderOccurrence>,
    pub steps: Vec<StepOccurrence>,
    pub calendar_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderOccurrence {
    pub id: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepOccurrence {
    pub id: String,
    pub because: String,
    pub at: DateTime<Utc>,
    pub reassign_queue: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClockPolicyError {
    #[error("a clock or calendar identifier is invalid")]
    Identifier,
    #[error("a clock or calendar collection exceeds its bound")]
    Bounds,
    #[error("a clock references an unknown calendar or queue")]
    Reference,
    #[error("a clock duration or calendar is invalid")]
    Value,
    #[error("the supplied holiday-set revision does not match the clock calendar")]
    HolidaySet,
    #[error("the source timing facts cannot be evaluated")]
    Timing,
}

pub fn check_clock_policies(
    calendars: &[CalendarPolicy],
    clocks: &[ClockPolicy],
    queues: &BTreeSet<String>,
) -> Result<(), ClockPolicyError> {
    if calendars.len() > MAXIMUM_CALENDARS || clocks.len() > MAXIMUM_CLOCKS {
        return Err(ClockPolicyError::Bounds);
    }
    let calendar_ids = calendars
        .iter()
        .map(|calendar| &calendar.id)
        .collect::<BTreeSet<_>>();
    if calendar_ids.len() != calendars.len()
        || calendars.iter().any(|calendar| {
            !valid_identifier(&calendar.id)
                || !valid_identifier(&calendar.holiday_set)
                || calendar.working_weekdays.is_empty()
                || calendar.working_weekdays.len() > 7
                || calendar
                    .working_weekdays
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != calendar.working_weekdays.len()
                || calendar.timezone.parse::<chrono_tz::Tz>().is_err()
        })
    {
        return Err(ClockPolicyError::Value);
    }
    let mut clock_ids = BTreeSet::new();
    for clock in clocks {
        if !valid_identifier(clock.id()) || !clock_ids.insert(clock.id()) {
            return Err(ClockPolicyError::Identifier);
        }
        match clock {
            ClockPolicy::Subject {
                after, pause_while, ..
            } => {
                if parse_elapsed_seconds(&after.elapsed).is_none()
                    || pause_while.as_slice() != [SubjectClockPause::AwaitingApplicant]
                {
                    return Err(ClockPolicyError::Value);
                }
            }
            ClockPolicy::Activity {
                calendar,
                after,
                due_time,
                at_risk,
                reminders,
                steps,
                ..
            } => {
                if !calendar_ids.contains(calendar)
                    || !(1..=crate::MAXIMUM_WORKING_DAY_OFFSET).contains(&after.working_days)
                    || reminders.len() > MAXIMUM_CLOCK_REMINDERS
                    || steps.len() > MAXIMUM_CLOCK_STEPS
                {
                    return Err(ClockPolicyError::Bounds);
                }
                let reminder_ids = reminders
                    .iter()
                    .map(|item| &item.id)
                    .collect::<BTreeSet<_>>();
                let step_ids = steps.iter().map(|item| &item.id).collect::<BTreeSet<_>>();
                if reminder_ids.len() != reminders.len()
                    || step_ids.len() != steps.len()
                    || reminders.iter().any(|item| {
                        !valid_identifier(&item.id)
                            || !(1..=crate::MAXIMUM_WORKING_DAY_OFFSET)
                                .contains(&item.working_days_before)
                    })
                    || steps.iter().any(|item| {
                        !valid_identifier(&item.id)
                            || item.because.trim().is_empty()
                            || item.because.len() > 256
                            || !queues.contains(&item.action.reassign.queue)
                    })
                    || at_risk.is_some_and(|item| {
                        !(1..=crate::MAXIMUM_WORKING_DAY_OFFSET).contains(&item.working_days_before)
                    })
                {
                    return Err(ClockPolicyError::Value);
                }
                // Exercise the shared parser without inventing a second time grammar.
                let empty_holidays: &[&str] = &[];
                let weekdays = [Weekday::Mon];
                let calendar = WorkingCalendar {
                    id: "check",
                    timezone: "UTC",
                    working_weekdays: &weekdays,
                    holiday_revision: HolidaySetRevision {
                        holiday_set: "check",
                        revision: 1,
                        dates: empty_holidays,
                    },
                };
                let rule = WorkingDayDeadlineRule {
                    after_working_days: after.working_days,
                    due_time,
                    warning_working_days_before: at_risk.map(|value| value.working_days_before),
                    reminder_working_days_before: None,
                };
                evaluate_working_day_deadline(&calendar, &rule, Utc::now())
                    .map_err(|_| ClockPolicyError::Value)?;
            }
        }
    }
    Ok(())
}

pub fn evaluate_subject_clock(
    clock: &ClockPolicy,
    timing: &ReviewTiming,
    now: DateTime<Utc>,
) -> Result<ElapsedBudget, ClockPolicyError> {
    let ClockPolicy::Subject { after, .. } = clock else {
        return Err(ClockPolicyError::Value);
    };
    let seconds = parse_elapsed_seconds(&after.elapsed).ok_or(ClockPolicyError::Value)?;
    let milliseconds = seconds.checked_mul(1_000).ok_or(ClockPolicyError::Value)?;
    evaluate_elapsed_budget(timing, milliseconds, now).map_err(|_| ClockPolicyError::Timing)
}

pub fn evaluate_activity_clock(
    clock: &ClockPolicy,
    calendar_policy: &CalendarPolicy,
    holiday_set: &HolidaySetDocument,
    anchor: DateTime<Utc>,
) -> Result<ActivityClockEvaluation, ClockPolicyError> {
    let ClockPolicy::Activity {
        calendar,
        after,
        due_time,
        at_risk,
        reminders,
        steps,
        ..
    } = clock
    else {
        return Err(ClockPolicyError::Value);
    };
    if calendar != &calendar_policy.id || holiday_set.holiday_set != calendar_policy.holiday_set {
        return Err(ClockPolicyError::HolidaySet);
    }
    let weekdays = calendar_policy
        .working_weekdays
        .iter()
        .copied()
        .map(Weekday::from)
        .collect::<Vec<_>>();
    let dates = holiday_set
        .dates
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let calendar = WorkingCalendar {
        id: &calendar_policy.id,
        timezone: &calendar_policy.timezone,
        working_weekdays: &weekdays,
        holiday_revision: HolidaySetRevision {
            holiday_set: &holiday_set.holiday_set,
            revision: holiday_set.revision,
            dates: &dates,
        },
    };
    let base = evaluate_working_day_deadline(
        &calendar,
        &WorkingDayDeadlineRule {
            after_working_days: after.working_days,
            due_time,
            warning_working_days_before: at_risk.map(|value| value.working_days_before),
            reminder_working_days_before: None,
        },
        anchor,
    )
    .map_err(|_| ClockPolicyError::Value)?;
    let mut occurrences = Vec::with_capacity(reminders.len());
    for reminder in reminders {
        let evaluated = evaluate_working_day_deadline(
            &calendar,
            &WorkingDayDeadlineRule {
                after_working_days: after.working_days,
                due_time,
                warning_working_days_before: None,
                reminder_working_days_before: Some(reminder.working_days_before),
            },
            anchor,
        )
        .map_err(|_| ClockPolicyError::Value)?;
        occurrences.push(ReminderOccurrence {
            id: reminder.id.clone(),
            at: evaluated
                .reminder_at
                .expect("requested reminder is present"),
        });
    }
    let step_occurrences = steps
        .iter()
        .map(|step| StepOccurrence {
            id: step.id.clone(),
            because: step.because.clone(),
            at: base.due_at,
            reassign_queue: step.action.reassign.queue.clone(),
        })
        .collect();
    Ok(ActivityClockEvaluation {
        due_at: base.due_at,
        at_risk_at: base.warning_at,
        reminders: occurrences,
        steps: step_occurrences,
        calendar_revision: holiday_set.revision,
    })
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn office_calendar() -> CalendarPolicy {
        CalendarPolicy {
            id: "office".to_owned(),
            timezone: "Asia/Bangkok".to_owned(),
            working_weekdays: vec![
                WorkingWeekday::Monday,
                WorkingWeekday::Tuesday,
                WorkingWeekday::Wednesday,
                WorkingWeekday::Thursday,
                WorkingWeekday::Friday,
            ],
            holiday_set: "office-holidays".to_owned(),
        }
    }

    fn deadline() -> ClockPolicy {
        ClockPolicy::Activity {
            id: "review-deadline".to_owned(),
            anchor: ActivityClockAnchor::StageEnteredAt,
            calendar: "office".to_owned(),
            after: WorkingDaysAfter { working_days: 5 },
            due_time: "17:00".to_owned(),
            at_risk: Some(WorkingDaysBefore {
                working_days_before: 1,
            }),
            reminders: vec![ClockReminder {
                id: "due-soon".to_owned(),
                working_days_before: 1,
            }],
            steps: vec![ClockStep {
                id: "supervisor-at-deadline".to_owned(),
                because: "The review deadline passed while the review remained active.".to_owned(),
                at: ClockStepInstant::Due,
                action: ClockStepAction {
                    reassign: ClockReassignment {
                        queue: "overdue-review".to_owned(),
                    },
                },
            }],
        }
    }

    #[test]
    fn working_day_policy_uses_the_external_holiday_revision_for_every_occurrence() {
        let evaluation = evaluate_activity_clock(
            &deadline(),
            &office_calendar(),
            &HolidaySetDocument {
                holiday_set: "office-holidays".to_owned(),
                revision: 7,
                dates: vec!["2026-09-07".to_owned()],
            },
            instant("2026-09-04T15:00:00+07:00"),
        )
        .unwrap();
        assert_eq!(evaluation.due_at, instant("2026-09-14T17:00:00+07:00"));
        assert_eq!(
            evaluation.at_risk_at,
            Some(instant("2026-09-11T17:00:00+07:00"))
        );
        assert_eq!(
            evaluation.reminders[0].at,
            instant("2026-09-11T17:00:00+07:00")
        );
        assert_eq!(evaluation.steps[0].at, evaluation.due_at);
        assert_eq!(evaluation.steps[0].reassign_queue, "overdue-review");
        assert_eq!(evaluation.calendar_revision, 7);
    }

    #[test]
    fn subject_policy_calls_the_shared_request_wide_elapsed_evaluator() {
        let clock = ClockPolicy::Subject {
            id: "response-budget".to_owned(),
            anchor: SubjectClockAnchor::FirstSubmittedAt,
            complete_on: SubjectClockCompletion::ReviewCompleted,
            after: ElapsedDuration {
                elapsed: "PT48H".to_owned(),
            },
            pause_while: vec![SubjectClockPause::AwaitingApplicant],
        };
        let result = evaluate_subject_clock(
            &clock,
            &ReviewTiming {
                first_submitted_at: instant("2026-09-10T09:00:00+07:00"),
                paused_milliseconds: 24 * 60 * 60 * 1_000,
                pause_started_at: None,
                completed_at: None,
            },
            instant("2026-09-11T13:00:00+07:00"),
        )
        .unwrap();
        assert_eq!(result.remaining_milliseconds, 44 * 60 * 60 * 1_000);
        assert_eq!(result.due_at, Some(instant("2026-09-13T09:00:00+07:00")));
    }

    #[test]
    fn authored_steps_can_only_name_a_local_reassignment_to_a_declared_queue() {
        let queues = BTreeSet::from(["overdue-review".to_owned()]);
        assert_eq!(
            check_clock_policies(&[office_calendar()], &[deadline()], &queues),
            Ok(())
        );
        let mut clock = deadline();
        let ClockPolicy::Activity { steps, .. } = &mut clock else {
            unreachable!()
        };
        steps[0].action.reassign.queue = "undeclared".to_owned();
        assert_eq!(
            check_clock_policies(&[office_calendar()], &[clock], &queues),
            Err(ClockPolicyError::Value)
        );
    }

    #[test]
    fn clock_authoring_contract_is_closed_and_uses_the_documented_names() {
        let subject: ClockPolicy = serde_norway::from_str(
            r#"id: response-budget
scope: subject
anchor: firstSubmittedAt
completeOn: reviewCompleted
after: {elapsed: PT48H}
pauseWhile: [awaitingApplicant]
"#,
        )
        .expect("documented subject clock");
        assert!(matches!(subject, ClockPolicy::Subject { .. }));

        assert!(serde_norway::from_str::<ClockPolicy>(
            r#"id: response-budget
scope: subject
anchor: firstSubmittedAt
completeOn: reviewCompleted
after: {elapsed: PT48H}
pauseWhile: [awaitingApplicant]
invented: true
"#,
        )
        .is_err());
    }
}
