// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use chrono::{DateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};

use crate::finding::{
    ConfigFinding, Findings, ELAPSED_ACTION, ELAPSED_MESSAGE, IDENTIFIER_ACTION, IDENTIFIER_MESSAGE,
};
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

/// A named clock, chosen by its `scope` member. The shared reader's union
/// helper decodes it so every error inside a variant keeps its position
/// (CFG-SCHEMA-8); the wire form is unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "scope"))]
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
        #[serde(default)]
        at_risk: Option<WorkingDaysBefore>,
        #[serde(default)]
        reminders: Vec<ClockReminder>,
        #[serde(default)]
        steps: Vec<ClockStep>,
    },
}
registry_platform_yaml::tagged_union!(ClockPolicy, tag = "scope");

/// The serialized form of [`ClockPolicy`], kept byte-identical to the stored
/// and published shape.
#[derive(Serialize)]
#[serde(
    tag = "scope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum ClockPolicyWire<'a> {
    Subject {
        id: &'a str,
        anchor: SubjectClockAnchor,
        complete_on: SubjectClockCompletion,
        after: &'a ElapsedDuration,
        pause_while: &'a [SubjectClockPause],
    },
    Activity {
        id: &'a str,
        anchor: ActivityClockAnchor,
        calendar: &'a str,
        after: WorkingDaysAfter,
        due_time: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        at_risk: Option<WorkingDaysBefore>,
        #[serde(skip_serializing_if = "is_empty_slice")]
        reminders: &'a [ClockReminder],
        #[serde(skip_serializing_if = "is_empty_slice")]
        steps: &'a [ClockStep],
    },
}

fn is_empty_slice<T>(items: &&[T]) -> bool {
    items.is_empty()
}

impl Serialize for ClockPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            Self::Subject {
                id,
                anchor,
                complete_on,
                after,
                pause_while,
            } => ClockPolicyWire::Subject {
                id,
                anchor: *anchor,
                complete_on: *complete_on,
                after,
                pause_while,
            },
            Self::Activity {
                id,
                anchor,
                calendar,
                after,
                due_time,
                at_risk,
                reminders,
                steps,
            } => ClockPolicyWire::Activity {
                id,
                anchor: *anchor,
                calendar,
                after: *after,
                due_time,
                at_risk: *at_risk,
                reminders,
                steps,
            },
        };
        wire.serialize(serializer)
    }
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

/// Every problem in the authored calendars and clocks, located by pointers
/// below `/calendars` and `/clocks` (CFG-DIAG-5). `queues` holds the declared
/// queue identifiers a clock step may reassign to.
#[must_use]
pub fn clock_policy_findings(
    calendars: &[CalendarPolicy],
    clocks: &[ClockPolicy],
    queues: &BTreeSet<String>,
) -> Vec<ConfigFinding> {
    let mut findings = Findings::default();
    if calendars.len() > MAXIMUM_CALENDARS {
        findings.push(
            "casework.calendar.too-many",
            "/calendars",
            format!("at most {MAXIMUM_CALENDARS} calendars may be declared"),
            "Remove calendars until no more than the bound remain.",
        );
    }
    findings.repeated(
        calendars
            .iter()
            .enumerate()
            .map(|(index, calendar)| (format!("/calendars/{index}/id"), calendar.id.as_str())),
        "casework.calendar.duplicate-id",
        "this calendar id is already declared",
        "Give every calendar a unique id.",
    );
    for (index, calendar) in calendars.iter().enumerate() {
        let at = format!("/calendars/{index}");
        if !valid_identifier(&calendar.id) {
            findings.push(
                "casework.calendar.invalid-id",
                format!("{at}/id"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if !valid_identifier(&calendar.holiday_set) {
            findings.push(
                "casework.calendar.invalid-holiday-set",
                format!("{at}/holidaySet"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if calendar.working_weekdays.is_empty() {
            findings.push(
                "casework.calendar.no-working-weekdays",
                format!("{at}/workingWeekdays"),
                "a calendar needs at least one working weekday",
                "List the working weekdays, such as [monday, tuesday, wednesday, thursday, friday].",
            );
        }
        findings.repeated(
            calendar
                .working_weekdays
                .iter()
                .enumerate()
                .map(|(day, weekday)| (format!("{at}/workingWeekdays/{day}"), *weekday)),
            "casework.calendar.duplicate-working-weekday",
            "this weekday is already listed",
            "List each working weekday once.",
        );
        if calendar.timezone.parse::<chrono_tz::Tz>().is_err() {
            findings.push(
                "casework.calendar.unknown-timezone",
                format!("{at}/timezone"),
                "the timezone is not an IANA time zone name",
                "Write an IANA time zone name, such as Asia/Bangkok.",
            );
        }
    }
    if clocks.len() > MAXIMUM_CLOCKS {
        findings.push(
            "casework.clock.too-many",
            "/clocks",
            format!("at most {MAXIMUM_CLOCKS} clocks may be declared"),
            "Remove clocks until no more than the bound remain.",
        );
    }
    findings.repeated(
        clocks
            .iter()
            .enumerate()
            .map(|(index, clock)| (format!("/clocks/{index}/id"), clock.id())),
        "casework.clock.duplicate-id",
        "this clock id is already declared",
        "Give every clock a unique id.",
    );
    let calendar_ids = calendars
        .iter()
        .map(|calendar| calendar.id.as_str())
        .collect::<BTreeSet<_>>();
    for (index, clock) in clocks.iter().enumerate() {
        let at = format!("/clocks/{index}");
        if !valid_identifier(clock.id()) {
            findings.push(
                "casework.clock.invalid-id",
                format!("{at}/id"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        match clock {
            ClockPolicy::Subject {
                after, pause_while, ..
            } => {
                if parse_elapsed_seconds(&after.elapsed).is_none() {
                    findings.push(
                        "casework.clock.invalid-elapsed",
                        format!("{at}/after/elapsed"),
                        ELAPSED_MESSAGE,
                        ELAPSED_ACTION,
                    );
                }
                if pause_while.as_slice() != [SubjectClockPause::AwaitingApplicant] {
                    findings.push(
                        "casework.clock.unsupported-pause",
                        format!("{at}/pauseWhile"),
                        "a subject clock pauses while awaitingApplicant and on nothing else",
                        "Write pauseWhile: [awaitingApplicant].",
                    );
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
            } => activity_clock_findings(
                &mut findings,
                &at,
                ActivityClockParts {
                    calendar_known: calendar_ids.contains(calendar.as_str()),
                    after: *after,
                    due_time,
                    at_risk: *at_risk,
                    reminders,
                    steps,
                },
                queues,
            ),
        }
    }
    findings.into_vec()
}

struct ActivityClockParts<'a> {
    calendar_known: bool,
    after: WorkingDaysAfter,
    due_time: &'a str,
    at_risk: Option<WorkingDaysBefore>,
    reminders: &'a [ClockReminder],
    steps: &'a [ClockStep],
}

fn activity_clock_findings(
    findings: &mut Findings,
    at: &str,
    clock: ActivityClockParts<'_>,
    queues: &BTreeSet<String>,
) {
    let offsets = 1..=crate::MAXIMUM_WORKING_DAY_OFFSET;
    let offset_message = format!(
        "expected a whole number of working days from 1 to {}",
        crate::MAXIMUM_WORKING_DAY_OFFSET
    );
    let offset_action = "Write a number of working days within the bound.";
    if !clock.calendar_known {
        findings.push(
            "casework.clock.unknown-calendar",
            format!("{at}/calendar"),
            "the calendar is not declared under calendars",
            "Declare the calendar under calendars, or name a declared one.",
        );
    }
    let mut offsets_valid = true;
    if !offsets.contains(&clock.after.working_days) {
        offsets_valid = false;
        findings.push(
            "casework.clock.working-days-out-of-range",
            format!("{at}/after/workingDays"),
            offset_message.as_str(),
            offset_action,
        );
    }
    if clock
        .at_risk
        .is_some_and(|value| !offsets.contains(&value.working_days_before))
    {
        offsets_valid = false;
        findings.push(
            "casework.clock.working-days-out-of-range",
            format!("{at}/atRisk/workingDaysBefore"),
            offset_message.as_str(),
            offset_action,
        );
    }
    if clock.reminders.len() > MAXIMUM_CLOCK_REMINDERS {
        findings.push(
            "casework.clock.too-many-reminders",
            format!("{at}/reminders"),
            format!("at most {MAXIMUM_CLOCK_REMINDERS} reminders may be declared on one clock"),
            "Remove reminders until no more than the bound remain.",
        );
    }
    findings.repeated(
        clock
            .reminders
            .iter()
            .enumerate()
            .map(|(index, reminder)| (format!("{at}/reminders/{index}/id"), reminder.id.as_str())),
        "casework.clock.duplicate-reminder-id",
        "this reminder id is already declared on the clock",
        "Give every reminder of the clock a unique id.",
    );
    for (index, reminder) in clock.reminders.iter().enumerate() {
        if !valid_identifier(&reminder.id) {
            findings.push(
                "casework.clock.invalid-reminder-id",
                format!("{at}/reminders/{index}/id"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if !offsets.contains(&reminder.working_days_before) {
            findings.push(
                "casework.clock.working-days-out-of-range",
                format!("{at}/reminders/{index}/workingDaysBefore"),
                offset_message.as_str(),
                offset_action,
            );
        }
    }
    if clock.steps.len() > MAXIMUM_CLOCK_STEPS {
        findings.push(
            "casework.clock.too-many-steps",
            format!("{at}/steps"),
            format!("at most {MAXIMUM_CLOCK_STEPS} steps may be declared on one clock"),
            "Remove steps until no more than the bound remain.",
        );
    }
    findings.repeated(
        clock
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| (format!("{at}/steps/{index}/id"), step.id.as_str())),
        "casework.clock.duplicate-step-id",
        "this step id is already declared on the clock",
        "Give every step of the clock a unique id.",
    );
    for (index, step) in clock.steps.iter().enumerate() {
        if !valid_identifier(&step.id) {
            findings.push(
                "casework.clock.invalid-step-id",
                format!("{at}/steps/{index}/id"),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if step.because.trim().is_empty() || step.because.len() > 256 {
            findings.push(
                "casework.clock.invalid-because",
                format!("{at}/steps/{index}/because"),
                "expected a reason of 1 to 256 bytes that is not only spaces",
                "Write a short reason for the step.",
            );
        }
        if !queues.contains(&step.action.reassign.queue) {
            findings.push(
                "casework.clock.unknown-queue",
                format!("{at}/steps/{index}/action/reassign/queue"),
                "the queue is not declared under queues",
                "Declare the queue under queues, or reassign to a declared queue.",
            );
        }
    }
    if offsets_valid && !valid_due_time(clock.after, clock.due_time, clock.at_risk) {
        findings.push(
            "casework.clock.invalid-due-time",
            format!("{at}/dueTime"),
            "expected a local time of day written HH:MM",
            "Write the due time as two-digit hours and minutes, such as 17:00.",
        );
    }
}

/// Exercise the shared working-day evaluator, so the check accepts exactly
/// the due times the runtime evaluates, without a second time grammar.
fn valid_due_time(
    after: WorkingDaysAfter,
    due_time: &str,
    at_risk: Option<WorkingDaysBefore>,
) -> bool {
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
    evaluate_working_day_deadline(&calendar, &rule, Utc::now()).is_ok()
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
            clock_policy_findings(&[office_calendar()], &[deadline()], &queues),
            []
        );
        let mut clock = deadline();
        let ClockPolicy::Activity { steps, .. } = &mut clock else {
            unreachable!()
        };
        steps[0].action.reassign.queue = "undeclared".to_owned();
        let findings = clock_policy_findings(&[office_calendar()], &[clock], &queues);
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code, finding.pointer.as_str()))
                .collect::<Vec<_>>(),
            [(
                "casework.clock.unknown-queue",
                "/clocks/0/steps/0/action/reassign/queue"
            )]
        );
    }

    /// One clock read through the shared reader, as a project reads it.
    fn read_clock(yaml: &str) -> Result<ClockPolicy, registry_platform_yaml::Report> {
        const CLOCK: registry_platform_yaml::FormatSpec<'static> =
            registry_platform_yaml::FormatSpec {
                kind: "ClockPolicy",
                envelope: registry_platform_yaml::EnvelopeRule::Exempt {
                    reason: "a test reads one clock",
                },
                removed_keys: &[],
            };
        registry_platform_yaml::decode_document(
            "clock.yaml",
            yaml.as_bytes(),
            &registry_platform_yaml::Expect::one(&CLOCK),
        )
        .map(|decoded| decoded.value)
    }

    #[test]
    fn clock_authoring_contract_is_closed_and_uses_the_documented_names() {
        let subject = read_clock(
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

        let refused = read_clock(
            r#"id: response-budget
scope: subject
anchor: firstSubmittedAt
completeOn: reviewCompleted
after: {elapsed: PT48H}
pauseWhile: [awaitingApplicant]
invented: true
"#,
        )
        .expect_err("an unknown member is refused");
        let diagnostics = refused.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "config.unknown-key");
        assert_eq!(diagnostics[0].path, "/invented");
    }
}
