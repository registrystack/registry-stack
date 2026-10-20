// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use chrono::{DateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};

use crate::finding::{ConfigFinding, Findings, IDENTIFIER_ACTION, IDENTIFIER_MESSAGE};
use crate::{
    evaluate_elapsed_budget, evaluate_working_day_deadline, CalendarEvaluationError, ElapsedBudget,
    HolidaySetRevision, ReviewTiming, WorkingCalendar, WorkingDayDeadlineRule,
    MAXIMUM_WORKING_DAY_OFFSET,
};

pub const MAXIMUM_CLOCKS: usize = 32;
pub const MAXIMUM_CALENDARS: usize = 16;
pub const MAXIMUM_CLOCK_REMINDERS: usize = 8;
pub const MAXIMUM_CLOCK_STEPS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub timezone: String,
    #[serde(deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<WorkingWeekday>")
    )]
    pub working_weekdays: Vec<WorkingWeekday>,
    pub holiday_set: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// A named clock, chosen by its `type` member (CFG-ID-7). The shared reader's
/// union helper decodes it so every error inside a variant keeps its position
/// (CFG-SCHEMA-8). The authored file, the stored record, the digest input, and
/// the HTTP description all carry this one spelling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ClockPolicy {
    Subject {
        #[serde(deserialize_with = "crate::typed::local_id")]
        id: String,
        anchor: SubjectClockAnchor,
        after: ElapsedDuration,
    },
    Stage {
        #[serde(deserialize_with = "crate::typed::local_id")]
        id: String,
        anchor: StageClockAnchor,
        calendar: String,
        after: WorkingDays,
        due_time: String,
        #[serde(default)]
        at_risk: Option<WorkingDaysBefore>,
        #[serde(default, deserialize_with = "crate::typed::id_keyed_or_list")]
        reminders: Vec<ClockReminder>,
        #[serde(default)]
        steps: Vec<ClockStep>,
    },
}
registry_platform_yaml::tagged_union!(ClockPolicy);

/// The serialized form of [`ClockPolicy`]: the shape the serializer emits.
#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ClockPolicyWire<'a> {
    Subject {
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        id: &'a str,
        anchor: SubjectClockAnchor,
        after: ElapsedDuration,
    },
    Stage {
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
        id: &'a str,
        anchor: StageClockAnchor,
        calendar: &'a str,
        after: WorkingDays,
        due_time: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "schema", schemars(default, with = "WorkingDaysBefore"))]
        at_risk: Option<WorkingDaysBefore>,
        #[serde(skip_serializing_if = "is_empty_slice")]
        #[cfg_attr(
            feature = "schema",
            schemars(
                default,
                schema_with = "crate::typed::id_keyed_or_list_schema::<ClockReminder>"
            )
        )]
        reminders: &'a [ClockReminder],
        #[serde(skip_serializing_if = "is_empty_slice")]
        #[cfg_attr(feature = "schema", schemars(default))]
        steps: &'a [ClockStep],
    },
}

fn is_empty_slice<T>(items: &&[T]) -> bool {
    items.is_empty()
}

impl Serialize for ClockPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            Self::Subject { id, anchor, after } => ClockPolicyWire::Subject {
                id,
                anchor: *anchor,
                after: *after,
            },
            Self::Stage {
                id,
                anchor,
                calendar,
                after,
                due_time,
                at_risk,
                reminders,
                steps,
            } => ClockPolicyWire::Stage {
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

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ClockPolicy {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ClockPolicy".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <ClockPolicyWire<'static> as schemars::JsonSchema>::json_schema(generator)
    }
}

impl ClockPolicy {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Subject { id, .. } | Self::Stage { id, .. } => id,
        }
    }

    pub(crate) fn authored_nested_ids(&self) -> Option<(&[ClockReminder], &[ClockStep])> {
        match self {
            Self::Subject { .. } => None,
            Self::Stage {
                reminders, steps, ..
            } => Some((reminders, steps)),
        }
    }
}

/// The instant a subject clock counts from: `anchor: {type: request-accepted}`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectClockAnchor {
    #[serde(rename = "type")]
    pub kind: SubjectClockAnchorType,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SubjectClockAnchorType {
    RequestAccepted,
}

/// The instant a stage clock counts from: `anchor: {type: stage-entered}`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageClockAnchor {
    #[serde(rename = "type")]
    pub kind: StageClockAnchorType,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum StageClockAnchorType {
    StageEntered,
}

/// The largest elapsed budget in each unit: ten years of 24-hour days.
pub const MAXIMUM_ELAPSED_DAYS: u32 = 3_650;
pub const MAXIMUM_ELAPSED_HOURS: u32 = MAXIMUM_ELAPSED_DAYS * 24;
pub const MAXIMUM_ELAPSED_MINUTES: u32 = MAXIMUM_ELAPSED_HOURS * 60;

/// An elapsed budget written in exactly one unit (CFG-QTY-1), such as
/// `after: {hours: 48}`. A day is 24 elapsed hours, not a calendar day.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", try_from = "ElapsedDurationUnits")]
pub enum ElapsedDuration {
    Minutes(u32),
    Hours(u32),
    Days(u32),
}

/// One object per unit, each with exactly that one member, the shape both
/// configuration and the served policy carry.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for ElapsedDuration {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ElapsedDuration".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let unit = |name: &str, maximum: u32| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    name: {"type": "integer", "format": "uint32", "minimum": 1, "maximum": maximum}
                },
                "required": [name],
                "additionalProperties": false,
            })
        };
        schemars::json_schema!({
            "description": "An elapsed budget in exactly one unit; a day is 24 elapsed hours.",
            "oneOf": [
                unit("minutes", MAXIMUM_ELAPSED_MINUTES),
                unit("hours", MAXIMUM_ELAPSED_HOURS),
                unit("days", MAXIMUM_ELAPSED_DAYS),
            ]
        })
    }
}

impl ElapsedDuration {
    /// The budget in seconds.
    #[must_use]
    pub fn seconds(&self) -> i64 {
        match *self {
            Self::Minutes(minutes) => i64::from(minutes) * 60,
            Self::Hours(hours) => i64::from(hours) * 60 * 60,
            Self::Days(days) => i64::from(days) * 24 * 60 * 60,
        }
    }
}

/// The units an elapsed budget may be written in, before exactly one is
/// chosen.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ElapsedDurationUnits {
    #[serde(default)]
    minutes: Option<u32>,
    #[serde(default)]
    hours: Option<u32>,
    #[serde(default)]
    days: Option<u32>,
}

impl TryFrom<ElapsedDurationUnits> for ElapsedDuration {
    type Error = String;

    fn try_from(units: ElapsedDurationUnits) -> Result<Self, Self::Error> {
        let (duration, value, maximum, unit) = match (units.minutes, units.hours, units.days) {
            (Some(minutes), None, None) => (
                Self::Minutes(minutes),
                minutes,
                MAXIMUM_ELAPSED_MINUTES,
                "minutes",
            ),
            (None, Some(hours), None) => {
                (Self::Hours(hours), hours, MAXIMUM_ELAPSED_HOURS, "hours")
            }
            (None, None, Some(days)) => (Self::Days(days), days, MAXIMUM_ELAPSED_DAYS, "days"),
            _ => {
                return Err(
                    "an elapsed budget names exactly one of minutes, hours or days; \
                     write one, such as after: {hours: 48}"
                        .to_owned(),
                )
            }
        };
        if (1..=maximum).contains(&value) {
            Ok(duration)
        } else {
            Err(format!(
                "expected a whole number of {unit} from 1 to {maximum}; write one within the bound"
            ))
        }
    }
}

/// A number of working days: `after: {workingDays: N}`, and the lead time
/// inside `before`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingDays {
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_WORKING_DAY_OFFSET>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_WORKING_DAY_OFFSET>")
    )]
    pub working_days: u32,
}

/// A lead time before a stage clock is due: `{before: {workingDays: N}}`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingDaysBefore {
    pub before: WorkingDays,
}

/// A named reminder, written `reminders: {ID: {before: {workingDays: N}}}`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockReminder {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub before: WorkingDays,
}

impl registry_platform_yaml::Identified for ClockReminder {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockStep {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::DisplayText")
    )]
    pub because: String,
    pub at: ClockStepInstant,
    pub action: ClockStepAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ClockStepInstant {
    Due,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockStepAction {
    pub reassign: ClockReassignment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockReassignment {
    pub queue: String,
}

/// One live, revisioned holiday set supplied separately from deployed policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetDocument {
    pub holiday_set: String,
    pub revision: u64,
    pub dates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageClockEvaluation {
    pub due_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_risk_at: Option<DateTime<Utc>>,
    pub reminders: Vec<ReminderOccurrence>,
    pub steps: Vec<StepOccurrence>,
    pub calendar_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderOccurrence {
    pub id: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepOccurrence {
    pub id: String,
    pub because: String,
    pub at: DateTime<Utc>,
    pub reassign_queue: String,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClockPolicyError {
    #[error("a clock or calendar identifier is invalid")]
    Identifier,
    #[error("a clock or calendar collection exceeds its bound")]
    Bounds,
    #[error("a clock references an unknown calendar or queue")]
    Reference,
    #[error("the clock is not the kind this evaluation reads")]
    Value,
    #[error("the supplied holiday-set revision does not match the clock calendar")]
    HolidaySet,
    #[error("the source timing facts cannot be evaluated")]
    Timing,
    /// The shared calendar refused the clock. `at` is the clock field the
    /// reason concerns, as a pointer relative to the clock, when there is one.
    #[error(
        "the clock calendar cannot be evaluated{}: {reason}",
        .at.as_deref().map(|at| format!(" at {at}")).unwrap_or_default()
    )]
    Calendar {
        at: Option<String>,
        reason: CalendarEvaluationError,
    },
}

/// Attach the Casework clock field a neutral calendar refusal concerns.
fn clock_calendar_error(
    reason: CalendarEvaluationError,
    reminder: Option<&str>,
) -> ClockPolicyError {
    let at = match (&reason, reminder) {
        (CalendarEvaluationError::InvalidDueTime { .. }, _) => Some("/dueTime".to_owned()),
        (CalendarEvaluationError::InvalidWorkingDayOffset { .. }, _) => {
            Some("/after/workingDays".to_owned())
        }
        (CalendarEvaluationError::InvalidWarningOffset { .. }, _) => {
            Some("/atRisk/before/workingDays".to_owned())
        }
        (CalendarEvaluationError::InvalidReminderOffset { .. }, Some(id)) => {
            Some(format!("/reminders/{id}/before/workingDays"))
        }
        _ => None,
    };
    ClockPolicyError::Calendar { at, reason }
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
    for calendar in calendars {
        let at = format!(
            "/calendars/{}",
            registry_platform_yaml::escape_pointer_segment(&calendar.id)
        );
        if !valid_identifier(&calendar.id) {
            findings.push(
                "casework.calendar.invalid-id",
                at.clone(),
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
    let calendar_ids = calendars
        .iter()
        .map(|calendar| calendar.id.as_str())
        .collect::<BTreeSet<_>>();
    for clock in clocks {
        let at = format!(
            "/clocks/{}",
            registry_platform_yaml::escape_pointer_segment(clock.id())
        );
        if !valid_identifier(clock.id()) {
            findings.push(
                "casework.clock.invalid-id",
                at.clone(),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        match clock {
            ClockPolicy::Subject { .. } => {}
            ClockPolicy::Stage {
                calendar,
                after,
                due_time,
                at_risk,
                reminders,
                steps,
                ..
            } => stage_clock_findings(
                &mut findings,
                &at,
                StageClockParts {
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

struct StageClockParts<'a> {
    calendar_known: bool,
    after: WorkingDays,
    due_time: &'a str,
    at_risk: Option<WorkingDaysBefore>,
    reminders: &'a [ClockReminder],
    steps: &'a [ClockStep],
}

fn stage_clock_findings(
    findings: &mut Findings,
    at: &str,
    clock: StageClockParts<'_>,
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
        .is_some_and(|value| !offsets.contains(&value.before.working_days))
    {
        offsets_valid = false;
        findings.push(
            "casework.clock.working-days-out-of-range",
            format!("{at}/atRisk/before/workingDays"),
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
    for reminder in clock.reminders {
        let reminder_at = format!(
            "{at}/reminders/{}",
            registry_platform_yaml::escape_pointer_segment(&reminder.id)
        );
        if !valid_identifier(&reminder.id) {
            findings.push(
                "casework.clock.invalid-reminder-id",
                reminder_at.clone(),
                IDENTIFIER_MESSAGE,
                IDENTIFIER_ACTION,
            );
        }
        if !offsets.contains(&reminder.before.working_days) {
            findings.push(
                "casework.clock.working-days-out-of-range",
                format!("{reminder_at}/before/workingDays"),
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
fn valid_due_time(after: WorkingDays, due_time: &str, at_risk: Option<WorkingDaysBefore>) -> bool {
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
        warning_working_days_before: at_risk.map(|value| value.before.working_days),
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
    let milliseconds = after
        .seconds()
        .checked_mul(1_000)
        .ok_or(ClockPolicyError::Value)?;
    evaluate_elapsed_budget(timing, milliseconds, now).map_err(|_| ClockPolicyError::Timing)
}

pub fn evaluate_stage_clock(
    clock: &ClockPolicy,
    calendar_policy: &CalendarPolicy,
    holiday_set: &HolidaySetDocument,
    anchor: DateTime<Utc>,
) -> Result<StageClockEvaluation, ClockPolicyError> {
    let ClockPolicy::Stage {
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
            warning_working_days_before: at_risk.map(|value| value.before.working_days),
            reminder_working_days_before: None,
        },
        anchor,
    )
    .map_err(|reason| clock_calendar_error(reason, None))?;
    let mut occurrences = Vec::with_capacity(reminders.len());
    for reminder in reminders {
        let evaluated = evaluate_working_day_deadline(
            &calendar,
            &WorkingDayDeadlineRule {
                after_working_days: after.working_days,
                due_time,
                warning_working_days_before: None,
                reminder_working_days_before: Some(reminder.before.working_days),
            },
            anchor,
        )
        .map_err(|reason| clock_calendar_error(reason, Some(&reminder.id)))?;
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
    Ok(StageClockEvaluation {
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
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_id_1_an_identifier_follows_the_local_identifier_grammar() {
        assert!(valid_identifier("first_review-2"));
        assert!(valid_identifier(&format!("a{}", "b".repeat(63))));
        for refused in ["", "First", "1st", "_first", "first.review", "first review"] {
            assert!(!valid_identifier(refused));
        }
        assert!(!valid_identifier(&format!("a{}", "b".repeat(64))));
    }

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
        ClockPolicy::Stage {
            id: "review-deadline".to_owned(),
            anchor: StageClockAnchor {
                kind: StageClockAnchorType::StageEntered,
            },
            calendar: "office".to_owned(),
            after: WorkingDays { working_days: 5 },
            due_time: "17:00".to_owned(),
            at_risk: Some(WorkingDaysBefore {
                before: WorkingDays { working_days: 1 },
            }),
            reminders: vec![ClockReminder {
                id: "due-soon".to_owned(),
                before: WorkingDays { working_days: 1 },
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
        let evaluation = evaluate_stage_clock(
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

    fn new_york_every_day() -> CalendarPolicy {
        CalendarPolicy {
            id: "office".to_owned(),
            timezone: "America/New_York".to_owned(),
            working_weekdays: vec![
                WorkingWeekday::Monday,
                WorkingWeekday::Tuesday,
                WorkingWeekday::Wednesday,
                WorkingWeekday::Thursday,
                WorkingWeekday::Friday,
                WorkingWeekday::Saturday,
                WorkingWeekday::Sunday,
            ],
            holiday_set: "office-holidays".to_owned(),
        }
    }

    fn no_holidays() -> HolidaySetDocument {
        HolidaySetDocument {
            holiday_set: "office-holidays".to_owned(),
            revision: 1,
            dates: Vec::new(),
        }
    }

    #[test]
    fn a_due_time_that_passes_check_evaluates_across_daylight_saving_gaps_and_folds() {
        let queues = BTreeSet::from(["overdue-review".to_owned()]);
        let mut clock = deadline();
        let ClockPolicy::Stage {
            after,
            due_time,
            reminders,
            ..
        } = &mut clock
        else {
            unreachable!()
        };
        after.working_days = 2;
        "02:30".clone_into(due_time);
        reminders[0].before.working_days = 1;
        assert_eq!(
            clock_policy_findings(&[new_york_every_day()], &[clock.clone()], &queues),
            []
        );

        // 02:30 does not exist on 2026-03-08 in New York; the warning and
        // reminder move to 03:00 EDT, the first instant after the gap.
        let spring = evaluate_stage_clock(
            &clock,
            &new_york_every_day(),
            &no_holidays(),
            instant("2026-03-07T12:00:00-05:00"),
        )
        .expect("a gap resolves forward");
        assert_eq!(spring.due_at, instant("2026-03-09T02:30:00-04:00"));
        assert_eq!(
            spring.at_risk_at,
            Some(instant("2026-03-08T03:00:00-04:00"))
        );
        assert_eq!(spring.reminders[0].at, instant("2026-03-08T03:00:00-04:00"));

        // 01:30 happens twice on 2026-11-01 in New York; the earlier wins.
        "01:30".clone_into(match &mut clock {
            ClockPolicy::Stage { due_time, .. } => due_time,
            ClockPolicy::Subject { .. } => unreachable!(),
        });
        let autumn = evaluate_stage_clock(
            &clock,
            &new_york_every_day(),
            &no_holidays(),
            instant("2026-10-31T12:00:00-04:00"),
        )
        .expect("a fold resolves to the earlier instant");
        assert_eq!(
            autumn.at_risk_at,
            Some(instant("2026-11-01T01:30:00-04:00"))
        );
    }

    #[test]
    fn a_value_refusal_names_the_clock_kind_and_not_the_calendar() {
        assert_eq!(
            ClockPolicyError::Value.to_string(),
            "the clock is not the kind this evaluation reads"
        );
    }

    #[test]
    fn a_calendar_refusal_keeps_its_reason_and_names_the_clock_field() {
        let mut clock = deadline();
        let ClockPolicy::Stage { reminders, .. } = &mut clock else {
            unreachable!()
        };
        reminders.push(ClockReminder {
            id: "overdue-soon".to_owned(),
            before: WorkingDays {
                working_days: MAXIMUM_WORKING_DAY_OFFSET + 1,
            },
        });
        let error = evaluate_stage_clock(
            &clock,
            &office_calendar(),
            &no_holidays(),
            instant("2026-09-04T15:00:00+07:00"),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ClockPolicyError::Calendar {
                at: Some("/reminders/overdue-soon/before/workingDays".to_owned()),
                reason: CalendarEvaluationError::InvalidReminderOffset {
                    value: MAXIMUM_WORKING_DAY_OFFSET + 1,
                    limit: MAXIMUM_WORKING_DAY_OFFSET,
                },
            }
        );
        assert_eq!(
            error.to_string(),
            "the clock calendar cannot be evaluated at /reminders/overdue-soon/before/workingDays: \
             the reminder offset 3651 is out of range; use 1 to 3650 working days before the due date"
        );

        let mut zone = office_calendar();
        zone.timezone = "Not/A_Zone".to_owned();
        assert_eq!(
            evaluate_stage_clock(
                &deadline(),
                &zone,
                &no_holidays(),
                instant("2026-09-04T15:00:00+07:00"),
            ),
            Err(ClockPolicyError::Calendar {
                at: None,
                reason: CalendarEvaluationError::InvalidTimezone,
            })
        );
    }

    #[test]
    fn subject_policy_calls_the_shared_request_wide_elapsed_evaluator() {
        let clock = ClockPolicy::Subject {
            id: "response-budget".to_owned(),
            anchor: SubjectClockAnchor {
                kind: SubjectClockAnchorType::RequestAccepted,
            },
            after: ElapsedDuration::Hours(48),
        };
        let result = evaluate_subject_clock(
            &clock,
            &ReviewTiming {
                request_accepted_at: instant("2026-09-10T09:00:00+07:00"),
                completed_at: None,
            },
            instant("2026-09-11T13:00:00+07:00"),
        )
        .unwrap();
        assert_eq!(result.remaining_milliseconds, 20 * 60 * 60 * 1_000);
        assert_eq!(result.due_at, instant("2026-09-12T09:00:00+07:00"));
    }

    #[test]
    fn authored_steps_can_only_name_a_local_reassignment_to_a_declared_queue() {
        let queues = BTreeSet::from(["overdue-review".to_owned()]);
        assert_eq!(
            clock_policy_findings(&[office_calendar()], &[deadline()], &queues),
            []
        );
        let mut clock = deadline();
        let ClockPolicy::Stage { steps, .. } = &mut clock else {
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
                "/clocks/review-deadline/steps/0/action/reassign/queue"
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
        let subject = read_clock(SUBJECT_CLOCK).expect("documented subject clock");
        assert!(matches!(subject, ClockPolicy::Subject { .. }));

        let stage = read_clock(
            r#"id: review-deadline
type: stage
anchor: {type: stage-entered}
calendar: office
after: {workingDays: 5}
dueTime: "17:00"
atRisk: {before: {workingDays: 1}}
reminders:
  due-soon: {before: {workingDays: 1}}
"#,
        )
        .expect("documented stage clock");
        let ClockPolicy::Stage { reminders, .. } = &stage else {
            panic!("stage clock")
        };
        assert_eq!(reminders[0].id, "due-soon");

        let refused = read_clock(&format!("{SUBJECT_CLOCK}invented: true\n"))
            .expect_err("an unknown member is refused");
        let diagnostics = refused.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "config.unknown-key");
        assert_eq!(diagnostics[0].path, "/invented");
    }

    const SUBJECT_CLOCK: &str = r#"id: response-budget
type: subject
anchor: {type: request-accepted}
after: {hours: 48}
"#;

    #[test]
    fn an_unknown_anchor_type_is_refused_and_the_accepted_one_named() {
        let authored = SUBJECT_CLOCK.replacen("request-accepted", "first-submitted", 1);
        let report = read_clock(&authored).expect_err("an unknown anchor type is refused");
        let diagnostics = report.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "config.unknown-variant");
        assert_eq!(diagnostics[0].path, "/anchor/type");
        assert!(
            diagnostics[0].message.contains("request-accepted")
                || diagnostics[0].suggested_action.contains("request-accepted")
        );
    }

    #[test]
    fn a_clock_is_written_in_the_spelling_it_is_read_in() {
        let subject = read_clock(SUBJECT_CLOCK).expect("subject clock");
        assert_eq!(
            serde_json::to_value(&subject).expect("clock serializes"),
            serde_json::json!({
                "id": "response-budget",
                "type": "subject",
                "anchor": {"type": "request-accepted"},
                "after": {"hours": 48},
            })
        );
    }
}
