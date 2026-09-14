// SPDX-License-Identifier: Apache-2.0

//! Timezone-correct calendar evaluation for Registry Stack.
//!
//! The crate deliberately contains no I/O and no product semantics: a
//! calendar id, a named IANA timezone, pinned holiday content, and bounded
//! arithmetic in, exact instants or intervals out. Daylight-saving gaps and
//! ambiguous local times are explicit errors, never silent shifts, so a
//! caller can never derive an invisible duplicate or shifted commitment.
//!
//! Two evaluators live here:
//!
//! - [`crate::working_day`]: working-day deadlines pinned to a calendar and
//!   holiday-set revision, as used by Registry Casework clocks.
//! - [`crate::weekly`]: expansion of a bounded weekly opening pattern into
//!   concrete half-open UTC intervals, with exception layering where a
//!   blocking closure wins over an ordinary opening and an exceptional
//!   reopening requires explicit authority.

mod weekly;
mod working_day;

pub use weekly::*;
pub use working_day::*;

use chrono::{DateTime, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;

/// A calendar evaluation refused the input instead of guessing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CalendarEvaluationError {
    #[error("the calendar id is empty")]
    EmptyCalendarId,
    #[error("the holiday-set id is empty")]
    EmptyHolidaySetId,
    #[error("the holiday-set revision must be positive")]
    InvalidHolidayRevision,
    #[error("the calendar has no working weekdays")]
    NoWorkingWeekdays,
    #[error("the calendar timezone is not a named IANA timezone")]
    InvalidTimezone,
    #[error("holiday date at index {index} is not a valid YYYY-MM-DD date")]
    InvalidHolidayDate { index: usize },
    #[error("dueTime is not a valid HH:MM local time")]
    InvalidDueTime,
    #[error("after.workingDays must be between 1 and 3650")]
    InvalidWorkingDayOffset,
    #[error("atRisk.workingDaysBefore must be between 1 and 3650")]
    InvalidWarningOffset,
    #[error("reminders[].workingDaysBefore must be between 1 and 3650")]
    InvalidReminderOffset,
    #[error("the calculated local due time does not exist in the calendar timezone")]
    NonexistentLocalTime,
    #[error("the calculated local due time is ambiguous in the calendar timezone")]
    AmbiguousLocalTime,
    #[error("working-day calendar arithmetic overflowed")]
    Overflow,
    #[error("the opening-pattern id is empty")]
    EmptyPatternId,
    #[error("the opening pattern has no weekdays")]
    NoPatternWeekdays,
    #[error("opening-pattern times must be valid HH:MM local values with start before end")]
    InvalidPatternTimes,
    #[error("opening-pattern date at index {index} is not a valid YYYY-MM-DD date")]
    InvalidPatternDate { index: usize },
    #[error("the opening-pattern effective range must have from on or before until")]
    InvalidEffectiveRange,
    #[error("the opening-pattern effective range spans more than 3650 days")]
    PatternSpanTooLarge,
    #[error("an exception id is empty")]
    EmptyExceptionId,
    #[error("exception times must be valid HH:MM local values with start before end")]
    InvalidExceptionTimes,
    #[error("exception date for {id} is not a valid YYYY-MM-DD date")]
    InvalidExceptionDate { id: String },
    #[error("the exception id {id} appears more than once")]
    DuplicateExceptionId { id: String },
    #[error("the blocking closure {id} carries reopening fields")]
    ClosureCarriesReopeningFields { id: String },
    #[error("the exceptional reopening {id} does not name an existing closure")]
    UnknownReopenedClosure { id: String },
    #[error("the exceptional reopening {id} has no explicit authority")]
    ReopenAuthorityMissing { id: String },
    #[error("the exceptional reopening {id} is not contained in the closure it reopens")]
    ReopenOutsideClosure { id: String },
    #[error("the exceptional reopening {id} overlaps a closure other than the one it reopens")]
    ReopenOverlapsUnrelatedClosure { id: String },
}

fn parse_date(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

fn parse_hh_mm(value: &str) -> Option<NaiveTime> {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 2 && !byte.is_ascii_digit())
    {
        return None;
    }
    NaiveTime::parse_from_str(value, "%H:%M").ok()
}

fn local_instant(
    date: NaiveDate,
    time: NaiveTime,
    timezone: Tz,
) -> Result<DateTime<Utc>, CalendarEvaluationError> {
    match timezone.from_local_datetime(&NaiveDateTime::new(date, time)) {
        LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
        LocalResult::None => Err(CalendarEvaluationError::NonexistentLocalTime),
        LocalResult::Ambiguous(_, _) => Err(CalendarEvaluationError::AmbiguousLocalTime),
    }
}
