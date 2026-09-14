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
    #[error("the reopening {id} is not inside the opening pattern's time on its date")]
    ReopenOutsidePattern { id: String },
    #[error("the interval date is not a valid YYYY-MM-DD date")]
    InvalidIntervalDate,
    #[error("interval times must be valid HH:MM local values with start before end")]
    InvalidIntervalTimes,
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

/// Convert one local wall-clock interval on a date into its half-open UTC
/// interval, in a named IANA timezone.
///
/// A start or end instant that falls in a daylight-saving gap or fold is an
/// explicit error, never a silent shift. This is the record-side companion of
/// the pattern expansion: a caller holding a dated exception as data converts
/// it the same way the expansion would.
pub fn local_interval(
    date: &str,
    start_time: &str,
    end_time: &str,
    timezone: &str,
) -> Result<CalendarInterval, CalendarEvaluationError> {
    let zone: Tz = timezone
        .parse()
        .map_err(|_| CalendarEvaluationError::InvalidTimezone)?;
    let date = parse_date(date).ok_or(CalendarEvaluationError::InvalidIntervalDate)?;
    let start = parse_hh_mm(start_time).ok_or(CalendarEvaluationError::InvalidIntervalTimes)?;
    let end = parse_hh_mm(end_time).ok_or(CalendarEvaluationError::InvalidIntervalTimes)?;
    if start >= end {
        return Err(CalendarEvaluationError::InvalidIntervalTimes);
    }
    day_interval(date, start, end, zone)
}

fn day_interval(
    date: NaiveDate,
    start: NaiveTime,
    end: NaiveTime,
    timezone: Tz,
) -> Result<CalendarInterval, CalendarEvaluationError> {
    Ok(CalendarInterval {
        start: local_instant(date, start, timezone)?,
        end: local_instant(date, end, timezone)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(value: &str) -> DateTime<Utc> {
        value
            .parse::<DateTime<Utc>>()
            .expect("a valid RFC 3339 instant")
    }

    #[test]
    fn a_local_interval_converts_to_its_half_open_utc_interval() {
        let interval =
            local_interval("2026-10-05", "09:00", "12:00", "Asia/Bangkok").expect("converts");
        assert_eq!(interval.start, instant("2026-10-05T02:00:00Z"));
        assert_eq!(interval.end, instant("2026-10-05T05:00:00Z"));
    }

    #[test]
    fn a_local_interval_spanning_a_transition_keeps_real_elapsed_time() {
        // 00:00 to 02:00 across the 2026-11-01 fall-back is three real hours.
        let interval =
            local_interval("2026-11-01", "00:00", "02:00", "America/New_York").expect("converts");
        assert_eq!(interval.start, instant("2026-11-01T04:00:00Z"));
        assert_eq!(interval.end, instant("2026-11-01T07:00:00Z"));
        assert_eq!((interval.end - interval.start).num_minutes(), 180);
    }

    #[test]
    fn local_interval_endpoints_inside_a_gap_or_fold_are_explicit_errors() {
        assert_eq!(
            local_interval("2026-03-08", "02:00", "02:30", "America/New_York"),
            Err(CalendarEvaluationError::NonexistentLocalTime)
        );
        assert_eq!(
            local_interval("2026-11-01", "01:30", "02:00", "America/New_York"),
            Err(CalendarEvaluationError::AmbiguousLocalTime)
        );
    }

    #[test]
    fn local_interval_reports_its_own_invalid_inputs() {
        assert_eq!(
            local_interval("2026-10-5", "09:00", "12:00", "Asia/Bangkok"),
            Err(CalendarEvaluationError::InvalidIntervalDate)
        );
        assert_eq!(
            local_interval("2026-10-05", "9:00", "12:00", "Asia/Bangkok"),
            Err(CalendarEvaluationError::InvalidIntervalTimes)
        );
        assert_eq!(
            local_interval("2026-10-05", "09:00", "12:00", "Not/A_Zone"),
            Err(CalendarEvaluationError::InvalidTimezone)
        );
        assert_eq!(
            local_interval("2026-10-05", "12:00", "09:00", "Asia/Bangkok"),
            Err(CalendarEvaluationError::InvalidIntervalTimes)
        );
    }
}
