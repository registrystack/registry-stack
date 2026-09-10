// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use chrono::{
    DateTime, Datelike, Days, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc,
    Weekday,
};
use chrono_tz::Tz;

/// Ten years is the maximum authored working-day offset evaluated locally.
pub const MAXIMUM_WORKING_DAY_OFFSET: u32 = 3_650;

/// One immutable revision of a named holiday set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HolidaySetRevision<'a> {
    pub holiday_set: &'a str,
    pub revision: u64,
    /// Strict ISO calendar dates in `YYYY-MM-DD` form.
    pub dates: &'a [&'a str],
}

/// Calendar content pinned when a clock occurrence is calculated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkingCalendar<'a> {
    pub id: &'a str,
    /// A named IANA timezone such as `Asia/Bangkok`.
    pub timezone: &'a str,
    pub working_weekdays: &'a [Weekday],
    pub holiday_revision: HolidaySetRevision<'a>,
}

/// Working-day offsets for one deadline, warning, and reminder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkingDayDeadlineRule<'a> {
    pub after_working_days: u32,
    /// Strict local wall time in `HH:MM` form.
    pub due_time: &'a str,
    pub warning_working_days_before: Option<u32>,
    pub reminder_working_days_before: Option<u32>,
}

/// Exact instants calculated from pinned calendar and holiday content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkingDayDeadline {
    pub due_at: DateTime<Utc>,
    pub warning_at: Option<DateTime<Utc>>,
    pub reminder_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
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
}

/// Evaluate a working-day deadline without reading mutable calendar or runtime state.
///
/// The offset excludes the anchor's local date. Warning and reminder offsets
/// exclude the due date and retain the configured local `dueTime`.
pub fn evaluate_working_day_deadline(
    calendar: &WorkingCalendar<'_>,
    rule: &WorkingDayDeadlineRule<'_>,
    anchor: DateTime<Utc>,
) -> Result<WorkingDayDeadline, CalendarEvaluationError> {
    if calendar.id.trim().is_empty() {
        return Err(CalendarEvaluationError::EmptyCalendarId);
    }
    if calendar.holiday_revision.holiday_set.trim().is_empty() {
        return Err(CalendarEvaluationError::EmptyHolidaySetId);
    }
    if calendar.holiday_revision.revision == 0 {
        return Err(CalendarEvaluationError::InvalidHolidayRevision);
    }

    let working_weekdays = weekday_flags(calendar.working_weekdays);
    if !working_weekdays.iter().any(|working| *working) {
        return Err(CalendarEvaluationError::NoWorkingWeekdays);
    }
    if !(1..=MAXIMUM_WORKING_DAY_OFFSET).contains(&rule.after_working_days) {
        return Err(CalendarEvaluationError::InvalidWorkingDayOffset);
    }
    if rule
        .warning_working_days_before
        .is_some_and(|days| !(1..=MAXIMUM_WORKING_DAY_OFFSET).contains(&days))
    {
        return Err(CalendarEvaluationError::InvalidWarningOffset);
    }
    if rule
        .reminder_working_days_before
        .is_some_and(|days| !(1..=MAXIMUM_WORKING_DAY_OFFSET).contains(&days))
    {
        return Err(CalendarEvaluationError::InvalidReminderOffset);
    }

    let timezone = calendar
        .timezone
        .parse::<Tz>()
        .map_err(|_| CalendarEvaluationError::InvalidTimezone)?;
    let due_time = parse_due_time(rule.due_time)?;
    let holidays = parse_holidays(calendar.holiday_revision.dates)?;
    let anchor_date = anchor.with_timezone(&timezone).date_naive();
    let due_date = shift_working_date(
        anchor_date,
        rule.after_working_days,
        Direction::Forward,
        &working_weekdays,
        &holidays,
    )?;
    let due_at = local_instant(due_date, due_time, timezone)?;
    let warning_at = rule
        .warning_working_days_before
        .map(|days| {
            shift_working_date(
                due_date,
                days,
                Direction::Backward,
                &working_weekdays,
                &holidays,
            )
            .and_then(|date| local_instant(date, due_time, timezone))
        })
        .transpose()?;
    let reminder_at = rule
        .reminder_working_days_before
        .map(|days| {
            shift_working_date(
                due_date,
                days,
                Direction::Backward,
                &working_weekdays,
                &holidays,
            )
            .and_then(|date| local_instant(date, due_time, timezone))
        })
        .transpose()?;

    Ok(WorkingDayDeadline {
        due_at,
        warning_at,
        reminder_at,
    })
}

fn weekday_flags(weekdays: &[Weekday]) -> [bool; 7] {
    let mut flags = [false; 7];
    for weekday in weekdays {
        flags[weekday.num_days_from_monday() as usize] = true;
    }
    flags
}

fn parse_holidays(dates: &[&str]) -> Result<BTreeSet<NaiveDate>, CalendarEvaluationError> {
    dates
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_date(value).ok_or(CalendarEvaluationError::InvalidHolidayDate { index })
        })
        .collect()
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

fn parse_due_time(value: &str) -> Result<NaiveTime, CalendarEvaluationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 2 && !byte.is_ascii_digit())
    {
        return Err(CalendarEvaluationError::InvalidDueTime);
    }
    NaiveTime::parse_from_str(value, "%H:%M").map_err(|_| CalendarEvaluationError::InvalidDueTime)
}

#[derive(Clone, Copy)]
enum Direction {
    Forward,
    Backward,
}

fn shift_working_date(
    start: NaiveDate,
    amount: u32,
    direction: Direction,
    working_weekdays: &[bool; 7],
    holidays: &BTreeSet<NaiveDate>,
) -> Result<NaiveDate, CalendarEvaluationError> {
    let working_per_week =
        u64::try_from(working_weekdays.iter().filter(|working| **working).count())
            .map_err(|_| CalendarEvaluationError::Overflow)?;
    let mut current = start;
    let mut remaining = u64::from(amount);

    while remaining > 0 {
        // Leave at least one working date for the bounded day-by-day tail.
        let full_weeks = remaining.saturating_sub(1) / working_per_week;
        if full_weeks > 0 {
            let calendar_days = full_weeks
                .checked_mul(7)
                .ok_or(CalendarEvaluationError::Overflow)?;
            let next = shift_date(current, calendar_days, direction)?;
            let skipped_holidays = holidays
                .iter()
                .filter(|holiday| {
                    let in_span = match direction {
                        Direction::Forward => **holiday > current && **holiday <= next,
                        Direction::Backward => **holiday >= next && **holiday < current,
                    };
                    in_span && is_listed_weekday(**holiday, working_weekdays)
                })
                .count();
            remaining = remaining
                .checked_sub(full_weeks * working_per_week)
                .and_then(|value| value.checked_add(skipped_holidays as u64))
                .ok_or(CalendarEvaluationError::Overflow)?;
            current = next;
            continue;
        }

        current = shift_date(current, 1, direction)?;
        if is_working_date(current, working_weekdays, holidays) {
            remaining -= 1;
        }
    }
    Ok(current)
}

fn shift_date(
    date: NaiveDate,
    days: u64,
    direction: Direction,
) -> Result<NaiveDate, CalendarEvaluationError> {
    match direction {
        Direction::Forward => date.checked_add_days(Days::new(days)),
        Direction::Backward => date.checked_sub_days(Days::new(days)),
    }
    .ok_or(CalendarEvaluationError::Overflow)
}

fn is_listed_weekday(date: NaiveDate, working_weekdays: &[bool; 7]) -> bool {
    working_weekdays[date.weekday().num_days_from_monday() as usize]
}

fn is_working_date(
    date: NaiveDate,
    working_weekdays: &[bool; 7],
    holidays: &BTreeSet<NaiveDate>,
) -> bool {
    is_listed_weekday(date, working_weekdays) && !holidays.contains(&date)
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

#[cfg(test)]
mod tests {
    use super::*;

    const WEEKDAYS: &[Weekday] = &[
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
        Weekday::Fri,
    ];
    const ALL_WEEKDAYS: &[Weekday] = &[
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
        Weekday::Fri,
        Weekday::Sat,
        Weekday::Sun,
    ];

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn calendar<'a>(timezone: &'a str, dates: &'a [&'a str]) -> WorkingCalendar<'a> {
        WorkingCalendar {
            id: "office",
            timezone,
            working_weekdays: WEEKDAYS,
            holiday_revision: HolidaySetRevision {
                holiday_set: "office-holidays",
                revision: 7,
                dates,
            },
        }
    }

    fn rule() -> WorkingDayDeadlineRule<'static> {
        WorkingDayDeadlineRule {
            after_working_days: 5,
            due_time: "17:00",
            warning_working_days_before: Some(1),
            reminder_working_days_before: Some(1),
        }
    }

    #[test]
    fn uc5_fixture_excludes_anchor_and_uses_pinned_holiday_revision() {
        let result = evaluate_working_day_deadline(
            &calendar("Asia/Bangkok", &["2026-09-07"]),
            &rule(),
            instant("2026-09-04T15:00:00+07:00"),
        )
        .unwrap();

        assert_eq!(result.due_at, instant("2026-09-14T17:00:00+07:00"));
        assert_eq!(
            result.warning_at,
            Some(instant("2026-09-11T17:00:00+07:00"))
        );
        assert_eq!(result.reminder_at, result.warning_at);

        let without_holiday = evaluate_working_day_deadline(
            &calendar("Asia/Bangkok", &[]),
            &rule(),
            instant("2026-09-04T15:00:00+07:00"),
        )
        .unwrap();
        assert_eq!(without_holiday.due_at, instant("2026-09-11T17:00:00+07:00"));
    }

    #[test]
    fn anchor_local_date_is_never_counted() {
        let result = evaluate_working_day_deadline(
            &calendar("Asia/Bangkok", &[]),
            &WorkingDayDeadlineRule {
                after_working_days: 1,
                due_time: "17:00",
                warning_working_days_before: None,
                reminder_working_days_before: None,
            },
            instant("2026-09-07T23:30:00+07:00"),
        )
        .unwrap();

        assert_eq!(result.due_at, instant("2026-09-08T17:00:00+07:00"));
    }

    #[test]
    fn invalid_calendar_date_time_and_offsets_have_distinct_diagnostics() {
        let anchor = instant("2026-09-04T15:00:00+07:00");
        assert_eq!(
            evaluate_working_day_deadline(&calendar("Not/A_Zone", &[]), &rule(), anchor),
            Err(CalendarEvaluationError::InvalidTimezone)
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &["2026-02-30"]),
                &rule(),
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidHolidayDate { index: 0 })
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &[]),
                &WorkingDayDeadlineRule {
                    due_time: "24:00",
                    ..rule()
                },
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidDueTime)
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &[]),
                &WorkingDayDeadlineRule {
                    after_working_days: 0,
                    ..rule()
                },
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidWorkingDayOffset)
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &[]),
                &WorkingDayDeadlineRule {
                    after_working_days: MAXIMUM_WORKING_DAY_OFFSET + 1,
                    ..rule()
                },
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidWorkingDayOffset)
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &[]),
                &WorkingDayDeadlineRule {
                    warning_working_days_before: Some(0),
                    ..rule()
                },
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidWarningOffset)
        );
        assert_eq!(
            evaluate_working_day_deadline(
                &calendar("Asia/Bangkok", &[]),
                &WorkingDayDeadlineRule {
                    reminder_working_days_before: Some(0),
                    ..rule()
                },
                anchor,
            ),
            Err(CalendarEvaluationError::InvalidReminderOffset)
        );
    }

    #[test]
    fn invalid_calendar_metadata_is_reported_before_arithmetic() {
        let anchor = instant("2026-09-04T15:00:00+07:00");
        let mut value = calendar("Asia/Bangkok", &[]);
        value.id = "";
        assert_eq!(
            evaluate_working_day_deadline(&value, &rule(), anchor),
            Err(CalendarEvaluationError::EmptyCalendarId)
        );
        value.id = "office";
        value.holiday_revision.holiday_set = "";
        assert_eq!(
            evaluate_working_day_deadline(&value, &rule(), anchor),
            Err(CalendarEvaluationError::EmptyHolidaySetId)
        );
        value.holiday_revision.holiday_set = "office-holidays";
        value.holiday_revision.revision = 0;
        assert_eq!(
            evaluate_working_day_deadline(&value, &rule(), anchor),
            Err(CalendarEvaluationError::InvalidHolidayRevision)
        );
        value.holiday_revision.revision = 7;
        value.working_weekdays = &[];
        assert_eq!(
            evaluate_working_day_deadline(&value, &rule(), anchor),
            Err(CalendarEvaluationError::NoWorkingWeekdays)
        );
    }

    #[test]
    fn daylight_saving_gaps_and_folds_are_explicit() {
        let mut value = calendar("America/New_York", &[]);
        value.working_weekdays = ALL_WEEKDAYS;
        let spring = WorkingDayDeadlineRule {
            after_working_days: 1,
            due_time: "02:30",
            warning_working_days_before: None,
            reminder_working_days_before: None,
        };
        assert_eq!(
            evaluate_working_day_deadline(&value, &spring, instant("2026-03-07T12:00:00-05:00"),),
            Err(CalendarEvaluationError::NonexistentLocalTime)
        );

        let autumn = WorkingDayDeadlineRule {
            due_time: "01:30",
            ..spring
        };
        assert_eq!(
            evaluate_working_day_deadline(&value, &autumn, instant("2026-10-31T12:00:00-04:00"),),
            Err(CalendarEvaluationError::AmbiguousLocalTime)
        );
    }

    #[test]
    fn date_overflow_is_an_explicit_diagnostic() {
        let value = WorkingCalendar {
            id: "maximum-date",
            timezone: "UTC",
            working_weekdays: ALL_WEEKDAYS,
            holiday_revision: HolidaySetRevision {
                holiday_set: "none",
                revision: 1,
                dates: &[],
            },
        };
        let anchor = NaiveDate::MAX.and_hms_opt(12, 0, 0).unwrap().and_utc();
        assert_eq!(
            evaluate_working_day_deadline(
                &value,
                &WorkingDayDeadlineRule {
                    after_working_days: 1,
                    due_time: "17:00",
                    warning_working_days_before: None,
                    reminder_working_days_before: None,
                },
                anchor,
            ),
            Err(CalendarEvaluationError::Overflow)
        );
    }
}
