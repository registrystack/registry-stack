// SPDX-License-Identifier: Apache-2.0

//! Expansion of a bounded weekly opening pattern into concrete intervals.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Days, NaiveDate, Utc, Weekday};
use chrono_tz::Tz;

use crate::{day_interval, parse_date, parse_hh_mm, CalendarEvaluationError, HolidaySetRevision};

/// Ten years is also the maximum authored opening-pattern span.
pub const MAXIMUM_PATTERN_SPAN_DAYS: u32 = 3_650;

/// A bounded weekly opening pattern evaluated in a named IANA timezone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeeklyOpeningPattern<'a> {
    pub id: &'a str,
    /// A named IANA timezone such as `Asia/Bangkok`.
    pub timezone: &'a str,
    pub weekdays: &'a [Weekday],
    /// Strict local wall time in `HH:MM` form.
    pub start_time: &'a str,
    /// Strict local wall time in `HH:MM` form, after `start_time` on the same
    /// local date. Patterns do not cross midnight.
    pub end_time: &'a str,
    /// Strict ISO calendar date in `YYYY-MM-DD` form, inclusive.
    pub effective_from: &'a str,
    /// Strict ISO calendar date in `YYYY-MM-DD` form, inclusive.
    pub effective_until: &'a str,
}

/// One dated exception over local wall-clock time in the pattern's timezone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalendarException<'a> {
    pub id: &'a str,
    pub kind: CalendarExceptionKind,
    /// Strict ISO calendar date in `YYYY-MM-DD` form.
    pub date: &'a str,
    /// Strict local wall time in `HH:MM` form.
    pub start_time: &'a str,
    /// Strict local wall time in `HH:MM` form, after `start_time` on the same
    /// local date.
    pub end_time: &'a str,
    /// The closure an exceptional reopening reopens. Required when `kind` is
    /// [`CalendarExceptionKind::Opening`], absent otherwise.
    pub reopens: Option<&'a str>,
    /// Explicit authority for an exceptional reopening. Required when `kind`
    /// is [`CalendarExceptionKind::Opening`], absent otherwise.
    pub authority: Option<&'a str>,
}

/// The layer an exception occupies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalendarExceptionKind {
    /// A blocking closure. It wins over an ordinary opening and over every
    /// pattern-generated interval it overlaps.
    Closure,
    /// An exceptional reopening. It requires explicit authority, must sit
    /// inside the one closure it names, and may not overlap any other
    /// closure, so it can never silently override unrelated closures.
    Opening,
}

/// A half-open UTC interval `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalendarInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Expand a bounded weekly opening pattern into sorted, merged half-open UTC
/// intervals without reading mutable calendar or runtime state.
///
/// Layering: a holiday date produces no interval; a blocking closure removes
/// opening time; an exceptional reopening adds time back only inside the
/// closure it names, only under explicit authority, and only within the
/// pattern's own hours on its date, so it can restore lost time but never
/// extend the published hours. A local start or end
/// instant that falls in a daylight-saving gap or fold is an explicit error,
/// never a silent shift; an interval that spans a transition (for example
/// `01:00` to `03:00` across a spring-forward jump) keeps its real elapsed
/// length, so no invisible duplicate or shifted commitment appears.
pub fn expand_weekly_openings(
    pattern: &WeeklyOpeningPattern<'_>,
    exceptions: &[CalendarException<'_>],
    holiday_revision: &HolidaySetRevision<'_>,
) -> Result<Vec<CalendarInterval>, CalendarEvaluationError> {
    if pattern.id.trim().is_empty() {
        return Err(CalendarEvaluationError::EmptyPatternId);
    }
    if pattern.weekdays.is_empty() {
        return Err(CalendarEvaluationError::NoPatternWeekdays);
    }
    let timezone: Tz = pattern
        .timezone
        .parse()
        .map_err(|_| CalendarEvaluationError::InvalidTimezone)?;
    let start_time =
        parse_hh_mm(pattern.start_time).ok_or(CalendarEvaluationError::InvalidPatternTimes)?;
    let end_time =
        parse_hh_mm(pattern.end_time).ok_or(CalendarEvaluationError::InvalidPatternTimes)?;
    if start_time >= end_time {
        return Err(CalendarEvaluationError::InvalidPatternTimes);
    }
    let effective_from = parse_date(pattern.effective_from)
        .ok_or(CalendarEvaluationError::InvalidPatternDate { index: 0 })?;
    let effective_until = parse_date(pattern.effective_until)
        .ok_or(CalendarEvaluationError::InvalidPatternDate { index: 1 })?;
    if effective_from > effective_until {
        return Err(CalendarEvaluationError::InvalidEffectiveRange);
    }
    if effective_until
        .signed_duration_since(effective_from)
        .num_days()
        > i64::from(MAXIMUM_PATTERN_SPAN_DAYS)
    {
        return Err(CalendarEvaluationError::PatternSpanTooLarge);
    }

    if holiday_revision.holiday_set.trim().is_empty() {
        return Err(CalendarEvaluationError::EmptyHolidaySetId);
    }
    if holiday_revision.revision == 0 {
        return Err(CalendarEvaluationError::InvalidHolidayRevision);
    }
    let holidays: BTreeSet<NaiveDate> = holiday_revision
        .dates
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_date(value).ok_or(CalendarEvaluationError::InvalidHolidayDate { index })
        })
        .collect::<Result<_, _>>()?;

    let weekdays: BTreeSet<u32> = pattern
        .weekdays
        .iter()
        .map(|weekday| weekday.num_days_from_monday())
        .collect();
    let mut openings = Vec::new();
    let mut date = effective_from;
    while date <= effective_until {
        if weekdays.contains(&date.weekday().num_days_from_monday()) && !holidays.contains(&date) {
            openings.push(day_interval(date, start_time, end_time, timezone)?);
        }
        date = date
            .checked_add_days(Days::new(1))
            .ok_or(CalendarEvaluationError::Overflow)?;
    }

    apply_exceptions_to_openings(openings, pattern.timezone, exceptions)
}

/// Layer dated closures and authorized reopenings over one location's merged
/// published openings.
///
/// Callers with several weekly patterns expand and merge those patterns
/// first, then call this function once. A reopening is therefore checked
/// against the location's complete schedule rather than being rejected by an
/// unrelated pattern that does not cover its date or time.
pub fn apply_exceptions_to_openings(
    openings: Vec<CalendarInterval>,
    timezone: &str,
    exceptions: &[CalendarException<'_>],
) -> Result<Vec<CalendarInterval>, CalendarEvaluationError> {
    let timezone: Tz = timezone
        .parse()
        .map_err(|_| CalendarEvaluationError::InvalidTimezone)?;
    let exceptions_by_id = parse_exceptions(exceptions, timezone)?;
    validate_layers(&exceptions_by_id)?;
    let published = merge_intervals(openings);
    let mut effective = published.clone();

    // Closures remove published time first; authorized reopenings then add
    // time back, so a reopening can never be subtracted by a later closure.
    for exception in exceptions_by_id.values() {
        if exception.kind == CalendarExceptionKind::Closure {
            subtract_interval(&mut effective, exception.interval);
        }
    }
    for (id, exception) in &exceptions_by_id {
        if exception.kind == CalendarExceptionKind::Opening {
            let covered = published.iter().any(|interval| {
                interval.start <= exception.interval.start && exception.interval.end <= interval.end
            });
            if covered {
                effective.push(exception.interval);
                continue;
            }
            return Err(CalendarEvaluationError::ReopenOutsidePattern { id: id.clone() });
        }
    }
    Ok(merge_intervals(effective))
}

struct ParsedException<'a> {
    kind: CalendarExceptionKind,
    interval: CalendarInterval,
    reopens: Option<&'a str>,
    authority: Option<&'a str>,
}

fn parse_exceptions<'e>(
    exceptions: &[CalendarException<'e>],
    timezone: Tz,
) -> Result<BTreeMap<String, ParsedException<'e>>, CalendarEvaluationError> {
    let mut parsed = BTreeMap::new();
    for exception in exceptions {
        if exception.id.trim().is_empty() {
            return Err(CalendarEvaluationError::EmptyExceptionId);
        }
        let interval = parse_exception_times(exception, timezone)?;
        if parsed
            .insert(
                exception.id.to_owned(),
                ParsedException {
                    kind: exception.kind,
                    interval,
                    reopens: exception.reopens,
                    authority: exception.authority,
                },
            )
            .is_some()
        {
            return Err(CalendarEvaluationError::DuplicateExceptionId {
                id: exception.id.to_owned(),
            });
        }
    }
    Ok(parsed)
}

fn parse_exception_times(
    exception: &CalendarException<'_>,
    timezone: Tz,
) -> Result<CalendarInterval, CalendarEvaluationError> {
    let date = parse_date(exception.date).ok_or(CalendarEvaluationError::InvalidExceptionDate {
        id: exception.id.to_owned(),
    })?;
    let start =
        parse_hh_mm(exception.start_time).ok_or(CalendarEvaluationError::InvalidExceptionTimes)?;
    let end =
        parse_hh_mm(exception.end_time).ok_or(CalendarEvaluationError::InvalidExceptionTimes)?;
    if start >= end {
        return Err(CalendarEvaluationError::InvalidExceptionTimes);
    }
    day_interval(date, start, end, timezone)
}

/// Enforce the exception layering rules across the parsed exceptions.
fn validate_layers(
    exceptions_by_id: &BTreeMap<String, ParsedException<'_>>,
) -> Result<(), CalendarEvaluationError> {
    for (id, exception) in exceptions_by_id {
        match exception.kind {
            CalendarExceptionKind::Closure => {
                if exception.reopens.is_some() || exception.authority.is_some() {
                    return Err(CalendarEvaluationError::ClosureCarriesReopeningFields {
                        id: id.clone(),
                    });
                }
            }
            CalendarExceptionKind::Opening => {
                let named = exception
                    .reopens
                    .and_then(|reopens| exceptions_by_id.get(reopens))
                    .filter(|named| named.kind == CalendarExceptionKind::Closure)
                    .ok_or_else(|| CalendarEvaluationError::UnknownReopenedClosure {
                        id: id.clone(),
                    })?;
                if exception
                    .authority
                    .is_none_or(|authority| authority.trim().is_empty())
                {
                    return Err(CalendarEvaluationError::ReopenAuthorityMissing { id: id.clone() });
                }
                if exception.interval.start < named.interval.start
                    || exception.interval.end > named.interval.end
                {
                    return Err(CalendarEvaluationError::ReopenOutsideClosure { id: id.clone() });
                }
                let strays = exceptions_by_id.iter().any(|(other_id, other)| {
                    other.kind == CalendarExceptionKind::Closure
                        && Some(other_id.as_str()) != exception.reopens
                        && exception.interval.start < other.interval.end
                        && other.interval.start < exception.interval.end
                });
                if strays {
                    return Err(CalendarEvaluationError::ReopenOverlapsUnrelatedClosure {
                        id: id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Remove `closure` from every interval in `openings`, splitting as needed.
fn subtract_interval(openings: &mut Vec<CalendarInterval>, closure: CalendarInterval) {
    let mut result = Vec::with_capacity(openings.len() + 1);
    for interval in openings.drain(..) {
        let overlaps = interval.start < closure.end && closure.start < interval.end;
        if !overlaps {
            result.push(interval);
            continue;
        }
        if interval.start < closure.start {
            result.push(CalendarInterval {
                start: interval.start,
                end: closure.start,
            });
        }
        if closure.end < interval.end {
            result.push(CalendarInterval {
                start: closure.end,
                end: interval.end,
            });
        }
    }
    *openings = result;
}

/// Merge overlapping or adjacent half-open intervals into a canonical form.
fn merge_intervals(mut intervals: Vec<CalendarInterval>) -> Vec<CalendarInterval> {
    intervals.sort_by_key(|interval| (interval.start, interval.end));
    let mut merged: Vec<CalendarInterval> = Vec::new();
    for interval in intervals {
        match merged.last_mut() {
            Some(last) if interval.start <= last.end => {
                last.end = last.end.max(interval.end);
            }
            _ => merged.push(interval),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

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

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .unwrap()
    }

    fn pattern<'a>(
        timezone: &'a str,
        from: &'a str,
        until: &'a str,
        start_time: &'a str,
        end_time: &'a str,
    ) -> WeeklyOpeningPattern<'a> {
        pattern_with(WEEKDAYS, timezone, from, until, start_time, end_time)
    }

    fn pattern_with<'a>(
        weekdays: &'a [Weekday],
        timezone: &'a str,
        from: &'a str,
        until: &'a str,
        start_time: &'a str,
        end_time: &'a str,
    ) -> WeeklyOpeningPattern<'a> {
        WeeklyOpeningPattern {
            id: "counter-hours",
            timezone,
            weekdays,
            start_time,
            end_time,
            effective_from: from,
            effective_until: until,
        }
    }

    fn holidays<'a>(dates: &'a [&'a str]) -> HolidaySetRevision<'a> {
        HolidaySetRevision {
            holiday_set: "office-holidays",
            revision: 7,
            dates,
        }
    }

    fn closure<'a>(
        id: &'a str,
        date: &'a str,
        start_time: &'a str,
        end_time: &'a str,
    ) -> CalendarException<'a> {
        CalendarException {
            id,
            kind: CalendarExceptionKind::Closure,
            date,
            start_time,
            end_time,
            reopens: None,
            authority: None,
        }
    }

    fn reopening<'a>(
        id: &'a str,
        reopens: &'a str,
        authority: &'a str,
        date: &'a str,
        start_time: &'a str,
        end_time: &'a str,
    ) -> CalendarException<'a> {
        CalendarException {
            id,
            kind: CalendarExceptionKind::Opening,
            date,
            start_time,
            end_time,
            reopens: Some(reopens),
            authority: Some(authority),
        }
    }

    fn expand(
        pattern: &WeeklyOpeningPattern<'_>,
        exceptions: &[CalendarException<'_>],
        dates: &[&str],
    ) -> Result<Vec<CalendarInterval>, CalendarEvaluationError> {
        expand_weekly_openings(pattern, exceptions, &holidays(dates))
    }

    #[test]
    fn weekday_pattern_expands_to_half_open_instants() {
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-09", "09:00", "12:00"),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                CalendarInterval {
                    start: instant("2026-10-05T09:00:00+07:00"),
                    end: instant("2026-10-05T12:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-06T09:00:00+07:00"),
                    end: instant("2026-10-06T12:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-07T09:00:00+07:00"),
                    end: instant("2026-10-07T12:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-08T09:00:00+07:00"),
                    end: instant("2026-10-08T12:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-09T09:00:00+07:00"),
                    end: instant("2026-10-09T12:00:00+07:00"),
                },
            ]
        );
    }

    #[test]
    fn holiday_dates_produce_no_interval() {
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-07", "09:00", "12:00"),
            &[],
            &["2026-10-06"],
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].start, instant("2026-10-05T09:00:00+07:00"));
        assert_eq!(result[1].start, instant("2026-10-07T09:00:00+07:00"));
    }

    #[test]
    fn daylight_saving_gap_and_fold_are_explicit_errors() {
        // America/New_York springs forward on 2026-03-08: 02:00 becomes 03:00.
        let gap = expand(
            &pattern_with(
                ALL_WEEKDAYS,
                "America/New_York",
                "2026-03-08",
                "2026-03-08",
                "02:00",
                "02:30",
            ),
            &[],
            &[],
        );
        assert_eq!(gap, Err(CalendarEvaluationError::NonexistentLocalTime));

        // America/New_York falls back on 2026-11-01: 01:30 occurs twice.
        let fold = expand(
            &pattern_with(
                ALL_WEEKDAYS,
                "America/New_York",
                "2026-11-01",
                "2026-11-01",
                "01:30",
                "02:00",
            ),
            &[],
            &[],
        );
        assert_eq!(fold, Err(CalendarEvaluationError::AmbiguousLocalTime));
    }

    #[test]
    fn an_interval_spanning_a_transition_keeps_real_elapsed_time() {
        // 01:00 to 03:00 across the 2026-03-08 spring-forward jump is one
        // real hour, and both wall-clock endpoints exist.
        let result = expand(
            &pattern_with(
                ALL_WEEKDAYS,
                "America/New_York",
                "2026-03-08",
                "2026-03-08",
                "01:00",
                "03:00",
            ),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![CalendarInterval {
                start: instant("2026-03-08T01:00:00-05:00"),
                end: instant("2026-03-08T03:00:00-04:00"),
            }]
        );
        assert_eq!((result[0].end - result[0].start).num_minutes(), 60);
    }

    #[test]
    fn a_blocking_closure_wins_over_an_ordinary_opening() {
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[closure("staff-meeting", "2026-10-05", "09:00", "10:00")],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![CalendarInterval {
                start: instant("2026-10-05T10:00:00+07:00"),
                end: instant("2026-10-05T12:00:00+07:00"),
            }]
        );

        // A closure that swallows the whole opening removes it entirely.
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[closure("all-day", "2026-10-05", "08:00", "17:00")],
            &[],
        )
        .unwrap();
        assert_eq!(result, Vec::<CalendarInterval>::new());

        // A closure inside the opening splits it in two, never truncates or
        // shifts silently.
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[closure("midday", "2026-10-05", "10:00", "11:00")],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                CalendarInterval {
                    start: instant("2026-10-05T09:00:00+07:00"),
                    end: instant("2026-10-05T10:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T11:00:00+07:00"),
                    end: instant("2026-10-05T12:00:00+07:00"),
                },
            ]
        );
    }

    #[test]
    fn closures_do_not_touch_time_outside_the_opening() {
        // A closure outside pattern hours removes nothing and adds nothing.
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[closure("early", "2026-10-05", "07:00", "09:00")],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![CalendarInterval {
                start: instant("2026-10-05T09:00:00+07:00"),
                end: instant("2026-10-05T12:00:00+07:00"),
            }]
        );
    }

    #[test]
    fn a_closure_may_not_carry_reopening_fields() {
        let base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00");
        let mut stray = closure("odd", "2026-10-05", "09:00", "10:00");
        stray.reopens = Some("other");
        assert_eq!(
            expand(&base, &[stray], &[]),
            Err(CalendarEvaluationError::ClosureCarriesReopeningFields {
                id: "odd".to_owned()
            })
        );
    }

    #[test]
    fn an_exceptional_reopening_requires_authority_and_a_named_closure() {
        let base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00");
        let staff_meeting = closure("staff-meeting", "2026-10-05", "09:00", "10:00");

        let mut no_authority = reopening(
            "re-open",
            "staff-meeting",
            "",
            "2026-10-05",
            "09:15",
            "09:45",
        );
        no_authority.authority = Some(" ");
        assert_eq!(
            expand(&base, &[staff_meeting, no_authority], &[]),
            Err(CalendarEvaluationError::ReopenAuthorityMissing {
                id: "re-open".to_owned()
            })
        );

        assert_eq!(
            expand(
                &base,
                &[
                    staff_meeting,
                    reopening(
                        "re-open",
                        "unknown",
                        "duty-officer",
                        "2026-10-05",
                        "09:15",
                        "09:45"
                    )
                ],
                &[]
            ),
            Err(CalendarEvaluationError::UnknownReopenedClosure {
                id: "re-open".to_owned()
            })
        );

        // Naming another reopening, not a closure, is refused the same way.
        assert_eq!(
            expand(
                &base,
                &[
                    staff_meeting,
                    reopening(
                        "first",
                        "staff-meeting",
                        "duty-officer",
                        "2026-10-05",
                        "09:15",
                        "09:45"
                    ),
                    reopening(
                        "second",
                        "first",
                        "duty-officer",
                        "2026-10-05",
                        "09:15",
                        "09:45"
                    ),
                ],
                &[]
            ),
            Err(CalendarEvaluationError::UnknownReopenedClosure {
                id: "second".to_owned()
            })
        );
    }

    #[test]
    fn an_exceptional_reopening_stays_inside_its_closure() {
        let base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00");
        assert_eq!(
            expand(
                &base,
                &[
                    closure("staff-meeting", "2026-10-05", "09:00", "10:00"),
                    reopening(
                        "re-open",
                        "staff-meeting",
                        "duty-officer",
                        "2026-10-05",
                        "09:30",
                        "10:30"
                    )
                ],
                &[]
            ),
            Err(CalendarEvaluationError::ReopenOutsideClosure {
                id: "re-open".to_owned()
            })
        );
    }

    #[test]
    fn an_exceptional_reopening_cannot_override_an_unrelated_closure() {
        let base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00");
        assert_eq!(
            expand(
                &base,
                &[
                    closure("staff-meeting", "2026-10-05", "09:00", "10:00"),
                    closure("training", "2026-10-05", "09:40", "10:20"),
                    reopening(
                        "re-open",
                        "staff-meeting",
                        "duty-officer",
                        "2026-10-05",
                        "09:30",
                        "10:00"
                    )
                ],
                &[]
            ),
            Err(CalendarEvaluationError::ReopenOverlapsUnrelatedClosure {
                id: "re-open".to_owned()
            })
        );
    }

    #[test]
    fn an_authorized_reopening_adds_time_back_inside_its_closure() {
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[
                closure("staff-meeting", "2026-10-05", "09:00", "10:00"),
                reopening(
                    "re-open",
                    "staff-meeting",
                    "duty-officer",
                    "2026-10-05",
                    "09:15",
                    "09:45",
                ),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                CalendarInterval {
                    start: instant("2026-10-05T09:15:00+07:00"),
                    end: instant("2026-10-05T09:45:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T10:00:00+07:00"),
                    end: instant("2026-10-05T12:00:00+07:00"),
                },
            ]
        );
    }

    #[test]
    fn a_reopening_may_not_extend_hours_past_the_pattern() {
        // The closure reaches outside pattern hours, so a reopening inside it
        // would open 07:30-08:30 as net-new time. A reopening restores lost
        // pattern time; it may not extend the published hours.
        assert_eq!(
            expand(
                &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
                &[
                    closure("building-work", "2026-10-05", "07:00", "12:00"),
                    reopening(
                        "early-open",
                        "building-work",
                        "duty-officer",
                        "2026-10-05",
                        "07:30",
                        "08:30"
                    ),
                ],
                &[],
            ),
            Err(CalendarEvaluationError::ReopenOutsidePattern {
                id: "early-open".to_owned()
            })
        );

        // A reopening inside pattern hours but reaching past the pattern's
        // end through its closure is refused for the same reason.
        assert_eq!(
            expand(
                &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
                &[
                    closure("late-work", "2026-10-05", "10:00", "13:00"),
                    reopening(
                        "late-open",
                        "late-work",
                        "duty-officer",
                        "2026-10-05",
                        "12:00",
                        "13:00"
                    ),
                ],
                &[],
            ),
            Err(CalendarEvaluationError::ReopenOutsidePattern {
                id: "late-open".to_owned()
            })
        );
    }

    #[test]
    fn a_reopening_on_a_holiday_or_a_non_pattern_weekday_is_refused() {
        let exceptions = |date: &'static str| {
            [
                closure("staff-meeting", date, "09:00", "10:00"),
                reopening(
                    "re-open",
                    "staff-meeting",
                    "duty-officer",
                    date,
                    "09:15",
                    "09:45",
                ),
            ]
        };

        // 2026-10-05 is a Monday inside the pattern, but a holiday.
        assert_eq!(
            expand(
                &pattern("Asia/Bangkok", "2026-10-05", "2026-10-06", "09:00", "12:00"),
                &exceptions("2026-10-05"),
                &["2026-10-05"],
            ),
            Err(CalendarEvaluationError::ReopenOutsidePattern {
                id: "re-open".to_owned()
            })
        );

        // 2026-10-04 is a Sunday, which the pattern does not cover.
        assert_eq!(
            expand(
                &pattern("Asia/Bangkok", "2026-10-04", "2026-10-06", "09:00", "12:00"),
                &exceptions("2026-10-04"),
                &[],
            ),
            Err(CalendarEvaluationError::ReopenOutsidePattern {
                id: "re-open".to_owned()
            })
        );
    }

    #[test]
    fn a_reopening_dated_outside_the_effective_range_is_refused() {
        // 2026-10-12 is a Monday, but the pattern ends on 2026-10-09.
        assert_eq!(
            expand(
                &pattern("Asia/Bangkok", "2026-10-05", "2026-10-09", "09:00", "12:00"),
                &[
                    closure("staff-meeting", "2026-10-12", "09:00", "10:00"),
                    reopening(
                        "re-open",
                        "staff-meeting",
                        "duty-officer",
                        "2026-10-12",
                        "09:15",
                        "09:45"
                    ),
                ],
                &[],
            ),
            Err(CalendarEvaluationError::ReopenOutsidePattern {
                id: "re-open".to_owned()
            })
        );
    }

    #[test]
    fn the_identity_reopening_restores_the_whole_closure() {
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[
                closure("staff-meeting", "2026-10-05", "09:00", "10:00"),
                reopening(
                    "re-open",
                    "staff-meeting",
                    "duty-officer",
                    "2026-10-05",
                    "09:00",
                    "10:00",
                ),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![CalendarInterval {
                start: instant("2026-10-05T09:00:00+07:00"),
                end: instant("2026-10-05T12:00:00+07:00"),
            }]
        );
    }

    #[test]
    fn a_reopening_adjacent_to_an_unrelated_closure_is_allowed() {
        // The reopened closure runs to 10:00, where the unrelated training
        // closure begins, so the reopening touches it at its endpoint without
        // overlapping it.
        let result = expand(
            &pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00"),
            &[
                closure("staff-meeting", "2026-10-05", "09:00", "10:00"),
                closure("training", "2026-10-05", "10:00", "10:30"),
                reopening(
                    "re-open",
                    "staff-meeting",
                    "duty-officer",
                    "2026-10-05",
                    "09:30",
                    "10:00",
                ),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                CalendarInterval {
                    start: instant("2026-10-05T09:30:00+07:00"),
                    end: instant("2026-10-05T10:00:00+07:00"),
                },
                CalendarInterval {
                    start: instant("2026-10-05T10:30:00+07:00"),
                    end: instant("2026-10-05T12:00:00+07:00"),
                }
            ]
        );
    }

    #[test]
    fn duplicate_weekday_entries_collapse_to_one_interval() {
        let duplicated = pattern_with(
            &[Weekday::Mon, Weekday::Mon],
            "Asia/Bangkok",
            "2026-10-05",
            "2026-10-05",
            "09:00",
            "12:00",
        );
        let single = pattern_with(
            &[Weekday::Mon],
            "Asia/Bangkok",
            "2026-10-05",
            "2026-10-05",
            "09:00",
            "12:00",
        );
        assert_eq!(
            expand(&duplicated, &[], &[]).unwrap(),
            expand(&single, &[], &[]).unwrap()
        );
    }

    #[test]
    fn an_interval_spanning_the_fold_keeps_real_elapsed_time() {
        // 00:00 to 02:00 across the 2026-11-01 fall-back is three real hours:
        // the repeated local hour happens twice in UTC.
        let result = expand(
            &pattern_with(
                ALL_WEEKDAYS,
                "America/New_York",
                "2026-11-01",
                "2026-11-01",
                "00:00",
                "02:00",
            ),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![CalendarInterval {
                start: instant("2026-11-01T00:00:00-04:00"),
                end: instant("2026-11-01T02:00:00-05:00"),
            }]
        );
        assert_eq!((result[0].end - result[0].start).num_minutes(), 180);
    }

    #[test]
    fn the_exactly_3650_day_span_is_within_bounds() {
        // 2020-01-01 plus 3650 days is 2029-12-28; the bound rejects only
        // spans strictly beyond it.
        let result = expand(
            &pattern_with(
                &[Weekday::Mon],
                "Asia/Bangkok",
                "2020-01-01",
                "2029-12-28",
                "09:00",
                "12:00",
            ),
            &[],
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn pattern_metadata_and_bounds_are_reported_before_arithmetic() {
        let mut base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-09", "09:00", "12:00");

        base.id = " ";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::EmptyPatternId)
        );
        base.id = "counter-hours";
        base.weekdays = &[];
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::NoPatternWeekdays)
        );
        base.weekdays = WEEKDAYS;
        base.timezone = "Not/A_Zone";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::InvalidTimezone)
        );
        base.timezone = "Asia/Bangkok";
        base.end_time = "09:00";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::InvalidPatternTimes)
        );
        base.end_time = "12:00";
        base.effective_from = "2026-10-06";
        base.effective_until = "2026-10-05";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::InvalidEffectiveRange)
        );
        base.effective_from = "2026-01-01";
        base.effective_until = "2036-01-02";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::PatternSpanTooLarge)
        );
        base.effective_from = "2026-13-01";
        base.effective_until = "2026-10-09";
        assert_eq!(
            expand(&base, &[], &[]),
            Err(CalendarEvaluationError::InvalidPatternDate { index: 0 })
        );
    }

    #[test]
    fn exception_identifiers_and_times_are_validated() {
        let base = pattern("Asia/Bangkok", "2026-10-05", "2026-10-05", "09:00", "12:00");

        let empty_id = closure(" ", "2026-10-05", "09:00", "10:00");
        assert_eq!(
            expand(&base, &[empty_id], &[]),
            Err(CalendarEvaluationError::EmptyExceptionId)
        );

        assert_eq!(
            expand(
                &base,
                &[
                    closure("a", "2026-10-05", "09:00", "10:00"),
                    closure("a", "2026-10-06", "09:00", "10:00"),
                ],
                &[]
            ),
            Err(CalendarEvaluationError::DuplicateExceptionId { id: "a".to_owned() })
        );

        assert_eq!(
            expand(&base, &[closure("a", "2026-02-30", "09:00", "10:00")], &[]),
            Err(CalendarEvaluationError::InvalidExceptionDate { id: "a".to_owned() })
        );

        assert_eq!(
            expand(&base, &[closure("a", "2026-10-05", "10:00", "09:00")], &[]),
            Err(CalendarEvaluationError::InvalidExceptionTimes)
        );
    }

    #[test]
    fn adjacent_intervals_merge_into_canonical_form() {
        let mut merged = merge_intervals(vec![
            CalendarInterval {
                start: utc(2026, 10, 5, 3, 0),
                end: utc(2026, 10, 5, 4, 0),
            },
            CalendarInterval {
                start: utc(2026, 10, 5, 4, 0),
                end: utc(2026, 10, 5, 5, 0),
            },
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].end, utc(2026, 10, 5, 5, 0));

        merged = merge_intervals(vec![
            CalendarInterval {
                start: utc(2026, 10, 5, 4, 30),
                end: utc(2026, 10, 5, 6, 0),
            },
            CalendarInterval {
                start: utc(2026, 10, 5, 3, 0),
                end: utc(2026, 10, 5, 5, 0),
            },
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, utc(2026, 10, 5, 3, 0));
        assert_eq!(merged[0].end, utc(2026, 10, 5, 6, 0));
    }
}
