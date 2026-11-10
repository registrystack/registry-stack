// SPDX-License-Identifier: Apache-2.0

//! Pure evaluation of the deliberately narrow Version 1 calendar trigger.

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, SecondsFormat, Utc};
use registry_platform_calendar::{local_date, resolve_local_instant, CalendarEvaluationError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    deployment::Workflows,
    runtime::RuntimeConfig,
    store::{CalendarCheck, Store},
};

/// A calendar expression is outside the reviewed first slice, names an
/// unknown timezone, or cannot be evaluated inside Chrono's date range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CalendarTriggerError {
    #[error("calendar cron must be `MIN HOUR 1|L * *`")]
    InvalidExpression,
    #[error("calendar timezone must be a named IANA timezone")]
    InvalidTimezone,
    #[error("calendar evaluation overflowed the supported date range")]
    Overflow,
}

/// Reviewed calendar trigger content retained in the Workflow snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendarTrigger {
    pub cron: String,
    pub timezone: String,
}

impl CalendarTrigger {
    pub fn schedule(&self) -> Result<CalendarSchedule, CalendarTriggerError> {
        CalendarSchedule::parse(&self.cron, &self.timezone)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonthDay {
    First,
    Last,
}

/// One validated monthly schedule. Version 1 accepts exactly one local time
/// on the first or last day of every month.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalendarSchedule {
    minute: u32,
    hour: u32,
    day: MonthDay,
    timezone: String,
}

/// One authored local occurrence and the exact instant selected for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalendarOccurrence {
    pub scheduled_at: DateTime<Utc>,
    pub local_date: NaiveDate,
}

impl CalendarOccurrence {
    /// Calendar admission exposes only the occurrence instant to the
    /// workflow. Catch-up and cursor details remain Coordinator state.
    pub fn input(&self) -> Value {
        json!({
            "scheduledAt": self
                .scheduled_at
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
    }
}

/// Latest-only catch-up result. `skipped` excludes the returned occurrence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CalendarCatchUp {
    pub latest: Option<CalendarOccurrence>,
    pub skipped: u64,
}

/// Stable data for `coordinatorctl explain`; it is calculated by the same
/// path as admission rather than by a second cron interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarNextExplanation {
    pub expression: String,
    pub timezone: String,
    pub after: DateTime<Utc>,
    pub next_scheduled_at: DateTime<Utc>,
    pub next_local_date: NaiveDate,
    pub next_local_time: String,
}

/// Check every calendar trigger of the served Workflows once, in order. Each
/// check takes only its own cursor row and skips one another replica holds, so
/// a slow or refused check delays nothing but itself. A refusal is logged and
/// the sweep goes on; the result is true when any check was refused. Log lines
/// carry fixed messages, counts and failure codes; the audit record of an
/// admission or reschedule carries the Workflow and trigger references.
pub async fn sweep(store: &Store, workflows: &Workflows, runtime: &RuntimeConfig) -> bool {
    let mut refused = false;
    for (_, package) in workflows.iter() {
        let definition = &package.definition;
        for trigger_id in definition.workflow.calendar_triggers.keys() {
            match store
                .admit_calendar_due(definition, trigger_id, runtime)
                .await
            {
                Ok(CalendarCheck::Idle) => {}
                Ok(CalendarCheck::Admitted(admission)) => tracing::info!(
                    skipped = admission.skipped,
                    "calendar occurrence admitted"
                ),
                Ok(CalendarCheck::Rescheduled { skipped: 0 }) => tracing::info!(
                    "calendar schedule changed; no occurrence of the previous schedule was due"
                ),
                Ok(CalendarCheck::Rescheduled { skipped }) => tracing::warn!(
                    skipped,
                    "calendar schedule changed; due occurrences of the previous schedule were not run"
                ),
                Err(error) => {
                    refused = true;
                    tracing::warn!(
                        code = %error.code,
                        suggested_action = error.suggested_action.as_deref(),
                        "calendar check was refused; it is retried at a later sweep"
                    );
                }
            }
        }
    }
    refused
}

impl CalendarSchedule {
    pub fn parse(expression: &str, timezone: &str) -> Result<Self, CalendarTriggerError> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 || fields[3] != "*" || fields[4] != "*" {
            return Err(CalendarTriggerError::InvalidExpression);
        }
        let minute = decimal_field(fields[0], 59)?;
        let hour = decimal_field(fields[1], 23)?;
        let day = match fields[2] {
            "1" => MonthDay::First,
            "L" => MonthDay::Last,
            _ => return Err(CalendarTriggerError::InvalidExpression),
        };
        local_date(DateTime::<Utc>::UNIX_EPOCH, timezone).map_err(platform_error)?;
        Ok(Self {
            minute,
            hour,
            day,
            timezone: timezone.to_owned(),
        })
    }

    /// The named IANA time zone the schedule is evaluated in.
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// The canonical cron form: the same schedule always gives the same text.
    pub fn expression(&self) -> String {
        format!(
            "{} {} {} * *",
            self.minute,
            self.hour,
            match self.day {
                MonthDay::First => "1",
                MonthDay::Last => "L",
            }
        )
    }

    /// Return the first occurrence strictly after `after`.
    pub fn next_after(
        &self,
        after: DateTime<Utc>,
    ) -> Result<CalendarOccurrence, CalendarTriggerError> {
        let local = local_date(after, &self.timezone).map_err(platform_error)?;
        let candidate = self.occurrence(local.year(), local.month())?;
        if candidate.scheduled_at > after {
            return Ok(candidate);
        }
        let (year, month) = shift_month(local.year(), local.month(), 1)?;
        self.occurrence(year, month)
    }

    /// Evaluate all occurrences after a durable cursor through `through`, but
    /// retain only the latest due occurrence. The count records every older
    /// due occurrence deliberately not admitted.
    pub fn latest_since(
        &self,
        cursor: DateTime<Utc>,
        through: DateTime<Utc>,
    ) -> Result<CalendarCatchUp, CalendarTriggerError> {
        if cursor >= through {
            return Ok(CalendarCatchUp::default());
        }
        let first = self.next_after(cursor)?;
        if first.scheduled_at > through {
            return Ok(CalendarCatchUp::default());
        }
        let latest = self.latest_at_or_before(through)?;
        if latest.scheduled_at < first.scheduled_at {
            return Ok(CalendarCatchUp::default());
        }
        Ok(CalendarCatchUp {
            skipped: month_distance(first.local_date, latest.local_date)?,
            latest: Some(latest),
        })
    }

    pub fn explain_next_after(
        &self,
        after: DateTime<Utc>,
    ) -> Result<CalendarNextExplanation, CalendarTriggerError> {
        let next = self.next_after(after)?;
        Ok(CalendarNextExplanation {
            expression: self.expression(),
            timezone: self.timezone.clone(),
            after,
            next_scheduled_at: next.scheduled_at,
            next_local_date: next.local_date,
            next_local_time: format!("{:02}:{:02}", self.hour, self.minute),
        })
    }

    fn latest_at_or_before(
        &self,
        through: DateTime<Utc>,
    ) -> Result<CalendarOccurrence, CalendarTriggerError> {
        let local = local_date(through, &self.timezone).map_err(platform_error)?;
        let candidate = self.occurrence(local.year(), local.month())?;
        if candidate.scheduled_at <= through {
            return Ok(candidate);
        }
        let (year, month) = shift_month(local.year(), local.month(), -1)?;
        self.occurrence(year, month)
    }

    fn occurrence(
        &self,
        year: i32,
        month: u32,
    ) -> Result<CalendarOccurrence, CalendarTriggerError> {
        let first =
            NaiveDate::from_ymd_opt(year, month, 1).ok_or(CalendarTriggerError::Overflow)?;
        let local_date = match self.day {
            MonthDay::First => first,
            MonthDay::Last => {
                let (next_year, next_month) = shift_month(year, month, 1)?;
                NaiveDate::from_ymd_opt(next_year, next_month, 1)
                    .and_then(|date| date.pred_opt())
                    .ok_or(CalendarTriggerError::Overflow)?
            }
        };
        let local_time = NaiveTime::from_hms_opt(self.hour, self.minute, 0)
            .ok_or(CalendarTriggerError::InvalidExpression)?;
        let scheduled_at = resolve_local_instant(local_date, local_time, &self.timezone)
            .map_err(platform_error)?;
        Ok(CalendarOccurrence {
            scheduled_at,
            local_date,
        })
    }
}

fn decimal_field(value: &str, maximum: u32) -> Result<u32, CalendarTriggerError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CalendarTriggerError::InvalidExpression);
    }
    let value = value
        .parse::<u32>()
        .map_err(|_| CalendarTriggerError::InvalidExpression)?;
    (value <= maximum)
        .then_some(value)
        .ok_or(CalendarTriggerError::InvalidExpression)
}

fn shift_month(year: i32, month: u32, amount: i64) -> Result<(i32, u32), CalendarTriggerError> {
    let month = i64::from(month)
        .checked_sub(1)
        .ok_or(CalendarTriggerError::Overflow)?;
    let index = i64::from(year)
        .checked_mul(12)
        .and_then(|value| value.checked_add(month))
        .and_then(|value| value.checked_add(amount))
        .ok_or(CalendarTriggerError::Overflow)?;
    let shifted_year =
        i32::try_from(index.div_euclid(12)).map_err(|_| CalendarTriggerError::Overflow)?;
    let shifted_month =
        u32::try_from(index.rem_euclid(12) + 1).map_err(|_| CalendarTriggerError::Overflow)?;
    Ok((shifted_year, shifted_month))
}

fn month_distance(from: NaiveDate, to: NaiveDate) -> Result<u64, CalendarTriggerError> {
    let years = i64::from(to.year())
        .checked_sub(i64::from(from.year()))
        .and_then(|value| value.checked_mul(12))
        .ok_or(CalendarTriggerError::Overflow)?;
    let months = years
        .checked_add(i64::from(to.month()))
        .and_then(|value| value.checked_sub(i64::from(from.month())))
        .ok_or(CalendarTriggerError::Overflow)?;
    u64::try_from(months).map_err(|_| CalendarTriggerError::Overflow)
}

fn platform_error(error: CalendarEvaluationError) -> CalendarTriggerError {
    match error {
        CalendarEvaluationError::InvalidTimezone => CalendarTriggerError::InvalidTimezone,
        _ => CalendarTriggerError::Overflow,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::*;

    fn instant(value: &str) -> DateTime<Utc> {
        value.parse().expect("a valid RFC 3339 instant")
    }

    #[test]
    fn only_the_reviewed_monthly_cron_subset_is_accepted() {
        let first = CalendarSchedule::parse("15 9 1 * *", "Asia/Bangkok").unwrap();
        assert_eq!(first.expression(), "15 9 1 * *");
        let last = CalendarSchedule::parse("0 17 L * *", "Europe/Paris").unwrap();
        assert_eq!(last.expression(), "0 17 L * *");

        for expression in [
            "15 9 2 * *",
            "15 9 * * *",
            "15 9 1 1 *",
            "15 9 1 * MON",
            "* 9 1 * *",
            "15 * 1 * *",
            "60 9 1 * *",
            "15 24 1 * *",
            "15 9 1 *",
        ] {
            assert!(
                CalendarSchedule::parse(expression, "UTC").is_err(),
                "{expression} must remain outside the first slice"
            );
        }
        assert_eq!(
            CalendarSchedule::parse("15 9 1 * *", "Not/A_Zone"),
            Err(CalendarTriggerError::InvalidTimezone)
        );
    }

    #[test]
    fn first_and_last_day_schedules_resolve_in_the_named_zone() {
        let first = CalendarSchedule::parse("15 9 1 * *", "Asia/Bangkok").unwrap();
        assert_eq!(
            first
                .next_after(instant("2026-01-31T17:00:00Z"))
                .unwrap()
                .scheduled_at,
            instant("2026-02-01T02:15:00Z")
        );

        let last = CalendarSchedule::parse("0 17 L * *", "Europe/Paris").unwrap();
        let leap = last.next_after(instant("2028-02-01T00:00:00Z")).unwrap();
        assert_eq!(leap.local_date.to_string(), "2028-02-29");
        assert_eq!(leap.scheduled_at, instant("2028-02-29T16:00:00Z"));
    }

    #[test]
    fn a_fold_produces_one_earlier_instant_and_an_exclusive_successor() {
        let schedule = CalendarSchedule::parse("30 1 1 * *", "America/New_York").unwrap();
        let folded = schedule
            .next_after(instant("2026-10-01T06:00:00Z"))
            .unwrap();
        assert_eq!(folded.scheduled_at, instant("2026-11-01T05:30:00Z"));
        assert_eq!(
            schedule
                .next_after(folded.scheduled_at)
                .unwrap()
                .scheduled_at,
            instant("2026-12-01T06:30:00Z")
        );
    }

    #[test]
    fn catch_up_selects_only_the_latest_due_instant_and_counts_every_skipped_one() {
        let schedule = CalendarSchedule::parse("0 9 1 * *", "UTC").unwrap();
        let caught_up = schedule
            .latest_since(
                instant("2026-01-01T09:00:00Z"),
                instant("2026-04-15T12:00:00Z"),
            )
            .unwrap();
        assert_eq!(caught_up.skipped, 2);
        assert_eq!(
            caught_up.latest.unwrap().scheduled_at,
            instant("2026-04-01T09:00:00Z")
        );

        assert_eq!(
            schedule
                .latest_since(
                    instant("2026-04-01T09:00:00Z"),
                    instant("2026-04-30T23:59:59Z")
                )
                .unwrap(),
            CalendarCatchUp::default()
        );
        assert_eq!(
            schedule
                .latest_since(
                    instant("2026-05-01T09:00:00Z"),
                    instant("2026-05-01T08:59:59Z")
                )
                .unwrap(),
            CalendarCatchUp::default()
        );
    }

    #[test]
    fn an_occurrence_input_contains_scheduled_at_and_nothing_else() {
        let occurrence = CalendarSchedule::parse("0 9 1 * *", "UTC")
            .unwrap()
            .next_after(instant("2026-01-01T09:00:00Z"))
            .unwrap();
        assert_eq!(
            occurrence.input(),
            json!({"scheduledAt":"2026-02-01T09:00:00Z"})
        );
    }

    #[test]
    fn explain_is_stable_data_derived_from_the_same_next_occurrence() {
        let schedule = CalendarSchedule::parse("5 8 L * *", "Asia/Bangkok").unwrap();
        let explanation = schedule
            .explain_next_after(instant("2026-01-10T00:00:00Z"))
            .unwrap();
        assert_eq!(explanation.expression, "5 8 L * *");
        assert_eq!(explanation.timezone, "Asia/Bangkok");
        assert_eq!(explanation.after, instant("2026-01-10T00:00:00Z"));
        assert_eq!(
            explanation.next_scheduled_at,
            instant("2026-01-31T01:05:00Z")
        );
        assert_eq!(explanation.next_local_date.to_string(), "2026-01-31");
        assert_eq!(explanation.next_local_time, "08:05");
    }
}
