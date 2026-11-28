// SPDX-License-Identifier: Apache-2.0
//! Pure field predicates shared by immediate and Proposal commit controllers.

use crate::model::{CompiledCommitGuard, CompiledCurrentDateRelation, CompiledRegistry};
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// Evaluate a compiled field predicate against the row held by the caller's
/// transaction. Revision guards require a frozen revision and are checked by
/// the controller, so they deliberately do not pass this field evaluator.
pub(crate) fn guard_matches(
    guard: &CompiledCommitGuard,
    inputs: &Map<String, Value>,
    current: &Map<String, Value>,
    registry: &CompiledRegistry,
    now: time::OffsetDateTime,
    is_timestamp: bool,
) -> bool {
    if guard.revision_unchanged {
        return false;
    }
    let Some(actual) = current.get(&guard.field) else {
        return false;
    };
    match (
        &guard.equals,
        &guard.equals_input,
        guard.at_least,
        guard.at_most,
        &guard.current_date,
        &guard.at_least_input,
        &guard.at_most_input,
    ) {
        (Some(expected), None, None, None, None, None, None) => {
            predicate_values_equal(actual, expected, is_timestamp)
        }
        (None, Some(input), None, None, None, None, None) => inputs
            .get(input)
            .is_some_and(|expected| predicate_values_equal(actual, expected, is_timestamp)),
        (None, None, Some(minimum), None, None, None, None) => {
            actual.as_i64().is_some_and(|actual| actual >= minimum)
        }
        (None, None, None, Some(maximum), None, None, None) => {
            actual.as_i64().is_some_and(|actual| actual <= maximum)
        }
        (None, None, None, None, Some(relation), None, None) => {
            let Some(today) = registry_today(
                registry,
                now,
                guard.current_date_offset_days,
                guard.current_date_offset_months,
            ) else {
                return false;
            };
            actual
                .as_str()
                .and_then(|date| chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
                .is_some_and(|date| match relation {
                    CompiledCurrentDateRelation::OnOrAfter => date >= today,
                    CompiledCurrentDateRelation::OnOrBefore => date <= today,
                })
        }
        (None, None, None, None, None, Some(input), None) => inputs
            .get(input)
            .and_then(|bound| compare_ordered(actual, bound, is_timestamp))
            .is_some_and(Ordering::is_ge),
        (None, None, None, None, None, None, Some(input)) => inputs
            .get(input)
            .and_then(|bound| compare_ordered(actual, bound, is_timestamp))
            .is_some_and(Ordering::is_le),
        _ => false,
    }
}

/// The registry's calendar date at `now`, the "today" a `currentDate` guard
/// compares against, shifted by whole days or whole calendar months. A date
/// that cannot be resolved fails the guard closed.
fn registry_today(
    registry: &CompiledRegistry,
    now: time::OffsetDateTime,
    offset_days: i32,
    offset_months: i32,
) -> Option<chrono::NaiveDate> {
    let shifted = registry
        .local_date_at(now)
        .ok()
        .and_then(|date| shift_date(date, offset_days, offset_months));
    // Only the runtime feature links `tracing`; test builds without it
    // still fail the guard closed.
    #[cfg(feature = "runtime")]
    if shifted.is_none() {
        tracing::error!(
            offset_days,
            offset_months,
            "a currentDate guard could not resolve the registry's offset date and fails closed"
        );
    }
    shifted
}

/// Shift a date by whole days, or by whole calendar months that clamp to the
/// last day of a shorter month, and keep it within the years 1 through 9999
/// the Rhai date helpers allow. A compiled guard carries at most one nonzero
/// offset.
fn shift_date(date: chrono::NaiveDate, days: i32, months: i32) -> Option<chrono::NaiveDate> {
    let shifted = if months >= 0 {
        date.checked_add_months(chrono::Months::new(months.unsigned_abs()))
    } else {
        date.checked_sub_months(chrono::Months::new(months.unsigned_abs()))
    }?;
    let shifted = if days >= 0 {
        shifted.checked_add_days(chrono::Days::new(u64::from(days.unsigned_abs())))
    } else {
        shifted.checked_sub_days(chrono::Days::new(u64::from(days.unsigned_abs())))
    }?;
    (1..=9999)
        .contains(&chrono::Datelike::year(&shifted))
        .then_some(shifted)
}

/// Order a stored value against a submitted one. The compiler only pairs a
/// field with an input of the same integer, date, or instant type, so the value
/// shape tells the three apart: numbers are integers, strings are instants for a
/// timestamp field and calendar dates otherwise. Anything that does not parse
/// has no order.
fn compare_ordered(actual: &Value, bound: &Value, timestamp: bool) -> Option<Ordering> {
    if timestamp {
        return Some(instant_nanos(actual)?.cmp(&instant_nanos(bound)?));
    }
    match (actual, bound) {
        (Value::Number(actual), Value::Number(bound)) => {
            Some(actual.as_i64()?.cmp(&bound.as_i64()?))
        }
        (Value::String(actual), Value::String(bound)) => {
            Some(calendar_date(actual)?.cmp(&calendar_date(bound)?))
        }
        _ => None,
    }
}

fn calendar_date(value: &str) -> Option<time::Date> {
    time::Date::parse(
        value,
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()
}

/// Nanoseconds since the Unix epoch of an RFC 3339 instant, including the two
/// boundary instants PostgreSQL renders outside RFC 3339's four-digit year
/// range.
fn instant_nanos(value: &Value) -> Option<i128> {
    let value = value.as_str()?;
    let (normalized, day_offset) = if let Some(bc) = value.strip_suffix(" BC") {
        let rest = bc.strip_prefix("0001-")?;
        (format!("0000-{rest}"), 0)
    } else if let Some(rest) = value.strip_prefix("10000-01-01T") {
        (format!("9999-12-31T{rest}"), 1)
    } else {
        (value.to_owned(), 0)
    };
    time::OffsetDateTime::parse(&normalized, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|parsed| parsed.unix_timestamp_nanos() + day_offset * 86_400_000_000_000)
}

/// PostgreSQL renders timestamp values in UTC, including the two boundary
/// instants that normalize outside RFC3339's four-digit year range.
pub(crate) fn predicate_values_equal(actual: &Value, expected: &Value, timestamp: bool) -> bool {
    if !timestamp || (actual.is_null() && expected.is_null()) {
        return actual == expected;
    }
    instant_nanos(actual)
        .zip(instant_nanos(expected))
        .is_some_and(|(actual, expected)| actual == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use serde_json::json;
    use time::macros::datetime;

    fn registry(timezone: Option<&str>) -> CompiledRegistry {
        let mut project = json!({"id": "guards", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://guards.example.test"});
        if let Some(timezone) = timezone {
            project["timezone"] = json!(timezone);
        }
        let source = json!({
            "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
            "kind": "BRegProject",
            "project": project,
            "datasets": {"guards": {}},
            "recordTypes": {"site": { "primaryDataset": "guards", "route": "sites",
                "mutationMode": "mutable",
                "fields": [{"id": "code", "type": "string", "required": true,
                    "maximumLength": 32, "classification": "internal"}]}}
        });
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Authoring).unwrap()
    }

    fn noon() -> time::OffsetDateTime {
        datetime!(2026-10-14 12:00 UTC)
    }

    fn guard() -> CompiledCommitGuard {
        CompiledCommitGuard {
            input: "record".into(),
            reason: None,
            entity_id: "record".into(),
            field: "value".into(),
            equals: None,
            equals_input: None,
            revision_unchanged: false,
            at_least: None,
            at_most: None,
            current_date: None,
            label: None,
            current_date_offset_days: 0,
            current_date_offset_months: 0,
            at_least_input: None,
            at_most_input: None,
        }
    }

    #[test]
    fn the_offset_date_stays_within_years_1_to_9999() {
        let registry = registry(Some("UTC"));
        let date = |now, offset| registry_today(&registry, now, offset, 0);
        assert_eq!(
            date(datetime!(9999-12-30 12:00 UTC), 1),
            chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
        );
        assert_eq!(date(datetime!(9999-12-31 12:00 UTC), 1), None);
        assert_eq!(
            date(datetime!(0001-01-02 12:00 UTC), -1),
            chrono::NaiveDate::from_ymd_opt(1, 1, 1)
        );
        assert_eq!(date(datetime!(0001-01-01 12:00 UTC), -1), None);
    }

    #[test]
    fn a_month_offset_clamps_to_the_last_day_of_a_shorter_month() {
        let registry = registry(Some("UTC"));
        let date = |now, months| registry_today(&registry, now, 0, months);
        let ymd = |year, month, day| chrono::NaiveDate::from_ymd_opt(year, month, day);
        // January 31 plus one month is February 28, or 29 in a leap year.
        assert_eq!(date(datetime!(2026-01-31 12:00 UTC), 1), ymd(2026, 2, 28));
        assert_eq!(date(datetime!(2028-01-31 12:00 UTC), 1), ymd(2028, 2, 29));
        // March 31 minus one month is the last day of February.
        assert_eq!(date(datetime!(2026-03-31 12:00 UTC), -1), ymd(2026, 2, 28));
        assert_eq!(date(datetime!(2028-03-31 12:00 UTC), -1), ymd(2028, 2, 29));
        // A shift across a year boundary changes the year.
        assert_eq!(date(datetime!(2026-12-15 12:00 UTC), 1), ymd(2027, 1, 15));
        assert_eq!(date(datetime!(2026-01-15 12:00 UTC), -1), ymd(2025, 12, 15));
        assert_eq!(date(datetime!(2026-10-14 12:00 UTC), 0), ymd(2026, 10, 14));
        // A shift past year 9999 or before year 1 fails closed.
        assert_eq!(date(datetime!(9999-12-15 12:00 UTC), 1), None);
        assert_eq!(date(datetime!(9999-11-15 12:00 UTC), 1), ymd(9999, 12, 15));
        assert_eq!(date(datetime!(0001-01-15 12:00 UTC), -1), None);
    }

    #[test]
    fn the_guard_and_the_planner_helper_agree_on_month_arithmetic() {
        let starts = [
            (2026, 1, 31),
            (2028, 1, 31),
            (2026, 3, 31),
            (2028, 2, 29),
            (2026, 12, 15),
            (2026, 1, 1),
            (2024, 2, 29),
            (2026, 5, 31),
            (2026, 10, 14),
            (1, 1, 31),
            (9999, 12, 31),
        ];
        let months = [
            -25, -13, -12, -2, -1, 0, 1, 2, 12, 13, 24, 100, -100, 12_000, -12_000,
        ];
        for (year, month, day) in starts {
            let start = chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap();
            for offset in months {
                let guard = shift_date(start, 0, offset).map(|date| date.to_string());
                let planner =
                    crate::rhai_planner::add_months(start.to_string().into(), offset.into())
                        .ok()
                        .map(|date| date.to_string());
                assert_eq!(guard, planner, "{start} plus {offset} months");
            }
        }
    }

    #[test]
    fn a_current_date_guard_applies_its_signed_month_offset() {
        let inputs = Map::new();
        let mut guard = guard();
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrAfter);
        guard.current_date_offset_months = 1;
        let at = |stored: &str, now| {
            guard_matches(
                &guard,
                &inputs,
                json!({"value": stored}).as_object().unwrap(),
                &registry(Some("UTC")),
                now,
                false,
            )
        };
        assert!(at("2026-02-28", datetime!(2026-01-31 12:00 UTC)));
        assert!(!at("2026-02-27", datetime!(2026-01-31 12:00 UTC)));
        assert!(at("2026-11-14", noon()));
        assert!(!at("2026-11-13", noon()));
        // An offset past year 9999 fails closed.
        assert!(!at("9999-12-31", datetime!(9999-12-15 12:00 UTC)));
    }

    #[test]
    fn missing_values_and_ambiguous_predicates_fail_closed() {
        let mut guard = guard();
        guard.equals = Some(Value::Null);
        assert!(guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            &Map::new(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.equals_input = Some("submitted".into());
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.equals = None;
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(guard_matches(
            &guard,
            json!({"submitted":null}).as_object().unwrap(),
            json!({"value":null}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
    }

    #[test]
    fn numeric_and_current_date_thresholds_are_inclusive() {
        let inputs = Map::new();
        let mut guard = guard();
        guard.at_least = Some(10);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":10}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":9}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"10"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.at_least = None;
        guard.at_most = Some(10);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":10}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":11}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.at_most = None;
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrAfter);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-14"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-13"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrBefore);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-14"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-15"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
    }

    #[test]
    fn a_current_date_guard_applies_its_signed_day_offset() {
        let inputs = Map::new();
        let mut guard = guard();
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrAfter);
        guard.current_date_offset_days = 2;
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-16"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-15"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));

        guard.current_date = Some(CompiledCurrentDateRelation::OnOrBefore);
        guard.current_date_offset_days = -2;
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-12"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-13"}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        guard.current_date_offset_days = 1;
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"9999-12-31"}).as_object().unwrap(),
            &registry(Some("UTC")),
            datetime!(9999-12-30 12:00 UTC),
            false
        ));
        // An offset past year 9999 fails closed.
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"9999-12-31"}).as_object().unwrap(),
            &registry(Some("UTC")),
            datetime!(9999-12-31 12:00 UTC),
            false
        ));
    }

    fn ordered_guard_matches(
        at_least: bool,
        stored: Value,
        submitted: Value,
        timestamp: bool,
    ) -> bool {
        let mut guard = guard();
        if at_least {
            guard.at_least_input = Some("bound".into());
        } else {
            guard.at_most_input = Some("bound".into());
        }
        guard_matches(
            &guard,
            json!({"bound": submitted}).as_object().unwrap(),
            json!({"value": stored}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            timestamp,
        )
    }

    #[test]
    fn ordered_input_guards_are_inclusive_and_compare_typed_values() {
        // The stored field is the subject: atLeast keeps it >= the input,
        // atMost keeps it <= the input.
        for (at_least, stored, submitted, expected) in [
            (true, json!(10), json!(10), true),
            (true, json!(11), json!(10), true),
            (true, json!(9), json!(10), false),
            (false, json!(10), json!(10), true),
            (false, json!(9), json!(10), true),
            (false, json!(11), json!(10), false),
            // Integers outside the f64 range still order exactly.
            (false, json!(i64::MAX - 1), json!(i64::MAX), true),
            (false, json!(i64::MAX), json!(i64::MAX - 1), false),
            (false, json!(i64::MIN), json!(i64::MIN), true),
            (true, json!(-5), json!(-6), true),
        ] {
            assert_eq!(
                ordered_guard_matches(at_least, stored.clone(), submitted.clone(), false),
                expected,
                "integer at_least={at_least} stored={stored} submitted={submitted}"
            );
        }
        for (at_least, stored, submitted, expected) in [
            (false, "2026-10-30", "2026-10-30", true),
            (false, "2026-10-29", "2026-10-30", true),
            (false, "2026-10-31", "2026-10-30", false),
            (true, "2026-10-30", "2026-10-30", true),
            (true, "2026-11-01", "2026-10-30", true),
            (true, "2026-10-29", "2026-10-30", false),
            // Dates order as dates across month and year boundaries.
            (false, "2026-09-30", "2026-10-01", true),
            (false, "2025-12-31", "2026-01-01", true),
        ] {
            assert_eq!(
                ordered_guard_matches(at_least, json!(stored), json!(submitted), false),
                expected,
                "date at_least={at_least} stored={stored} submitted={submitted}"
            );
        }
        for (at_least, stored, submitted, expected) in [
            // Z and +00:00 name the same instant.
            (
                false,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T10:00:00Z",
                true,
            ),
            (
                true,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T10:00:00Z",
                true,
            ),
            (
                true,
                "2026-10-30T10:00:00Z",
                "2026-10-30T10:00:00+00:00",
                true,
            ),
            (
                false,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T09:59:59Z",
                false,
            ),
            (
                true,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T10:00:01Z",
                false,
            ),
            // Offsets are compared as instants, not as text.
            (
                false,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T12:00:00+02:00",
                true,
            ),
            (
                false,
                "2026-10-30T10:00:00+00:00",
                "2026-10-30T11:59:59+02:00",
                false,
            ),
            (
                true,
                "2026-10-30T10:00:01+00:00",
                "2026-10-30T12:00:00+02:00",
                true,
            ),
            // Fractional seconds count.
            (
                false,
                "2026-10-30T10:00:00.5+00:00",
                "2026-10-30T10:00:00Z",
                false,
            ),
            (
                true,
                "2026-10-30T10:00:00.5+00:00",
                "2026-10-30T10:00:00Z",
                true,
            ),
        ] {
            assert_eq!(
                ordered_guard_matches(at_least, json!(stored), json!(submitted), true),
                expected,
                "instant at_least={at_least} stored={stored} submitted={submitted}"
            );
        }
    }

    #[test]
    fn ordered_input_guards_fail_closed() {
        for at_least in [true, false] {
            // A stored null, an unparseable value, and a mismatched shape.
            assert!(!ordered_guard_matches(
                at_least,
                Value::Null,
                json!(1),
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!(1),
                Value::Null,
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!("1"),
                json!(1),
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!(1),
                json!("1"),
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!("2026-10-30"),
                json!("not-a-date"),
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!("2026-02-30"),
                json!("2026-02-28"),
                false
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!("2026-10-30T10:00:00Z"),
                json!("2026-10-30"),
                true
            ));
            assert!(!ordered_guard_matches(
                at_least,
                json!("2026-10-30T10:00:00Z"),
                json!("invalid"),
                true
            ));
        }
        // A missing submitted input never satisfies the guard.
        let mut guard = guard();
        guard.at_most_input = Some("bound".into());
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            json!({"value": 1}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
        // Two comparisons on one guard never match.
        guard.at_least_input = Some("bound".into());
        assert!(!guard_matches(
            &guard,
            json!({"bound": 1}).as_object().unwrap(),
            json!({"value": 1}).as_object().unwrap(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
    }

    #[test]
    fn timestamp_equality_preserves_offsets_and_postgres_boundary_years() {
        for (actual, expected) in [
            ("2026-09-12T09:30:00+07:00", "2026-09-12T02:30:00Z"),
            (
                "0001-12-31T23:00:00.123456+00:00 BC",
                "0001-01-01T00:00:00.123456+01:00",
            ),
            (
                "10000-01-01T00:00:00.12+00:00",
                "9999-12-31T23:00:00.12-01:00",
            ),
        ] {
            assert!(predicate_values_equal(
                &json!(actual),
                &json!(expected),
                true
            ));
            assert!(!predicate_values_equal(
                &json!(actual),
                &json!(expected),
                false
            ));
        }
        assert!(!predicate_values_equal(
            &json!("invalid"),
            &json!("invalid"),
            true
        ));
        assert!(!predicate_values_equal(
            &json!("2026-09-12T02:30:00Z"),
            &json!("2026-09-12T02:30:01Z"),
            true
        ));
        assert!(predicate_values_equal(&Value::Null, &Value::Null, true));
    }

    #[test]
    fn revision_guard_requires_the_controller_frozen_revision_check() {
        let mut guard = guard();
        guard.revision_unchanged = true;
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            &Map::new(),
            &registry(Some("UTC")),
            noon(),
            false
        ));
    }

    #[test]
    fn a_current_date_guard_compares_against_the_registry_local_date() {
        let colombo = registry(Some("Asia/Colombo"));
        let mut guard = guard();
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrAfter);
        let late_evening_utc = datetime!(2026-10-30 23:30 UTC);
        assert!(guard_matches(
            &guard,
            &Map::new(),
            json!({"value":"2026-10-31"}).as_object().unwrap(),
            &colombo,
            late_evening_utc,
            false
        ));
        assert!(
            !guard_matches(
                &guard,
                &Map::new(),
                json!({"value":"2026-10-30"}).as_object().unwrap(),
                &colombo,
                late_evening_utc,
                false
            ),
            "Colombo is already on 31 October at 23:30 UTC"
        );
        assert!(
            !guard_matches(
                &guard,
                &Map::new(),
                json!({"value":"2026-10-30"}).as_object().unwrap(),
                &registry(None),
                late_evening_utc,
                false
            ),
            "a registry without a time zone has no today, so the guard fails closed"
        );
        assert!(
            registry(None).local_date_at(late_evening_utc).is_err(),
            "a registry without a time zone is never given a UTC date"
        );
    }
}
