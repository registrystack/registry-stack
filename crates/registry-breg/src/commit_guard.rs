// SPDX-License-Identifier: Apache-2.0
//! Pure field predicates shared by immediate and Proposal commit controllers.

use crate::model::{CompiledCommitGuard, CompiledCurrentDateRelation};
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// Evaluate a compiled field predicate against the row held by the caller's
/// transaction. Revision guards require a frozen revision and are checked by
/// the controller, so they deliberately do not pass this field evaluator.
pub(crate) fn guard_matches(
    guard: &CompiledCommitGuard,
    inputs: &Map<String, Value>,
    current: &Map<String, Value>,
    current_date: &str,
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
            actual.as_str().is_some_and(|date| match relation {
                CompiledCurrentDateRelation::OnOrAfter => date >= current_date,
                CompiledCurrentDateRelation::OnOrBefore => date <= current_date,
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
    use serde_json::json;

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
            at_least_input: None,
            at_most_input: None,
        }
    }

    #[test]
    fn missing_values_and_ambiguous_predicates_fail_closed() {
        let mut guard = guard();
        guard.equals = Some(Value::Null);
        assert!(guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            &Map::new(),
            "2026-10-14",
            false
        ));
        guard.equals_input = Some("submitted".into());
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        guard.equals = None;
        assert!(!guard_matches(
            &guard,
            &Map::new(),
            json!({"value":null}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(guard_matches(
            &guard,
            json!({"submitted":null}).as_object().unwrap(),
            json!({"value":null}).as_object().unwrap(),
            "2026-10-14",
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
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":9}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"10"}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        guard.at_least = None;
        guard.at_most = Some(10);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":10}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":11}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        guard.at_most = None;
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrAfter);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-14"}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-13"}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        guard.current_date = Some(CompiledCurrentDateRelation::OnOrBefore);
        assert!(guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-14"}).as_object().unwrap(),
            "2026-10-14",
            false
        ));
        assert!(!guard_matches(
            &guard,
            &inputs,
            json!({"value":"2026-10-15"}).as_object().unwrap(),
            "2026-10-14",
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
            "2026-10-14",
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
            "2026-10-14",
            false
        ));
        // Two comparisons on one guard never match.
        guard.at_least_input = Some("bound".into());
        assert!(!guard_matches(
            &guard,
            json!({"bound": 1}).as_object().unwrap(),
            json!({"value": 1}).as_object().unwrap(),
            "2026-10-14",
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
            "2026-10-14",
            false
        ));
    }
}
