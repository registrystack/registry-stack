// SPDX-License-Identifier: Apache-2.0
//! Pure field predicates shared by immediate and Proposal commit controllers.

use crate::model::{CompiledCommitGuard, CompiledCurrentDateRelation};
use serde_json::{Map, Value};

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
    ) {
        (Some(expected), None, None, None, None) => {
            predicate_values_equal(actual, expected, is_timestamp)
        }
        (None, Some(input), None, None, None) => inputs
            .get(input)
            .is_some_and(|expected| predicate_values_equal(actual, expected, is_timestamp)),
        (None, None, Some(minimum), None, None) => {
            actual.as_i64().is_some_and(|actual| actual >= minimum)
        }
        (None, None, None, Some(maximum), None) => {
            actual.as_i64().is_some_and(|actual| actual <= maximum)
        }
        (None, None, None, None, Some(relation)) => {
            actual.as_str().is_some_and(|date| match relation {
                CompiledCurrentDateRelation::OnOrAfter => date >= current_date,
                CompiledCurrentDateRelation::OnOrBefore => date <= current_date,
            })
        }
        _ => false,
    }
}

/// PostgreSQL renders timestamp values in UTC, including the two boundary
/// instants that normalize outside RFC3339's four-digit year range.
pub(crate) fn predicate_values_equal(actual: &Value, expected: &Value, timestamp: bool) -> bool {
    if !timestamp || (actual.is_null() && expected.is_null()) {
        return actual == expected;
    }
    let parse = |value: &Value| {
        value.as_str().and_then(|value| {
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
        })
    };
    parse(actual)
        .zip(parse(expected))
        .is_some_and(|(actual, expected)| actual == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn guard() -> CompiledCommitGuard {
        CompiledCommitGuard {
            input: "record".into(),
            entity_id: "record".into(),
            field: "value".into(),
            equals: None,
            equals_input: None,
            revision_unchanged: false,
            at_least: None,
            at_most: None,
            current_date: None,
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
