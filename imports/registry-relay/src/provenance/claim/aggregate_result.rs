// SPDX-License-Identifier: Apache-2.0
//! `AggregateResult` v1 credentialSubject builder.
//!
//! Plain aggregate rows arrive flat: `{group_field: value, ...,
//! measure_name: value}` (groups and measures merged into one object).
//! The credential model splits each row into `{group: {...}, values:
//! {...}}` for clarity.
//! This module performs the split using the configured `group_by` and
//! `measures` lists; anything else in the row is dropped on the floor
//! (defence in depth: only public-visible columns reach the wire).

use serde_json::{json, Map, Value};

/// Inputs gathered by the `/aggregates/{aggregate_id}` handler.
#[derive(Debug, Clone)]
pub struct AggregateResultInput {
    pub subject_uri: String,
    pub dataset: String,
    pub entity: String,
    pub aggregate_id: String,
    pub aggregate_url: String,
    pub group_by: Vec<String>,
    pub measures: Vec<String>,
    pub rows: Vec<Value>,
    pub suppressed_groups: u64,
    pub min_group_size: u64,
    pub computed_at_rfc3339: String,
    pub as_of_rfc3339: String,
}

/// Build the `credentialSubject` JSON for an `AggregateResult` VC.
#[must_use]
pub fn aggregate_result_subject(input: &AggregateResultInput) -> Value {
    let rows: Vec<Value> = input
        .rows
        .iter()
        .map(|row| split_row(row, &input.group_by, &input.measures))
        .collect();

    json!({
        "id": &input.subject_uri,
        "dataset": &input.dataset,
        "entity": &input.entity,
        "aggregateId": &input.aggregate_id,
        "aggregateUrl": &input.aggregate_url,
        "groupBy": &input.group_by,
        "measures": &input.measures,
        "rows": rows,
        "suppressedGroups": input.suppressed_groups,
        "minGroupSize": input.min_group_size,
        "computedAt": &input.computed_at_rfc3339,
        "asOf": &input.as_of_rfc3339,
    })
}

/// Split a plain aggregate row into `{group, values}` form. The
/// `group` object reflects the declared group-by fields (empty for a
/// global aggregate); `values` reflects the declared measure ids.
/// Anything else present in `row` is intentionally discarded.
fn split_row(row: &Value, group_by: &[String], measures: &[String]) -> Value {
    let mut group = Map::new();
    let mut values = Map::new();
    if let Some(object) = row.as_object() {
        for key in group_by {
            if let Some(v) = object.get(key) {
                group.insert(key.clone(), v.clone());
            }
        }
        for key in measures {
            if let Some(v) = object.get(key) {
                values.insert(key.clone(), v.clone());
            } else {
                // Disclosure control may have removed a measure; keep
                // the key with a null so the consumer-side schema
                // still sees the declared measure list.
                values.insert(key.clone(), Value::Null);
            }
        }
    }
    json!({
        "group": Value::Object(group),
        "values": Value::Object(values),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn split_row_separates_group_keys_from_measures() {
        let row = json!({
            "region": "north",
            "year": 2025,
            "count": 12,
            "average": 3.4,
        });
        let split = split_row(
            &row,
            &["region".to_string(), "year".to_string()],
            &["count".to_string(), "average".to_string()],
        );
        assert_eq!(
            split,
            json!({
                "group": {"region": "north", "year": 2025},
                "values": {"count": 12, "average": 3.4}
            })
        );
    }

    #[test]
    fn missing_measure_lands_as_null() {
        let row = json!({"region": "north"});
        let split = split_row(
            &row,
            &["region".to_string()],
            &["count".to_string(), "average".to_string()],
        );
        assert_eq!(
            split,
            json!({
                "group": {"region": "north"},
                "values": {"count": null, "average": null},
            })
        );
    }

    #[test]
    fn unexpected_columns_are_discarded() {
        let row = json!({
            "region": "north",
            "count": 12,
            "__internal_table_id": "secret",
        });
        let split = split_row(&row, &["region".to_string()], &["count".to_string()]);
        let group = split.get("group").unwrap().as_object().unwrap();
        let values = split.get("values").unwrap().as_object().unwrap();
        assert!(!group.contains_key("__internal_table_id"));
        assert!(!values.contains_key("__internal_table_id"));
    }
}
