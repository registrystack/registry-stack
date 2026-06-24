// SPDX-License-Identifier: Apache-2.0
//! SDMX-JSON aggregate response rendering.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::api::aggregates::format::SDMX_JSON;
use crate::query::AggregateResult;

const SDMX_JSON_SCHEMA: &str = "https://json.sdmx.org/2.1/sdmx-json-data-schema.json";

pub(super) fn sdmx_json_response(result: &AggregateResult, as_of: Option<&str>) -> Response {
    let mut response = Json(sdmx_result_json(result, as_of)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(SDMX_JSON));
    response
}

fn sdmx_result_json(result: &AggregateResult, as_of: Option<&str>) -> Value {
    let dimensions = sdmx_dimension_values(result);
    let include_observation_status = result
        .data
        .iter()
        .any(|row| row_status(result, row).is_some());
    let observations = result
        .data
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            let key = sdmx_observation_key(result, row, row_index, &dimensions);
            let mut values = result
                .indicators
                .iter()
                .map(|measure| row.get(measure).cloned().unwrap_or(Value::Null))
                .collect::<Vec<_>>();
            if include_observation_status {
                values.push(
                    row_status(result, row)
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                );
            }
            (key, Value::Array(values))
        })
        .collect::<serde_json::Map<_, _>>();
    let observation_attributes = if include_observation_status {
        vec![json!({
            "id": "OBS_STATUS",
            "name": "Observation status",
            "description": "Registry Relay disclosure-control status for suppressed aggregate observations.",
            "observation": {},
            "values": [
                {
                    "id": "S",
                    "name": "Suppressed"
                }
            ],
            "x-source": "attributes.*$status"
        })]
    } else {
        Vec::new()
    };
    let mut meta = json!({
        "schema": SDMX_JSON_SCHEMA,
        "id": sdmx_message_id(&result.dataset_id, &result.aggregate_id),
        "prepared": result.computed_at,
        "sender": {
            "id": "registry-relay",
            "name": "Registry Relay"
        },
        "x-completeness": {
            "complete": !result.truncated,
            "truncated": result.truncated
        }
    });
    if let Some(as_of) = as_of {
        meta["x-asOf"] = json!(as_of);
    }
    json!({
        "$schema": SDMX_JSON_SCHEMA,
        "meta": meta,
        "data": {
            "dataSets": [
                {
                    "structure": 0,
                    "action": "Information",
                    "observations": observations
                }
            ],
            "structures": [{
                "dataSets": [0],
                "name": result.aggregate_id,
                "description": format!(
                    "Aggregate result for {}/{}",
                    result.dataset_id, result.aggregate_id
                ),
                "links": [
                    {
                        "rel": "self",
                        "href": format!(
                            "/v1/datasets/{}/aggregates/{}",
                            result.dataset_id, result.aggregate_id
                        ),
                        "type": SDMX_JSON
                    },
                    {
                        "rel": "describedby",
                        "href": format!(
                            "/v1/datasets/{}/aggregates/{}/structure",
                            result.dataset_id, result.aggregate_id
                        ),
                        "type": "application/json"
                    }
                ],
                "dimensions": {
                    "dataSet": [],
                    "series": [],
                    "observation": result.schema.dimensions.iter().enumerate().map(
                        |(position, dimension)| {
                            let values = dimensions
                                .get(position)
                                .into_iter()
                                .flatten()
                                .map(|value| json!({ "id": value, "name": value }))
                                .collect::<Vec<_>>();
                            let mut dimension = json!({
                                "id": dimension.id,
                                "name": dimension.label,
                                "keyPosition": position,
                            });
                            if !values.is_empty() {
                                dimension["values"] = Value::Array(values);
                            }
                            dimension
                        }
                    ).collect::<Vec<_>>()
                },
                "measures": {
                    "observation": result.schema.indicators.iter().map(|measure| json!({
                        "id": measure.id,
                        "name": measure.label,
                        "x-unitMeasure": measure.unit_measure,
                        "x-unitMultiplier": measure.unit_mult,
                        "x-decimals": measure.decimals,
                    })).collect::<Vec<_>>()
                },
                "attributes": {
                    "dataSet": [],
                    "dimensionGroup": [],
                    "series": [],
                    "observation": observation_attributes
                }
            }]
        }
    })
}

fn sdmx_dimension_values(result: &AggregateResult) -> Vec<Vec<String>> {
    let mut values = vec![Vec::<String>::new(); result.group_by.len()];
    for row in &result.data {
        for (position, dimension) in result.group_by.iter().enumerate() {
            let value = row
                .get(dimension)
                .map(sdmx_value_id)
                .unwrap_or_else(sdmx_missing_id);
            if !values[position].contains(&value) {
                values[position].push(value);
            }
        }
    }
    for dimension_values in &mut values {
        dimension_values.sort();
    }
    values
}

fn sdmx_observation_key(
    result: &AggregateResult,
    row: &Value,
    row_index: usize,
    dimensions: &[Vec<String>],
) -> String {
    if result.group_by.is_empty() {
        return row_index.to_string();
    }
    result
        .group_by
        .iter()
        .enumerate()
        .map(|(position, dimension)| {
            let value = row
                .get(dimension)
                .map(sdmx_value_id)
                .unwrap_or_else(sdmx_missing_id);
            dimensions
                .get(position)
                .and_then(|values| values.iter().position(|candidate| candidate == &value))
                .unwrap_or(0)
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn sdmx_value_id(value: &Value) -> String {
    let raw = match value {
        Value::String(value) => format!("S:{value}"),
        Value::Number(value) => format!("N:{value}"),
        Value::Bool(value) => format!("B:{value}"),
        Value::Null => "Z:null".to_string(),
        Value::Array(_) | Value::Object(_) => format!("J:{value}"),
    };
    sdmx_token(&raw, false)
}

fn sdmx_missing_id() -> String {
    sdmx_token("M:missing", false)
}

fn sdmx_message_id(dataset_id: &str, aggregate_id: &str) -> String {
    sdmx_display_token(&format!("{dataset_id}${aggregate_id}"))
}

fn sdmx_token(value: &str, must_start_with_letter: bool) -> String {
    let mut token = String::new();
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '@' | '$' | '-') {
            token.push(ch);
        } else {
            token.push_str(&format!("_x{byte:02X}_"));
        }
    }
    if token.is_empty() {
        token.push_str("NA");
    }
    if must_start_with_letter
        && !token
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
    {
        token.insert(0, 'A');
    }
    token
}

fn sdmx_display_token(value: &str) -> String {
    let mut token = String::new();
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '@' | '$' | '-') {
            token.push(ch);
        } else {
            token.push_str(&format!("_x{byte:02X}_"));
        }
    }
    if token.is_empty() {
        token.push_str("NA");
    }
    token
}

/// Resolve a single observation-level status token for a row that may carry
/// per-measure `*$status` attributes.
///
/// A row can suppress more than one measure, and the measures can in principle
/// carry different status tokens. The SDMX observation array exposes one
/// `OBS_STATUS` slot per row, so the per-measure tokens are reconciled with a
/// fixed, measure-order-independent precedence:
///
/// 1. `S` (suppressed) wins whenever any measure is suppressed, so a row that
///    hides any value is always reported as suppressed.
/// 2. Otherwise the lexicographically smallest non-empty token is chosen, which
///    keeps the output deterministic regardless of measure ordering.
fn row_status(result: &AggregateResult, row: &Value) -> Option<String> {
    let attributes = row.get("attributes").and_then(Value::as_object)?;
    let mut selected: Option<String> = None;
    for indicator in &result.indicators {
        let status_key = format!("{indicator}$status");
        let Some(status) = attributes
            .get(&status_key)
            .and_then(Value::as_str)
            .filter(|status| !status.is_empty())
        else {
            continue;
        };
        if status == "S" {
            return Some(status.to_string());
        }
        match &selected {
            Some(current) if current.as_str() <= status => {}
            _ => selected = Some(status.to_string()),
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::aggregates::{
        AggregateDimensionItem, AggregateDisclosure, AggregateIndicatorItem, AggregateSchema,
    };

    fn indicator(id: &str) -> AggregateIndicatorItem {
        AggregateIndicatorItem {
            id: id.to_string(),
            label: id.to_string(),
            function: "count",
            column: id.to_string(),
            unit_measure: "units".to_string(),
            unit_mult: None,
            decimals: None,
            frequency: None,
            definition_uri: None,
        }
    }

    fn result_with_two_measures(row: Value) -> AggregateResult {
        AggregateResult {
            dataset_id: "social_registry".to_string(),
            aggregate_id: "by_region".to_string(),
            computed_at: "2026-06-11T00:00:00Z".to_string(),
            data: vec![row],
            truncated: false,
            schema: AggregateSchema {
                dimensions: vec![AggregateDimensionItem {
                    id: "region".to_string(),
                    label: "Region".to_string(),
                    field: "region".to_string(),
                    codelist: None,
                }],
                indicators: vec![indicator("first_count"), indicator("second_count")],
            },
            disclosure_control: AggregateDisclosure {
                method: vec!["k-anonymity".to_string()],
                min_cell_size: 2,
                suppression: "omit",
                suppressed_rows: Some(0),
                tracked_query_budget: false,
                query_budget_scope: "none",
            },
            group_by: vec!["region".to_string()],
            indicators: vec!["first_count".to_string(), "second_count".to_string()],
            source_tables: vec!["households_table".to_string()],
        }
    }

    #[test]
    fn row_status_reports_suppression_when_only_the_second_measure_is_suppressed() {
        // The first measure carries a non-suppression token and the second is
        // suppressed. A naive first-match scan would surface the first token and
        // miss the suppression; the row must report "S" instead.
        let row = json!({
            "region": "north",
            "first_count": 42,
            "second_count": null,
            "attributes": {
                "first_count$status": "A",
                "second_count$status": "S",
            }
        });
        let result = result_with_two_measures(row);

        assert_eq!(row_status(&result, &result.data[0]).as_deref(), Some("S"));
    }

    #[test]
    fn sdmx_observation_carries_suppressed_status_for_second_measure() {
        let row = json!({
            "region": "north",
            "first_count": 42,
            "second_count": null,
            "attributes": {
                "first_count$status": "A",
                "second_count$status": "S",
            }
        });
        let result = result_with_two_measures(row);
        let message = sdmx_result_json(&result, None);

        let observations = message["data"]["dataSets"][0]["observations"]
            .as_object()
            .expect("observations object");
        let values = observations
            .values()
            .next()
            .and_then(Value::as_array)
            .expect("observation values array");
        // [first_count, second_count, OBS_STATUS]
        assert_eq!(values.last(), Some(&json!("S")));
    }
}
