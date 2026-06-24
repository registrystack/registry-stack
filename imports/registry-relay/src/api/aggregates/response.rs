// SPDX-License-Identifier: Apache-2.0
//! Aggregate JSON and CSV response rendering.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::error::Error;
use crate::query::AggregateResult;

pub(super) fn aggregate_result_json(result: &AggregateResult, as_of: Option<&str>) -> Value {
    let mut freshness = json!({ "computed_at": result.computed_at });
    if let Some(as_of) = as_of {
        freshness["as_of"] = json!(as_of);
    }
    json!({
        "dataset_id": result.dataset_id,
        "aggregate_id": result.aggregate_id,
        "observations": result.data,
        "structure": aggregate_structure_body_json(&result.schema),
        "completeness": {
            "complete": !result.truncated,
            "truncated": result.truncated,
        },
        "disclosure_control": disclosure_json(&result.disclosure_control),
        "freshness": freshness,
        "links": [
            { "rel": "self", "href": format!("/v1/datasets/{}/aggregates/{}", result.dataset_id, result.aggregate_id), "type": "application/json" },
            { "rel": "describedby", "href": format!("/v1/datasets/{}/aggregates/{}/structure", result.dataset_id, result.aggregate_id), "type": "application/json" },
            { "rel": "alternate", "href": format!("/v1/datasets/{}/aggregates/{}?f=sdmx-json", result.dataset_id, result.aggregate_id), "type": "application/vnd.sdmx.data+json;version=2.1" }
        ]
    })
}

pub(super) fn csv_response(result: &AggregateResult, envelope: &Value) -> Response {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    let headers = csv_headers(result);
    if let Err(err) = wtr.write_record(&headers) {
        tracing::error!(error = %err, "aggregate.csv_header_failed");
        return Error::from(crate::error::AggregateError::ExecutionFailed).into_response();
    }
    for row in &result.data {
        let Some(object) = row.as_object() else {
            continue;
        };
        let record = headers
            .iter()
            .map(|header| csv_row_value(object, header))
            .collect::<Vec<_>>();
        if let Err(err) = wtr.write_record(record) {
            tracing::error!(error = %err, "aggregate.csv_row_failed");
            return Error::from(crate::error::AggregateError::ExecutionFailed).into_response();
        }
    }
    let bytes = match wtr.into_inner() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "aggregate.csv_finish_failed");
            return Error::from(crate::error::AggregateError::ExecutionFailed).into_response();
        }
    };
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv"));
    if let Some(disclosure) = envelope.get("disclosure_control") {
        if let Ok(value) = HeaderValue::from_str(&disclosure.to_string()) {
            response
                .headers_mut()
                .insert("x-registry-relay-disclosure-control", value.clone());
            response
                .headers_mut()
                .insert("x-spdci-disclosure-control", value);
        }
    }
    if let Some(freshness) = envelope.get("freshness") {
        if let Ok(value) = HeaderValue::from_str(&freshness.to_string()) {
            response
                .headers_mut()
                .insert("x-registry-relay-freshness", value.clone());
            response.headers_mut().insert("x-spdci-freshness", value);
        }
    }
    let link = format!(
        "</v1/datasets/{}/aggregates/{}/structure>; rel=\"describedby\"; type=\"application/json\"",
        result.dataset_id, result.aggregate_id
    );
    if let Ok(value) = HeaderValue::from_str(&link) {
        response.headers_mut().insert(header::LINK, value);
    }
    response
}

fn aggregate_structure_body_json(schema: &crate::query::aggregates::AggregateSchema) -> Value {
    json!({
        "dimensions": schema.dimensions.iter().map(|dimension| json!({
            "id": dimension.id,
            "label": dimension.label,
            "field": dimension.field,
            "codelist": dimension.codelist,
        })).collect::<Vec<_>>(),
        "measures": schema.indicators.iter().map(|indicator| json!({
            "id": indicator.id,
            "label": indicator.label,
            "aggregation_method": indicator.function,
            "column": indicator.column,
            "unit_measure": indicator.unit_measure,
            "unit_multiplier": indicator.unit_mult,
            "decimals": indicator.decimals,
            "frequency": indicator.frequency,
            "definition_uri": indicator.definition_uri,
        })).collect::<Vec<_>>()
    })
}

fn disclosure_json(disclosure: &crate::query::aggregates::AggregateDisclosure) -> Value {
    json!({
        "method": disclosure.method,
        "min_cell_size": disclosure.min_cell_size,
        "suppression": disclosure.suppression,
        "suppressed_observations": disclosure.suppressed_rows,
        "query_budget": {
            "tracked": disclosure.tracked_query_budget,
            "scope": disclosure.query_budget_scope
        }
    })
}

fn csv_headers(result: &AggregateResult) -> Vec<String> {
    let mut headers = result.group_by.clone();
    headers.extend(result.indicators.clone());
    for indicator in &result.indicators {
        let status_key = format!("{indicator}$status");
        if result.data.iter().any(|row| {
            row.get("attributes")
                .and_then(Value::as_object)
                .is_some_and(|attributes| attributes.contains_key(&status_key))
        }) {
            headers.push(status_key);
        }
    }
    headers
}

fn csv_row_value(object: &serde_json::Map<String, Value>, header: &str) -> String {
    object
        .get(header)
        .or_else(|| {
            object
                .get("attributes")
                .and_then(Value::as_object)
                .and_then(|attributes| attributes.get(header))
        })
        .map(csv_value)
        .unwrap_or_default()
}

fn csv_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => escape_csv_formula_cell(value),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn escape_csv_formula_cell(value: &str) -> String {
    match value.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r') => format!("'{value}"),
        _ => value.to_string(),
    }
}
