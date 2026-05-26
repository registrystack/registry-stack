// SPDX-License-Identifier: Apache-2.0
//! Dataset-scoped aggregate HTTP route declarations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{Config, DatasetConfig};
use crate::error::{AuthError, Error, FilterError, SchemaError};
use crate::ingest::ReadinessSnapshot;
use crate::query::{
    AggregateFilter, AggregateFilterOp, AggregateQueryEngine, AggregateQueryRequest,
    AggregateResult,
};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const QUERY_UNAVAILABLE_CODE: &str = "aggregate.query_unavailable";
const DATA_PURPOSE_HEADER: &str = "data-purpose";

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/datasets/{dataset_id}/aggregates", get(list_aggregates))
        .route(
            "/datasets/{dataset_id}/aggregates/{aggregate_id}",
            get(execute_aggregate),
        )
        .route(
            "/datasets/{dataset_id}/aggregates/{aggregate_id}/query",
            post(query_aggregate),
        )
        .route(
            "/datasets/{dataset_id}/aggregates/{aggregate_id}/metadata",
            get(aggregate_metadata),
        )
        .route("/datasets/{dataset_id}/indicators", get(list_indicators))
        .route(
            "/datasets/{dataset_id}/indicators/{item_id}",
            get(get_indicator),
        )
        .route("/datasets/{dataset_id}/dimensions", get(list_dimensions))
        .route(
            "/datasets/{dataset_id}/dimensions/{item_id}",
            get(get_dimension),
        )
}

#[derive(Debug, Deserialize)]
struct AggregatePath {
    dataset_id: String,
}

#[derive(Debug, Deserialize)]
struct AggregateRunPath {
    dataset_id: String,
    aggregate_id: String,
}

#[derive(Debug, Deserialize)]
struct AggregateDiscoveryPath {
    dataset_id: String,
    item_id: String,
}

#[derive(Debug, Deserialize)]
struct FormatQuery {
    #[serde(default)]
    f: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AggregateQueryBody {
    #[serde(default)]
    indicators: Option<Vec<String>>,
    #[serde(default)]
    group_by: Option<Vec<String>>,
    #[serde(default)]
    filters: BTreeMap<String, Value>,
    #[serde(default)]
    temporal: Option<TemporalFilter>,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TemporalFilter {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

async fn list_aggregates(
    Path(path): Path<AggregatePath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    if let Err(error) = require_metadata_scope(config.as_ref(), principal, &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "aggregate list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => Json(json!({
            "data": aggregates.into_iter().map(aggregate_list_json).collect::<Vec<_>>(),
            "links": [
                { "rel": "self", "href": format!("/datasets/{}/aggregates", path.dataset_id), "type": "application/json" }
            ]
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn aggregate_metadata(
    Path(path): Path<AggregateRunPath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "aggregate metadata route matched, but aggregate query state is not installed",
        );
    };
    let aggregate = match query.aggregate_config(&path.dataset_id, &path.aggregate_id) {
        Ok((dataset, aggregate)) => {
            if let Err(error) = require_metadata_scope(
                config.as_ref(),
                principal,
                &path.dataset_id,
                Some(aggregate),
            ) {
                return error.into_response();
            }
            aggregate_metadata_json(dataset, aggregate)
        }
        Err(error) => return error.into_response(),
    };
    Json(aggregate).into_response()
}

async fn list_indicators(
    Path(path): Path<AggregatePath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    if let Err(error) = require_metadata_scope(config.as_ref(), principal, &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "indicator list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => Json(json!({
            "data": indicator_discovery_items(&path.dataset_id, &aggregates),
            "links": [
                { "rel": "self", "href": format!("/datasets/{}/indicators", path.dataset_id), "type": "application/json" }
            ]
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn get_indicator(
    Path(path): Path<AggregateDiscoveryPath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    if let Err(error) = require_metadata_scope(config.as_ref(), principal, &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "indicator detail route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => indicator_discovery_items(&path.dataset_id, &aggregates)
            .into_iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(path.item_id.as_str()))
            .map(Json)
            .map(IntoResponse::into_response)
            .unwrap_or_else(|| Error::from(SchemaError::UnknownAggregate).into_response()),
        Err(error) => error.into_response(),
    }
}

async fn list_dimensions(
    Path(path): Path<AggregatePath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    if let Err(error) = require_metadata_scope(config.as_ref(), principal, &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "dimension list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => Json(json!({
            "data": dimension_discovery_items(&path.dataset_id, &aggregates),
            "links": [
                { "rel": "self", "href": format!("/datasets/{}/dimensions", path.dataset_id), "type": "application/json" }
            ]
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn get_dimension(
    Path(path): Path<AggregateDiscoveryPath>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
) -> Response {
    if let Err(error) = require_metadata_scope(config.as_ref(), principal, &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "dimension detail route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => dimension_discovery_items(&path.dataset_id, &aggregates)
            .into_iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(path.item_id.as_str()))
            .map(Json)
            .map(IntoResponse::into_response)
            .unwrap_or_else(|| Error::from(FilterError::UnknownField).into_response()),
        Err(error) => error.into_response(),
    }
}

async fn execute_aggregate(
    Path(path): Path<AggregateRunPath>,
    Query(format): Query<FormatQuery>,
    headers: HeaderMap,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
    provenance: Option<Extension<Arc<crate::provenance::ProvenanceState>>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
) -> Response {
    run_aggregate(
        path,
        headers,
        query,
        principal,
        config,
        provenance,
        readiness,
        AggregateQueryBody {
            format: format.f,
            ..AggregateQueryBody::default()
        },
    )
    .await
}

async fn query_aggregate(
    Path(path): Path<AggregateRunPath>,
    headers: HeaderMap,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
    provenance: Option<Extension<Arc<crate::provenance::ProvenanceState>>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
    Json(body): Json<AggregateQueryBody>,
) -> Response {
    run_aggregate(
        path, headers, query, principal, config, provenance, readiness, body,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_aggregate(
    path: AggregateRunPath,
    headers: HeaderMap,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    config: Option<Extension<Arc<Config>>>,
    provenance: Option<Extension<Arc<crate::provenance::ProvenanceState>>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
    body: AggregateQueryBody,
) -> Response {
    let Some(Extension(query)) = query else {
        return query_unavailable(
            "aggregate route matched, but aggregate query state is not installed",
        );
    };
    let (dataset, aggregate) = match query.aggregate_config(&path.dataset_id, &path.aggregate_id) {
        Ok(pair) => pair,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_purpose_header(dataset, aggregate, &headers) {
        return error.into_response();
    }
    if let Err(error) = require_aggregate_scope(
        config.as_ref(),
        principal,
        &path.dataset_id,
        Some(aggregate),
    ) {
        return error.into_response();
    }
    let format = body.format.clone().unwrap_or_else(|| "json".to_string());
    if format != "json" && format != "csv" {
        return Error::from(FilterError::UnsupportedOp).into_response();
    }
    let request = match aggregate_query_request(body, aggregate) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match query
        .execute_aggregate(&path.dataset_id, &path.aggregate_id, request)
        .await
    {
        Ok(result) => {
            let as_of = resolve_as_of_rfc3339(readiness.as_ref().map(|Extension(r)| r), &result);
            let envelope = aggregate_result_json(&result, as_of.as_deref());
            let plain_response = if format == "csv" {
                csv_response(&result, &envelope)
            } else {
                Json(envelope.clone()).into_response()
            };
            let mut response = crate::api::provenance_issuance::maybe_issue_aggregate_result(
                provenance.as_ref().map(|Extension(state)| state),
                config.as_ref().map(|Extension(cfg)| cfg),
                &headers,
                plain_response,
                crate::api::provenance_issuance::AggregateIssuanceArgs {
                    dataset: &path.dataset_id,
                    aggregate_id: &path.aggregate_id,
                    group_by: result.group_by.clone(),
                    indicators: result.indicators.clone(),
                    rows: result.data.clone(),
                    suppressed_rows: result.disclosure_control.suppressed_rows.unwrap_or(0),
                    min_cell_size: u64::from(result.disclosure_control.min_cell_size),
                    computed_at_rfc3339: result.computed_at.clone(),
                    as_of_rfc3339: as_of,
                },
            );
            response.extensions_mut().insert(AuditContextExt {
                dataset_id: Some(path.dataset_id),
                aggregate_id: Some(path.aggregate_id),
                row_count: Some(result.data.len() as u64),
                suppressed_groups: result.disclosure_control.suppressed_rows,
                ..AuditContextExt::default()
            });
            response
        }
        Err(error) => error.into_response(),
    }
}

fn aggregate_query_request(
    body: AggregateQueryBody,
    aggregate: &crate::config::AggregateConfig,
) -> Result<AggregateQueryRequest, Error> {
    let mut filters = Vec::new();
    for (field, value) in body.filters {
        filters.push(filter_from_value(field, value, aggregate)?);
    }
    if let Some(temporal) = body.temporal {
        append_temporal_filters(&mut filters, temporal, aggregate)?;
    }
    Ok(AggregateQueryRequest {
        indicators: body.indicators,
        group_by: body.group_by,
        filters,
        max_rows: None,
    })
}

fn append_temporal_filters(
    filters: &mut Vec<AggregateFilter>,
    temporal: TemporalFilter,
    aggregate: &crate::config::AggregateConfig,
) -> Result<(), Error> {
    let from = temporal.from.filter(|value| !value.trim().is_empty());
    let to = temporal.to.filter(|value| !value.trim().is_empty());
    if from.is_none() && to.is_none() {
        return Ok(());
    }
    let field = aggregate
        .temporal_field
        .as_ref()
        .ok_or(FilterError::NotAllowed)?;
    let allowed = aggregate
        .allowed_filters
        .iter()
        .find(|allowed| allowed.field == *field)
        .ok_or(FilterError::NotAllowed)?;
    match (from, to) {
        (Some(from), Some(to)) if allowed.ops.contains(&crate::config::FilterOp::Between) => {
            filters.push(AggregateFilter {
                field: field.clone(),
                op: AggregateFilterOp::Between,
                value: Value::Array(vec![Value::String(from), Value::String(to)]),
            });
        }
        (Some(from), Some(to))
            if allowed.ops.contains(&crate::config::FilterOp::Gte)
                && allowed.ops.contains(&crate::config::FilterOp::Lte) =>
        {
            filters.push(AggregateFilter {
                field: field.clone(),
                op: AggregateFilterOp::Gte,
                value: Value::String(from),
            });
            filters.push(AggregateFilter {
                field: field.clone(),
                op: AggregateFilterOp::Lte,
                value: Value::String(to),
            });
        }
        (Some(from), None) if allowed.ops.contains(&crate::config::FilterOp::Gte) => {
            filters.push(AggregateFilter {
                field: field.clone(),
                op: AggregateFilterOp::Gte,
                value: Value::String(from),
            });
        }
        (None, Some(to)) if allowed.ops.contains(&crate::config::FilterOp::Lte) => {
            filters.push(AggregateFilter {
                field: field.clone(),
                op: AggregateFilterOp::Lte,
                value: Value::String(to),
            });
        }
        _ => return Err(FilterError::UnsupportedOp.into()),
    }
    Ok(())
}

fn filter_from_value(
    field: String,
    value: Value,
    aggregate: &crate::config::AggregateConfig,
) -> Result<AggregateFilter, Error> {
    let allowed = aggregate
        .allowed_filters
        .iter()
        .find(|allowed| allowed.field == field)
        .ok_or(FilterError::NotAllowed)?;
    let op = match &value {
        Value::Array(_) if allowed.ops.contains(&crate::config::FilterOp::In) => {
            AggregateFilterOp::In
        }
        Value::Object(object)
            if object.contains_key("from")
                && object.contains_key("to")
                && allowed.ops.contains(&crate::config::FilterOp::Between) =>
        {
            let from = object
                .get("from")
                .cloned()
                .ok_or(FilterError::InvalidRange)?;
            let to = object.get("to").cloned().ok_or(FilterError::InvalidRange)?;
            return Ok(AggregateFilter {
                field,
                op: AggregateFilterOp::Between,
                value: Value::Array(vec![from, to]),
            });
        }
        _ if allowed.ops.contains(&crate::config::FilterOp::Eq) => AggregateFilterOp::Eq,
        _ => return Err(FilterError::UnsupportedOp.into()),
    };
    Ok(AggregateFilter { field, op, value })
}

fn aggregate_result_json(result: &AggregateResult, as_of: Option<&str>) -> Value {
    let mut freshness = json!({ "computed_at": result.computed_at });
    if let Some(as_of) = as_of {
        freshness["as_of"] = json!(as_of);
    }
    json!({
        "dataset_id": result.dataset_id,
        "aggregate_id": result.aggregate_id,
        "data": result.data,
        "schema": aggregate_schema_json(&result.schema),
        "disclosure_control": disclosure_json(&result.disclosure_control),
        "freshness": freshness,
        "links": [
            { "rel": "self", "href": format!("/datasets/{}/aggregates/{}", result.dataset_id, result.aggregate_id), "type": "application/json" },
            { "rel": "describedby", "href": format!("/datasets/{}/aggregates/{}/metadata", result.dataset_id, result.aggregate_id), "type": "application/json" }
        ]
    })
}

fn aggregate_schema_json(schema: &crate::query::aggregates::AggregateSchema) -> Value {
    json!({
        "dimensions": schema.dimensions.iter().map(|dimension| json!({
            "id": dimension.id,
            "label": dimension.label,
            "field": dimension.field,
            "codelist": dimension.codelist,
        })).collect::<Vec<_>>(),
        "indicators": schema.indicators.iter().map(|indicator| json!({
            "id": indicator.id,
            "label": indicator.label,
            "aggregation_method": indicator.function,
            "column": indicator.column,
            "unit_measure": indicator.unit_measure,
            "unit_mult": indicator.unit_mult,
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
        "suppressed_rows": disclosure.suppressed_rows,
        "query_budget": {
            "tracked": disclosure.tracked_query_budget,
            "scope": disclosure.query_budget_scope
        }
    })
}

fn aggregate_list_json(item: crate::query::aggregates::AggregateListItem) -> Value {
    json!({
        "aggregate_id": item.aggregate_id,
        "title": item.title,
        "description": item.description,
        "default_group_by": item.default_group_by,
        "dimensions": item.dimensions.into_iter().map(|dimension| json!({
            "id": dimension.id,
            "label": dimension.label,
            "field": dimension.field,
            "codelist": dimension.codelist,
        })).collect::<Vec<_>>(),
        "indicators": item.indicators.into_iter().map(|indicator| json!({
            "id": indicator.id,
            "label": indicator.label,
            "aggregation_method": indicator.function,
            "column": indicator.column,
            "unit_measure": indicator.unit_measure,
            "unit_mult": indicator.unit_mult,
            "decimals": indicator.decimals,
            "frequency": indicator.frequency,
            "definition_uri": indicator.definition_uri,
        })).collect::<Vec<_>>(),
        "min_cell_size": item.min_cell_size,
        "temporal_field": item.temporal_field,
        "edr_collection_id": item.collection_id,
    })
}

fn aggregate_metadata_json(
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
) -> Value {
    let item = crate::query::aggregates::AggregateListItem {
        aggregate_id: aggregate.id.to_string(),
        title: aggregate.title.clone(),
        description: aggregate.description.clone(),
        dimensions: aggregate
            .dimensions
            .iter()
            .map(
                |dimension| crate::query::aggregates::AggregateDimensionItem {
                    id: dimension.id.clone(),
                    label: dimension.label.clone(),
                    field: dimension.field.clone(),
                    codelist: dimension.codelist.clone(),
                },
            )
            .collect(),
        indicators: aggregate
            .indicators
            .iter()
            .map(
                |indicator| crate::query::aggregates::AggregateIndicatorItem {
                    id: indicator.id.clone(),
                    label: indicator.label.clone(),
                    function: match indicator.function {
                        crate::config::AggregateFunction::Count => "count",
                        crate::config::AggregateFunction::Sum => "sum",
                        crate::config::AggregateFunction::Avg => "avg",
                        crate::config::AggregateFunction::Min => "min",
                        crate::config::AggregateFunction::Max => "max",
                        crate::config::AggregateFunction::Median => "median",
                        crate::config::AggregateFunction::CountDistinct => "count_distinct",
                        crate::config::AggregateFunction::Stddev => "stddev",
                    },
                    column: indicator.column.clone(),
                    unit_measure: indicator.unit_measure.clone(),
                    unit_mult: indicator.unit_mult,
                    decimals: indicator.decimals,
                    frequency: indicator.frequency.clone(),
                    definition_uri: indicator.definition_uri.clone(),
                },
            )
            .collect(),
        default_group_by: aggregate.default_group_by.clone(),
        temporal_field: aggregate.temporal_field.clone(),
        min_cell_size: aggregate.disclosure_control.effective_min_cell_size(),
        collection_id: crate::query::aggregates::aggregate_edr_collection_id(dataset, aggregate),
    };
    aggregate_list_json(item)
}

fn indicator_discovery_items(
    dataset_id: &str,
    aggregates: &[crate::query::aggregates::AggregateListItem],
) -> Vec<Value> {
    let mut items = BTreeMap::<String, IndicatorDiscovery>::new();
    for aggregate in aggregates {
        let aggregate_ref = AggregateDiscoveryRef::new(dataset_id, aggregate);
        let dimensions = aggregate
            .dimensions
            .iter()
            .map(|dimension| dimension.id.clone())
            .collect::<Vec<_>>();
        for indicator in &aggregate.indicators {
            let item = items
                .entry(indicator.id.clone())
                .or_insert_with(|| IndicatorDiscovery::new(indicator));
            item.valid_dimensions.extend(dimensions.iter().cloned());
            item.queryable_via
                .extend(aggregate_ref.queryable_via().into_iter());
            item.aggregates.push(aggregate_ref.as_json());
        }
    }
    items
        .into_values()
        .map(|item| item.into_json(dataset_id))
        .collect()
}

fn dimension_discovery_items(
    dataset_id: &str,
    aggregates: &[crate::query::aggregates::AggregateListItem],
) -> Vec<Value> {
    let mut items = BTreeMap::<String, DimensionDiscovery>::new();
    for aggregate in aggregates {
        let aggregate_ref = AggregateDiscoveryRef::new(dataset_id, aggregate);
        for dimension in &aggregate.dimensions {
            let item = items
                .entry(dimension.id.clone())
                .or_insert_with(|| DimensionDiscovery::new(dimension));
            item.queryable_via
                .extend(aggregate_ref.queryable_via().into_iter());
            item.aggregates.push(aggregate_ref.as_json());
        }
    }
    items
        .into_values()
        .map(|item| item.into_json(dataset_id))
        .collect()
}

struct IndicatorDiscovery {
    id: String,
    label: String,
    function: &'static str,
    column: String,
    unit_measure: String,
    unit_mult: Option<i32>,
    decimals: Option<u32>,
    frequency: Option<String>,
    definition_uri: Option<String>,
    valid_dimensions: BTreeSet<String>,
    queryable_via: BTreeSet<String>,
    aggregates: Vec<Value>,
}

impl IndicatorDiscovery {
    fn new(indicator: &crate::query::aggregates::AggregateIndicatorItem) -> Self {
        Self {
            id: indicator.id.clone(),
            label: indicator.label.clone(),
            function: indicator.function,
            column: indicator.column.clone(),
            unit_measure: indicator.unit_measure.clone(),
            unit_mult: indicator.unit_mult,
            decimals: indicator.decimals,
            frequency: indicator.frequency.clone(),
            definition_uri: indicator.definition_uri.clone(),
            valid_dimensions: BTreeSet::new(),
            queryable_via: BTreeSet::new(),
            aggregates: Vec::new(),
        }
    }

    fn into_json(self, dataset_id: &str) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "aggregation_method": self.function,
            "column": self.column,
            "unit_measure": self.unit_measure,
            "unit_mult": self.unit_mult,
            "decimals": self.decimals,
            "frequency": self.frequency,
            "definition_uri": self.definition_uri,
            "valid_dimensions": self.valid_dimensions.into_iter().collect::<Vec<_>>(),
            "queryable_via": self.queryable_via.into_iter().collect::<Vec<_>>(),
            "aggregates": self.aggregates,
            "links": [
                { "rel": "self", "href": format!("/datasets/{dataset_id}/indicators/{}", self.id), "type": "application/json" }
            ]
        })
    }
}

struct DimensionDiscovery {
    id: String,
    label: String,
    field: String,
    codelist: Option<String>,
    queryable_via: BTreeSet<String>,
    aggregates: Vec<Value>,
}

impl DimensionDiscovery {
    fn new(dimension: &crate::query::aggregates::AggregateDimensionItem) -> Self {
        Self {
            id: dimension.id.clone(),
            label: dimension.label.clone(),
            field: dimension.field.clone(),
            codelist: dimension.codelist.clone(),
            queryable_via: BTreeSet::new(),
            aggregates: Vec::new(),
        }
    }

    fn into_json(self, dataset_id: &str) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "field": self.field,
            "codelist": self.codelist,
            "queryable_via": self.queryable_via.into_iter().collect::<Vec<_>>(),
            "aggregates": self.aggregates,
            "links": [
                { "rel": "self", "href": format!("/datasets/{dataset_id}/dimensions/{}", self.id), "type": "application/json" }
            ]
        })
    }
}

struct AggregateDiscoveryRef<'a> {
    dataset_id: &'a str,
    aggregate_id: &'a str,
    collection_id: Option<&'a str>,
}

impl<'a> AggregateDiscoveryRef<'a> {
    fn new(
        dataset_id: &'a str,
        aggregate: &'a crate::query::aggregates::AggregateListItem,
    ) -> Self {
        Self {
            dataset_id,
            aggregate_id: &aggregate.aggregate_id,
            collection_id: aggregate.collection_id.as_deref(),
        }
    }

    fn queryable_via(&self) -> Vec<String> {
        let mut values = vec![format!("aggregates:{}", self.aggregate_id)];
        if let Some(collection_id) = self.collection_id {
            values.push(format!("edr:{collection_id}"));
        }
        values
    }

    fn as_json(&self) -> Value {
        let mut value = json!({
            "aggregate_id": self.aggregate_id,
            "href": format!("/datasets/{}/aggregates/{}", self.dataset_id, self.aggregate_id),
        });
        if let Some(collection_id) = self.collection_id {
            value["edr_collection_id"] = json!(collection_id);
            value["edr_area_href"] = json!(format!("/ogc/edr/v1/collections/{collection_id}/area"));
        }
        value
    }
}

fn csv_response(result: &AggregateResult, envelope: &Value) -> Response {
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
        "</datasets/{}/aggregates/{}/metadata>; rel=\"describedby\"; type=\"application/json\"",
        result.dataset_id, result.aggregate_id
    );
    if let Ok(value) = HeaderValue::from_str(&link) {
        response.headers_mut().insert(header::LINK, value);
    }
    response
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
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn require_metadata_scope(
    config: Option<&Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
    dataset_id: &str,
    aggregate: Option<&crate::config::AggregateConfig>,
) -> Result<(), Error> {
    let required = aggregate
        .and_then(|aggregate| aggregate.access.as_ref())
        .and_then(|access| access.metadata_scope.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{dataset_id}:metadata"));
    require_principal_scope(principal, &required)?;
    let _ = config;
    Ok(())
}

fn require_aggregate_scope(
    config: Option<&Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
    dataset_id: &str,
    aggregate: Option<&crate::config::AggregateConfig>,
) -> Result<(), Error> {
    let required = aggregate
        .and_then(|aggregate| aggregate.access.as_ref())
        .and_then(|access| access.aggregate_scope.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{dataset_id}:aggregate"));
    require_principal_scope(principal, &required)?;
    let _ = config;
    Ok(())
}

fn require_principal_scope(
    principal: Option<Extension<Principal>>,
    required: &str,
) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, required)
}

fn require_purpose_header(
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
    headers: &HeaderMap,
) -> Result<(), Error> {
    let Some(source_entity) = aggregate.source_entity.as_deref() else {
        return Err(SchemaError::UnknownAggregate.into());
    };
    let require = dataset
        .entities
        .iter()
        .find(|entity| entity.name == source_entity)
        .is_some_and(|entity| entity.api.require_purpose_header);
    if !require {
        return Ok(());
    }
    let present = headers
        .get(DATA_PURPOSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().is_empty());
    if present {
        Ok(())
    } else {
        Err(AuthError::PurposeRequired.into())
    }
}

fn resolve_as_of_rfc3339(
    readiness: Option<&watch::Receiver<ReadinessSnapshot>>,
    result: &AggregateResult,
) -> Option<String> {
    let readiness = readiness?;
    let snapshot = readiness.borrow();
    let mut timestamps = Vec::new();
    for table_id in &result.source_tables {
        let dataset_key = id_from_str::<crate::config::DatasetId>(&result.dataset_id)?;
        let resource_key = id_from_str::<crate::config::ResourceId>(table_id)?;
        let entry = snapshot.ready.get(&(dataset_key, resource_key))?;
        timestamps.push(entry.registered_at);
    }
    timestamps
        .into_iter()
        .min()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn id_from_str<T>(value: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(&format!(r#""{value}""#)).ok()
}

fn query_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": format!("{}aggregate/query_unavailable", crate::error::PROBLEM_TYPE_BASE),
            "title": "Aggregate query unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": QUERY_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(QUERY_UNAVAILABLE_CODE.to_string()));
    response
}
