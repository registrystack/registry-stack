// SPDX-License-Identifier: Apache-2.0
//! Dataset-scoped aggregate HTTP route declarations.

mod discovery;
mod format;
mod response;
mod sdmx;

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::api::governed::{
    attach_pdp_audit, require_governed_read_access, GovernedAccessError, GovernedReadDecision,
};
use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{DatasetConfig, EntityConfig};
use crate::error::{AuthError, Error, FilterError, SchemaError};
use crate::ingest::ReadinessSnapshot;
use crate::query::{AggregateFilter, AggregateFilterOp, AggregateQueryRequest, AggregateResult};
use crate::runtime_config::RuntimeSnapshot;

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const QUERY_UNAVAILABLE_CODE: &str = "aggregate.query_unavailable";

/// Official SDMX-JSON 2.1 data message schema vendored for offline validation.
pub const SDMX_JSON_DATA_SCHEMA_2_1: &[u8] =
    include_bytes!("../../resources/schemas/sdmx-json/2.1/sdmx-json-data-schema.json");

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/v1/datasets/{dataset_id}/aggregates", get(list_aggregates))
        .route(
            "/v1/datasets/{dataset_id}/aggregates/{aggregate_id}",
            get(execute_aggregate),
        )
        .route(
            "/v1/datasets/{dataset_id}/aggregates/{aggregate_id}/query",
            post(query_aggregate),
        )
        .route(
            "/v1/datasets/{dataset_id}/aggregates/{aggregate_id}/metadata",
            get(aggregate_structure),
        )
        .route(
            "/v1/datasets/{dataset_id}/aggregates/{aggregate_id}/structure",
            get(aggregate_structure),
        )
        .route("/v1/datasets/{dataset_id}/measures", get(list_measures))
        .route(
            "/v1/datasets/{dataset_id}/measures/{item_id}",
            get(get_measure),
        )
        .route("/v1/datasets/{dataset_id}/dimensions", get(list_dimensions))
        .route(
            "/v1/datasets/{dataset_id}/dimensions/{item_id}",
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
    measures: Option<Vec<String>>,
    #[serde(default)]
    group_by: Option<Vec<String>>,
    #[serde(default)]
    filters: BTreeMap<String, Value>,
    #[serde(default)]
    temporal: Option<TemporalFilter>,
    #[serde(default)]
    max_rows: Option<usize>,
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_metadata_scope(principal.clone(), &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "aggregate list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => {
            let aggregates = discovery::filter_visible_aggregates(principal.as_ref(), aggregates);
            Json(json!({
                "data": aggregates.into_iter().map(discovery::aggregate_list_json).collect::<Vec<_>>(),
                "links": [
                    { "rel": "self", "href": format!("/v1/datasets/{}/aggregates", path.dataset_id), "type": "application/json" }
                ]
            }))
            .into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn aggregate_structure(
    Path(path): Path<AggregateRunPath>,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "aggregate metadata route matched, but aggregate query state is not installed",
        );
    };
    let aggregate = match query.aggregate_config(&path.dataset_id, &path.aggregate_id) {
        Ok((dataset, aggregate)) => {
            if let Err(error) =
                require_metadata_scope(principal.clone(), &path.dataset_id, Some(aggregate))
            {
                return error.into_response();
            }
            if let Err(error) = require_source_entity_metadata_scope(principal, dataset, aggregate)
            {
                return error.into_response();
            }
            discovery::aggregate_structure_json(dataset, aggregate)
        }
        Err(error) => return error.into_response(),
    };
    Json(aggregate).into_response()
}

async fn list_measures(
    Path(path): Path<AggregatePath>,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_metadata_scope(principal.clone(), &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "measure list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => Json(json!({
            "data": discovery::measure_discovery_items(
                &path.dataset_id,
                &discovery::filter_visible_aggregates(principal.as_ref(), aggregates),
            ),
            "links": [
                { "rel": "self", "href": format!("/v1/datasets/{}/measures", path.dataset_id), "type": "application/json" }
            ]
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn get_measure(
    Path(path): Path<AggregateDiscoveryPath>,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_metadata_scope(principal.clone(), &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "measure detail route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => discovery::measure_discovery_items(
            &path.dataset_id,
            &discovery::filter_visible_aggregates(principal.as_ref(), aggregates),
        )
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
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_metadata_scope(principal.clone(), &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "dimension list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => Json(json!({
            "data": discovery::dimension_discovery_items(
                &path.dataset_id,
                &discovery::filter_visible_aggregates(principal.as_ref(), aggregates),
            ),
            "links": [
                { "rel": "self", "href": format!("/v1/datasets/{}/dimensions", path.dataset_id), "type": "application/json" }
            ]
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn get_dimension(
    Path(path): Path<AggregateDiscoveryPath>,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_metadata_scope(principal.clone(), &path.dataset_id, None) {
        return error.into_response();
    }
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "dimension detail route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id) {
        Ok(aggregates) => discovery::dimension_discovery_items(
            &path.dataset_id,
            &discovery::filter_visible_aggregates(principal.as_ref(), aggregates),
        )
        .into_iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(path.item_id.as_str()))
        .map(Json)
        .map(IntoResponse::into_response)
        .unwrap_or_else(|| Error::from(FilterError::UnknownField).into_response()),
        Err(error) => error.into_response(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_aggregate(
    Path(path): Path<AggregateRunPath>,
    Query(format): Query<FormatQuery>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    run_aggregate(
        path,
        headers,
        runtime,
        principal,
        AggregateQueryBody {
            format: format.f,
            ..AggregateQueryBody::default()
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn query_aggregate(
    Path(path): Path<AggregateRunPath>,
    Query(format): Query<FormatQuery>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
    Json(mut body): Json<AggregateQueryBody>,
) -> Response {
    body.format = format.f.or(body.format);
    run_aggregate(path, headers, runtime, principal, body).await
}

async fn run_aggregate(
    path: AggregateRunPath,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
    body: AggregateQueryBody,
) -> Response {
    let Some(query) = runtime.aggregate_query() else {
        return query_unavailable(
            "aggregate route matched, but aggregate query state is not installed",
        );
    };
    let (dataset, aggregate) = match query.aggregate_config(&path.dataset_id, &path.aggregate_id) {
        Ok(pair) => pair,
        Err(error) => return error.into_response(),
    };
    let governed_decision = match require_source_entity_governed_access(
        &runtime,
        &path.dataset_id,
        dataset,
        aggregate,
        &headers,
    ) {
        Ok(decision) => decision,
        Err(error) => return aggregate_access_error_response(error, &path),
    };
    if let Err(error) =
        require_aggregate_scope(principal.clone(), &path.dataset_id, Some(aggregate))
    {
        return error.into_response();
    }
    if let Err(error) = require_source_entity_read_scope(principal, dataset, aggregate) {
        return error.into_response();
    }
    let signed_vc_requested = crate::api::provenance_issuance::signed_vc_requested(
        runtime.provenance_state().as_ref(),
        &headers,
    )
    .is_some();
    let format = if signed_vc_requested {
        format::AggregateResponseFormat::Json
    } else {
        match format::aggregate_response_format(&headers, body.format.as_deref()) {
            Ok(format) => format,
            Err(error) => return error.into_response(),
        }
    };
    let request = match aggregate_query_request(body, aggregate) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match query
        .execute_aggregate(&path.dataset_id, &path.aggregate_id, request)
        .await
    {
        Ok(mut result) => {
            redact_aggregate_result(&mut result, &governed_decision.redaction_fields);
            let readiness = runtime.readiness_rx();
            let as_of = resolve_as_of_rfc3339(readiness.as_ref(), &result);
            let envelope = response::aggregate_result_json(&result, as_of.as_deref());
            let plain_response = match format {
                format::AggregateResponseFormat::Csv => response::csv_response(&result, &envelope),
                format::AggregateResponseFormat::SdmxJson => {
                    sdmx::sdmx_json_response(&result, as_of.as_deref())
                }
                format::AggregateResponseFormat::Json => Json(envelope.clone()).into_response(),
            };
            let mut response = crate::api::provenance_issuance::maybe_issue_aggregate_result(
                runtime.provenance_state().as_ref(),
                runtime.config().as_ref(),
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
            let mut audit_context = Some(AuditContextExt {
                dataset_id: Some(path.dataset_id),
                aggregate_id: Some(path.aggregate_id),
                row_count: Some(result.data.len() as u64),
                suppressed_groups: result.disclosure_control.suppressed_rows,
                ..AuditContextExt::default()
            });
            attach_pdp_audit(&mut audit_context, governed_decision.audit.as_ref());
            if let Some(context) = audit_context {
                response.extensions_mut().insert(context);
            }
            vary_accept(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

pub(crate) fn redact_aggregate_result(
    result: &mut AggregateResult,
    field_names: &BTreeSet<String>,
) {
    if field_names.is_empty() {
        return;
    }
    let row_fields = aggregate_row_fields_to_redact(result, field_names);
    for row in &mut result.data {
        redact_aggregate_row(row, &row_fields);
    }
    result.group_by.retain(|field| !row_fields.contains(field));
    result
        .indicators
        .retain(|field| !row_fields.contains(field));
    result.schema.dimensions.retain(|dimension| {
        !field_names.contains(&dimension.id) && !field_names.contains(&dimension.field)
    });
    result.schema.indicators.retain(|indicator| {
        !field_names.contains(&indicator.id) && !field_names.contains(&indicator.column)
    });
}

fn aggregate_row_fields_to_redact(
    result: &AggregateResult,
    field_names: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut row_fields = field_names.clone();
    for dimension in &result.schema.dimensions {
        if field_names.contains(&dimension.id) || field_names.contains(&dimension.field) {
            row_fields.insert(dimension.id.clone());
        }
    }
    for indicator in &result.schema.indicators {
        if field_names.contains(&indicator.id) || field_names.contains(&indicator.column) {
            row_fields.insert(indicator.id.clone());
        }
    }
    row_fields
}

fn redact_aggregate_row(row: &mut Value, field_names: &BTreeSet<String>) {
    let Value::Object(object) = row else {
        return;
    };
    for field_name in field_names {
        object.remove(field_name);
        if let Some(attributes) = object.get_mut("attributes").and_then(Value::as_object_mut) {
            attributes.remove(&format!("{field_name}$status"));
        }
    }
}

fn vary_accept(response: &mut Response) {
    let headers = response.headers_mut();
    let Some(current) = headers
        .get(header::VARY)
        .and_then(|value| value.to_str().ok())
    else {
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
        return;
    };
    if current
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case("accept"))
    {
        return;
    }
    let Ok(value) = HeaderValue::from_str(&format!("{current}, Accept")) else {
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
        return;
    };
    headers.insert(header::VARY, value);
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
        indicators: body.measures.or(body.indicators),
        group_by: body.group_by,
        filters,
        max_rows: body.max_rows,
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

fn require_metadata_scope(
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
    Ok(())
}

fn require_aggregate_scope(
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

fn require_source_entity_governed_access(
    runtime: &RuntimeSnapshot,
    dataset_id: &str,
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
    headers: &HeaderMap,
) -> Result<GovernedReadDecision, GovernedAccessError> {
    let entity = source_entity(dataset, aggregate).map_err(GovernedAccessError::from)?;
    require_governed_read_access(runtime, dataset_id, entity, headers)
}

fn aggregate_access_error_response(
    error: GovernedAccessError,
    path: &AggregateRunPath,
) -> Response {
    let mut audit_context = Some(AuditContextExt {
        dataset_id: Some(path.dataset_id.clone()),
        aggregate_id: Some(path.aggregate_id.clone()),
        ..AuditContextExt::default()
    });
    attach_pdp_audit(&mut audit_context, error.pdp_audit.as_ref());
    let mut response = error.error.into_response();
    if let Some(context) = audit_context {
        response.extensions_mut().insert(context);
    }
    response
}

fn require_source_entity_metadata_scope(
    principal: Option<Extension<Principal>>,
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
) -> Result<(), Error> {
    require_principal_scope(
        principal,
        &source_entity(dataset, aggregate)?.access.metadata_scope,
    )
}

fn require_source_entity_read_scope(
    principal: Option<Extension<Principal>>,
    dataset: &DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
) -> Result<(), Error> {
    if aggregate
        .access
        .as_ref()
        .is_some_and(|access| access.aggregate_only_execution)
    {
        return Ok(());
    }
    require_principal_scope(
        principal,
        &source_entity(dataset, aggregate)?.access.read_scope,
    )
}

fn source_entity<'a>(
    dataset: &'a DatasetConfig,
    aggregate: &crate::config::AggregateConfig,
) -> Result<&'a EntityConfig, Error> {
    let Some(source_entity) = aggregate.source_entity.as_deref() else {
        return Err(SchemaError::UnknownAggregate.into());
    };
    dataset
        .entities
        .iter()
        .find(|entity| entity.name == source_entity)
        .ok_or_else(|| SchemaError::UnknownAggregate.into())
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
