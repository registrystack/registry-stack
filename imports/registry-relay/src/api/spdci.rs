// SPDX-License-Identifier: Apache-2.0
//! Optional SP DCI standards adapter routes.
//!
//! The adapter is intentionally thin: Registry Relay still owns source
//! ingestion, authorization, filtering, and entity projection. These
//! routes translate the SP DCI Disability Registry synchronous request
//! envelope onto one configured entity.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Json, Path};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json as JsonResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::audit::AuditContextExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{Config, SpdciDisabilityRegistryConfig, SpdciRegistryConfig};
use crate::entity::EntityModel;
use crate::error::{AuthError, Error, FilterError, InternalError, SchemaError, SpdciError};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine};
use crate::runtime_config::RuntimeSnapshot;
use crate::spdci::SpdciResponseMapper;

/// Header fields the SP DCI standard marks `required` on inbound
/// requests (see `MsgHeader_V1.0.0.yaml`).
const REQUIRED_HEADER_FIELDS: &[&str] = &[
    "message_id",
    "message_ts",
    "action",
    "sender_id",
    "total_count",
];

struct RouteDeps {
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
}

impl<S> FromRequestParts<S> for RouteDeps
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            runtime: RuntimeSnapshot::from_request_parts(parts, state).await?,
            principal: Option::<Extension<Principal>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None),
        })
    }
}

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/dci/{registry}/registry/sync/search",
            post(sync_search_for_registry),
        )
        .route(
            "/dci/{registry}/registry/sync/disabled",
            post(disabled_status),
        )
        .route(
            "/dci/{registry}/registry/sync/get-disability-details",
            post(disability_details),
        )
        .route(
            "/dci/{registry}/registry/sync/get-disability-support",
            post(disability_support),
        )
}

async fn sync_search_for_registry(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    deps: RouteDeps,
    Json(body): Json<Value>,
) -> Response {
    sync_search_response(headers, Some(registry_name), deps, body).await
}

async fn disabled_status(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    deps: RouteDeps,
    Json(body): Json<Value>,
) -> Response {
    let RouteDeps { runtime, principal } = deps;
    let route = match RouteState::resolve(&runtime, &registry_name) {
        Ok(route) => route,
        Err(error) => return error.into_response(),
    };
    let result = run_disabled_status(&route, headers, principal, body).await;
    let (response, row_count) = match result {
        Ok(value) => value,
        Err(error) => (error.into_response(), 0),
    };
    with_audit_context(response, &route, row_count)
}

async fn run_disabled_status(
    route: &RouteState,
    headers: HeaderMap,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Result<(Response, u64), Error> {
    require_scope_for(principal, &route.entity.access.evidence_verification_scope)?;
    let request = SpdciRequest::from_body(body, &route.config)?;
    let rows = read_rows(route, &request, Some(projected_status_fields(route))).await?;
    let row_count = rows.len() as u64;
    let disabled = rows.first().is_some_and(|row| {
        row.get(&route.config.disabled_status_field)
            .is_some_and(|value| positive_status(value, &route.config.disabled_positive_values))
    });

    let message = json!({
        "transaction_id": request.transaction_id,
        "correlation_id": request.correlation_id,
        "disabled_response": [{
            "reference_id": request.reference_id,
            "timestamp": now_rfc3339(),
            "status": "succ",
            "disabled_status": if disabled { "yes" } else { "no" },
        }],
    });
    // disabled_status is a single yes/no answer per the SP DCI spec, so
    // the wire envelope always reports total_count = 1 even when 0 rows
    // matched the query. The audit row_count is the real cardinality.
    const DISABLED_STATUS_TOTAL_COUNT: u64 = 1;
    Ok((
        spdci_envelope_with_count("on-search", message, &headers, DISABLED_STATUS_TOTAL_COUNT),
        row_count,
    ))
}

async fn sync_search_response(
    headers: HeaderMap,
    registry_name: Option<String>,
    deps: RouteDeps,
    body: Value,
) -> Response {
    let RouteDeps { runtime, principal } = deps;
    let route = match SearchRouteState::resolve(&runtime, registry_name.as_deref()) {
        Ok(route) => route,
        Err(error) => return error.into_response(),
    };
    let response_mapper = runtime.spdci_response_mapper();
    let result =
        run_sync_search_response(&route, headers, response_mapper.as_deref(), principal, body)
            .await;
    let (response, total_count) = match result {
        Ok((response, total_count)) => (response, total_count),
        Err(error) => (error.into_response(), 0),
    };
    with_search_audit_context(response, &route, total_count)
}

async fn run_sync_search_response(
    route: &SearchRouteState,
    headers: HeaderMap,
    response_mapper: Option<&SpdciResponseMapper>,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Result<(Response, u64), Error> {
    require_scope_for(principal, &route.entity.access.read_scope)?;
    let request = SearchRequest::from_body(body, &route.config)?;
    let mut search_response = Vec::with_capacity(request.items.len());
    let mut total_count = 0_u64;
    for item in request.items {
        let rows = read_search_rows(route, &item).await?;
        total_count += rows.len() as u64;
        let reg_records =
            project_search_records(&route.registry_name, &route.config, response_mapper, rows)?;
        search_response.push(json!({
            "reference_id": item.reference_id,
            "timestamp": now_rfc3339(),
            "status": "succ",
            "data": {
                "version": "1.0.0",
                "reg_type": route.config.registry_type,
                "reg_record_type": route.config.record_type,
                "reg_records": reg_records,
            },
        }));
    }
    let message = json!({
        "transaction_id": request.transaction_id,
        "correlation_id": request.correlation_id,
        "search_response": search_response,
    });
    Ok((
        spdci_envelope_with_count("on-search", message, &headers, total_count),
        total_count,
    ))
}

async fn disability_details(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    deps: RouteDeps,
    Json(body): Json<Value>,
) -> Response {
    search_response(headers, registry_name, deps, body).await
}

async fn disability_support(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    deps: RouteDeps,
    Json(body): Json<Value>,
) -> Response {
    search_response(headers, registry_name, deps, body).await
}

async fn search_response(
    headers: HeaderMap,
    registry_name: String,
    deps: RouteDeps,
    body: Value,
) -> Response {
    let RouteDeps { runtime, principal } = deps;
    // Look up the named-registry config so its `response_fields` /
    // mapping path drive projection through the same code path as
    // `sync_search`. `RouteState::resolve` below requires the same
    // entry, so the lookup is guaranteed to succeed when route
    // resolution does.
    let named_search_config = runtime.config().and_then(|cfg| {
        cfg.standards
            .spdci
            .as_ref()
            .and_then(|spdci| spdci.registries.get(&registry_name).cloned())
    });
    let route = match RouteState::resolve(&runtime, &registry_name) {
        Ok(route) => route,
        Err(error) => return error.into_response(),
    };
    let response_mapper = runtime.spdci_response_mapper();
    let search_registry_config = named_search_config
        .expect("named_search_config must be Some when RouteState::resolve succeeded");
    let result = run_search_response(
        &route,
        &registry_name,
        &search_registry_config,
        headers,
        response_mapper.as_deref(),
        principal,
        body,
    )
    .await;
    let (response, row_count) = match result {
        Ok((response, count)) => (response, count),
        Err(error) => (error.into_response(), 0),
    };
    with_audit_context(response, &route, row_count)
}

async fn run_search_response(
    route: &RouteState,
    registry_name: &str,
    search_registry_config: &SpdciRegistryConfig,
    headers: HeaderMap,
    response_mapper: Option<&SpdciResponseMapper>,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Result<(Response, u64), Error> {
    require_scope_for(principal, &route.entity.access.read_scope)?;
    let request = SpdciRequest::from_body(body, &route.config)?;
    let rows = read_rows(route, &request, None).await?;
    let row_count = rows.len() as u64;
    let reg_records =
        project_search_records(registry_name, search_registry_config, response_mapper, rows)?;
    let message = json!({
        "transaction_id": request.transaction_id,
        "correlation_id": request.correlation_id,
        "search_response": [{
            "reference_id": request.reference_id,
            "timestamp": now_rfc3339(),
            "status": "succ",
            "data": {
                "version": "1.0.0",
                "reg_records": reg_records,
            },
        }],
    });
    Ok((
        spdci_envelope_with_count("on-search", message, &headers, row_count),
        row_count,
    ))
}

struct RouteState {
    config: SpdciDisabilityRegistryConfig,
    entity: EntityModel,
    query: Arc<EntityQueryEngine>,
}

struct SearchRouteState {
    registry_name: String,
    config: SpdciRegistryConfig,
    entity: EntityModel,
    query: Arc<EntityQueryEngine>,
}

impl RouteState {
    fn resolve(runtime: &RuntimeSnapshot, registry_name: &str) -> Result<Self, Error> {
        let config = runtime.config().ok_or(SchemaError::UnknownResource)?;
        let disability = resolve_disability_config(&config, registry_name)?;
        let registry = runtime
            .entity_registry()
            .ok_or(SchemaError::UnknownResource)?;
        let entity = registry
            .dataset(disability.dataset.as_str())
            .and_then(|dataset| dataset.entity(&disability.entity))
            .cloned()
            .ok_or(SchemaError::UnknownResource)?;
        let query = runtime.query().ok_or(SchemaError::UnknownResource)?;
        Ok(Self {
            config: disability,
            entity,
            query,
        })
    }
}

fn resolve_disability_config(
    config: &Config,
    registry_name: &str,
) -> Result<SpdciDisabilityRegistryConfig, Error> {
    let spdci = config
        .standards
        .spdci
        .as_ref()
        .ok_or(SchemaError::UnknownResource)?;
    let disability = spdci
        .disability_registry
        .clone()
        .ok_or(SchemaError::UnknownResource)?;
    if let Some(registry) = spdci.registries.get(registry_name) {
        if registry.dataset == disability.dataset && registry.entity == disability.entity {
            return Ok(disability);
        }
        return Err(SchemaError::UnknownResource.into());
    }
    Err(SchemaError::UnknownResource.into())
}

impl SearchRouteState {
    fn resolve(runtime: &RuntimeSnapshot, registry_name: Option<&str>) -> Result<Self, Error> {
        let config = runtime.config().ok_or(SchemaError::UnknownResource)?;
        let (resolved_name, search) = resolve_search_config(&config, registry_name)?;
        let registry = runtime
            .entity_registry()
            .ok_or(SchemaError::UnknownResource)?;
        let entity = registry
            .dataset(search.dataset.as_str())
            .and_then(|dataset| dataset.entity(&search.entity))
            .cloned()
            .ok_or(SchemaError::UnknownResource)?;
        let query = runtime.query().ok_or(SchemaError::UnknownResource)?;
        Ok(Self {
            registry_name: resolved_name,
            config: search,
            entity,
            query,
        })
    }
}

fn resolve_search_config(
    config: &Config,
    registry_name: Option<&str>,
) -> Result<(String, SpdciRegistryConfig), Error> {
    let spdci = config
        .standards
        .spdci
        .as_ref()
        .ok_or(SchemaError::UnknownResource)?;
    if let Some(name) = registry_name {
        return spdci
            .registries
            .get(name)
            .cloned()
            .map(|registry| (name.to_string(), registry))
            .ok_or_else(|| SchemaError::UnknownResource.into());
    }
    if spdci.registries.len() == 1 {
        return spdci
            .registries
            .iter()
            .next()
            .map(|(name, registry)| (name.clone(), registry.clone()))
            .ok_or_else(|| SchemaError::UnknownResource.into());
    }
    Err(SchemaError::UnknownResource.into())
}

struct SpdciRequest {
    transaction_id: String,
    correlation_id: String,
    reference_id: String,
    query_value: Value,
}

struct SearchRequest {
    transaction_id: String,
    correlation_id: String,
    items: Vec<SearchRequestItem>,
}

struct SearchRequestItem {
    reference_id: String,
    filters: Vec<EntityFilter>,
    limit: usize,
}

impl SpdciRequest {
    fn from_body(body: Value, config: &SpdciDisabilityRegistryConfig) -> Result<Self, Error> {
        let message = validated_message(&body)?;
        let transaction_id = required_transaction_id(message)?;
        let correlation_id = optional_correlator(message, "correlation_id", &transaction_id);
        let reference_id = optional_correlator(message, "reference_id", &transaction_id);
        let query = message
            .pointer("/disabled_criteria/query")
            .ok_or(FilterError::InvalidValue)?;
        let query_value = query_value(query, &config.query_key).ok_or(FilterError::InvalidValue)?;
        Ok(Self {
            transaction_id,
            correlation_id,
            reference_id,
            query_value,
        })
    }
}

impl SearchRequest {
    fn from_body(body: Value, config: &SpdciRegistryConfig) -> Result<Self, Error> {
        let message = validated_message(&body)?;
        let transaction_id = required_transaction_id(message)?;
        let correlation_id = optional_correlator(message, "correlation_id", &transaction_id);
        let Some(items) = message.get("search_request").and_then(Value::as_array) else {
            return Err(FilterError::InvalidValue.into());
        };
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            let criteria = item
                .get("search_criteria")
                .ok_or(FilterError::InvalidValue)?;
            let query_type =
                string_field(criteria, "query_type").ok_or(FilterError::InvalidValue)?;
            let query = criteria.get("query").ok_or(FilterError::InvalidValue)?;
            let filters = filters_from_search_query(&query_type, query, config)?;
            let limit = criteria
                .pointer("/pagination/page_size")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(config.default_limit as usize);
            let reference_id = string_field(item, "reference_id").unwrap_or_else(|| {
                let synthesized = Ulid::new().to_string();
                tracing::debug!(
                    code = "spdci.request.reference_id_substituted",
                    "search_request item missing reference_id; substituted a fresh ULID"
                );
                synthesized
            });
            parsed.push(SearchRequestItem {
                reference_id,
                filters,
                limit,
            });
        }
        Ok(Self {
            transaction_id,
            correlation_id,
            items: parsed,
        })
    }
}

/// Validate the SP DCI request envelope and return the inner message.
///
/// Rejects bodies whose `header` is missing or not an object, whose
/// header omits any of [`REQUIRED_HEADER_FIELDS`], or whose `message`
/// is missing or not an object. See `MsgHeader_V1.0.0.yaml`.
fn validated_message(body: &Value) -> Result<&Value, Error> {
    let header = body
        .get("header")
        .and_then(Value::as_object)
        .ok_or(SpdciError::InvalidHeader)?;
    for field in REQUIRED_HEADER_FIELDS {
        if header.get(*field).is_none_or(Value::is_null) {
            return Err(SpdciError::InvalidHeader.into());
        }
    }
    body.get("message")
        .filter(|value| value.is_object())
        .ok_or_else(|| SpdciError::InvalidMessage.into())
}

fn required_transaction_id(message: &Value) -> Result<String, Error> {
    string_field(message, "transaction_id").ok_or_else(|| SpdciError::MissingTransactionId.into())
}

/// Read a correlation-style field that the SP DCI standard does not
/// require on inbound request bodies (`correlation_id` is response-
/// only, `reference_id` is required only on inner search-request
/// items). Substitute the request's `transaction_id` when absent and
/// emit a debug log so the substitution is audit-visible.
fn optional_correlator(message: &Value, field: &str, transaction_id: &str) -> String {
    if let Some(value) = string_field(message, field) {
        return value;
    }
    tracing::debug!(
        code = "spdci.request.correlator_substituted",
        field,
        "request message missing optional correlator; defaulting to transaction_id"
    );
    transaction_id.to_string()
}

async fn read_rows(
    route: &RouteState,
    request: &SpdciRequest,
    fields: Option<Vec<String>>,
) -> Result<Vec<Value>, Error> {
    let result = route
        .query
        .read_collection(
            route.config.dataset.as_str(),
            &route.config.entity,
            EntityCollectionQuery {
                fields,
                limit: Some(1),
                filters: vec![EntityFilter {
                    field: route.config.query_field.clone(),
                    op: EntityFilterOp::Eq,
                    value: request.query_value.clone(),
                }],
                ..EntityCollectionQuery::default()
            },
        )
        .await?;
    Ok(result.rows)
}

async fn read_search_rows(
    route: &SearchRouteState,
    request: &SearchRequestItem,
) -> Result<Vec<Value>, Error> {
    let result = route
        .query
        .read_collection(
            route.config.dataset.as_str(),
            &route.config.entity,
            EntityCollectionQuery {
                limit: Some(request.limit),
                filters: request.filters.clone(),
                ..EntityCollectionQuery::default()
            },
        )
        .await?;
    Ok(result.rows)
}

fn projected_status_fields(route: &RouteState) -> Vec<String> {
    let mut fields = vec![route.config.disabled_status_field.clone()];
    if route.config.query_field != route.config.disabled_status_field {
        fields.push(route.config.query_field.clone());
    }
    fields
}

fn filters_from_search_query(
    query_type: &str,
    query: &Value,
    config: &SpdciRegistryConfig,
) -> Result<Vec<EntityFilter>, Error> {
    match query_type {
        "idtype-value" => filters_from_idtype_query(query, config),
        "expression" => filters_from_expression_query(query, config),
        "predicate" => filters_from_predicate_query(query, config),
        _ => Err(FilterError::UnsupportedOp.into()),
    }
}

fn filters_from_idtype_query(
    query: &Value,
    config: &SpdciRegistryConfig,
) -> Result<Vec<EntityFilter>, Error> {
    let id_type = string_field(query, "type").ok_or(FilterError::InvalidValue)?;
    let field = config
        .identifiers
        .get(&id_type)
        .ok_or(FilterError::NotAllowed)?;
    let value = query.get("value").ok_or(FilterError::InvalidValue)?;
    Ok(vec![EntityFilter {
        field: field.clone(),
        op: EntityFilterOp::Eq,
        value: value.clone(),
    }])
}

fn filters_from_expression_query(
    query: &Value,
    config: &SpdciRegistryConfig,
) -> Result<Vec<EntityFilter>, Error> {
    let expression = query
        .pointer("/value/expression")
        .or_else(|| query.get("expression"))
        .unwrap_or(query);
    let expression = expression.get("query").unwrap_or(expression);
    parse_expression_object(expression, config)
}

fn parse_expression_object(
    expression: &Value,
    config: &SpdciRegistryConfig,
) -> Result<Vec<EntityFilter>, Error> {
    if let Some(and) = expression.get("$and").and_then(Value::as_array) {
        let mut filters = Vec::new();
        for part in and {
            filters.extend(parse_expression_object(part, config)?);
        }
        return Ok(filters);
    }
    let Some(object) = expression.as_object() else {
        return Err(FilterError::InvalidValue.into());
    };
    let mut filters = Vec::new();
    for (attribute, value) in object {
        let field = config
            .expression_fields
            .get(attribute)
            .ok_or(FilterError::NotAllowed)?;
        filters.push(filter_from_operator_object(field, value)?);
    }
    Ok(filters)
}

fn filters_from_predicate_query(
    query: &Value,
    config: &SpdciRegistryConfig,
) -> Result<Vec<EntityFilter>, Error> {
    let Some(predicates) = query.as_array() else {
        return Err(FilterError::InvalidValue.into());
    };
    let mut filters = Vec::new();
    for predicate in predicates {
        if let Some(condition) = string_field(predicate, "condition") {
            if condition != "and" {
                return Err(FilterError::UnsupportedOp.into());
            }
        }
        for key in ["expression1", "expression2"] {
            if let Some(expression) = predicate.get(key) {
                filters.push(filter_from_predicate_expression(expression, config)?);
            }
        }
    }
    Ok(filters)
}

fn filter_from_predicate_expression(
    expression: &Value,
    config: &SpdciRegistryConfig,
) -> Result<EntityFilter, Error> {
    let attribute = string_field(expression, "attribute_name").ok_or(FilterError::InvalidValue)?;
    let field = config
        .expression_fields
        .get(&attribute)
        .ok_or(FilterError::NotAllowed)?;
    let operator = string_field(expression, "operator").ok_or(FilterError::InvalidValue)?;
    let value = expression
        .get("attribute_value")
        .ok_or(FilterError::InvalidValue)?;
    let op = match operator.as_str() {
        "eq" => EntityFilterOp::Eq,
        "in" => EntityFilterOp::In,
        "ge" => EntityFilterOp::Gte,
        "le" => EntityFilterOp::Lte,
        "gt" | "lt" => return Err(FilterError::UnsupportedOp.into()),
        _ => return Err(FilterError::UnsupportedOp.into()),
    };
    Ok(EntityFilter {
        field: field.clone(),
        op,
        value: value.clone(),
    })
}

fn filter_from_operator_object(field: &str, value: &Value) -> Result<EntityFilter, Error> {
    if let Some(eq) = value.get("$eq").or_else(|| value.get("eq")) {
        return Ok(EntityFilter {
            field: field.to_string(),
            op: EntityFilterOp::Eq,
            value: eq.clone(),
        });
    }
    if let Some(values) = value.get("$in").or_else(|| value.get("in")) {
        return Ok(EntityFilter {
            field: field.to_string(),
            op: EntityFilterOp::In,
            value: values.clone(),
        });
    }
    if let Some(ge) = value.get("$gte").or_else(|| value.get("ge")) {
        return Ok(EntityFilter {
            field: field.to_string(),
            op: EntityFilterOp::Gte,
            value: ge.clone(),
        });
    }
    if let Some(le) = value.get("$lte").or_else(|| value.get("le")) {
        return Ok(EntityFilter {
            field: field.to_string(),
            op: EntityFilterOp::Lte,
            value: le.clone(),
        });
    }
    if value.as_object().is_some_and(|object| {
        object
            .keys()
            .any(|key| key.starts_with('$') || matches!(key.as_str(), "ne" | "gt" | "lt"))
    }) {
        return Err(FilterError::UnsupportedOp.into());
    }
    Ok(EntityFilter {
        field: field.to_string(),
        op: EntityFilterOp::Eq,
        value: value.clone(),
    })
}

fn query_value(query: &Value, key: &str) -> Option<Value> {
    let direct = query.get(key).or_else(|| dotted_lookup(query, key))?;
    if let Some(eq) = direct.get("eq").or_else(|| direct.get("$eq")) {
        return Some(eq.clone());
    }
    Some(direct.clone())
}

fn dotted_lookup<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.')
        .try_fold(value, |current, part| current.get(part))
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn project_search_records(
    registry_name: &str,
    registry_config: &SpdciRegistryConfig,
    response_mapper: Option<&SpdciResponseMapper>,
    rows: Vec<Value>,
) -> Result<Value, Error> {
    let default_mapper;
    let mapper = match response_mapper {
        Some(mapper) => mapper,
        None if registry_has_mapping(registry_config) => {
            tracing::error!(
                code = "spdci.mapper.unavailable",
                registry = %registry_name,
                dataset_id = %registry_config.dataset,
                entity = %registry_config.entity,
                "SP DCI response mapper extension absent for a registry that requires it"
            );
            return Err(SpdciError::MapperUnavailable.into());
        }
        None => {
            default_mapper = SpdciResponseMapper::default();
            &default_mapper
        }
    };
    let mapped = rows
        .into_iter()
        .map(|row| mapper.project_record(registry_name, registry_config, row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            tracing::error!(
                registry = %registry_name,
                dataset_id = %registry_config.dataset,
                entity = %registry_config.entity,
                error = %err,
                "SP DCI response projection failed"
            );
            Error::from(InternalError::Unhandled)
        })?;
    // Per the SP DCI spec, `reg_records` is always a JSON array
    // (`@container: "@set"`). Empty results emit `[]`.
    Ok(Value::Array(mapped))
}

fn registry_has_mapping(config: &SpdciRegistryConfig) -> bool {
    !config.response_fields.is_empty()
        || config.response_mapping_path.is_some()
        || config.response_schema_path.is_some()
}

fn positive_status(value: &Value, positive_values: &[String]) -> bool {
    let normalized = match value {
        Value::Bool(value) => value.to_string(),
        Value::String(value) => value.trim().to_ascii_lowercase(),
        Value::Number(value) => value.to_string(),
        _ => return false,
    };
    positive_values
        .iter()
        .any(|candidate| candidate.trim().eq_ignore_ascii_case(&normalized))
}

fn require_scope_for(principal: Option<Extension<Principal>>, required: &str) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, required)
}

fn spdci_envelope_with_count(
    action: &str,
    message: Value,
    headers: &HeaderMap,
    total_count: u64,
) -> Response {
    JsonResponse(json!({
        "header": {
            "message_id": response_message_id(headers),
            "message_ts": now_rfc3339(),
            "action": action,
            "status": "succ",
            "total_count": total_count,
            "is_msg_encrypted": false,
        },
        "message": message,
    }))
    .into_response()
}

fn response_message_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn with_audit_context(mut response: Response, route: &RouteState, row_count: u64) -> Response {
    response.extensions_mut().insert(AuditContextExt {
        dataset_id: Some(route.config.dataset.to_string()),
        entity_name: Some(route.config.entity.clone()),
        table_id: Some(route.entity.table_id.clone()),
        row_count: Some(row_count),
        ..AuditContextExt::default()
    });
    response
}

fn with_search_audit_context(
    mut response: Response,
    route: &SearchRouteState,
    row_count: u64,
) -> Response {
    response.extensions_mut().insert(AuditContextExt {
        dataset_id: Some(route.config.dataset.to_string()),
        entity_name: Some(route.config.entity.clone()),
        table_id: Some(route.entity.table_id.clone()),
        row_count: Some(row_count),
        ..AuditContextExt::default()
    });
    response
}
