// SPDX-License-Identifier: Apache-2.0
//! Optional SP DCI standards adapter routes.
//!
//! The adapter is intentionally thin: Registry Relay still owns source
//! ingestion, authorization, filtering, and entity projection. These
//! routes translate the SP DCI Disability Registry synchronous request
//! envelope onto one configured entity.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Json, Path};
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
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, FilterError, SchemaError};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine};

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
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    sync_search_response(
        headers,
        Some(registry_name),
        config,
        registry,
        query,
        principal,
        body,
    )
    .await
}

async fn disabled_status(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    let Ok(route) = RouteState::resolve(config, registry, query, &registry_name) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    if let Err(error) = require_scope_for(principal, &route.entity.access.verify_scope) {
        return error.into_response();
    }

    let request = match SpdciRequest::from_body(body, &route.config) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let rows = match read_rows(&route, &request, Some(projected_status_fields(&route))).await {
        Ok(rows) => rows,
        Err(error) => return error.into_response(),
    };
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
    with_audit_context(spdci_envelope("on-search", message, &headers), &route, 1)
}

async fn sync_search_response(
    headers: HeaderMap,
    registry_name: Option<String>,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Response {
    let Ok(route) = SearchRouteState::resolve(config, registry, query, registry_name.as_deref())
    else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    if let Err(error) = require_scope_for(principal, &route.entity.access.read_scope) {
        return error.into_response();
    }

    let request = match SearchRequest::from_body(body, &route.config) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let mut search_response = Vec::with_capacity(request.items.len());
    let mut total_count = 0_u64;
    for item in request.items {
        let rows = match read_search_rows(&route, &item).await {
            Ok(rows) => rows,
            Err(error) => return error.into_response(),
        };
        total_count += rows.len() as u64;
        search_response.push(json!({
            "reference_id": item.reference_id,
            "timestamp": now_rfc3339(),
            "status": "succ",
            "data": {
                "version": "1.0.0",
                "reg_type": route.config.registry_type,
                "reg_record_type": route.config.record_type,
                "reg_records": generic_reg_records(rows),
            },
        }));
    }

    let message = json!({
        "transaction_id": request.transaction_id,
        "correlation_id": request.correlation_id,
        "search_response": search_response,
    });
    with_search_audit_context(
        spdci_envelope_with_count("on-search", message, &headers, total_count),
        &route,
        total_count,
    )
}

async fn disability_details(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    search_response(
        headers,
        registry_name,
        config,
        registry,
        query,
        principal,
        body,
    )
    .await
}

async fn disability_support(
    Path(registry_name): Path<String>,
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    search_response(
        headers,
        registry_name,
        config,
        registry,
        query,
        principal,
        body,
    )
    .await
}

async fn search_response(
    headers: HeaderMap,
    registry_name: String,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Response {
    let Ok(route) = RouteState::resolve(config, registry, query, &registry_name) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    if let Err(error) = require_scope_for(principal, &route.entity.access.read_scope) {
        return error.into_response();
    }

    let request = match SpdciRequest::from_body(body, &route.config) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let rows = match read_rows(&route, &request, None).await {
        Ok(rows) => rows,
        Err(error) => return error.into_response(),
    };
    let row_count = rows.len() as u64;
    let message = json!({
        "transaction_id": request.transaction_id,
        "correlation_id": request.correlation_id,
        "search_response": [{
            "reference_id": request.reference_id,
            "timestamp": now_rfc3339(),
            "status": "succ",
            "data": {
                "version": "1.0.0",
                "reg_records": rows,
            },
        }],
    });
    with_audit_context(
        spdci_envelope("on-search", message, &headers),
        &route,
        row_count,
    )
}

struct RouteState {
    config: SpdciDisabilityRegistryConfig,
    entity: EntityModel,
    query: Arc<EntityQueryEngine>,
}

struct SearchRouteState {
    config: SpdciRegistryConfig,
    entity: EntityModel,
    query: Arc<EntityQueryEngine>,
}

impl RouteState {
    fn resolve(
        config: Option<Extension<Arc<Config>>>,
        registry: Option<Extension<Arc<EntityRegistry>>>,
        query: Option<Extension<Arc<EntityQueryEngine>>>,
        registry_name: &str,
    ) -> Result<Self, Error> {
        let Extension(config) = config.ok_or(SchemaError::UnknownResource)?;
        let disability = resolve_disability_config(&config, registry_name)?;
        let Extension(registry) = registry.ok_or(SchemaError::UnknownResource)?;
        let entity = registry
            .dataset(disability.dataset.as_str())
            .and_then(|dataset| dataset.entity(&disability.entity))
            .cloned()
            .ok_or(SchemaError::UnknownResource)?;
        let Extension(query) = query.ok_or(SchemaError::UnknownResource)?;
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
    if registry_name == "dr" {
        return Ok(disability);
    }
    Err(SchemaError::UnknownResource.into())
}

impl SearchRouteState {
    fn resolve(
        config: Option<Extension<Arc<Config>>>,
        registry: Option<Extension<Arc<EntityRegistry>>>,
        query: Option<Extension<Arc<EntityQueryEngine>>>,
        registry_name: Option<&str>,
    ) -> Result<Self, Error> {
        let Extension(config) = config.ok_or(SchemaError::UnknownResource)?;
        let search = resolve_search_config(&config, registry_name)?;
        let Extension(registry) = registry.ok_or(SchemaError::UnknownResource)?;
        let entity = registry
            .dataset(search.dataset.as_str())
            .and_then(|dataset| dataset.entity(&search.entity))
            .cloned()
            .ok_or(SchemaError::UnknownResource)?;
        let Extension(query) = query.ok_or(SchemaError::UnknownResource)?;
        Ok(Self {
            config: search,
            entity,
            query,
        })
    }
}

fn resolve_search_config(
    config: &Config,
    registry_name: Option<&str>,
) -> Result<SpdciRegistryConfig, Error> {
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
            .ok_or_else(|| SchemaError::UnknownResource.into());
    }
    if spdci.registries.len() == 1 {
        return spdci
            .registries
            .values()
            .next()
            .cloned()
            .ok_or_else(|| SchemaError::UnknownResource.into());
    }
    if spdci.registries.is_empty() {
        if let Some(disability) = &spdci.disability_registry {
            return Ok(search_config_from_disability(disability));
        }
    }
    Err(SchemaError::UnknownResource.into())
}

fn search_config_from_disability(
    disability: &SpdciDisabilityRegistryConfig,
) -> SpdciRegistryConfig {
    let identifiers = ["DISABILITY_ID", "MEMBER_ID", "UIN", "NIN"]
        .into_iter()
        .map(|name| (name.to_string(), disability.query_field.clone()))
        .collect();
    let expression_fields = BTreeMap::from([(
        "disability_status".to_string(),
        disability.disabled_status_field.clone(),
    )]);
    SpdciRegistryConfig {
        dataset: disability.dataset.clone(),
        entity: disability.entity.clone(),
        registry_type: "ns:org:RegistryType:DR".to_string(),
        record_type: "spdci-extensions-dci:DisabledPerson".to_string(),
        identifiers,
        expression_fields,
        default_limit: 100,
    }
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
        let message = body.get("message").unwrap_or(&body);
        let transaction_id = string_field(message, "transaction_id")
            .or_else(|| string_field(body.get("header").unwrap_or(&Value::Null), "message_id"))
            .unwrap_or_else(|| Ulid::new().to_string());
        let correlation_id = string_field(message, "correlation_id")
            .or_else(|| string_field(body.get("header").unwrap_or(&Value::Null), "message_id"))
            .unwrap_or_else(|| transaction_id.clone());
        let reference_id = string_field(message, "reference_id")
            .or_else(|| string_field(message, "transaction_id"))
            .unwrap_or_else(|| transaction_id.clone());
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
        let message = body.get("message").unwrap_or(&body);
        let transaction_id = string_field(message, "transaction_id")
            .or_else(|| string_field(body.get("header").unwrap_or(&Value::Null), "message_id"))
            .unwrap_or_else(|| Ulid::new().to_string());
        let correlation_id = string_field(message, "correlation_id")
            .or_else(|| string_field(body.get("header").unwrap_or(&Value::Null), "message_id"))
            .unwrap_or_else(|| transaction_id.clone());
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
            parsed.push(SearchRequestItem {
                reference_id: string_field(item, "reference_id")
                    .unwrap_or_else(|| Ulid::new().to_string()),
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

fn generic_reg_records(rows: Vec<Value>) -> Value {
    match rows.len() {
        0 => json!({}),
        1 => rows.into_iter().next().unwrap_or_else(|| json!({})),
        _ => json!({ "items": rows }),
    }
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

fn spdci_envelope(action: &str, message: Value, headers: &HeaderMap) -> Response {
    spdci_envelope_with_count(action, message, headers, 1)
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
