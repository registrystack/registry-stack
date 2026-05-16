// SPDX-License-Identifier: Apache-2.0
//! Optional SPD CI standards adapter routes.
//!
//! The adapter is intentionally thin: Registry Relay still owns source
//! ingestion, authorization, filtering, and entity projection. These
//! routes translate the SPD CI Disability Registry synchronous request
//! envelope onto one configured entity.

use std::sync::Arc;

use axum::extract::Json;
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
use crate::config::{Config, SpdciDisabilityRegistryConfig};
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, FilterError, SchemaError};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine};

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/registry/sync/disabled", post(disabled_status))
        .route(
            "/registry/sync/get-disability-details",
            post(disability_details),
        )
        .route(
            "/registry/sync/get-disability-support",
            post(disability_support),
        )
}

async fn disabled_status(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    let Ok(route) = RouteState::resolve(config, registry, query) else {
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

async fn disability_details(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    search_response(headers, config, registry, query, principal, body).await
}

async fn disability_support(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    search_response(headers, config, registry, query, principal, body).await
}

async fn search_response(
    headers: HeaderMap,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    principal: Option<Extension<Principal>>,
    body: Value,
) -> Response {
    let Ok(route) = RouteState::resolve(config, registry, query) else {
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

impl RouteState {
    fn resolve(
        config: Option<Extension<Arc<Config>>>,
        registry: Option<Extension<Arc<EntityRegistry>>>,
        query: Option<Extension<Arc<EntityQueryEngine>>>,
    ) -> Result<Self, Error> {
        let Extension(config) = config.ok_or(SchemaError::UnknownResource)?;
        let disability = config
            .standards
            .spdci
            .as_ref()
            .and_then(|spdci| spdci.disability_registry.clone())
            .ok_or(SchemaError::UnknownResource)?;
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

struct SpdciRequest {
    transaction_id: String,
    correlation_id: String,
    reference_id: String,
    query_value: Value,
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

fn projected_status_fields(route: &RouteState) -> Vec<String> {
    let mut fields = vec![route.config.disabled_status_field.clone()];
    if route.config.query_field != route.config.disabled_status_field {
        fields.push(route.config.query_field.clone());
    }
    fields
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
    JsonResponse(json!({
        "header": {
            "message_id": response_message_id(headers),
            "message_ts": now_rfc3339(),
            "action": action,
            "total_count": 1,
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
