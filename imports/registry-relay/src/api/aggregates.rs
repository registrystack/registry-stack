// SPDX-License-Identifier: Apache-2.0
//! Entity aggregate HTTP route declarations.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::json;

use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, SchemaError};
use crate::query::{AggregateQueryEngine, AggregateResult};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const QUERY_UNAVAILABLE_CODE: &str = "aggregate.query_unavailable";

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/datasets/{dataset_id}/{entity}/aggregates",
            get(list_aggregates),
        )
        .route(
            "/datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}",
            get(execute_aggregate),
        )
}

#[derive(Debug, Deserialize)]
struct AggregatePath {
    dataset_id: String,
    entity: String,
}

#[derive(Debug, Deserialize)]
struct AggregateRunPath {
    dataset_id: String,
    entity: String,
    aggregate_id: String,
}

async fn list_aggregates(
    Path(path): Path<AggregatePath>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
) -> Response {
    let audit_context = registry
        .as_ref()
        .and_then(|Extension(registry)| audit_context_for_entity(registry, &path));
    if let Some(Extension(registry)) = registry.as_ref() {
        match entity_from_registry(registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) =
                    require_principal_scope(principal, &entity.access.aggregate_scope)
                {
                    return error.into_response();
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "aggregate list route matched, but aggregate query state is not installed",
        );
    };
    match query.list_aggregates(&path.dataset_id, &path.entity) {
        Ok(aggregates) => {
            let data = aggregates
                .into_iter()
                .map(|aggregate| {
                    json!({
                        "aggregate_id": aggregate.aggregate_id,
                        "description": aggregate.description,
                        "group_by": aggregate.group_by,
                        "measures": aggregate.measures.into_iter().map(|measure| {
                            json!({
                                "name": measure.name,
                                "function": measure.function,
                                "column": measure.column,
                            })
                        }).collect::<Vec<_>>(),
                        "min_group_size": aggregate.min_group_size,
                    })
                })
                .collect::<Vec<_>>();
            with_optional_audit_context(
                Json(json!({ "data": data })).into_response(),
                audit_context,
            )
        }
        Err(error) => error.into_response(),
    }
}

async fn execute_aggregate(
    Path(path): Path<AggregateRunPath>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
) -> Response {
    let audit_context = registry.as_ref().and_then(|Extension(registry)| {
        audit_context_for_aggregate(registry, &path.dataset_id, &path.entity, &path.aggregate_id)
    });
    if let Some(Extension(registry)) = registry.as_ref() {
        match entity_from_registry(registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) =
                    require_principal_scope(principal, &entity.access.aggregate_scope)
                {
                    return error.into_response();
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "aggregate route matched, but aggregate query state is not installed",
        );
    };

    match query
        .execute_aggregate(&path.dataset_id, &path.entity, &path.aggregate_id)
        .await
    {
        Ok(result) => {
            let row_count = result.rows.len() as u64;
            let suppressed_groups = result.suppressed_groups as u64;
            let mut response = Json(aggregate_result_json(result)).into_response();
            if let Some(mut context) = audit_context {
                context.row_count = Some(row_count);
                context.suppressed_groups = Some(suppressed_groups);
                response = with_audit_context(response, context);
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

fn aggregate_result_json(result: AggregateResult) -> serde_json::Value {
    json!({
        "dataset_id": result.dataset_id,
        "entity": result.entity,
        "aggregate_id": result.aggregate_id,
        "computed_at": result.computed_at,
        "min_group_size": result.min_group_size,
        "suppressed_groups": result.suppressed_groups,
        "rows": result.rows,
    })
}

fn entity_from_registry<'a>(
    registry: &'a EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
) -> Result<&'a EntityModel, Error> {
    let Some(dataset) = registry.dataset(dataset_id) else {
        return Err(SchemaError::UnknownDataset.into());
    };
    dataset
        .entity(entity_name)
        .ok_or_else(|| SchemaError::UnknownResource.into())
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

fn audit_context_for_entity(
    registry: &EntityRegistry,
    path: &AggregatePath,
) -> Option<AuditContextExt> {
    let entity = registry.dataset(&path.dataset_id)?.entity(&path.entity)?;
    Some(AuditContextExt {
        dataset_id: Some(path.dataset_id.clone()),
        entity_name: Some(path.entity.clone()),
        table_id: Some(entity.table_id.clone()),
        ..AuditContextExt::default()
    })
}

fn audit_context_for_aggregate(
    registry: &EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
    aggregate_id: &str,
) -> Option<AuditContextExt> {
    let entity = registry.dataset(dataset_id)?.entity(entity_name)?;
    Some(AuditContextExt {
        dataset_id: Some(dataset_id.to_string()),
        entity_name: Some(entity_name.to_string()),
        table_id: Some(entity.table_id.clone()),
        aggregate_id: Some(aggregate_id.to_string()),
        ..AuditContextExt::default()
    })
}

fn with_optional_audit_context(response: Response, context: Option<AuditContextExt>) -> Response {
    match context {
        Some(context) => with_audit_context(response, context),
        None => response,
    }
}

fn with_audit_context(mut response: Response, context: AuditContextExt) -> Response {
    response.extensions_mut().insert(context);
    response
}

fn query_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/aggregate/query_unavailable",
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
