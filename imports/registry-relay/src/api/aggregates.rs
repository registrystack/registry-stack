// SPDX-License-Identifier: Apache-2.0
//! Entity aggregate HTTP route declarations.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::json;

use tokio::sync::watch;

use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::Config;
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, SchemaError};
use crate::ingest::ReadinessSnapshot;
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

#[allow(clippy::too_many_arguments)]
async fn execute_aggregate(
    Path(path): Path<AggregateRunPath>,
    headers: HeaderMap,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<AggregateQueryEngine>>>,
    config: Option<Extension<Arc<Config>>>,
    provenance: Option<Extension<Arc<crate::provenance::ProvenanceState>>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
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
            // `asOf` is the ingest-time freshness of the underlying
            // resource: when the ready snapshot for this table became
            // visible. `computedAt` is when the handler ran the query.
            // The two values are produced at different points in time;
            // collapsing them hides freshness information from VC
            // consumers. We resolve `asOf` from the readiness watch
            // (entity.table_id == ResourceId) and fall back to
            // `computed_at` only when readiness is not installed (e.g.
            // tests that exercise just the route, no ingest gate).
            let registry_ref = registry.as_ref().map(|Extension(r)| r);
            let readiness_ref = readiness.as_ref().map(|Extension(r)| r);
            let as_of_rfc3339 = resolve_as_of_rfc3339(
                registry_ref,
                readiness_ref,
                &path.dataset_id,
                &path.entity,
                &result.computed_at,
            );
            let plain_response = Json(aggregate_result_json(&result)).into_response();
            let provenance_state = provenance.as_ref().map(|Extension(state)| state);
            let config_ref = config.as_ref().map(|Extension(cfg)| cfg);
            let mut response = crate::api::provenance_issuance::maybe_issue_aggregate_result(
                provenance_state,
                config_ref,
                &headers,
                plain_response,
                crate::api::provenance_issuance::AggregateIssuanceArgs {
                    dataset: &path.dataset_id,
                    entity: &path.entity,
                    aggregate_id: &path.aggregate_id,
                    group_by: result.group_by.clone(),
                    measures: result.measures.clone(),
                    rows: result.rows.clone(),
                    suppressed_groups,
                    min_group_size: u64::from(result.min_group_size),
                    computed_at_rfc3339: result.computed_at.clone(),
                    as_of_rfc3339,
                },
            );
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

/// Resolve the VC `asOf` claim from the ingest readiness snapshot for
/// the resource that backs `(dataset, entity)`. When the readiness
/// watch is not installed, when the entity is unknown, or when the
/// resource has not yet shown up in the ready map, we fall back to the
/// handler's `computed_at` so the issuer never serves an empty
/// timestamp.
fn resolve_as_of_rfc3339(
    registry: Option<&Arc<EntityRegistry>>,
    readiness: Option<&watch::Receiver<ReadinessSnapshot>>,
    dataset_id: &str,
    entity_name: &str,
    fallback_rfc3339: &str,
) -> String {
    let Some(registry) = registry else {
        return fallback_rfc3339.to_string();
    };
    let Some(readiness) = readiness else {
        return fallback_rfc3339.to_string();
    };
    let Some(dataset) = registry.dataset(dataset_id) else {
        return fallback_rfc3339.to_string();
    };
    let Some(entity) = dataset.entity(entity_name) else {
        return fallback_rfc3339.to_string();
    };
    let Some(dataset_key) = id_from_str::<crate::config::DatasetId>(dataset_id) else {
        return fallback_rfc3339.to_string();
    };
    let Some(resource_key) = id_from_str::<crate::config::ResourceId>(&entity.table_id) else {
        return fallback_rfc3339.to_string();
    };
    let snapshot = readiness.borrow();
    let Some(entry) = snapshot.ready.get(&(dataset_key, resource_key)) else {
        return fallback_rfc3339.to_string();
    };
    entry
        .registered_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| fallback_rfc3339.to_string())
}

fn id_from_str<T>(value: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(&format!(r#""{value}""#)).ok()
}

fn aggregate_result_json(result: &AggregateResult) -> serde_json::Value {
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
