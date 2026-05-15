// SPDX-License-Identifier: Apache-2.0
//! Entity-shaped HTTP route declarations.
//!
//! This module owns only the route surface for the public entity API.
//! Server integration and query execution are intentionally separate:
//! callers can merge [`router`] into the protected data-plane router
//! once auth and query state are wired. Without query state, data reads
//! return an explicit RFC 9457-style `501` response.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::ErrorCodeExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, SchemaError};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityQueryEngine};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const QUERY_UNAVAILABLE_CODE: &str = "entity.query_unavailable";

/// Sub-router for entity-shaped dataset routes from Spec.md Section 7.
///
/// The router is generic over Axum state so `server::build_app` can
/// mount it later without this module choosing the server state type.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/datasets/{dataset_id}/{entity}/schema", get(entity_schema))
        .route("/datasets/{dataset_id}/{entity}/verify", get(entity_verify))
        .route("/datasets/{dataset_id}/{entity}", get(entity_collection))
        .route(
            "/datasets/{dataset_id}/{entity}/{id}/{relationship}",
            get(entity_relationship),
        )
        .route("/datasets/{dataset_id}/{entity}/{id}", get(entity_record))
}

#[derive(Debug, Deserialize)]
struct EntityPath {
    dataset_id: String,
    entity: String,
}

#[derive(Debug, Deserialize)]
struct EntityRecordPath {
    dataset_id: String,
    entity: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct EntityRelationshipPath {
    dataset_id: String,
    entity: String,
    id: String,
    relationship: String,
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    id: String,
}

async fn entity_schema(
    Path(path): Path<EntityPath>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(registry)) = registry else {
        return query_unavailable(
            "entity schema route matched, but entity registry is not installed",
        );
    };

    let Some(dataset) = registry.dataset(&path.dataset_id) else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };
    let Some(entity) = dataset.entity(&path.entity) else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    if let Err(error) = require_principal_scope(principal, &entity.access.metadata_scope) {
        return error.into_response();
    }

    Json(schema_document(&path.dataset_id, entity)).into_response()
}

async fn entity_collection(
    Path(path): Path<EntityPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
) -> Response {
    if let Some(Extension(registry)) = registry {
        match entity_from_registry(&registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) = require_read_access(principal.clone(), entity, &headers) {
                    return error.into_response();
                }
                if let Some(expand) = params.get("expand") {
                    let expansions = match parse_expansions(expand) {
                        Ok(expansions) => expansions,
                        Err(error) => return error.into_response(),
                    };
                    if let Err(error) = require_expansion_access(
                        &registry,
                        &path.dataset_id,
                        entity,
                        &expansions,
                        principal.clone(),
                        &headers,
                    ) {
                        return error.into_response();
                    }
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "entity collection route matched, but entity query state is not installed",
        );
    };

    let query_params = match collection_query_from_params(params) {
        Ok(query_params) => query_params,
        Err(error) => return error.into_response(),
    };
    match query
        .read_collection(&path.dataset_id, &path.entity, query_params)
        .await
    {
        Ok(rows) => Json(json!({ "data": rows.rows })).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn entity_verify(
    Path(path): Path<EntityPath>,
    Query(params): Query<VerifyParams>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
) -> Response {
    if let Some(Extension(registry)) = registry {
        match entity_from_registry(&registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) = require_principal_scope(principal, &entity.access.verify_scope)
                {
                    return error.into_response();
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "entity verify route matched, but entity query state is not installed",
        );
    };

    match query
        .read_record(
            &path.dataset_id,
            &path.entity,
            json!(params.id),
            None,
            Vec::new(),
        )
        .await
    {
        Ok(Some(_)) => Json(json!({ "exists": true })).into_response(),
        Ok(None) => Json(json!({ "exists": false })).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn entity_record(
    Path(path): Path<EntityRecordPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
) -> Response {
    if let Some(Extension(registry)) = registry {
        match entity_from_registry(&registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) = require_read_access(principal.clone(), entity, &headers) {
                    return error.into_response();
                }
                if let Some(expand) = params.get("expand") {
                    let expansions = match parse_expansions(expand) {
                        Ok(expansions) => expansions,
                        Err(error) => return error.into_response(),
                    };
                    if let Err(error) = require_expansion_access(
                        &registry,
                        &path.dataset_id,
                        entity,
                        &expansions,
                        principal.clone(),
                        &headers,
                    ) {
                        return error.into_response();
                    }
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "entity record route matched, but entity query state is not installed",
        );
    };

    let query_params = match record_query_from_params(params) {
        Ok(query_params) => query_params,
        Err(error) => return error.into_response(),
    };
    match query
        .read_record(
            &path.dataset_id,
            &path.entity,
            json!(path.id),
            query_params.fields,
            query_params.expansions,
        )
        .await
    {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => Error::from(SchemaError::UnknownResource).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn entity_relationship(
    Path(path): Path<EntityRelationshipPath>,
    headers: HeaderMap,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
) -> Response {
    if let Some(Extension(registry)) = registry {
        match entity_from_registry(&registry, &path.dataset_id, &path.entity) {
            Ok(entity) => {
                if let Err(error) = require_read_access(principal.clone(), entity, &headers) {
                    return error.into_response();
                }
                if let Err(error) = require_relationship_target_access(
                    &registry,
                    &path.dataset_id,
                    entity,
                    &path.relationship,
                    principal.clone(),
                    &headers,
                ) {
                    return error.into_response();
                }
            }
            Err(error) => return error.into_response(),
        }
    }

    let Some(Extension(query)) = query else {
        return query_unavailable(
            "entity relationship route matched, but entity query state is not installed",
        );
    };

    match query
        .read_relationship(
            &path.dataset_id,
            &path.entity,
            json!(path.id),
            &path.relationship,
        )
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
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

fn require_read_access(
    principal: Option<Extension<Principal>>,
    entity: &EntityModel,
    headers: &HeaderMap,
) -> Result<(), Error> {
    require_principal_scope(principal, &entity.access.read_scope)?;
    if entity.api.require_purpose_header && !headers.contains_key("x-data-purpose") {
        return Err(AuthError::PurposeRequired.into());
    }
    Ok(())
}

fn require_expansion_access(
    registry: &EntityRegistry,
    dataset_id: &str,
    entity: &EntityModel,
    expansions: &[String],
    principal: Option<Extension<Principal>>,
    headers: &HeaderMap,
) -> Result<(), Error> {
    for expansion in expansions {
        if expansion == "*" || expansion.contains('.') {
            return Err(crate::error::FilterError::UnsupportedOp.into());
        }
        if !entity
            .api
            .allowed_expansions
            .iter()
            .any(|allowed| allowed == expansion)
        {
            return Err(crate::error::FilterError::NotAllowed.into());
        }
        require_relationship_target_access(
            registry,
            dataset_id,
            entity,
            expansion,
            principal.clone(),
            headers,
        )?;
    }
    Ok(())
}

fn require_relationship_target_access(
    registry: &EntityRegistry,
    dataset_id: &str,
    entity: &EntityModel,
    relationship_name: &str,
    principal: Option<Extension<Principal>>,
    headers: &HeaderMap,
) -> Result<(), Error> {
    let relationship = entity
        .relationships
        .get(relationship_name)
        .ok_or(crate::error::FilterError::NotAllowed)?;
    let target = entity_from_registry(registry, dataset_id, &relationship.target)?;
    require_principal_scope(principal, &target.access.read_scope)?;
    if target.api.require_purpose_header && !headers.contains_key("x-data-purpose") {
        return Err(AuthError::PurposeRequired.into());
    }
    Ok(())
}

fn schema_document(dataset_id: &str, entity: &EntityModel) -> Value {
    let fields = entity
        .fields
        .iter()
        .map(|field| json!({ "name": field.name }))
        .collect::<Vec<_>>();
    let relationships = entity
        .relationships
        .values()
        .map(|relationship| {
            json!({
                "name": relationship.name,
                "kind": relationship_kind(relationship.kind),
                "target": relationship.target,
                "concept_uri": relationship.concept_uri,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "dataset_id": dataset_id,
        "entity": entity.name,
        "primary_key": entity.primary_key.name,
        "fields": fields,
        "relationships": relationships,
    })
}

fn relationship_kind(kind: crate::config::RelationshipKind) -> &'static str {
    match kind {
        crate::config::RelationshipKind::BelongsTo => "belongs_to",
        crate::config::RelationshipKind::HasMany => "has_many",
        crate::config::RelationshipKind::HasOne => "has_one",
    }
}

fn collection_query_from_params(
    params: HashMap<String, String>,
) -> Result<EntityCollectionQuery, Error> {
    let mut query = EntityCollectionQuery::new();
    for (name, value) in params {
        match name.as_str() {
            "limit" => {
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| crate::error::FilterError::InvalidValue)?;
                query = query.with_limit(limit);
            }
            "fields" => {
                let fields = value
                    .split(',')
                    .filter(|field| !field.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                query = query.with_fields(fields);
            }
            "expand" => {
                query = query.with_expansions(parse_expansions(&value)?);
            }
            "cursor" => {
                return Err(crate::error::FilterError::UnsupportedOp.into());
            }
            field => {
                query = query.with_filter(EntityFilter::eq(field, value));
            }
        }
    }
    Ok(query)
}

#[derive(Default)]
struct EntityRecordQuery {
    fields: Option<Vec<String>>,
    expansions: Vec<String>,
}

fn record_query_from_params(params: HashMap<String, String>) -> Result<EntityRecordQuery, Error> {
    let mut query = EntityRecordQuery::default();
    for (name, value) in params {
        match name.as_str() {
            "fields" => {
                query.fields = Some(
                    value
                        .split(',')
                        .filter(|field| !field.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                );
            }
            "expand" => {
                query.expansions = parse_expansions(&value)?;
            }
            _ => return Err(crate::error::FilterError::UnsupportedOp.into()),
        }
    }
    Ok(query)
}

fn parse_expansions(value: &str) -> Result<Vec<String>, Error> {
    let expansions = value
        .split(',')
        .filter(|expansion| !expansion.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if expansions
        .iter()
        .any(|expansion| expansion == "*" || expansion.contains('.'))
    {
        return Err(crate::error::FilterError::UnsupportedOp.into());
    }
    Ok(expansions)
}

fn query_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/entity/query_unavailable",
            "title": "Entity query unavailable",
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
