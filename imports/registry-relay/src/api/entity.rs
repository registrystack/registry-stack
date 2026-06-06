// SPDX-License-Identifier: Apache-2.0
//! Entity-shaped HTTP route declarations.
//!
//! This module owns only the route surface for the public entity API.
//! Server integration and query execution are intentionally separate:
//! callers can merge [`router`] into the protected data-plane router
//! once auth and query state are wired. Without query state, data reads
//! return an explicit RFC 9457-style `501` response.

use std::collections::{BTreeMap, HashMap};

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{DatasetId, ResourceId};
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, EntityError, Error, InternalError, SchemaError};
use crate::ingest::ReadinessSnapshot;
use crate::metadata;
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, RelationshipPageQuery};
use crate::runtime_config::{CursorSigner, RuntimeSnapshot, CURSOR_MAC_LEN};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const QUERY_UNAVAILABLE_CODE: &str = "entity.query_unavailable";
const CURSOR_INVALIDATED_CODE: &str = "pagination.cursor_invalidated";
const DATA_PURPOSE_HEADER: &str = "data-purpose";

/// Defensive cap on the number of filter parameters accepted on a
/// single entity-collection request. Pairs with the URI length cap in
/// `server.rs` to bound the cost a single client can impose on filter
/// parsing and DataFusion logical-plan construction.
const MAX_FILTERS_PER_REQUEST: usize = 20;

/// Sub-router for the entity-shaped dataset routes documented in `docs/api.md`.
///
/// The router is generic over Axum state so `server::build_app` can
/// mount it later without this module choosing the server state type.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/v1/datasets/{dataset_id}/entities/{entity}/schema",
            get(entity_schema),
        )
        .route(
            "/v1/datasets/{dataset_id}/entities/{entity}/records",
            get(entity_collection),
        )
        .route(
            "/v1/datasets/{dataset_id}/entities/{entity}/records/{id}/relationships/{relationship}",
            get(entity_relationship),
        )
        .route(
            "/v1/datasets/{dataset_id}/entities/{entity}/records/{id}",
            get(entity_record),
        )
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

async fn entity_schema(
    Path(path): Path<EntityPath>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(registry) = runtime.entity_registry() else {
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
    let readiness = runtime.readiness_rx();
    let ingest_version = ingest_version_for_entity(readiness.as_ref(), &path.dataset_id, entity);

    let config = runtime.config();
    let document = config
        .as_ref()
        .and_then(|config| {
            metadata::entity_schema_document(config, &registry, &path.dataset_id, &path.entity)
        })
        .unwrap_or_else(|| schema_document(&path.dataset_id, entity));
    let etag = entity_etag(
        "schema",
        &path.dataset_id,
        &path.entity,
        ingest_version.as_deref(),
        "",
    );
    if let Some(etag) = etag.as_deref() {
        if if_none_match_matches(&headers, etag) {
            return with_audit_context(
                not_modified_response(etag),
                AuditContextExt {
                    dataset_id: Some(path.dataset_id),
                    entity_name: Some(path.entity),
                    table_id: Some(entity.table_id.clone()),
                    ..AuditContextExt::default()
                },
            );
        }
    }

    let response = with_optional_etag(Json(document).into_response(), etag.as_deref());
    with_audit_context(
        response,
        AuditContextExt {
            dataset_id: Some(path.dataset_id),
            entity_name: Some(path.entity),
            table_id: Some(entity.table_id.clone()),
            ..AuditContextExt::default()
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn entity_collection(
    Path(path): Path<EntityPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(registry) = runtime.entity_registry() else {
        return query_unavailable(
            "entity collection route matched, but entity registry state is not installed",
        );
    };
    let audit_context = audit_context_for_entity(&registry, &path);
    let required_filters = match entity_from_registry(&registry, &path.dataset_id, &path.entity) {
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
            entity.api.required_filters.clone()
        }
        Err(error) => return error.into_response(),
    };

    let Some(query) = runtime.query() else {
        return query_unavailable(
            "entity collection route matched, but entity query state is not installed",
        );
    };

    let Some(signer) = runtime.cursor_signer() else {
        return query_unavailable(
            "entity collection route matched, but cursor signer is not installed",
        );
    };

    let validator = params_validator(&params);
    let link_params = params.clone();
    let cursor_context = CursorContext {
        dataset_id: path.dataset_id.clone(),
        entity: path.entity.clone(),
        relationship: None,
        filters: Vec::new(),
        ingest_version: None,
    };
    let query_params = match collection_query_from_params(&signer, params, cursor_context) {
        Ok(query_params) => query_params,
        Err(PageParamError::CursorInvalidated) => return cursor_invalidated(),
        Err(PageParamError::Error(error)) => return error.into_response(),
    };
    if !required_filters.is_empty() {
        let satisfied = query_params
            .filters
            .iter()
            .any(|f| required_filters.iter().any(|r| r == &f.field));
        if !satisfied {
            return Error::from(EntityError::FilterRequired {
                required: required_filters,
            })
            .into_response();
        }
    }
    let cursor = query_params.cursor.clone();
    if cursor.is_none() && query_params.query.expansions.is_empty() {
        if let Some(dataset) = registry.dataset(&path.dataset_id) {
            if dataset.entity(&path.entity).is_some() {
                if let Err(error) = query.validate_collection_query(
                    &path.dataset_id,
                    &path.entity,
                    &query_params.query,
                ) {
                    return error.into_response();
                }
            }
        }
    }
    match query
        .read_collection(&path.dataset_id, &path.entity, query_params.query)
        .await
    {
        Ok(rows) => {
            let cursor_context = CursorContext {
                dataset_id: path.dataset_id.clone(),
                entity: path.entity.clone(),
                relationship: None,
                filters: query_params.filters.clone(),
                ingest_version: rows.cursor_ingest_version.clone(),
            };
            if let Some(cursor) = cursor.as_ref() {
                if validate_cursor(cursor, &cursor_context).is_err() {
                    return cursor_invalidated();
                }
            }
            let row_count = rows.rows.len() as u64;
            let next_cursor = if let Some(position) = rows.next_primary_key {
                let cursor = PageCursor {
                    version: 1,
                    dataset_id: cursor_context.dataset_id,
                    entity: cursor_context.entity,
                    relationship: cursor_context.relationship,
                    position,
                    filters: cursor_context.filters,
                    ingest_version: cursor_context.ingest_version,
                };
                let encoded = match encode_cursor(&signer, &cursor) {
                    Ok(encoded) => encoded,
                    Err(error) => return error.into_response(),
                };
                Some(encoded)
            } else {
                None
            };
            let body = paginated_body(Value::Array(rows.rows), next_cursor.as_deref());
            let etag = entity_etag(
                "collection",
                &path.dataset_id,
                &path.entity,
                rows.validator_ingest_version.as_deref(),
                &validator,
            );
            let mut response = if let Some(etag) = etag.as_deref() {
                if if_none_match_matches(&headers, etag) {
                    not_modified_response(etag)
                } else {
                    with_etag(Json(body).into_response(), etag)
                }
            } else {
                Json(body).into_response()
            };
            let next_link = next_cursor
                .as_deref()
                .map(|cursor| collection_next_link(&path, &link_params, cursor));
            response = with_next_link(response, next_link.as_deref());
            if let Some(mut context) = audit_context {
                context.row_count = Some(row_count);
                response = with_audit_context(response, context);
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn entity_record(
    Path(path): Path<EntityRecordPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(registry) = runtime.entity_registry() else {
        return query_unavailable(
            "entity record route matched, but entity registry state is not installed",
        );
    };
    let audit_context = audit_context_for_entity_record(&registry, &path.dataset_id, &path.entity);
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

    let Some(query) = runtime.query() else {
        return query_unavailable(
            "entity record route matched, but entity query state is not installed",
        );
    };

    let validator = format!("{}?{}", path.id, params_validator(&params));
    let query_params = match record_query_from_params(params) {
        Ok(query_params) => query_params,
        Err(error) => return error.into_response(),
    };
    // Preserve the expansion list locally so the provenance helper can
    // partition the record into `{fields, expanded}` later. The plain
    // JSON path consumes `query_params.expansions` so we clone first.
    let expansions_for_vc = query_params.expansions.clone();
    match query
        .read_record(
            &path.dataset_id,
            &path.entity,
            json!(path.id.clone()),
            query_params.fields,
            query_params.expansions,
        )
        .await
    {
        Ok(Some(record)) => {
            let etag = entity_etag(
                "record",
                &path.dataset_id,
                &path.entity,
                record.validator_ingest_version.as_deref(),
                &validator,
            );
            let plain_response = if let Some(etag) = etag.as_deref() {
                if if_none_match_matches(&headers, etag) {
                    not_modified_response(etag)
                } else {
                    with_etag(Json(record.value.clone()).into_response(), etag)
                }
            } else {
                Json(record.value.clone()).into_response()
            };
            let provenance_state = runtime.provenance_state();
            let config_ref = runtime.config();
            let publicschema_ref = runtime.publicschema_registry();
            let mut response = crate::api::provenance_issuance::maybe_issue_entity_record(
                provenance_state.as_ref(),
                config_ref.as_ref(),
                publicschema_ref.as_ref(),
                &headers,
                plain_response,
                &path.dataset_id,
                &path.entity,
                &path.id,
                record.value,
                expansions_for_vc,
                crate::api::provenance_issuance::now_rfc3339(),
            );
            if let Some(mut context) = audit_context {
                context.row_count = Some(1);
                response = with_audit_context(response, context);
            }
            response
        }
        Ok(None) => Error::from(SchemaError::UnknownResource).into_response(),
        Err(error) => error.into_response(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn entity_relationship(
    Path(path): Path<EntityRelationshipPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(registry) = runtime.entity_registry() else {
        return query_unavailable(
            "entity relationship route matched, but entity registry state is not installed",
        );
    };
    let audit_context = audit_context_for_relationship(
        &registry,
        &path.dataset_id,
        &path.entity,
        &path.relationship,
    );
    let mut page_context = None;
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
            if let Some(relationship) = entity.relationships.get(&path.relationship) {
                let target =
                    match entity_from_registry(&registry, &path.dataset_id, &relationship.target) {
                        Ok(target) => target,
                        Err(error) => return error.into_response(),
                    };
                if relationship.kind == crate::config::RelationshipKind::HasMany {
                    let target_fk_name =
                        match field_name_by_table_column(target, &relationship.foreign_key) {
                            Ok(field) => field,
                            Err(error) => return error.into_response(),
                        };
                    page_context = Some(CursorContext {
                        dataset_id: path.dataset_id.clone(),
                        entity: path.entity.clone(),
                        relationship: Some(path.relationship.clone()),
                        filters: vec![CursorFilter {
                            field: target_fk_name,
                            op: "eq".to_string(),
                            value: json!(path.id.clone()),
                        }],
                        ingest_version: None,
                    });
                }
            }
        }
        Err(error) => return error.into_response(),
    }

    let Some(query) = runtime.query() else {
        return query_unavailable(
            "entity relationship route matched, but entity query state is not installed",
        );
    };

    let Some(signer) = runtime.cursor_signer() else {
        return query_unavailable(
            "entity relationship route matched, but cursor signer is not installed",
        );
    };

    let link_params = params.clone();
    let validator = format!(
        "{}:{}?{}",
        path.id,
        path.relationship,
        params_validator(&link_params)
    );
    let relationship_query =
        match relationship_query_from_params(&signer, params, page_context.as_ref()) {
            Ok(query) => query,
            Err(PageParamError::CursorInvalidated) => return cursor_invalidated(),
            Err(PageParamError::Error(error)) => return error.into_response(),
        };
    let cursor = relationship_query.cursor.clone();
    match query
        .read_relationship_page(
            &path.dataset_id,
            &path.entity,
            json!(path.id),
            &path.relationship,
            relationship_query.query,
        )
        .await
    {
        Ok(page) => {
            let etag = entity_etag(
                "relationship",
                &path.dataset_id,
                &path.entity,
                page.validator_ingest_version.as_deref(),
                &validator,
            );
            if let Some(mut context) = page_context {
                context.ingest_version = page.cursor_ingest_version.clone();
                if let Some(cursor) = cursor.as_ref() {
                    if validate_cursor(cursor, &context).is_err() {
                        return cursor_invalidated();
                    }
                }
                let row_count = page.value.as_array().map_or(0, |rows| rows.len()) as u64;
                let next_cursor = if let Some(position) = page.next_primary_key {
                    let cursor = PageCursor {
                        version: 1,
                        dataset_id: context.dataset_id,
                        entity: context.entity,
                        relationship: context.relationship,
                        position,
                        filters: context.filters,
                        ingest_version: context.ingest_version,
                    };
                    let encoded = match encode_cursor(&signer, &cursor) {
                        Ok(encoded) => encoded,
                        Err(error) => return error.into_response(),
                    };
                    Some(encoded)
                } else {
                    None
                };
                let body = paginated_body(page.value, next_cursor.as_deref());
                let mut response = relationship_response(body, etag.as_deref(), &headers);
                if response.status() != StatusCode::NOT_MODIFIED {
                    let next_link = next_cursor
                        .as_deref()
                        .map(|cursor| relationship_next_link(&path, &link_params, cursor));
                    response = with_next_link(response, next_link.as_deref());
                }
                if let Some(mut context) = audit_context {
                    context.row_count = Some(row_count);
                    response = with_audit_context(response, context);
                }
                response
            } else {
                let response = relationship_response(page.value, etag.as_deref(), &headers);
                with_optional_audit_context(response, audit_context)
            }
        }
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
    if entity.api.require_purpose_header && !has_purpose_header(headers) {
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
    if target.api.require_purpose_header && !has_purpose_header(headers) {
        return Err(AuthError::PurposeRequired.into());
    }
    Ok(())
}

fn has_purpose_header(headers: &HeaderMap) -> bool {
    purpose_header_value(headers, DATA_PURPOSE_HEADER).is_some()
}

fn purpose_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn field_name_by_table_column(entity: &EntityModel, table_column: &str) -> Result<String, Error> {
    entity
        .fields
        .iter()
        .find(|field| field.table_column == table_column)
        .map(|field| field.name.clone())
        .ok_or_else(|| crate::error::FilterError::UnknownField.into())
}

fn audit_context_for_entity(
    registry: &EntityRegistry,
    path: &EntityPath,
) -> Option<AuditContextExt> {
    audit_context_for_entity_record(registry, &path.dataset_id, &path.entity)
}

fn audit_context_for_entity_record(
    registry: &EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
) -> Option<AuditContextExt> {
    let entity = registry.dataset(dataset_id)?.entity(entity_name)?;
    Some(AuditContextExt {
        dataset_id: Some(dataset_id.to_string()),
        entity_name: Some(entity_name.to_string()),
        table_id: Some(entity.table_id.clone()),
        ..AuditContextExt::default()
    })
}

fn audit_context_for_relationship(
    registry: &EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
    relationship_name: &str,
) -> Option<AuditContextExt> {
    let mut context = audit_context_for_entity_record(registry, dataset_id, entity_name)?;
    context.relationship = Some(relationship_name.to_string());
    Some(context)
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

#[doc(hidden)]
pub fn entity_etag(
    kind: &str,
    dataset_id: &str,
    entity_name: &str,
    ingest_version: Option<&str>,
    variant: &str,
) -> Option<String> {
    let ingest_version = ingest_version?;
    Some(strong_etag(&[
        "entity",
        kind,
        dataset_id,
        entity_name,
        ingest_version,
        variant,
    ]))
}

fn params_validator(params: &HashMap<String, String>) -> String {
    let params = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<BTreeMap<_, _>>();
    serde_json::to_string(&params).expect("string map serializes")
}

#[doc(hidden)]
pub fn strong_etag(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
        hasher.update(b";");
    }
    format!(r#""sha256:{}""#, hex_lower(&hasher.finalize()))
}

fn with_optional_etag(response: Response, etag: Option<&str>) -> Response {
    match etag {
        Some(etag) => with_etag(response, etag),
        None => response,
    }
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("strong_etag returns a valid header value"),
    );
    response
}

fn not_modified_response(etag: &str) -> Response {
    with_etag(StatusCode::NOT_MODIFIED.into_response(), etag)
}

#[doc(hidden)]
pub fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*"
                || candidate == etag
                || candidate
                    .strip_prefix("W/")
                    .is_some_and(|weak_candidate| weak_candidate == etag)
        })
}

fn paginated_body(data: Value, next_cursor: Option<&str>) -> Value {
    let mut pagination = json!({ "has_more": next_cursor.is_some() });
    if let Some(cursor) = next_cursor {
        pagination["next_cursor"] = Value::String(cursor.to_string());
    }
    json!({
        "data": data,
        "pagination": pagination,
    })
}

fn with_next_link(mut response: Response, next_link: Option<&str>) -> Response {
    let Some(next_link) = next_link else {
        return response;
    };
    if let Ok(link) = HeaderValue::from_str(next_link) {
        response.headers_mut().insert(header::LINK, link);
    }
    response
}

fn relationship_response(body: Value, etag: Option<&str>, headers: &HeaderMap) -> Response {
    if let Some(etag) = etag {
        if if_none_match_matches(headers, etag) {
            not_modified_response(etag)
        } else {
            with_etag(Json(body).into_response(), etag)
        }
    } else {
        Json(body).into_response()
    }
}

fn collection_next_link(
    path: &EntityPath,
    params: &HashMap<String, String>,
    cursor: &str,
) -> String {
    next_link_value(
        &format!(
            "/v1/datasets/{}/entities/{}/records",
            path.dataset_id, path.entity
        ),
        params,
        cursor,
    )
}

fn relationship_next_link(
    path: &EntityRelationshipPath,
    params: &HashMap<String, String>,
    cursor: &str,
) -> String {
    next_link_value(
        &format!(
            "/v1/datasets/{}/entities/{}/records/{}/relationships/{}",
            path.dataset_id, path.entity, path.id, path.relationship
        ),
        params,
        cursor,
    )
}

fn next_link_value(path: &str, params: &HashMap<String, String>, cursor: &str) -> String {
    let mut params = params
        .iter()
        .filter(|(name, _)| name.as_str() != "cursor")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    params.push(format!("cursor={cursor}"));
    format!("<{}?{}>; rel=\"next\"", path, params.join("&"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
                "foreign_key": relationship.foreign_key,
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
    signer: &CursorSigner,
    params: HashMap<String, String>,
    mut cursor_context: CursorContext,
) -> Result<ParsedCollectionQuery, PageParamError> {
    let mut query = EntityCollectionQuery::new();
    let mut cursor = None;
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
                cursor = Some(value);
            }
            name => {
                let (field, op) = parse_filter_name(name)?;
                let value = parse_filter_value(op, value)?;
                if query.filters.len() >= MAX_FILTERS_PER_REQUEST {
                    return Err(crate::error::FilterError::TooManyFilters.into());
                }
                query = query.with_filter(EntityFilter::with_op(field, op, value));
            }
        }
    }
    cursor_context.filters = cursor_filters_from_filters(&query.filters);
    let cursor = if let Some(cursor) = cursor {
        let cursor = decode_cursor(signer, &cursor)?;
        validate_cursor(&cursor, &cursor_context)?;
        query = query.with_after_primary_key(cursor.position.clone());
        Some(cursor)
    } else {
        None
    };
    let filters = cursor_context.filters;
    Ok(ParsedCollectionQuery {
        query,
        filters,
        cursor,
    })
}

fn relationship_query_from_params(
    signer: &CursorSigner,
    params: HashMap<String, String>,
    cursor_context: Option<&CursorContext>,
) -> Result<ParsedRelationshipQuery, PageParamError> {
    if params.is_empty() {
        return Ok(ParsedRelationshipQuery {
            query: RelationshipPageQuery::new(),
            cursor: None,
        });
    }
    let Some(cursor_context) = cursor_context else {
        return Err(crate::error::FilterError::UnsupportedOp.into());
    };
    let mut query = RelationshipPageQuery::new();
    let mut cursor = None;
    for (name, value) in params {
        match name.as_str() {
            "limit" => {
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| crate::error::FilterError::InvalidValue)?;
                query = query.with_limit(limit);
            }
            "cursor" => {
                cursor = Some(value);
            }
            _ => return Err(crate::error::FilterError::UnsupportedOp.into()),
        }
    }
    let cursor = if let Some(cursor) = cursor {
        let cursor = decode_cursor(signer, &cursor)?;
        validate_cursor(&cursor, cursor_context)?;
        query = query.with_after_primary_key(cursor.position.clone());
        Some(cursor)
    } else {
        None
    };
    Ok(ParsedRelationshipQuery { query, cursor })
}

struct ParsedCollectionQuery {
    query: EntityCollectionQuery,
    filters: Vec<CursorFilter>,
    cursor: Option<PageCursor>,
}

struct ParsedRelationshipQuery {
    query: RelationshipPageQuery,
    cursor: Option<PageCursor>,
}

#[derive(Debug)]
enum PageParamError {
    Error(Error),
    CursorInvalidated,
}

impl From<Error> for PageParamError {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

impl From<crate::error::FilterError> for PageParamError {
    fn from(error: crate::error::FilterError) -> Self {
        Self::Error(error.into())
    }
}

#[derive(Clone, Debug)]
struct CursorContext {
    dataset_id: String,
    entity: String,
    relationship: Option<String>,
    filters: Vec<CursorFilter>,
    ingest_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct PageCursor {
    version: u8,
    dataset_id: String,
    entity: String,
    relationship: Option<String>,
    position: Value,
    filters: Vec<CursorFilter>,
    ingest_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct CursorFilter {
    field: String,
    op: String,
    value: Value,
}

fn cursor_filters_from_filters(filters: &[EntityFilter]) -> Vec<CursorFilter> {
    let mut filters = filters
        .iter()
        .map(|filter| CursorFilter {
            field: filter.field.clone(),
            op: filter_op_name(filter.op).to_string(),
            value: filter.value.clone(),
        })
        .collect::<Vec<_>>();
    filters.sort_by(|left, right| {
        (
            left.field.as_str(),
            left.op.as_str(),
            serde_json::to_string(&left.value).unwrap_or_default(),
        )
            .cmp(&(
                right.field.as_str(),
                right.op.as_str(),
                serde_json::to_string(&right.value).unwrap_or_default(),
            ))
    });
    filters
}

fn filter_op_name(op: EntityFilterOp) -> &'static str {
    match op {
        EntityFilterOp::Eq => "eq",
        EntityFilterOp::In => "in",
        EntityFilterOp::Gte => "gte",
        EntityFilterOp::Lte => "lte",
        EntityFilterOp::Between => "between",
    }
}

fn validate_cursor(cursor: &PageCursor, context: &CursorContext) -> Result<(), PageParamError> {
    if cursor.version != 1
        || cursor.dataset_id != context.dataset_id
        || cursor.entity != context.entity
        || cursor.relationship != context.relationship
        || cursor.filters != context.filters
        || (context.ingest_version.is_some() && cursor.ingest_version != context.ingest_version)
    {
        return Err(PageParamError::CursorInvalidated);
    }
    Ok(())
}

fn encode_cursor(signer: &CursorSigner, cursor: &PageCursor) -> Result<String, Error> {
    let payload = serde_json::to_vec(cursor).map_err(|_| Error::from(InternalError::Unhandled))?;
    let tag = signer.sign_payload(&payload);
    let mut buf = Vec::with_capacity(CURSOR_MAC_LEN + payload.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&payload);
    Ok(hex_lower(&buf))
}

fn decode_cursor(signer: &CursorSigner, cursor: &str) -> Result<PageCursor, Error> {
    let bytes = hex_decode(cursor).ok_or(crate::error::FilterError::InvalidValue)?;
    if bytes.len() <= CURSOR_MAC_LEN {
        return Err(crate::error::FilterError::InvalidValue.into());
    }
    let (tag, payload) = bytes.split_at(CURSOR_MAC_LEN);
    if !signer.verify_payload(payload, tag) {
        return Err(crate::error::FilterError::InvalidValue.into());
    }
    serde_json::from_slice(payload).map_err(|_| crate::error::FilterError::InvalidValue.into())
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let high = hex_value(bytes[i])?;
        let low = hex_value(bytes[i + 1])?;
        decoded.push(high << 4 | low);
        i += 2;
    }
    Some(decoded)
}

fn ingest_version_for_entity(
    readiness: Option<&watch::Receiver<ReadinessSnapshot>>,
    dataset_id: &str,
    entity: &EntityModel,
) -> Option<String> {
    let readiness = readiness?;
    let dataset = id_from_str::<DatasetId>(dataset_id)?;
    let resource = id_from_str::<ResourceId>(&entity.table_id)?;
    readiness
        .borrow()
        .ready
        .get(&(dataset, resource))
        .map(|entry| entry.ingest_ulid.to_string())
}

fn id_from_str<T>(value: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(&format!(r#""{value}""#)).ok()
}

fn parse_filter_name(name: &str) -> Result<(&str, EntityFilterOp), Error> {
    match name.rsplit_once('.') {
        Some((field, "in")) if !field.is_empty() => Ok((field, EntityFilterOp::In)),
        Some((field, "gte")) if !field.is_empty() => Ok((field, EntityFilterOp::Gte)),
        Some((field, "lte")) if !field.is_empty() => Ok((field, EntityFilterOp::Lte)),
        Some((field, "between")) if !field.is_empty() => Ok((field, EntityFilterOp::Between)),
        Some(_) => Err(crate::error::FilterError::UnsupportedOp.into()),
        None => Ok((name, EntityFilterOp::Eq)),
    }
}

fn parse_filter_value(op: EntityFilterOp, value: String) -> Result<Value, Error> {
    match op {
        EntityFilterOp::Eq | EntityFilterOp::Gte | EntityFilterOp::Lte => Ok(json!(value)),
        EntityFilterOp::In => {
            let values = split_csv_values(&value)?;
            if values.len() > 100 {
                return Err(crate::error::FilterError::TooManyValues.into());
            }
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
        EntityFilterOp::Between => {
            let values = split_csv_values(&value)?;
            if values.len() != 2 {
                return Err(crate::error::FilterError::InvalidRange.into());
            }
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
    }
}

fn split_csv_values(value: &str) -> Result<Vec<String>, Error> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(crate::error::FilterError::InvalidValue.into());
    }
    Ok(values)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
            "type": format!("{}entity/query_unavailable", crate::error::PROBLEM_TYPE_BASE),
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

fn cursor_invalidated() -> Response {
    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "type": format!("{}pagination/cursor_invalidated", crate::error::PROBLEM_TYPE_BASE),
            "title": "Pagination cursor invalidated",
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "detail": "cursor no longer matches the requested page",
            "code": CURSOR_INVALIDATED_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(CURSOR_INVALIDATED_CODE.to_string()));
    response
}
