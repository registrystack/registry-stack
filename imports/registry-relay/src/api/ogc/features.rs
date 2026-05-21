// SPDX-License-Identifier: Apache-2.0
//! Read-only OGC API Features routes for spatial registry entities.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use geojson::{Geometry, Value as GeoValue};
use ogcapi_types::common::{Conformance, LandingPage, Link};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::api::CursorSigner;
use crate::audit::{AuditContextExt, ErrorCodeExt};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{FieldType, SpatialBboxFieldsConfig, SpatialGeometryConfig, CRS84};
use crate::entity::{EntityModel, EntityRegistry, EntitySpatialModel};
use crate::error::{
    AuthError, Error, FilterError, InternalError, OgcError, QueryError, SpatialError,
};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine};

const GEOJSON: HeaderValue = HeaderValue::from_static("application/geo+json");
const JSON: &str = "application/json";
const GEOJSON_MIME: &str = "application/geo+json";
const OGC_BASE: &str = "/ogc/v1";
const DATA_PURPOSE_HEADER: &str = "data-purpose";
const MAX_FILTERS_PER_REQUEST: usize = 20;
const CURSOR_MAC_LEN: usize = 16;
const OPENAPI_ENABLED: bool = true;

const CONFORMANCE_CORE: &str = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core";
const CONFORMANCE_GEOJSON: &str = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson";
const CONFORMANCE_OAS30: &str = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/oas30";

/// Sub-router for the OGC API Features V1 surface.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/ogc/v1", get(landing))
        .route("/ogc/v1/conformance", get(conformance))
        .route("/ogc/v1/collections", get(collections))
        .route(
            "/ogc/v1/datasets/{dataset_id}/collections",
            get(dataset_collections),
        )
        .route(
            "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
            get(collection_detail),
        )
        .route(
            "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
            get(collection_items),
        )
        .route(
            "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
            get(feature_item),
        )
}

#[derive(Debug, Deserialize)]
struct CollectionPath {
    dataset_id: String,
    collection_id: String,
}

#[derive(Debug, Deserialize)]
struct DatasetPath {
    dataset_id: String,
}

#[derive(Debug, Deserialize)]
struct FeaturePath {
    dataset_id: String,
    collection_id: String,
    feature_id: String,
}

async fn landing(
    config: Option<Extension<Arc<crate::config::Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return query_unavailable("OGC landing route matched, but config is not installed");
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }

    let page = LandingPage::new("Registry Relay OGC API")
        .description("Spatial collections exposed from registry datasets.")
        .links(landing_links());
    Json(page).into_response()
}

async fn conformance(
    config: Option<Extension<Arc<crate::config::Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return query_unavailable("OGC conformance route matched, but config is not installed");
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }
    Json(Conformance::new(&conformance_uris())).into_response()
}

async fn collections(
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = ogc_state(config, registry) else {
        return query_unavailable("OGC collections route matched, but state is not installed");
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };

    let collections = spatial_collections(&config, &registry, &principal, None);
    if collections.is_empty() {
        return Error::from(AuthError::ScopeDenied {
            required: "metadata scope on at least one spatial entity".to_string(),
        })
        .into_response();
    }
    Json(json!({
        "links": [link_json(&format!("{OGC_BASE}/collections"), "self", JSON, None)],
        "collections": collections,
    }))
    .into_response()
}

async fn dataset_collections(
    Path(path): Path<DatasetPath>,
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = ogc_state(config, registry) else {
        return query_unavailable(
            "OGC dataset collections route matched, but state is not installed",
        );
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };

    let collections = spatial_collections(&config, &registry, &principal, Some(&path.dataset_id));
    if collections.is_empty() {
        return Error::from(OgcError::CollectionNotFound).into_response();
    }
    Json(json!({
        "links": [link_json(
            &format!("{OGC_BASE}/datasets/{}/collections", path.dataset_id),
            "self",
            JSON,
            None,
        )],
        "collections": collections,
    }))
    .into_response()
}

async fn collection_detail(
    Path(path): Path<CollectionPath>,
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = ogc_state(config, registry) else {
        return query_unavailable("OGC collection route matched, but state is not installed");
    };
    let Ok((entity, spatial)) = require_spatial_entity(
        &registry,
        &path.dataset_id,
        &path.collection_id,
        principal,
        AccessKind::Metadata,
    ) else {
        return Error::from(OgcError::CollectionNotFound).into_response();
    };

    let body = collection_json(&config, &path.dataset_id, entity, spatial);
    Json(body).into_response()
}

#[allow(clippy::too_many_arguments)]
async fn collection_items(
    Path(path): Path<CollectionPath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    signer: Option<Extension<Arc<CursorSigner>>>,
) -> Response {
    let Some((_, registry)) = ogc_state(config, registry) else {
        return query_unavailable("OGC items route matched, but state is not installed");
    };
    let Some(Extension(query)) = query else {
        return query_unavailable("OGC items route matched, but query engine is not installed");
    };
    let Some(Extension(signer)) = signer else {
        return query_unavailable("OGC items route matched, but cursor signer is not installed");
    };
    let principal_ref = principal.as_ref().map(|Extension(principal)| principal);
    let Ok((entity, spatial)) = require_spatial_entity(
        &registry,
        &path.dataset_id,
        &path.collection_id,
        principal.clone(),
        AccessKind::Read,
    ) else {
        return Error::from(OgcError::CollectionNotFound).into_response();
    };
    if let Err(error) = require_read_purpose_header(entity, &headers) {
        return error.into_response();
    }

    let parsed = match parse_items_query(entity, spatial, params, None) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = enforce_required_filters(entity, &parsed.caller_filters) {
        return error.into_response();
    }
    let query_context = cursor_context(
        &path.dataset_id,
        &path.collection_id,
        principal_ref,
        &parsed,
        projection_context(entity, spatial),
    );
    let mut entity_query = parsed.entity_query;
    let mut decoded_cursor = None;
    if let Some(after) = parsed.after.as_deref() {
        let cursor = match decode_ogc_cursor(&signer, after) {
            Ok(cursor) if cursor.version == 1 && cursor.context == query_context => cursor,
            _ => return Error::from(QueryError::CursorInvalid).into_response(),
        };
        entity_query = entity_query.with_after_primary_key(cursor.position.clone());
        decoded_cursor = Some(cursor);
    }

    match query
        .read_collection(&path.dataset_id, &entity.name, entity_query)
        .await
    {
        Ok(rows) => {
            if let Some(cursor) = decoded_cursor.as_ref() {
                if cursor.ingest_version != rows.cursor_ingest_version {
                    return Error::from(QueryError::CursorInvalid).into_response();
                }
            }
            let feature_rows = match rows_to_features(
                &path.dataset_id,
                entity,
                spatial,
                &parsed.link_params,
                rows.rows,
            ) {
                Ok(features) => features,
                Err(error) => {
                    let response = error.error.into_response();
                    return with_audit_context(
                        response,
                        audit_context(
                            entity,
                            spatial,
                            &path.dataset_id,
                            OgcAuditContext {
                                underlying_kind: "entity_collection",
                                primary_key: None,
                                row_count: None,
                                null_geometry_count: Some(error.null_geometry_count),
                                invalid_geometry_count: Some(error.invalid_geometry_count),
                            },
                        ),
                    );
                }
            };
            let row_count = feature_rows.features.len() as u64;
            let next = rows.next_primary_key.map(|position| OgcCursor {
                version: 1,
                context: query_context,
                position,
                ingest_version: rows.cursor_ingest_version,
            });
            let next = match next {
                Some(cursor) => match encode_ogc_cursor(&signer, &cursor) {
                    Ok(encoded) => Some(encoded),
                    Err(error) => return error.into_response(),
                },
                None => None,
            };
            let body = feature_collection_json(
                &path.dataset_id,
                &path.collection_id,
                &parsed.link_params,
                feature_rows.features,
                next.as_deref(),
            );
            let mut response = Json(body).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, GEOJSON);
            with_audit_context(
                response,
                audit_context(
                    entity,
                    spatial,
                    &path.dataset_id,
                    OgcAuditContext {
                        underlying_kind: "entity_collection",
                        primary_key: None,
                        row_count: Some(row_count),
                        null_geometry_count: Some(feature_rows.null_geometry_count),
                        invalid_geometry_count: Some(feature_rows.invalid_geometry_count),
                    },
                ),
            )
        }
        Err(error) => error.into_response(),
    }
}

async fn feature_item(
    Path(path): Path<FeaturePath>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
) -> Response {
    let Some((_, registry)) = ogc_state(config, registry) else {
        return query_unavailable("OGC feature route matched, but state is not installed");
    };
    let Some(Extension(query)) = query else {
        return query_unavailable("OGC feature route matched, but query engine is not installed");
    };
    let Ok((entity, spatial)) = require_spatial_entity(
        &registry,
        &path.dataset_id,
        &path.collection_id,
        principal,
        AccessKind::Read,
    ) else {
        return Error::from(OgcError::FeatureNotFound).into_response();
    };
    if let Err(error) = require_read_purpose_header(entity, &headers) {
        return error.into_response();
    }

    let parsed = match parse_items_query(entity, spatial, params, Some(&path.feature_id)) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    if parsed.after.is_some() {
        return Error::from(SpatialError::FilterUnsupported {
            parameter: "after".to_string(),
        })
        .into_response();
    }
    if let Err(error) = enforce_required_filters(entity, &parsed.caller_filters) {
        return error.into_response();
    }

    match query
        .read_collection(&path.dataset_id, &entity.name, parsed.entity_query)
        .await
    {
        Ok(rows) => {
            let feature_rows = match rows_to_features(
                &path.dataset_id,
                entity,
                spatial,
                &parsed.link_params,
                rows.rows,
            ) {
                Ok(features) => features,
                Err(error) => {
                    let response = error.error.into_response();
                    return with_audit_context(
                        response,
                        audit_context(
                            entity,
                            spatial,
                            &path.dataset_id,
                            OgcAuditContext {
                                underlying_kind: "entity_record",
                                primary_key: Some(path.feature_id),
                                row_count: None,
                                null_geometry_count: Some(error.null_geometry_count),
                                invalid_geometry_count: Some(error.invalid_geometry_count),
                            },
                        ),
                    );
                }
            };
            let Some(feature) = feature_rows.features.into_iter().next() else {
                return Error::from(OgcError::FeatureNotFound).into_response();
            };
            let mut response = Json(feature).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, GEOJSON);
            with_audit_context(
                response,
                audit_context(
                    entity,
                    spatial,
                    &path.dataset_id,
                    OgcAuditContext {
                        underlying_kind: "entity_record",
                        primary_key: Some(path.feature_id),
                        row_count: Some(1),
                        null_geometry_count: Some(feature_rows.null_geometry_count),
                        invalid_geometry_count: Some(feature_rows.invalid_geometry_count),
                    },
                ),
            )
        }
        Err(error) => error.into_response(),
    }
}

fn ogc_state(
    config: Option<Extension<Arc<crate::config::Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<crate::config::Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn require_any_metadata_scope(
    config: &crate::config::Config,
    principal: Option<Extension<Principal>>,
) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    if config.datasets.iter().any(|dataset| {
        dataset.entities.iter().any(|entity| {
            entity.spatial.is_some() && principal.scopes.contains(&entity.access.metadata_scope)
        })
    }) {
        Ok(())
    } else {
        Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one spatial entity".to_string(),
        }
        .into())
    }
}

#[derive(Clone, Copy)]
enum AccessKind {
    Metadata,
    Read,
}

fn require_spatial_entity<'a>(
    registry: &'a EntityRegistry,
    dataset_id: &str,
    collection_id: &str,
    principal: Option<Extension<Principal>>,
    access: AccessKind,
) -> Result<(&'a EntityModel, &'a EntitySpatialModel), Error> {
    let dataset = registry
        .dataset(dataset_id)
        .ok_or(OgcError::CollectionNotFound)?;
    let (entity, spatial) = dataset
        .entities()
        .find_map(|entity| {
            let spatial = entity.spatial.as_ref()?;
            (spatial.collection_id == collection_id).then_some((entity, spatial))
        })
        .ok_or(OgcError::CollectionNotFound)?;
    let required = match access {
        AccessKind::Metadata => &entity.access.metadata_scope,
        AccessKind::Read => &entity.access.read_scope,
    };
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, required)?;
    Ok((entity, spatial))
}

fn require_read_purpose_header(entity: &EntityModel, headers: &HeaderMap) -> Result<(), Error> {
    if !entity.api.require_purpose_header || purpose_header_value(headers).is_some() {
        return Ok(());
    }
    Err(AuthError::PurposeRequired.into())
}

fn purpose_header_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DATA_PURPOSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn spatial_collections(
    config: &crate::config::Config,
    registry: &EntityRegistry,
    principal: &Principal,
    dataset_filter: Option<&str>,
) -> Vec<Value> {
    config
        .datasets
        .iter()
        .filter(|dataset| dataset_filter.is_none_or(|id| id == dataset.id.as_str()))
        .filter_map(|dataset| {
            let compiled = registry.dataset(dataset.id.as_str())?;
            Some((dataset, compiled))
        })
        .flat_map(|(dataset, compiled)| {
            compiled.entities().filter_map(move |entity| {
                let spatial = entity.spatial.as_ref()?;
                if !principal.scopes.contains(&entity.access.metadata_scope) {
                    return None;
                }
                Some(collection_json(
                    config,
                    dataset.id.as_str(),
                    entity,
                    spatial,
                ))
            })
        })
        .collect()
}

fn collection_json(
    _config: &crate::config::Config,
    dataset_id: &str,
    entity: &EntityModel,
    spatial: &EntitySpatialModel,
) -> Value {
    let collection_path = format!(
        "{OGC_BASE}/datasets/{dataset_id}/collections/{}",
        spatial.collection_id
    );
    let items_path = format!("{collection_path}/items");
    let title = spatial.title.clone().unwrap_or_else(|| entity.name.clone());
    let supported_query_parameters = supported_query_parameters(entity, spatial);
    json!({
        "id": format!("{dataset_id}.{}", spatial.collection_id),
        "title": title,
        "description": spatial.description,
        "itemType": "feature",
        "crs": [CRS84],
        "storageCrs": CRS84,
        "properties": {
            "dataset_id": dataset_id,
            "collection_id": spatial.collection_id,
            "propertyNames": property_names(entity, spatial),
            "supportedQueryParameters": supported_query_parameters,
        },
        "links": [
            link_json(&collection_path, "self", JSON, None),
            link_json(&items_path, "items", GEOJSON_MIME, None),
        ],
    })
}

fn supported_query_parameters(entity: &EntityModel, spatial: &EntitySpatialModel) -> Vec<String> {
    let mut params = vec!["limit".to_string()];
    if supports_bbox(spatial) {
        params.push("bbox".to_string());
        params.push("bbox-crs".to_string());
    }
    if spatial.datetime_field.is_some() {
        params.push("datetime".to_string());
    }
    params.push("after".to_string());
    params.extend(
        entity
            .api
            .allowed_filters
            .iter()
            .map(|filter| filter.field.clone()),
    );
    params.dedup();
    params
}

fn supports_bbox(spatial: &EntitySpatialModel) -> bool {
    matches!(spatial.geometry, SpatialGeometryConfig::Point { .. }) || spatial.bbox_fields.is_some()
}

fn property_names(entity: &EntityModel, spatial: &EntitySpatialModel) -> Vec<String> {
    let mut hidden = geometry_carrier_fields(spatial);
    if let Some(bbox) = &spatial.bbox_fields {
        hidden.extend([
            bbox.min_x.clone(),
            bbox.min_y.clone(),
            bbox.max_x.clone(),
            bbox.max_y.clone(),
        ]);
    }
    entity
        .fields
        .iter()
        .filter(|field| !hidden.iter().any(|hidden| hidden == &field.name))
        .map(|field| field.name.clone())
        .collect()
}

struct ParsedItemsQuery {
    entity_query: EntityCollectionQuery,
    caller_filters: Vec<EntityFilter>,
    link_params: BTreeMap<String, String>,
    cursor_params: BTreeMap<String, String>,
    after: Option<String>,
}

fn parse_items_query(
    entity: &EntityModel,
    spatial: &EntitySpatialModel,
    params: HashMap<String, String>,
    feature_id: Option<&str>,
) -> Result<ParsedItemsQuery, Error> {
    let mut query = EntityCollectionQuery::new();
    let mut caller_filters = Vec::new();
    let mut link_params = BTreeMap::new();
    let mut cursor_params = BTreeMap::new();
    let mut after = None;
    let mut bbox = None;
    let mut bbox_crs = None;
    let mut datetime = None;

    for (name, value) in params {
        match name.as_str() {
            "limit" => {
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| FilterError::InvalidValue)?;
                query = query.with_limit(limit);
                link_params.insert(name.clone(), value.clone());
                cursor_params.insert(name, value);
            }
            "after" => {
                after = Some(value);
            }
            "bbox" => {
                bbox = Some(value.clone());
                link_params.insert(name.clone(), value.clone());
                cursor_params.insert(name, value);
            }
            "bbox-crs" => {
                bbox_crs = Some(value.clone());
                link_params.insert(name.clone(), value.clone());
                cursor_params.insert(name, value);
            }
            "datetime" => {
                datetime = Some(value.clone());
                link_params.insert(name.clone(), value.clone());
                cursor_params.insert(name, value);
            }
            "offset" | "filter" | "filter-lang" | "crs" => {
                return Err(SpatialError::FilterUnsupported { parameter: name }.into());
            }
            _ => {
                if caller_filters.len() >= MAX_FILTERS_PER_REQUEST {
                    return Err(FilterError::TooManyFilters.into());
                }
                let (field, op) = parse_filter_name(&name)?;
                let value = parse_filter_value(op, value)?;
                let filter = EntityFilter::with_op(field, op, value);
                caller_filters.push(filter.clone());
                query = query.with_filter(filter);
                let link_value = filter_value_for_link(&caller_filters);
                link_params.insert(name.clone(), link_value.clone());
                cursor_params.insert(name, link_value);
            }
        }
    }

    if bbox_crs.as_deref().is_some_and(|crs| crs != CRS84) {
        return Err(SpatialError::CrsUnsupported.into());
    }
    if let Some(bbox) = bbox {
        query = apply_bbox(spatial, query, &bbox)?;
    }
    if let Some(datetime) = datetime {
        query = apply_datetime(spatial, query, &datetime)?;
    }
    if let Some(feature_id) = feature_id {
        query = query.with_trusted_filter(EntityFilter::eq(
            entity.primary_key.name.clone(),
            feature_id,
        ));
    }

    Ok(ParsedItemsQuery {
        entity_query: query,
        caller_filters,
        link_params,
        cursor_params,
        after,
    })
}

fn filter_value_for_link(filters: &[EntityFilter]) -> String {
    filters
        .last()
        .map(|filter| match &filter.value {
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            Value::String(value) => value.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

fn parse_filter_name(name: &str) -> Result<(String, EntityFilterOp), Error> {
    match name.rsplit_once('.') {
        Some((field, "in")) if !field.is_empty() => Ok((field.to_string(), EntityFilterOp::In)),
        Some((field, "gte")) if !field.is_empty() => Ok((field.to_string(), EntityFilterOp::Gte)),
        Some((field, "lte")) if !field.is_empty() => Ok((field.to_string(), EntityFilterOp::Lte)),
        Some((field, "between")) if !field.is_empty() => {
            Ok((field.to_string(), EntityFilterOp::Between))
        }
        Some(_) => Err(FilterError::UnsupportedOp.into()),
        None => Ok((name.to_string(), EntityFilterOp::Eq)),
    }
}

fn parse_filter_value(op: EntityFilterOp, value: String) -> Result<Value, Error> {
    match op {
        EntityFilterOp::Eq | EntityFilterOp::Gte | EntityFilterOp::Lte => Ok(json!(value)),
        EntityFilterOp::In => {
            let values = split_csv_values(&value)?;
            if values.len() > 100 {
                return Err(FilterError::TooManyValues.into());
            }
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
        EntityFilterOp::Between => {
            let values = split_csv_values(&value)?;
            if values.len() != 2 {
                return Err(FilterError::InvalidRange.into());
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
        return Err(FilterError::InvalidValue.into());
    }
    Ok(values)
}

fn enforce_required_filters(entity: &EntityModel, filters: &[EntityFilter]) -> Result<(), Error> {
    if entity.api.required_filters.is_empty() {
        return Ok(());
    }
    if filters.iter().any(|filter| {
        entity
            .api
            .required_filters
            .iter()
            .any(|required| required == &filter.field)
    }) {
        Ok(())
    } else {
        Err(crate::error::EntityError::FilterRequired {
            required: entity.api.required_filters.clone(),
        }
        .into())
    }
}

#[derive(Clone, Copy, Debug)]
struct Bbox {
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

fn apply_bbox(
    spatial: &EntitySpatialModel,
    mut query: EntityCollectionQuery,
    value: &str,
) -> Result<EntityCollectionQuery, Error> {
    let bbox = parse_bbox(value, spatial.max_bbox_degrees)?;
    match &spatial.geometry {
        SpatialGeometryConfig::Point {
            longitude_field,
            latitude_field,
            ..
        } => {
            query = query
                .with_trusted_filter(EntityFilter::with_op(
                    longitude_field.clone(),
                    EntityFilterOp::Gte,
                    json!(bbox.min_x),
                ))
                .with_trusted_filter(EntityFilter::with_op(
                    longitude_field.clone(),
                    EntityFilterOp::Lte,
                    json!(bbox.max_x),
                ))
                .with_trusted_filter(EntityFilter::with_op(
                    latitude_field.clone(),
                    EntityFilterOp::Gte,
                    json!(bbox.min_y),
                ))
                .with_trusted_filter(EntityFilter::with_op(
                    latitude_field.clone(),
                    EntityFilterOp::Lte,
                    json!(bbox.max_y),
                ));
        }
        SpatialGeometryConfig::Geojson { .. }
        | SpatialGeometryConfig::Wkt { .. }
        | SpatialGeometryConfig::Wkb { .. } => {
            let Some(fields) = &spatial.bbox_fields else {
                return Err(SpatialError::FilterUnsupported {
                    parameter: "bbox".to_string(),
                }
                .into());
            };
            query = apply_bbox_fields(query, fields, bbox);
        }
    }
    Ok(query)
}

fn apply_bbox_fields(
    query: EntityCollectionQuery,
    fields: &SpatialBboxFieldsConfig,
    bbox: Bbox,
) -> EntityCollectionQuery {
    query
        .with_trusted_filter(EntityFilter::with_op(
            fields.max_x.clone(),
            EntityFilterOp::Gte,
            json!(bbox.min_x),
        ))
        .with_trusted_filter(EntityFilter::with_op(
            fields.min_x.clone(),
            EntityFilterOp::Lte,
            json!(bbox.max_x),
        ))
        .with_trusted_filter(EntityFilter::with_op(
            fields.max_y.clone(),
            EntityFilterOp::Gte,
            json!(bbox.min_y),
        ))
        .with_trusted_filter(EntityFilter::with_op(
            fields.min_y.clone(),
            EntityFilterOp::Lte,
            json!(bbox.max_y),
        ))
}

fn parse_bbox(value: &str, max_degrees: f64) -> Result<Bbox, Error> {
    let parts = value
        .split(',')
        .map(str::trim)
        .map(str::parse::<f64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SpatialError::BboxInvalid)?;
    if parts.len() != 4 || parts.iter().any(|value| !value.is_finite()) {
        return Err(SpatialError::BboxInvalid.into());
    }
    let bbox = Bbox {
        min_x: parts[0],
        min_y: parts[1],
        max_x: parts[2],
        max_y: parts[3],
    };
    if bbox.min_x > bbox.max_x {
        return Err(SpatialError::BboxAntimeridianUnsupported.into());
    }
    if bbox.min_y > bbox.max_y {
        return Err(SpatialError::BboxInvalid.into());
    }
    if bbox.max_x - bbox.min_x > max_degrees || bbox.max_y - bbox.min_y > max_degrees {
        return Err(SpatialError::BboxInvalid.into());
    }
    Ok(bbox)
}

fn apply_datetime(
    spatial: &EntitySpatialModel,
    mut query: EntityCollectionQuery,
    value: &str,
) -> Result<EntityCollectionQuery, Error> {
    let Some(field) = &spatial.datetime_field else {
        return Err(SpatialError::FilterUnsupported {
            parameter: "datetime".to_string(),
        }
        .into());
    };
    if value == "../.." {
        return Err(FilterError::InvalidRange.into());
    }
    if let Some((start, end)) = value.split_once('/') {
        let has_start = start != ".." && !start.is_empty();
        let has_end = end != ".." && !end.is_empty();
        if !has_start && !has_end {
            return Err(FilterError::InvalidRange.into());
        }
        if has_start {
            let start = normalize_datetime_filter_value(spatial, start)?;
            query = query.with_trusted_filter(EntityFilter::with_op(
                field.clone(),
                EntityFilterOp::Gte,
                json!(start),
            ));
        }
        if has_end {
            let end = normalize_datetime_filter_value(spatial, end)?;
            query = query.with_trusted_filter(EntityFilter::with_op(
                field.clone(),
                EntityFilterOp::Lte,
                json!(end),
            ));
        }
    } else {
        let value = normalize_datetime_filter_value(spatial, value)?;
        query = query.with_trusted_filter(EntityFilter::eq(field.clone(), value));
    }
    Ok(query)
}

fn normalize_datetime_filter_value(
    spatial: &EntitySpatialModel,
    value: &str,
) -> Result<String, Error> {
    validate_datetime_value(value)?;
    if !matches!(spatial.datetime_field_type, Some(FieldType::Date)) {
        return Ok(value.to_string());
    }
    if let Ok(date) = Date::parse(
        value,
        &time::macros::format_description!("[year]-[month]-[day]"),
    ) {
        return Ok(date.to_string());
    }
    let instant = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| FilterError::InvalidValue)?;
    Ok(instant.date().to_string())
}

fn validate_datetime_value(value: &str) -> Result<(), Error> {
    if OffsetDateTime::parse(value, &Rfc3339).is_ok()
        || Date::parse(
            value,
            &time::macros::format_description!("[year]-[month]-[day]"),
        )
        .is_ok()
    {
        Ok(())
    } else {
        Err(FilterError::InvalidValue.into())
    }
}

struct FeatureRows {
    features: Vec<Value>,
    null_geometry_count: u64,
    invalid_geometry_count: u64,
}

struct FeatureRowsError {
    error: Error,
    null_geometry_count: u64,
    invalid_geometry_count: u64,
}

fn rows_to_features(
    dataset_id: &str,
    entity: &EntityModel,
    spatial: &EntitySpatialModel,
    link_params: &BTreeMap<String, String>,
    rows: Vec<Value>,
) -> Result<FeatureRows, FeatureRowsError> {
    let mut features = Vec::with_capacity(rows.len());
    let mut null_geometry_count = 0;
    for row in rows {
        let feature = match row_to_feature(dataset_id, entity, spatial, link_params, row) {
            Ok(feature) => feature,
            Err(error) => {
                return Err(FeatureRowsError {
                    invalid_geometry_count: u64::from(is_geometry_row_error(&error)),
                    error,
                    null_geometry_count,
                });
            }
        };
        if feature.get("geometry").is_some_and(Value::is_null) {
            null_geometry_count += 1;
        }
        features.push(feature);
    }
    Ok(FeatureRows {
        features,
        null_geometry_count,
        invalid_geometry_count: 0,
    })
}

fn is_geometry_row_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Spatial(SpatialError::GeometryInvalid | SpatialError::GeometryTooLarge)
    )
}

fn row_to_feature(
    dataset_id: &str,
    entity: &EntityModel,
    spatial: &EntitySpatialModel,
    link_params: &BTreeMap<String, String>,
    row: Value,
) -> Result<Value, Error> {
    let Value::Object(mut object) = row else {
        return Err(InternalError::Unhandled.into());
    };
    let id = object
        .get(&entity.primary_key.name)
        .and_then(value_to_id)
        .ok_or(InternalError::Unhandled)?;
    let geometry = geometry_from_row(spatial, &object)?;
    for field in geometry_carrier_fields(spatial) {
        object.remove(&field);
    }
    if let Some(bbox) = &spatial.bbox_fields {
        for field in [&bbox.min_x, &bbox.min_y, &bbox.max_x, &bbox.max_y] {
            object.remove(field);
        }
    }
    Ok(json!({
        "type": "Feature",
        "id": id,
        "geometry": geometry,
        "properties": object,
        "links": [
            link_json(
                &feature_url(
                    dataset_id,
                    &spatial.collection_id,
                    &id,
                    link_params,
                ),
                "self",
                GEOJSON_MIME,
                None,
            ),
            link_json(
                &format!(
                    "{OGC_BASE}/datasets/{dataset_id}/collections/{}",
                    spatial.collection_id
                ),
                "collection",
                JSON,
                None,
            )
        ],
    }))
}

fn geometry_from_row(
    spatial: &EntitySpatialModel,
    object: &Map<String, Value>,
) -> Result<Value, Error> {
    match &spatial.geometry {
        SpatialGeometryConfig::Point {
            longitude_field,
            latitude_field,
            ..
        } => {
            let lon = object.get(longitude_field).and_then(Value::as_f64);
            let lat = object.get(latitude_field).and_then(Value::as_f64);
            match (lon, lat) {
                (Some(lon), Some(lat)) => Ok(json!({"type": "Point", "coordinates": [lon, lat]})),
                _ if object.get(longitude_field).is_some_and(Value::is_null)
                    || object.get(latitude_field).is_some_and(Value::is_null) =>
                {
                    Ok(Value::Null)
                }
                _ => Err(SpatialError::GeometryInvalid.into()),
            }
        }
        SpatialGeometryConfig::Geojson { field, .. } => {
            let Some(value) = object.get(field) else {
                return Err(SpatialError::GeometryInvalid.into());
            };
            if value.is_null() {
                return Ok(Value::Null);
            }
            let geometry = match value {
                Value::Object(_) => serde_json::from_value::<Geometry>(value.clone())
                    .map_err(|_| SpatialError::GeometryInvalid)?,
                Value::String(value) => {
                    Geometry::from_str(value).map_err(|_| SpatialError::GeometryInvalid)?
                }
                _ => return Err(SpatialError::GeometryInvalid.into()),
            };
            if count_vertices(&geometry.value) > spatial.max_geometry_vertices as usize {
                return Err(SpatialError::GeometryTooLarge.into());
            }
            serde_json::to_value(geometry).map_err(|_| Error::from(InternalError::Unhandled))
        }
        SpatialGeometryConfig::Wkt { .. } | SpatialGeometryConfig::Wkb { .. } => {
            Err(SpatialError::GeometryInvalid.into())
        }
    }
}

fn count_vertices(value: &GeoValue) -> usize {
    match value {
        GeoValue::Point(_) => 1,
        GeoValue::MultiPoint(points) | GeoValue::LineString(points) => points.len(),
        GeoValue::MultiLineString(lines) | GeoValue::Polygon(lines) => {
            lines.iter().map(Vec::len).sum()
        }
        GeoValue::MultiPolygon(polygons) => polygons
            .iter()
            .flat_map(|polygon| polygon.iter())
            .map(Vec::len)
            .sum(),
        GeoValue::GeometryCollection(geometries) => geometries
            .iter()
            .map(|geometry| count_vertices(&geometry.value))
            .sum(),
    }
}

fn value_to_id(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn geometry_carrier_fields(spatial: &EntitySpatialModel) -> Vec<String> {
    match &spatial.geometry {
        SpatialGeometryConfig::Point {
            longitude_field,
            latitude_field,
            ..
        } => vec![longitude_field.clone(), latitude_field.clone()],
        SpatialGeometryConfig::Geojson { field, .. }
        | SpatialGeometryConfig::Wkt { field, .. }
        | SpatialGeometryConfig::Wkb { field, .. } => vec![field.clone()],
    }
}

fn feature_collection_json(
    dataset_id: &str,
    collection_id: &str,
    params: &BTreeMap<String, String>,
    features: Vec<Value>,
    next: Option<&str>,
) -> Value {
    let mut links = vec![
        link_json(
            &items_url(dataset_id, collection_id, params, None),
            "self",
            GEOJSON_MIME,
            None,
        ),
        link_json(
            &items_url(dataset_id, collection_id, params, None),
            "first",
            GEOJSON_MIME,
            None,
        ),
    ];
    if let Some(next) = next {
        links.push(link_json(
            &items_url(dataset_id, collection_id, params, Some(next)),
            "next",
            GEOJSON_MIME,
            None,
        ));
    }
    json!({
        "type": "FeatureCollection",
        "timeStamp": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        "numberReturned": features.len(),
        "links": links,
        "features": features,
    })
}

fn items_url(
    dataset_id: &str,
    collection_id: &str,
    params: &BTreeMap<String, String>,
    after: Option<&str>,
) -> String {
    let mut query = params.clone();
    if let Some(after) = after {
        query.insert("after".to_string(), after.to_string());
    } else {
        query.remove("after");
    }
    let path = format!(
        "{OGC_BASE}/datasets/{}/collections/{}/items",
        percent_encode_component(dataset_id),
        percent_encode_component(collection_id)
    );
    if query.is_empty() {
        path
    } else {
        format!("{}?{}", path, encoded_query(&query))
    }
}

fn feature_url(
    dataset_id: &str,
    collection_id: &str,
    feature_id: &str,
    params: &BTreeMap<String, String>,
) -> String {
    let path = format!(
        "{OGC_BASE}/datasets/{}/collections/{}/items/{}",
        percent_encode_component(dataset_id),
        percent_encode_component(collection_id),
        percent_encode_component(feature_id)
    );
    if params.is_empty() {
        path
    } else {
        format!("{}?{}", path, encoded_query(params))
    }
}

fn encoded_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                percent_encode_component(name),
                percent_encode_component(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte))
            }
            _ => {
                use std::fmt::Write as _;
                write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
            }
        }
    }
    encoded
}

#[derive(Debug, Deserialize, Serialize)]
struct OgcCursor {
    version: u8,
    context: OgcCursorContext,
    position: Value,
    ingest_version: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct OgcCursorContext {
    dataset_id: String,
    collection_id: String,
    principal_id: Option<String>,
    projection: Vec<String>,
    params: BTreeMap<String, String>,
}

fn cursor_context(
    dataset_id: &str,
    collection_id: &str,
    principal: Option<&Principal>,
    parsed: &ParsedItemsQuery,
    projection: Vec<String>,
) -> OgcCursorContext {
    OgcCursorContext {
        dataset_id: dataset_id.to_string(),
        collection_id: collection_id.to_string(),
        principal_id: principal.map(|principal| principal.principal_id.clone()),
        projection,
        params: parsed.cursor_params.clone(),
    }
}

fn projection_context(entity: &EntityModel, spatial: &EntitySpatialModel) -> Vec<String> {
    // This is currently the config-level entity projection. Keep it in
    // the cursor context so future per-principal field visibility can
    // tighten cursor replay without changing the cursor schema.
    property_names(entity, spatial)
}

fn encode_ogc_cursor(signer: &CursorSigner, cursor: &OgcCursor) -> Result<String, Error> {
    let payload = serde_json::to_vec(cursor).map_err(|_| Error::from(InternalError::Unhandled))?;
    let tag = signer.sign_payload(&payload);
    let mut buf = Vec::with_capacity(CURSOR_MAC_LEN + payload.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&payload);
    Ok(hex_lower(&buf))
}

fn decode_ogc_cursor(signer: &CursorSigner, cursor: &str) -> Result<OgcCursor, Error> {
    let bytes = hex_decode(cursor).ok_or(QueryError::CursorInvalid)?;
    if bytes.len() <= CURSOR_MAC_LEN {
        return Err(QueryError::CursorInvalid.into());
    }
    let (tag, payload) = bytes.split_at(CURSOR_MAC_LEN);
    if !signer.verify_payload(payload, tag) {
        return Err(QueryError::CursorInvalid.into());
    }
    serde_json::from_slice(payload).map_err(|_| QueryError::CursorInvalid.into())
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

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn link(href: &str, rel: &str, media_type: &str, title: &str) -> Link {
    Link::new(href, rel).mediatype(media_type).title(title)
}

fn link_json(href: &str, rel: &str, media_type: &str, title: Option<&str>) -> Value {
    let mut value = json!({
        "href": href,
        "rel": rel,
        "type": media_type,
    });
    if let Some(title) = title {
        value["title"] = json!(title);
    }
    value
}

fn landing_links() -> Vec<Link> {
    let mut links = vec![
        link(OGC_BASE, "self", JSON, "Landing page"),
        link(
            &format!("{OGC_BASE}/conformance"),
            "conformance",
            JSON,
            "Conformance",
        ),
        link(
            &format!("{OGC_BASE}/collections"),
            "data",
            JSON,
            "Collections",
        ),
    ];
    if openapi_enabled() {
        links.push(link(
            "/openapi.json",
            "service-desc",
            "application/vnd.oai.openapi+json;version=3.0",
            "OpenAPI definition",
        ));
    }
    links
}

fn conformance_uris() -> Vec<&'static str> {
    let mut conforms_to = vec![CONFORMANCE_CORE, CONFORMANCE_GEOJSON];
    if openapi_enabled() {
        conforms_to.push(CONFORMANCE_OAS30);
    }
    conforms_to
}

fn openapi_enabled() -> bool {
    // OpenAPI is always mounted today. Keep this as the single OGC gate
    // point so an eventual optional OpenAPI surface can drop both the
    // service-desc link and the oas30 conformance URI together.
    OPENAPI_ENABLED
}

struct OgcAuditContext {
    underlying_kind: &'static str,
    primary_key: Option<String>,
    row_count: Option<u64>,
    null_geometry_count: Option<u64>,
    invalid_geometry_count: Option<u64>,
}

fn audit_context(
    entity: &EntityModel,
    spatial: &EntitySpatialModel,
    dataset_id: &str,
    context: OgcAuditContext,
) -> AuditContextExt {
    AuditContextExt {
        dataset_id: Some(dataset_id.to_string()),
        entity_name: Some(entity.name.clone()),
        table_id: Some(entity.table_id.clone()),
        underlying_kind: Some(context.underlying_kind.to_string()),
        collection_id: Some(spatial.collection_id.clone()),
        primary_key: context.primary_key,
        null_geometry_count: context.null_geometry_count,
        invalid_geometry_count: context.invalid_geometry_count,
        row_count: context.row_count,
        ..AuditContextExt::default()
    }
}

fn with_audit_context(mut response: Response, context: AuditContextExt) -> Response {
    response.extensions_mut().insert(context);
    response
}

fn query_unavailable(message: &'static str) -> Response {
    tracing::error!(code = "entity.query_unavailable", "{message}");
    let mut response = Error::from(InternalError::Unhandled).into_response();
    response
        .extensions_mut()
        .insert(ErrorCodeExt("entity.query_unavailable".to_string()));
    *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EntityAccessConfig, EntityApiConfig};

    fn test_entity() -> EntityModel {
        let primary_key = crate::entity::EntityField {
            name: "id".to_string(),
            table_column: "id".to_string(),
        };
        EntityModel {
            name: "facility".to_string(),
            table_id: "facilities_table".to_string(),
            primary_key: primary_key.clone(),
            fields: vec![
                primary_key,
                crate::entity::EntityField {
                    name: "geom".to_string(),
                    table_column: "geom".to_string(),
                },
                crate::entity::EntityField {
                    name: "updated_at".to_string(),
                    table_column: "updated_at".to_string(),
                },
            ],
            relationships: BTreeMap::new(),
            access: EntityAccessConfig {
                metadata_scope: "metadata".to_string(),
                aggregate_scope: "aggregate".to_string(),
                read_scope: "rows".to_string(),
                verify_scope: None,
                claim_verification_scope: None,
                evidence_verification_scope: String::new(),
            },
            api: EntityApiConfig {
                default_limit: 100,
                max_limit: 1000,
                require_purpose_header: false,
                required_filters: Vec::new(),
                allowed_filters: Vec::new(),
                allowed_expansions: Vec::new(),
            },
            spatial: None,
            claim_verification: None,
        }
    }

    fn geojson_spatial(max_geometry_vertices: u32) -> EntitySpatialModel {
        EntitySpatialModel {
            collection_id: "parcels".to_string(),
            title: None,
            description: None,
            geometry: SpatialGeometryConfig::Geojson {
                field: "geom".to_string(),
                crs: CRS84.to_string(),
            },
            bbox_fields: None,
            datetime_field: None,
            datetime_field_type: None,
            max_bbox_degrees: 5.0,
            max_geometry_vertices,
        }
    }

    #[test]
    fn rejects_antimeridian_bbox() {
        let error = parse_bbox("170,-10,-170,10", 100.0).expect_err("antimeridian rejected");
        assert_eq!(error.code(), "spatial.bbox_invalid");
        assert!(error.detail().contains("antimeridian"));
    }

    #[test]
    fn rejects_open_open_datetime() {
        let spatial = EntitySpatialModel {
            collection_id: "facilities".to_string(),
            title: None,
            description: None,
            geometry: SpatialGeometryConfig::Point {
                longitude_field: "lon".to_string(),
                latitude_field: "lat".to_string(),
                crs: CRS84.to_string(),
            },
            bbox_fields: None,
            datetime_field: Some("updated_at".to_string()),
            datetime_field_type: Some(FieldType::Timestamp),
            max_bbox_degrees: 5.0,
            max_geometry_vertices: 100,
        };
        assert!(apply_datetime(&spatial, EntityCollectionQuery::new(), "../..").is_err());
        let query = apply_datetime(
            &spatial,
            EntityCollectionQuery::new(),
            "2026-01-01T00:00:00Z/..",
        )
        .expect("open-ended start is accepted");
        assert_eq!(query.trusted_filters.len(), 1);
        let query = apply_datetime(&spatial, EntityCollectionQuery::new(), "../2026-01-31")
            .expect("open-ended end is accepted");
        assert_eq!(query.trusted_filters.len(), 1);
    }

    #[test]
    fn date_datetime_field_compares_at_date_precision() {
        let spatial = EntitySpatialModel {
            collection_id: "facilities".to_string(),
            title: None,
            description: None,
            geometry: SpatialGeometryConfig::Point {
                longitude_field: "lon".to_string(),
                latitude_field: "lat".to_string(),
                crs: CRS84.to_string(),
            },
            bbox_fields: None,
            datetime_field: Some("updated_on".to_string()),
            datetime_field_type: Some(FieldType::Date),
            max_bbox_degrees: 5.0,
            max_geometry_vertices: 100,
        };
        let query = apply_datetime(
            &spatial,
            EntityCollectionQuery::new(),
            "2026-01-01T23:30:00Z",
        )
        .expect("RFC3339 instant normalizes to UTC date for date fields");
        assert_eq!(query.trusted_filters.len(), 1);
        assert_eq!(query.trusted_filters[0].value, json!("2026-01-01"));
    }

    #[test]
    fn collection_discovery_only_advertises_supported_bbox_parameters() {
        let entity = test_entity();
        let spatial = geojson_spatial(10);
        let params = supported_query_parameters(&entity, &spatial);

        assert_eq!(params, vec!["limit".to_string(), "after".to_string()]);
    }

    #[test]
    fn ogc_audit_context_includes_spatial_fields() {
        let entity = test_entity();
        let spatial = geojson_spatial(10);
        let context = audit_context(
            &entity,
            &spatial,
            "civic_registry",
            OgcAuditContext {
                underlying_kind: "entity_record",
                primary_key: Some("FAC-001".to_string()),
                row_count: Some(1),
                null_geometry_count: Some(1),
                invalid_geometry_count: Some(0),
            },
        );

        assert_eq!(context.dataset_id.as_deref(), Some("civic_registry"));
        assert_eq!(context.entity_name.as_deref(), Some("facility"));
        assert_eq!(context.table_id.as_deref(), Some("facilities_table"));
        assert_eq!(context.underlying_kind.as_deref(), Some("entity_record"));
        assert_eq!(context.collection_id.as_deref(), Some("parcels"));
        assert_eq!(context.primary_key.as_deref(), Some("FAC-001"));
        assert_eq!(context.row_count, Some(1));
        assert_eq!(context.null_geometry_count, Some(1));
        assert_eq!(context.invalid_geometry_count, Some(0));
    }

    #[test]
    fn geojson_geometry_accepts_string_and_object_values() {
        let spatial = geojson_spatial(10);
        let mut object = Map::new();
        object.insert(
            "geom".to_string(),
            json!(r#"{"type":"Point","coordinates":[100.5,13.7]}"#),
        );
        let geometry = geometry_from_row(&spatial, &object).expect("string geometry parses");
        assert_eq!(geometry["type"], "Point");

        object.insert(
            "geom".to_string(),
            json!({"type":"Point","coordinates":[100.6,13.8]}),
        );
        let geometry = geometry_from_row(&spatial, &object).expect("object geometry parses");
        assert_eq!(geometry["coordinates"][0], 100.6);
    }

    #[test]
    fn geojson_geometry_enforces_vertex_cap() {
        let spatial = geojson_spatial(3);
        let mut object = Map::new();
        object.insert(
            "geom".to_string(),
            json!({
                "type": "LineString",
                "coordinates": [[100.0, 13.0], [100.1, 13.1], [100.2, 13.2], [100.3, 13.3]],
            }),
        );
        let error = geometry_from_row(&spatial, &object).expect_err("vertex cap is enforced");
        assert_eq!(error.code(), "spatial.geometry_too_large");
    }

    #[test]
    fn geojson_bbox_without_bbox_fields_is_unsupported() {
        let error = apply_bbox(
            &geojson_spatial(10),
            EntityCollectionQuery::new(),
            "100,13,101,14",
        )
        .expect_err("GeoJSON bbox needs precomputed bbox fields in phase one");
        assert_eq!(error.code(), "spatial.filter_unsupported");
    }

    #[test]
    fn urls_percent_encode_path_and_query_components() {
        let mut params = BTreeMap::new();
        params.insert("facility_type".to_string(), "clinic & urgent".to_string());
        assert_eq!(
            feature_url("civic_registry", "facilities", "FAC/004", &params),
            "/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC%2F004?facility_type=clinic%20%26%20urgent"
        );
    }
}
