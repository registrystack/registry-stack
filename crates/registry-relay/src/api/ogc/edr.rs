// SPDX-License-Identifier: Apache-2.0
//! OGC API EDR-style routes for spatial aggregate area queries.

use std::collections::HashMap;
use std::str::FromStr;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use geo::Intersects;
use geojson::{GeoJson, Geometry, GeometryValue};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::sync::watch;

use crate::api::governed::{
    attach_pdp_audit, require_governed_read_access, GovernedAccessError, GovernedReadDecision,
    GovernedRedactionProjection, GovernedRequestInfo,
};
use crate::audit::AuditContextExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{AggregateConfig, AggregateSpatialConfig, Config, DatasetConfig, EntityConfig};
use crate::entity::EntityRegistry;
use crate::error::{AggregateError, AuthError, Error, FilterError, OgcError, SpatialError};
use crate::ingest::ReadinessSnapshot;
use crate::query::{
    AggregateFilter, AggregateFilterOp, AggregateQueryRequest, EntityCollectionQuery,
    EntityQueryEngine,
};
use crate::runtime_config::RuntimeSnapshot;

const EDR_BASE: &str = "/ogc/edr/v1";
const GEOJSON: HeaderValue = HeaderValue::from_static("application/geo+json");
const JSON: &str = "application/json";

const CONFORMANCE_CORE: &str = "http://www.opengis.net/spec/ogcapi-edr-1/1.1/conf/core";
const CONFORMANCE_COLLECTIONS: &str =
    "http://www.opengis.net/spec/ogcapi-common-2/1.0/conf/collections";
const CONFORMANCE_AREA: &str = "http://www.opengis.net/spec/ogcapi-edr-1/1.1/conf/area";
const CONFORMANCE_GEOJSON: &str = "http://www.opengis.net/spec/ogcapi-edr-1/1.1/conf/geojson";
const CONFORMANCE_GROUP_BY: &str = "https://spec.spdci.org/spdci-aggregates-1/1.0/conf/group-by";
const PROFILE_GROUP_BY: &str = "https://spec.spdci.org/spdci-aggregates-1/1.0/profile/group-by";
const NO_MATCH_ADMIN_ID: &str = "__registry_relay_no_matching_admin_geometry__";

/// Upper bound on rows scanned while resolving an EDR `area` query, to
/// stop a single authenticated request from forcing an unbounded
/// full-table geometry scan. Generous: legitimate admin-boundary tables
/// are far smaller.
const MAX_AREA_SCAN_ROWS: usize = 1_000_000;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/ogc/edr/v1", get(landing))
        .route("/ogc/edr/v1/conformance", get(conformance))
        .route("/ogc/edr/v1/collections", get(collections))
        .route(
            "/ogc/edr/v1/collections/{collection_id}",
            get(collection_detail),
        )
        .route(
            "/ogc/edr/v1/collections/{collection_id}/area",
            get(area_get).post(area_post),
        )
}

#[derive(Debug, Deserialize)]
struct CollectionPath {
    collection_id: String,
}

#[derive(Debug, Deserialize)]
struct AreaQuery {
    coords: Option<String>,
    #[serde(rename = "parameter-name")]
    parameter_name: Option<String>,
    group_by: Option<String>,
    #[serde(default)]
    f: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, String>,
}

async fn landing(runtime: RuntimeSnapshot, principal: Option<Extension<Principal>>) -> Response {
    let Some(config) = runtime.config() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }
    Json(json!({
        "title": "Registry Relay OGC EDR API",
        "description": "Spatial aggregate area queries.",
        "links": [
            link(EDR_BASE, "self", JSON),
            link(&format!("{EDR_BASE}/conformance"), "conformance", JSON),
            link(&format!("{EDR_BASE}/collections"), "data", JSON)
        ]
    }))
    .into_response()
}

async fn conformance(
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(config) = runtime.config() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }
    Json(json!({
        "conformsTo": [
            CONFORMANCE_CORE,
            CONFORMANCE_COLLECTIONS,
            CONFORMANCE_AREA,
            CONFORMANCE_GEOJSON,
            CONFORMANCE_GROUP_BY
        ]
    }))
    .into_response()
}

async fn collections(
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(config) = runtime.config() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let collections = edr_collections(&config, &principal)
        .into_iter()
        .map(|collection| collection_json(&collection))
        .collect::<Vec<_>>();
    if collections.is_empty() {
        return Error::from(AuthError::ScopeDenied {
            required: "metadata scope on at least one EDR aggregate".to_string(),
        })
        .into_response();
    }
    Json(json!({
        "links": [link(&format!("{EDR_BASE}/collections"), "self", JSON)],
        "collections": collections
    }))
    .into_response()
}

async fn collection_detail(
    Path(path): Path<CollectionPath>,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(config) = runtime.config() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let Some(collection) = find_edr_collection(&config, &path.collection_id) else {
        return Error::from(OgcError::CollectionNotFound).into_response();
    };
    if let Err(error) = require_scope(&principal, &collection.metadata_scope) {
        return error.into_response();
    }
    if let Err(error) = require_collection_source_metadata_scope(&principal, &collection) {
        return error.into_response();
    }
    Json(collection_json(&collection)).into_response()
}

#[allow(clippy::too_many_arguments)]
async fn area_get(
    Path(path): Path<CollectionPath>,
    Query(params): Query<AreaQuery>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(coords) = params.coords.as_deref() else {
        return Error::from(SpatialError::GeometryInvalid).into_response();
    };
    let geometry = match geometry_from_wkt(coords) {
        Ok(geometry) => geometry,
        Err(error) => return error.into_response(),
    };
    area_common(path, params, geometry, headers, runtime, principal).await
}

#[allow(clippy::too_many_arguments)]
async fn area_post(
    Path(path): Path<CollectionPath>,
    Query(mut params): Query<AreaQuery>,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
    Json(body): Json<Value>,
) -> Response {
    apply_body_query_fields(&mut params, &body);
    let geometry = match geometry_from_geojson_value(&body) {
        Ok(geometry) => geometry,
        Err(error) => return error.into_response(),
    };
    area_common(path, params, geometry, headers, runtime, principal).await
}

#[allow(clippy::too_many_arguments)]
async fn area_common(
    path: CollectionPath,
    params: AreaQuery,
    input_geometry: Geometry,
    headers: HeaderMap,
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
) -> Response {
    if params
        .f
        .as_deref()
        .is_some_and(|format| format != "geojson")
    {
        return Error::from(AggregateError::FormatUnsupported).into_response();
    }
    let geometry_vertex_count = count_vertices(&input_geometry) as u64;
    let Some(config) = runtime.config() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let Some(aggregate_query) = runtime.aggregate_query() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(entity_query) = runtime.query() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(registry) = runtime.entity_registry() else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(collection) = find_edr_collection(&config, &path.collection_id) else {
        return Error::from(OgcError::CollectionNotFound).into_response();
    };
    if let Err(error) = require_scope(&principal, &collection.aggregate_scope) {
        return error.into_response();
    }
    if let Err(error) = require_collection_source_read_scope(&principal, &collection) {
        return error.into_response();
    }
    let governed_decision = match require_collection_source_governed_access(
        &runtime,
        &config,
        &collection,
        &headers,
        Some(&principal),
    ) {
        Ok(decision) => decision,
        Err(error) => return edr_access_error_response(error, &collection, geometry_vertex_count),
    };
    let AggregateSpatialConfig::AdminArea {
        dimension,
        geometry_entity,
        geometry_id_field,
        geometry_field,
        max_geometry_vertices,
        ..
    } = collection
        .aggregate
        .spatial
        .as_ref()
        .expect("spatial collection");
    if geometry_vertex_count > u64::from(*max_geometry_vertices) {
        return Error::from(SpatialError::GeometryTooLarge).into_response();
    }
    let matched = match matching_admin_geometries(
        &config,
        &principal,
        &entity_query,
        &collection.dataset_id,
        geometry_entity,
        geometry_id_field,
        geometry_field,
        aggregate_only_execution(collection.aggregate),
        *max_geometry_vertices,
        &input_geometry,
    )
    .await
    {
        Ok(matched) => matched,
        Err(error) => return error.into_response(),
    };
    let indicator_ids = params.parameter_name.as_deref().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    });
    let requested_group_by = params.group_by.clone();
    let group_by = requested_group_by
        .as_ref()
        .map(|group| vec![group.clone()])
        .unwrap_or_default();
    let matched_ids = if matched.is_empty() {
        vec![json!(NO_MATCH_ADMIN_ID)]
    } else {
        matched.iter().map(|item| json!(item.id)).collect()
    };
    let mut filters = vec![AggregateFilter {
        field: dimension.clone(),
        op: AggregateFilterOp::In,
        value: Value::Array(matched_ids),
    }];
    match edr_query_filters(&params) {
        Ok(mut extra_filters) => filters.append(&mut extra_filters),
        Err(error) => return error.into_response(),
    }
    let request = AggregateQueryRequest {
        indicators: indicator_ids,
        group_by: Some(group_by),
        filters,
        max_rows: None,
    };
    let mut result = match aggregate_query
        .execute_aggregate(&collection.dataset_id, &collection.aggregate_id, request)
        .await
    {
        Ok(result) => result,
        Err(error) => return error.into_response(),
    };
    crate::api::aggregates::redact_aggregate_result(
        &mut result,
        &governed_decision.redaction_fields,
    );
    let as_of = resolve_as_of(
        runtime.readiness_rx().as_ref(),
        &result,
        Some((&registry, &collection.dataset_id, geometry_entity)),
    );
    let features = if requested_group_by.is_some() {
        grouped_features(&result, dimension, &matched, as_of.as_deref())
    } else {
        single_feature(&result, input_geometry, as_of.as_deref())
    };
    let mut links = vec![
        link(
            &format!("{EDR_BASE}/collections/{}/area", path.collection_id),
            "self",
            "application/geo+json",
        ),
        link(
            &format!("{EDR_BASE}/collections/{}", path.collection_id),
            "collection",
            JSON,
        ),
    ];
    if requested_group_by.is_some() {
        links.push(link(PROFILE_GROUP_BY, "profile", JSON));
    }
    let mut freshness = json!({ "computed_at": result.computed_at });
    if let Some(as_of) = as_of.as_deref() {
        freshness["as_of"] = json!(as_of);
    }
    let feature_count = features.len() as u64;
    let mut response = Json(json!({
        "type": "FeatureCollection",
        "dataset_id": result.dataset_id,
        "aggregate_id": result.aggregate_id,
        "schema": {
            "dimensions": result.schema.dimensions,
            "measures": result.schema.indicators,
        },
        "disclosure_control": {
            "method": result.disclosure_control.method,
            "min_cell_size": result.disclosure_control.min_cell_size,
            "suppression": result.disclosure_control.suppression,
            "suppressed_observations": result.disclosure_control.suppressed_rows,
            "query_budget": {
                "tracked": result.disclosure_control.tracked_query_budget,
                "scope": result.disclosure_control.query_budget_scope,
            }
        },
        "freshness": freshness,
        "links": links,
        "features": features,
    }))
    .into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, GEOJSON);
    let mut audit_context = Some(AuditContextExt {
        dataset_id: Some(result.dataset_id.clone()),
        aggregate_id: Some(result.aggregate_id.clone()),
        collection_id: Some(path.collection_id),
        row_count: Some(feature_count),
        suppressed_groups: result.disclosure_control.suppressed_rows,
        geometry_vertex_count: Some(geometry_vertex_count),
        ..AuditContextExt::default()
    });
    attach_pdp_audit(&mut audit_context, governed_decision.audit.as_ref());
    if let Some(context) = audit_context {
        response.extensions_mut().insert(context);
    }
    response
}

#[derive(Clone)]
struct EdrCollection<'a> {
    dataset_id: String,
    aggregate_id: String,
    collection_id: String,
    metadata_scope: String,
    aggregate_scope: String,
    source_entity_metadata_scope: Option<String>,
    source_entity_read_scope: Option<String>,
    aggregate: &'a AggregateConfig,
}

#[derive(Clone)]
struct AdminGeometry {
    id: String,
    geometry: Geometry,
}

fn edr_collections<'a>(config: &'a Config, principal: &Principal) -> Vec<EdrCollection<'a>> {
    config
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset.aggregates.iter().filter_map(move |aggregate| {
                let collection = edr_collection(dataset, aggregate)?;
                require_scope(principal, &collection.metadata_scope).ok()?;
                if let Some(scope) = collection.source_entity_metadata_scope.as_deref() {
                    require_scope(principal, scope).ok()?;
                }
                Some(collection)
            })
        })
        .collect()
}

fn find_edr_collection<'a>(config: &'a Config, collection_id: &str) -> Option<EdrCollection<'a>> {
    config.datasets.iter().find_map(|dataset| {
        dataset
            .aggregates
            .iter()
            .filter_map(|aggregate| edr_collection(dataset, aggregate))
            .find(|collection| collection.collection_id == collection_id)
    })
}

fn edr_collection<'a>(
    dataset: &'a DatasetConfig,
    aggregate: &'a AggregateConfig,
) -> Option<EdrCollection<'a>> {
    let spatial = aggregate.spatial.as_ref()?;
    let dataset_id = dataset.id.as_str();
    let collection_id = match spatial {
        AggregateSpatialConfig::AdminArea { collection_id, .. } => collection_id
            .clone()
            .unwrap_or_else(|| format!("{}_{}", dataset_id, aggregate.id)),
    };
    Some(EdrCollection {
        dataset_id: dataset_id.to_string(),
        aggregate_id: aggregate.id.to_string(),
        collection_id,
        metadata_scope: aggregate
            .access
            .as_ref()
            .and_then(|access| access.metadata_scope.clone())
            .unwrap_or_else(|| format!("{dataset_id}:metadata")),
        aggregate_scope: aggregate
            .access
            .as_ref()
            .and_then(|access| access.aggregate_scope.clone())
            .unwrap_or_else(|| format!("{dataset_id}:aggregate")),
        source_entity_metadata_scope: aggregate
            .source_entity
            .as_deref()
            .and_then(|name| dataset.entities.iter().find(|entity| entity.name == name))
            .map(|entity| entity.access.metadata_scope.clone()),
        source_entity_read_scope: aggregate
            .source_entity
            .as_deref()
            .and_then(|name| dataset.entities.iter().find(|entity| entity.name == name))
            .map(|entity| entity.access.read_scope.clone()),
        aggregate,
    })
}

fn collection_json(collection: &EdrCollection<'_>) -> Value {
    json!({
        "id": collection.collection_id,
        "title": collection.aggregate.title,
        "description": collection.aggregate.description,
        "dataset_id": collection.dataset_id,
        "aggregate_id": collection.aggregate_id,
        "links": [
            link(&format!("{EDR_BASE}/collections/{}", collection.collection_id), "self", JSON),
            link(&format!("{EDR_BASE}/collections/{}/area", collection.collection_id), "data", "application/geo+json")
        ]
    })
}

#[allow(clippy::too_many_arguments)]
async fn matching_admin_geometries(
    config: &Config,
    principal: &Principal,
    entity_query: &EntityQueryEngine,
    dataset_id: &str,
    geometry_entity: &str,
    geometry_id_field: &str,
    geometry_field: &str,
    aggregate_only_execution: bool,
    max_geometry_vertices: u32,
    input_geometry: &Geometry,
) -> Result<Vec<AdminGeometry>, Error> {
    if !aggregate_only_execution {
        require_geometry_entity_read_scope(config, principal, dataset_id, geometry_entity)?;
    }
    let input_geo = geo_geometry(input_geometry)?;
    let mut matched = Vec::new();
    let mut after_primary_key = None;
    let mut scanned: usize = 0;
    loop {
        let mut query = EntityCollectionQuery::new()
            .with_fields([geometry_id_field.to_string(), geometry_field.to_string()])
            .with_limit(10_000);
        if let Some(after) = after_primary_key {
            query = query.with_after_primary_key(after);
        }
        let rows = entity_query
            .read_collection(dataset_id, geometry_entity, query)
            .await?;
        after_primary_key = rows.next_primary_key;
        scanned = scanned.saturating_add(rows.rows.len());
        if scanned > MAX_AREA_SCAN_ROWS {
            return Err(SpatialError::AreaScanTooLarge.into());
        }
        for row in rows.rows {
            let Some(object) = row.as_object() else {
                continue;
            };
            let Some(id) = object.get(geometry_id_field).and_then(value_to_id) else {
                continue;
            };
            let Some(geometry_value) = object.get(geometry_field) else {
                continue;
            };
            let geometry = geometry_from_geojson_value(geometry_value)?;
            if count_vertices(&geometry) > max_geometry_vertices as usize {
                return Err(SpatialError::GeometryTooLarge.into());
            }
            let admin_geo = geo_geometry(&geometry)?;
            if admin_geo.intersects(&input_geo) {
                matched.push(AdminGeometry { id, geometry });
            }
        }
        if after_primary_key.is_none() {
            break;
        }
    }
    Ok(matched)
}

fn require_geometry_entity_read_scope(
    config: &Config,
    principal: &Principal,
    dataset_id: &str,
    geometry_entity: &str,
) -> Result<(), Error> {
    let read_scope = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == dataset_id)
        .and_then(|dataset| {
            dataset
                .entities
                .iter()
                .find(|entity| entity.name == geometry_entity)
        })
        .map(|entity| entity.access.read_scope.as_str())
        .ok_or(OgcError::CollectionNotFound)?;
    require_scope(principal, read_scope)?;
    Ok(())
}

fn grouped_features(
    result: &crate::query::AggregateResult,
    dimension: &str,
    geometries: &[AdminGeometry],
    as_of: Option<&str>,
) -> Vec<Value> {
    let geometry_by_id = geometries
        .iter()
        .map(|item| (item.id.clone(), item.geometry.clone()))
        .collect::<HashMap<_, _>>();
    result
        .data
        .iter()
        .filter_map(|row| {
            let object = row.as_object()?;
            let id = object.get(dimension).and_then(value_to_id)?;
            let geometry = geometry_by_id.get(&id)?;
            Some(feature_json(
                Some(format!("{dimension}:{id}")),
                geometry.clone(),
                properties_with_disclosure(object, result, as_of),
            ))
        })
        .collect()
}

fn single_feature(
    result: &crate::query::AggregateResult,
    geometry: Geometry,
    as_of: Option<&str>,
) -> Vec<Value> {
    let mut properties = Map::new();
    if let Some(object) = result.data.first().and_then(Value::as_object) {
        properties = properties_with_disclosure(object, result, as_of);
    }
    vec![feature_json(None, geometry, properties)]
}

fn properties_with_disclosure(
    object: &serde_json::Map<String, Value>,
    result: &crate::query::AggregateResult,
    as_of: Option<&str>,
) -> serde_json::Map<String, Value> {
    let mut properties = object.clone();
    properties.insert(
        "_disclosure_method".to_string(),
        json!(result.disclosure_control.method.join("+")),
    );
    properties.insert(
        "_min_cell_size".to_string(),
        json!(result.disclosure_control.min_cell_size),
    );
    properties.insert(
        "_suppressed".to_string(),
        json!(result
            .indicators
            .iter()
            .any(|id| object.get(id).is_some_and(Value::is_null))),
    );
    if let Some(as_of) = as_of {
        properties.insert("_as_of".to_string(), json!(as_of));
    }
    properties
}

fn edr_query_filters(params: &AreaQuery) -> Result<Vec<AggregateFilter>, Error> {
    let mut filters = Vec::new();
    for (key, value) in &params.extra {
        let Some(field) = key.strip_prefix("filter.") else {
            continue;
        };
        if field.is_empty() || value.trim().is_empty() {
            return Err(FilterError::NotAllowed.into());
        }
        let values = value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| Value::String(value.to_string()))
            .collect::<Vec<_>>();
        if values.len() > 1 {
            filters.push(AggregateFilter {
                field: field.to_string(),
                op: AggregateFilterOp::In,
                value: Value::Array(values),
            });
        } else if let Some(value) = values.into_iter().next() {
            filters.push(AggregateFilter {
                field: field.to_string(),
                op: AggregateFilterOp::Eq,
                value,
            });
        }
    }
    Ok(filters)
}

fn apply_body_query_fields(params: &mut AreaQuery, body: &Value) {
    let properties = body
        .as_object()
        .and_then(|object| object.get("properties"))
        .and_then(Value::as_object);
    let Some(properties) = properties else {
        return;
    };
    if params.parameter_name.is_none() {
        if let Some(value) = properties.get("parameter-name").and_then(Value::as_str) {
            params.parameter_name = Some(value.to_string());
        } else if let Some(values) = properties.get("measures").and_then(Value::as_array) {
            let csv = values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            if !csv.is_empty() {
                params.parameter_name = Some(csv);
            }
        }
    }
    if params.group_by.is_none() {
        if let Some(value) = properties.get("group_by").and_then(Value::as_str) {
            params.group_by = Some(value.to_string());
        } else if let Some(value) = properties
            .get("group_by")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
        {
            params.group_by = Some(value.to_string());
        }
    }
    if let Some(filters) = properties.get("filters").and_then(Value::as_object) {
        for (field, value) in filters {
            let key = format!("filter.{field}");
            params
                .extra
                .entry(key)
                .or_insert_with(|| filter_value(value));
        }
    }
}

fn filter_value(value: &Value) -> String {
    match value {
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn feature_json(
    id: Option<String>,
    geometry: Geometry,
    properties: serde_json::Map<String, Value>,
) -> Value {
    let mut feature = json!({
        "type": "Feature",
        "geometry": geometry,
        "properties": properties,
    });
    if let Some(id) = id {
        feature["id"] = json!(id);
    }
    feature
}

fn geometry_from_wkt(value: &str) -> Result<Geometry, Error> {
    let wkt = wkt::Wkt::<f64>::from_str(value).map_err(|_| SpatialError::GeometryInvalid)?;
    let geometry: geo_types::Geometry<f64> =
        geo_types::Geometry::try_from(wkt).map_err(|_| SpatialError::GeometryInvalid)?;
    Ok(Geometry::from(&geometry))
}

fn geometry_from_geojson_value(value: &Value) -> Result<Geometry, Error> {
    match value {
        Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("Feature") => {
            object
                .get("geometry")
                .ok_or(SpatialError::GeometryInvalid)
                .and_then(|geometry| {
                    geometry_from_geojson_value(geometry).map_err(|_| SpatialError::GeometryInvalid)
                })
                .map_err(Error::from)
        }
        Value::Object(_) => serde_json::from_value::<Geometry>(value.clone())
            .map_err(|_| SpatialError::GeometryInvalid.into()),
        Value::String(value) => {
            let geojson = GeoJson::from_str(value).map_err(|_| SpatialError::GeometryInvalid)?;
            match geojson {
                GeoJson::Geometry(geometry) => Ok(geometry),
                GeoJson::Feature(feature) => {
                    feature.geometry.ok_or(SpatialError::GeometryInvalid.into())
                }
                GeoJson::FeatureCollection(_) => Err(SpatialError::GeometryInvalid.into()),
            }
        }
        _ => Err(SpatialError::GeometryInvalid.into()),
    }
}

fn geo_geometry(geometry: &Geometry) -> Result<geo_types::Geometry<f64>, Error> {
    geometry
        .clone()
        .try_into()
        .map_err(|_| SpatialError::GeometryInvalid.into())
}

fn count_vertices(geometry: &Geometry) -> usize {
    match &geometry.value {
        GeometryValue::Point { .. } => 1,
        GeometryValue::MultiPoint { coordinates } | GeometryValue::LineString { coordinates } => {
            coordinates.len()
        }
        GeometryValue::MultiLineString { coordinates } | GeometryValue::Polygon { coordinates } => {
            coordinates.iter().map(Vec::len).sum()
        }
        GeometryValue::MultiPolygon { coordinates } => coordinates
            .iter()
            .flat_map(|polygon| polygon.iter())
            .map(Vec::len)
            .sum(),
        GeometryValue::GeometryCollection { geometries } => {
            geometries.iter().map(count_vertices).sum()
        }
    }
}

fn value_to_id(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn resolve_as_of(
    readiness: Option<&watch::Receiver<ReadinessSnapshot>>,
    result: &crate::query::AggregateResult,
    geometry_source: Option<(&EntityRegistry, &str, &str)>,
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
    if let Some((registry, dataset_id, entity_name)) = geometry_source {
        let geometry_table = registry
            .dataset(dataset_id)?
            .entity(entity_name)?
            .table_id
            .clone();
        let dataset_key = id_from_str::<crate::config::DatasetId>(dataset_id)?;
        let resource_key = id_from_str::<crate::config::ResourceId>(&geometry_table)?;
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

#[allow(clippy::result_large_err)]
fn require_collection_source_governed_access(
    runtime: &RuntimeSnapshot,
    config: &Config,
    collection: &EdrCollection<'_>,
    headers: &HeaderMap,
    principal: Option<&Principal>,
) -> Result<GovernedReadDecision, GovernedAccessError> {
    let entity = collection_source_entity(config, collection).map_err(GovernedAccessError::from)?;
    require_governed_read_access(
        runtime,
        &collection.dataset_id,
        entity,
        headers,
        principal,
        GovernedRequestInfo {
            route_identity: "registry-relay.ogc.edr",
            requested_disclosure: "ogc_edr_area",
            checked_scope: collection_checked_scope(collection, entity),
            redaction_projection: GovernedRedactionProjection::DeferredOutput,
        },
    )
}

fn collection_checked_scope<'a>(
    collection: &'a EdrCollection<'_>,
    entity: &'a EntityConfig,
) -> &'a str {
    if aggregate_only_execution(collection.aggregate) {
        &collection.aggregate_scope
    } else {
        &entity.access.read_scope
    }
}

fn collection_source_entity<'a>(
    config: &'a Config,
    collection: &EdrCollection<'_>,
) -> Result<&'a EntityConfig, Error> {
    let source_entity = collection
        .aggregate
        .source_entity
        .as_deref()
        .ok_or(OgcError::CollectionNotFound)?;
    config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == collection.dataset_id)
        .and_then(|dataset| {
            dataset
                .entities
                .iter()
                .find(|entity| entity.name == source_entity)
        })
        .ok_or_else(|| OgcError::CollectionNotFound.into())
}

fn edr_access_error_response(
    error: GovernedAccessError,
    collection: &EdrCollection<'_>,
    geometry_vertex_count: u64,
) -> Response {
    let mut audit_context = Some(AuditContextExt {
        dataset_id: Some(collection.dataset_id.clone()),
        aggregate_id: Some(collection.aggregate_id.clone()),
        collection_id: Some(collection.collection_id.clone()),
        geometry_vertex_count: Some(geometry_vertex_count),
        ..AuditContextExt::default()
    });
    attach_pdp_audit(&mut audit_context, error.pdp_audit.as_ref());
    let mut response = error.error.into_response();
    if let Some(context) = audit_context {
        response.extensions_mut().insert(context);
    }
    response
}

fn require_collection_source_metadata_scope(
    principal: &Principal,
    collection: &EdrCollection<'_>,
) -> Result<(), Error> {
    if let Some(scope) = collection.source_entity_metadata_scope.as_deref() {
        require_scope(principal, scope)?;
    }
    Ok(())
}

fn require_collection_source_read_scope(
    principal: &Principal,
    collection: &EdrCollection<'_>,
) -> Result<(), Error> {
    if aggregate_only_execution(collection.aggregate) {
        return Ok(());
    }
    if let Some(scope) = collection.source_entity_read_scope.as_deref() {
        require_scope(principal, scope)?;
    }
    Ok(())
}

fn aggregate_only_execution(aggregate: &AggregateConfig) -> bool {
    aggregate
        .access
        .as_ref()
        .is_some_and(|access| access.aggregate_only_execution)
}

fn require_any_metadata_scope(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    for dataset in &config.datasets {
        let scope = format!("{}:metadata", dataset.id);
        if require_scope(&principal, &scope).is_ok() {
            return Ok(());
        }
    }
    Err(AuthError::ScopeDenied {
        required: "metadata scope on at least one dataset".to_string(),
    }
    .into())
}

fn link(href: &str, rel: &str, media_type: &str) -> Value {
    json!({ "href": href, "rel": rel, "type": media_type })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn count_vertices_counts_nested_geojson_geometries() {
        let geometry: Geometry = serde_json::from_value(json!({
            "type": "GeometryCollection",
            "geometries": [
                {"type": "Point", "coordinates": [100.0, 13.0]},
                {
                    "type": "LineString",
                    "coordinates": [[100.0, 13.0], [100.1, 13.1]]
                },
                {
                    "type": "Polygon",
                    "coordinates": [[
                        [100.0, 13.0],
                        [100.1, 13.0],
                        [100.1, 13.1],
                        [100.0, 13.0]
                    ]]
                }
            ]
        }))
        .expect("test geometry parses");

        assert_eq!(count_vertices(&geometry), 7);
    }
}
