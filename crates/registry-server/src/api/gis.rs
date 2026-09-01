// SPDX-License-Identifier: Apache-2.0

//! Bounded QGIS-facing OAPIF-shaped adapter.
//!
//! This module is only a transport adapter over compiled direct list operations.
//! It does not declare OGC API Features conformance, compute extents, add a
//! query engine, or reinterpret Registry access profiles.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, VARY};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde_json::{json, Map, Value};

use super::{
    audited_read_concealment, audited_read_refusal, authorize_route, concealed, data_field_type,
    exact_read_no_store, invalid_query, percent_decode, read_query, unavailable, AuthorizedSurface,
    HttpService, QueryOptions, QueryParseError, ReadQueryError, RecordReadKind, RecordReadRequest,
    VerifiedRequestClaims, MAX_RAW_QUERY_BYTES,
};
use crate::contract::{FieldTypeSource, Operation};
use crate::correlation::RequestCorrelation;
use crate::cursor::{CursorAdapter, CursorRepresentation};
use crate::model::{CompiledEntity, CompiledQueryKind, CompiledQueryOperation, CompiledRoute};
use crate::query as strict_query;

const GIS_ROOT: &str = "/v1/gis";
const SERVICE_DESC_MEDIA_TYPE: &str = "application/vnd.oai.openapi+json;version=3.0";
const MAX_GIS_LIMIT: u32 = 10_000;

/// Route inventory for the governed GIS adapter.
///
/// The parent API router mounts this literal six-route set under the same
/// authentication, correlation, security-header, and fallback layers as the
/// native Registry routes.
pub(crate) fn routes() -> Router<Arc<HttpService>> {
    Router::new()
        .route(GIS_ROOT, get(landing))
        .route(&format!("{GIS_ROOT}/api"), get(api))
        .route(&format!("{GIS_ROOT}/conformance"), get(conformance))
        .route(&format!("{GIS_ROOT}/collections"), get(collections))
        .route(
            &format!("{GIS_ROOT}/collections/{{collection}}"),
            get(collection),
        )
        .route(
            &format!("{GIS_ROOT}/collections/{{collection}}/items"),
            get(items),
        )
}

async fn landing(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if parse_metadata_query(raw_query.as_deref()).is_err() {
        return invalid_query();
    }
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(origin) = public_origin(&service) else {
        return unavailable();
    };
    let collections = visible_gis_collections(&service, &claims);
    let body = json!({
        "title": service.registry.registry_id(),
        "description": "Bounded Registry GIS adapter for authorized CRS84 Point bbox reads.",
        "links": [
            link(origin, "self", "application/json", GIS_ROOT),
            link(origin, "data", "application/json", &format!("{GIS_ROOT}/collections")),
            link(origin, "conformance", "application/json", &format!("{GIS_ROOT}/conformance")),
            link(origin, "service-desc", SERVICE_DESC_MEDIA_TYPE, &format!("{GIS_ROOT}/api")),
        ],
        "registry": {
            "profile": "registry-server-gis-bounded-crs84-point-bbox-v1",
            "collections": collections.len(),
        },
    });
    exact_json_no_store(body)
}

async fn conformance(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if parse_metadata_query(raw_query.as_deref()).is_err() {
        return invalid_query();
    }
    let _claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    if public_origin(&service).is_none() {
        return unavailable();
    }
    exact_json_no_store(json!({"conformsTo": []}))
}

async fn api(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if parse_metadata_query(raw_query.as_deref()).is_err() {
        return invalid_query();
    }
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(origin) = public_origin(&service) else {
        return unavailable();
    };
    let collections = visible_gis_collections(&service, &claims);
    let mut paths = Map::new();
    for collection in &collections {
        paths.insert(
            format!("{GIS_ROOT}/collections/{}/items", collection.id),
            json!({
                "get": {
                    "operationId": format!("gis.{}.items", collection.id),
                    "parameters": [
                        {
                            "name": "bbox",
                            "in": "query",
                            "required": false,
                            "schema": {
                                "type": "array",
                                "items": {"type": "number"},
                                "minItems": 4,
                                "maxItems": 4,
                            },
                            "style": "form",
                            "explode": false,
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": collection.max_page_size,
                            },
                        },
                        {
                            "name": "cursor",
                            "in": "query",
                            "required": false,
                            "schema": {"type": "string", "maxLength": strict_query::MAX_OPAQUE_VALUE_BYTES},
                        },
                        {
                            "name": "f",
                            "in": "query",
                            "required": false,
                            "schema": {"type": "string", "enum": ["json"]},
                        },
                    ],
                    "responses": {
                        "200": {
                            "description": "Authorized GeoJSON FeatureCollection page.",
                            "content": {
                                "application/geo+json": {
                                    "schema": {"$ref": "#/components/schemas/FeatureCollection"}
                                }
                            }
                        }
                    }
                }
            }),
        );
    }
    let body = json!({
        "openapi": "3.0.0",
        "info": {
            "title": format!("{} GIS adapter", service.registry.registry_id()),
            "version": service.registry.version(),
        },
        "servers": [{"url": origin}],
        "paths": paths,
        "components": {
            "schemas": {
                "FeatureCollection": {
                    "type": "object",
                    "required": ["type", "features"],
                    "properties": {
                        "type": {"type": "string", "enum": ["FeatureCollection"]},
                        "features": {"type": "array", "items": {"$ref": "#/components/schemas/Feature"}},
                        "numberReturned": {"type": "integer", "minimum": 0},
                        "links": {"type": "array", "items": {"type": "object"}},
                        "registry": {"type": "object"},
                    },
                    "additionalProperties": true,
                },
                "Feature": {
                    "type": "object",
                    "required": ["type", "id", "geometry", "properties"],
                    "properties": {
                        "type": {"type": "string", "enum": ["Feature"]},
                        "id": {"type": "string"},
                        "geometry": {
                            "type": "object",
                            "nullable": true,
                            "required": ["type", "coordinates"],
                            "properties": {
                                "type": {"type": "string", "enum": ["Point"]},
                                "coordinates": {
                                    "type": "array",
                                    "items": {"type": "number"},
                                    "minItems": 2,
                                    "maxItems": 2,
                                },
                            },
                        },
                        "properties": {"type": "object"},
                        "registry": {"type": "object"},
                    },
                    "additionalProperties": true,
                },
            },
        },
    });
    exact_json_media_no_store(body, SERVICE_DESC_MEDIA_TYPE)
}

async fn collections(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if parse_metadata_query(raw_query.as_deref()).is_err() {
        return invalid_query();
    }
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(origin) = public_origin(&service) else {
        return unavailable();
    };
    let collections = visible_gis_collections(&service, &claims)
        .into_iter()
        .map(|collection| collection.value(origin))
        .collect::<Vec<_>>();
    exact_json_no_store(json!({
        "links": [link(origin, "self", "application/json", &format!("{GIS_ROOT}/collections"))],
        "collections": collections,
    }))
}

async fn collection(
    State(service): State<Arc<HttpService>>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(collection): Path<String>,
) -> Response {
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(collection) = authorize_gis_collection(&service, &claims, &collection) else {
        return concealed();
    };
    if parse_metadata_query(raw_query.as_deref()).is_err() {
        return invalid_query();
    }
    let Some(origin) = public_origin(&service) else {
        return unavailable();
    };
    exact_json_no_store(collection.collection.value(origin))
}

async fn items(
    State(service): State<Arc<HttpService>>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    Path(collection): Path<String>,
) -> Response {
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(authorized) = authorize_gis_collection(&service, &claims, &collection) else {
        return concealed();
    };
    let query = match parse_items_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(QueryParseError::Invalid) => {
            return audited_read_refusal(
                &service,
                authorized.route,
                &authorized.surface,
                None,
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let options = match query_options(&authorized, query) {
        Ok(options) => options,
        Err(QueryParseError::Invalid) => {
            return audited_read_refusal(
                &service,
                authorized.route,
                &authorized.surface,
                None,
                invalid_query(),
                &correlation,
            )
            .await;
        }
    };
    let Some(origin) = public_origin(&service) else {
        return unavailable();
    };
    let next_link_prefix = absolute_href(
        origin,
        &format!(
            "{GIS_ROOT}/collections/{}/items?cursor=",
            authorized.collection.id
        ),
    );
    let read = match read_query(
        &service,
        authorized.route,
        &authorized.surface,
        &options,
        None,
        CursorRepresentation::GeoJson,
        CursorAdapter::Gis,
    )
    .await
    {
        Ok(Some(query)) => query,
        Ok(None) => return unavailable(),
        Err(ReadQueryError::Invalid) => {
            return audited_read_refusal(
                &service,
                authorized.route,
                &authorized.surface,
                None,
                invalid_query(),
                &correlation,
            )
            .await;
        }
        Err(ReadQueryError::CursorInvalid) => {
            return audited_read_refusal(
                &service,
                authorized.route,
                &authorized.surface,
                None,
                super::cursor_invalid(),
                &correlation,
            )
            .await;
        }
    };
    let readable_fields = read
        .cursor_binding
        .selected_fields
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !readable_fields.is_subset(&authorized.surface.readable_fields) {
        return audited_read_concealment(
            &service,
            authorized.route,
            &options,
            &claims,
            None,
            &correlation,
        )
        .await;
    }
    let maximum_records = usize::from(read.page_size) + 1;
    let request = RecordReadRequest {
        entity_id: authorized.route.entity_id.clone(),
        operation_id: authorized.route.id.clone(),
        method: authorized.route.method,
        context: authorized.surface.context,
        selected_fields: readable_fields,
        representation: CursorRepresentation::GeoJson,
        adapter: CursorAdapter::Gis,
        adapter_origin: Some(origin.to_owned()),
        geojson_next_link_prefix: Some(next_link_prefix),
        kind: RecordReadKind::List { plan: read },
        maximum_records,
        request_history_after_proposal_version: None,
        correlation,
    };
    match service.records.list(request).await {
        Ok(response) => exact_read_no_store(response),
        Err(super::ReadServiceError::Unavailable) => unavailable(),
        Err(super::ReadServiceError::CursorInvalid) => super::cursor_invalid(),
    }
}

struct AuthorizedGisCollection<'a> {
    collection: GisCollection,
    route: &'a CompiledRoute,
    surface: AuthorizedSurface<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GisCollection {
    id: String,
    title: String,
    entity_id: String,
    profile_id: String,
    geometry_field: String,
    max_page_size: u16,
    fields: Vec<GisField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GisField {
    name: String,
    field_type: FieldTypeSource,
}

impl GisCollection {
    fn value(&self, origin: &str) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "itemType": "feature",
            "links": [
                link(origin, "self", "application/json", &format!("{GIS_ROOT}/collections/{}", self.id)),
                link(origin, "items", "application/geo+json", &format!("{GIS_ROOT}/collections/{}/items", self.id)),
            ],
            "registry": {
                "entity": self.entity_id,
                "accessProfile": self.profile_id,
                "geometryField": self.geometry_field,
                "pageLimitMaximum": self.max_page_size,
                "profile": "bounded-crs84-point-bbox",
                "fields": self.fields.iter().map(|field| {
                    json!({
                        "name": field.name,
                        "type": field_type_name(&field.field_type),
                    })
                }).collect::<Vec<_>>(),
            },
        })
    }
}

fn visible_gis_collections(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
) -> Vec<GisCollection> {
    service
        .registry
        .queries()
        .operations
        .iter()
        .filter_map(|operation| {
            let id = operation.gis_collection_id()?;
            authorize_gis_collection(service, claims, &id).map(|authorized| authorized.collection)
        })
        .collect()
}

fn authorize_gis_collection<'a>(
    service: &'a HttpService,
    claims: &VerifiedRequestClaims,
    collection_id: &str,
) -> Option<AuthorizedGisCollection<'a>> {
    let operation = service
        .registry
        .queries()
        .operations
        .iter()
        .find(|operation| operation.gis_collection_id().as_deref() == Some(collection_id))?;
    if operation.kind != CompiledQueryKind::List || operation.read_path.is_some() {
        return None;
    }
    let bbox = operation.spatial.as_ref()?.bbox.as_ref()?;
    let route = service.registry.routes().routes.iter().find(|route| {
        route.id == operation.route_id
            && route.operation == Operation::List
            && route.query_kind == Some(CompiledQueryKind::List)
    })?;
    let options = profile_query_options(&operation.profile_id);
    let surface = authorize_route(service, route, claims, &options)?;
    if surface.read_path.is_some()
        || surface.response_entity.id != operation.entity_id
        || !surface.readable_fields.contains(&bbox.geometry_field)
        || !geojson_geometry_available(surface.response_entity, &surface.readable_fields)
    {
        return None;
    }
    let collection = gis_collection_value(operation, surface.response_entity, &surface)?;
    Some(AuthorizedGisCollection {
        collection,
        route,
        surface,
    })
}

fn gis_collection_value(
    operation: &CompiledQueryOperation,
    entity: &CompiledEntity,
    surface: &AuthorizedSurface<'_>,
) -> Option<GisCollection> {
    let collection_id = operation.gis_collection_id()?;
    let bbox = operation.spatial.as_ref()?.bbox.as_ref()?;
    let mut fields = Vec::new();
    for field_id in &operation.projection_fields {
        if field_id == &bbox.geometry_field || !surface.readable_fields.contains(field_id) {
            continue;
        }
        let field_type = data_field_type(entity, field_id)?;
        fields.push(GisField {
            name: api_name_for_field(entity, field_id)?.to_owned(),
            field_type: field_type.clone(),
        });
    }
    Some(GisCollection {
        id: collection_id,
        title: format!("{}.{}", operation.entity_id, operation.profile_id),
        entity_id: operation.entity_id.clone(),
        profile_id: operation.profile_id.clone(),
        geometry_field: bbox.geometry_field.clone(),
        max_page_size: operation.max_page_size,
        fields,
    })
}

fn geojson_geometry_available(entity: &CompiledEntity, readable_fields: &BTreeSet<String>) -> bool {
    let Some(geojson) = entity.geojson.as_ref() else {
        return false;
    };
    readable_fields.contains(&geojson.geometry_field)
        && matches!(
            entity
                .fields
                .get(&geojson.geometry_field)
                .map(|field| &field.field_type),
            Some(FieldTypeSource::Crs84Point { .. })
        )
}

fn api_name_for_field<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<&'a str> {
    entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .find(|field| field.id == field_id)
        .map(|field| field.api_name.as_str())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct GisItemsQuery {
    bbox: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

fn parse_metadata_query(raw: Option<&str>) -> Result<(), QueryParseError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let pairs = decode_query_pairs(raw)?;
    let mut seen = BTreeSet::new();
    for (name, value) in pairs {
        if !seen.insert(name.clone()) {
            return Err(QueryParseError::Invalid);
        }
        match name.as_str() {
            "f" if value == "json" => {}
            _ => return Err(QueryParseError::Invalid),
        }
    }
    Ok(())
}

fn parse_items_query(raw: Option<&str>) -> Result<GisItemsQuery, QueryParseError> {
    let Some(raw) = raw else {
        return Ok(GisItemsQuery::default());
    };
    if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let pairs = decode_query_pairs(raw)?;
    let mut seen = BTreeSet::new();
    let mut query = GisItemsQuery::default();
    for (name, value) in pairs {
        if !seen.insert(name.clone()) {
            return Err(QueryParseError::Invalid);
        }
        match name.as_str() {
            "f" if value == "json" => {}
            "bbox" => {
                strict_query::parse_read_query([("bbox", value.as_str())])
                    .map_err(|_| QueryParseError::Invalid)?;
                query.bbox = Some(value);
            }
            "limit" => {
                query.limit = Some(parse_limit(&value)?);
            }
            "cursor" => {
                if value.is_empty()
                    || value.len() > strict_query::MAX_OPAQUE_VALUE_BYTES
                    || value.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(QueryParseError::Invalid);
                }
                query.cursor = Some(value);
            }
            "crs" | "filter" | "datetime" | "properties" | "sortby" | "offset" => {
                return Err(QueryParseError::Invalid);
            }
            _ => return Err(QueryParseError::Invalid),
        }
    }
    if query.cursor.is_some() && (query.bbox.is_some() || query.limit.is_some()) {
        return Err(QueryParseError::Invalid);
    }
    Ok(query)
}

fn parse_limit(value: &str) -> Result<u32, QueryParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QueryParseError::Invalid);
    }
    let parsed = value.parse::<u32>().map_err(|_| QueryParseError::Invalid)?;
    if parsed == 0 || parsed > MAX_GIS_LIMIT {
        return Err(QueryParseError::Invalid);
    }
    Ok(parsed)
}

fn decode_query_pairs(raw: &str) -> Result<Vec<(String, String)>, QueryParseError> {
    raw.split('&')
        .map(|pair| {
            let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
            Ok((percent_decode(name)?, percent_decode(value)?))
        })
        .collect()
}

fn query_options(
    authorized: &AuthorizedGisCollection<'_>,
    query: GisItemsQuery,
) -> Result<QueryOptions, QueryParseError> {
    let mut pairs = Vec::new();
    pairs.push((
        "accessProfile".to_owned(),
        authorized.collection.profile_id.clone(),
    ));
    if let Some(cursor) = query.cursor {
        pairs.push(("$skiptoken".to_owned(), cursor));
    } else {
        let page_size = query
            .limit
            .map(|limit| limit.min(u32::from(authorized.collection.max_page_size)))
            .unwrap_or(u32::from(authorized.collection.max_page_size));
        pairs.push(("$top".to_owned(), page_size.to_string()));
        if let Some(bbox) = query.bbox {
            pairs.push(("bbox".to_owned(), bbox));
        }
    }
    let parsed = strict_query::parse_read_query(pairs).map_err(|_| QueryParseError::Invalid)?;
    Ok(QueryOptions {
        parsed,
        request_history_after_proposal_version: None,
        historical: None,
    })
}

fn profile_query_options(profile_id: &str) -> QueryOptions {
    QueryOptions {
        parsed: strict_query::ParsedReadQuery {
            access_profile: Some(profile_id.to_owned()),
            as_of: None,
            mode: strict_query::ParsedReadQueryMode::Query(
                strict_query::ReadQueryOptions::default(),
            ),
        },
        request_history_after_proposal_version: None,
        historical: None,
    }
}

fn exact_json_no_store(body: Value) -> Response {
    exact_json_media_no_store(body, "application/json")
}

fn exact_json_media_no_store(body: Value, content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, content_type),
            (CACHE_CONTROL, "no-store"),
            (VARY, "authorization, accept"),
        ],
        Json(body),
    )
        .into_response()
}

fn public_origin(service: &HttpService) -> Option<&str> {
    service.public_origin.as_ref().map(|origin| origin.as_str())
}

fn absolute_href(origin: &str, path: &str) -> String {
    debug_assert!(path.starts_with('/'));
    format!("{origin}{path}")
}

fn link(origin: &str, rel: &str, media_type: &str, path: &str) -> Value {
    json!({
        "rel": rel,
        "type": media_type,
        "href": absolute_href(origin, path),
    })
}

fn field_type_name(field_type: &FieldTypeSource) -> &'static str {
    match field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::String { .. } => "string",
        FieldTypeSource::Text { .. } => "string",
        FieldTypeSource::Int64 => "integer",
        FieldTypeSource::Decimal { .. } => "number",
        FieldTypeSource::Date => "date",
        FieldTypeSource::Timestamp => "dateTime",
        FieldTypeSource::Uuid => "string",
        FieldTypeSource::VocabularyCode { .. } => "string",
        FieldTypeSource::Reference { .. } => "string",
        FieldTypeSource::Crs84Point { .. } => "geometry",
        FieldTypeSource::Structured { .. } => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_yaml;

    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use crate::api::{
        HeldReadResponse, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe, RecordReadService,
        ServiceFuture,
    };
    use crate::cursor::CursorCodec;
    use crate::runtime_config::PublicOrigin;

    #[test]
    fn gis_items_query_accepts_qgis_limit_and_rejects_cursor_rewrites() {
        let query = parse_items_query(Some("bbox=100,13,101,14&limit=1000&f=json"))
            .expect("QGIS first page query is accepted");
        assert_eq!(query.bbox.as_deref(), Some("100,13,101,14"));
        assert_eq!(query.limit, Some(1000));
        assert_eq!(query.cursor, None);

        assert_eq!(
            parse_items_query(Some("cursor=opaque&bbox=100,13,101,14")),
            Err(QueryParseError::Invalid)
        );
        assert_eq!(
            parse_items_query(Some("cursor=opaque&limit=2")),
            Err(QueryParseError::Invalid)
        );
        assert_eq!(
            parse_items_query(Some("bbox=100,13,99,14")),
            Err(QueryParseError::Invalid)
        );
        assert_eq!(
            parse_items_query(Some("crs=http%3A%2F%2Fexample.test%2Fcrs")),
            Err(QueryParseError::Invalid)
        );
    }

    #[test]
    fn metadata_queries_only_accept_honest_json_format() {
        assert_eq!(parse_metadata_query(None), Ok(()));
        assert_eq!(parse_metadata_query(Some("f=json")), Ok(()));
        assert_eq!(
            parse_metadata_query(Some("f=html")),
            Err(QueryParseError::Invalid)
        );
        assert_eq!(
            parse_metadata_query(Some("bbox=100,13,101,14")),
            Err(QueryParseError::Invalid)
        );
    }

    #[test]
    fn collection_links_use_public_origin() {
        let collection = GisCollection {
            id: "service-site.map-reader".to_owned(),
            title: "service-site.map-reader".to_owned(),
            entity_id: "service-site".to_owned(),
            profile_id: "map-reader".to_owned(),
            geometry_field: "location".to_owned(),
            max_page_size: 100,
            fields: vec![],
        };
        let value = collection.value("https://registry.example.test");
        let links = value["links"].as_array().expect("collection links");
        assert!(links.iter().all(|link| link["href"]
            .as_str()
            .is_some_and(|href| href.starts_with("https://registry.example.test/v1/gis"))));
    }

    #[tokio::test]
    async fn gis_discovery_uses_public_origin_not_request_headers() {
        let app = test_app(Some("https://registry.example.test"));
        let response = request_with_malicious_origin_headers(
            app,
            "/v1/gis/collections",
            Some(map_reader_claims()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body_string(response).await;
        assert!(body.contains("https://registry.example.test/v1/gis/collections"));
        assert!(body.contains(
            "https://registry.example.test/v1/gis/collections/service-site.map-reader/items"
        ));
        assert!(!body.contains("evil.example"));
        assert!(!body.contains("\"href\":\"/v1/gis"));
    }

    #[tokio::test]
    async fn gis_service_description_uses_openapi_3_nullable_point_schema() {
        let response = request_with_malicious_origin_headers(
            test_app(Some("https://registry.example.test")),
            "/v1/gis/api",
            Some(map_reader_claims()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&response_body_string(response).await).unwrap();
        assert_eq!(body["openapi"], "3.0.0");
        let geometry = &body["components"]["schemas"]["Feature"]["properties"]["geometry"];
        assert_eq!(geometry["type"], "object");
        assert_eq!(geometry["nullable"], true);
        assert!(geometry.get("oneOf").is_none());
        assert!(!body.to_string().contains("\"type\":\"null\""));
    }

    #[tokio::test]
    async fn gis_metadata_without_public_origin_refuses_without_relative_fallback() {
        let records = Arc::new(RecordingReadService::default());
        let app = test_app_with_records(None, Arc::clone(&records) as Arc<dyn RecordReadService>);
        let response =
            request_with_malicious_origin_headers(app, "/v1/gis", Some(map_reader_claims())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body_string(response).await;
        assert!(body.contains("runtime.unavailable") || body.contains("unavailable"));
        assert!(!body.contains("/v1/gis/collections"));
        assert!(!body.contains("evil.example"));
        assert_eq!(
            records
                .list_requests
                .lock()
                .expect("recorded requests")
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn gis_items_without_public_origin_does_not_enter_record_runtime() {
        let records = Arc::new(RecordingReadService::default());
        let app = test_app_with_records(None, Arc::clone(&records) as Arc<dyn RecordReadService>);
        let response = request_with_malicious_origin_headers(
            app,
            "/v1/gis/collections/service-site.map-reader/items?bbox=100,13,101,14&limit=1000&f=json",
            Some(map_reader_claims()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body_string(response).await;
        assert!(!body.contains("/v1/gis/collections/service-site.map-reader/items"));
        assert!(!body.contains("evil.example"));
        assert_eq!(
            records
                .list_requests
                .lock()
                .expect("recorded requests")
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn gis_items_passes_absolute_trusted_next_link_prefix_to_record_runtime() {
        let records = Arc::new(RecordingReadService::default());
        let app = test_app_with_records(
            Some("https://registry.example.test"),
            Arc::clone(&records) as Arc<dyn RecordReadService>,
        );
        let response = request_with_malicious_origin_headers(
            app,
            "/v1/gis/collections/service-site.map-reader/items?bbox=100,13,101,14&limit=1000&f=json",
            Some(map_reader_claims()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let requests = records.list_requests.lock().expect("recorded requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].geojson_next_link_prefix.as_deref(),
            Some("https://registry.example.test/v1/gis/collections/service-site.map-reader/items?cursor=")
        );
    }

    #[test]
    fn compiled_gis_collection_id_omits_get_only_and_no_bbox_profiles() {
        let registry = compile_fixture();
        let ids = registry
            .queries()
            .operations
            .iter()
            .filter_map(CompiledQueryOperation::gis_collection_id)
            .collect::<BTreeSet<_>>();
        assert!(ids.contains("service-site.map-reader"));
        assert!(!ids.contains("service-site.get-only"));
        assert!(!ids.contains("service-site.no-bbox"));
    }

    #[test]
    fn qgis_limit_is_clamped_to_compiled_page_maximum() {
        let registry = compile_fixture();
        let operation = registry
            .queries()
            .operations
            .iter()
            .find(|operation| {
                operation.gis_collection_id().as_deref() == Some("service-site.map-reader")
            })
            .expect("GIS operation exists");
        let authorized = AuthorizedGisCollection {
            collection: GisCollection {
                id: "service-site.map-reader".to_owned(),
                title: "service-site.map-reader".to_owned(),
                entity_id: "service-site".to_owned(),
                profile_id: "map-reader".to_owned(),
                geometry_field: "location".to_owned(),
                max_page_size: operation.max_page_size,
                fields: vec![],
            },
            route: registry
                .routes()
                .routes
                .iter()
                .find(|route| route.id == operation.route_id)
                .expect("route exists"),
            surface: test_surface(&registry, operation),
        };
        let options = query_options(
            &authorized,
            GisItemsQuery {
                bbox: None,
                limit: Some(1000),
                cursor: None,
            },
        )
        .expect("limit is parsed");
        let strict_query::ParsedReadQueryMode::Query(query) = options.parsed.mode else {
            panic!("first page query expected");
        };
        assert_eq!(query.top, Some(u32::from(operation.max_page_size)));
    }

    #[derive(Default)]
    struct RecordingReadService {
        list_requests: Mutex<Vec<RecordReadRequest>>,
    }

    impl RecordReadService for RecordingReadService {
        fn get(
            &self,
            _request: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
            Box::pin(async { Ok(None) })
        }

        fn list(
            &self,
            request: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
            self.list_requests
                .lock()
                .expect("recorded requests")
                .push(request);
            Box::pin(async {
                HeldReadResponse::from_geojson(&json!({
                    "type": "FeatureCollection",
                    "features": [],
                    "numberReturned": 0,
                    "links": [],
                }))
            })
        }

        fn lookup(
            &self,
            _request: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
            Box::pin(async { Ok(None) })
        }
    }

    struct Ready;

    impl ReadinessProbe for Ready {
        fn is_ready(&self) -> ServiceFuture<'_, bool> {
            Box::pin(async { true })
        }
    }

    fn test_app(origin: Option<&str>) -> Router {
        test_app_with_records(origin, Arc::new(RecordingReadService::default()))
    }

    fn test_app_with_records(origin: Option<&str>, records: Arc<dyn RecordReadService>) -> Router {
        let registry = Arc::new(compile_fixture());
        let identity = ReadRuntimeIdentity {
            package_revision: "test-package".to_owned(),
            schema_fingerprint: "test-schema".to_owned(),
        };
        let cursors = Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(60))
                .expect("cursor codec"),
        );
        let readiness = Arc::new(Ready) as Arc<dyn ReadinessProbe>;
        let mut service = HttpService::new(registry, identity, records, readiness, cursors);
        if let Some(origin) = origin {
            service =
                service.with_public_origin(PublicOrigin::parse(origin).expect("public origin"));
        }
        super::super::route_set(Arc::new(service))
    }

    fn map_reader_claims() -> VerifiedRequestClaims {
        VerifiedRequestClaims::authenticated(
            "principal",
            "qgis-client",
            BTreeSet::from(["registry:sites:read".to_owned()]),
            None,
            BTreeMap::new(),
        )
        .expect("claims")
    }

    async fn request_with_malicious_origin_headers(
        app: Router,
        uri: &str,
        claims: Option<VerifiedRequestClaims>,
    ) -> Response {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, "evil.example")
            .header("forwarded", "for=192.0.2.10;host=evil.example;proto=https")
            .header("x-forwarded-host", "evil.example")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(RequestCorrelation::server_created());
        if let Some(claims) = claims {
            request.extensions_mut().insert(claims);
        }
        app.oneshot(request).await.expect("response")
    }

    async fn response_body_string(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    fn test_surface<'a>(
        registry: &'a crate::model::CompiledRegistry,
        operation: &CompiledQueryOperation,
    ) -> AuthorizedSurface<'a> {
        let entity = registry
            .entities()
            .get(&operation.entity_id)
            .expect("entity exists");
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == operation.route_id)
            .expect("route exists");
        AuthorizedSurface {
            route,
            entity,
            response_entity: entity,
            context: super::super::AuthorizedRequestContext::new(
                Some("principal".to_owned()),
                None,
                operation.profile_id.clone(),
                vec![],
            ),
            readable_fields: entity.access_profiles[&operation.profile_id]
                .readable_fields
                .clone(),
            read_path: None,
        }
    }

    fn compile_fixture() -> crate::model::CompiledRegistry {
        let source = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry: {id: gis-test, version: "1", defaultLanguage: en}
entities:
  - id: service-site
    route: service-sites
    mutationMode: create_only
    geojson: {geometryField: location}
    fields:
      - {id: code, type: string, maxLength: 32, classification: public, required: true}
      - {id: label, type: string, maxLength: 80, classification: public}
      - {id: location, type: crs84-point, precision: 6, classification: public}
accessProfiles:
  - id: map-reader
    default: true
    principalClaim: principal
    requiredScopes: [registry:sites:read]
    grants:
      - entity: service-site
        operations: [get, list]
        readableFields: [code, label, location]
        spatialQueries:
          bbox:
            maximumLongitudeSpanDegrees: 2
            maximumLatitudeSpanDegrees: 2
  - id: get-only
    principalClaim: principal
    grants:
      - entity: service-site
        operations: [get]
        readableFields: [code, label, location]
  - id: no-bbox
    principalClaim: principal
    grants:
      - entity: service-site
        operations: [get, list]
        readableFields: [code, label, location]
"#;
        let project = parse_project_yaml(source.as_bytes()).expect("fixture parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .unwrap_or_else(|failure| panic!("fixture compiles: {:?}", failure.diagnostics()))
    }
}
