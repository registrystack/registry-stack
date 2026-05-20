// SPDX-License-Identifier: Apache-2.0
//! Read-only OGC API Records routes for catalog metadata discovery.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use registry_metadata_core as metadata_core;
use registry_metadata_core::{CompiledDataset, CompiledMetadata};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::CursorSigner;
use crate::auth::Principal;
use crate::config::Config;
use crate::entity::EntityRegistry;
use crate::error::{
    AuthError, Error, FilterError, InternalError, OgcError, QueryError, SpatialError,
};
use crate::metadata::catalog::normalized_base_url;
use crate::metadata::scoped_compiled_from_runtime;

const RECORDS_BASE: &str = "/ogc/v1/records";
const DATASETS_COLLECTION_ID: &str = "datasets";
const GEOJSON: HeaderValue = HeaderValue::from_static("application/geo+json");
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;
const CURSOR_MAC_LEN: usize = 16;
pub(crate) const CONFORMANCE_RECORD_CORE: &str =
    "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core";
pub(crate) const CONFORMANCE_RECORD_COLLECTION: &str =
    "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-collection";
pub(crate) const CONFORMANCE_RECORD_API: &str =
    "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-api";
pub(crate) const CONFORMANCE_JSON: &str =
    "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/json";
pub(crate) const CONFORMANCE_OAS30: &str =
    "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/oas30";

/// Sub-router for the OGC API Records V1 surface.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(RECORDS_BASE, get(landing))
        .route(&format!("{RECORDS_BASE}/conformance"), get(conformance))
        .route(&format!("{RECORDS_BASE}/collections"), get(collections))
        .route(
            &format!("{RECORDS_BASE}/collections/{{collection_id}}"),
            get(collection_detail),
        )
        .route(
            &format!("{RECORDS_BASE}/collections/{{collection_id}}/items"),
            get(collection_items),
        )
        .route(
            &format!("{RECORDS_BASE}/collections/{{collection_id}}/items/{{record_id}}"),
            get(record_item),
        )
}

#[derive(Debug, Deserialize)]
struct CollectionPath {
    collection_id: String,
}

#[derive(Debug, Deserialize)]
struct RecordPath {
    collection_id: String,
    record_id: String,
}

async fn landing(
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if let Err(error) = require_metadata_access(&config, principal) {
        return error.into_response();
    }
    let base_url = normalized_base_url(&config.catalog.base_url);

    Json(json!({
        "title": "Registry Relay OGC API Records",
        "description": "Catalog records exposed from Registry Relay dataset metadata.",
        "links": [
            link_abs(&base_url, RECORDS_BASE, "self", "application/json", Some("Landing page")),
            link_abs(&base_url, &format!("{RECORDS_BASE}/conformance"), "conformance", "application/json", Some("Conformance")),
            link_abs(&base_url, &format!("{RECORDS_BASE}/collections"), "data", "application/json", Some("Record collections")),
            link_abs(&base_url, "/openapi.json", "service-desc", "application/vnd.oai.openapi+json;version=3.0", Some("OpenAPI definition")),
        ],
    }))
    .into_response()
}

async fn conformance(
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if let Err(error) = require_metadata_access(&config, principal) {
        return error.into_response();
    }

    Json(json!({
        "conformsTo": conformance_uris(),
    }))
    .into_response()
}

async fn collections(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, _registry)) = records_state(config, registry) else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if let Err(error) = require_metadata_access(&config, principal) {
        return error.into_response();
    }
    let base_url = normalized_base_url(&config.catalog.base_url);

    Json(json!({
        "links": [link_abs(&base_url, &format!("{RECORDS_BASE}/collections"), "self", "application/json", None)],
        "collections": [records_collection_json(&base_url)],
    }))
    .into_response()
}

async fn collection_detail(
    Path(path): Path<CollectionPath>,
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    if path.collection_id != DATASETS_COLLECTION_ID {
        return Error::from(OgcError::CollectionNotFound).into_response();
    }
    if let Err(error) = require_metadata_access(&config, principal) {
        return error.into_response();
    }

    Json(records_collection_json(&normalized_base_url(
        &config.catalog.base_url,
    )))
    .into_response()
}

async fn collection_items(
    Path(path): Path<CollectionPath>,
    Query(params): Query<HashMap<String, String>>,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
    signer: Option<Extension<Arc<CursorSigner>>>,
) -> Response {
    if path.collection_id != DATASETS_COLLECTION_ID {
        return Error::from(OgcError::CollectionNotFound).into_response();
    }
    let Some((config, registry)) = records_state(config, registry) else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let Some(Extension(signer)) = signer else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let principal_ref = principal.as_ref().map(|Extension(principal)| principal);
    let compiled =
        match scoped_records_metadata(&config, &registry, compiled_metadata, principal.clone()) {
            Ok(compiled) => compiled,
            Err(error) => return error.into_response(),
        };
    let parsed = match parse_records_query(params) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let base_url = normalized_base_url(&config.catalog.base_url);
    let cursor_context = cursor_context(&path.collection_id, principal_ref, &parsed);
    let after = match parsed.after.as_deref() {
        Some(after) => match decode_records_cursor(&signer, after) {
            Ok(cursor) if cursor.version == 1 && cursor.context == cursor_context => {
                Some(cursor.position)
            }
            _ => return Error::from(QueryError::CursorInvalid).into_response(),
        },
        None => None,
    };
    let mut datasets = compiled
        .datasets()
        .filter(|dataset| {
            parsed
                .q
                .as_ref()
                .is_none_or(|q| dataset_matches_q(dataset, q))
        })
        .collect::<Vec<_>>();
    datasets.sort_by(|left, right| left.dataset_id.cmp(&right.dataset_id));
    let number_matched = datasets.len();
    if let Some(after) = after.as_deref() {
        datasets.retain(|dataset| dataset.dataset_id.as_str() > after);
    }
    let next =
        (datasets.len() > parsed.limit).then(|| datasets[parsed.limit - 1].dataset_id.clone());
    datasets.truncate(parsed.limit);
    let features = datasets
        .iter()
        .map(|dataset| record_feature_json(&compiled, &base_url, dataset))
        .collect::<Vec<_>>();
    let next = match next {
        Some(position) => {
            let cursor = RecordsCursor {
                version: 1,
                context: cursor_context,
                position,
            };
            match encode_records_cursor(&signer, &cursor) {
                Ok(encoded) => Some(encoded),
                Err(error) => return error.into_response(),
            }
        }
        None => None,
    };
    let mut links = vec![
        link_abs(
            &base_url,
            &items_path(&parsed.link_params, None),
            "self",
            "application/geo+json",
            None,
        ),
        link_abs(
            &base_url,
            &format!("{RECORDS_BASE}/collections/{DATASETS_COLLECTION_ID}"),
            "collection",
            "application/json",
            None,
        ),
    ];
    if let Some(next) = next.as_deref() {
        links.push(link_abs(
            &base_url,
            &items_path(&parsed.link_params, Some(next)),
            "next",
            "application/geo+json",
            None,
        ));
    }

    let mut response = Json(json!({
        "type": "FeatureCollection",
        "numberMatched": number_matched,
        "numberReturned": features.len(),
        "links": links,
        "features": features,
    }))
    .into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, GEOJSON);
    response
}

async fn record_item(
    Path(path): Path<RecordPath>,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    compiled_metadata: Option<Extension<Arc<CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if path.collection_id != DATASETS_COLLECTION_ID {
        return Error::from(OgcError::CollectionNotFound).into_response();
    }
    let Some((config, registry)) = records_state(config, registry) else {
        return Error::from(crate::error::InternalError::Unhandled).into_response();
    };
    let compiled = match scoped_records_metadata(&config, &registry, compiled_metadata, principal) {
        Ok(compiled) => compiled,
        Err(error) => return error.into_response(),
    };
    let Some(dataset) = compiled
        .datasets()
        .find(|dataset| dataset.dataset_id == path.record_id)
    else {
        return Error::from(OgcError::RecordNotFound).into_response();
    };
    let base_url = normalized_base_url(&config.catalog.base_url);

    let mut response = Json(record_feature_json(&compiled, &base_url, dataset)).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, GEOJSON);
    response
}

fn records_state(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn visible_metadata_entity_ids(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<BTreeSet<(String, String)>, Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    let entity_ids = config
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset
                .entities
                .iter()
                .filter(|entity| principal.scopes.contains(&entity.access.metadata_scope))
                .map(|entity| (dataset.id.to_string(), entity.name.clone()))
        })
        .collect::<BTreeSet<_>>();
    if entity_ids.is_empty() {
        Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity".to_string(),
        }
        .into())
    } else {
        Ok(entity_ids)
    }
}

fn require_metadata_access(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<(), Error> {
    visible_metadata_entity_ids(config, principal).map(|_| ())
}

fn scoped_records_metadata(
    config: &Config,
    registry: &EntityRegistry,
    compiled_metadata: Option<Extension<Arc<CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Result<CompiledMetadata, Error> {
    let visible_entity_ids = visible_metadata_entity_ids(config, principal)?;
    if let Some(Extension(compiled)) = compiled_metadata {
        return Ok(compiled.filter(|dataset, entity| {
            visible_entity_ids.contains(&(dataset.dataset_id.clone(), entity.name.clone()))
        }));
    }
    scoped_compiled_from_runtime(config, registry, &visible_entity_ids)
        .map_err(|_| Error::from(InternalError::Unhandled))
}

fn records_collection_json(base_url: &str) -> Value {
    let collection_path = format!("{RECORDS_BASE}/collections/{DATASETS_COLLECTION_ID}");
    json!({
        "id": DATASETS_COLLECTION_ID,
        "title": "Dataset catalog records",
        "description": "Records describing Registry Relay datasets visible to the caller.",
        "itemType": "record",
        "extent": {
            "temporal": {
                "interval": [[Value::Null, Value::Null]],
            },
        },
        "supportedQueryParameters": ["limit", "after", "q"],
        "links": [
            link_abs(base_url, &collection_path, "self", "application/json", None),
            link_abs(base_url, &format!("{collection_path}/items"), "items", "application/geo+json", None),
            link_json(&format!("{base_url}/metadata/dcat/bregdcat-ap"), "alternate", "application/ld+json", Some("BRegDCAT-AP JSON-LD metadata catalog")),
        ],
    })
}

fn record_feature_json(
    compiled: &CompiledMetadata,
    base_url: &str,
    dataset: &CompiledDataset,
) -> Value {
    let item_path = format!(
        "{RECORDS_BASE}/collections/{DATASETS_COLLECTION_ID}/items/{}",
        dataset.dataset_id
    );
    let mut feature = metadata_core::render_ogc_records_item(compiled, &dataset.dataset_id)
        .expect("dataset came from compiled metadata");
    if let Some(properties) = feature.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert("entityCount".to_string(), json!(dataset.entities.len()));
        if let Some(entities) = properties.get_mut("entities").and_then(Value::as_array_mut) {
            for entity in entities {
                inject_entity_links(base_url, &dataset.dataset_id, entity);
            }
        }
    }
    feature["links"] = json!([
        link_abs(base_url, &item_path, "self", "application/geo+json", None),
        link_abs(
            base_url,
            &format!("{RECORDS_BASE}/collections/{DATASETS_COLLECTION_ID}"),
            "collection",
            "application/json",
            None,
        ),
        link_abs(
            base_url,
            &format!("/datasets/{}", dataset.dataset_id),
            "describes",
            "application/json",
            Some("Registry Relay dataset metadata"),
        ),
        link_json(
            &format!("{base_url}/metadata/dcat/bregdcat-ap"),
            "alternate",
            "application/ld+json",
            Some("BRegDCAT-AP JSON-LD metadata catalog")
        ),
    ]);
    feature
}

#[derive(Debug)]
struct ParsedRecordsQuery {
    limit: usize,
    after: Option<String>,
    q: Option<String>,
    link_params: BTreeMap<String, String>,
    cursor_params: BTreeMap<String, String>,
}

fn parse_records_query(params: HashMap<String, String>) -> Result<ParsedRecordsQuery, Error> {
    let mut limit = DEFAULT_LIMIT;
    let mut after = None;
    let mut q = None;
    let mut link_params = BTreeMap::new();
    let mut cursor_params = BTreeMap::new();

    for (name, value) in params {
        match name.as_str() {
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .map_err(|_| Error::from(FilterError::InvalidValue))?;
                if limit == 0 || limit > MAX_LIMIT {
                    return Err(FilterError::LimitOutOfRange.into());
                }
                link_params.insert(name.clone(), value.clone());
                cursor_params.insert(name, value);
            }
            "after" => {
                after = Some(value);
            }
            "q" => {
                let normalized = value.trim().to_lowercase();
                if !normalized.is_empty() {
                    q = Some(normalized);
                    link_params.insert(name.clone(), value.clone());
                    cursor_params.insert(name, value);
                }
            }
            "bbox" | "bbox-crs" | "datetime" | "offset" | "filter" | "filter-lang" => {
                return Err(SpatialError::FilterUnsupported { parameter: name }.into());
            }
            _ => return Err(FilterError::UnknownField.into()),
        }
    }

    Ok(ParsedRecordsQuery {
        limit,
        after,
        q,
        link_params,
        cursor_params,
    })
}

fn dataset_matches_q(dataset: &CompiledDataset, query: &str) -> bool {
    let haystacks = record_search_text(dataset);
    query
        .split_whitespace()
        .all(|term| haystacks.iter().any(|text| text.contains(term)))
}

fn record_search_text(dataset: &CompiledDataset) -> Vec<String> {
    let mut values = vec![
        dataset.dataset_id.clone(),
        dataset.title.clone(),
        dataset.description.clone(),
        dataset.owner.clone(),
        format!("{:?}", dataset.sensitivity),
        format!("{:?}", dataset.access_rights),
        format!("{:?}", dataset.update_frequency),
    ];
    values.extend(dataset.conforms_to.iter().cloned());
    values.extend(dataset.spatial_coverage.iter().cloned());
    for entity in dataset.entities.values() {
        values.push(entity.name.clone());
        values.push(entity.title.clone());
        values.push(entity.description.clone());
        values.extend(entity.concept_uri.iter().cloned());
    }
    values
        .into_iter()
        .map(|value| value.to_lowercase())
        .collect()
}

fn items_path(params: &BTreeMap<String, String>, after: Option<&str>) -> String {
    let mut path = format!("{RECORDS_BASE}/collections/{DATASETS_COLLECTION_ID}/items");
    let mut query = params
        .iter()
        .map(|(name, value)| format!("{}={}", url_encode(name), url_encode(value)))
        .collect::<Vec<_>>();
    if let Some(after) = after {
        query.push(format!("after={}", url_encode(after)));
    }
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    path
}

fn inject_entity_links(base_url: &str, dataset_id: &str, entity: &mut Value) {
    let Some(entity_object) = entity.as_object_mut() else {
        return;
    };
    let Some(entity_name) = entity_object
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    entity_object.insert(
        "schema".to_string(),
        json!(format!(
            "{base_url}/metadata/schema/{dataset_id}/{entity_name}/schema.json"
        )),
    );
    entity_object.insert(
        "collection".to_string(),
        json!(format!("{base_url}/datasets/{dataset_id}/{entity_name}")),
    );
}

fn link_json(href: &str, rel: &str, media_type: &str, title: Option<&str>) -> Value {
    let mut link = json!({
        "href": href,
        "rel": rel,
        "type": media_type,
    });
    if let Some(title) = title {
        link["title"] = json!(title);
    }
    link
}

fn link_abs(base_url: &str, path: &str, rel: &str, media_type: &str, title: Option<&str>) -> Value {
    link_json(&abs_url(base_url, path), rel, media_type, title)
}

fn abs_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct RecordsCursorContext {
    collection_id: String,
    principal_id: Option<String>,
    params: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecordsCursor {
    version: u8,
    context: RecordsCursorContext,
    position: String,
}

fn cursor_context(
    collection_id: &str,
    principal: Option<&Principal>,
    parsed: &ParsedRecordsQuery,
) -> RecordsCursorContext {
    RecordsCursorContext {
        collection_id: collection_id.to_string(),
        principal_id: principal.map(|principal| principal.principal_id.clone()),
        params: parsed.cursor_params.clone(),
    }
}

fn encode_records_cursor(signer: &CursorSigner, cursor: &RecordsCursor) -> Result<String, Error> {
    let payload = serde_json::to_vec(cursor).map_err(|_| Error::from(InternalError::Unhandled))?;
    let tag = signer.sign_payload(&payload);
    let mut buf = Vec::with_capacity(CURSOR_MAC_LEN + payload.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&payload);
    Ok(hex_lower(&buf))
}

fn decode_records_cursor(signer: &CursorSigner, cursor: &str) -> Result<RecordsCursor, Error> {
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
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn url_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

pub(crate) fn conformance_uris() -> [&'static str; 5] {
    [
        CONFORMANCE_RECORD_CORE,
        CONFORMANCE_RECORD_COLLECTION,
        CONFORMANCE_RECORD_API,
        CONFORMANCE_JSON,
        CONFORMANCE_OAS30,
    ]
}
