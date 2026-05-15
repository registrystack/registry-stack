// SPDX-License-Identifier: Apache-2.0
//! Catalog and entity-grain metadata routes.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::json;

use crate::audit::ErrorCodeExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::Config;
use crate::entity::EntityRegistry;
use crate::error::{AuthError, Error, SchemaError};
use crate::metadata;

const JSON_LD: HeaderValue = HeaderValue::from_static("application/ld+json");
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const METADATA_UNAVAILABLE_CODE: &str = "catalog.metadata_unavailable";

/// Sub-router for catalog metadata routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/catalog", get(catalog))
        .route("/catalog/dcat-ap.jsonld", get(dcat_ap))
        .route(
            "/catalog/datasets/{dataset_id}/{entity}/schema.jsonld",
            get(entity_schema),
        )
}

#[derive(Debug, Deserialize)]
struct EntityPath {
    dataset_id: String,
    entity: String,
}

async fn catalog(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = metadata_state(config, registry) else {
        return metadata_unavailable("catalog route matched, but metadata state is not installed");
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }

    Json(metadata::catalog_document(&config, &registry)).into_response()
}

async fn dcat_ap(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = metadata_state(config, registry) else {
        return metadata_unavailable(
            "DCAT-AP catalog route matched, but metadata state is not installed",
        );
    };
    if let Err(error) = require_any_metadata_scope(&config, principal) {
        return error.into_response();
    }

    json_ld_response(metadata::dcat_ap_document(&config, &registry))
}

async fn entity_schema(
    Path(path): Path<EntityPath>,
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = metadata_state(config, registry) else {
        return metadata_unavailable(
            "entity schema catalog route matched, but metadata state is not installed",
        );
    };
    if registry.dataset(&path.dataset_id).is_none() {
        return Error::from(SchemaError::UnknownDataset).into_response();
    }
    let Some(entity) = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == path.dataset_id)
        .and_then(|dataset| {
            dataset
                .entities
                .iter()
                .find(|entity| entity.name == path.entity)
        })
    else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    if let Err(error) = require_principal_scope(principal, &entity.access.metadata_scope) {
        return error.into_response();
    }
    let Some(document) =
        metadata::entity_shape_document(&config, &registry, &path.dataset_id, &path.entity)
    else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };

    json_ld_response(document)
}

fn metadata_state(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn json_ld_response(value: serde_json::Value) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, JSON_LD);
    response
}

fn require_any_metadata_scope(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    if config.datasets.iter().any(|dataset| {
        dataset
            .entities
            .iter()
            .any(|entity| principal.scopes.contains(&entity.access.metadata_scope))
    }) {
        Ok(())
    } else {
        Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity".to_string(),
        }
        .into())
    }
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

fn metadata_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/catalog/metadata_unavailable",
            "title": "Catalog metadata unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": METADATA_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(METADATA_UNAVAILABLE_CODE.to_string()));
    response
}
