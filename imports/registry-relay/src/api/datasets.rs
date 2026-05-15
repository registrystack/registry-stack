// SPDX-License-Identifier: Apache-2.0
//! Dataset listing route declarations.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Serialize;
use serde_json::json;

use crate::audit::ErrorCodeExt;
use crate::auth::Principal;
use crate::config::{AccessRights, Config, DatasetConfig, Sensitivity, UpdateFrequency};
use crate::error::{AuthError, Error, SchemaError};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const DATASETS_UNAVAILABLE_CODE: &str = "datasets.config_unavailable";

/// Sub-router for dataset summary routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/datasets", get(datasets))
        .route("/datasets/{dataset_id}", get(dataset))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DatasetSummary {
    dataset_id: String,
    title: String,
    description: String,
    owner: String,
    sensitivity: &'static str,
    access_rights: &'static str,
    update_frequency: &'static str,
    conforms_to: Vec<String>,
    entities: Vec<String>,
}

async fn datasets(
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return datasets_unavailable("datasets route matched, but config state is not installed");
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };

    let summaries = config
        .datasets
        .iter()
        .filter_map(|dataset| dataset_summary(dataset, &principal))
        .collect::<Vec<_>>();

    if summaries.is_empty() {
        return Error::from(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity".to_string(),
        })
        .into_response();
    }

    Json(json!({ "data": summaries })).into_response()
}

async fn dataset(
    Path(dataset_id): Path<String>,
    config: Option<Extension<Arc<Config>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(config)) = config else {
        return datasets_unavailable("dataset route matched, but config state is not installed");
    };
    let Some(Extension(principal)) = principal else {
        return Error::from(AuthError::MissingCredential).into_response();
    };
    let Some(dataset) = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == dataset_id)
    else {
        return Error::from(SchemaError::UnknownDataset).into_response();
    };

    let Some(summary) = dataset_summary(dataset, &principal) else {
        return Error::from(AuthError::ScopeDenied {
            required: "metadata scope on one entity in dataset".to_string(),
        })
        .into_response();
    };

    Json(summary).into_response()
}

fn dataset_summary(dataset: &DatasetConfig, principal: &Principal) -> Option<DatasetSummary> {
    let entities = dataset
        .entities
        .iter()
        .filter(|entity| principal.scopes.contains(&entity.access.metadata_scope))
        .map(|entity| entity.name.clone())
        .collect::<Vec<_>>();
    if entities.is_empty() {
        return None;
    }

    Some(DatasetSummary {
        dataset_id: dataset.id.to_string(),
        title: dataset.title.clone(),
        description: dataset.description.clone(),
        owner: dataset.owner.clone(),
        sensitivity: sensitivity(dataset.sensitivity),
        access_rights: access_rights(dataset.access_rights),
        update_frequency: update_frequency(dataset.update_frequency),
        conforms_to: dataset.conforms_to.clone(),
        entities,
    })
}

fn sensitivity(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Public => "public",
        Sensitivity::Internal => "internal",
        Sensitivity::Personal => "personal",
        Sensitivity::Confidential => "confidential",
        Sensitivity::Secret => "secret",
    }
}

fn access_rights(access_rights: AccessRights) -> &'static str {
    match access_rights {
        AccessRights::Public => "public",
        AccessRights::Restricted => "restricted",
        AccessRights::NonPublic => "non_public",
    }
}

fn update_frequency(update_frequency: UpdateFrequency) -> &'static str {
    match update_frequency {
        UpdateFrequency::Continuous => "continuous",
        UpdateFrequency::Daily => "daily",
        UpdateFrequency::Weekly => "weekly",
        UpdateFrequency::Termly => "termly",
        UpdateFrequency::Monthly => "monthly",
        UpdateFrequency::Quarterly => "quarterly",
        UpdateFrequency::Annual => "annual",
        UpdateFrequency::Irregular => "irregular",
        UpdateFrequency::AsNeeded => "as_needed",
        UpdateFrequency::Unknown => "unknown",
    }
}

fn datasets_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/datasets/config_unavailable",
            "title": "Dataset config unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": DATASETS_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(DATASETS_UNAVAILABLE_CODE.to_string()));
    response
}
