// SPDX-License-Identifier: Apache-2.0
//! Dataset listing route declarations.

use std::collections::BTreeSet;
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
    links: DatasetLinks,
    #[serde(skip_serializing_if = "DatasetStandards::is_empty")]
    standards: DatasetStandards,
    entities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DatasetLinks {
    #[serde(rename = "self")]
    self_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ogc_collections: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct DatasetStandards {
    #[serde(skip_serializing_if = "Option::is_none")]
    ogc_api_features: Option<OgcApiFeaturesStandard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spdci: Option<SpdciStandard>,
}

impl DatasetStandards {
    fn is_empty(&self) -> bool {
        self.ogc_api_features.is_none() && self.spdci.is_none()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct OgcApiFeaturesStandard {
    landing: String,
    conformance: String,
    collections: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SpdciStandard {
    registries: Vec<SpdciRegistryStandard>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SpdciRegistryStandard {
    registry: String,
    entity: String,
    record_type: String,
    sync_search: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disability_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disability_support: Option<String>,
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
        .filter_map(|dataset| dataset_summary(&config, dataset, &principal))
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

    let Some(summary) = dataset_summary(&config, dataset, &principal) else {
        return Error::from(AuthError::ScopeDenied {
            required: "metadata scope on one entity in dataset".to_string(),
        })
        .into_response();
    };

    Json(summary).into_response()
}

fn dataset_summary(
    config: &Config,
    dataset: &DatasetConfig,
    principal: &Principal,
) -> Option<DatasetSummary> {
    let entities = dataset
        .entities
        .iter()
        .filter(|entity| principal.scopes.contains(&entity.access.metadata_scope))
        .map(|entity| entity.name.clone())
        .collect::<Vec<_>>();
    if entities.is_empty() {
        return None;
    }
    let standards = dataset_standards(config, dataset, &entities);

    Some(DatasetSummary {
        dataset_id: dataset.id.to_string(),
        title: dataset.title.clone(),
        description: dataset.description.clone(),
        owner: dataset.owner.clone(),
        sensitivity: sensitivity(dataset.sensitivity),
        access_rights: access_rights(dataset.access_rights),
        update_frequency: update_frequency(dataset.update_frequency),
        conforms_to: dataset.conforms_to.clone(),
        links: DatasetLinks {
            self_url: format!("/datasets/{}", dataset.id),
            ogc_collections: standards
                .ogc_api_features
                .as_ref()
                .map(|ogc| ogc.collections.clone()),
        },
        standards,
        entities,
    })
}

fn dataset_standards(
    config: &Config,
    dataset: &DatasetConfig,
    visible_entities: &[String],
) -> DatasetStandards {
    let visible_entities = visible_entities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    DatasetStandards {
        ogc_api_features: ogc_api_features_standard(dataset, &visible_entities),
        spdci: spdci_standard(config, dataset, &visible_entities),
    }
}

#[cfg(feature = "ogcapi-features")]
fn ogc_api_features_standard(
    dataset: &DatasetConfig,
    visible_entities: &BTreeSet<&str>,
) -> Option<OgcApiFeaturesStandard> {
    dataset
        .entities
        .iter()
        .any(|entity| visible_entities.contains(entity.name.as_str()) && entity.spatial.is_some())
        .then(|| OgcApiFeaturesStandard {
            landing: "/ogc/v1".to_string(),
            conformance: "/ogc/v1/conformance".to_string(),
            collections: format!("/ogc/v1/datasets/{}/collections", dataset.id),
        })
}

#[cfg(not(feature = "ogcapi-features"))]
fn ogc_api_features_standard(
    _dataset: &DatasetConfig,
    _visible_entities: &BTreeSet<&str>,
) -> Option<OgcApiFeaturesStandard> {
    None
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_standard(
    config: &Config,
    dataset: &DatasetConfig,
    visible_entities: &BTreeSet<&str>,
) -> Option<SpdciStandard> {
    let spdci = config.standards.spdci.as_ref()?;
    let disability = spdci.disability_registry.as_ref();
    let mut registries = Vec::new();

    if spdci.registries.is_empty() {
        if let Some(disability) = disability {
            if disability.dataset.as_str() == dataset.id.as_str()
                && visible_entities.contains(disability.entity.as_str())
            {
                registries.push(spdci_registry_standard(
                    "dr",
                    &disability.entity,
                    "spdci-extensions-dci:DisabledPerson",
                    true,
                ));
            }
        }
    } else {
        for (name, registry) in &spdci.registries {
            if registry.dataset.as_str() != dataset.id.as_str()
                || !visible_entities.contains(registry.entity.as_str())
            {
                continue;
            }
            let supports_disability = disability.is_some_and(|disability| {
                disability.dataset.as_str() == registry.dataset.as_str()
                    && disability.entity.as_str() == registry.entity.as_str()
            });
            registries.push(spdci_registry_standard(
                name,
                &registry.entity,
                &registry.record_type,
                supports_disability,
            ));
        }
    }

    (!registries.is_empty()).then_some(SpdciStandard { registries })
}

#[cfg(not(feature = "spdci-api-standards"))]
fn spdci_standard(
    _config: &Config,
    _dataset: &DatasetConfig,
    _visible_entities: &BTreeSet<&str>,
) -> Option<SpdciStandard> {
    None
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_registry_standard(
    registry: &str,
    entity: &str,
    record_type: &str,
    supports_disability: bool,
) -> SpdciRegistryStandard {
    let sync_base = format!("/dci/{registry}/registry/sync");
    SpdciRegistryStandard {
        registry: registry.to_string(),
        entity: entity.to_string(),
        record_type: record_type.to_string(),
        sync_search: format!("{sync_base}/search"),
        disabled: supports_disability.then(|| format!("{sync_base}/disabled")),
        disability_details: supports_disability
            .then(|| format!("{sync_base}/get-disability-details")),
        disability_support: supports_disability
            .then(|| format!("{sync_base}/get-disability-support")),
    }
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
