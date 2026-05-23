// SPDX-License-Identifier: Apache-2.0
//! Stable JSON catalog renderer over configured entity metadata.

use std::collections::{BTreeMap, BTreeSet};

use registry_manifest_core as metadata_core;
use serde::Serialize;

use crate::config::vocabularies;
use crate::config::{
    AccessRights, AdmsStatus, Config, DatasetConfig, EntityConfig, FieldConfig, FieldType,
    RelationshipKind, UpdateFrequency,
};
use crate::entity::{EntityField, EntityModel, EntityRegistry};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CatalogDocument {
    pub title: String,
    pub publisher: String,
    pub base_url: String,
    pub participant_id: String,
    /// BRegDCAT-AP publisher authority type IRI, forwarded from `CatalogConfig`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
    pub links: CatalogLinks,
    pub datasets: Vec<DatasetMetadata>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CatalogLinks {
    #[serde(rename = "self")]
    pub self_url: String,
    pub dcat_ap: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatasetMetadata {
    pub dataset_id: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub publisher: String,
    pub sensitivity: &'static str,
    pub access_rights: &'static str,
    pub update_frequency: &'static str,
    pub conforms_to: Vec<String>,
    /// DCAT-AP `dcatap:applicableLegislation` IRIs.
    pub applicable_legislation: Vec<String>,
    /// BRegDCAT-AP `dct:spatial` IRI, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial_coverage: Option<String>,
    /// BRegDCAT-AP `adms:status`. Defaulted at construction to
    /// `UnderDevelopment` when the operator does not declare one (the
    /// weakest lifecycle claim; forces explicit opt-in to anything
    /// stronger). The emitter maps this to the canonical
    /// `http://purl.org/adms/status/<Term>` IRI.
    pub adms_status: AdmsStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub public_services: Vec<PublicServiceMetadata>,
    #[serde(skip)]
    pub compiled_policy: Option<metadata_core::CompiledDatasetPolicy>,
    pub links: DatasetLinks,
    #[serde(skip_serializing_if = "DatasetStandardsMetadata::is_empty")]
    pub standards: DatasetStandardsMetadata,
    pub entities: Vec<EntityMetadata>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicServiceMetadata {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatasetLinks {
    #[serde(rename = "self")]
    pub self_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_collections: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_records: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DatasetStandardsMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_api_features: Option<OgcApiFeaturesMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_api_records: Option<OgcApiRecordsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdci: Option<SpdciStandardsMetadata>,
}

impl DatasetStandardsMetadata {
    fn is_empty(&self) -> bool {
        self.ogc_api_features.is_none() && self.ogc_api_records.is_none() && self.spdci.is_none()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OgcApiFeaturesMetadata {
    pub landing: String,
    pub conformance: String,
    pub collections: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OgcApiRecordsMetadata {
    pub landing: String,
    pub conformance: String,
    pub collection: String,
    pub items: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SpdciStandardsMetadata {
    pub registries: Vec<SpdciRegistryMetadata>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SpdciRegistryMetadata {
    pub registry: String,
    pub entity: String,
    pub record_type: String,
    pub sync_search: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disability_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disability_support: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EntityMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    pub primary_key: String,
    pub fields: Vec<FieldMetadata>,
    pub relationships: Vec<RelationshipMetadata>,
    pub links: EntityLinks,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EntityLinks {
    pub collection: String,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_collection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ogc_items: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldMetadata {
    pub name: String,
    pub r#type: &'static str,
    pub nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codelist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelationshipMetadata {
    pub name: String,
    pub kind: &'static str,
    pub target: String,
    pub foreign_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    pub links: RelationshipLinks,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelationshipLinks {
    pub target_schema: String,
}

#[must_use]
pub fn catalog_document(config: &Config, registry: &EntityRegistry) -> CatalogDocument {
    catalog_document_with_entity_filter(config, registry, |_, _| true)
}

#[must_use]
pub fn catalog_document_for_dataset_ids(
    config: &Config,
    registry: &EntityRegistry,
    dataset_ids: &BTreeSet<String>,
) -> CatalogDocument {
    catalog_document_with_entity_filter(config, registry, |dataset, _entity| {
        dataset_ids.contains(dataset.id.as_str())
    })
}

#[must_use]
pub fn catalog_document_for_entity_ids(
    config: &Config,
    registry: &EntityRegistry,
    entity_ids: &BTreeSet<(String, String)>,
) -> CatalogDocument {
    catalog_document_with_entity_filter(config, registry, |dataset, entity| {
        entity_ids.contains(&(dataset.id.to_string(), entity.name.clone()))
    })
}

fn catalog_document_with_entity_filter(
    config: &Config,
    registry: &EntityRegistry,
    is_visible: impl Fn(&DatasetConfig, &EntityConfig) -> bool,
) -> CatalogDocument {
    let base_url = normalized_base_url(&config.catalog.base_url);
    let datasets = config
        .datasets
        .iter()
        .filter_map(|dataset| {
            dataset_metadata_with_entity_filter(config, registry, &base_url, dataset, &is_visible)
        })
        .collect();

    CatalogDocument {
        title: config.catalog.title.clone(),
        publisher: config.catalog.publisher.clone(),
        base_url: base_url.clone(),
        participant_id: config
            .catalog
            .participant_id
            .clone()
            .unwrap_or_else(|| base_url.clone()),
        authority_type: config
            .catalog
            .authority_type
            .as_deref()
            .and_then(|uri| vocabularies::expand(uri, &config.vocabularies)),
        links: CatalogLinks {
            self_url: format!("{base_url}/metadata/catalog"),
            dcat_ap: format!("{base_url}/metadata/dcat/bregdcat-ap"),
        },
        datasets,
    }
}

#[must_use]
pub fn dataset_metadata(
    config: &Config,
    registry: &EntityRegistry,
    base_url: &str,
    dataset: &DatasetConfig,
) -> Option<DatasetMetadata> {
    dataset_metadata_with_entity_filter(config, registry, base_url, dataset, &|_, _| true)
}

fn dataset_metadata_with_entity_filter(
    config: &Config,
    registry: &EntityRegistry,
    base_url: &str,
    dataset: &DatasetConfig,
    is_visible: &impl Fn(&DatasetConfig, &EntityConfig) -> bool,
) -> Option<DatasetMetadata> {
    let dataset_id = dataset.id.as_str();
    let compiled = registry.dataset(dataset_id)?;
    let entity_configs = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.as_str(), entity))
        .collect::<BTreeMap<_, _>>();
    let table_fields = table_field_index(dataset);
    let entities = compiled
        .entities()
        .filter_map(|entity| {
            let entity_config = entity_configs.get(entity.name.as_str()).copied()?;
            if !is_visible(dataset, entity_config) {
                return None;
            }
            entity_metadata(
                config,
                base_url,
                dataset_id,
                entity,
                Some(entity_config),
                &table_fields,
            )
        })
        .collect::<Vec<_>>();
    if entities.is_empty() {
        return None;
    }

    let links = dataset_links(base_url, dataset_id, &entities);
    let standards = dataset_standards(config, base_url, dataset_id, &entities);

    let spatial_coverage = dataset
        .spatial_coverage
        .as_deref()
        .or(config.catalog.default_spatial_coverage.as_deref())
        .and_then(|uri| expand_uri(config, uri));

    Some(DatasetMetadata {
        dataset_id: dataset_id.to_string(),
        title: dataset.title.clone(),
        description: dataset.description.clone(),
        owner: dataset.owner.clone(),
        publisher: config.catalog.publisher.clone(),
        sensitivity: sensitivity(dataset.sensitivity),
        access_rights: access_rights(dataset.access_rights),
        update_frequency: update_frequency(dataset.update_frequency),
        conforms_to: dataset
            .conforms_to
            .iter()
            .filter_map(|uri| expand_uri(config, uri))
            .collect(),
        applicable_legislation: dataset
            .applicable_legislation
            .iter()
            .filter_map(|uri| expand_uri(config, uri))
            .collect(),
        spatial_coverage,
        adms_status: dataset.status.unwrap_or(AdmsStatus::UnderDevelopment),
        public_services: dataset
            .public_services
            .iter()
            .enumerate()
            .map(|(index, service)| PublicServiceMetadata {
                id: service
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("#service-{}-{}", dataset_id, index + 1)),
                title: service.title.clone(),
                description: service.description.clone().unwrap_or_default(),
            })
            .collect(),
        compiled_policy: None,
        links,
        standards,
        entities,
    })
}

pub fn attach_compiled_policies(
    catalog: &mut CatalogDocument,
    compiled: &metadata_core::CompiledMetadata,
) {
    for dataset in &mut catalog.datasets {
        dataset.compiled_policy = compiled
            .dataset(&dataset.dataset_id)
            .map(|compiled_dataset| compiled_dataset.policy.clone());
    }
}

fn dataset_links(base_url: &str, dataset_id: &str, entities: &[EntityMetadata]) -> DatasetLinks {
    DatasetLinks {
        self_url: format!("{base_url}/datasets/{dataset_id}"),
        ogc_collections: ogc_collections_url(base_url, dataset_id, entities),
        ogc_records: ogc_records_url(base_url, entities),
    }
}

fn dataset_standards(
    config: &Config,
    base_url: &str,
    dataset_id: &str,
    entities: &[EntityMetadata],
) -> DatasetStandardsMetadata {
    DatasetStandardsMetadata {
        ogc_api_features: ogc_api_features_metadata(base_url, dataset_id, entities),
        ogc_api_records: ogc_api_records_metadata(base_url, entities),
        spdci: spdci_metadata(config, base_url, dataset_id, entities),
    }
}

#[cfg(feature = "ogcapi-features")]
fn ogc_collections_url(
    base_url: &str,
    dataset_id: &str,
    entities: &[EntityMetadata],
) -> Option<String> {
    entities
        .iter()
        .any(|entity| entity.links.ogc_collection.is_some())
        .then(|| format!("{base_url}/ogc/v1/datasets/{dataset_id}/collections"))
}

#[cfg(not(feature = "ogcapi-features"))]
fn ogc_collections_url(
    _base_url: &str,
    _dataset_id: &str,
    _entities: &[EntityMetadata],
) -> Option<String> {
    None
}

#[cfg(feature = "ogcapi-features")]
fn ogc_api_features_metadata(
    base_url: &str,
    dataset_id: &str,
    entities: &[EntityMetadata],
) -> Option<OgcApiFeaturesMetadata> {
    entities
        .iter()
        .any(|entity| entity.links.ogc_collection.is_some())
        .then(|| OgcApiFeaturesMetadata {
            landing: format!("{base_url}/ogc/v1"),
            conformance: format!("{base_url}/ogc/v1/conformance"),
            collections: format!("{base_url}/ogc/v1/datasets/{dataset_id}/collections"),
        })
}

#[cfg(not(feature = "ogcapi-features"))]
fn ogc_api_features_metadata(
    _base_url: &str,
    _dataset_id: &str,
    _entities: &[EntityMetadata],
) -> Option<OgcApiFeaturesMetadata> {
    None
}

#[cfg(feature = "ogcapi-records")]
fn ogc_records_url(base_url: &str, entities: &[EntityMetadata]) -> Option<String> {
    (!entities.is_empty()).then(|| format!("{base_url}/ogc/v1/records/collections/datasets/items"))
}

#[cfg(not(feature = "ogcapi-records"))]
fn ogc_records_url(_base_url: &str, _entities: &[EntityMetadata]) -> Option<String> {
    None
}

#[cfg(feature = "ogcapi-records")]
fn ogc_api_records_metadata(
    base_url: &str,
    entities: &[EntityMetadata],
) -> Option<OgcApiRecordsMetadata> {
    (!entities.is_empty()).then(|| OgcApiRecordsMetadata {
        landing: format!("{base_url}/ogc/v1/records"),
        conformance: format!("{base_url}/ogc/v1/records/conformance"),
        collection: format!("{base_url}/ogc/v1/records/collections/datasets"),
        items: format!("{base_url}/ogc/v1/records/collections/datasets/items"),
    })
}

#[cfg(not(feature = "ogcapi-records"))]
fn ogc_api_records_metadata(
    _base_url: &str,
    _entities: &[EntityMetadata],
) -> Option<OgcApiRecordsMetadata> {
    None
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_metadata(
    config: &Config,
    base_url: &str,
    dataset_id: &str,
    entities: &[EntityMetadata],
) -> Option<SpdciStandardsMetadata> {
    let spdci = config.standards.spdci.as_ref()?;
    let visible_entities = entities
        .iter()
        .map(|entity| entity.name.as_str())
        .collect::<BTreeSet<_>>();
    let disability = spdci.disability_registry.as_ref();
    let mut registries = Vec::new();

    if spdci.registries.is_empty() {
        if let Some(disability) = disability {
            if disability.dataset.as_str() == dataset_id
                && visible_entities.contains(disability.entity.as_str())
            {
                registries.push(spdci_registry_metadata(
                    base_url,
                    "dr",
                    &disability.entity,
                    "spdci-extensions-dci:DisabledPerson",
                    true,
                ));
            }
        }
    } else {
        for (name, registry) in &spdci.registries {
            if registry.dataset.as_str() != dataset_id
                || !visible_entities.contains(registry.entity.as_str())
            {
                continue;
            }
            let supports_disability = disability.is_some_and(|disability| {
                disability.dataset.as_str() == registry.dataset.as_str()
                    && disability.entity.as_str() == registry.entity.as_str()
            });
            registries.push(spdci_registry_metadata(
                base_url,
                name,
                &registry.entity,
                &registry.record_type,
                supports_disability,
            ));
        }
    }

    (!registries.is_empty()).then_some(SpdciStandardsMetadata { registries })
}

#[cfg(not(feature = "spdci-api-standards"))]
fn spdci_metadata(
    _config: &Config,
    _base_url: &str,
    _dataset_id: &str,
    _entities: &[EntityMetadata],
) -> Option<SpdciStandardsMetadata> {
    None
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_registry_metadata(
    base_url: &str,
    registry: &str,
    entity: &str,
    record_type: &str,
    supports_disability: bool,
) -> SpdciRegistryMetadata {
    let sync_base = format!("{base_url}/dci/{registry}/registry/sync");
    SpdciRegistryMetadata {
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

#[must_use]
pub fn entity_metadata(
    config: &Config,
    base_url: &str,
    dataset_id: &str,
    entity: &EntityModel,
    entity_config: Option<&EntityConfig>,
    table_fields: &BTreeMap<(String, String), &FieldConfig>,
) -> Option<EntityMetadata> {
    let fields = entity
        .fields
        .iter()
        .filter_map(|field| field_metadata(config, entity_config, entity, field, table_fields))
        .collect::<Vec<_>>();
    let relationships = entity
        .relationships
        .values()
        .map(|relationship| RelationshipMetadata {
            name: relationship.name.clone(),
            kind: relationship_kind(relationship.kind),
            target: relationship.target.clone(),
            foreign_key: relationship.foreign_key.clone(),
            concept_uri: relationship
                .concept_uri
                .as_deref()
                .and_then(|uri| expand_uri(config, uri)),
            links: RelationshipLinks {
                target_schema: format!(
                    "{base_url}/metadata/schema/{dataset_id}/{}/schema.json",
                    relationship.target
                ),
            },
        })
        .collect();

    #[cfg(feature = "ogcapi-features")]
    let (ogc_collection, ogc_items) = entity
        .spatial
        .as_ref()
        .map(|spatial| {
            (
                Some(format!(
                    "{base_url}/ogc/v1/datasets/{dataset_id}/collections/{}",
                    spatial.collection_id
                )),
                Some(format!(
                    "{base_url}/ogc/v1/datasets/{dataset_id}/collections/{}/items",
                    spatial.collection_id
                )),
            )
        })
        .unwrap_or((None, None));
    #[cfg(not(feature = "ogcapi-features"))]
    let (ogc_collection, ogc_items) = (None, None);

    Some(EntityMetadata {
        name: entity.name.clone(),
        title: entity_config.and_then(|cfg| cfg.title.clone()),
        description: entity_config.and_then(|cfg| cfg.description.clone()),
        concept_uri: entity_config
            .and_then(|cfg| cfg.concept_uri.as_deref())
            .and_then(|uri| expand_uri(config, uri)),
        primary_key: entity.primary_key.name.clone(),
        fields,
        relationships,
        links: EntityLinks {
            collection: format!("{base_url}/datasets/{dataset_id}/{}", entity.name),
            schema: format!(
                "{base_url}/metadata/schema/{dataset_id}/{}/schema.json",
                entity.name
            ),
            ogc_collection,
            ogc_items,
        },
    })
}

fn field_metadata(
    config: &Config,
    entity_config: Option<&EntityConfig>,
    entity: &EntityModel,
    entity_field: &EntityField,
    table_fields: &BTreeMap<(String, String), &FieldConfig>,
) -> Option<FieldMetadata> {
    let table_field =
        table_fields.get(&(entity.table_id.clone(), entity_field.table_column.clone()))?;
    let override_field = entity_config.and_then(|cfg| {
        cfg.fields
            .iter()
            .find(|field| field.name == entity_field.name)
    });

    Some(FieldMetadata {
        name: entity_field.name.clone(),
        r#type: field_type(table_field.r#type),
        nullable: table_field.nullable,
        concept_uri: override_field
            .and_then(|field| field.concept_uri.as_deref())
            .or(table_field.concept_uri.as_deref())
            .and_then(|uri| expand_uri(config, uri)),
        codelist: override_field
            .and_then(|field| field.codelist.as_deref())
            .or(table_field.codelist.as_deref())
            .and_then(|uri| expand_uri(config, uri)),
        unit: override_field
            .and_then(|field| field.unit.clone())
            .or_else(|| table_field.unit.clone()),
        language: override_field
            .and_then(|field| field.language.clone())
            .or_else(|| table_field.language.clone()),
    })
}

#[must_use]
pub fn field_property_uri(
    base_url: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &FieldMetadata,
) -> String {
    field.concept_uri.clone().unwrap_or_else(|| {
        format!(
            "{base_url}/datasets/{dataset_id}/{entity_name}/fields/{}",
            field.name
        )
    })
}

#[must_use]
pub fn entity_class_uri(base_url: &str, dataset_id: &str, entity: &EntityMetadata) -> String {
    entity
        .concept_uri
        .clone()
        .unwrap_or_else(|| format!("{base_url}/datasets/{dataset_id}/{}/schema", entity.name))
}

#[must_use]
pub fn normalized_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn table_field_index(dataset: &DatasetConfig) -> BTreeMap<(String, String), &FieldConfig> {
    let mut fields = BTreeMap::new();
    for table in dataset.table_configs() {
        for field in &table.schema.fields {
            fields.insert((table.id.to_string(), field.name.clone()), field);
        }
    }
    fields
}

fn expand_uri(config: &Config, uri: &str) -> Option<String> {
    vocabularies::expand(uri, &config.vocabularies)
}

pub fn field_type(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String => "string",
        FieldType::Number => "number",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::Date => "date",
        FieldType::Timestamp => "timestamp",
    }
}

pub fn relationship_kind(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::BelongsTo => "belongs_to",
        RelationshipKind::HasMany => "has_many",
        RelationshipKind::HasOne => "has_one",
    }
}

fn sensitivity(sensitivity: crate::config::Sensitivity) -> &'static str {
    match sensitivity {
        crate::config::Sensitivity::Public => "public",
        crate::config::Sensitivity::Internal => "internal",
        crate::config::Sensitivity::Personal => "personal",
        crate::config::Sensitivity::Confidential => "confidential",
        crate::config::Sensitivity::Secret => "secret",
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
