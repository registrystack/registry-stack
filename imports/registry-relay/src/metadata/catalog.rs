// SPDX-License-Identifier: Apache-2.0
//! Stable JSON catalog renderer over configured entity metadata.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::vocabularies;
use crate::config::{
    AccessRights, Config, DatasetConfig, EntityConfig, FieldConfig, FieldType, RelationshipKind,
    UpdateFrequency,
};
use crate::entity::{EntityField, EntityModel, EntityRegistry};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CatalogDocument {
    pub title: String,
    pub publisher: String,
    pub base_url: String,
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
    pub links: DatasetLinks,
    pub entities: Vec<EntityMetadata>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatasetLinks {
    #[serde(rename = "self")]
    pub self_url: String,
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
    let base_url = normalized_base_url(&config.catalog.base_url);
    let datasets = config
        .datasets
        .iter()
        .filter_map(|dataset| dataset_metadata(config, registry, &base_url, dataset))
        .collect();

    CatalogDocument {
        title: config.catalog.title.clone(),
        publisher: config.catalog.publisher.clone(),
        base_url: base_url.clone(),
        links: CatalogLinks {
            self_url: format!("{base_url}/catalog"),
            dcat_ap: format!("{base_url}/catalog/dcat-ap.jsonld"),
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
            entity_metadata(
                config,
                base_url,
                dataset_id,
                entity,
                entity_configs.get(entity.name.as_str()).copied(),
                &table_fields,
            )
        })
        .collect();

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
        links: DatasetLinks {
            self_url: format!("{base_url}/datasets/{dataset_id}"),
        },
        entities,
    })
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
                    "{base_url}/catalog/datasets/{dataset_id}/{}/schema.jsonld",
                    relationship.target
                ),
            },
        })
        .collect();

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
                "{base_url}/catalog/datasets/{dataset_id}/{}/schema.jsonld",
                entity.name
            ),
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
        UpdateFrequency::Monthly => "monthly",
        UpdateFrequency::Quarterly => "quarterly",
        UpdateFrequency::Annual => "annual",
        UpdateFrequency::Irregular => "irregular",
        UpdateFrequency::Unknown => "unknown",
    }
}
