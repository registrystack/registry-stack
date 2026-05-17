// SPDX-License-Identifier: Apache-2.0
//! Entity-layer registry.
//!
//! This module is the boundary between private storage tables and the
//! public REST model. Config validation proves the shape is coherent;
//! the registry compiles it into lookup maps for query/API code.

use std::collections::BTreeMap;

use crate::config::{
    Config, DatasetConfig, EntityAccessConfig, EntityApiConfig, EntityClaimVerificationConfig,
    EntityConfig, EntityRelationshipConfig, FieldType, ResourceConfig, SpatialBboxFieldsConfig,
    SpatialGeometryConfig,
};
use crate::error::{ConfigError, Error};

#[derive(Clone, Debug, Default)]
pub struct EntityRegistry {
    datasets: BTreeMap<String, DatasetEntities>,
}

#[derive(Clone, Debug, Default)]
pub struct DatasetEntities {
    entities: BTreeMap<String, EntityModel>,
}

#[derive(Clone, Debug)]
pub struct EntityModel {
    pub name: String,
    pub table_id: String,
    pub primary_key: EntityField,
    pub fields: Vec<EntityField>,
    pub relationships: BTreeMap<String, EntityRelationshipConfig>,
    pub access: EntityAccessConfig,
    pub api: EntityApiConfig,
    pub spatial: Option<EntitySpatialModel>,
    pub claim_verification: Option<EntityClaimVerificationConfig>,
}

#[derive(Clone, Debug)]
pub struct EntityField {
    pub name: String,
    pub table_column: String,
}

#[derive(Clone, Debug)]
pub struct EntitySpatialModel {
    pub collection_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub geometry: SpatialGeometryConfig,
    pub bbox_fields: Option<SpatialBboxFieldsConfig>,
    pub datetime_field: Option<String>,
    pub datetime_field_type: Option<FieldType>,
    pub max_bbox_degrees: f64,
    pub max_geometry_vertices: u32,
}

impl EntityRegistry {
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut datasets = BTreeMap::new();
        for dataset in &config.datasets {
            datasets.insert(dataset.id.to_string(), compile_dataset(dataset)?);
        }
        Ok(Self { datasets })
    }

    pub fn dataset(&self, dataset_id: &str) -> Option<&DatasetEntities> {
        self.datasets.get(dataset_id)
    }
}

impl DatasetEntities {
    pub fn entity(&self, entity_name: &str) -> Option<&EntityModel> {
        self.entities.get(entity_name)
    }

    pub fn entities(&self) -> impl Iterator<Item = &EntityModel> {
        self.entities.values()
    }
}

fn compile_dataset(dataset: &DatasetConfig) -> Result<DatasetEntities, Error> {
    let tables: BTreeMap<&str, &ResourceConfig> = dataset
        .table_configs()
        .map(|table| (table.id.as_str(), table))
        .collect();
    let mut entities = BTreeMap::new();

    for entity in &dataset.entities {
        let table = tables
            .get(entity.table.as_str())
            .ok_or(ConfigError::ValidationError)?;
        let fields = compile_fields(entity, table);
        let primary_key = primary_key_field(table, &fields)?;
        let relationships = entity
            .relationships
            .iter()
            .cloned()
            .map(|rel| (rel.name.clone(), rel))
            .collect();
        let spatial = compile_spatial(entity, table, &fields);

        entities.insert(
            entity.name.clone(),
            EntityModel {
                name: entity.name.clone(),
                table_id: entity.table.to_string(),
                primary_key,
                fields,
                relationships,
                access: entity.access.clone(),
                api: entity.api.clone(),
                spatial,
                claim_verification: entity.claim_verification.clone(),
            },
        );
    }

    Ok(DatasetEntities { entities })
}

fn compile_fields(entity: &EntityConfig, table: &ResourceConfig) -> Vec<EntityField> {
    if entity.fields.is_empty() {
        return table
            .schema
            .fields
            .iter()
            .map(|field| EntityField {
                name: field.name.clone(),
                table_column: field.name.clone(),
            })
            .collect();
    }

    entity
        .fields
        .iter()
        .map(|field| EntityField {
            name: field.name.clone(),
            table_column: field.from.clone().unwrap_or_else(|| field.name.clone()),
        })
        .collect()
}

fn primary_key_field(table: &ResourceConfig, fields: &[EntityField]) -> Result<EntityField, Error> {
    let primary_key = table
        .primary_key
        .as_deref()
        .ok_or(ConfigError::ValidationError)?;
    fields
        .iter()
        .find(|field| field.table_column == primary_key)
        .cloned()
        .ok_or_else(|| ConfigError::ValidationError.into())
}

fn compile_spatial(
    entity: &EntityConfig,
    table: &ResourceConfig,
    fields: &[EntityField],
) -> Option<EntitySpatialModel> {
    let spatial = entity.spatial.as_ref()?;
    let datetime_field_type = spatial
        .datetime_field
        .as_deref()
        .and_then(|datetime_field| {
            let table_column = fields
                .iter()
                .find(|field| field.name == datetime_field)?
                .table_column
                .as_str();
            table
                .schema
                .fields
                .iter()
                .find(|field| field.name == table_column)
                .map(|field| field.r#type)
        });
    Some(EntitySpatialModel {
        collection_id: spatial
            .collection_id
            .clone()
            .unwrap_or_else(|| entity.name.clone()),
        title: spatial.title.clone(),
        description: spatial.description.clone(),
        geometry: spatial.geometry.clone(),
        bbox_fields: spatial.bbox_fields.clone(),
        datetime_field: spatial.datetime_field.clone(),
        datetime_field_type,
        max_bbox_degrees: spatial.max_bbox_degrees,
        max_geometry_vertices: spatial.max_geometry_vertices,
    })
}
