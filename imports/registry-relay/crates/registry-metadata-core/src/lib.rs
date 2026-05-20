// SPDX-License-Identifier: Apache-2.0
//! Portable metadata model and pure renderers for Registry Relay catalogs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

const DATASETS_COLLECTION_ID: &str = "datasets";
const JSON_SCHEMA_DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetadataManifest {
    pub schema_version: String,
    pub catalog: CatalogManifest,
    #[serde(default)]
    pub vocabularies: BTreeMap<String, String>,
    #[serde(default)]
    pub profiles: Vec<ProfileClaim>,
    #[serde(default)]
    pub datasets: Vec<DatasetManifest>,
    #[serde(default)]
    pub codelists: Vec<CodelistManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogManifest {
    pub id: String,
    pub base_url: String,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    pub publisher: PublisherManifest,
    #[serde(default)]
    pub participant_id: Option<String>,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    #[serde(default)]
    pub standards: StandardsManifest,
    #[serde(default)]
    pub application_profiles: Vec<ApplicationProfile>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StandardsManifest {
    #[serde(default)]
    pub dcat: Option<String>,
    #[serde(default)]
    pub shacl: Option<String>,
    #[serde(default)]
    pub json_schema: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationProfile {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileClaim {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LocalizedText {
    Plain(String),
    Localized(BTreeMap<String, String>),
}

impl LocalizedText {
    pub fn text(&self) -> String {
        match self {
            Self::Plain(value) => value.clone(),
            Self::Localized(values) => values
                .get("en")
                .or_else(|| values.values().next())
                .cloned()
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublisherManifest {
    pub name: String,
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub authority_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatasetManifest {
    pub id: String,
    pub title: LocalizedText,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub access_rights: AccessRights,
    #[serde(default)]
    pub update_frequency: UpdateFrequency,
    #[serde(default)]
    pub conforms_to: Vec<String>,
    #[serde(default)]
    pub spatial_coverage: Option<String>,
    #[serde(default)]
    pub status: Option<AdmsStatus>,
    #[serde(default)]
    pub entities: Vec<EntityManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntityManifest {
    pub name: String,
    #[serde(default)]
    pub title: Option<LocalizedText>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub concept_uri: Option<String>,
    #[serde(default)]
    pub identifiers: Vec<IdentifierManifest>,
    #[serde(default)]
    pub fields: Vec<FieldManifest>,
    #[serde(default)]
    pub relationships: Vec<RelationshipManifest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentifierManifest {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldManifest {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub constraints: FieldConstraints,
    #[serde(default)]
    pub concepts: Vec<String>,
    #[serde(default)]
    pub codelist: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldConstraints {
    #[serde(default)]
    pub min_length: Option<u64>,
    #[serde(default)]
    pub max_length: Option<u64>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "in")]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationshipManifest {
    pub name: String,
    #[serde(default)]
    pub target_entity: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub cardinality: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub concept_uri: Option<String>,
}

impl RelationshipManifest {
    fn target_name(&self) -> Option<&str> {
        self.target_entity.as_deref().or(self.target.as_deref())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodelistManifest {
    pub id: String,
    pub scheme_iri: String,
    #[serde(default)]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub concepts: Vec<CodelistConcept>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodelistConcept {
    pub code: String,
    #[serde(default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub label: Option<LocalizedText>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    #[default]
    Public,
    Internal,
    Personal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessRights {
    Public,
    #[default]
    Restricted,
    NonPublic,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFrequency {
    Continuous,
    Daily,
    Weekly,
    Termly,
    Monthly,
    Quarterly,
    Annual,
    Irregular,
    AsNeeded,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmsStatus {
    UnderDevelopment,
    Active,
    Completed,
    Deprecated,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Number,
    Integer,
    Boolean,
    Date,
    Timestamp,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMetadata {
    inner: Arc<CompiledMetadataInner>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledMetadataInner {
    pub catalog: CompiledCatalog,
    pub datasets: BTreeMap<String, CompiledDataset>,
    pub codelists: BTreeMap<String, CompiledCodelist>,
    pub profiles: Vec<ProfileClaim>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledCatalog {
    pub id: String,
    pub title: String,
    pub description: String,
    pub publisher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_iri: Option<String>,
    pub base_url: String,
    pub participant_id: String,
    pub conforms_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
    pub application_profiles: Vec<ApplicationProfile>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledDataset {
    pub dataset_id: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub sensitivity: Sensitivity,
    pub access_rights: AccessRights,
    pub update_frequency: UpdateFrequency,
    pub conforms_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spatial_coverage: Option<String>,
    pub adms_status: AdmsStatus,
    pub entities: BTreeMap<String, CompiledEntity>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledEntity {
    pub name: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
    pub primary_key: String,
    pub identifiers: Vec<IdentifierManifest>,
    pub fields: BTreeMap<String, CompiledField>,
    pub relationships: Vec<CompiledRelationship>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledField {
    pub name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub constraints: FieldConstraints,
    pub concepts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codelist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codelist_scheme_iri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledRelationship {
    pub name: String,
    pub target: String,
    pub cardinality: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompiledCodelist {
    pub id: String,
    pub scheme_iri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    pub concepts: Vec<CodelistConcept>,
}

impl CompiledMetadata {
    pub fn catalog(&self) -> &CompiledCatalog {
        &self.inner.catalog
    }

    pub fn datasets(&self) -> impl Iterator<Item = &CompiledDataset> {
        self.inner.datasets.values()
    }

    pub fn dataset(&self, dataset_id: &str) -> Option<&CompiledDataset> {
        self.inner.datasets.get(dataset_id)
    }

    pub fn codelist(&self, codelist_id: &str) -> Option<&CompiledCodelist> {
        self.inner.codelists.get(codelist_id)
    }

    pub fn codelists(&self) -> impl Iterator<Item = &CompiledCodelist> {
        self.inner.codelists.values()
    }

    pub fn profiles(&self) -> &[ProfileClaim] {
        &self.inner.profiles
    }

    pub fn filter(
        &self,
        predicate: impl Fn(&CompiledDataset, &CompiledEntity) -> bool,
    ) -> CompiledMetadata {
        let datasets = self
            .inner
            .datasets
            .iter()
            .filter_map(|(dataset_id, dataset)| {
                let entities = dataset
                    .entities
                    .iter()
                    .filter(|(_, entity)| predicate(dataset, entity))
                    .map(|(entity_name, entity)| (entity_name.clone(), entity.clone()))
                    .collect::<BTreeMap<_, _>>();
                (!entities.is_empty()).then(|| {
                    let mut dataset = dataset.clone();
                    dataset.entities = entities;
                    (dataset_id.clone(), dataset)
                })
            })
            .collect();
        CompiledMetadata {
            inner: Arc::new(CompiledMetadataInner {
                catalog: self.inner.catalog.clone(),
                datasets,
                codelists: self.inner.codelists.clone(),
                profiles: self.inner.profiles.clone(),
            }),
        }
    }
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("metadata.manifest.version_unsupported")]
    VersionUnsupported,
    #[error("metadata.manifest.validation_failed")]
    Validation { errors: Vec<ValidationError> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl ValidationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

pub fn validate_manifest(manifest: &MetadataManifest) -> Result<(), MetadataError> {
    let mut errors = Vec::new();
    if manifest.schema_version != "registry-metadata/v1" {
        return Err(MetadataError::VersionUnsupported);
    }
    validate_id(&manifest.catalog.id, "catalog.id", &mut errors);
    validate_http_url(&manifest.catalog.base_url, "catalog.base_url", &mut errors);
    validate_non_empty(&manifest.catalog.title.text(), "catalog.title", &mut errors);
    validate_non_empty(
        &manifest.catalog.publisher.name,
        "catalog.publisher.name",
        &mut errors,
    );
    validate_optional_uri(
        manifest.catalog.publisher.iri.as_deref(),
        "catalog.publisher.iri",
        &manifest.vocabularies,
        &mut errors,
    );
    validate_optional_uri(
        manifest.catalog.publisher.authority_type.as_deref(),
        "catalog.publisher.authority_type",
        &manifest.vocabularies,
        &mut errors,
    );
    validate_uri_list(
        &manifest.catalog.conforms_to,
        "catalog.conforms_to",
        &manifest.vocabularies,
        &mut errors,
    );
    for (index, profile) in manifest.catalog.application_profiles.iter().enumerate() {
        validate_id(
            &profile.id,
            format!("catalog.application_profiles[{index}].id"),
            &mut errors,
        );
        validate_non_empty(
            &profile.version,
            format!("catalog.application_profiles[{index}].version"),
            &mut errors,
        );
        if !is_supported_application_profile(&profile.id) {
            errors.push(ValidationError::new(
                format!("catalog.application_profiles[{index}].id"),
                "application profile is not supported by the current renderer",
            ));
        }
    }

    let mut codelist_ids = BTreeSet::new();
    for (index, codelist) in manifest.codelists.iter().enumerate() {
        let path = format!("codelists[{index}]");
        validate_id(&codelist.id, format!("{path}.id"), &mut errors);
        if !codelist_ids.insert(codelist.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "codelist id must be unique",
            ));
        }
        validate_uri(
            &codelist.scheme_iri,
            format!("{path}.scheme_iri"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_optional_uri(
            codelist.external_ref.as_deref(),
            format!("{path}.external_ref"),
            &manifest.vocabularies,
            &mut errors,
        );
    }

    let mut dataset_ids = BTreeSet::new();
    for (dataset_index, dataset) in manifest.datasets.iter().enumerate() {
        let path = format!("datasets[{dataset_index}]");
        validate_id(&dataset.id, format!("{path}.id"), &mut errors);
        if !dataset_ids.insert(dataset.id.as_str()) {
            errors.push(ValidationError::new(
                format!("{path}.id"),
                "dataset id must be unique",
            ));
        }
        validate_non_empty(&dataset.title.text(), format!("{path}.title"), &mut errors);
        validate_uri_list(
            &dataset.conforms_to,
            format!("{path}.conforms_to"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_optional_uri(
            dataset.spatial_coverage.as_deref(),
            format!("{path}.spatial_coverage"),
            &manifest.vocabularies,
            &mut errors,
        );
        validate_entities(
            dataset,
            &path,
            &codelist_ids,
            &manifest.vocabularies,
            &mut errors,
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(MetadataError::Validation { errors })
    }
}

pub fn compile_manifest(manifest: &MetadataManifest) -> Result<CompiledMetadata, MetadataError> {
    validate_manifest(manifest)?;
    let base_url = normalized_base_url(&manifest.catalog.base_url);
    let codelists = manifest
        .codelists
        .iter()
        .map(|codelist| {
            (
                codelist.id.clone(),
                CompiledCodelist {
                    id: codelist.id.clone(),
                    scheme_iri: expand_uri(&codelist.scheme_iri, &manifest.vocabularies)
                        .unwrap_or_else(|| codelist.scheme_iri.clone()),
                    external_ref: codelist
                        .external_ref
                        .as_deref()
                        .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                    concepts: codelist.concepts.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let datasets = manifest
        .datasets
        .iter()
        .map(|dataset| {
            (
                dataset.id.clone(),
                compile_dataset(manifest, &base_url, &codelists, dataset),
            )
        })
        .collect();
    let publisher = &manifest.catalog.publisher;
    Ok(CompiledMetadata {
        inner: Arc::new(CompiledMetadataInner {
            catalog: CompiledCatalog {
                id: manifest.catalog.id.clone(),
                title: manifest.catalog.title.text(),
                description: manifest
                    .catalog
                    .description
                    .as_ref()
                    .map(LocalizedText::text)
                    .unwrap_or_default(),
                publisher: publisher.name.clone(),
                publisher_iri: publisher
                    .iri
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                base_url: base_url.clone(),
                participant_id: manifest
                    .catalog
                    .participant_id
                    .clone()
                    .unwrap_or_else(|| base_url.clone()),
                conforms_to: manifest
                    .catalog
                    .conforms_to
                    .iter()
                    .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
                    .collect(),
                authority_type: publisher
                    .authority_type
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
                application_profiles: manifest.catalog.application_profiles.clone(),
            },
            datasets,
            codelists,
            profiles: manifest.profiles.clone(),
        }),
    })
}

pub fn render_catalog(compiled: &CompiledMetadata) -> Value {
    json!({
        "id": compiled.catalog().id,
        "title": compiled.catalog().title,
        "description": compiled.catalog().description,
        "publisher": compiled.catalog().publisher,
        "base_url": compiled.catalog().base_url,
        "participant_id": compiled.catalog().participant_id,
        "conforms_to": compiled.catalog().conforms_to,
        "application_profiles": compiled.catalog().application_profiles,
        "datasets": compiled.datasets().map(catalog_dataset_json).collect::<Vec<_>>(),
        "profiles": compiled.profiles(),
    })
}

pub fn render_base_dcat(compiled: &CompiledMetadata) -> Value {
    json!({
        "@context": jsonld_context(),
        "@id": format!("{}/metadata/dcat.jsonld", compiled.catalog().base_url),
        "@type": "dcat:Catalog",
        "dcterms:title": compiled.catalog().title,
        "dcterms:description": compiled.catalog().description,
        "dcterms:publisher": publisher_agent(compiled.catalog()),
        "dcat:landingPage": compiled.catalog().base_url,
        "dcterms:conformsTo": compiled.catalog().conforms_to,
        "dcat:dataset": compiled.datasets().map(base_dcat_dataset).collect::<Vec<_>>(),
    })
}

pub fn render_breg_dcat_ap(compiled: &CompiledMetadata) -> Value {
    let mut catalog = render_base_dcat(compiled);
    catalog["@id"] = json!(format!(
        "{}/metadata/dcat.bregdcat-ap.jsonld",
        compiled.catalog().base_url
    ));
    catalog["dspace:participantId"] = json!(compiled.catalog().participant_id);
    catalog["dcat:dataset"] = Value::Array(compiled.datasets().map(breg_dcat_dataset).collect());
    catalog["sh:shapesGraph"] = Value::Array(
        compiled
            .datasets()
            .flat_map(|dataset| {
                dataset
                    .entities
                    .values()
                    .map(move |entity| entity_shape(compiled, dataset, entity))
            })
            .collect(),
    );
    catalog
}

pub fn render_dcat_profile(compiled: &CompiledMetadata, profile: &str) -> Option<Value> {
    match profile {
        "bregdcat-ap" => Some(render_breg_dcat_ap(compiled)),
        "dcat" | "dcat-ap" => Some(render_base_dcat(compiled)),
        _ => None,
    }
}

pub fn render_shacl(compiled: &CompiledMetadata) -> Value {
    json!({
        "@context": jsonld_context(),
        "@graph": compiled
            .datasets()
            .flat_map(|dataset| dataset.entities.values().map(move |entity| entity_shape(compiled, dataset, entity)))
            .chain(compiled.codelists().map(codelist_shape))
            .collect::<Vec<_>>(),
    })
}

pub fn render_entity_shacl(
    compiled: &CompiledMetadata,
    dataset_id: &str,
    entity_name: &str,
) -> Option<Value> {
    let dataset = compiled.dataset(dataset_id)?;
    let entity = dataset.entities.get(entity_name)?;
    Some(json!({
        "@context": jsonld_context(),
        "shape": entity_shape(compiled, dataset, entity),
    }))
}

pub fn render_entity_schema_draft_2020_12(
    compiled: &CompiledMetadata,
    dataset_id: &str,
    entity_name: &str,
) -> Option<Value> {
    let dataset = compiled.dataset(dataset_id)?;
    let entity = dataset.entities.get(entity_name)?;
    Some(entity_json_schema(compiled, dataset, entity))
}

pub fn render_ogc_records_items(compiled: &CompiledMetadata) -> Value {
    let features = compiled
        .datasets()
        .map(record_feature_json)
        .collect::<Vec<_>>();
    json!({
        "type": "FeatureCollection",
        "numberMatched": features.len(),
        "numberReturned": features.len(),
        "features": features,
    })
}

pub fn render_ogc_records_item(compiled: &CompiledMetadata, record_id: &str) -> Option<Value> {
    compiled.dataset(record_id).map(record_feature_json)
}

pub fn render_ogc_records_collections() -> Value {
    json!({ "collections": [records_collection_json()] })
}

pub fn render_ogc_records_collection(collection_id: &str) -> Option<Value> {
    (collection_id == DATASETS_COLLECTION_ID).then(records_collection_json)
}

pub fn render_ogc_records_conformance() -> Value {
    json!({ "conformsTo": ogc_records_conformance() })
}

fn validate_entities(
    dataset: &DatasetManifest,
    path: &str,
    codelist_ids: &BTreeSet<&str>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let entity_names = dataset
        .entities
        .iter()
        .map(|entity| entity.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen_entity_names = BTreeSet::new();
    for (entity_index, entity) in dataset.entities.iter().enumerate() {
        let entity_path = format!("{path}.entities[{entity_index}]");
        validate_id(&entity.name, format!("{entity_path}.name"), errors);
        if !seen_entity_names.insert(entity.name.as_str()) {
            errors.push(ValidationError::new(
                format!("{entity_path}.name"),
                "entity name must be unique within a dataset",
            ));
        }
        validate_optional_uri(
            entity.concept_uri.as_deref(),
            format!("{entity_path}.concept_uri"),
            vocabularies,
            errors,
        );
        let mut field_names = BTreeSet::new();
        for (field_index, field) in entity.fields.iter().enumerate() {
            let field_path = format!("{entity_path}.fields[{field_index}]");
            validate_id(&field.name, format!("{field_path}.name"), errors);
            if !field_names.insert(field.name.as_str()) {
                errors.push(ValidationError::new(
                    format!("{field_path}.name"),
                    "field name must be unique within an entity",
                ));
            }
            validate_uri_list(
                &field.concepts,
                format!("{field_path}.concepts"),
                vocabularies,
                errors,
            );
            if let Some(codelist) = field.codelist.as_deref() {
                validate_id(codelist, format!("{field_path}.codelist"), errors);
                if !codelist_ids.contains(codelist) {
                    errors.push(ValidationError::new(
                        format!("{field_path}.codelist"),
                        "field codelist must reference a known codelist",
                    ));
                }
            }
        }
        for identifier in &entity.identifiers {
            if !field_names.contains(identifier.name.as_str()) {
                errors.push(ValidationError::new(
                    format!("{entity_path}.identifiers"),
                    "identifier must reference a field on the entity",
                ));
            }
        }
        for (relationship_index, relationship) in entity.relationships.iter().enumerate() {
            let relationship_path = format!("{entity_path}.relationships[{relationship_index}]");
            validate_id(
                &relationship.name,
                format!("{relationship_path}.name"),
                errors,
            );
            let Some(target) = relationship.target_name() else {
                errors.push(ValidationError::new(
                    format!("{relationship_path}.target_entity"),
                    "relationship target_entity is required",
                ));
                continue;
            };
            if !entity_names.contains(target) {
                errors.push(ValidationError::new(
                    format!("{relationship_path}.target_entity"),
                    "relationship target must name an entity in the same dataset",
                ));
            }
            validate_optional_uri(
                relationship.concept_uri.as_deref(),
                format!("{relationship_path}.concept_uri"),
                vocabularies,
                errors,
            );
            if let Some(cardinality) = relationship.cardinality.as_deref() {
                validate_cardinality(
                    cardinality,
                    format!("{relationship_path}.cardinality"),
                    errors,
                );
            }
        }
    }
}

fn compile_dataset(
    manifest: &MetadataManifest,
    base_url: &str,
    codelists: &BTreeMap<String, CompiledCodelist>,
    dataset: &DatasetManifest,
) -> CompiledDataset {
    let entities = dataset
        .entities
        .iter()
        .map(|entity| {
            (
                entity.name.clone(),
                compile_entity(manifest, base_url, codelists, &dataset.id, entity),
            )
        })
        .collect();
    CompiledDataset {
        dataset_id: dataset.id.clone(),
        title: dataset.title.text(),
        description: dataset
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        owner: dataset
            .owner
            .clone()
            .unwrap_or_else(|| manifest.catalog.publisher.name.clone()),
        sensitivity: dataset.sensitivity,
        access_rights: dataset.access_rights,
        update_frequency: dataset.update_frequency,
        conforms_to: dataset
            .conforms_to
            .iter()
            .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
            .collect(),
        spatial_coverage: dataset
            .spatial_coverage
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        adms_status: dataset.status.unwrap_or(AdmsStatus::UnderDevelopment),
        entities,
    }
}

fn compile_entity(
    manifest: &MetadataManifest,
    _base_url: &str,
    codelists: &BTreeMap<String, CompiledCodelist>,
    _dataset_id: &str,
    entity: &EntityManifest,
) -> CompiledEntity {
    let fields = entity
        .fields
        .iter()
        .map(|field| {
            let codelist_scheme_iri = field
                .codelist
                .as_deref()
                .and_then(|id| codelists.get(id))
                .map(|codelist| codelist.scheme_iri.clone());
            (
                field.name.clone(),
                CompiledField {
                    name: field.name.clone(),
                    field_type: field.field_type,
                    required: field.required,
                    constraints: field.constraints.clone(),
                    concepts: field
                        .concepts
                        .iter()
                        .filter_map(|iri| expand_uri(iri, &manifest.vocabularies))
                        .collect(),
                    codelist: field.codelist.clone(),
                    codelist_scheme_iri,
                    unit: field.unit.clone(),
                    language: field.language.clone(),
                },
            )
        })
        .collect();
    let relationships = entity
        .relationships
        .iter()
        .filter_map(|relationship| {
            Some(CompiledRelationship {
                name: relationship.name.clone(),
                target: relationship.target_name()?.to_string(),
                cardinality: relationship
                    .cardinality
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
                role: relationship.role.clone(),
                concept_uri: relationship
                    .concept_uri
                    .as_deref()
                    .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
            })
        })
        .collect();
    let primary_key = entity
        .identifiers
        .first()
        .map(|identifier| identifier.name.clone())
        .or_else(|| entity.fields.first().map(|field| field.name.clone()))
        .unwrap_or_else(|| "id".to_string());
    CompiledEntity {
        name: entity.name.clone(),
        title: entity
            .title
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_else(|| entity.name.clone()),
        description: entity
            .description
            .as_ref()
            .map(LocalizedText::text)
            .unwrap_or_default(),
        concept_uri: entity
            .concept_uri
            .as_deref()
            .and_then(|iri| expand_uri(iri, &manifest.vocabularies)),
        primary_key,
        identifiers: entity.identifiers.clone(),
        fields,
        relationships,
    }
}

fn catalog_dataset_json(dataset: &CompiledDataset) -> Value {
    json!({
        "dataset_id": dataset.dataset_id,
        "title": dataset.title,
        "description": dataset.description,
        "owner": dataset.owner,
        "sensitivity": sensitivity_name(dataset.sensitivity),
        "access_rights": access_rights_name(dataset.access_rights),
        "update_frequency": update_frequency_name(dataset.update_frequency),
        "conforms_to": dataset.conforms_to,
        "entities": dataset.entities.values().map(catalog_entity_json).collect::<Vec<_>>(),
    })
}

fn catalog_entity_json(entity: &CompiledEntity) -> Value {
    json!({
        "name": entity.name,
        "title": entity.title,
        "description": entity.description,
        "concept_uri": entity.concept_uri,
        "primary_key": entity.primary_key,
        "identifiers": entity.identifiers,
        "fields": entity.fields.values().map(catalog_field_json).collect::<Vec<_>>(),
        "relationships": entity.relationships,
    })
}

fn catalog_field_json(field: &CompiledField) -> Value {
    json!({
        "name": field.name,
        "type": field_type_name(field.field_type),
        "required": field.required,
        "concepts": field.concepts,
        "codelist": field.codelist,
        "codelist_scheme_iri": field.codelist_scheme_iri,
        "constraints": field.constraints,
        "unit": field.unit,
        "language": field.language,
    })
}

fn base_dcat_dataset(dataset: &CompiledDataset) -> Value {
    json!({
        "@id": dataset_url(dataset),
        "@type": "dcat:Dataset",
        "dcterms:identifier": dataset.dataset_id,
        "dcterms:title": dataset.title,
        "dcterms:description": dataset.description,
        "dcterms:conformsTo": dataset.conforms_to,
    })
}

fn breg_dcat_dataset(dataset: &CompiledDataset) -> Value {
    let mut obj = base_dcat_dataset(dataset);
    obj["dcterms:rightsHolder"] = json!(dataset.owner);
    obj["dcterms:accessRights"] = json!(access_rights_uri(dataset.access_rights));
    obj["dcterms:accrualPeriodicity"] = json!(frequency_uri(dataset.update_frequency));
    obj["adms:status"] = json!(adms_status_uri(dataset.adms_status));
    if let Some(spatial) = dataset.spatial_coverage.as_deref() {
        obj["dcterms:spatial"] = json!(spatial);
    }
    obj
}

fn publisher_agent(catalog: &CompiledCatalog) -> Value {
    let mut agent = json!({
        "@type": "foaf:Agent",
        "foaf:name": catalog.publisher,
    });
    if let Some(iri) = catalog.publisher_iri.as_deref() {
        agent["@id"] = json!(iri);
    }
    if let Some(authority_type) = catalog.authority_type.as_deref() {
        agent["dcterms:type"] = json!(authority_type);
    }
    agent
}

fn entity_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> Value {
    let properties = entity
        .fields
        .values()
        .map(|field| field_shape(compiled, dataset, entity, field))
        .chain(
            entity
                .relationships
                .iter()
                .map(|rel| relationship_shape(compiled, dataset, entity, rel)),
        )
        .collect::<Vec<_>>();
    json!({
        "@id": entity_schema_id(compiled, dataset, entity),
        "@type": "sh:NodeShape",
        "sh:targetClass": entity_class_uri(compiled, dataset, entity),
        "dcterms:isPartOf": dataset_url(dataset),
        "dcterms:identifier": format!("{}:{}", dataset.dataset_id, entity.name),
        "sh:name": entity.name,
        "sh:nodeKind": "sh:IRI",
        "registry_relay:primaryKey": entity.primary_key,
        "sh:property": properties,
    })
}

fn field_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    field: &CompiledField,
) -> Value {
    let mut shape = json!({
        "@type": "sh:PropertyShape",
        "sh:path": field_property_uri(compiled, dataset, entity, field),
        "sh:name": field.name,
        "sh:nodeKind": "sh:Literal",
        "sh:datatype": shacl_datatype(field.field_type),
        "sh:minCount": if field.required { 1 } else { 0 },
        "sh:maxCount": 1,
    });
    if let Some(pattern) = field.constraints.pattern.as_deref() {
        shape["sh:pattern"] = json!(pattern);
    }
    if let Some(min_length) = field.constraints.min_length {
        shape["sh:minLength"] = json!(min_length);
    }
    if let Some(max_length) = field.constraints.max_length {
        shape["sh:maxLength"] = json!(max_length);
    }
    if !field.constraints.values.is_empty() {
        shape["sh:in"] = json!(field.constraints.values);
    }
    if let Some(scheme) = field.codelist_scheme_iri.as_deref() {
        shape["skos:inScheme"] = json!(scheme);
    }
    shape
}

fn relationship_shape(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    relationship: &CompiledRelationship,
) -> Value {
    let target_class = dataset
        .entities
        .get(&relationship.target)
        .map(|target| entity_class_uri(compiled, dataset, target))
        .unwrap_or_else(|| {
            format!(
                "{}/datasets/{}/{}/schema",
                compiled.catalog().base_url,
                dataset.dataset_id,
                relationship.target
            )
        });
    let mut shape = json!({
        "@type": "sh:PropertyShape",
        "sh:path": relationship.concept_uri.clone().unwrap_or_else(|| {
            format!(
                "{}/datasets/{}/{}/relationships/{}",
                compiled.catalog().base_url,
                dataset.dataset_id,
                entity.name,
                relationship.name
            )
        }),
        "sh:name": relationship.name,
        "sh:nodeKind": "sh:IRI",
        "registry_relay:relationshipKind": relationship.cardinality,
        "registry_relay:targetEntity": relationship.target,
        "sh:class": target_class,
    });
    if relationship.cardinality == "zero_or_one" || relationship.cardinality == "one" {
        shape["sh:maxCount"] = json!(1);
    }
    if relationship.cardinality == "one" {
        shape["sh:minCount"] = json!(1);
    }
    shape
}

fn codelist_shape(codelist: &CompiledCodelist) -> Value {
    let mut scheme = json!({
        "@id": codelist.scheme_iri,
        "@type": "skos:ConceptScheme",
        "dcterms:identifier": codelist.id,
        "skos:hasTopConcept": codelist.concepts.iter().map(|concept| {
            json!({
                "@id": concept
                    .iri
                    .clone()
                    .unwrap_or_else(|| format!("{}/{}", codelist.scheme_iri.trim_end_matches('/'), concept.code)),
                "@type": "skos:Concept",
                "skos:notation": concept.code,
                "skos:prefLabel": concept.label.as_ref().map(LocalizedText::text),
                "skos:inScheme": codelist.scheme_iri,
            })
        }).collect::<Vec<_>>(),
    });
    if let Some(external_ref) = codelist.external_ref.as_deref() {
        scheme["rdfs:seeAlso"] = json!(external_ref);
    }
    scheme
}

fn entity_json_schema(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> Value {
    let properties = entity
        .fields
        .values()
        .map(|field| {
            let mut schema = json_schema_for_field(field);
            if let Some(concept) = field.concepts.first() {
                schema["x-concept-uri"] = json!(concept);
            }
            if let Some(codelist) = field.codelist_scheme_iri.as_deref() {
                schema["x-codelist"] = json!(codelist);
            }
            (field.name.clone(), schema)
        })
        .collect::<serde_json::Map<_, _>>();
    let required = entity
        .fields
        .values()
        .filter(|field| field.required)
        .map(|field| field.name.clone())
        .collect::<Vec<_>>();
    json!({
        "$schema": JSON_SCHEMA_DRAFT_2020_12,
        "$id": entity_schema_id(compiled, dataset, entity),
        "title": entity.title,
        "description": entity.description,
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn json_schema_for_field(field: &CompiledField) -> Value {
    let mut schema = match field.field_type {
        FieldType::String | FieldType::Code => json!({ "type": "string" }),
        FieldType::Number => json!({ "type": "number" }),
        FieldType::Integer => json!({ "type": "integer" }),
        FieldType::Boolean => json!({ "type": "boolean" }),
        FieldType::Date => json!({ "type": "string", "format": "date" }),
        FieldType::Timestamp => json!({ "type": "string", "format": "date-time" }),
    };
    if let Some(min_length) = field.constraints.min_length {
        schema["minLength"] = json!(min_length);
    }
    if let Some(max_length) = field.constraints.max_length {
        schema["maxLength"] = json!(max_length);
    }
    if let Some(pattern) = field.constraints.pattern.as_deref() {
        schema["pattern"] = json!(pattern);
    }
    if !field.constraints.values.is_empty() {
        schema["enum"] = json!(field.constraints.values);
    }
    schema
}

fn record_feature_json(dataset: &CompiledDataset) -> Value {
    json!({
        "id": dataset.dataset_id,
        "type": "Feature",
        "geometry": Value::Null,
        "properties": {
            "type": "Record",
            "resourceType": "dcat:Dataset",
            "title": dataset.title,
            "description": dataset.description,
            "identifier": dataset.dataset_id,
            "owner": dataset.owner,
            "accessRights": access_rights_name(dataset.access_rights),
            "updateFrequency": update_frequency_name(dataset.update_frequency),
            "conformsTo": dataset.conforms_to,
            "entities": dataset.entities.values().map(entity_record_summary).collect::<Vec<_>>(),
        },
    })
}

fn entity_record_summary(entity: &CompiledEntity) -> Value {
    json!({
        "name": entity.name,
        "title": entity.title,
        "description": entity.description,
        "conceptUri": entity.concept_uri,
    })
}

fn records_collection_json() -> Value {
    json!({
        "id": DATASETS_COLLECTION_ID,
        "title": "Dataset catalog records",
        "description": "Records describing Registry Relay datasets visible to the caller.",
        "itemType": "record",
    })
}

fn validate_non_empty(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if value.trim().is_empty() {
        errors.push(ValidationError::new(path, "value must not be empty"));
    }
}

fn validate_id(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    let valid = value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' => true,
        b'0'..=b'9' | b'_' | b'-' => index > 0,
        _ => false,
    });
    if value.is_empty() || !valid {
        errors.push(ValidationError::new(
            path,
            "id must use lower-case letters, digits, hyphen, or underscore and start with a letter",
        ));
    }
}

fn validate_cardinality(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !matches!(value, "one" | "zero_or_one" | "many" | "zero_or_more") {
        errors.push(ValidationError::new(
            path,
            "cardinality must be one, zero_or_one, many, or zero_or_more",
        ));
    }
}

fn is_supported_application_profile(id: &str) -> bool {
    matches!(id, "bregdcat-ap" | "dcat-ap")
}

fn validate_http_url(value: &str, path: impl Into<String>, errors: &mut Vec<ValidationError>) {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        errors.push(ValidationError::new(
            path,
            "URL must start with http:// or https://",
        ));
    }
}

fn validate_uri(
    value: &str,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    validate_optional_uri(Some(value), path, vocabularies, errors);
}

fn validate_uri_list(
    values: &[String],
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let path = path.into();
    for (index, value) in values.iter().enumerate() {
        validate_uri(value, format!("{path}[{index}]"), vocabularies, errors);
    }
}

fn validate_optional_uri(
    value: Option<&str>,
    path: impl Into<String>,
    vocabularies: &BTreeMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(value) = value else {
        return;
    };
    if expand_uri(value, vocabularies).is_none() {
        errors.push(ValidationError::new(
            path,
            "URI must be absolute or use a configured vocabulary prefix",
        ));
    }
}

fn expand_uri(uri: &str, vocabularies: &BTreeMap<String, String>) -> Option<String> {
    if uri.starts_with("http://") || uri.starts_with("https://") || uri.starts_with("urn:") {
        return Some(uri.to_string());
    }
    let (prefix, suffix) = uri.split_once(':')?;
    let base = vocabularies.get(prefix)?;
    Some(format!("{base}{suffix}"))
}

fn normalized_base_url(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn dataset_url(dataset: &CompiledDataset) -> String {
    format!("#dataset-{}", dataset.dataset_id)
}

fn entity_schema_id(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> String {
    format!(
        "{}/metadata/schema/{}/{}/schema.json",
        compiled.catalog().base_url,
        dataset.dataset_id,
        entity.name
    )
}

fn field_property_uri(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
    field: &CompiledField,
) -> String {
    field.concepts.first().cloned().unwrap_or_else(|| {
        format!(
            "{}/datasets/{}/{}/fields/{}",
            compiled.catalog().base_url,
            dataset.dataset_id,
            entity.name,
            field.name
        )
    })
}

fn entity_class_uri(
    compiled: &CompiledMetadata,
    dataset: &CompiledDataset,
    entity: &CompiledEntity,
) -> String {
    entity.concept_uri.clone().unwrap_or_else(|| {
        format!(
            "{}/datasets/{}/{}/schema",
            compiled.catalog().base_url,
            dataset.dataset_id,
            entity.name
        )
    })
}

fn shacl_datatype(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String | FieldType::Code => "xsd:string",
        FieldType::Number => "xsd:decimal",
        FieldType::Integer => "xsd:integer",
        FieldType::Boolean => "xsd:boolean",
        FieldType::Date => "xsd:date",
        FieldType::Timestamp => "xsd:dateTime",
    }
}

fn adms_status_uri(status: AdmsStatus) -> &'static str {
    match status {
        AdmsStatus::UnderDevelopment => "http://purl.org/adms/status/UnderDevelopment",
        AdmsStatus::Active => "http://purl.org/adms/status/Active",
        AdmsStatus::Completed => "http://purl.org/adms/status/Completed",
        AdmsStatus::Deprecated => "http://purl.org/adms/status/Deprecated",
        AdmsStatus::Withdrawn => "http://purl.org/adms/status/Withdrawn",
    }
}

fn access_rights_uri(access_rights: AccessRights) -> &'static str {
    match access_rights {
        AccessRights::Public => {
            "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
        }
        AccessRights::Restricted => {
            "http://publications.europa.eu/resource/authority/access-right/RESTRICTED"
        }
        AccessRights::NonPublic => {
            "http://publications.europa.eu/resource/authority/access-right/NON_PUBLIC"
        }
    }
}

fn frequency_uri(frequency: UpdateFrequency) -> &'static str {
    match frequency {
        UpdateFrequency::Continuous => {
            "http://publications.europa.eu/resource/authority/frequency/CONT"
        }
        UpdateFrequency::Daily => {
            "http://publications.europa.eu/resource/authority/frequency/DAILY"
        }
        UpdateFrequency::Weekly => {
            "http://publications.europa.eu/resource/authority/frequency/WEEKLY"
        }
        UpdateFrequency::Monthly => {
            "http://publications.europa.eu/resource/authority/frequency/MONTHLY"
        }
        UpdateFrequency::Quarterly => {
            "http://publications.europa.eu/resource/authority/frequency/QUARTERLY"
        }
        UpdateFrequency::Annual => {
            "http://publications.europa.eu/resource/authority/frequency/ANNUAL"
        }
        UpdateFrequency::Irregular => {
            "http://publications.europa.eu/resource/authority/frequency/IRREG"
        }
        UpdateFrequency::Termly | UpdateFrequency::AsNeeded | UpdateFrequency::Unknown => {
            "http://publications.europa.eu/resource/authority/frequency/UNKNOWN"
        }
    }
}

fn sensitivity_name(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Public => "public",
        Sensitivity::Internal => "internal",
        Sensitivity::Personal => "personal",
        Sensitivity::Confidential => "confidential",
        Sensitivity::Secret => "secret",
    }
}

fn access_rights_name(access_rights: AccessRights) -> &'static str {
    match access_rights {
        AccessRights::Public => "public",
        AccessRights::Restricted => "restricted",
        AccessRights::NonPublic => "non_public",
    }
}

fn update_frequency_name(update_frequency: UpdateFrequency) -> &'static str {
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

fn field_type_name(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::String => "string",
        FieldType::Number => "number",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::Date => "date",
        FieldType::Timestamp => "timestamp",
        FieldType::Code => "code",
    }
}

fn ogc_records_conformance() -> Value {
    json!([
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-collection",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-api",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/json",
        "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/oas30",
    ])
}

fn jsonld_context() -> Value {
    json!({
        "adms": "http://www.w3.org/ns/adms#",
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "dspace": "https://w3id.org/dspace/2025/1/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "sh": "http://www.w3.org/ns/shacl#",
        "skos": "http://www.w3.org/2004/02/skos/core#",
        "registry_relay": "https://registry-relay.dev/ns#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "adms:status": { "@type": "@id" },
        "dcat:accessURL": { "@type": "@id" },
        "dcat:landingPage": { "@type": "@id" },
        "dcterms:accessRights": { "@type": "@id" },
        "dcterms:accrualPeriodicity": { "@type": "@id" },
        "dcterms:conformsTo": { "@type": "@id" },
        "dcterms:isPartOf": { "@type": "@id" },
        "dcterms:spatial": { "@type": "@id" },
        "dcterms:type": { "@type": "@id" },
        "sh:class": { "@type": "@id" },
        "sh:datatype": { "@type": "@id" },
        "sh:nodeKind": { "@type": "@id" },
        "sh:path": { "@type": "@id" },
        "sh:targetClass": { "@type": "@id" },
        "skos:hasTopConcept": { "@type": "@id" },
        "skos:inScheme": { "@type": "@id" },
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "rdfs:seeAlso": { "@type": "@id" },
    })
}
