// SPDX-License-Identifier: Apache-2.0
//! Adapter from Relay runtime config to the portable metadata manifest.
//!
//! Runtime bindings remain in `Config` and `EntityRegistry`; this module
//! projects only the standard-facing metadata into `registry-manifest-core`.

use std::collections::{BTreeMap, BTreeSet};

use registry_manifest_core as core;

use crate::config::{
    self, Config, DatasetConfig, EntityConfig, EntityFieldConfig, FieldConfig, RelationshipKind,
};
use crate::entity::{EntityModel, EntityRegistry};

pub fn manifest_from_runtime(config: &Config, registry: &EntityRegistry) -> core::MetadataManifest {
    let mut codelist_ids = CodelistIds::default();
    let datasets = config
        .datasets
        .iter()
        .filter_map(|dataset| dataset_manifest(config, registry, dataset, None, &mut codelist_ids))
        .collect::<Vec<_>>();

    core::MetadataManifest {
        schema_version: "registry-manifest/v1".to_string(),
        catalog: catalog_manifest(config),
        vocabularies: config.vocabularies.clone(),
        profiles: Vec::new(),
        federation: None,
        evaluation_profiles: Vec::new(),
        requirements: Vec::new(),
        evidence_types: Vec::new(),
        authorities: Vec::new(),
        public_services: Vec::new(),
        data_services: Vec::new(),
        forms: Vec::new(),
        datasets,
        codelists: codelist_ids.into_manifests(),
    }
}

pub fn compiled_from_runtime(
    config: &Config,
    registry: &EntityRegistry,
) -> Result<core::CompiledMetadata, core::MetadataError> {
    core::compile_manifest(&manifest_from_runtime(config, registry))
}

pub fn scoped_compiled_from_runtime(
    config: &Config,
    registry: &EntityRegistry,
    visible_entity_ids: &BTreeSet<(String, String)>,
) -> Result<core::CompiledMetadata, core::MetadataError> {
    let mut codelist_ids = CodelistIds::default();
    let datasets = config
        .datasets
        .iter()
        .filter_map(|dataset| {
            dataset_manifest(
                config,
                registry,
                dataset,
                Some(visible_entity_ids),
                &mut codelist_ids,
            )
        })
        .collect::<Vec<_>>();

    core::compile_manifest(&core::MetadataManifest {
        schema_version: "registry-manifest/v1".to_string(),
        catalog: catalog_manifest(config),
        vocabularies: config.vocabularies.clone(),
        profiles: Vec::new(),
        federation: None,
        evaluation_profiles: Vec::new(),
        requirements: Vec::new(),
        evidence_types: Vec::new(),
        authorities: Vec::new(),
        public_services: Vec::new(),
        data_services: Vec::new(),
        forms: Vec::new(),
        datasets,
        codelists: codelist_ids.into_manifests(),
    })
}

fn catalog_manifest(config: &Config) -> core::CatalogManifest {
    core::CatalogManifest {
        id: "registry-relay".to_string(),
        base_url: config.catalog.base_url.clone(),
        title: core::LocalizedText::Plain(config.catalog.title.clone()),
        description: None,
        publisher: core::PublisherManifest {
            name: config.catalog.publisher.clone(),
            iri: config.catalog.publisher_iri.clone(),
            authority_type: config.catalog.authority_type.clone(),
        },
        participant_id: config.catalog.participant_id.clone(),
        conforms_to: Vec::new(),
        standards: core::StandardsManifest {
            dcat: Some("3.0".to_string()),
            shacl: Some("1.1".to_string()),
            json_schema: Some("2020-12".to_string()),
        },
        application_profiles: vec![core::ApplicationProfile {
            id: "bregdcat-ap".to_string(),
            version: "3.0".to_string(),
        }],
    }
}

fn dataset_manifest(
    config: &Config,
    registry: &EntityRegistry,
    dataset: &DatasetConfig,
    visible_entity_ids: Option<&BTreeSet<(String, String)>>,
    codelist_ids: &mut CodelistIds,
) -> Option<core::DatasetManifest> {
    let compiled = registry.dataset(dataset.id.as_str())?;
    let entity_configs = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.as_str(), entity))
        .collect::<BTreeMap<_, _>>();
    let table_fields = table_field_index(dataset);
    let visible_entity_names = visible_entity_ids.map(|ids| {
        ids.iter()
            .filter(|(dataset_id, _)| dataset_id == dataset.id.as_str())
            .map(|(_, entity)| entity.as_str())
            .collect::<BTreeSet<_>>()
    });
    let entities = compiled
        .entities()
        .filter_map(|entity| {
            let entity_config = entity_configs.get(entity.name.as_str()).copied()?;
            if visible_entity_ids
                .is_some_and(|ids| !ids.contains(&(dataset.id.to_string(), entity.name.clone())))
            {
                return None;
            }
            entity_manifest(
                config,
                dataset,
                entity_config,
                entity,
                &table_fields,
                codelist_ids,
                visible_entity_names.as_ref(),
            )
        })
        .collect::<Vec<_>>();

    if entities.is_empty() {
        return None;
    }

    Some(core::DatasetManifest {
        id: dataset.id.to_string(),
        title: core::LocalizedText::Plain(dataset.title.clone()),
        description: Some(core::LocalizedText::Plain(dataset.description.clone())),
        owner: Some(dataset.owner.clone()),
        sensitivity: sensitivity(dataset.sensitivity),
        access_rights: access_rights(dataset.access_rights),
        update_frequency: update_frequency(dataset.update_frequency),
        conforms_to: dataset.conforms_to.clone(),
        applicable_legislation: dataset.applicable_legislation.clone(),
        spatial_coverage: dataset
            .spatial_coverage
            .clone()
            .or_else(|| config.catalog.default_spatial_coverage.clone()),
        status: Some(adms_status(
            dataset
                .status
                .unwrap_or(config::AdmsStatus::UnderDevelopment),
        )),
        public_services: dataset
            .public_services
            .iter()
            .map(|service| core::PublicServiceManifest {
                id: service.id.clone(),
                title: core::LocalizedText::Plain(service.title.clone()),
                description: service
                    .description
                    .as_ref()
                    .map(|description| core::LocalizedText::Plain(description.clone())),
            })
            .collect(),
        policy: None,
        evidence_offerings: Vec::new(),
        entities,
    })
}

fn entity_manifest(
    _config: &Config,
    _dataset: &DatasetConfig,
    entity_config: &EntityConfig,
    entity: &EntityModel,
    table_fields: &BTreeMap<(String, String), &FieldConfig>,
    codelist_ids: &mut CodelistIds,
    visible_entity_names: Option<&BTreeSet<&str>>,
) -> Option<core::EntityManifest> {
    let fields = entity
        .fields
        .iter()
        .filter_map(|field| {
            let table_field =
                table_fields.get(&(entity.table_id.clone(), field.table_column.clone()))?;
            let override_field = entity_field_override(entity_config, &field.name);
            Some(field_manifest(
                field.name.clone(),
                table_field,
                override_field,
                codelist_ids,
            ))
        })
        .collect::<Vec<_>>();
    if fields.is_empty() {
        return None;
    }

    let identifiers = vec![core::IdentifierManifest {
        name: entity.primary_key.name.clone(),
        kind: "primary".to_string(),
    }];
    let relationships = entity
        .relationships
        .values()
        .filter(|relationship| match visible_entity_names {
            Some(names) => names.contains(relationship.target.as_str()),
            None => true,
        })
        .map(|relationship| core::RelationshipManifest {
            name: relationship.name.clone(),
            target_entity: Some(relationship.target.clone()),
            target: None,
            cardinality: Some(cardinality(relationship.kind).to_string()),
            role: Some(relationship.name.clone()),
            concept_uri: relationship.concept_uri.clone(),
        })
        .collect();

    Some(core::EntityManifest {
        name: entity.name.clone(),
        title: entity_config.title.clone().map(core::LocalizedText::Plain),
        description: entity_config
            .description
            .clone()
            .map(core::LocalizedText::Plain),
        concept_uri: entity_config.concept_uri.clone(),
        identifiers,
        fields,
        relationships,
    })
}

fn field_manifest(
    name: String,
    table_field: &FieldConfig,
    override_field: Option<&EntityFieldConfig>,
    codelist_ids: &mut CodelistIds,
) -> core::FieldManifest {
    let concept_uri = override_field
        .and_then(|field| field.concept_uri.clone())
        .or_else(|| table_field.concept_uri.clone());
    let codelist = override_field
        .and_then(|field| field.codelist.clone())
        .or_else(|| table_field.codelist.clone());
    let codelist_id = codelist
        .as_deref()
        .map(|scheme_iri| codelist_ids.id_for_scheme(scheme_iri));

    core::FieldManifest {
        name,
        field_type: field_type(table_field.r#type, codelist_id.is_some()),
        required: !table_field.nullable,
        constraints: core::FieldConstraints::default(),
        concepts: concept_uri.into_iter().collect(),
        codelist: codelist_id,
        unit: override_field
            .and_then(|field| field.unit.clone())
            .or_else(|| table_field.unit.clone()),
        language: override_field
            .and_then(|field| field.language.clone())
            .or_else(|| table_field.language.clone()),
    }
}

fn entity_field_override<'a>(
    entity_config: &'a EntityConfig,
    field_name: &str,
) -> Option<&'a EntityFieldConfig> {
    entity_config
        .fields
        .iter()
        .find(|field| field.name == field_name)
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

fn sensitivity(value: config::Sensitivity) -> core::Sensitivity {
    match value {
        config::Sensitivity::Public => core::Sensitivity::Public,
        config::Sensitivity::Internal => core::Sensitivity::Internal,
        config::Sensitivity::Personal => core::Sensitivity::Personal,
        config::Sensitivity::Confidential => core::Sensitivity::Confidential,
        config::Sensitivity::Secret => core::Sensitivity::Secret,
    }
}

fn access_rights(value: config::AccessRights) -> core::AccessRights {
    match value {
        config::AccessRights::Public => core::AccessRights::Public,
        config::AccessRights::Restricted => core::AccessRights::Restricted,
        config::AccessRights::NonPublic => core::AccessRights::NonPublic,
    }
}

fn update_frequency(value: config::UpdateFrequency) -> core::UpdateFrequency {
    match value {
        config::UpdateFrequency::Continuous => core::UpdateFrequency::Continuous,
        config::UpdateFrequency::Daily => core::UpdateFrequency::Daily,
        config::UpdateFrequency::Weekly => core::UpdateFrequency::Weekly,
        config::UpdateFrequency::Termly => core::UpdateFrequency::Termly,
        config::UpdateFrequency::Monthly => core::UpdateFrequency::Monthly,
        config::UpdateFrequency::Quarterly => core::UpdateFrequency::Quarterly,
        config::UpdateFrequency::Annual => core::UpdateFrequency::Annual,
        config::UpdateFrequency::Irregular => core::UpdateFrequency::Irregular,
        config::UpdateFrequency::AsNeeded => core::UpdateFrequency::AsNeeded,
        config::UpdateFrequency::Unknown => core::UpdateFrequency::Unknown,
    }
}

fn adms_status(value: config::AdmsStatus) -> core::AdmsStatus {
    match value {
        config::AdmsStatus::UnderDevelopment => core::AdmsStatus::UnderDevelopment,
        config::AdmsStatus::Completed => core::AdmsStatus::Completed,
        config::AdmsStatus::Deprecated => core::AdmsStatus::Deprecated,
        config::AdmsStatus::Withdrawn => core::AdmsStatus::Withdrawn,
    }
}

fn field_type(value: config::FieldType, has_codelist: bool) -> core::FieldType {
    if has_codelist && value == config::FieldType::String {
        return core::FieldType::Code;
    }
    match value {
        config::FieldType::String => core::FieldType::String,
        config::FieldType::Number => core::FieldType::Number,
        config::FieldType::Integer => core::FieldType::Integer,
        config::FieldType::Boolean => core::FieldType::Boolean,
        config::FieldType::Date => core::FieldType::Date,
        config::FieldType::Timestamp => core::FieldType::Timestamp,
    }
}

fn cardinality(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::BelongsTo | RelationshipKind::HasOne => "zero_or_one",
        RelationshipKind::HasMany => "many",
    }
}

#[derive(Default)]
struct CodelistIds {
    by_scheme: BTreeMap<String, String>,
    used_ids: BTreeSet<String>,
}

impl CodelistIds {
    fn id_for_scheme(&mut self, scheme_iri: &str) -> String {
        if let Some(id) = self.by_scheme.get(scheme_iri) {
            return id.clone();
        }
        let base = sanitize_id(scheme_iri).unwrap_or_else(|| "codelist".to_string());
        let mut candidate = base.clone();
        let mut suffix = 2;
        while !self.used_ids.insert(candidate.clone()) {
            candidate = format!("{base}_{suffix}");
            suffix += 1;
        }
        self.by_scheme
            .insert(scheme_iri.to_string(), candidate.clone());
        candidate
    }

    fn into_manifests(self) -> Vec<core::CodelistManifest> {
        self.by_scheme
            .into_iter()
            .map(|(scheme_iri, id)| core::CodelistManifest {
                id,
                scheme_iri,
                external_ref: None,
                concepts: Vec::new(),
            })
            .collect()
    }
}

fn sanitize_id(value: &str) -> Option<String> {
    let tail = value
        .rsplit(['/', '#', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(value);
    let mut out = String::new();
    for ch in tail.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if (ch == '-' || ch == '_') && !out.is_empty() {
            out.push(ch);
        }
    }
    while out.ends_with(['-', '_']) {
        out.pop();
    }
    if out
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase())
    {
        Some(out)
    } else if out.is_empty() {
        None
    } else {
        Some(format!("c{out}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::entity::EntityRegistry;

    #[test]
    fn adapter_projects_runtime_metadata_without_table_bindings() {
        let config: Config = serde_saphyr::from_str(
            r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Program Data Catalog
  base_url: https://data.example.test/
  publisher: Ministry of Delivery
  participant_id: did:web:data.example.test
vocabularies:
  ex: https://example.test/vocab/
auth:
  mode: api_key
  api_keys: []
datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Social Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    conforms_to: [ex:profiles/social]
    defaults:
      refresh:
        mode: manual
    tables:
      - id: households_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
            - name: region_code
              type: string
              nullable: true
              concept_uri: ex:properties/regionCode
              codelist: ex:codelists/Region
    entities:
      - name: household
        title: Household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
            concept_uri: ex:properties/region
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
audit:
  sink: stdout
  format: jsonl
"#,
        )
        .expect("parse config");
        config::validate::run(&config).expect("config validates");
        let registry = EntityRegistry::from_config(&config).expect("registry compiles");

        let compiled = compiled_from_runtime(&config, &registry).expect("metadata compiles");
        let catalog = core::render_catalog(&compiled);
        let json = serde_json::to_string(&catalog).expect("catalog serializes");

        assert!(json.contains("\"household\""));
        assert!(json.contains("https://example.test/vocab/properties/region"));
        assert!(json.contains("https://example.test/vocab/codelists/Region"));
        assert!(!json.contains("households_table"));
        assert!(!json.contains("region_code"));
    }
}
