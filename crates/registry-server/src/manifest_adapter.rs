// SPDX-License-Identifier: Apache-2.0
//! One-way lossy Registry Manifest projection.

use std::collections::{BTreeMap, BTreeSet};

use registry_manifest_core::{
    compile_manifest, render_base_dcat, AccessRights, AdmsStatus, ApplicationProfile,
    CatalogManifest, CodelistConcept, CodelistManifest, DataServiceManifest, DatasetManifest,
    FieldConstraints, FieldManifest, FieldType, IdentifierManifest, LocalizedText, MetadataError,
    MetadataManifest, PublisherManifest, RelationshipManifest, Sensitivity, StandardsManifest,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

use crate::artifacts::decimal_pattern;
use crate::contract::{
    Classification, FieldTypeSource, ManifestProjectionDatasetStatus,
    ManifestProjectionEntitySource, ManifestProjectionFieldSource, ManifestProjectionSource,
    ManifestProjectionTextSource, ManifestProjectionVocabularySource, Operation,
};
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledEntity, CompiledField};

pub(crate) struct ProjectedManifestArtifacts {
    pub manifest: Vec<u8>,
    pub dcat: Vec<u8>,
}

pub(crate) fn project_manifest_artifacts(
    registry_id: &str,
    projection: &ManifestProjectionSource,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<ProjectedManifestArtifacts, Diagnostic> {
    let manifest = project_manifest(registry_id, projection, entities);
    let mut value =
        serde_json::to_value(&manifest).map_err(|_| manifest_canonicalization_diagnostic())?;
    strip_null_members(&mut value);
    let manifest: MetadataManifest = serde_json::from_value(value.clone())
        .map_err(|_| manifest_canonicalization_diagnostic())?;
    let compiled = compile_manifest(&manifest).map_err(manifest_diagnostic)?;
    let manifest = canonicalize_json(&value).map_err(|_| manifest_canonicalization_diagnostic())?;
    let dcat = canonicalize_json(&render_base_dcat(&compiled))
        .map_err(|_| manifest_canonicalization_diagnostic())?;
    Ok(ProjectedManifestArtifacts { manifest, dcat })
}

fn project_manifest(
    registry_id: &str,
    projection: &ManifestProjectionSource,
    entities: &BTreeMap<String, CompiledEntity>,
) -> MetadataManifest {
    let visible_entities = visible_entities(projection, entities);
    let dataset_id = projection
        .dataset
        .id
        .as_deref()
        .unwrap_or(registry_id)
        .to_owned();
    let access_rights = if selected_profile_is_anonymous(projection, &visible_entities) {
        AccessRights::Public
    } else {
        AccessRights::Restricted
    };

    MetadataManifest {
        schema_version: "registry-manifest/v1".to_owned(),
        catalog: CatalogManifest {
            id: registry_id.to_owned(),
            base_url: projection.catalog.base_url.clone(),
            title: localized_text(&projection.catalog.title),
            description: projection.catalog.description.as_ref().map(localized_text),
            publisher: PublisherManifest {
                name: projection.catalog.publisher.name.clone(),
                iri: projection.catalog.publisher.iri.clone(),
                authority_type: projection.catalog.publisher.authority_type.clone(),
            },
            participant_id: projection.catalog.participant_id.clone(),
            conforms_to: projection.catalog.conforms_to.clone(),
            standards: StandardsManifest {
                dcat: projection.catalog.standards.dcat.clone(),
                shacl: projection.catalog.standards.shacl.clone(),
                json_schema: projection.catalog.standards.json_schema.clone(),
            },
            application_profiles: projection
                .catalog
                .application_profiles
                .iter()
                .map(|profile| ApplicationProfile {
                    id: profile.id.clone(),
                    version: profile.version.clone(),
                })
                .collect(),
        },
        vocabularies: BTreeMap::new(),
        profiles: Vec::new(),
        evaluation_profiles: Vec::new(),
        ecosystem_bindings: Vec::new(),
        requirements: Vec::new(),
        evidence_types: Vec::new(),
        authorities: Vec::new(),
        public_services: Vec::new(),
        data_services: projection
            .data_service
            .iter()
            .map(|service| DataServiceManifest {
                id: service.id.clone(),
                iri: service.iri.clone(),
                title: localized_text(&service.title),
                description: service.description.as_ref().map(localized_text),
                endpoint_url: Some(service.endpoint_url.clone()),
                endpoint_description: service.endpoint_description.clone(),
                serves_datasets: vec![dataset_id.clone()],
                conforms_to: service.conforms_to.clone(),
            })
            .collect(),
        distributions: Vec::new(),
        forms: Vec::new(),
        datasets: vec![DatasetManifest {
            id: dataset_id,
            iri: None,
            version: None,
            title: localized_text(&projection.dataset.title),
            description: projection.dataset.description.as_ref().map(localized_text),
            owner: projection.dataset.owner.clone(),
            sensitivity: sensitivity(projection.classification_ceiling),
            access_rights,
            update_frequency: Default::default(),
            conforms_to: projection.dataset.conforms_to.clone(),
            applicable_legislation: projection.dataset.applicable_legislation.clone(),
            spatial_coverage: projection.dataset.spatial_coverage.clone(),
            status: projection.dataset.status.map(adms_status),
            public_services: Vec::new(),
            policy: None,
            evidence_offerings: Vec::new(),
            entities: visible_entities
                .iter()
                .map(|entity| project_entity(projection, entity, &visible_entities))
                .collect(),
        }],
        codelists: project_codelists(projection, &visible_entities),
    }
}

fn localized_text(source: &ManifestProjectionTextSource) -> LocalizedText {
    match source {
        ManifestProjectionTextSource::Plain(value) => LocalizedText::Plain(value.clone()),
        ManifestProjectionTextSource::Localized(values) => LocalizedText::Localized(values.clone()),
    }
}

fn visible_entities<'a>(
    projection: &ManifestProjectionSource,
    entities: &'a BTreeMap<String, CompiledEntity>,
) -> Vec<&'a CompiledEntity> {
    entities
        .values()
        .filter(|entity| entity.classification <= projection.classification_ceiling)
        .filter(|entity| {
            entity
                .access_profiles
                .get(&projection.access_profile)
                .is_some_and(|profile| {
                    profile.operations.contains(&Operation::Get)
                        || profile.operations.contains(&Operation::List)
                })
        })
        .collect()
}

fn selected_profile_is_anonymous(
    projection: &ManifestProjectionSource,
    visible_entities: &[&CompiledEntity],
) -> bool {
    visible_entities.iter().all(|entity| {
        entity
            .access_profiles
            .get(&projection.access_profile)
            .is_some_and(|profile| profile.anonymous)
    })
}

fn project_entity(
    projection: &ManifestProjectionSource,
    entity: &CompiledEntity,
    visible_entities: &[&CompiledEntity],
) -> registry_manifest_core::EntityManifest {
    let metadata = projection
        .entities
        .iter()
        .find(|metadata| metadata.id == entity.id);
    let visible_entity_ids = visible_entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    let readable_fields = entity
        .access_profiles
        .get(&projection.access_profile)
        .map(|profile| profile.readable_fields.clone())
        .unwrap_or_default();

    let fields = entity
        .fields
        .values()
        .filter(|field| readable_fields.contains(&field.id))
        .filter(|field| field.classification <= projection.classification_ceiling)
        .filter_map(|field| project_field(field, field_metadata(metadata, &field.id), projection))
        .collect();
    let relationships = entity
        .fields
        .values()
        .filter(|field| readable_fields.contains(&field.id))
        .filter(|field| field.classification <= projection.classification_ceiling)
        .filter_map(|field| {
            project_relationship(
                field,
                field_metadata(metadata, &field.id),
                &visible_entity_ids,
            )
        })
        .collect();

    registry_manifest_core::EntityManifest {
        name: entity.id.clone(),
        title: metadata
            .and_then(|metadata| metadata.title.as_ref())
            .map(localized_text),
        description: metadata
            .and_then(|metadata| metadata.description.as_ref())
            .map(localized_text),
        concept_uri: metadata.and_then(|metadata| metadata.concept_uri.clone()),
        identifiers: metadata
            .map(|metadata| {
                metadata
                    .identifiers
                    .iter()
                    .map(|identifier| IdentifierManifest {
                        name: identifier.field.clone(),
                        kind: identifier.kind.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        fields,
        relationships,
    }
}

fn field_metadata<'a>(
    entity: Option<&'a ManifestProjectionEntitySource>,
    field_id: &str,
) -> Option<&'a ManifestProjectionFieldSource> {
    entity.and_then(|entity| entity.fields.iter().find(|field| field.id == field_id))
}

fn project_field(
    field: &CompiledField,
    metadata: Option<&ManifestProjectionFieldSource>,
    projection: &ManifestProjectionSource,
) -> Option<FieldManifest> {
    let (field_type, constraints) = match &field.field_type {
        FieldTypeSource::Boolean => (FieldType::Boolean, FieldConstraints::default()),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => (
            FieldType::String,
            FieldConstraints {
                min_length: Some(u64::from(*min_length)),
                max_length: Some(u64::from(*max_length)),
                ..FieldConstraints::default()
            },
        ),
        FieldTypeSource::Text { max_length } => (
            FieldType::String,
            FieldConstraints {
                max_length: Some(u64::from(*max_length)),
                ..FieldConstraints::default()
            },
        ),
        FieldTypeSource::Int64 => (FieldType::Integer, FieldConstraints::default()),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => (
            FieldType::String,
            FieldConstraints {
                pattern: Some(decimal_pattern(*precision, *scale)),
                ..FieldConstraints::default()
            },
        ),
        FieldTypeSource::Date => (FieldType::Date, FieldConstraints::default()),
        FieldTypeSource::Timestamp => (FieldType::Timestamp, FieldConstraints::default()),
        FieldTypeSource::Uuid => (FieldType::String, FieldConstraints::default()),
        FieldTypeSource::VocabularyCode { values, .. } => (
            FieldType::Code,
            FieldConstraints {
                values: values.clone(),
                ..FieldConstraints::default()
            },
        ),
        FieldTypeSource::Reference { .. }
        | FieldTypeSource::Crs84Point { .. }
        | FieldTypeSource::Structured { .. } => return None,
    };
    Some(FieldManifest {
        name: field.id.clone(),
        field_type,
        required: field.required,
        constraints,
        concepts: metadata
            .map(|metadata| metadata.concepts.clone())
            .unwrap_or_default(),
        codelist: match &field.field_type {
            FieldTypeSource::VocabularyCode { vocabulary, .. }
                if projection
                    .vocabularies
                    .iter()
                    .any(|metadata| metadata.id.as_str() == vocabulary) =>
            {
                Some(vocabulary.clone())
            }
            _ => None,
        },
        unit: metadata.and_then(|metadata| metadata.unit.clone()),
        language: metadata.and_then(|metadata| metadata.language.clone()),
    })
}

fn project_relationship(
    field: &CompiledField,
    metadata: Option<&ManifestProjectionFieldSource>,
    visible_entity_ids: &BTreeSet<&str>,
) -> Option<RelationshipManifest> {
    let FieldTypeSource::Reference { target, .. } = &field.field_type else {
        return None;
    };
    visible_entity_ids
        .contains(target.as_str())
        .then(|| RelationshipManifest {
            name: field.id.clone(),
            target_entity: Some(target.clone()),
            target: None,
            cardinality: Some(if field.required {
                "one".to_owned()
            } else {
                "zero_or_one".to_owned()
            }),
            role: metadata.and_then(|metadata| metadata.relationship_role.clone()),
            concept_uri: metadata.and_then(|metadata| metadata.relationship_concept_uri.clone()),
        })
}

fn project_codelists(
    projection: &ManifestProjectionSource,
    visible_entities: &[&CompiledEntity],
) -> Vec<CodelistManifest> {
    let used = visible_entities
        .iter()
        .flat_map(|entity| {
            let readable_fields = entity
                .access_profiles
                .get(&projection.access_profile)
                .map(|profile| &profile.readable_fields);
            entity.fields.values().filter(move |field| {
                readable_fields.is_some_and(|fields| fields.contains(&field.id))
                    && field.classification <= projection.classification_ceiling
            })
        })
        .filter_map(|field| match &field.field_type {
            FieldTypeSource::VocabularyCode { vocabulary, values } => {
                Some((vocabulary.as_str(), values.as_slice()))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    projection
        .vocabularies
        .iter()
        .filter_map(|metadata| {
            let values = used.get(metadata.id.as_str())?;
            let concepts = values
                .iter()
                .map(|code| project_codelist_concept(metadata, code))
                .collect();
            Some(CodelistManifest {
                id: metadata.id.clone(),
                scheme_iri: metadata.scheme_iri.clone(),
                version: metadata.version.clone(),
                valid_from: None,
                valid_to: None,
                external_ref: metadata.external_ref.clone(),
                concepts,
            })
        })
        .collect()
}

fn project_codelist_concept(
    metadata: &ManifestProjectionVocabularySource,
    code: &str,
) -> CodelistConcept {
    let authored = metadata
        .concepts
        .iter()
        .find(|concept| concept.code == code);
    CodelistConcept {
        code: code.to_owned(),
        iri: authored.and_then(|concept| concept.iri.clone()),
        label: authored
            .and_then(|concept| concept.label.as_ref())
            .map(localized_text),
    }
}

fn sensitivity(classification: Classification) -> Sensitivity {
    match classification {
        Classification::Public => Sensitivity::Public,
        Classification::Internal => Sensitivity::Internal,
        Classification::Restricted => Sensitivity::Confidential,
    }
}

fn adms_status(status: ManifestProjectionDatasetStatus) -> AdmsStatus {
    match status {
        ManifestProjectionDatasetStatus::UnderDevelopment => AdmsStatus::UnderDevelopment,
        ManifestProjectionDatasetStatus::Active => AdmsStatus::Active,
        ManifestProjectionDatasetStatus::Completed => AdmsStatus::Completed,
        ManifestProjectionDatasetStatus::Deprecated => AdmsStatus::Deprecated,
        ManifestProjectionDatasetStatus::Withdrawn => AdmsStatus::Withdrawn,
    }
}

fn strip_null_members(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, child| {
                strip_null_members(child);
                !child.is_null()
            });
        }
        Value::Array(values) => {
            for child in values {
                strip_null_members(child);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn manifest_diagnostic(error: MetadataError) -> Diagnostic {
    match error {
        MetadataError::VersionUnsupported => Diagnostic::error(
            "manifest_projection.invalid",
            "project.manifestProjection",
            "the Registry Manifest projection is invalid",
        ),
        MetadataError::Validation { errors } => {
            let path = errors
                .first()
                .map(|error| format!("project.manifestProjection.{}", error.path))
                .unwrap_or_else(|| "project.manifestProjection".to_owned());
            Diagnostic::error(
                "manifest_projection.invalid",
                path,
                "the Registry Manifest projection is invalid",
            )
        }
    }
}

fn manifest_canonicalization_diagnostic() -> Diagnostic {
    Diagnostic::error(
        "manifest_projection.canonicalization_failed",
        "project.manifestProjection",
        "the Registry Manifest projection could not be canonicalized",
    )
}

#[cfg(test)]
mod tests {
    use registry_manifest_core::FieldType;

    use super::project_field;
    use crate::contract::{Classification, FieldTypeSource};
    use crate::model::CompiledField;

    #[test]
    fn decimal_projection_preserves_the_canonical_string_wire_contract() {
        let projected = project_field(
            &CompiledField {
                id: "measurement".to_owned(),
                field_type: FieldTypeSource::Decimal {
                    precision: 12,
                    scale: 4,
                    minimum: None,
                    maximum: None,
                },
                required: true,
                classification: Classification::Internal,
                valid_time_role: None,
                physical_name: "field_measurement".to_owned(),
            },
            None,
            &crate::contract::ManifestProjectionSource {
                access_profile: "reader".to_owned(),
                classification_ceiling: Classification::Internal,
                catalog: crate::contract::ManifestProjectionCatalogSource {
                    base_url: "https://registry.example.test".to_owned(),
                    title: crate::contract::ManifestProjectionTextSource::Plain(
                        "Registry".to_owned(),
                    ),
                    description: None,
                    publisher: crate::contract::ManifestProjectionPublisherSource {
                        name: "Registry".to_owned(),
                        iri: None,
                        authority_type: None,
                    },
                    participant_id: None,
                    conforms_to: Vec::new(),
                    standards: Default::default(),
                    application_profiles: Vec::new(),
                },
                dataset: crate::contract::ManifestProjectionDatasetSource {
                    id: None,
                    title: crate::contract::ManifestProjectionTextSource::Plain(
                        "Dataset".to_owned(),
                    ),
                    description: None,
                    owner: None,
                    status: None,
                    conforms_to: Vec::new(),
                    applicable_legislation: Vec::new(),
                    spatial_coverage: None,
                },
                data_service: None,
                entities: Vec::new(),
                vocabularies: Vec::new(),
            },
        )
        .expect("decimal is representable in the portable Manifest");

        assert_eq!(projected.field_type, FieldType::String);
        assert_eq!(
            projected.constraints.pattern.as_deref(),
            Some("^-?(0|[1-9][0-9]{0,7})\\.[0-9]{4}$")
        );
    }
}
