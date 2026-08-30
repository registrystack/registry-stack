// SPDX-License-Identifier: Apache-2.0
//! One-way lossy Registry Manifest projection.

use std::collections::{BTreeMap, BTreeSet};

use registry_manifest_core::{
    compile_manifest, AccessRights, AdmsStatus, CatalogManifest, DatasetManifest, FieldConstraints,
    FieldManifest, FieldType, LocalizedText, MetadataError, MetadataManifest, PublisherManifest,
    RelationshipManifest, Sensitivity,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

use crate::artifacts::decimal_pattern;
use crate::contract::{
    Classification, FieldTypeSource, ManifestProjectionDatasetStatus, ManifestProjectionSource,
    Operation,
};
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledEntity, CompiledField};

pub(crate) fn project_manifest_bytes(
    registry_id: &str,
    projection: &ManifestProjectionSource,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<Vec<u8>, Diagnostic> {
    let manifest = project_manifest(registry_id, projection, entities);
    compile_manifest(&manifest).map_err(manifest_diagnostic)?;
    let mut value =
        serde_json::to_value(&manifest).map_err(|_| manifest_canonicalization_diagnostic())?;
    strip_null_members(&mut value);
    let manifest: MetadataManifest = serde_json::from_value(value.clone())
        .map_err(|_| manifest_canonicalization_diagnostic())?;
    compile_manifest(&manifest).map_err(manifest_diagnostic)?;
    canonicalize_json(&value).map_err(|_| manifest_canonicalization_diagnostic())
}

fn project_manifest(
    registry_id: &str,
    projection: &ManifestProjectionSource,
    entities: &BTreeMap<String, CompiledEntity>,
) -> MetadataManifest {
    let visible_entities = visible_entities(projection, entities);
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
            title: LocalizedText::Plain(projection.catalog.title.clone()),
            description: projection
                .catalog
                .description
                .clone()
                .map(LocalizedText::Plain),
            publisher: PublisherManifest {
                name: projection.catalog.publisher.name.clone(),
                iri: projection.catalog.publisher.iri.clone(),
                authority_type: projection.catalog.publisher.authority_type.clone(),
            },
            participant_id: projection.catalog.participant_id.clone(),
            conforms_to: Vec::new(),
            standards: Default::default(),
            application_profiles: Vec::new(),
        },
        vocabularies: BTreeMap::new(),
        profiles: Vec::new(),
        evaluation_profiles: Vec::new(),
        ecosystem_bindings: Vec::new(),
        requirements: Vec::new(),
        evidence_types: Vec::new(),
        authorities: Vec::new(),
        public_services: Vec::new(),
        data_services: Vec::new(),
        forms: Vec::new(),
        datasets: vec![DatasetManifest {
            id: registry_id.to_owned(),
            title: LocalizedText::Plain(projection.dataset.title.clone()),
            description: projection
                .dataset
                .description
                .clone()
                .map(LocalizedText::Plain),
            owner: projection.dataset.owner.clone(),
            sensitivity: sensitivity(projection.classification_ceiling),
            access_rights,
            update_frequency: Default::default(),
            conforms_to: Vec::new(),
            applicable_legislation: Vec::new(),
            spatial_coverage: None,
            status: projection.dataset.status.map(adms_status),
            public_services: Vec::new(),
            policy: None,
            evidence_offerings: Vec::new(),
            entities: visible_entities
                .iter()
                .map(|entity| project_entity(projection, entity, &visible_entities))
                .collect(),
        }],
        codelists: Vec::new(),
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
        .filter_map(project_field)
        .collect();
    let relationships = entity
        .fields
        .values()
        .filter(|field| readable_fields.contains(&field.id))
        .filter(|field| field.classification <= projection.classification_ceiling)
        .filter_map(|field| project_relationship(field, &visible_entity_ids))
        .collect();

    registry_manifest_core::EntityManifest {
        name: entity.id.clone(),
        title: None,
        description: None,
        concept_uri: None,
        identifiers: Vec::new(),
        fields,
        relationships,
    }
}

fn project_field(field: &CompiledField) -> Option<FieldManifest> {
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
        concepts: Vec::new(),
        codelist: None,
        unit: None,
        language: None,
    })
}

fn project_relationship(
    field: &CompiledField,
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
            role: None,
            concept_uri: None,
        })
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
        let projected = project_field(&CompiledField {
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
        })
        .expect("decimal is representable in the portable Manifest");

        assert_eq!(projected.field_type, FieldType::String);
        assert_eq!(
            projected.constraints.pattern.as_deref(),
            Some("^-?(0|[1-9][0-9]{0,7})\\.[0-9]{4}$")
        );
    }
}
