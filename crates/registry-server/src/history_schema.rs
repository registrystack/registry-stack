// SPDX-License-Identifier: Apache-2.0

//! Retained schema descriptors for decoding immutable revision snapshots.
//!
//! These descriptors are deliberately narrower than `CompiledRegistry`: they
//! preserve the old byte contract for stored data while leaving every access,
//! projection, filtering, and row-authorization decision with the active
//! compiled package.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::contract::{FieldTypeSource, ValidTimeRole};
use crate::data::{validate_field_value, FieldValue};
use crate::model::{CompiledEntity, CompiledRegistry};

pub const HISTORY_SCHEMA_ENCODING_VERSION: &str = "registry-server-history-schema-v1";
pub const MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HISTORY_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistorySchemaError {
    #[error("the retained schema descriptor is unavailable")]
    DescriptorUnavailable,
    #[error("the retained schema descriptor is malformed")]
    MalformedDescriptor,
    #[error("the retained schema descriptor uses an unsupported encoding version")]
    UnsupportedDescriptorVersion,
    #[error("the requested entity is unavailable in the retained schema descriptor")]
    MissingEntity,
    #[error("a required retained field is unavailable")]
    MissingRequiredField,
    #[error("a retained field is incompatible with the active schema")]
    IncompatibleField,
    #[error("the retained revision snapshot is malformed")]
    MalformedSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HistorySchemaDescriptor {
    pub encoding_version: String,
    pub registry_id: String,
    pub package_revision: String,
    pub lifecycle: HistoryLifecycleDescriptor,
    pub entities: BTreeMap<String, HistoryEntityDescriptor>,
}

impl HistorySchemaDescriptor {
    #[must_use]
    pub fn from_compiled_registry(registry: &CompiledRegistry, package_revision: &str) -> Self {
        Self::from_compiled_entities(
            registry.registry_id(),
            package_revision,
            registry.entities().values(),
        )
    }

    fn from_compiled_entities<'a>(
        registry_id: &str,
        package_revision: &str,
        entities: impl IntoIterator<Item = &'a CompiledEntity>,
    ) -> Self {
        let entities = entities
            .into_iter()
            .map(|entity| (entity.id.clone(), HistoryEntityDescriptor::from(entity)))
            .collect();
        Self {
            encoding_version: HISTORY_SCHEMA_ENCODING_VERSION.to_owned(),
            registry_id: registry_id.to_owned(),
            package_revision: package_revision.to_owned(),
            lifecycle: HistoryLifecycleDescriptor::journal_v1(),
            entities,
        }
    }

    pub fn entity(&self, entity_id: &str) -> Result<&HistoryEntityDescriptor, HistorySchemaError> {
        self.ensure_supported()?;
        self.entities
            .get(entity_id)
            .ok_or(HistorySchemaError::MissingEntity)
    }

    pub fn compatibility_for_fields(
        &self,
        active_entity: &CompiledEntity,
        required_fields: &BTreeSet<String>,
    ) -> Result<HistorySchemaCompatibility, HistorySchemaError> {
        self.entity(&active_entity.id)?
            .compatibility_for_fields(active_entity, required_fields)
    }

    pub fn required_history_fields<S, R, T, SI, RI, TI>(
        selected_fields: S,
        row_authorization_fields: R,
        temporal_fields: T,
    ) -> BTreeSet<String>
    where
        S: IntoIterator<Item = SI>,
        R: IntoIterator<Item = RI>,
        T: IntoIterator<Item = TI>,
        SI: AsRef<str>,
        RI: AsRef<str>,
        TI: AsRef<str>,
    {
        let mut fields = BTreeSet::new();
        fields.extend(
            selected_fields
                .into_iter()
                .map(|field| field.as_ref().to_owned()),
        );
        fields.extend(
            row_authorization_fields
                .into_iter()
                .map(|field| field.as_ref().to_owned()),
        );
        fields.extend(
            temporal_fields
                .into_iter()
                .map(|field| field.as_ref().to_owned()),
        );
        fields
    }

    pub fn decode_snapshot_for_fields(
        &self,
        compatibility: &HistorySchemaCompatibility,
        snapshot: &[u8],
        journal_record_id: Option<&str>,
    ) -> Result<DecodedHistorySnapshot, HistorySchemaError> {
        self.entity(&compatibility.entity_id)?
            .decode_snapshot_for_fields(compatibility, snapshot, journal_record_id)
    }

    fn ensure_supported(&self) -> Result<(), HistorySchemaError> {
        if self.encoding_version != HISTORY_SCHEMA_ENCODING_VERSION {
            return Err(HistorySchemaError::UnsupportedDescriptorVersion);
        }
        if !valid_descriptor_id(&self.registry_id)
            || self.package_revision.is_empty()
            || self.package_revision.len() > 512
            || self.package_revision.chars().any(char::is_control)
            || self.lifecycle != HistoryLifecycleDescriptor::journal_v1()
            || self.entities.iter().any(|(id, entity)| id != &entity.id)
        {
            return Err(HistorySchemaError::MalformedDescriptor);
        }
        for entity in self.entities.values() {
            entity.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HistoryLifecycleDescriptor {
    pub source: HistoryLifecycleSource,
    pub active_value: String,
    pub tombstoned_value: String,
}

impl HistoryLifecycleDescriptor {
    fn journal_v1() -> Self {
        Self {
            source: HistoryLifecycleSource::RevisionJournalRecordLifecycle,
            active_value: "active".to_owned(),
            tombstoned_value: "tombstoned".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryLifecycleSource {
    RevisionJournalRecordLifecycle,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HistoryEntityDescriptor {
    pub id: String,
    pub canonical_id: HistoryFieldDescriptor,
    pub stored_fields: BTreeMap<String, HistoryFieldDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<HistoryTemporalDescriptor>,
}

impl From<&CompiledEntity> for HistoryEntityDescriptor {
    fn from(entity: &CompiledEntity) -> Self {
        let canonical_id = HistoryFieldDescriptor {
            id: entity.canonical_id.id.clone(),
            source: HistoryFieldSource::JournalRecordId,
            field_type: entity.canonical_id.field_type.clone(),
            required: true,
            nullable: false,
            valid_time_role: None,
        };
        let stored_fields = entity
            .stored_fields
            .iter()
            .map(|field| {
                (
                    field.logical.id.clone(),
                    HistoryFieldDescriptor {
                        id: field.logical.id.clone(),
                        source: HistoryFieldSource::SnapshotKey {
                            key: field.logical.id.clone(),
                        },
                        field_type: field.logical.field_type.clone(),
                        required: field.required,
                        nullable: !field.required,
                        valid_time_role: field.valid_time_role,
                    },
                )
            })
            .collect();
        let temporal = entity
            .temporal
            .as_ref()
            .and_then(|temporal| HistoryTemporalDescriptor::from_entity(entity, temporal));
        Self {
            id: entity.id.clone(),
            canonical_id,
            stored_fields,
            temporal,
        }
    }
}

impl HistoryEntityDescriptor {
    pub fn compatibility_for_fields(
        &self,
        active_entity: &CompiledEntity,
        required_fields: &BTreeSet<String>,
    ) -> Result<HistorySchemaCompatibility, HistorySchemaError> {
        self.validate()?;
        if self.id != active_entity.id {
            return Err(HistorySchemaError::MissingEntity);
        }
        let mut fields = BTreeMap::new();
        for field_id in required_fields {
            let retained = self
                .field(field_id)
                .ok_or(HistorySchemaError::MissingRequiredField)?;
            let active = active_field(active_entity, field_id)
                .ok_or(HistorySchemaError::MissingRequiredField)?;
            if !retained.compatible_with(active)? {
                return Err(HistorySchemaError::IncompatibleField);
            }
            fields.insert(
                field_id.clone(),
                HistoryFieldCompatibility {
                    field_id: field_id.clone(),
                    active_api_name: active.api_name.to_owned(),
                    source: retained.source.clone(),
                    field_type: retained.field_type.clone(),
                    required: active.required,
                    nullable: !active.required,
                },
            );
        }
        Ok(HistorySchemaCompatibility {
            entity_id: self.id.clone(),
            fields,
        })
    }

    pub fn decode_snapshot_for_fields(
        &self,
        compatibility: &HistorySchemaCompatibility,
        snapshot: &[u8],
        journal_record_id: Option<&str>,
    ) -> Result<DecodedHistorySnapshot, HistorySchemaError> {
        self.validate()?;
        if compatibility.entity_id != self.id {
            return Err(HistorySchemaError::MissingEntity);
        }
        let snapshot = parse_canonical_snapshot(snapshot)?;
        let mut by_field_id = Map::new();
        let mut by_api_name = Map::new();
        for field in compatibility.fields.values() {
            let value = match &field.source {
                HistoryFieldSource::JournalRecordId => {
                    let value =
                        journal_record_id.ok_or(HistorySchemaError::MissingRequiredField)?;
                    Value::String(value.to_owned())
                }
                HistoryFieldSource::SnapshotKey { key } => snapshot
                    .get(key)
                    .cloned()
                    .ok_or(HistorySchemaError::MissingRequiredField)?,
            };
            validate_history_value(&value, &field.field_type, field.required)?;
            if by_field_id
                .insert(field.field_id.clone(), value.clone())
                .is_some()
                || by_api_name
                    .insert(field.active_api_name.clone(), value)
                    .is_some()
            {
                return Err(HistorySchemaError::MalformedDescriptor);
            }
        }
        Ok(DecodedHistorySnapshot {
            by_field_id,
            by_api_name,
        })
    }

    pub fn field(&self, field_id: &str) -> Option<&HistoryFieldDescriptor> {
        (self.canonical_id.id == field_id)
            .then_some(&self.canonical_id)
            .or_else(|| self.stored_fields.get(field_id))
    }

    fn validate(&self) -> Result<(), HistorySchemaError> {
        if !valid_descriptor_id(&self.id)
            || self.canonical_id.id != "id"
            || !matches!(
                &self.canonical_id.source,
                HistoryFieldSource::JournalRecordId
            )
            || self.canonical_id.field_type != FieldTypeSource::Uuid
            || !self.canonical_id.required
            || self.canonical_id.nullable
            || self
                .stored_fields
                .iter()
                .any(|(id, field)| id != &field.id || field.id == self.canonical_id.id)
        {
            return Err(HistorySchemaError::MalformedDescriptor);
        }
        self.canonical_id.validate()?;
        for field in self.stored_fields.values() {
            field.validate()?;
        }
        if let Some(temporal) = &self.temporal {
            temporal.validate(self)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HistoryFieldDescriptor {
    pub id: String,
    pub source: HistoryFieldSource,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_role: Option<ValidTimeRole>,
}

impl HistoryFieldDescriptor {
    fn compatible_with(&self, active: ActiveField<'_>) -> Result<bool, HistorySchemaError> {
        self.validate()?;
        if self.id != active.id || self.field_type != *active.field_type {
            return Ok(false);
        }
        if active.required && (self.nullable || !self.required) {
            return Ok(false);
        }
        if self.valid_time_role != active.valid_time_role {
            return Ok(false);
        }
        Ok(true)
    }

    fn validate(&self) -> Result<(), HistorySchemaError> {
        if !valid_descriptor_id(&self.id) || self.required == self.nullable {
            return Err(HistorySchemaError::MalformedDescriptor);
        }
        match &self.source {
            HistoryFieldSource::JournalRecordId => {
                if self.id != "id"
                    || self.field_type != FieldTypeSource::Uuid
                    || self.valid_time_role.is_some()
                {
                    return Err(HistorySchemaError::MalformedDescriptor);
                }
            }
            HistoryFieldSource::SnapshotKey { key } => {
                if !valid_descriptor_id(key) {
                    return Err(HistorySchemaError::MalformedDescriptor);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum HistoryFieldSource {
    JournalRecordId,
    SnapshotKey { key: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HistoryTemporalDescriptor {
    pub start_field: String,
    pub end_field: String,
    pub value_kind: HistoryTemporalValueKind,
    pub semantics: HistoryTemporalSemantics,
}

impl HistoryTemporalDescriptor {
    fn from_entity(
        entity: &CompiledEntity,
        temporal: &crate::model::CompiledTemporal,
    ) -> Option<Self> {
        let start = entity.fields.get(&temporal.start_field)?;
        let end = entity.fields.get(&temporal.end_field)?;
        let value_kind = match (&start.field_type, &end.field_type) {
            (FieldTypeSource::Date, FieldTypeSource::Date) => HistoryTemporalValueKind::Date,
            (FieldTypeSource::Timestamp, FieldTypeSource::Timestamp) => {
                HistoryTemporalValueKind::Timestamp
            }
            _ => return None,
        };
        Some(Self {
            start_field: temporal.start_field.clone(),
            end_field: temporal.end_field.clone(),
            value_kind,
            semantics: HistoryTemporalSemantics::StartInclusiveEndExclusive,
        })
    }

    fn validate(&self, entity: &HistoryEntityDescriptor) -> Result<(), HistorySchemaError> {
        let start = entity
            .field(&self.start_field)
            .ok_or(HistorySchemaError::MalformedDescriptor)?;
        let end = entity
            .field(&self.end_field)
            .ok_or(HistorySchemaError::MalformedDescriptor)?;
        let expected_kind = match (&start.field_type, &end.field_type) {
            (FieldTypeSource::Date, FieldTypeSource::Date) => HistoryTemporalValueKind::Date,
            (FieldTypeSource::Timestamp, FieldTypeSource::Timestamp) => {
                HistoryTemporalValueKind::Timestamp
            }
            _ => return Err(HistorySchemaError::MalformedDescriptor),
        };
        if self.value_kind != expected_kind
            || self.semantics != HistoryTemporalSemantics::StartInclusiveEndExclusive
            || start.valid_time_role != Some(ValidTimeRole::ValidFrom)
            || end.valid_time_role != Some(ValidTimeRole::ValidTo)
        {
            return Err(HistorySchemaError::MalformedDescriptor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryTemporalValueKind {
    Date,
    Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryTemporalSemantics {
    StartInclusiveEndExclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistorySchemaCompatibility {
    pub entity_id: String,
    pub fields: BTreeMap<String, HistoryFieldCompatibility>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryFieldCompatibility {
    pub field_id: String,
    pub active_api_name: String,
    pub source: HistoryFieldSource,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub nullable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedHistorySnapshot {
    pub by_field_id: Map<String, Value>,
    pub by_api_name: Map<String, Value>,
}

pub fn serialize_descriptor(
    descriptor: &HistorySchemaDescriptor,
) -> Result<Vec<u8>, HistorySchemaError> {
    descriptor.ensure_supported()?;
    let value =
        serde_json::to_value(descriptor).map_err(|_| HistorySchemaError::MalformedDescriptor)?;
    let bytes = canonicalize_json(&value).map_err(|_| HistorySchemaError::MalformedDescriptor)?;
    if bytes.is_empty() || bytes.len() > MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES {
        return Err(HistorySchemaError::MalformedDescriptor);
    }
    Ok(bytes)
}

pub fn parse_descriptor(bytes: &[u8]) -> Result<HistorySchemaDescriptor, HistorySchemaError> {
    if bytes.is_empty() || bytes.len() > MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES {
        return Err(HistorySchemaError::DescriptorUnavailable);
    }
    let value = parse_json_strict(bytes).map_err(|_| HistorySchemaError::MalformedDescriptor)?;
    let canonical =
        canonicalize_json(&value).map_err(|_| HistorySchemaError::MalformedDescriptor)?;
    if canonical != bytes {
        return Err(HistorySchemaError::MalformedDescriptor);
    }
    let descriptor: HistorySchemaDescriptor =
        serde_json::from_value(value).map_err(|_| HistorySchemaError::MalformedDescriptor)?;
    descriptor.ensure_supported()?;
    Ok(descriptor)
}

fn parse_canonical_snapshot(snapshot: &[u8]) -> Result<Map<String, Value>, HistorySchemaError> {
    if snapshot.is_empty() || snapshot.len() > MAX_HISTORY_SNAPSHOT_BYTES {
        return Err(HistorySchemaError::MalformedSnapshot);
    }
    let value = parse_json_strict(snapshot).map_err(|_| HistorySchemaError::MalformedSnapshot)?;
    let canonical = canonicalize_json(&value).map_err(|_| HistorySchemaError::MalformedSnapshot)?;
    if canonical != snapshot {
        return Err(HistorySchemaError::MalformedSnapshot);
    }
    value
        .as_object()
        .cloned()
        .ok_or(HistorySchemaError::MalformedSnapshot)
}

fn validate_history_value(
    value: &Value,
    field_type: &FieldTypeSource,
    required: bool,
) -> Result<(), HistorySchemaError> {
    if value.is_null() {
        return (!required)
            .then_some(())
            .ok_or(HistorySchemaError::MissingRequiredField);
    }
    validate_field_value(FieldValue::Json(value), field_type)
        .then_some(())
        .ok_or(HistorySchemaError::IncompatibleField)
}

#[derive(Clone, Copy)]
struct ActiveField<'a> {
    id: &'a str,
    api_name: &'a str,
    field_type: &'a FieldTypeSource,
    required: bool,
    valid_time_role: Option<ValidTimeRole>,
}

fn active_field<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<ActiveField<'a>> {
    if field_id == entity.canonical_id.id {
        return Some(ActiveField {
            id: &entity.canonical_id.id,
            api_name: &entity.canonical_id.api_name,
            field_type: &entity.canonical_id.field_type,
            required: true,
            valid_time_role: None,
        });
    }
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| ActiveField {
            id: &field.logical.id,
            api_name: &field.logical.api_name,
            field_type: &field.logical.field_type,
            required: field.required,
            valid_time_role: field.valid_time_role,
        })
}

fn valid_descriptor_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use registry_platform_canonical_json::canonicalize_json;
    use serde_json::{json, Value};

    use super::*;
    use crate::contract::{Classification, MutationMode};
    use crate::model::{
        CompiledDerivedField, CompiledEntity, CompiledLogicalField, CompiledSourceRelation,
        CompiledStoredField, CompiledTemporal,
    };

    fn logical(id: &str, api_name: &str, field_type: FieldTypeSource) -> CompiledLogicalField {
        CompiledLogicalField {
            id: id.to_owned(),
            api_name: api_name.to_owned(),
            sql_name: id.replace('-', "_"),
            field_type,
            classification: Classification::Restricted,
        }
    }

    fn stored(
        id: &str,
        api_name: &str,
        field_type: FieldTypeSource,
        required: bool,
        valid_time_role: Option<ValidTimeRole>,
    ) -> CompiledStoredField {
        CompiledStoredField {
            logical: logical(id, api_name, field_type),
            required,
            valid_time_role,
            physical_name: format!("f_{}", id.replace('-', "_")),
        }
    }

    fn entity(fields: Vec<CompiledStoredField>) -> CompiledEntity {
        let compiled_fields = fields
            .iter()
            .map(|field| {
                (
                    field.logical.id.clone(),
                    crate::model::CompiledField {
                        id: field.logical.id.clone(),
                        field_type: field.logical.field_type.clone(),
                        required: field.required,
                        classification: field.logical.classification,
                        valid_time_role: field.valid_time_role,
                        physical_name: field.physical_name.clone(),
                    },
                )
            })
            .collect();
        CompiledEntity {
            primary_dataset: None,
            id: "membership".to_owned(),
            route: "memberships".to_owned(),
            mutation_mode: MutationMode::Mutable,
            tombstone: true,
            batch: None,
            change_control: None,
            change_request: None,
            classification: Classification::Restricted,
            access_requirements: None,
            geojson: None,
            physical_table: "e_membership".to_owned(),
            temporal: Some(CompiledTemporal {
                start_field: "valid-from".to_owned(),
                end_field: "valid-to".to_owned(),
                scope_fields: vec!["person".to_owned()],
            }),
            canonical_id: logical("id", "id", FieldTypeSource::Uuid),
            stored_fields: fields,
            derived_fields: BTreeMap::new(),
            derived_relations: BTreeMap::new(),
            source_relation: CompiledSourceRelation {
                entity_id: "membership".to_owned(),
                sql_name: "membership".to_owned(),
                stored_fields: vec![],
            },
            selector_profiles: BTreeMap::new(),
            read_paths: BTreeMap::new(),
            fields: compiled_fields,
            constraints: BTreeMap::new(),
            indexes: BTreeMap::new(),
            access_profiles: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    fn membership_entity() -> CompiledEntity {
        entity(vec![
            stored("person", "person", FieldTypeSource::Uuid, true, None),
            stored(
                "household",
                "household",
                FieldTypeSource::String {
                    min_length: 1,
                    max_length: 64,
                },
                true,
                None,
            ),
            stored(
                "valid-from",
                "validFrom",
                FieldTypeSource::Date,
                true,
                Some(ValidTimeRole::ValidFrom),
            ),
            stored(
                "valid-to",
                "validTo",
                FieldTypeSource::Date,
                false,
                Some(ValidTimeRole::ValidTo),
            ),
        ])
    }

    fn descriptor_for(entity: &CompiledEntity) -> HistorySchemaDescriptor {
        HistorySchemaDescriptor::from_compiled_entities("registry", "sha256:package", [entity])
    }

    fn required(fields: &[&str]) -> BTreeSet<String> {
        fields.iter().map(|field| (*field).to_owned()).collect()
    }

    fn snapshot(value: Value) -> Vec<u8> {
        canonicalize_json(&value).expect("snapshot canonicalizes")
    }

    #[test]
    fn renamed_active_field_decodes_by_stable_id_and_current_api_name() {
        let old = membership_entity();
        let mut active = old.clone();
        active
            .stored_fields
            .iter_mut()
            .find(|field| field.logical.id == "household")
            .expect("fixture field exists")
            .logical
            .api_name = "householdId".to_owned();
        let descriptor = descriptor_for(&old);
        let compatibility = descriptor
            .compatibility_for_fields(&active, &required(&["id", "household"]))
            .expect("rename preserves stable field compatibility");

        let decoded = descriptor
            .decode_snapshot_for_fields(
                &compatibility,
                &snapshot(json!({
                    "person": "00000000-0000-4000-8000-000000000001",
                    "household": "A",
                    "valid-from": "2026-01-01",
                    "valid-to": null
                })),
                Some("00000000-0000-4000-8000-00000000000a"),
            )
            .expect("snapshot decodes");

        assert_eq!(decoded.by_field_id["household"], json!("A"));
        assert_eq!(decoded.by_api_name["householdId"], json!("A"));
        assert_eq!(
            decoded.by_api_name["id"],
            json!("00000000-0000-4000-8000-00000000000a")
        );
    }

    #[test]
    fn same_schema_and_unrelated_additive_fields_are_compatible() {
        let old = membership_entity();
        let mut active = old.clone();
        let extra = stored(
            "note",
            "note",
            FieldTypeSource::Text { max_length: 256 },
            false,
            None,
        );
        active.fields.insert(
            "note".to_owned(),
            crate::model::CompiledField {
                id: "note".to_owned(),
                field_type: extra.logical.field_type.clone(),
                required: false,
                classification: Classification::Restricted,
                valid_time_role: None,
                physical_name: "f_note".to_owned(),
            },
        );
        active.stored_fields.push(extra);
        let descriptor = descriptor_for(&old);

        descriptor
            .compatibility_for_fields(&active, &required(&["person", "valid-from"]))
            .expect("unrelated additive field does not affect old compatible query");
    }

    #[test]
    fn missing_or_type_changed_required_fields_are_unavailable() {
        let old = membership_entity();
        let descriptor = descriptor_for(&old);

        let mut missing = old.clone();
        missing.fields.remove("household");
        missing
            .stored_fields
            .retain(|field| field.logical.id != "household");
        assert_eq!(
            descriptor
                .compatibility_for_fields(&missing, &required(&["household"]))
                .expect_err("active query field must exist"),
            HistorySchemaError::MissingRequiredField
        );

        let mut changed = old.clone();
        changed.fields.get_mut("household").unwrap().field_type = FieldTypeSource::Int64;
        changed
            .stored_fields
            .iter_mut()
            .find(|field| field.logical.id == "household")
            .unwrap()
            .logical
            .field_type = FieldTypeSource::Int64;
        assert_eq!(
            descriptor
                .compatibility_for_fields(&changed, &required(&["household"]))
                .expect_err("type changes must not reinterpret old values"),
            HistorySchemaError::IncompatibleField
        );

        let mut tightened = old.clone();
        tightened.fields.get_mut("valid-to").unwrap().required = true;
        tightened
            .stored_fields
            .iter_mut()
            .find(|field| field.logical.id == "valid-to")
            .unwrap()
            .required = true;
        assert_eq!(
            descriptor
                .compatibility_for_fields(&tightened, &required(&["valid-to"]))
                .expect_err("a newly required field cannot rely on nullable retained bytes"),
            HistorySchemaError::IncompatibleField
        );
    }

    #[test]
    fn stored_queries_remain_compatible_when_active_entity_has_derived_fields() {
        let old = membership_entity();
        let mut active = old.clone();
        active.derived_fields.insert(
            "risk-score".to_owned(),
            CompiledDerivedField {
                logical: logical("risk-score", "riskScore", FieldTypeSource::Int64),
                derivation_id: "risk".to_owned(),
            },
        );
        let descriptor = descriptor_for(&old);

        descriptor
            .compatibility_for_fields(&active, &required(&["household"]))
            .expect("stored field query does not activate current derived SQL");
        assert_eq!(
            descriptor
                .compatibility_for_fields(&active, &required(&["risk-score"]))
                .expect_err("historical derived fields are unsupported"),
            HistorySchemaError::MissingRequiredField
        );
    }

    #[test]
    fn no_defaults_are_invented_for_missing_or_null_snapshot_values() {
        let entity = membership_entity();
        let descriptor = descriptor_for(&entity);
        let compatibility = descriptor
            .compatibility_for_fields(&entity, &required(&["household", "valid-to"]))
            .expect("compatible fields");

        assert_eq!(
            descriptor
                .decode_snapshot_for_fields(
                    &compatibility,
                    &snapshot(json!({
                        "person": "00000000-0000-4000-8000-000000000001",
                        "valid-from": "2026-01-01",
                        "valid-to": null
                    })),
                    None,
                )
                .expect_err("required household is missing"),
            HistorySchemaError::MissingRequiredField
        );
        assert_eq!(
            descriptor
                .decode_snapshot_for_fields(
                    &compatibility,
                    &snapshot(json!({
                        "person": "00000000-0000-4000-8000-000000000001",
                        "household": null,
                        "valid-from": "2026-01-01",
                        "valid-to": null
                    })),
                    None,
                )
                .expect_err("required household is null"),
            HistorySchemaError::MissingRequiredField
        );
        assert_eq!(
            descriptor
                .decode_snapshot_for_fields(
                    &compatibility,
                    &snapshot(json!({
                        "person": "00000000-0000-4000-8000-000000000001",
                        "household": "A",
                        "valid-from": "2026-01-01"
                    })),
                    None,
                )
                .expect_err("requested optional field must exist as retained snapshot data"),
            HistorySchemaError::MissingRequiredField
        );

        let decoded = descriptor
            .decode_snapshot_for_fields(
                &compatibility,
                &snapshot(json!({
                    "person": "00000000-0000-4000-8000-000000000001",
                    "household": "A",
                    "valid-from": "2026-01-01",
                    "valid-to": null
                })),
                None,
            )
            .expect("explicit null optional retained field decodes");
        assert_eq!(decoded.by_field_id["valid-to"], Value::Null);
    }

    #[test]
    fn descriptors_and_snapshots_are_strict_bounded_and_canonical() {
        let entity = membership_entity();
        let descriptor = descriptor_for(&entity);
        let bytes = serialize_descriptor(&descriptor).expect("descriptor serializes");
        assert_eq!(
            parse_descriptor(&bytes).expect("descriptor parses"),
            descriptor
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert_eq!(
            parse_descriptor(&noncanonical).expect_err("noncanonical bytes are refused"),
            HistorySchemaError::MalformedDescriptor
        );

        let mut unsupported = descriptor.clone();
        unsupported.encoding_version = "registry-server-history-schema-v99".to_owned();
        let unsupported = canonicalize_json(&serde_json::to_value(unsupported).unwrap()).unwrap();
        assert_eq!(
            parse_descriptor(&unsupported).expect_err("unknown encoding versions are refused"),
            HistorySchemaError::UnsupportedDescriptorVersion
        );

        assert_eq!(
            parse_descriptor(&vec![b' '; MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES + 1])
                .expect_err("oversized descriptors are refused"),
            HistorySchemaError::DescriptorUnavailable
        );

        let compatibility = descriptor
            .compatibility_for_fields(&entity, &required(&["household"]))
            .expect("compatible fields");
        let noncanonical_snapshot = br#"{"household":"A"}
"#;
        assert_eq!(
            descriptor
                .decode_snapshot_for_fields(&compatibility, noncanonical_snapshot, None)
                .expect_err("noncanonical snapshots are refused"),
            HistorySchemaError::MalformedSnapshot
        );
    }

    #[test]
    fn retained_descriptor_excludes_old_authorization_and_executable_metadata() {
        let entity = membership_entity();
        let descriptor = descriptor_for(&entity);
        let text = String::from_utf8(serialize_descriptor(&descriptor).unwrap()).unwrap();

        for forbidden in [
            "classification",
            "accessProfiles",
            "requiredScopes",
            "requiredPurposes",
            "readableFields",
            "writableFields",
            "filterableFields",
            "sortableFields",
            "rowBoundaries",
            "operations",
            "constraints",
            "events",
            "derivedFields",
            "derivedRelations",
            "physicalName",
            "sql",
        ] {
            assert!(
                !text.contains(forbidden),
                "descriptor leaked old governed metadata key {forbidden}: {text}"
            );
        }
    }

    #[test]
    fn temporal_descriptor_records_lifecycle_and_exact_interval_encoding() {
        let entity = membership_entity();
        let descriptor = descriptor_for(&entity);
        let retained = descriptor.entity("membership").expect("entity exists");

        assert_eq!(
            descriptor.lifecycle,
            HistoryLifecycleDescriptor {
                source: HistoryLifecycleSource::RevisionJournalRecordLifecycle,
                active_value: "active".to_owned(),
                tombstoned_value: "tombstoned".to_owned(),
            }
        );
        assert_eq!(
            retained.temporal,
            Some(HistoryTemporalDescriptor {
                start_field: "valid-from".to_owned(),
                end_field: "valid-to".to_owned(),
                value_kind: HistoryTemporalValueKind::Date,
                semantics: HistoryTemporalSemantics::StartInclusiveEndExclusive,
            })
        );
    }
}
