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

pub const HISTORY_SCHEMA_ENCODING_VERSION: &str = "breg-history-schema-v1";
pub const MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HISTORY_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
/// The member name an encrypted stored field records in a revision snapshot.
/// It matches `registry_platform_crypto::field_encryption::ENVELOPE_MEMBER_TAG`,
/// which this always-compiled module cannot reach: the crypto crate is a
/// runtime-only dependency. The response edge, not the decoder, opens the
/// member, so nothing here needs the crypto layer itself.
pub const ENVELOPE_MEMBER_TAG: &str = "__bregEncryptedV1";

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
        requested_fields: &BTreeSet<String>,
        authorizing_fields: &BTreeSet<String>,
    ) -> Result<HistorySchemaCompatibility, HistorySchemaError> {
        self.entity(&active_entity.id)?.compatibility_for_fields(
            active_entity,
            requested_fields,
            authorizing_fields,
        )
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
            encrypted: false,
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
                        encrypted: field.logical.encryption.is_some(),
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
    /// Describes how each requested field of one retained revision is read.
    ///
    /// `authorizing_fields` names the fields that decide which rows a caller may
    /// see. They must be present in the descriptor, because a row cannot be
    /// authorized from a value the revision never recorded.
    pub fn compatibility_for_fields(
        &self,
        active_entity: &CompiledEntity,
        requested_fields: &BTreeSet<String>,
        authorizing_fields: &BTreeSet<String>,
    ) -> Result<HistorySchemaCompatibility, HistorySchemaError> {
        self.validate()?;
        if self.id != active_entity.id {
            return Err(HistorySchemaError::MissingEntity);
        }
        let mut fields = BTreeMap::new();
        for field_id in requested_fields {
            let active = active_field(active_entity, field_id)
                .ok_or(HistorySchemaError::MissingRequiredField)?;
            let Some(retained) = self.field(field_id) else {
                // The descriptor predates the field, so the revision recorded no
                // value for it and an optional field reads as the null the record
                // held. A required field, a validity boundary, and a field that
                // decides row visibility refuse instead of inventing a value.
                if active.required
                    || active.valid_time_role.is_some()
                    || authorizing_fields.contains(field_id)
                {
                    return Err(HistorySchemaError::MissingRequiredField);
                }
                fields.insert(
                    field_id.clone(),
                    HistoryFieldCompatibility {
                        field_id: field_id.clone(),
                        active_api_name: active.api_name.to_owned(),
                        source: HistoryValueSource::AbsentAtRecording,
                        field_type: active.field_type.clone(),
                        required: false,
                        nullable: true,
                        encrypted: false,
                    },
                );
                continue;
            };
            if !retained.compatible_with(active)? {
                return Err(HistorySchemaError::IncompatibleField);
            }
            fields.insert(
                field_id.clone(),
                HistoryFieldCompatibility {
                    field_id: field_id.clone(),
                    active_api_name: active.api_name.to_owned(),
                    source: HistoryValueSource::Retained(retained.source.clone()),
                    field_type: retained.field_type.clone(),
                    required: active.required,
                    nullable: !active.required,
                    encrypted: retained.encrypted,
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
                HistoryValueSource::Retained(HistoryFieldSource::JournalRecordId) => {
                    let value =
                        journal_record_id.ok_or(HistorySchemaError::MissingRequiredField)?;
                    Value::String(value.to_owned())
                }
                HistoryValueSource::Retained(HistoryFieldSource::SnapshotKey { key }) => snapshot
                    .get(key)
                    .cloned()
                    .ok_or(HistorySchemaError::MissingRequiredField)?,
                HistoryValueSource::AbsentAtRecording => Value::Null,
            };
            validate_history_value(&value, &field.field_type, field.required, field.encrypted)?;
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
    /// Whether the revision recorded this field as a tagged envelope member.
    /// Descriptors recorded before field encryption default to false.
    #[serde(default)]
    pub encrypted: bool,
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
        // Recorded plaintext must never surface as an envelope, and recorded
        // envelopes must never surface as plaintext, so either flip refuses.
        if self.encrypted != active.encrypted {
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
                    || self.encrypted
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

/// Where one requested field's value for a retained revision comes from.
///
/// This is a runtime reading decision, not part of the retained descriptor
/// grammar, so a stored descriptor can never declare a field absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryValueSource {
    /// The descriptor carries the field, and the revision recorded a value.
    Retained(HistoryFieldSource),
    /// The descriptor predates the field, so the field reads as null.
    AbsentAtRecording,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryFieldCompatibility {
    pub field_id: String,
    pub active_api_name: String,
    pub source: HistoryValueSource,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub nullable: bool,
    pub encrypted: bool,
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
    encrypted: bool,
) -> Result<(), HistorySchemaError> {
    if value.is_null() {
        return (!required)
            .then_some(())
            .ok_or(HistorySchemaError::MissingRequiredField);
    }
    if encrypted {
        // An encrypted field records exactly the tagged envelope member, and
        // it stays sealed here: the caller-authorized response edge opens it.
        // Anything else was never sealed, so it refuses instead of surfacing.
        return tagged_envelope_member(value)
            .then_some(())
            .ok_or(HistorySchemaError::IncompatibleField);
    }
    validate_field_value(FieldValue::Json(value), field_type)
        .then_some(())
        .ok_or(HistorySchemaError::IncompatibleField)
}

/// Whether `value` is the single-key tagged envelope member an encrypted
/// stored field records: an object naming only the envelope tag with a string
/// payload. The payload's base64 and the envelope itself stay the crypto
/// layer's business at the response edge.
pub(crate) fn tagged_envelope_member(value: &Value) -> bool {
    let Value::Object(member) = value else {
        return false;
    };
    member.len() == 1
        && member
            .get(ENVELOPE_MEMBER_TAG)
            .is_some_and(Value::is_string)
}

#[derive(Clone, Copy)]
struct ActiveField<'a> {
    id: &'a str,
    api_name: &'a str,
    field_type: &'a FieldTypeSource,
    required: bool,
    valid_time_role: Option<ValidTimeRole>,
    encrypted: bool,
}

fn active_field<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<ActiveField<'a>> {
    if field_id == entity.canonical_id.id {
        return Some(ActiveField {
            id: &entity.canonical_id.id,
            api_name: &entity.canonical_id.api_name,
            field_type: &entity.canonical_id.field_type,
            required: true,
            valid_time_role: None,
            encrypted: false,
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
            encrypted: field.logical.encryption.is_some(),
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
            encryption: None,
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
                        pattern: None,
                        id: field.logical.id.clone(),
                        field_type: field.logical.field_type.clone(),
                        required: field.required,
                        classification: field.logical.classification,
                        valid_time_role: field.valid_time_role,
                        physical_name: field.physical_name.clone(),
                        encryption: None,
                    },
                )
            })
            .collect();
        CompiledEntity {
            attachments: Default::default(),
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
            membership_boundaries: BTreeMap::new(),
            hooks: BTreeMap::new(),
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

    fn add_note_field(entity: &mut CompiledEntity, is_required: bool) {
        let note = stored(
            "note",
            "note",
            FieldTypeSource::Text { max_length: 256 },
            is_required,
            None,
        );
        entity.fields.insert(
            "note".to_owned(),
            crate::model::CompiledField {
                pattern: None,
                id: "note".to_owned(),
                field_type: note.logical.field_type.clone(),
                required: is_required,
                classification: Classification::Restricted,
                valid_time_role: None,
                physical_name: "f_note".to_owned(),
                encryption: None,
            },
        );
        entity.stored_fields.push(note);
    }

    fn required(fields: &[&str]) -> BTreeSet<String> {
        fields.iter().map(|field| (*field).to_owned()).collect()
    }

    /// Declare one stored field of the entity encrypted, mirroring what the
    /// compiler records for `encrypted: true`.
    fn encrypt_field(entity: &mut CompiledEntity, field_id: &str) {
        let encryption = crate::model::CompiledFieldEncryption { blind_index: None };
        let stored = entity
            .stored_fields
            .iter_mut()
            .find(|field| field.logical.id == field_id)
            .expect("fixture field exists");
        stored.logical.encryption = Some(encryption.clone());
        entity
            .fields
            .get_mut(field_id)
            .expect("fixture field compiles")
            .encryption = Some(encryption);
    }

    fn snapshot(value: Value) -> Vec<u8> {
        canonicalize_json(&value).expect("snapshot canonicalizes")
    }

    /// One tagged envelope member carrying `payload` as its opaque string.
    fn tagged_member(payload: &str) -> Value {
        let mut member = Map::new();
        member.insert(ENVELOPE_MEMBER_TAG.to_owned(), json!(payload));
        Value::Object(member)
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
            .compatibility_for_fields(&active, &required(&["id", "household"]), &required(&[]))
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
                pattern: None,
                id: "note".to_owned(),
                field_type: extra.logical.field_type.clone(),
                required: false,
                classification: Classification::Restricted,
                valid_time_role: None,
                physical_name: "f_note".to_owned(),
                encryption: None,
            },
        );
        active.stored_fields.push(extra);
        let descriptor = descriptor_for(&old);

        descriptor
            .compatibility_for_fields(
                &active,
                &required(&["person", "valid-from"]),
                &required(&[]),
            )
            .expect("unrelated additive field does not affect old compatible query");
    }

    #[test]
    fn optional_field_absent_from_an_older_descriptor_reads_as_null() {
        let old = membership_entity();
        let descriptor = descriptor_for(&old);
        let mut active = old.clone();
        add_note_field(&mut active, false);

        let compatibility = descriptor
            .compatibility_for_fields(
                &active,
                &required(&["household", "note"]),
                &required(&["household"]),
            )
            .expect("granting an optional field the old revision predates keeps the query usable");
        assert_eq!(
            compatibility.fields["note"].source,
            HistoryValueSource::AbsentAtRecording
        );
        assert!(compatibility.fields["note"].nullable);
        assert_eq!(
            compatibility.fields["household"].source,
            HistoryValueSource::Retained(HistoryFieldSource::SnapshotKey {
                key: "household".to_owned()
            })
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
            .expect("a snapshot recorded before the field decodes");
        assert_eq!(decoded.by_field_id["household"], json!("A"));
        assert_eq!(decoded.by_field_id["note"], Value::Null);
        assert_eq!(decoded.by_api_name["note"], Value::Null);
    }

    #[test]
    fn absent_required_authorizing_and_validity_fields_stay_unavailable() {
        let old = membership_entity();
        let descriptor = descriptor_for(&old);

        let mut active = old.clone();
        add_note_field(&mut active, false);
        assert_eq!(
            descriptor
                .compatibility_for_fields(&active, &required(&["note"]), &required(&["note"]))
                .expect_err("a field that decides row visibility cannot read as null"),
            HistorySchemaError::MissingRequiredField
        );

        let mut newly_required = old.clone();
        add_note_field(&mut newly_required, true);
        assert_eq!(
            descriptor
                .compatibility_for_fields(&newly_required, &required(&["note"]), &required(&[]))
                .expect_err("a required field cannot read as null"),
            HistorySchemaError::MissingRequiredField
        );

        let mut boundary = old.clone();
        add_note_field(&mut boundary, false);
        boundary
            .stored_fields
            .iter_mut()
            .find(|field| field.logical.id == "note")
            .expect("fixture field exists")
            .valid_time_role = Some(ValidTimeRole::ValidTo);
        assert_eq!(
            descriptor
                .compatibility_for_fields(&boundary, &required(&["note"]), &required(&[]))
                .expect_err("a validity boundary cannot read as null"),
            HistorySchemaError::MissingRequiredField
        );
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
                .compatibility_for_fields(&missing, &required(&["household"]), &required(&[]))
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
                .compatibility_for_fields(&changed, &required(&["household"]), &required(&[]))
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
                .compatibility_for_fields(&tightened, &required(&["valid-to"]), &required(&[]))
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
            .compatibility_for_fields(&active, &required(&["household"]), &required(&[]))
            .expect("stored field query does not activate current derived SQL");
        assert_eq!(
            descriptor
                .compatibility_for_fields(&active, &required(&["risk-score"]), &required(&[]))
                .expect_err("historical derived fields are unsupported"),
            HistorySchemaError::MissingRequiredField
        );
    }

    #[test]
    fn no_defaults_are_invented_for_missing_or_null_snapshot_values() {
        let entity = membership_entity();
        let descriptor = descriptor_for(&entity);
        let compatibility = descriptor
            .compatibility_for_fields(
                &entity,
                &required(&["household", "valid-to"]),
                &required(&[]),
            )
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
        unsupported.encoding_version = "breg-history-schema-v99".to_owned();
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
            .compatibility_for_fields(&entity, &required(&["household"]), &required(&[]))
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
            "hooks",
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

    #[test]
    fn encrypted_members_decode_as_tagged_envelopes_and_stay_tagged() {
        let mut entity = membership_entity();
        add_note_field(&mut entity, false);
        encrypt_field(&mut entity, "note");
        let descriptor = descriptor_for(&entity);
        assert!(
            descriptor
                .entity("membership")
                .expect("entity exists")
                .field("note")
                .expect("note field exists")
                .encrypted,
            "the retained descriptor marks the encrypted field"
        );

        let compatibility = descriptor
            .compatibility_for_fields(&entity, &required(&["note"]), &required(&[]))
            .expect("an encrypted retained field stays compatible with itself");
        assert!(compatibility.fields["note"].encrypted);

        // The tagged envelope member decodes and stays the tagged member: the
        // response edge opens it, never the decoder. Envelope bytes and their
        // base64 stay the crypto layer's business; decode recognizes the tag.
        let member = tagged_member("AAAA");
        let decoded = descriptor
            .decode_snapshot_for_fields(
                &compatibility,
                &snapshot(json!({
                    "person": "00000000-0000-4000-8000-000000000001",
                    "household": "A",
                    "valid-from": "2026-01-01",
                    "valid-to": null,
                    "note": member.clone(),
                })),
                None,
            )
            .expect("the tagged envelope member decodes");
        assert_eq!(decoded.by_field_id["note"], member);
        assert_eq!(decoded.by_api_name["note"], member);

        // An optional encrypted member a revision recorded as null reads null.
        let decoded = descriptor
            .decode_snapshot_for_fields(
                &compatibility,
                &snapshot(json!({
                    "person": "00000000-0000-4000-8000-000000000001",
                    "household": "A",
                    "valid-from": "2026-01-01",
                    "valid-to": null,
                    "note": null,
                })),
                None,
            )
            .expect("a null encrypted member decodes");
        assert_eq!(decoded.by_field_id["note"], Value::Null);

        // Anything but null and the exact single-key tagged shape is refused.
        let non_string_member = {
            let mut member = Map::new();
            member.insert(ENVELOPE_MEMBER_TAG.to_owned(), json!(7));
            Value::Object(member)
        };
        let foreign_member = {
            let mut member = Map::new();
            member.insert("other".to_owned(), json!("member"));
            Value::Object(member)
        };
        let extra_key_member = {
            let mut member = Map::new();
            member.insert(ENVELOPE_MEMBER_TAG.to_owned(), json!("AAAA"));
            member.insert("extra".to_owned(), json!("member"));
            Value::Object(member)
        };
        for malformed in [
            json!("recorded plaintext"),
            non_string_member,
            foreign_member,
            extra_key_member,
        ] {
            assert_eq!(
                descriptor
                    .decode_snapshot_for_fields(
                        &compatibility,
                        &snapshot(json!({
                            "person": "00000000-0000-4000-8000-000000000001",
                            "household": "A",
                            "valid-from": "2026-01-01",
                            "valid-to": null,
                            "note": malformed,
                        })),
                        None,
                    )
                    .expect_err("only the tagged envelope member decodes"),
                HistorySchemaError::IncompatibleField
            );
        }
    }

    #[test]
    fn descriptors_recorded_before_the_encrypted_marker_still_parse() {
        let mut entity = membership_entity();
        add_note_field(&mut entity, false);
        encrypt_field(&mut entity, "note");
        let descriptor = descriptor_for(&entity);
        let bytes = serialize_descriptor(&descriptor).expect("descriptor serializes");

        // Strip every encrypted marker by hand, as a descriptor recorded by an
        // older revision of the runtime looks.
        let mut stripped = serde_json::from_slice::<Value>(&bytes).expect("descriptor is JSON");
        for entity in stripped
            .get_mut("entities")
            .and_then(Value::as_object_mut)
            .expect("entities object")
            .values_mut()
        {
            if let Some(fields) = entity
                .get_mut("storedFields")
                .and_then(Value::as_object_mut)
            {
                for field in fields.values_mut() {
                    field
                        .as_object_mut()
                        .expect("field object")
                        .remove("encrypted");
                }
            }
        }
        let stripped = canonicalize_json(&stripped).expect("stripped descriptor canonicalizes");
        let parsed = parse_descriptor(&stripped).expect("old descriptors keep parsing");
        assert!(
            !parsed
                .entity("membership")
                .expect("entity exists")
                .field("note")
                .expect("note field exists")
                .encrypted
        );
    }

    #[test]
    fn encryption_state_flips_are_incompatible_in_both_directions() {
        let mut plain = membership_entity();
        add_note_field(&mut plain, false);
        let mut encrypted = plain.clone();
        encrypt_field(&mut encrypted, "note");

        // Retained plaintext against an active encrypted declaration.
        let plain_descriptor = descriptor_for(&plain);
        assert_eq!(
            plain_descriptor
                .compatibility_for_fields(&encrypted, &required(&["note"]), &required(&[]))
                .expect_err("recorded plaintext cannot be read as an envelope"),
            HistorySchemaError::IncompatibleField
        );

        // Retained envelopes against an active plaintext declaration.
        let encrypted_descriptor = descriptor_for(&encrypted);
        assert_eq!(
            encrypted_descriptor
                .compatibility_for_fields(&plain, &required(&["note"]), &required(&[]))
                .expect_err("recorded envelopes must not surface as plaintext"),
            HistorySchemaError::IncompatibleField
        );
    }

    #[test]
    fn canonical_id_cannot_declare_encryption() {
        let entity = membership_entity();
        let mut descriptor = descriptor_for(&entity);
        descriptor
            .entities
            .get_mut("membership")
            .expect("entity exists")
            .canonical_id
            .encrypted = true;
        assert_eq!(
            serialize_descriptor(&descriptor).expect_err("an encrypted canonical id is malformed"),
            HistorySchemaError::MalformedDescriptor
        );
    }
}
