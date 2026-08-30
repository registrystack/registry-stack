// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::artifacts::GeneratedArtifacts;
use crate::contract::{
    AccessProfileSource, BatchSource, Classification, ConstraintSource, EventSource,
    FieldTypeSource, ManifestProjectionSource, MutationMode, Operation, PackageIdentitySource,
    TemporalSource, ValidTimeRole, WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::physical_names::PhysicalNameInventory;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledField {
    pub id: String,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_role: Option<ValidTimeRole>,
    pub physical_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledLogicalField {
    pub id: String,
    pub api_name: String,
    pub sql_name: String,
    pub field_type: FieldTypeSource,
    pub classification: Classification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledStoredField {
    #[serde(flatten)]
    pub logical: CompiledLogicalField,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_role: Option<ValidTimeRole>,
    pub physical_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledDerivedField {
    #[serde(flatten)]
    pub logical: CompiledLogicalField,
    pub derivation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledDerivedRelation {
    pub id: String,
    pub sql_path: String,
    pub key_field: String,
    pub execution: crate::contract::DerivedExecutionSource,
    pub sql_sha256: String,
    pub sql_bytes: Vec<u8>,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSourceRelation {
    pub entity_id: String,
    pub sql_name: String,
    pub stored_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSelectorProfile {
    pub id: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledReadPath {
    pub id: String,
    pub through: String,
    pub to: String,
    pub route: String,
    pub source_ref: String,
    pub target_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEntity {
    pub id: String,
    pub route: String,
    pub mutation_mode: MutationMode,
    pub tombstone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchSource>,
    pub classification: Classification,
    pub physical_table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<CompiledTemporal>,
    pub canonical_id: CompiledLogicalField,
    pub stored_fields: Vec<CompiledStoredField>,
    pub derived_fields: BTreeMap<String, CompiledDerivedField>,
    pub derived_relations: BTreeMap<String, CompiledDerivedRelation>,
    pub source_relation: CompiledSourceRelation,
    pub selector_profiles: BTreeMap<String, CompiledSelectorProfile>,
    pub read_paths: BTreeMap<String, CompiledReadPath>,
    pub fields: BTreeMap<String, CompiledField>,
    pub constraints: BTreeMap<String, ConstraintSource>,
    pub indexes: BTreeMap<String, Vec<String>>,
    pub access_profiles: BTreeMap<String, AccessProfileSource>,
    pub events: BTreeMap<String, EventSource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTemporal {
    pub start_field: String,
    pub end_field: String,
    pub scope_fields: Vec<String>,
}

impl From<TemporalSource> for CompiledTemporal {
    fn from(source: TemporalSource) -> Self {
        Self {
            start_field: source.start_field,
            end_field: source.end_field,
            scope_fields: source.scope_fields,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Delete,
    Get,
    Patch,
    Post,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRoute {
    pub id: String,
    pub entity_id: String,
    pub method: HttpMethod,
    pub path: String,
    pub operation: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_kind: Option<CompiledQueryKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_kind: Option<CompiledRevisionKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_records: Option<u16>,
    pub access_profiles: Vec<String>,
    pub default_access_profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRouteInventory {
    pub routes: Vec<CompiledRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventDelivery {
    pub id: String,
    pub entity_id: String,
    pub event_id: String,
    pub trigger: crate::contract::EventTrigger,
    pub destination_id: String,
    pub projection_fields: Vec<String>,
    pub classification_ceiling: Classification,
    pub authentication_profile: WebhookAuthenticationProfile,
    pub delivery_mode: CompiledWebhookDeliveryMode,
    pub attempt_timeout_ms: u32,
    pub initial_backoff_ms: u32,
    pub maximum_backoff_ms: u32,
    /// Fixed V1 exponential multiplier. Runtime configuration may only tighten
    /// the resulting delays.
    pub exponential_backoff_multiplier: u8,
    pub maximum_attempts: u8,
    pub retry_delays_ms: Vec<u32>,
    /// Compiler-proved upper bound for the canonical projected JSON body.
    pub maximum_payload_bytes: u32,
    pub dead_letter: WebhookDeadLetterMode,
    pub operator_replay: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledWebhookDeliveryMode {
    AfterCommit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventDeliveryInventory {
    pub deliveries: Vec<CompiledEventDelivery>,
}

/// Conservative, non-pageable bound for one record's newest revision entries.
pub const MAX_REVISION_HISTORY_RECORDS: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledRevisionKind {
    List,
    Detail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessEntry {
    #[serde(default)]
    pub route_id: String,
    pub entity_id: String,
    pub operation: Operation,
    pub profile_ids: BTreeSet<String>,
    pub default_profile_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessInventory {
    pub entries: Vec<CompiledAccessEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataEntry {
    pub route_id: String,
    pub operation: Operation,
    pub access_profile: String,
    pub response_entity_id: String,
    pub readable_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataEntity {
    pub id: String,
    pub route: String,
    pub schema_path: String,
    pub entries: Vec<CompiledMetadataEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataInventory {
    pub registry_id: String,
    pub version: String,
    pub entities: Vec<CompiledMetadataEntity>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryKind {
    List,
    Current,
    AsOf,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryFilterOperator {
    Equals,
    In,
    Range,
    IsNull,
    IsNotNull,
    Prefix,
    Contains,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQuerySortDirection {
    Asc,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryFilterField {
    pub field: String,
    pub operators: Vec<CompiledQueryFilterOperator>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQuerySortField {
    pub field: String,
    pub directions: Vec<CompiledQuerySortDirection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryTemporalBinding {
    pub start_field: String,
    pub end_field: String,
    pub scope_fields: Vec<String>,
    pub semantics: CompiledQueryTemporalSemantics,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryTemporalSemantics {
    StartInclusiveEndExclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryOperation {
    pub id: String,
    pub route_id: String,
    pub entity_id: String,
    pub profile_id: String,
    pub kind: CompiledQueryKind,
    pub max_page_size: u16,
    pub projection_fields: Vec<String>,
    pub filter_fields: Vec<CompiledQueryFilterField>,
    pub sort_fields: Vec<CompiledQuerySortField>,
    #[serde(default)]
    pub allow_count: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processing_fields: Vec<String>,
    pub stable_tie_breaker: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<CompiledQueryTemporalBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryInventory {
    pub operations: Vec<CompiledQueryOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledModuleIdentity {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Immutable result consumed by runtime, migration, and authoring surfaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistry {
    registry_id: String,
    version: String,
    default_language: String,
    package: Option<PackageIdentitySource>,
    manifest_projection: Option<ManifestProjectionSource>,
    module_order: Vec<String>,
    module_closure: Vec<CompiledModuleIdentity>,
    entities: BTreeMap<String, CompiledEntity>,
    physical_names: PhysicalNameInventory,
    route_inventory: CompiledRouteInventory,
    access_inventory: CompiledAccessInventory,
    metadata_inventory: CompiledMetadataInventory,
    query_inventory: CompiledQueryInventory,
    event_delivery_inventory: CompiledEventDeliveryInventory,
    ddl: DdlInventory,
    artifacts: GeneratedArtifacts,
    findings: Vec<Diagnostic>,
    revision: String,
}

impl CompiledRegistry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry_id: String,
        version: String,
        default_language: String,
        package: Option<PackageIdentitySource>,
        manifest_projection: Option<ManifestProjectionSource>,
        module_order: Vec<String>,
        module_closure: Vec<CompiledModuleIdentity>,
        entities: BTreeMap<String, CompiledEntity>,
        physical_names: PhysicalNameInventory,
        route_inventory: CompiledRouteInventory,
        access_inventory: CompiledAccessInventory,
        metadata_inventory: CompiledMetadataInventory,
        query_inventory: CompiledQueryInventory,
        event_delivery_inventory: CompiledEventDeliveryInventory,
        ddl: DdlInventory,
        artifacts: GeneratedArtifacts,
        findings: Vec<Diagnostic>,
        revision: String,
    ) -> Self {
        Self {
            registry_id,
            version,
            default_language,
            package,
            manifest_projection,
            module_order,
            module_closure,
            entities,
            physical_names,
            route_inventory,
            access_inventory,
            metadata_inventory,
            query_inventory,
            event_delivery_inventory,
            ddl,
            artifacts,
            findings,
            revision,
        }
    }

    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn package(&self) -> Option<&PackageIdentitySource> {
        self.package.as_ref()
    }

    pub fn manifest_projection(&self) -> Option<&ManifestProjectionSource> {
        self.manifest_projection.as_ref()
    }

    pub fn module_order(&self) -> &[String] {
        &self.module_order
    }

    pub fn module_closure(&self) -> &[CompiledModuleIdentity] {
        &self.module_closure
    }

    pub fn entities(&self) -> &BTreeMap<String, CompiledEntity> {
        &self.entities
    }

    pub fn physical_names(&self) -> &PhysicalNameInventory {
        &self.physical_names
    }

    pub fn routes(&self) -> &CompiledRouteInventory {
        &self.route_inventory
    }

    pub fn access(&self) -> &CompiledAccessInventory {
        &self.access_inventory
    }

    pub fn metadata(&self) -> &CompiledMetadataInventory {
        &self.metadata_inventory
    }

    pub fn queries(&self) -> &CompiledQueryInventory {
        &self.query_inventory
    }

    pub fn event_deliveries(&self) -> &CompiledEventDeliveryInventory {
        &self.event_delivery_inventory
    }

    pub fn ddl(&self) -> &DdlInventory {
        &self.ddl
    }

    pub fn artifacts(&self) -> &GeneratedArtifacts {
        &self.artifacts
    }

    pub fn findings(&self) -> &[Diagnostic] {
        &self.findings
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }
}
