// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::artifacts::GeneratedArtifacts;
use crate::contract::{
    AccessProfileSource, BatchSource, Classification, ConstraintSource, EventConditionSource,
    EventSource, FieldTypeSource, ManifestProjectionSource, MutationMode, Operation,
    PackageIdentitySource, RowBoundarySource, TemporalSource, ValidTimeRole,
    WebhookAuthenticationProfile, WebhookDeadLetterMode,
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
pub struct CompiledChangeControl {
    pub required_for: BTreeSet<Operation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequest {
    pub request_entity_id: String,
    pub contract_fingerprint: String,
    pub retention_mode: CompiledChangeRequestRetentionMode,
    pub effects: Vec<CompiledChangeRequestEffect>,
    pub stages: Vec<CompiledChangeRequestStage>,
    pub actions: Vec<CompiledChangeRequestActionRoute>,
    pub review_grants: Vec<CompiledChangeRequestReviewGrant>,
    pub apply_grants: Vec<CompiledChangeRequestApplyGrant>,
    pub presence_grants: Vec<CompiledChangeRequestPresenceGrant>,
    pub target_entities: BTreeSet<String>,
    pub maximum_targets: u16,
    pub maximum_field_mutations: u16,
    pub maximum_snapshot_bytes: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledChangeRequestRetentionMode {
    #[default]
    Retain,
    OperatorErase,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestEffect {
    pub id: String,
    pub target: CompiledChangeRequestTarget,
    pub operation: Operation,
    pub mutations: Vec<CompiledChangeRequestMutation>,
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestTarget {
    pub entity_id: String,
    pub binding: CompiledChangeRequestTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestTargetBinding {
    Existing { from_field: String },
    ReservedCreate { effect: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestMutation {
    Set {
        field: String,
        value: CompiledChangeRequestValue,
    },
    Clear {
        field: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestValue {
    FromField {
        field: String,
    },
    FromEffect {
        effect: String,
        target_entity_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestStage {
    pub id: String,
    pub approvals: u16,
    pub exclude_submitter: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestOperation {
    SubmitRequest,
    ApproveRequest,
    RejectRequest,
    RequestRevision,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
}

impl ChangeRequestOperation {
    pub fn access_operation(self) -> Operation {
        match self {
            Self::SubmitRequest => Operation::SubmitRequest,
            Self::ApproveRequest => Operation::ApproveRequest,
            Self::RejectRequest => Operation::RejectRequest,
            Self::RequestRevision => Operation::RequestRevision,
            Self::ReviseRequest => Operation::ReviseRequest,
            Self::CancelRequest => Operation::CancelRequest,
            Self::ApplyRequest => Operation::ApplyRequest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestActionRoute {
    pub operation: ChangeRequestOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_stage: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestReviewGrant {
    pub profile_id: String,
    pub stage: String,
    pub target_entity_id: String,
    pub readable_fields: BTreeSet<String>,
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestApplyGrant {
    pub profile_id: String,
    pub target_entity_id: String,
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPresenceGrant {
    pub profile_id: String,
    pub target_entity_id: String,
    pub request_row_boundaries: Vec<RowBoundarySource>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_control: Option<CompiledChangeControl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_request: Option<CompiledChangeRequest>,
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
    pub request_stage: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<EventConditionSource>,
    pub classification_ceiling: Classification,
    pub data_schema: String,
    pub data_schema_fingerprint: String,
    pub data_schema_artifact_path: String,
    pub authentication_profile: WebhookAuthenticationProfile,
    pub delivery_mode: CompiledWebhookDeliveryMode,
    pub retry_profile: CompiledWebhookRetryProfile,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledWebhookRetryProfile {
    RegistryV1,
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

pub const REQUEST_SERVER_STATE_QUERY_FIELD: &str = "__request_server_state";
pub const REQUEST_PROPOSAL_VERSION_QUERY_FIELD: &str = "__request_proposal_version";
pub const REQUEST_EFFECT_DIGEST_QUERY_FIELD: &str = "__request_effect_digest";

pub fn request_query_field_id_for_api(api_name: &str) -> Option<&'static str> {
    match api_name {
        "serverState" => Some(REQUEST_SERVER_STATE_QUERY_FIELD),
        "proposalVersion" => Some(REQUEST_PROPOSAL_VERSION_QUERY_FIELD),
        "effectDigest" => Some(REQUEST_EFFECT_DIGEST_QUERY_FIELD),
        _ => None,
    }
}

pub fn request_query_field_api_name(field_id: &str) -> Option<&'static str> {
    match field_id {
        REQUEST_SERVER_STATE_QUERY_FIELD => Some("serverState"),
        REQUEST_PROPOSAL_VERSION_QUERY_FIELD => Some("proposalVersion"),
        REQUEST_EFFECT_DIGEST_QUERY_FIELD => Some("effectDigest"),
        _ => None,
    }
}

pub fn request_query_field_type(field_id: &str) -> Option<FieldTypeSource> {
    match field_id {
        REQUEST_SERVER_STATE_QUERY_FIELD => Some(FieldTypeSource::String {
            min_length: 4,
            max_length: 16,
        }),
        REQUEST_PROPOSAL_VERSION_QUERY_FIELD => Some(FieldTypeSource::Int64),
        REQUEST_EFFECT_DIGEST_QUERY_FIELD => Some(FieldTypeSource::String {
            min_length: 71,
            max_length: 71,
        }),
        _ => None,
    }
}

pub fn request_state_query_filter_fields() -> Vec<CompiledQueryFilterField> {
    vec![
        CompiledQueryFilterField {
            field: REQUEST_SERVER_STATE_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
            ],
        },
        CompiledQueryFilterField {
            field: REQUEST_PROPOSAL_VERSION_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
                CompiledQueryFilterOperator::Range,
            ],
        },
        CompiledQueryFilterField {
            field: REQUEST_EFFECT_DIGEST_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
                CompiledQueryFilterOperator::IsNull,
                CompiledQueryFilterOperator::IsNotNull,
            ],
        },
    ]
}

pub fn request_state_query_sort_fields() -> Vec<CompiledQuerySortField> {
    vec![
        CompiledQuerySortField {
            field: REQUEST_SERVER_STATE_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
        CompiledQuerySortField {
            field: REQUEST_PROPOSAL_VERSION_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
        CompiledQuerySortField {
            field: REQUEST_EFFECT_DIGEST_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
    ]
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
