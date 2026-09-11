//! Bounded, caller-bound Base Registry Engine runtime metadata.
//!
//! Only the served `GET /v1/registry` metadata v1 document can produce an
//! executable operation binding. Generated entity summaries and older
//! metadata artifacts are deliberately insufficient authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jsonschema::{Draft, JSONSchema};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use uuid::Uuid;

/// Maximum accepted size of one Base Registry Engine runtime metadata document.
pub const MAX_BREG_METADATA_BYTES: usize = 8 * 1024 * 1024;
/// Maximum nesting depth accepted anywhere in runtime metadata, including
/// open JSON Schema values.
pub const MAX_BREG_METADATA_DEPTH: usize = 32;

const MAX_ARRAY_ITEMS: usize = 16_384;
const MAX_OBJECT_MEMBERS: usize = 16_384;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_TOTAL_NODES: usize = 524_288;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_SUPPORTED_ACTION_TARGETS: u64 = 16;
const MAX_SUPPORTED_ACTION_FIELD_MUTATIONS: u64 = 128;
const MAX_SUPPORTED_ACTION_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHANGE_REQUEST_STAGES: usize = 32;
const MAX_CHANGE_REQUEST_STAGE_ID_BYTES: usize = 64;
const MAX_CHANGE_REQUEST_STAGE_APPROVALS: u64 = 32;

/// A coarse, response-value-free reason that runtime metadata was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegMetadataErrorKind {
    Size,
    Json,
    DuplicateMember,
    Bound,
    Shape,
    Version,
    Revision,
    Identifier,
    DuplicateIdentifier,
    DanglingReference,
}

/// Failure to decode a trustworthy Base Registry Engine runtime metadata document.
///
/// Debug and display output intentionally contain no response-controlled
/// member names, identifiers, paths, or values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BRegMetadataError {
    kind: BRegMetadataErrorKind,
}

impl BRegMetadataError {
    #[must_use]
    pub fn kind(self) -> BRegMetadataErrorKind {
        self.kind
    }

    fn new(kind: BRegMetadataErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for BRegMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegMetadataError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for BRegMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Base Registry Engine metadata was refused")
    }
}

impl std::error::Error for BRegMetadataError {}

/// A Base Registry Engine operation kind understood by this client version.
#[derive(Clone, Eq, PartialEq)]
pub enum BRegOperationKind {
    Create,
    Get,
    Lookup,
    List,
    Patch,
    Tombstone,
    Batch,
    Revisions,
    Snapshot,
    SubmitRequest,
    ApproveRequest,
    RejectRequest,
    RequestRevision,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
    Invoke,
    /// A future operation remains discoverable but is never executable by
    /// this client version.
    Unknown(String),
}

impl BRegOperationKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Create => "create",
            Self::Get => "get",
            Self::Lookup => "lookup",
            Self::List => "list",
            Self::Patch => "patch",
            Self::Tombstone => "tombstone",
            Self::Batch => "batch",
            Self::Revisions => "revisions",
            Self::Snapshot => "snapshot",
            Self::SubmitRequest => "submit_request",
            Self::ApproveRequest => "approve_request",
            Self::RejectRequest => "reject_request",
            Self::RequestRevision => "request_revision",
            Self::ReviseRequest => "revise_request",
            Self::CancelRequest => "cancel_request",
            Self::ApplyRequest => "apply_request",
            Self::Invoke => "invoke",
            Self::Unknown(value) => value,
        }
    }

    fn parse(value: String) -> Self {
        match value.as_str() {
            "create" => Self::Create,
            "get" => Self::Get,
            "lookup" => Self::Lookup,
            "list" => Self::List,
            "patch" => Self::Patch,
            "tombstone" => Self::Tombstone,
            "batch" => Self::Batch,
            "revisions" => Self::Revisions,
            "snapshot" => Self::Snapshot,
            "submit_request" => Self::SubmitRequest,
            "approve_request" => Self::ApproveRequest,
            "reject_request" => Self::RejectRequest,
            "request_revision" => Self::RequestRevision,
            "revise_request" => Self::ReviseRequest,
            "cancel_request" => Self::CancelRequest,
            "apply_request" => Self::ApplyRequest,
            "invoke" => Self::Invoke,
            _ => Self::Unknown(value),
        }
    }
}

impl fmt::Debug for BRegOperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(_) => formatter.write_str("Unknown(<redacted>)"),
            known => formatter.write_str(known.as_str()),
        }
    }
}

/// Planner implementation described by caller-filtered change-request metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegChangeRequestPlannerKind {
    Declarative,
    Rhai,
}

/// Fixed resource and proposal ceilings for a visible Rhai planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BRegChangeRequestPlannerLimits {
    maximum_targets: u64,
    maximum_field_mutations: u64,
    maximum_snapshot_bytes: u64,
    maximum_source_bytes: u64,
    maximum_operations: u64,
    maximum_call_depth: u64,
    maximum_expression_depth: u64,
    maximum_string_bytes: u64,
    maximum_array_items: u64,
    maximum_map_entries: u64,
    maximum_modules: u64,
}

impl BRegChangeRequestPlannerLimits {
    #[must_use]
    pub const fn maximum_targets(self) -> u64 {
        self.maximum_targets
    }

    #[must_use]
    pub const fn maximum_field_mutations(self) -> u64 {
        self.maximum_field_mutations
    }

    #[must_use]
    pub const fn maximum_snapshot_bytes(self) -> u64 {
        self.maximum_snapshot_bytes
    }

    #[must_use]
    pub const fn maximum_source_bytes(self) -> u64 {
        self.maximum_source_bytes
    }

    #[must_use]
    pub const fn maximum_operations(self) -> u64 {
        self.maximum_operations
    }

    #[must_use]
    pub const fn maximum_call_depth(self) -> u64 {
        self.maximum_call_depth
    }

    #[must_use]
    pub const fn maximum_expression_depth(self) -> u64 {
        self.maximum_expression_depth
    }

    #[must_use]
    pub const fn maximum_string_bytes(self) -> u64 {
        self.maximum_string_bytes
    }

    #[must_use]
    pub const fn maximum_array_items(self) -> u64 {
        self.maximum_array_items
    }

    #[must_use]
    pub const fn maximum_map_entries(self) -> u64 {
        self.maximum_map_entries
    }

    #[must_use]
    pub const fn maximum_modules(self) -> u64 {
        self.maximum_modules
    }
}

/// Source-free planner capability. This value is descriptive and cannot
/// create lifecycle or target-write authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegChangeRequestPlannerCapability {
    kind: BRegChangeRequestPlannerKind,
    abi: Option<String>,
    limits: Option<BRegChangeRequestPlannerLimits>,
    possible_write_count: Option<u64>,
    possible_write_operations: Vec<BRegOperationKind>,
}

impl BRegChangeRequestPlannerCapability {
    #[must_use]
    pub const fn kind(&self) -> BRegChangeRequestPlannerKind {
        self.kind
    }

    #[must_use]
    pub fn abi(&self) -> Option<&str> {
        self.abi.as_deref()
    }

    #[must_use]
    pub const fn limits(&self) -> Option<BRegChangeRequestPlannerLimits> {
        self.limits
    }

    #[must_use]
    pub const fn possible_write_count(&self) -> Option<u64> {
        self.possible_write_count
    }

    #[must_use]
    pub fn possible_write_operations(&self) -> &[BRegOperationKind] {
        &self.possible_write_operations
    }
}

/// Static review policy for one visible request type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegChangeRequestReviewMode {
    None,
    Staged,
}

/// Application policy selected by the governed request type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegChangeRequestApplicationMode {
    Manual,
    Automatic,
    Planner,
}

/// An application result permitted by the governed application policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BRegChangeRequestDisposition {
    Apply,
    Queue,
}

/// One finite package-authored reason for a planner-selected queue outcome.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegChangeRequestQueueReason {
    code: String,
    label: String,
}

impl BRegChangeRequestQueueReason {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for BRegChangeRequestQueueReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegChangeRequestQueueReason")
            .field("code", &self.code)
            .field("label", &"<redacted>")
            .finish()
    }
}

/// Source-free application capability for one visible request type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegChangeRequestApplicationCapability {
    mode: BRegChangeRequestApplicationMode,
    allowed_dispositions: Vec<BRegChangeRequestDisposition>,
    queue_reasons: Vec<BRegChangeRequestQueueReason>,
}

impl BRegChangeRequestApplicationCapability {
    #[must_use]
    pub const fn mode(&self) -> BRegChangeRequestApplicationMode {
        self.mode
    }

    #[must_use]
    pub fn allowed_dispositions(&self) -> &[BRegChangeRequestDisposition] {
        &self.allowed_dispositions
    }

    #[must_use]
    pub fn queue_reasons(&self) -> &[BRegChangeRequestQueueReason] {
        &self.queue_reasons
    }
}

/// Caller-filtered, descriptive change-request capability for one entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegChangeRequestCapability {
    planner: BRegChangeRequestPlannerCapability,
    review_mode: BRegChangeRequestReviewMode,
    stages: Option<Vec<BRegChangeRequestStage>>,
    application: BRegChangeRequestApplicationCapability,
}

/// One authored review stage advertised for a change-request kind.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegChangeRequestStage {
    id: String,
    approvals: u64,
    exclude_submitter: bool,
    exclude_previous_reviewers: bool,
}

impl fmt::Debug for BRegChangeRequestStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegChangeRequestStage")
            .field("identifier", &"<redacted>")
            .field("approvals", &self.approvals)
            .field("exclude_submitter", &self.exclude_submitter)
            .field(
                "exclude_previous_reviewers",
                &self.exclude_previous_reviewers,
            )
            .finish()
    }
}

impl BRegChangeRequestStage {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn approvals(&self) -> u64 {
        self.approvals
    }

    #[must_use]
    pub const fn exclude_submitter(&self) -> bool {
        self.exclude_submitter
    }

    #[must_use]
    pub const fn exclude_previous_reviewers(&self) -> bool {
        self.exclude_previous_reviewers
    }
}

impl BRegChangeRequestCapability {
    #[must_use]
    pub const fn planner(&self) -> &BRegChangeRequestPlannerCapability {
        &self.planner
    }

    #[must_use]
    pub const fn review_mode(&self) -> BRegChangeRequestReviewMode {
        self.review_mode
    }

    /// Returns authored stages when the server supports this additive metadata field.
    #[must_use]
    pub fn stages(&self) -> Option<&[BRegChangeRequestStage]> {
        self.stages.as_deref()
    }

    #[must_use]
    pub const fn application(&self) -> &BRegChangeRequestApplicationCapability {
        &self.application
    }
}

/// One caller-visible field on an authoritative runtime operation.
#[derive(Clone, PartialEq)]
pub struct BRegMetadataField {
    id: String,
    api_name: String,
    label: String,
    schema: Value,
    required: bool,
    nullable: bool,
    read_only: bool,
    removable: bool,
    storage_validation: Option<BRegStorageValidationDescriptor>,
    code_labels: BTreeMap<String, String>,
    reference: Option<BRegReferenceDescriptor>,
}

/// Native storage validation advertised for one field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegStorageValidationDescriptor {
    kind: String,
    pattern: String,
}

impl BRegStorageValidationDescriptor {
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// One independently authorized operation for resolving a record reference.
#[derive(Clone, PartialEq)]
pub struct BRegReferenceOperationDescriptor {
    operation_id: String,
    access_profile: String,
    label_fields: Vec<String>,
}

impl BRegReferenceOperationDescriptor {
    #[must_use]
    pub fn operation_identifier(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }

    #[must_use]
    pub fn label_fields(&self) -> &[String] {
        &self.label_fields
    }
}

impl fmt::Debug for BRegReferenceOperationDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegReferenceOperationDescriptor")
            .field("label_field_count", &self.label_fields.len())
            .finish_non_exhaustive()
    }
}

/// Descriptive record-reference capability for one visible field.
#[derive(Clone, PartialEq)]
pub struct BRegReferenceDescriptor {
    manual_entry: bool,
    target_entity: Option<String>,
    operations: Vec<BRegReferenceOperationDescriptor>,
}

impl BRegReferenceDescriptor {
    #[must_use]
    pub const fn manual_entry(&self) -> bool {
        self.manual_entry
    }

    #[must_use]
    pub fn target_entity(&self) -> Option<&str> {
        self.target_entity.as_deref()
    }

    #[must_use]
    pub fn operations(&self) -> &[BRegReferenceOperationDescriptor] {
        &self.operations
    }
}

impl fmt::Debug for BRegReferenceDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegReferenceDescriptor")
            .field("manual_entry", &self.manual_entry)
            .field("operation_count", &self.operations.len())
            .finish_non_exhaustive()
    }
}

impl BRegMetadataField {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }

    /// The declared target entity for this field's typed record reference.
    /// This is metadata, not authority to read or mutate the target entity.
    #[must_use]
    pub fn reference_target_entity(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .and_then(BRegReferenceDescriptor::target_entity)
    }

    #[must_use]
    pub fn reference(&self) -> Option<&BRegReferenceDescriptor> {
        self.reference.as_ref()
    }

    #[must_use]
    pub fn code_labels(&self) -> &BTreeMap<String, String> {
        &self.code_labels
    }

    #[must_use]
    pub const fn storage_validation(&self) -> Option<&BRegStorageValidationDescriptor> {
        self.storage_validation.as_ref()
    }

    /// Returns the bounded, inert JSON Schema value advertised by the BReg.
    #[must_use]
    pub fn schema(&self) -> &Value {
        &self.schema
    }

    #[must_use]
    pub fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub fn nullable(&self) -> bool {
        self.nullable
    }

    #[must_use]
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub fn removable(&self) -> bool {
        self.removable
    }
}

/// One selector field accepted by a caller-visible Lookup operation.
#[derive(Clone, PartialEq)]
pub struct BRegLookupSelectorFieldDescriptor {
    id: String,
    api_name: String,
    label: String,
    schema: Value,
    required: bool,
}

impl BRegLookupSelectorFieldDescriptor {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    #[must_use]
    pub fn schema(&self) -> &Value {
        &self.schema
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

impl fmt::Debug for BRegLookupSelectorFieldDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLookupSelectorFieldDescriptor")
            .field("required", &self.required)
            .finish_non_exhaustive()
    }
}

/// One complete caller-visible Lookup selector.
#[derive(Clone, PartialEq)]
pub struct BRegLookupSelectorDescriptor {
    id: String,
    label: String,
    value_origin: String,
    fields: Vec<BRegLookupSelectorFieldDescriptor>,
    request_fields: Vec<String>,
}

impl BRegLookupSelectorDescriptor {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    #[must_use]
    pub fn value_origin(&self) -> &str {
        &self.value_origin
    }
    #[must_use]
    pub fn fields(&self) -> &[BRegLookupSelectorFieldDescriptor] {
        &self.fields
    }
    #[must_use]
    pub fn request_fields(&self) -> &[String] {
        &self.request_fields
    }
}

impl fmt::Debug for BRegLookupSelectorDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLookupSelectorDescriptor")
            .field("field_count", &self.fields.len())
            .field("request_field_count", &self.request_fields.len())
            .finish_non_exhaustive()
    }
}

/// A related-record path advertised for one operation.
#[derive(Clone, PartialEq)]
pub struct BRegReadPathDescriptor {
    id: String,
    label: String,
}

impl BRegReadPathDescriptor {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for BRegReadPathDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegReadPathDescriptor(<descriptive>)")
    }
}

impl fmt::Debug for BRegMetadataField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegMetadataField")
            .field("required", &self.required)
            .field("nullable", &self.nullable)
            .field("read_only", &self.read_only)
            .field("removable", &self.removable)
            .finish_non_exhaustive()
    }
}

/// Parsed request metadata for one caller-visible operation.
#[derive(Clone, PartialEq)]
pub struct BRegOperationRequest {
    field_names: Option<String>,
    query_parameters: Vec<String>,
    body: Option<String>,
    content_type: Option<String>,
    schema: Option<Value>,
    idempotency_key_required: Option<bool>,
    if_match_required: Option<bool>,
    mutation_semantics: Option<String>,
    patch_path_prefix: Option<String>,
    patch_operations: Vec<String>,
    remove_semantics: Option<String>,
    maximum_items: Option<u64>,
    maximum_body_bytes: Option<u64>,
    allow_create: Option<bool>,
    allow_patch: Option<bool>,
}

impl BRegOperationRequest {
    #[must_use]
    pub fn field_names(&self) -> Option<&str> {
        self.field_names.as_deref()
    }

    #[must_use]
    pub fn query_parameters(&self) -> &[String] {
        &self.query_parameters
    }

    #[must_use]
    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }

    #[must_use]
    pub fn schema(&self) -> Option<&Value> {
        self.schema.as_ref()
    }

    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    #[must_use]
    pub fn idempotency_key_required(&self) -> Option<bool> {
        self.idempotency_key_required
    }

    #[must_use]
    pub fn if_match_required(&self) -> Option<bool> {
        self.if_match_required
    }

    #[must_use]
    pub fn mutation_semantics(&self) -> Option<&str> {
        self.mutation_semantics.as_deref()
    }

    #[must_use]
    pub fn patch_path_prefix(&self) -> Option<&str> {
        self.patch_path_prefix.as_deref()
    }

    #[must_use]
    pub fn patch_operations(&self) -> &[String] {
        &self.patch_operations
    }

    #[must_use]
    pub fn remove_semantics(&self) -> Option<&str> {
        self.remove_semantics.as_deref()
    }

    #[must_use]
    pub const fn maximum_items(&self) -> Option<u64> {
        self.maximum_items
    }

    #[must_use]
    pub const fn maximum_body_bytes(&self) -> Option<u64> {
        self.maximum_body_bytes
    }

    #[must_use]
    pub const fn allow_create(&self) -> Option<bool> {
        self.allow_create
    }

    #[must_use]
    pub const fn allow_patch(&self) -> Option<bool> {
        self.allow_patch
    }
}

impl fmt::Debug for BRegOperationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegOperationRequest")
            .field("has_body", &self.body.is_some())
            .field("has_schema", &self.schema.is_some())
            .field("idempotency_key_required", &self.idempotency_key_required)
            .field("if_match_required", &self.if_match_required)
            .finish_non_exhaustive()
    }
}

/// Caller-visible list capability. Descriptive metadata does not grant authority.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegQueryDescriptor {
    pub kind: String,
    pub selectable_fields: Vec<BRegQueryField>,
    pub filterable_fields: Vec<BRegQueryField>,
    pub sortable_fields: Vec<BRegQueryField>,
    pub allow_count: bool,
    pub default_page_size: u64,
    pub max_page_size: u64,
    pub max_filter_clauses: u64,
    pub max_in_values: u64,
    pub pagination: BRegQueryPagination,
    pub temporal: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_queries: Option<BRegSpatialQueryDescriptor>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegQueryField {
    pub id: String,
    pub api_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operators: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegQueryPagination {
    pub parameter: String,
    pub response_path: String,
    pub exclusive: bool,
}

/// Spatial query capabilities for one caller-visible collection operation.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegSpatialQueryDescriptor {
    pub bbox: Option<BRegBboxQueryDescriptor>,
}

/// Exact bounded CRS84 bbox contract for one collection operation.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegBboxQueryDescriptor {
    pub geometry_property: String,
    pub maximum_longitude_span_degrees: Number,
    pub maximum_latitude_span_degrees: Number,
    pub coordinate_reference_system: String,
    pub semantics: String,
}

/// One authoritative operation from caller-filtered runtime metadata.
#[derive(Clone, PartialEq)]
pub struct BRegMetadataOperation {
    id: String,
    method: String,
    path: String,
    kind: BRegOperationKind,
    source_entity: String,
    response_entity: String,
    access_profile: String,
    required_capabilities: Vec<String>,
    fields: Vec<BRegMetadataField>,
    readable_fields: Vec<String>,
    readable_request_fields: Vec<String>,
    create_writable_fields: Vec<String>,
    patch_writable_fields: Vec<String>,
    request: BRegOperationRequest,
    entity_label: String,
    title_fields: Vec<String>,
    query: Option<BRegQueryDescriptor>,
    selectors: Vec<BRegLookupSelectorDescriptor>,
    read_path: Option<BRegReadPathDescriptor>,
}

impl BRegMetadataOperation {
    #[must_use]
    pub fn entity_label(&self) -> &str {
        &self.entity_label
    }
    #[must_use]
    pub fn title_fields(&self) -> &[String] {
        &self.title_fields
    }
    #[must_use]
    pub fn query(&self) -> Option<&BRegQueryDescriptor> {
        self.query.as_ref()
    }

    #[must_use]
    pub fn selectors(&self) -> &[BRegLookupSelectorDescriptor] {
        &self.selectors
    }

    #[must_use]
    pub const fn read_path(&self) -> Option<&BRegReadPathDescriptor> {
        self.read_path.as_ref()
    }

    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn kind(&self) -> &BRegOperationKind {
        &self.kind
    }

    #[must_use]
    pub fn source_entity(&self) -> &str {
        &self.source_entity
    }

    #[must_use]
    pub fn response_entity(&self) -> &str {
        &self.response_entity
    }

    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }

    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    #[must_use]
    pub fn fields(&self) -> &[BRegMetadataField] {
        &self.fields
    }

    #[must_use]
    pub fn readable_fields(&self) -> &[String] {
        &self.readable_fields
    }

    /// Change-request metadata this operation's profile may read, such as
    /// `review_state`. An engine that predates the grant projection names
    /// none, so a caller that needs one refuses rather than assumes it.
    #[must_use]
    pub fn readable_request_fields(&self) -> &[String] {
        &self.readable_request_fields
    }

    #[must_use]
    pub fn create_writable_fields(&self) -> &[String] {
        &self.create_writable_fields
    }

    #[must_use]
    pub fn patch_writable_fields(&self) -> &[String] {
        &self.patch_writable_fields
    }

    #[must_use]
    pub fn request(&self) -> &BRegOperationRequest {
        &self.request
    }
}

impl fmt::Debug for BRegMetadataOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegMetadataOperation")
            .field("kind", &self.kind)
            .field(
                "required_capability_count",
                &self.required_capabilities.len(),
            )
            .field("field_count", &self.fields.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq)]
struct BRegMetadataEntity {
    id: String,
    dataset_identifier: String,
    route: String,
    schema_path: String,
    operations: Vec<(BRegOperationKind, String)>,
    readable_fields: Vec<String>,
    change_control: Option<Value>,
    change_request: Option<BRegChangeRequestCapability>,
}

/// One typed input advertised by a caller-visible immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionInputDescriptor {
    id: String,
    api_name: String,
    field_type: Value,
    required: bool,
    nullable: Option<bool>,
    classification: String,
}

impl BRegImmediateActionInputDescriptor {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    #[must_use]
    pub fn field_type(&self) -> &Value {
        &self.field_type
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
    #[must_use]
    pub const fn nullable(&self) -> Option<bool> {
        self.nullable
    }
    #[must_use]
    pub fn classification(&self) -> &str {
        &self.classification
    }
}

impl fmt::Debug for BRegImmediateActionInputDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegImmediateActionInputDescriptor")
            .field("required", &self.required)
            .field("nullable", &self.nullable)
            .finish_non_exhaustive()
    }
}

/// A typed immediate-action input that references one entity.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionReferenceInputDescriptor {
    input: String,
    api_name: String,
    target_entity: String,
}

impl BRegImmediateActionReferenceInputDescriptor {
    #[must_use]
    pub fn input_identifier(&self) -> &str {
        &self.input
    }
    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    #[must_use]
    pub fn target_entity(&self) -> &str {
        &self.target_entity
    }
}

/// One caller-visible result effect from an immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionResultEffectDescriptor {
    effect: String,
    entity: String,
    operation: BRegOperationKind,
}

impl BRegImmediateActionResultEffectDescriptor {
    #[must_use]
    pub fn effect_identifier(&self) -> &str {
        &self.effect
    }
    #[must_use]
    pub fn entity_identifier(&self) -> &str {
        &self.entity
    }
    #[must_use]
    pub const fn operation(&self) -> &BRegOperationKind {
        &self.operation
    }
}

/// Resource ceilings advertised for an immediate action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BRegImmediateActionBounds {
    maximum_targets: u64,
    maximum_field_mutations: u64,
    maximum_snapshot_bytes: u64,
}

impl BRegImmediateActionBounds {
    #[must_use]
    pub const fn maximum_targets(self) -> u64 {
        self.maximum_targets
    }
    #[must_use]
    pub const fn maximum_field_mutations(self) -> u64 {
        self.maximum_field_mutations
    }
    #[must_use]
    pub const fn maximum_snapshot_bytes(self) -> u64 {
        self.maximum_snapshot_bytes
    }
}

/// Complete descriptive metadata for one caller-visible immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionDescriptor {
    id: String,
    route: String,
    condition_route: Option<String>,
    contract_fingerprint: String,
    input_mode: Option<String>,
    maximum_input_string_bytes: Option<u64>,
    inputs: Vec<BRegImmediateActionInputDescriptor>,
    reference_inputs: Vec<BRegImmediateActionReferenceInputDescriptor>,
    required_condition_keys: Vec<String>,
    result_effects: Vec<BRegImmediateActionResultEffectDescriptor>,
    access_profile: String,
    invoke_path: String,
    target_conditions_path: Option<String>,
    bounds: BRegImmediateActionBounds,
}

impl BRegImmediateActionDescriptor {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn contract_fingerprint(&self) -> &str {
        &self.contract_fingerprint
    }
    #[must_use]
    pub fn input_mode(&self) -> Option<&str> {
        self.input_mode.as_deref()
    }
    #[must_use]
    pub const fn maximum_input_string_bytes(&self) -> Option<u64> {
        self.maximum_input_string_bytes
    }
    #[must_use]
    pub fn inputs(&self) -> &[BRegImmediateActionInputDescriptor] {
        &self.inputs
    }
    #[must_use]
    pub fn reference_inputs(&self) -> &[BRegImmediateActionReferenceInputDescriptor] {
        &self.reference_inputs
    }
    #[must_use]
    pub fn required_condition_keys(&self) -> &[String] {
        &self.required_condition_keys
    }
    #[must_use]
    pub fn result_effects(&self) -> &[BRegImmediateActionResultEffectDescriptor] {
        &self.result_effects
    }
    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }
    #[must_use]
    pub fn invoke_path(&self) -> &str {
        &self.invoke_path
    }
    #[must_use]
    pub fn target_conditions_path(&self) -> Option<&str> {
        self.target_conditions_path.as_deref()
    }
    #[must_use]
    pub const fn bounds(&self) -> BRegImmediateActionBounds {
        self.bounds
    }
}

impl fmt::Debug for BRegImmediateActionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegImmediateActionDescriptor")
            .field("input_count", &self.inputs.len())
            .field("result_effect_count", &self.result_effects.len())
            .finish_non_exhaustive()
    }
}

/// Validated Base Registry Engine runtime metadata v1 for one caller projection.
#[derive(Clone, PartialEq)]
pub struct BRegMetadata {
    id: String,
    version: String,
    revision: String,
    entities: Vec<BRegMetadataEntity>,
    operations: Vec<BRegMetadataOperation>,
    actions: Option<Value>,
    immediate_actions: Vec<BRegImmediateActionDescriptor>,
    source_binding: Option<String>,
}

impl BRegMetadata {
    /// Parse exact runtime metadata v1 bytes using duplicate-key detection and
    /// resource bounds before interpreting any operation as authority.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BRegMetadataError> {
        if bytes.len() > MAX_BREG_METADATA_BYTES {
            return Err(metadata_error(BRegMetadataErrorKind::Size));
        }
        let value = decode_unique_json(bytes)?;
        validate_value_bounds(&value)?;
        crate::strict_json::validate_number_tokens(bytes)
            .map_err(|()| metadata_error(BRegMetadataErrorKind::Json))?;
        parse_metadata(value)
    }

    #[must_use]
    pub fn registry_identifier(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn registry_version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn operations(&self) -> &[BRegMetadataOperation] {
        &self.operations
    }

    #[must_use]
    pub fn operation(&self, operation_identifier: &str) -> Option<&BRegMetadataOperation> {
        self.operations
            .iter()
            .find(|operation| operation.id == operation_identifier)
    }

    /// Returns caller-filtered descriptive change-request capability metadata.
    /// Executable authority still comes only from [`Self::select_lifecycle`].
    #[must_use]
    pub fn change_request_capability(
        &self,
        entity_identifier: &str,
    ) -> Option<&BRegChangeRequestCapability> {
        self.entities
            .iter()
            .find(|entity| entity.id == entity_identifier)
            .and_then(|entity| entity.change_request.as_ref())
    }

    /// Returns caller-filtered immediate-action metadata as a bounded inert
    /// JSON value. A separate action contract validator must promote it before
    /// invocation.
    #[must_use]
    pub fn actions(&self) -> Option<&Value> {
        self.actions.as_ref()
    }

    /// Returns complete typed caller-filtered immediate-action descriptors.
    #[must_use]
    pub fn immediate_actions(&self) -> &[BRegImmediateActionDescriptor] {
        &self.immediate_actions
    }

    /// Promote one complete caller-visible immediate-action contract.
    pub fn select_immediate_action(
        &self,
        action_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegImmediateActionBinding, BRegMetadataSelectionError> {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let action = self
            .immediate_actions
            .iter()
            .find(|action| action.id == action_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        if action.access_profile != expected_profile {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ProfileMismatch,
            ));
        }
        let semantics_are_exact = match action.input_mode.as_deref() {
            Some("fixed") => {
                action.maximum_input_string_bytes.is_none()
                    && action
                        .inputs
                        .iter()
                        .all(|input| input.nullable == Some(false))
            }
            Some("handler") => {
                action.maximum_input_string_bytes == Some(16_384)
                    && action
                        .inputs
                        .iter()
                        .all(|input| input.nullable == Some(!input.required))
            }
            _ => false,
        };
        if !semantics_are_exact || !immediate_action_contract_is_exact(action) {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }
        Ok(BRegImmediateActionBinding::from_descriptor(
            self.revision.clone(),
            source_binding.clone(),
            action,
        ))
    }

    /// Promote one exact direct Tombstone contract.
    pub fn select_tombstone(
        &self,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegTombstoneBinding, BRegMetadataSelectionError> {
        let (entity, operation, source_binding) = self.select_mutation_operation(
            entity_identifier,
            expected_profile,
            BRegOperationKind::Tombstone,
        )?;
        let collection_path = format!("/v1/records/{}", entity.route);
        let request = &operation.request;
        if operation.id != format!("records.{}.tombstone", entity.id)
            || operation.method != "DELETE"
            || operation.path != format!("{collection_path}/{{record_id}}")
            || request.field_names.as_deref() != Some("api")
            || !request.query_parameters.is_empty()
            || request.body.as_deref() != Some("none")
            || request.content_type.is_some()
            || request.schema.is_some()
            || request.idempotency_key_required != Some(true)
            || request.if_match_required != Some(true)
            || request.mutation_semantics.as_deref() != Some("direct")
            || request.maximum_items.is_some()
            || request.maximum_body_bytes.is_some()
            || request.allow_create.is_some()
            || request.allow_patch.is_some()
            || request.patch_path_prefix.is_some()
            || !request.patch_operations.is_empty()
            || request.remove_semantics.is_some()
            || !operation.create_writable_fields.is_empty()
            || !operation.patch_writable_fields.is_empty()
        {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }
        Ok(BRegTombstoneBinding {
            common: BRegMutationBinding::new(
                self,
                entity,
                operation,
                collection_path,
                None,
                source_binding,
            ),
        })
    }

    /// Promote one exact caller-visible atomic Batch contract.
    pub fn select_batch(
        &self,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegBatchBinding, BRegMetadataSelectionError> {
        let (entity, operation, source_binding) = self.select_mutation_operation(
            entity_identifier,
            expected_profile,
            BRegOperationKind::Batch,
        )?;
        let collection_path = format!("/v1/records/{}", entity.route);
        let request = &operation.request;
        let (Some(maximum_items), Some(maximum_bytes), Some(schema)) = (
            request.maximum_items,
            request.maximum_body_bytes,
            request.schema.clone(),
        ) else {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        };
        let (Some(allow_create), Some(allow_patch)) = (request.allow_create, request.allow_patch)
        else {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        };
        if operation.id != format!("records.{}.batch", entity.id)
            || operation.method != "POST"
            || operation.path != format!("{collection_path}:batch")
            || request.field_names.as_deref() != Some("api")
            || !request.query_parameters.is_empty()
            || request.body.as_deref() != Some("batch")
            || request.content_type.as_deref() != Some("application/json")
            || request.idempotency_key_required != Some(true)
            || request.if_match_required.is_some()
            || request.mutation_semantics.as_deref() != Some("direct")
            || request.patch_path_prefix.is_some()
            || !request.patch_operations.is_empty()
            || request.remove_semantics.is_some()
            || maximum_items > u64::from(u16::MAX)
            || (!allow_create && !allow_patch)
            || !batch_schema_operations_are_exact(&schema, maximum_items, allow_create, allow_patch)
        {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }
        Ok(BRegBatchBinding {
            common: BRegMutationBinding::new(
                self,
                entity,
                operation,
                collection_path,
                Some(schema),
                source_binding,
            ),
            maximum_items,
            maximum_bytes,
            allow_create,
            allow_patch,
            readable_api_names: api_names_for(operation, &operation.readable_fields),
            create_writable_api_names: api_names_for(operation, &operation.create_writable_fields),
            required_create_api_names: operation
                .fields
                .iter()
                .filter(|field| {
                    field.required && operation.create_writable_fields.contains(&field.id)
                })
                .map(|field| field.api_name.clone())
                .collect(),
            patch_writable_api_names: api_names_for(operation, &operation.patch_writable_fields),
            removable_api_names: operation
                .fields
                .iter()
                .filter(|field| {
                    field.removable && operation.patch_writable_fields.contains(&field.id)
                })
                .map(|field| field.api_name.clone())
                .collect(),
        })
    }

    fn select_mutation_operation(
        &self,
        entity_identifier: &str,
        expected_profile: &str,
        expected_kind: BRegOperationKind,
    ) -> Result<(&BRegMetadataEntity, &BRegMetadataOperation, String), BRegMetadataSelectionError>
    {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let entity = self
            .entities
            .iter()
            .find(|entity| entity.id == entity_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        let mut operations = self.operations.iter().filter(|operation| {
            operation.source_entity == entity.id && operation.kind == expected_kind
        });
        let operation = operations
            .find(|operation| operation.access_profile == expected_profile)
            .ok_or_else(|| {
                if self.operations.iter().any(|operation| {
                    operation.source_entity == entity.id && operation.kind == expected_kind
                }) {
                    selection_error(BRegMetadataSelectionErrorKind::ProfileMismatch)
                } else {
                    selection_error(BRegMetadataSelectionErrorKind::NotFound)
                }
            })?;
        if operation.response_entity != entity.id || !operation.required_capabilities.is_empty() {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }
        Ok((entity, operation, source_binding.clone()))
    }

    /// Attach the canonical client source after transport has fetched this
    /// caller-filtered document. Parsing alone never creates execution
    /// authority.
    pub(crate) fn bind_source(mut self, source: String) -> Self {
        self.source_binding = Some(source);
        self
    }

    /// Promote exactly one complete direct Create or PATCH contract into a
    /// non-forgeable executable binding.
    pub fn select_direct_write(
        &self,
        operation_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegDirectWrite, BRegMetadataSelectionError> {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let operation = self
            .operation(operation_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        if operation.access_profile != expected_profile {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ProfileMismatch,
            ));
        }
        if !operation.required_capabilities.is_empty() {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::RequiredCapability,
            ));
        }
        let entity = self
            .entities
            .iter()
            .find(|entity| entity.id == operation.source_entity)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))?;
        if operation.response_entity != entity.id {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }

        let expected_collection_path = format!("/v1/records/{}", entity.route);
        let request = &operation.request;
        let common = || BRegDirectWriteBinding {
            registry_identifier: self.id.clone(),
            dataset_identifier: entity.dataset_identifier.clone(),
            registry_revision: self.revision.clone(),
            operation_identifier: operation.id.clone(),
            access_profile: operation.access_profile.clone(),
            entity_identifier: entity.id.clone(),
            collection_path: expected_collection_path.clone(),
            request_schema: request.schema.clone().expect("checked direct schema"),
            source_binding: source_binding.clone(),
        };

        match operation.kind {
            BRegOperationKind::Create
                if operation.method == "POST"
                    && operation.id == format!("records.{}.create", entity.id)
                    && operation.path == expected_collection_path
                    && request.field_names.as_deref() == Some("api")
                    && request.query_parameters.is_empty()
                    && request.body.as_deref() == Some("data_envelope")
                    && request.content_type.as_deref() == Some("application/json")
                    && request.schema.is_some()
                    && request.idempotency_key_required == Some(true)
                    && request.if_match_required.is_none()
                    && request.mutation_semantics.as_deref() == Some("direct")
                    && request.patch_path_prefix.is_none()
                    && request.patch_operations.is_empty()
                    && request.remove_semantics.is_none()
                    && request.maximum_items.is_none()
                    && request.maximum_body_bytes.is_none()
                    && request.allow_create.is_none()
                    && request.allow_patch.is_none()
                    && !operation.create_writable_fields.is_empty()
                    && operation.patch_writable_fields.is_empty() =>
            {
                Ok(BRegDirectWrite::Create(BRegCreateBinding {
                    common: common(),
                    writable_api_names: api_names_for(operation, &operation.create_writable_fields),
                    required_api_names: operation
                        .fields
                        .iter()
                        .filter(|field| {
                            field.required
                                && operation
                                    .create_writable_fields
                                    .iter()
                                    .any(|writable| writable == &field.id)
                        })
                        .map(|field| field.api_name.clone())
                        .collect(),
                }))
            }
            BRegOperationKind::Patch
                if operation.method == "PATCH"
                    && operation.id == format!("records.{}.patch", entity.id)
                    && operation.path == format!("{expected_collection_path}/{{record_id}}")
                    && request.field_names.as_deref() == Some("api")
                    && request.query_parameters.is_empty()
                    && request.body.as_deref() == Some("json_patch")
                    && request.content_type.as_deref() == Some("application/json-patch+json")
                    && request.schema.is_some()
                    && request.idempotency_key_required == Some(true)
                    && request.if_match_required == Some(true)
                    && request.mutation_semantics.as_deref() == Some("direct")
                    && request.patch_path_prefix.as_deref() == Some("/data/")
                    && request.patch_operations == ["add", "replace", "remove", "test"]
                    && request.remove_semantics.as_deref() == Some("set_null")
                    && request.maximum_items.is_none()
                    && request.maximum_body_bytes.is_none()
                    && request.allow_create.is_none()
                    && request.allow_patch.is_none()
                    && operation.create_writable_fields.is_empty()
                    && !operation.patch_writable_fields.is_empty() =>
            {
                Ok(BRegDirectWrite::Patch(BRegPatchBinding {
                    common: common(),
                    readable_api_names: api_names_for(operation, &operation.readable_fields),
                    writable_api_names: api_names_for(operation, &operation.patch_writable_fields),
                    removable_api_names: operation
                        .fields
                        .iter()
                        .filter(|field| {
                            field.removable
                                && operation
                                    .patch_writable_fields
                                    .iter()
                                    .any(|writable| writable == &field.id)
                        })
                        .map(|field| field.api_name.clone())
                        .collect(),
                }))
            }
            BRegOperationKind::Create | BRegOperationKind::Patch => Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            )),
            _ => Err(selection_error(
                BRegMetadataSelectionErrorKind::UnsupportedOperation,
            )),
        }
    }

    /// Promote the complete set of caller-visible lifecycle routes for one
    /// request entity and one exact selected access profile.
    pub fn select_lifecycle(
        &self,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> Result<crate::BRegLifecycleAuthority, BRegMetadataSelectionError> {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let entity = self
            .entities
            .iter()
            .find(|entity| entity.id == entity_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        let entity_lifecycle = self
            .operations
            .iter()
            .filter_map(|operation| {
                lifecycle_operation(&operation.kind).map(|kind| (operation, kind))
            })
            .filter(|(operation, _)| operation.source_entity == entity.id)
            .collect::<Vec<_>>();
        if entity_lifecycle.is_empty() {
            return Err(selection_error(BRegMetadataSelectionErrorKind::NotFound));
        }
        let candidates = entity_lifecycle
            .into_iter()
            .filter(|(operation, _)| operation.access_profile == expected_profile)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ProfileMismatch,
            ));
        }

        let base_path = format!("/v1/records/{}/{{record_id}}/actions", entity.route);
        let mut bindings = Vec::with_capacity(candidates.len());
        for (operation, kind) in candidates {
            if operation.response_entity != entity.id
                || operation.method != "POST"
                || operation.required_capabilities != ["change_request_lifecycle"]
                || !operation.create_writable_fields.is_empty()
                || !operation.patch_writable_fields.is_empty()
                || !lifecycle_request_is_exact(operation, kind)
            {
                return Err(selection_error(
                    BRegMetadataSelectionErrorKind::ContractMismatch,
                ));
            }
            let stage = lifecycle_route_stage(operation, kind, &base_path, &entity.id)?;
            bindings.push(crate::BRegLifecycleOperationBinding::new(
                kind,
                operation.path.clone(),
                stage,
            ));
        }

        crate::BRegLifecycleAuthority::new(
            self.id.clone(),
            entity.dataset_identifier.clone(),
            self.revision.clone(),
            entity.id.clone(),
            expected_profile.to_owned(),
            source_binding.clone(),
            bindings,
        )
        .map_err(|_| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))
    }

    /// Promote every caller-visible attachment slot on one entity for one exact
    /// selected access profile.
    ///
    /// The engine repeats the same slot capability on every surface that
    /// carries the slot, so a slot promotes only when each surface agrees
    /// exactly and every advertised route matches that slot's own route.
    pub fn select_attachments(
        &self,
        entity_identifier: &str,
        expected_profile: &str,
    ) -> Result<Vec<crate::BRegAttachmentSlot>, BRegMetadataSelectionError> {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let entity = self
            .entities
            .iter()
            .find(|entity| entity.id == entity_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        let carrying = self
            .operations
            .iter()
            .filter(|operation| {
                operation.source_entity == entity.id
                    && operation.response_entity == entity.id
                    && operation.fields.iter().any(attachment_capability_present)
            })
            .collect::<Vec<_>>();
        if carrying.is_empty() {
            return Err(selection_error(BRegMetadataSelectionErrorKind::NotFound));
        }
        let candidates = carrying
            .into_iter()
            .filter(|operation| operation.access_profile == expected_profile)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ProfileMismatch,
            ));
        }

        let source = crate::BRegAttachmentSource {
            registry_identifier: self.id.clone(),
            dataset_identifier: entity.dataset_identifier.clone(),
            registry_revision: self.revision.clone(),
            entity_identifier: entity.id.clone(),
            access_profile: expected_profile.to_owned(),
            collection_path: format!("/v1/records/{}", entity.route),
            source_binding: source_binding.clone(),
        };
        let mut descriptors: BTreeMap<&str, &Value> = BTreeMap::new();
        for operation in candidates {
            for field in operation.fields.iter().filter(|field| {
                attachment_capability_present(field)
                    && operation.readable_fields.contains(&field.id)
            }) {
                let descriptor = &field.schema["x-registry-attachment"];
                if descriptors
                    .insert(field.id.as_str(), descriptor)
                    .is_some_and(|previous| previous != descriptor)
                {
                    return Err(selection_error(
                        BRegMetadataSelectionErrorKind::ContractMismatch,
                    ));
                }
            }
        }
        if descriptors.is_empty() {
            return Err(selection_error(BRegMetadataSelectionErrorKind::NotFound));
        }
        descriptors
            .into_iter()
            .map(|(slot_identifier, descriptor)| {
                crate::BRegAttachmentSlot::from_descriptor(&source, slot_identifier, descriptor)
                    .map_err(|_| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))
            })
            .collect()
    }
}

fn immediate_action_contract_is_exact(action: &BRegImmediateActionDescriptor) -> bool {
    if action.invoke_path != format!("/v1/actions/{}", action.id)
        || action.bounds.maximum_targets > MAX_SUPPORTED_ACTION_TARGETS
        || action.bounds.maximum_field_mutations > MAX_SUPPORTED_ACTION_FIELD_MUTATIONS
        || action.bounds.maximum_snapshot_bytes > MAX_SUPPORTED_ACTION_SNAPSHOT_BYTES
        || action.result_effects.len() > action.bounds.maximum_targets as usize
        || action.result_effects.iter().any(|effect| {
            !matches!(
                effect.operation,
                BRegOperationKind::Create | BRegOperationKind::Patch
            )
        })
        || action
            .inputs
            .iter()
            .any(|input| !action_field_type_is_exact(&input.field_type))
    {
        return false;
    }
    match &action.target_conditions_path {
        Some(path) if path != &format!("{}/target-conditions", action.invoke_path) => return false,
        None if !action.required_condition_keys.is_empty() => return false,
        _ => {}
    }
    for reference in &action.reference_inputs {
        let Some(input) = action
            .inputs
            .iter()
            .find(|input| input.id == reference.input && input.api_name == reference.api_name)
        else {
            return false;
        };
        if input.field_type.get("type").and_then(Value::as_str) != Some("reference")
            || input.field_type.get("target").and_then(Value::as_str)
                != Some(reference.target_entity.as_str())
        {
            return false;
        }
    }
    action.required_condition_keys.iter().all(|key| {
        let Some(reference) = action
            .reference_inputs
            .iter()
            .find(|reference| reference.api_name == *key)
        else {
            return false;
        };
        action.inputs.iter().any(|input| {
            input.id == reference.input
                && input.api_name == reference.api_name
                && input.required
                && input.nullable == Some(false)
        })
    })
}

fn action_field_type_is_exact(value: &Value) -> bool {
    action_field_type(value.clone()).is_ok()
}

fn action_field_type(value: Value) -> Result<(), BRegMetadataError> {
    let mut field_type = object(value)?;
    let kind = string(required(&mut field_type, "type")?)?;
    match kind.as_str() {
        "boolean" | "int64" | "date" | "timestamp" | "uuid" => {}
        "string" => {
            let minimum = required(&mut field_type, "minLength")?
                .as_u64()
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
            let maximum = positive_integer(required(&mut field_type, "maxLength")?)?;
            if maximum > 1_000_000 || minimum > maximum {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "text" => {
            if positive_integer(required(&mut field_type, "maxLength")?)? > 10_000_000 {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "decimal" => {
            let precision = positive_integer(required(&mut field_type, "precision")?)?;
            let scale = required(&mut field_type, "scale")?
                .as_u64()
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
            let minimum = optional_string(&mut field_type, "minimum")?;
            let maximum = optional_string(&mut field_type, "maximum")?;
            if precision > 38 || scale > precision {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            let minimum = minimum
                .as_deref()
                .map(|value| action_decimal_scaled_value(value, precision, scale))
                .transpose()?;
            let maximum = maximum
                .as_deref()
                .map(|value| action_decimal_scaled_value(value, precision, scale))
                .transpose()?;
            if minimum
                .zip(maximum)
                .is_some_and(|(minimum, maximum)| minimum > maximum)
            {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "vocabulary-code" => {
            identifier(required(&mut field_type, "vocabulary")?)?;
            let values = identifier_array(required(&mut field_type, "values")?)?;
            if values.is_empty() || ensure_unique(values.iter().map(String::as_str)).is_err() {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "reference" => {
            identifier(required(&mut field_type, "target")?)?;
            let on_delete = string(required(&mut field_type, "onDelete")?)?;
            if on_delete != "restrict" {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "crs84-point" => {
            let precision = required(&mut field_type, "precision")?
                .as_u64()
                .filter(|precision| *precision <= 9)
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
            if let Some(bbox) = field_type.remove("bbox") {
                validate_action_bbox(bbox, precision)?;
            }
        }
        "structured" => {
            let max_bytes = positive_integer(required(&mut field_type, "maxBytes")?)?;
            if max_bytes > 1_048_576
                || !valid_action_structured_schema(required(&mut field_type, "schema")?)
            {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        _ => return Err(metadata_error(BRegMetadataErrorKind::Shape)),
    }
    finish(field_type)
}

fn valid_action_structured_schema(schema: Value) -> bool {
    schema.as_object().is_some_and(|object| {
        (action_schema_declares_object(object)
            && object.get("additionalProperties") == Some(&Value::Bool(false)))
            || (object.get("type") == Some(&Value::String("array".to_owned()))
                && object.get("items").is_some_and(Value::is_object))
    }) && registry_platform_canonical_json::canonicalize_json(&schema)
        .is_ok_and(|bytes| bytes.len() <= 64 * 1024)
        && action_schema_refs_are_local(&schema)
        && action_object_schemas_are_closed(&schema)
        && JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .is_ok()
}

fn action_schema_declares_object(object: &Map<String, Value>) -> bool {
    object.get("type").is_some_and(|kind| {
        kind == "object"
            || kind
                .as_array()
                .is_some_and(|types| types.iter().any(|kind| kind == "object"))
    })
}

fn action_schema_refs_are_local(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/"))
            } else {
                action_schema_refs_are_local(value)
            }
        }),
        Value::Array(values) => values.iter().all(action_schema_refs_are_local),
        _ => true,
    }
}

fn action_object_schemas_are_closed(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let describes_object = object.get("properties").is_some()
                || object.get("patternProperties").is_some()
                || action_schema_declares_object(object);
            (!describes_object || object.get("additionalProperties") == Some(&Value::Bool(false)))
                && object.values().all(action_object_schemas_are_closed)
        }
        Value::Array(values) => values.iter().all(action_object_schemas_are_closed),
        _ => true,
    }
}

fn action_decimal_scaled_value(
    value: &str,
    precision: u64,
    scale: u64,
) -> Result<i128, BRegMetadataError> {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = if scale == 0 {
        (unsigned, "")
    } else {
        unsigned
            .split_once('.')
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?
    };
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.len() != scale as usize
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || integer != "0" && integer.len() > (precision - scale) as usize
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let digits = format!("{integer}{fraction}");
    let magnitude = digits
        .parse::<i128>()
        .map_err(|_| metadata_error(BRegMetadataErrorKind::Shape))?;
    Ok(if value.starts_with('-') {
        -magnitude
    } else {
        magnitude
    })
}

fn validate_action_bbox(value: Value, precision: u64) -> Result<(), BRegMetadataError> {
    let mut bbox = object(value)?;
    let west = action_coordinate(required(&mut bbox, "west")?, precision, -180.0, 180.0)?;
    let south = action_coordinate(required(&mut bbox, "south")?, precision, -90.0, 90.0)?;
    let east = action_coordinate(required(&mut bbox, "east")?, precision, -180.0, 180.0)?;
    let north = action_coordinate(required(&mut bbox, "north")?, precision, -90.0, 90.0)?;
    if west > east || south > north {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    finish(bbox)
}

fn action_coordinate(
    value: Value,
    precision: u64,
    minimum: f64,
    maximum: f64,
) -> Result<f64, BRegMetadataError> {
    let value = string(value)?;
    let fraction_digits = value
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    value
        .parse::<f64>()
        .ok()
        .filter(|number| {
            number.is_finite()
                && *number >= minimum
                && *number <= maximum
                && fraction_digits <= precision as usize
        })
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn attachment_capability_present(field: &BRegMetadataField) -> bool {
    field
        .schema
        .get("x-registry-fieldKind")
        .and_then(Value::as_str)
        == Some("attachment")
        && field.schema.get("x-registry-attachment").is_some()
}

fn batch_schema_operations_are_exact(
    schema: &Value,
    maximum_items: u64,
    allow_create: bool,
    allow_patch: bool,
) -> bool {
    let Some(items) = schema
        .get("properties")
        .and_then(|properties| properties.get("items"))
    else {
        return false;
    };
    if items.get("minItems").and_then(Value::as_u64) != Some(1)
        || items.get("maxItems").and_then(Value::as_u64) != Some(maximum_items)
    {
        return false;
    }
    let Some(variants) = items
        .get("items")
        .and_then(|item| item.get("oneOf"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    let operations = variants
        .iter()
        .filter_map(|variant| {
            variant
                .get("properties")?
                .get("operation")?
                .get("const")?
                .as_str()
        })
        .collect::<BTreeSet<_>>();
    operations.len() == variants.len()
        && operations.contains("create") == allow_create
        && operations.contains("patch") == allow_patch
        && operations.len() == usize::from(allow_create) + usize::from(allow_patch)
}

impl fmt::Debug for BRegMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegMetadata")
            .field("entity_count", &self.entities.len())
            .field("operation_count", &self.operations.len())
            .field("has_actions", &self.actions.is_some())
            .finish_non_exhaustive()
    }
}

/// Why an authoritative operation could not become an executable direct-write
/// binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegMetadataSelectionErrorKind {
    NotFound,
    UnboundSource,
    ProfileMismatch,
    UnsupportedOperation,
    RequiredCapability,
    ContractMismatch,
}

/// Value-free direct-write selection failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BRegMetadataSelectionError {
    kind: BRegMetadataSelectionErrorKind,
}

impl BRegMetadataSelectionError {
    #[must_use]
    pub fn kind(self) -> BRegMetadataSelectionErrorKind {
        self.kind
    }
}

impl fmt::Debug for BRegMetadataSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegMetadataSelectionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for BRegMetadataSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Base Registry Engine operation is not executable")
    }
}

impl std::error::Error for BRegMetadataSelectionError {}

/// Exact input contract retained by an immediate-action binding.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionInputBinding {
    api_name: String,
    required: bool,
    nullable: bool,
    field_type: Value,
}

impl BRegImmediateActionInputBinding {
    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
    #[must_use]
    pub const fn nullable(&self) -> bool {
        self.nullable
    }
    #[must_use]
    pub fn field_type(&self) -> &Value {
        &self.field_type
    }
}

/// Opaque executable binding for one exact caller-visible immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegImmediateActionBinding {
    action_identifier: String,
    registry_revision: String,
    access_profile: String,
    invoke_path: String,
    target_conditions_path: Option<String>,
    contract_fingerprint: String,
    required_condition_keys: BTreeSet<String>,
    result_effects: BTreeMap<String, String>,
    inputs: Vec<BRegImmediateActionInputBinding>,
    reference_inputs: Vec<BRegImmediateActionReferenceInputDescriptor>,
    bounds: BRegImmediateActionBounds,
    handler: bool,
    maximum_input_string_bytes: Option<u64>,
    source_binding: String,
}

impl BRegImmediateActionBinding {
    fn from_descriptor(
        registry_revision: String,
        source_binding: String,
        action: &BRegImmediateActionDescriptor,
    ) -> Self {
        Self {
            action_identifier: action.id.clone(),
            registry_revision,
            access_profile: action.access_profile.clone(),
            invoke_path: action.invoke_path.clone(),
            target_conditions_path: action.target_conditions_path.clone(),
            contract_fingerprint: action.contract_fingerprint.clone(),
            required_condition_keys: action.required_condition_keys.iter().cloned().collect(),
            result_effects: action
                .result_effects
                .iter()
                .map(|effect| (effect.effect.clone(), effect.entity.clone()))
                .collect(),
            inputs: action
                .inputs
                .iter()
                .map(|input| BRegImmediateActionInputBinding {
                    api_name: input.api_name.clone(),
                    required: input.required,
                    nullable: input
                        .nullable
                        .expect("selection checked nullable semantics"),
                    field_type: input.field_type.clone(),
                })
                .collect(),
            reference_inputs: action.reference_inputs.clone(),
            bounds: action.bounds,
            handler: action.input_mode.as_deref() == Some("handler"),
            maximum_input_string_bytes: action.maximum_input_string_bytes,
            source_binding,
        }
    }

    #[must_use]
    pub fn action_identifier(&self) -> &str {
        &self.action_identifier
    }
    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }
    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }
    #[must_use]
    pub fn invoke_path(&self) -> &str {
        &self.invoke_path
    }
    #[must_use]
    pub fn target_conditions_path(&self) -> Option<&str> {
        self.target_conditions_path.as_deref()
    }
    #[must_use]
    pub fn contract_fingerprint(&self) -> &str {
        &self.contract_fingerprint
    }
    #[must_use]
    pub const fn bounds(&self) -> BRegImmediateActionBounds {
        self.bounds
    }
    #[must_use]
    pub const fn is_handler(&self) -> bool {
        self.handler
    }
    #[must_use]
    pub const fn maximum_input_string_bytes(&self) -> Option<u64> {
        self.maximum_input_string_bytes
    }
    #[must_use]
    pub(crate) fn required_condition_keys(&self) -> &BTreeSet<String> {
        &self.required_condition_keys
    }
    #[must_use]
    pub(crate) fn result_effects(&self) -> &BTreeMap<String, String> {
        &self.result_effects
    }
    #[must_use]
    pub(crate) fn inputs(&self) -> &[BRegImmediateActionInputBinding] {
        &self.inputs
    }
    #[must_use]
    pub(crate) fn reference_inputs(&self) -> &[BRegImmediateActionReferenceInputDescriptor] {
        &self.reference_inputs
    }
    #[must_use]
    pub(crate) fn matches_source(&self, source: &str) -> bool {
        self.source_binding == source
    }
    #[must_use]
    pub(crate) fn source_binding(&self) -> &str {
        &self.source_binding
    }
}

impl fmt::Debug for BRegImmediateActionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegImmediateActionBinding(<bound>)")
    }
}

#[derive(Clone, PartialEq)]
struct BRegMutationBinding {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    operation_identifier: String,
    access_profile: String,
    entity_identifier: String,
    collection_path: String,
    request_schema: Option<Value>,
    source_binding: String,
}

impl BRegMutationBinding {
    fn new(
        metadata: &BRegMetadata,
        entity: &BRegMetadataEntity,
        operation: &BRegMetadataOperation,
        collection_path: String,
        request_schema: Option<Value>,
        source_binding: String,
    ) -> Self {
        Self {
            registry_identifier: metadata.id.clone(),
            dataset_identifier: entity.dataset_identifier.clone(),
            registry_revision: metadata.revision.clone(),
            operation_identifier: operation.id.clone(),
            access_profile: operation.access_profile.clone(),
            entity_identifier: entity.id.clone(),
            collection_path,
            request_schema,
            source_binding,
        }
    }
}

/// Opaque executable binding for one direct Tombstone operation.
#[derive(Clone, PartialEq)]
pub struct BRegTombstoneBinding {
    common: BRegMutationBinding,
}

/// Opaque executable binding for one atomic Batch operation.
#[derive(Clone, PartialEq)]
pub struct BRegBatchBinding {
    common: BRegMutationBinding,
    maximum_items: u64,
    maximum_bytes: u64,
    allow_create: bool,
    allow_patch: bool,
    readable_api_names: BTreeSet<String>,
    create_writable_api_names: BTreeSet<String>,
    required_create_api_names: BTreeSet<String>,
    patch_writable_api_names: BTreeSet<String>,
    removable_api_names: BTreeSet<String>,
}

macro_rules! mutation_binding_accessors {
    ($binding:ty) => {
        impl $binding {
            #[must_use]
            pub fn registry_identifier(&self) -> &str {
                &self.common.registry_identifier
            }
            #[must_use]
            pub fn dataset_identifier(&self) -> &str {
                &self.common.dataset_identifier
            }
            #[must_use]
            pub fn registry_revision(&self) -> &str {
                &self.common.registry_revision
            }
            #[must_use]
            pub fn operation_identifier(&self) -> &str {
                &self.common.operation_identifier
            }
            #[must_use]
            pub fn access_profile(&self) -> &str {
                &self.common.access_profile
            }
            #[must_use]
            pub fn entity_identifier(&self) -> &str {
                &self.common.entity_identifier
            }
            #[must_use]
            pub fn request_schema(&self) -> Option<&Value> {
                self.common.request_schema.as_ref()
            }
            #[must_use]
            pub(crate) fn matches_source(&self, source: &str) -> bool {
                self.common.source_binding == source
            }
            #[must_use]
            pub(crate) fn source_binding(&self) -> &str {
                &self.common.source_binding
            }
        }
    };
}

mutation_binding_accessors!(BRegTombstoneBinding);
mutation_binding_accessors!(BRegBatchBinding);

impl BRegTombstoneBinding {
    #[must_use]
    pub fn path_for_record(&self, record_identifier: Uuid) -> String {
        format!("{}/{}", self.common.collection_path, record_identifier)
    }
}

impl BRegBatchBinding {
    #[must_use]
    pub fn path(&self) -> String {
        format!("{}:batch", self.common.collection_path)
    }
    #[must_use]
    pub const fn maximum_items(&self) -> u64 {
        self.maximum_items
    }
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
    #[must_use]
    pub const fn allows_create(&self) -> bool {
        self.allow_create
    }
    #[must_use]
    pub const fn allows_patch(&self) -> bool {
        self.allow_patch
    }
    #[must_use]
    pub(crate) fn readable_api_names(&self) -> &BTreeSet<String> {
        &self.readable_api_names
    }
    #[must_use]
    pub(crate) fn create_writable_api_names(&self) -> &BTreeSet<String> {
        &self.create_writable_api_names
    }
    #[must_use]
    pub(crate) fn required_create_api_names(&self) -> &BTreeSet<String> {
        &self.required_create_api_names
    }
    #[must_use]
    pub(crate) fn patch_writable_api_names(&self) -> &BTreeSet<String> {
        &self.patch_writable_api_names
    }
    #[must_use]
    pub(crate) fn removable_api_names(&self) -> &BTreeSet<String> {
        &self.removable_api_names
    }
}

impl fmt::Debug for BRegTombstoneBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegTombstoneBinding(<bound>)")
    }
}

impl fmt::Debug for BRegBatchBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegBatchBinding(<bound>)")
    }
}

#[derive(Clone, PartialEq)]
struct BRegDirectWriteBinding {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    operation_identifier: String,
    access_profile: String,
    entity_identifier: String,
    collection_path: String,
    request_schema: Value,
    source_binding: String,
}

/// A complete direct-write contract selected from caller-filtered metadata.
#[derive(Clone, PartialEq)]
pub enum BRegDirectWrite {
    Create(BRegCreateBinding),
    Patch(BRegPatchBinding),
}

impl fmt::Debug for BRegDirectWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Create(_) => "BRegDirectWrite::Create(<bound>)",
            Self::Patch(_) => "BRegDirectWrite::Patch(<bound>)",
        })
    }
}

/// Non-forgeable direct Create binding.
#[derive(Clone, PartialEq)]
pub struct BRegCreateBinding {
    common: BRegDirectWriteBinding,
    writable_api_names: BTreeSet<String>,
    required_api_names: BTreeSet<String>,
}

/// Non-forgeable direct PATCH binding.
#[derive(Clone, PartialEq)]
pub struct BRegPatchBinding {
    common: BRegDirectWriteBinding,
    readable_api_names: BTreeSet<String>,
    writable_api_names: BTreeSet<String>,
    removable_api_names: BTreeSet<String>,
}

macro_rules! direct_binding_accessors {
    ($binding:ty) => {
        impl $binding {
            #[must_use]
            pub fn registry_identifier(&self) -> &str {
                &self.common.registry_identifier
            }

            #[must_use]
            pub fn dataset_identifier(&self) -> &str {
                &self.common.dataset_identifier
            }

            #[must_use]
            pub fn registry_revision(&self) -> &str {
                &self.common.registry_revision
            }

            #[must_use]
            pub fn operation_identifier(&self) -> &str {
                &self.common.operation_identifier
            }

            #[must_use]
            pub fn access_profile(&self) -> &str {
                &self.common.access_profile
            }

            #[must_use]
            pub fn entity_identifier(&self) -> &str {
                &self.common.entity_identifier
            }

            #[must_use]
            pub fn request_schema(&self) -> &Value {
                &self.common.request_schema
            }

            #[must_use]
            pub(crate) fn writable_api_names(&self) -> &BTreeSet<String> {
                &self.writable_api_names
            }

            #[must_use]
            pub(crate) fn matches_source(&self, source: &str) -> bool {
                self.common.source_binding == source
            }
        }
    };
}

direct_binding_accessors!(BRegCreateBinding);
direct_binding_accessors!(BRegPatchBinding);

impl BRegCreateBinding {
    /// Exact static path from the selected Create contract.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.common.collection_path
    }

    #[must_use]
    pub(crate) fn required_api_names(&self) -> &BTreeSet<String> {
        &self.required_api_names
    }
}

impl BRegPatchBinding {
    /// Bind a typed record UUID to the one exact PATCH route. This is not a
    /// general URI-template expander.
    #[must_use]
    pub fn path_for_record(&self, record_identifier: Uuid) -> String {
        format!("{}/{}", self.common.collection_path, record_identifier)
    }

    #[must_use]
    pub(crate) fn readable_api_names(&self) -> &BTreeSet<String> {
        &self.readable_api_names
    }

    #[must_use]
    pub(crate) fn removable_api_names(&self) -> &BTreeSet<String> {
        &self.removable_api_names
    }
}

impl fmt::Debug for BRegCreateBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegCreateBinding(<bound>)")
    }
}

impl fmt::Debug for BRegPatchBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegPatchBinding(<bound>)")
    }
}

fn lifecycle_operation(operation: &BRegOperationKind) -> Option<crate::BRegLifecycleOperation> {
    use crate::BRegLifecycleOperation as Lifecycle;
    Some(match operation {
        BRegOperationKind::SubmitRequest => Lifecycle::SubmitRequest,
        BRegOperationKind::ApproveRequest => Lifecycle::ApproveRequest,
        BRegOperationKind::RejectRequest => Lifecycle::RejectRequest,
        BRegOperationKind::RequestRevision => Lifecycle::RequestRevision,
        BRegOperationKind::ReviseRequest => Lifecycle::ReviseRequest,
        BRegOperationKind::CancelRequest => Lifecycle::CancelRequest,
        BRegOperationKind::ApplyRequest => Lifecycle::ApplyRequest,
        _ => return None,
    })
}

fn lifecycle_request_is_exact(
    operation: &BRegMetadataOperation,
    kind: crate::BRegLifecycleOperation,
) -> bool {
    let request = &operation.request;
    request.field_names.as_deref() == Some("api")
        && request.query_parameters.is_empty()
        && request.body.as_deref() == Some("change_request_action")
        && request.content_type.as_deref() == Some("application/json")
        && request.idempotency_key_required == Some(true)
        && request.if_match_required == Some(true)
        && request.mutation_semantics.as_deref() == Some("change_request_lifecycle")
        && request.patch_path_prefix.is_none()
        && request.patch_operations.is_empty()
        && request.remove_semantics.is_none()
        && request.maximum_items.is_none()
        && request.maximum_body_bytes.is_none()
        && request.allow_create.is_none()
        && request.allow_patch.is_none()
        && request.schema.as_ref() == Some(&expected_lifecycle_schema(kind))
}

fn expected_lifecycle_schema(kind: crate::BRegLifecycleOperation) -> Value {
    use crate::BRegLifecycleOperation as Lifecycle;
    let mut schema = match kind {
        Lifecycle::ApproveRequest
        | Lifecycle::RejectRequest
        | Lifecycle::RequestRevision
        | Lifecycle::ApplyRequest => serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["proposalVersion", "effectDigest"],
            "properties": {
                "proposalVersion": {
                    "type": "integer", "format": "int64", "minimum": 1,
                    "maximum": u32::MAX
                },
                "effectDigest": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "description": "Digest of the immutable proposal effects displayed to the actor."
                }
            }
        }),
        Lifecycle::ReviseRequest => serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["rebase"],
            "properties": {"rebase": {"type": "boolean"}}
        }),
        Lifecycle::SubmitRequest | Lifecycle::CancelRequest => serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
    };
    if matches!(kind, Lifecycle::RejectRequest | Lifecycle::RequestRevision) {
        schema["properties"]["reason"] = serde_json::json!({"type": "string", "maxLength": 4096, "pattern": r"^[^\u0000]*$", "description": "Optional reviewer explanation, preserved unchanged. At most 4096 Unicode characters; NUL is refused."});
    }
    schema
}

fn lifecycle_route_stage(
    operation: &BRegMetadataOperation,
    kind: crate::BRegLifecycleOperation,
    base_path: &str,
    entity_identifier: &str,
) -> Result<Option<String>, BRegMetadataSelectionError> {
    use crate::BRegLifecycleOperation as Lifecycle;
    let mismatch = || selection_error(BRegMetadataSelectionErrorKind::ContractMismatch);
    let (id_suffix, path_suffix) = match kind {
        Lifecycle::SubmitRequest => ("submit", "submit"),
        Lifecycle::ApproveRequest => ("approve", "approve"),
        Lifecycle::RejectRequest => ("reject", "reject"),
        Lifecycle::RequestRevision => ("request_revision", "request-revision"),
        Lifecycle::ReviseRequest => ("revise", "revise"),
        Lifecycle::CancelRequest => ("cancel", "cancel"),
        Lifecycle::ApplyRequest => ("apply", "apply"),
    };
    if matches!(
        kind,
        Lifecycle::ApproveRequest | Lifecycle::RejectRequest | Lifecycle::RequestRevision
    ) {
        let id_prefix = format!("records.{entity_identifier}.request.stages.");
        let remainder = operation.id.strip_prefix(&id_prefix).ok_or_else(mismatch)?;
        let (stage, suffix) = remainder.split_once('.').ok_or_else(mismatch)?;
        if suffix != id_suffix || stage.contains('.') {
            return Err(mismatch());
        }
        identifier(Value::String(stage.to_owned())).map_err(|_| mismatch())?;
        if operation.path != format!("{base_path}/stages/{stage}/{path_suffix}") {
            return Err(mismatch());
        }
        return Ok(Some(stage.to_owned()));
    }

    if operation.id != format!("records.{entity_identifier}.request.{id_suffix}")
        || operation.path != format!("{base_path}/{path_suffix}")
    {
        return Err(mismatch());
    }
    Ok(None)
}

fn parse_metadata(value: Value) -> Result<BRegMetadata, BRegMetadataError> {
    let mut root = object(value)?;
    let metadata_version = string(required(&mut root, "metadataVersion")?)?;
    if metadata_version != "1" {
        return Err(metadata_error(BRegMetadataErrorKind::Version));
    }
    let id = identifier(required(&mut root, "id")?)?;
    let version = bounded_short_text(required(&mut root, "version")?)?;
    let revision = string(required(&mut root, "revision")?)?;
    if !valid_revision(&revision) {
        return Err(metadata_error(BRegMetadataErrorKind::Revision));
    }
    let entities = array(required(&mut root, "entities")?)?
        .into_iter()
        .map(parse_entity)
        .collect::<Result<Vec<_>, _>>()?;
    let operations = array(required(&mut root, "operations")?)?
        .into_iter()
        .map(parse_operation)
        .collect::<Result<Vec<_>, _>>()?;
    let actions = root.remove("actions");
    let immediate_actions = actions
        .as_ref()
        .map(|value| parse_immediate_actions(value.clone()))
        .transpose()?
        .unwrap_or_default();
    finish(root)?;

    ensure_unique(entities.iter().map(|entity| entity.id.as_str()))?;
    ensure_unique(entities.iter().map(|entity| entity.route.as_str()))?;
    ensure_unique(operations.iter().map(|operation| operation.id.as_str()))?;
    validate_metadata_references(&entities, &operations)?;

    Ok(BRegMetadata {
        id,
        version,
        revision,
        entities,
        operations,
        actions,
        immediate_actions,
        source_binding: None,
    })
}

fn parse_entity(value: Value) -> Result<BRegMetadataEntity, BRegMetadataError> {
    let mut entity = object(value)?;
    let id = identifier(required(&mut entity, "id")?)?;
    let dataset_identifier = identifier(required(&mut entity, "datasetIdentifier")?)?;
    let route = identifier(required(&mut entity, "route")?)?;
    let schema_path = path(required(&mut entity, "schema")?)?;
    if schema_path != format!("/v1/schemas/{id}") {
        return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
    }
    let operations = array(required(&mut entity, "operations")?)?
        .into_iter()
        .map(|value| {
            let mut summary = object(value)?;
            let kind = BRegOperationKind::parse(identifier(required(&mut summary, "operation")?)?);
            let profile = identifier(required(&mut summary, "accessProfile")?)?;
            finish(summary)?;
            Ok((kind, profile))
        })
        .collect::<Result<Vec<_>, BRegMetadataError>>()?;
    let mut summaries = BTreeSet::new();
    for (kind, profile) in &operations {
        if !summaries.insert((kind.as_str(), profile.as_str())) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
    }
    let readable_fields = identifier_array(required(&mut entity, "readableFields")?)?;
    ensure_unique(readable_fields.iter().map(String::as_str))?;
    let change_control = entity.remove("changeControl");
    if let Some(value) = &change_control {
        validate_change_control(value)?;
    }
    let change_request = entity
        .remove("changeRequest")
        .map(parse_change_request_capability)
        .transpose()?;
    finish(entity)?;
    Ok(BRegMetadataEntity {
        id,
        dataset_identifier,
        route,
        schema_path,
        operations,
        readable_fields,
        change_control,
        change_request,
    })
}

fn parse_change_request_capability(
    value: Value,
) -> Result<BRegChangeRequestCapability, BRegMetadataError> {
    let mut capability = object(value)?;
    let planner = parse_change_request_planner(required(&mut capability, "planner")?)?;
    let review_mode = match identifier(required(&mut capability, "reviewMode")?)?.as_str() {
        "none" => BRegChangeRequestReviewMode::None,
        "staged" => BRegChangeRequestReviewMode::Staged,
        _ => return Err(metadata_error(BRegMetadataErrorKind::Shape)),
    };
    let stages = capability
        .remove("stages")
        .map(parse_change_request_stages)
        .transpose()?;
    if review_mode == BRegChangeRequestReviewMode::None
        && stages.as_ref().is_some_and(|stages| !stages.is_empty())
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let application = parse_change_request_application(required(&mut capability, "application")?)?;
    finish(capability)?;
    Ok(BRegChangeRequestCapability {
        planner,
        review_mode,
        stages,
        application,
    })
}

fn parse_change_request_stages(
    value: Value,
) -> Result<Vec<BRegChangeRequestStage>, BRegMetadataError> {
    let values = array(value)?;
    if values.len() > MAX_CHANGE_REQUEST_STAGES {
        return Err(metadata_error(BRegMetadataErrorKind::Bound));
    }
    let mut ids = BTreeSet::new();
    values
        .into_iter()
        .map(|value| {
            let mut stage = object(value)?;
            let id = identifier(required(&mut stage, "id")?)?;
            if id.len() > MAX_CHANGE_REQUEST_STAGE_ID_BYTES || id.contains('.') {
                return Err(metadata_error(BRegMetadataErrorKind::Identifier));
            }
            if !ids.insert(id.clone()) {
                return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
            }
            let approvals = positive_integer(required(&mut stage, "approvals")?)?;
            if approvals > MAX_CHANGE_REQUEST_STAGE_APPROVALS {
                return Err(metadata_error(BRegMetadataErrorKind::Bound));
            }
            let exclude_submitter = boolean(required(&mut stage, "excludeSubmitter")?)?;
            let exclude_previous_reviewers = stage
                .remove("excludePreviousReviewers")
                .map(boolean)
                .transpose()?
                .unwrap_or(false);
            finish(stage)?;
            Ok(BRegChangeRequestStage {
                id,
                approvals,
                exclude_submitter,
                exclude_previous_reviewers,
            })
        })
        .collect()
}

fn parse_change_request_planner(
    value: Value,
) -> Result<BRegChangeRequestPlannerCapability, BRegMetadataError> {
    let mut planner = object(value)?;
    match identifier(required(&mut planner, "kind")?)?.as_str() {
        "declarative" => {
            finish(planner)?;
            Ok(BRegChangeRequestPlannerCapability {
                kind: BRegChangeRequestPlannerKind::Declarative,
                abi: None,
                limits: None,
                possible_write_count: None,
                possible_write_operations: Vec::new(),
            })
        }
        "rhai" => {
            let abi = bounded_short_text(required(&mut planner, "abi")?)?;
            if abi != "registry.change-request-plan/v1" {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            let limits = parse_change_request_planner_limits(required(&mut planner, "limits")?)?;
            let possible_write_count =
                positive_integer(required(&mut planner, "possibleWriteCount")?)?;
            let possible_write_operations =
                identifier_array(required(&mut planner, "possibleWriteOperations")?)?
                    .into_iter()
                    .map(|operation| match operation.as_str() {
                        "create" => Ok(BRegOperationKind::Create),
                        "patch" => Ok(BRegOperationKind::Patch),
                        _ => Err(metadata_error(BRegMetadataErrorKind::Shape)),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            if possible_write_operations.is_empty()
                || u64::try_from(possible_write_operations.len())
                    .map_or(true, |count| count > possible_write_count)
            {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            ensure_unique(
                possible_write_operations
                    .iter()
                    .map(BRegOperationKind::as_str),
            )?;
            finish(planner)?;
            Ok(BRegChangeRequestPlannerCapability {
                kind: BRegChangeRequestPlannerKind::Rhai,
                abi: Some(abi),
                limits: Some(limits),
                possible_write_count: Some(possible_write_count),
                possible_write_operations,
            })
        }
        _ => Err(metadata_error(BRegMetadataErrorKind::Shape)),
    }
}

fn parse_change_request_planner_limits(
    value: Value,
) -> Result<BRegChangeRequestPlannerLimits, BRegMetadataError> {
    let mut limits = object(value)?;
    let parsed = BRegChangeRequestPlannerLimits {
        maximum_targets: positive_integer(required(&mut limits, "maximumTargets")?)?,
        maximum_field_mutations: positive_integer(required(&mut limits, "maximumFieldMutations")?)?,
        maximum_snapshot_bytes: positive_integer(required(&mut limits, "maximumSnapshotBytes")?)?,
        maximum_source_bytes: positive_integer(required(&mut limits, "maximumSourceBytes")?)?,
        maximum_operations: positive_integer(required(&mut limits, "maximumOperations")?)?,
        maximum_call_depth: positive_integer(required(&mut limits, "maximumCallDepth")?)?,
        maximum_expression_depth: positive_integer(required(
            &mut limits,
            "maximumExpressionDepth",
        )?)?,
        maximum_string_bytes: positive_integer(required(&mut limits, "maximumStringBytes")?)?,
        maximum_array_items: positive_integer(required(&mut limits, "maximumArrayItems")?)?,
        maximum_map_entries: positive_integer(required(&mut limits, "maximumMapEntries")?)?,
        maximum_modules: required(&mut limits, "maximumModules")?
            .as_u64()
            .filter(|value| *value == 0)
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?,
    };
    finish(limits)?;
    Ok(parsed)
}

fn parse_change_request_application(
    value: Value,
) -> Result<BRegChangeRequestApplicationCapability, BRegMetadataError> {
    let mut application = object(value)?;
    let mode = match identifier(required(&mut application, "mode")?)?.as_str() {
        "manual" => BRegChangeRequestApplicationMode::Manual,
        "automatic" => BRegChangeRequestApplicationMode::Automatic,
        "planner" => BRegChangeRequestApplicationMode::Planner,
        _ => return Err(metadata_error(BRegMetadataErrorKind::Shape)),
    };
    let allowed_dispositions =
        identifier_array(required(&mut application, "allowedDispositions")?)?
            .into_iter()
            .map(|disposition| match disposition.as_str() {
                "apply" => Ok(BRegChangeRequestDisposition::Apply),
                "queue" => Ok(BRegChangeRequestDisposition::Queue),
                _ => Err(metadata_error(BRegMetadataErrorKind::Shape)),
            })
            .collect::<Result<Vec<_>, _>>()?;
    let unique_dispositions = allowed_dispositions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if allowed_dispositions.is_empty() || unique_dispositions.len() != allowed_dispositions.len() {
        return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
    }
    let static_dispositions_are_exact = match mode {
        BRegChangeRequestApplicationMode::Manual => {
            allowed_dispositions == [BRegChangeRequestDisposition::Queue]
        }
        BRegChangeRequestApplicationMode::Automatic => {
            allowed_dispositions == [BRegChangeRequestDisposition::Apply]
        }
        BRegChangeRequestApplicationMode::Planner => true,
    };
    if !static_dispositions_are_exact {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let queue_reasons = array(required(&mut application, "queueReasons")?)?
        .into_iter()
        .map(|reason| {
            let mut reason = object(reason)?;
            let code = identifier(required(&mut reason, "code")?)?;
            let label = bounded_short_text(required(&mut reason, "label")?)?;
            if label.is_empty() {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            finish(reason)?;
            Ok(BRegChangeRequestQueueReason { code, label })
        })
        .collect::<Result<Vec<_>, BRegMetadataError>>()?;
    ensure_unique(queue_reasons.iter().map(|reason| reason.code.as_str()))?;
    if (mode != BRegChangeRequestApplicationMode::Planner && !queue_reasons.is_empty())
        || (!queue_reasons.is_empty()
            && !unique_dispositions.contains(&BRegChangeRequestDisposition::Queue))
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    finish(application)?;
    Ok(BRegChangeRequestApplicationCapability {
        mode,
        allowed_dispositions,
        queue_reasons,
    })
}

fn parse_operation(value: Value) -> Result<BRegMetadataOperation, BRegMetadataError> {
    let mut operation = object(value)?;
    let id = identifier(required(&mut operation, "id")?)?;
    let method = string(required(&mut operation, "method")?)?;
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let path = path(required(&mut operation, "path")?)?;
    let kind = BRegOperationKind::parse(identifier(required(&mut operation, "operation")?)?);
    let source_entity = identifier(required(&mut operation, "sourceEntity")?)?;
    let response_entity = identifier(required(&mut operation, "responseEntity")?)?;
    let access_profile = identifier(required(&mut operation, "accessProfile")?)?;
    let required_capabilities =
        identifier_array(required(&mut operation, "requiredCapabilities")?)?;
    ensure_unique(required_capabilities.iter().map(String::as_str))?;
    let fields = array(required(&mut operation, "fields")?)?
        .into_iter()
        .map(parse_field)
        .collect::<Result<Vec<_>, _>>()?;
    ensure_unique(fields.iter().map(|field| field.id.as_str()))?;
    ensure_unique(fields.iter().map(|field| field.api_name.as_str()))?;
    let readable_fields = identifier_array(required(&mut operation, "readableFields")?)?;
    let create_writable_fields =
        identifier_array(required(&mut operation, "createWritableFields")?)?;
    let patch_writable_fields = identifier_array(required(&mut operation, "patchWritableFields")?)?;
    for values in [
        &readable_fields,
        &create_writable_fields,
        &patch_writable_fields,
    ] {
        ensure_unique(values.iter().map(String::as_str))?;
        if values
            .iter()
            .any(|field| !fields.iter().any(|candidate| candidate.id == *field))
        {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
    }
    if fields.iter().any(|field| {
        field
            .schema
            .get("x-registry-fieldKind")
            .and_then(Value::as_str)
            == Some("attachment")
            && (create_writable_fields.contains(&field.id)
                || patch_writable_fields.contains(&field.id))
    }) {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let request = parse_request(required(&mut operation, "request")?)?;
    let entity_label = bounded_text(required(&mut operation, "entityLabel")?)?;
    validate_envelope_identifier(required(&mut operation, "identifier")?)?;
    let title_fields = identifier_array(required(&mut operation, "titleFields")?)?;
    ensure_unique(title_fields.iter().map(String::as_str))?;
    if title_fields
        .iter()
        .any(|title| !fields.iter().any(|field| field.id == *title))
    {
        return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
    }
    let selectors = parse_selectors(required(&mut operation, "selectors")?)?;
    let slots = fields
        .iter()
        .filter(|field| {
            field
                .schema
                .get("x-registry-fieldKind")
                .and_then(Value::as_str)
                == Some("attachment")
        })
        .map(|field| field.id.as_str())
        .collect::<BTreeSet<_>>();
    let query_value = required(&mut operation, "query")?;
    validate_query(query_value.clone(), &slots)?;
    let query = serde_json::from_value(query_value)
        .map_err(|_| metadata_error(BRegMetadataErrorKind::Shape))?;
    let read_path = operation
        .remove("readPath")
        .map(parse_read_path)
        .transpose()?;
    let readable_request_fields = operation
        .remove("readableRequestFields")
        .map(parse_request_metadata_fields)
        .transpose()?
        .unwrap_or_default();
    finish(operation)?;
    Ok(BRegMetadataOperation {
        id,
        method,
        path,
        kind,
        source_entity,
        response_entity,
        access_profile,
        required_capabilities,
        fields,
        readable_fields,
        readable_request_fields,
        create_writable_fields,
        patch_writable_fields,
        request,
        entity_label,
        title_fields,
        query,
        selectors,
        read_path,
    })
}

fn parse_request_metadata_fields(value: Value) -> Result<Vec<String>, BRegMetadataError> {
    let fields = identifier_array(value)?;
    ensure_unique(fields.iter().map(String::as_str))?;
    if fields.iter().any(|field| {
        !matches!(
            field.as_str(),
            "actor_reference" | "reason" | "review_state"
        )
    }) {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    Ok(fields)
}

fn parse_field(value: Value) -> Result<BRegMetadataField, BRegMetadataError> {
    let mut field = object(value)?;
    let id = identifier(required(&mut field, "id")?)?;
    let api_name_value = required(&mut field, "apiName")?;
    let schema = required(&mut field, "schema")?;
    // Slot IDs are verbatim API properties. Keep ordinary scalar API naming strict.
    let attachment =
        schema.get("x-registry-fieldKind").and_then(Value::as_str) == Some("attachment");
    let api_name = if attachment {
        identifier(api_name_value)?
    } else {
        api_name(api_name_value)?
    };
    let required_value = boolean(required(&mut field, "required")?)?;
    let nullable = boolean(required(&mut field, "nullable")?)?;
    let read_only = boolean(required(&mut field, "readOnly")?)?;
    let removable = boolean(required(&mut field, "removable")?)?;
    if attachment && (api_name != id || required_value || !nullable || !read_only || removable) {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let label = bounded_text(required(&mut field, "label")?)?;
    let storage_validation = field
        .remove("storageValidation")
        .map(parse_storage_validation)
        .transpose()?;
    let reference = field
        .remove("reference")
        .map(parse_references)
        .transpose()?;
    let code_labels = field
        .remove("codeLabels")
        .map(parse_code_labels)
        .transpose()?
        .unwrap_or_default();
    finish(field)?;
    Ok(BRegMetadataField {
        id,
        api_name,
        label,
        schema,
        required: required_value,
        nullable,
        read_only,
        removable,
        storage_validation,
        code_labels,
        reference,
    })
}

fn parse_storage_validation(
    value: Value,
) -> Result<BRegStorageValidationDescriptor, BRegMetadataError> {
    let mut validation = object(value)?;
    let kind = identifier(required(&mut validation, "kind")?)?;
    let pattern = bounded_text(required(&mut validation, "pattern")?)?;
    finish(validation)?;
    Ok(BRegStorageValidationDescriptor { kind, pattern })
}

fn parse_code_labels(value: Value) -> Result<BTreeMap<String, String>, BRegMetadataError> {
    object(value)?
        .into_iter()
        .map(|(code, label)| {
            let code = bounded_short_text(Value::String(code))?;
            let label = bounded_text(label)?;
            Ok((code, label))
        })
        .collect()
}

fn parse_references(value: Value) -> Result<BRegReferenceDescriptor, BRegMetadataError> {
    let mut reference = object(value)?;
    let manual_entry = boolean(required(&mut reference, "manualEntry")?)?;
    let target_entity = reference
        .remove("targetEntity")
        .map(identifier)
        .transpose()?;
    let Some(operations) = reference.remove("operations") else {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    };
    let references = array(operations)?
        .into_iter()
        .map(|value| {
            let mut operation = object(value)?;
            let operation_id = identifier(required(&mut operation, "operationId")?)?;
            let access_profile = identifier(required(&mut operation, "accessProfile")?)?;
            let label_fields = identifier_array(required(&mut operation, "labelFields")?)?;
            ensure_unique(label_fields.iter().map(String::as_str))?;
            finish(operation)?;
            Ok(BRegReferenceOperationDescriptor {
                operation_id,
                access_profile,
                label_fields,
            })
        })
        .collect::<Result<Vec<_>, BRegMetadataError>>()?;
    ensure_unique(
        references
            .iter()
            .map(|reference| reference.operation_id.as_str()),
    )?;
    finish(reference)?;
    Ok(BRegReferenceDescriptor {
        manual_entry,
        target_entity,
        operations: references,
    })
}

fn parse_request(value: Value) -> Result<BRegOperationRequest, BRegMetadataError> {
    let mut request = object(value)?;
    let parsed = BRegOperationRequest {
        field_names: optional_string(&mut request, "fieldNames")?,
        query_parameters: optional_text_array(&mut request, "queryParameters")?.unwrap_or_default(),
        body: optional_string(&mut request, "body")?,
        content_type: optional_string(&mut request, "contentType")?,
        schema: request.remove("schema"),
        idempotency_key_required: optional_bool(&mut request, "idempotencyKeyRequired")?,
        if_match_required: optional_bool(&mut request, "ifMatchRequired")?,
        mutation_semantics: optional_string(&mut request, "mutationSemantics")?,
        patch_path_prefix: optional_string(&mut request, "patchPathPrefix")?,
        patch_operations: optional_identifier_array(&mut request, "patchOperations")?
            .unwrap_or_default(),
        remove_semantics: optional_string(&mut request, "removeSemantics")?,
        maximum_items: optional_positive_integer(&mut request, "maximumItems")?,
        maximum_body_bytes: optional_positive_integer(&mut request, "maximumBodyBytes")?,
        allow_create: optional_bool(&mut request, "allowCreate")?,
        allow_patch: optional_bool(&mut request, "allowPatch")?,
    };
    finish(request)?;
    Ok(parsed)
}

fn validate_envelope_identifier(value: Value) -> Result<(), BRegMetadataError> {
    let mut identifier_value = object(value)?;
    if string(required(&mut identifier_value, "apiName")?)? != "id"
        || string(required(&mut identifier_value, "location")?)? != "envelope"
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    finish(identifier_value)
}

fn parse_read_path(value: Value) -> Result<BRegReadPathDescriptor, BRegMetadataError> {
    let mut read_path = object(value)?;
    let id = identifier(required(&mut read_path, "id")?)?;
    let label = bounded_text(required(&mut read_path, "label")?)?;
    finish(read_path)?;
    Ok(BRegReadPathDescriptor { id, label })
}

fn parse_selectors(value: Value) -> Result<Vec<BRegLookupSelectorDescriptor>, BRegMetadataError> {
    let selectors = array(value)?;
    let mut selector_ids = BTreeSet::new();
    let mut parsed = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let mut selector = object(selector)?;
        let id = identifier(required(&mut selector, "id")?)?;
        if !selector_ids.insert(id.clone()) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        let label = bounded_text(required(&mut selector, "label")?)?;
        let value_origin = identifier(required(&mut selector, "valueOrigin")?)?;
        if !matches!(value_origin.as_str(), "request" | "verified_claim") {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        let mut api_names = BTreeSet::new();
        let mut field_ids = BTreeSet::new();
        let mut fields = Vec::new();
        for field in array(required(&mut selector, "fields")?)? {
            let mut field = object(field)?;
            let field_id = identifier(required(&mut field, "id")?)?;
            let field_api_name = api_name(required(&mut field, "apiName")?)?;
            if !field_ids.insert(field_id.clone()) || !api_names.insert(field_api_name.clone()) {
                return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
            }
            let field_label = bounded_text(required(&mut field, "label")?)?;
            let schema = required(&mut field, "schema")?;
            let required_value = boolean(required(&mut field, "required")?)?;
            finish(field)?;
            fields.push(BRegLookupSelectorFieldDescriptor {
                id: field_id,
                api_name: field_api_name,
                label: field_label,
                schema,
                required: required_value,
            });
        }
        let request_fields = api_name_array(required(&mut selector, "requestFields")?)?;
        ensure_unique(request_fields.iter().map(String::as_str))?;
        if request_fields
            .iter()
            .any(|request_field| !api_names.contains(request_field))
        {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        finish(selector)?;
        if (value_origin == "request" && request_fields.len() != fields.len())
            || (value_origin == "verified_claim" && !request_fields.is_empty())
        {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        parsed.push(BRegLookupSelectorDescriptor {
            id,
            label,
            value_origin,
            fields,
            request_fields,
        });
    }
    Ok(parsed)
}

fn validate_query(value: Value, slots: &BTreeSet<&str>) -> Result<(), BRegMetadataError> {
    if value.is_null() {
        return Ok(());
    }
    let mut query = object(value)?;
    identifier(required(&mut query, "kind")?)?;
    validate_field_identities(required(&mut query, "selectableFields")?, None, slots)?;
    validate_field_identities(
        required(&mut query, "filterableFields")?,
        Some("operators"),
        slots,
    )?;
    validate_field_identities(
        required(&mut query, "sortableFields")?,
        Some("directions"),
        slots,
    )?;
    boolean(required(&mut query, "allowCount")?)?;
    positive_integer(required(&mut query, "defaultPageSize")?)?;
    positive_integer(required(&mut query, "maxPageSize")?)?;
    positive_integer(required(&mut query, "maxFilterClauses")?)?;
    positive_integer(required(&mut query, "maxInValues")?)?;
    validate_pagination(required(&mut query, "pagination")?)?;
    validate_temporal(required(&mut query, "temporal")?)?;
    if let Some(spatial) = query.remove("spatialQueries") {
        validate_spatial_queries(spatial)?;
    }
    finish(query)
}

fn validate_spatial_queries(value: Value) -> Result<(), BRegMetadataError> {
    let mut spatial = object(value)?;
    let mut bbox = object(required(&mut spatial, "bbox")?)?;
    api_name(required(&mut bbox, "geometryProperty")?)?;
    positive_number_with_maximum(required(&mut bbox, "maximumLongitudeSpanDegrees")?, 360.0)?;
    positive_number_with_maximum(required(&mut bbox, "maximumLatitudeSpanDegrees")?, 180.0)?;
    if string(required(&mut bbox, "coordinateReferenceSystem")?)? != "CRS84"
        || string(required(&mut bbox, "semantics")?)? != "inclusive_2d_non_crossing"
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    finish(bbox)?;
    finish(spatial)
}

fn query_field_identifier(value: Value) -> Result<String, BRegMetadataError> {
    match value.as_str() {
        Some("__request_breg_state" | "__request_proposal_version" | "__request_effect_digest") => {
            string(value)
        }
        _ => identifier(value),
    }
}

fn validate_field_identities(
    value: Value,
    extra_member: Option<&str>,
    slots: &BTreeSet<&str>,
) -> Result<(), BRegMetadataError> {
    let mut ids = BTreeSet::new();
    let mut api_names = BTreeSet::new();
    for field in array(value)? {
        let mut field = object(field)?;
        let id = query_field_identifier(required(&mut field, "id")?)?;
        // A slot identifier is its own verbatim API property. Every other
        // queryable field keeps strict scalar API naming.
        let api_name_value = required(&mut field, "apiName")?;
        let api = if slots.contains(id.as_str()) {
            let api = identifier(api_name_value)?;
            if api != id {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            api
        } else {
            api_name(api_name_value)?
        };
        if !ids.insert(id) || !api_names.insert(api) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        if let Some(member) = extra_member {
            let values = identifier_array(required(&mut field, member)?)?;
            ensure_unique(values.iter().map(String::as_str))?;
        }
        finish(field)?;
    }
    Ok(())
}

fn validate_pagination(value: Value) -> Result<(), BRegMetadataError> {
    let mut pagination = object(value)?;
    bounded_text(required(&mut pagination, "parameter")?)?;
    bounded_text(required(&mut pagination, "responsePath")?)?;
    boolean(required(&mut pagination, "exclusive")?)?;
    finish(pagination)
}

fn validate_temporal(value: Value) -> Result<(), BRegMetadataError> {
    if value.is_null() {
        return Ok(());
    }
    let mut temporal = object(value)?;
    let mode = identifier(required(&mut temporal, "mode")?)?;
    match mode.as_str() {
        "current" => {}
        "as_of" => {
            bounded_text(required(&mut temporal, "parameter")?)?;
            boolean(required(&mut temporal, "required")?)?;
            validate_schema_object(required(&mut temporal, "schema")?)?;
        }
        "snapshot" => {
            validate_temporal_parameter(required(&mut temporal, "snapshot")?)?;
            if let Some(valid_at) = temporal.remove("validAt") {
                validate_temporal_parameter(valid_at)?;
            }
        }
        _ => return Err(metadata_error(BRegMetadataErrorKind::Shape)),
    }
    finish(temporal)
}

fn validate_temporal_parameter(value: Value) -> Result<(), BRegMetadataError> {
    let mut parameter = object(value)?;
    bounded_text(required(&mut parameter, "parameter")?)?;
    boolean(required(&mut parameter, "required")?)?;
    validate_schema_object(required(&mut parameter, "schema")?)?;
    finish(parameter)
}

fn validate_schema_object(value: Value) -> Result<(), BRegMetadataError> {
    if value.is_object() || value.is_boolean() {
        Ok(())
    } else {
        Err(metadata_error(BRegMetadataErrorKind::Shape))
    }
}

fn validate_change_control(value: &Value) -> Result<(), BRegMetadataError> {
    let mut change_control = object(value.clone())?;
    let controlled = identifier_array(required(&mut change_control, "controlledOperations")?)?;
    ensure_unique(controlled.iter().map(String::as_str))?;
    let mut request_ids = BTreeSet::new();
    for request_type in array(required(&mut change_control, "eligibleRequestTypes")?)? {
        let mut request_type = object(request_type)?;
        if !request_ids.insert(identifier(required(&mut request_type, "id")?)?) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        identifier(required(&mut request_type, "primaryDataset")?)?;
        identifier(required(&mut request_type, "route")?)?;
        finish(request_type)?;
    }
    finish(change_control)
}

fn parse_immediate_actions(
    value: Value,
) -> Result<Vec<BRegImmediateActionDescriptor>, BRegMetadataError> {
    let actions = array(value)?;
    let mut identifiers = BTreeSet::new();
    let mut parsed = Vec::with_capacity(actions.len());
    for action in actions {
        let action_object = action
            .as_object()
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
        let action_id = identifier(
            action_object
                .get("id")
                .cloned()
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?,
        )?;
        if !identifiers.insert(action_id) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        if ![
            "route",
            "conditionRoute",
            "contractFingerprint",
            "inputs",
            "referenceInputs",
            "requiredConditionKeys",
            "resultEffects",
            "access",
            "routes",
            "bounds",
        ]
        .iter()
        .all(|member| action_object.contains_key(*member))
        {
            continue;
        }
        let mut action = object(action)?;
        let id = identifier(required(&mut action, "id")?)?;
        let route = path(required(&mut action, "route")?)?;
        let condition_route = nullable_path(required(&mut action, "conditionRoute")?)?;
        let contract_fingerprint = string(required(&mut action, "contractFingerprint")?)?;
        if !valid_revision(&contract_fingerprint) {
            return Err(metadata_error(BRegMetadataErrorKind::Revision));
        }
        let input_mode = action.remove("inputMode").map(identifier).transpose()?;
        if input_mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "fixed" | "handler"))
        {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        let maximum_input_string_bytes = match action.remove("maximumInputStringBytes") {
            None | Some(Value::Null) => None,
            Some(value) => Some(positive_integer(value)?),
        };
        let inputs = array(required(&mut action, "inputs")?)?
            .into_iter()
            .map(parse_immediate_action_input)
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(inputs.iter().map(|input| input.id.as_str()))?;
        ensure_unique(inputs.iter().map(|input| input.api_name.as_str()))?;
        let reference_inputs = array(required(&mut action, "referenceInputs")?)?
            .into_iter()
            .map(parse_immediate_action_reference_input)
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(reference_inputs.iter().map(|input| input.input.as_str()))?;
        for reference in &reference_inputs {
            if !inputs
                .iter()
                .any(|input| input.id == reference.input && input.api_name == reference.api_name)
            {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
        let required_condition_keys =
            api_name_array(required(&mut action, "requiredConditionKeys")?)?;
        ensure_unique(required_condition_keys.iter().map(String::as_str))?;
        if required_condition_keys
            .iter()
            .any(|key| !inputs.iter().any(|input| input.api_name == *key))
        {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        let result_effects = array(required(&mut action, "resultEffects")?)?
            .into_iter()
            .map(parse_immediate_action_result_effect)
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(result_effects.iter().map(|effect| effect.effect.as_str()))?;

        let mut access = object(required(&mut action, "access")?)?;
        let access_profile = identifier(required(&mut access, "selectedProfile")?)?;
        finish(access)?;
        let mut routes = object(required(&mut action, "routes")?)?;
        let invoke_path = parse_immediate_action_route(
            required(&mut routes, "invoke")?,
            &format!("actions.{id}.invoke"),
            true,
            &format!("action-{id}-invoke-input"),
            &format!("action-{id}-invoke-response"),
        )?;
        if invoke_path != route {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        let target_conditions_path = match required(&mut routes, "targetConditions")? {
            Value::Null => None,
            value => Some(parse_immediate_action_route(
                value,
                &format!("actions.{id}.target_conditions"),
                false,
                &format!("action-{id}-target-conditions-input"),
                &format!("action-{id}-target-conditions-response"),
            )?),
        };
        if target_conditions_path != condition_route {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        finish(routes)?;
        let mut bounds_value = object(required(&mut action, "bounds")?)?;
        let bounds = BRegImmediateActionBounds {
            maximum_targets: positive_integer(required(&mut bounds_value, "maximumTargets")?)?,
            maximum_field_mutations: positive_integer(required(
                &mut bounds_value,
                "maximumFieldMutations",
            )?)?,
            maximum_snapshot_bytes: positive_integer(required(
                &mut bounds_value,
                "maximumSnapshotBytes",
            )?)?,
        };
        finish(bounds_value)?;
        finish(action)?;
        parsed.push(BRegImmediateActionDescriptor {
            id,
            route,
            condition_route,
            contract_fingerprint,
            input_mode,
            maximum_input_string_bytes,
            inputs,
            reference_inputs,
            required_condition_keys,
            result_effects,
            access_profile,
            invoke_path,
            target_conditions_path,
            bounds,
        });
    }
    Ok(parsed)
}

fn parse_immediate_action_input(
    value: Value,
) -> Result<BRegImmediateActionInputDescriptor, BRegMetadataError> {
    let mut input = object(value)?;
    let parsed = BRegImmediateActionInputDescriptor {
        id: identifier(required(&mut input, "id")?)?,
        api_name: api_name(required(&mut input, "apiName")?)?,
        field_type: required(&mut input, "fieldType")?,
        required: boolean(required(&mut input, "required")?)?,
        nullable: optional_bool(&mut input, "nullable")?,
        classification: identifier(required(&mut input, "classification")?)?,
    };
    finish(input)?;
    Ok(parsed)
}

fn parse_immediate_action_reference_input(
    value: Value,
) -> Result<BRegImmediateActionReferenceInputDescriptor, BRegMetadataError> {
    let mut input = object(value)?;
    let parsed = BRegImmediateActionReferenceInputDescriptor {
        input: identifier(required(&mut input, "input")?)?,
        api_name: api_name(required(&mut input, "apiName")?)?,
        target_entity: identifier(required(&mut input, "targetEntity")?)?,
    };
    finish(input)?;
    Ok(parsed)
}

fn parse_immediate_action_result_effect(
    value: Value,
) -> Result<BRegImmediateActionResultEffectDescriptor, BRegMetadataError> {
    let mut effect = object(value)?;
    let parsed = BRegImmediateActionResultEffectDescriptor {
        effect: identifier(required(&mut effect, "effect")?)?,
        entity: identifier(required(&mut effect, "entity")?)?,
        operation: BRegOperationKind::parse(identifier(required(&mut effect, "operation")?)?),
    };
    finish(effect)?;
    Ok(parsed)
}

fn parse_immediate_action_route(
    value: Value,
    expected_operation_id: &str,
    requires_idempotency: bool,
    expected_input_schema: &str,
    expected_response_schema: &str,
) -> Result<String, BRegMetadataError> {
    let mut route = object(value)?;
    if string(required(&mut route, "method")?)? != "POST"
        || identifier(required(&mut route, "operationId")?)? != expected_operation_id
        || boolean(required(&mut route, "requiresIdempotencyKey")?)? != requires_idempotency
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let path = path(required(&mut route, "path")?)?;
    if bounded_text(required(&mut route, "inputSchema")?)? != expected_input_schema
        || bounded_text(required(&mut route, "responseSchema")?)? != expected_response_schema
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    finish(route)?;
    Ok(path)
}

/// Every metadata limit crosses a JavaScript number boundary in the bindings,
/// so a value that boundary cannot carry exactly is refused here.
const MAXIMUM_EXACT_INTEGER: u64 = 9_007_199_254_740_991;

fn positive_integer(value: Value) -> Result<u64, BRegMetadataError> {
    value
        .as_u64()
        .filter(|value| *value > 0 && *value <= MAXIMUM_EXACT_INTEGER)
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn optional_positive_integer(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<u64>, BRegMetadataError> {
    object.remove(member).map(positive_integer).transpose()
}

fn positive_number_with_maximum(value: Value, maximum: f64) -> Result<Number, BRegMetadataError> {
    let number = value
        .as_number()
        .filter(|number| {
            number
                .as_f64()
                .is_some_and(|value| value.is_finite() && value > 0.0 && value <= maximum)
        })
        .cloned()
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
    Ok(number)
}

fn validate_metadata_references(
    entities: &[BRegMetadataEntity],
    operations: &[BRegMetadataOperation],
) -> Result<(), BRegMetadataError> {
    for operation in operations {
        if !entities
            .iter()
            .any(|entity| entity.id == operation.response_entity)
        {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        for reference in operation
            .fields
            .iter()
            .filter_map(|field| field.reference.as_ref())
            .flat_map(|reference| &reference.operations)
        {
            let Some(candidate) = operations.iter().find(|candidate| {
                candidate.id == reference.operation_id
                    && candidate.access_profile == reference.access_profile
            }) else {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            };
            if reference.label_fields.iter().any(|label| {
                !candidate
                    .readable_fields
                    .iter()
                    .any(|readable| readable == label)
            }) {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
        for target in operation
            .fields
            .iter()
            .filter_map(|field| field.reference.as_ref()?.target_entity.as_ref())
        {
            if !entities.iter().any(|entity| entity.id == *target) {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
    }
    for entity in entities {
        if entity.readable_fields.iter().any(|field| {
            !operations.iter().any(|operation| {
                operation.response_entity == entity.id
                    && operation
                        .readable_fields
                        .iter()
                        .any(|candidate| candidate == field)
            })
        }) {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        for (kind, profile) in &entity.operations {
            if !operations.iter().any(|operation| {
                operation.response_entity == entity.id
                    && operation.kind.as_str() == kind.as_str()
                    && operation.access_profile == *profile
            }) {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
        let _ = (&entity.schema_path, &entity.change_control);
    }
    Ok(())
}

fn decode_unique_json(bytes: &[u8]) -> Result<Value, BRegMetadataError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| {
            if error.to_string().contains("duplicate JSON object member") {
                metadata_error(BRegMetadataErrorKind::DuplicateMember)
            } else if error.to_string().contains("metadata resource bound") {
                metadata_error(BRegMetadataErrorKind::Bound)
            } else {
                metadata_error(BRegMetadataErrorKind::Json)
            }
        })?
        .0;
    deserializer
        .end()
        .map_err(|_| metadata_error(BRegMetadataErrorKind::Json))?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX_STRING_BYTES {
            return Err(E::custom("metadata resource bound"));
        }
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            if values.len() >= MAX_ARRAY_ITEMS {
                return Err(de::Error::custom("metadata resource bound"));
            }
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_STRING_BYTES || values.len() >= MAX_OBJECT_MEMBERS {
                return Err(de::Error::custom("metadata resource bound"));
            }
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = object.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn validate_value_bounds(value: &Value) -> Result<(), BRegMetadataError> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), BRegMetadataError> {
        if depth > MAX_BREG_METADATA_DEPTH {
            return Err(metadata_error(BRegMetadataErrorKind::Bound));
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_TOTAL_NODES {
            return Err(metadata_error(BRegMetadataErrorKind::Bound));
        }
        match value {
            Value::String(value) if value.len() > MAX_STRING_BYTES => {
                Err(metadata_error(BRegMetadataErrorKind::Bound))
            }
            Value::Array(values) => {
                if values.len() > MAX_ARRAY_ITEMS {
                    return Err(metadata_error(BRegMetadataErrorKind::Bound));
                }
                for value in values {
                    visit(value, depth + 1, nodes)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                if values.len() > MAX_OBJECT_MEMBERS
                    || values.keys().any(|key| key.len() > MAX_STRING_BYTES)
                {
                    return Err(metadata_error(BRegMetadataErrorKind::Bound));
                }
                for value in values.values() {
                    visit(value, depth + 1, nodes)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    visit(value, 0, &mut 0)
}

fn metadata_error(kind: BRegMetadataErrorKind) -> BRegMetadataError {
    BRegMetadataError::new(kind)
}

fn selection_error(kind: BRegMetadataSelectionErrorKind) -> BRegMetadataSelectionError {
    BRegMetadataSelectionError { kind }
}

fn object(value: Value) -> Result<Map<String, Value>, BRegMetadataError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn array(value: Value) -> Result<Vec<Value>, BRegMetadataError> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn required(object: &mut Map<String, Value>, member: &str) -> Result<Value, BRegMetadataError> {
    object
        .remove(member)
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn string(value: Value) -> Result<String, BRegMetadataError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn boolean(value: Value) -> Result<bool, BRegMetadataError> {
    value
        .as_bool()
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
}

fn optional_string(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<String>, BRegMetadataError> {
    object.remove(member).map(string).transpose()
}

fn optional_bool(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<bool>, BRegMetadataError> {
    object.remove(member).map(boolean).transpose()
}

fn optional_identifier_array(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<Vec<String>>, BRegMetadataError> {
    object.remove(member).map(identifier_array).transpose()
}

fn optional_text_array(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<Vec<String>>, BRegMetadataError> {
    object.remove(member).map(text_array).transpose()
}

fn identifier_array(value: Value) -> Result<Vec<String>, BRegMetadataError> {
    array(value)?.into_iter().map(identifier).collect()
}

fn api_name_array(value: Value) -> Result<Vec<String>, BRegMetadataError> {
    array(value)?.into_iter().map(api_name).collect()
}

fn text_array(value: Value) -> Result<Vec<String>, BRegMetadataError> {
    array(value)?.into_iter().map(bounded_text).collect()
}

fn finish(object: Map<String, Value>) -> Result<(), BRegMetadataError> {
    if object.is_empty() {
        Ok(())
    } else {
        Err(metadata_error(BRegMetadataErrorKind::Shape))
    }
}

fn api_names_for(operation: &BRegMetadataOperation, logical_ids: &[String]) -> BTreeSet<String> {
    operation
        .fields
        .iter()
        .filter(|field| logical_ids.iter().any(|id| id == &field.id))
        .map(|field| field.api_name.clone())
        .collect()
}

fn bounded_text(value: Value) -> Result<String, BRegMetadataError> {
    let value = string(value)?;
    if value.is_empty() || value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
        return Err(metadata_error(BRegMetadataErrorKind::Identifier));
    }
    Ok(value)
}

fn bounded_short_text(value: Value) -> Result<String, BRegMetadataError> {
    let value = bounded_text(value)?;
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(metadata_error(BRegMetadataErrorKind::Identifier));
    }
    Ok(value)
}

fn identifier(value: Value) -> Result<String, BRegMetadataError> {
    let value = string(value)?;
    let mut bytes = value.bytes();
    if value.len() > MAX_IDENTIFIER_BYTES
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(metadata_error(BRegMetadataErrorKind::Identifier));
    }
    Ok(value)
}

fn api_name(value: Value) -> Result<String, BRegMetadataError> {
    let value = string(value)?;
    let mut bytes = value.bytes();
    if value.len() > MAX_IDENTIFIER_BYTES
        || !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(metadata_error(BRegMetadataErrorKind::Identifier));
    }
    Ok(value)
}

fn path(value: Value) -> Result<String, BRegMetadataError> {
    let value = string(value)?;
    if value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('?')
        || value.contains('#')
        || value.split('/').any(|segment| segment == "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'-' | b'_' | b'.' | b':' | b'{' | b'}')
        })
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    Ok(value)
}

fn nullable_path(value: Value) -> Result<Option<String>, BRegMetadataError> {
    match value {
        Value::Null => Ok(None),
        value => path(value).map(Some),
    }
}

fn valid_revision(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_unique<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), BRegMetadataError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
    }
    Ok(())
}
