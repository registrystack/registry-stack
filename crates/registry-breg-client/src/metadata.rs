//! Bounded, caller-bound Base Registry Engine runtime metadata.
//!
//! Only the served `GET /v1/registry` metadata v2 document can produce an
//! executable operation binding. Generated entity summaries and older
//! metadata artifacts are deliberately insufficient authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jsonschema::{Draft, JSONSchema};
use registry_platform_canonical_json::parse_json_preserving_integers;
use serde_json::{Map, Number, Value};
use time::{Date, Month};
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
    name: Option<String>,
    cardinality: Option<String>,
    inverse_name: Option<String>,
    target_record_type: Option<String>,
    operations: Vec<BRegReferenceOperationDescriptor>,
}

impl BRegReferenceDescriptor {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn cardinality(&self) -> Option<&str> {
        self.cardinality.as_deref()
    }
    pub fn inverse_name(&self) -> Option<&str> {
        self.inverse_name.as_deref()
    }
    #[must_use]
    pub const fn manual_entry(&self) -> bool {
        self.manual_entry
    }

    #[must_use]
    pub fn target_record_type(&self) -> Option<&str> {
        self.target_record_type.as_deref()
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
    pub fn reference_target_record_type(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .and_then(BRegReferenceDescriptor::target_record_type)
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
    pub maximum_page_size: u64,
    pub maximum_filter_clauses: u64,
    pub maximum_in_values: u64,
    pub pagination: BRegQueryPagination,
    /// The temporal descriptor as served. `None` means the collection is not
    /// temporal. A `mode` this client does not understand is retained
    /// uninterpreted, so the caller can tell that default results are not
    /// described by a mode it knows.
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
    source_record_type: String,
    response_record_type: String,
    access_profile: String,
    required_capabilities: Vec<String>,
    fields: Vec<BRegMetadataField>,
    readable_fields: Vec<String>,
    create_writable_fields: Vec<String>,
    patch_writable_fields: Vec<String>,
    request: BRegOperationRequest,
    record_type_label: String,
    title_fields: Vec<String>,
    query: Option<BRegQueryDescriptor>,
    selectors: Vec<BRegLookupSelectorDescriptor>,
    read_path: Option<BRegReadPathDescriptor>,
}

impl BRegMetadataOperation {
    /// Use only this caller projection's declared readable title fields.
    /// The permitted opaque identity is the fallback when no title was disclosed.
    pub fn title_for_record(&self, record: &crate::RegistryRecord) -> String {
        self.title_fields
            .iter()
            .filter_map(|id| {
                let field = self
                    .fields
                    .iter()
                    .find(|field| field.id == *id && self.readable_fields.contains(id))?;
                record
                    .domain_data
                    .get(&field.api_name)?
                    .as_str()
                    .filter(|title| !title.is_empty())
            })
            .next()
            .map(str::to_owned)
            .unwrap_or_else(|| record.record_identifier.clone())
    }
    #[must_use]
    pub fn record_type_label(&self) -> &str {
        &self.record_type_label
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
    pub fn source_record_type(&self) -> &str {
        &self.source_record_type
    }

    #[must_use]
    pub fn response_record_type(&self) -> &str {
        &self.response_record_type
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
    mutation_policy: Option<Value>,
}

/// One typed input advertised by a caller-visible immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegActionInputDescriptor {
    id: String,
    api_name: String,
    label: Option<String>,
    description: Option<String>,
    schema: Value,
    field_type: Value,
    required: bool,
    nullable: Option<bool>,
    classification: String,
}

impl BRegActionInputDescriptor {
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
        self.label
            .as_deref()
            .filter(|label| !label.is_empty())
            .unwrap_or(&self.api_name)
    }
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    #[must_use]
    pub fn schema(&self) -> &Value {
        &self.schema
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

impl fmt::Debug for BRegActionInputDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionInputDescriptor")
            .field("required", &self.required)
            .field("nullable", &self.nullable)
            .finish_non_exhaustive()
    }
}

/// A typed immediate-action input that references one entity.
#[derive(Clone, PartialEq)]
pub struct BRegActionReferenceInputDescriptor {
    input: String,
    api_name: String,
    target_record_type: String,
}

impl BRegActionReferenceInputDescriptor {
    #[must_use]
    pub fn input_identifier(&self) -> &str {
        &self.input
    }
    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    #[must_use]
    pub fn target_record_type(&self) -> &str {
        &self.target_record_type
    }
}

/// One caller-visible result effect from an immediate action.
#[derive(Clone, PartialEq)]
pub struct BRegActionResultEffectDescriptor {
    effect: String,
    entity: String,
    operation: BRegOperationKind,
}

impl BRegActionResultEffectDescriptor {
    #[must_use]
    pub fn effect_identifier(&self) -> &str {
        &self.effect
    }
    #[must_use]
    pub fn record_type_identifier(&self) -> &str {
        &self.entity
    }
    #[must_use]
    pub const fn operation(&self) -> &BRegOperationKind {
        &self.operation
    }
}

/// Resource ceilings advertised for an immediate action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BRegActionBounds {
    maximum_targets: u64,
    maximum_field_mutations: u64,
    maximum_snapshot_bytes: u64,
}

impl BRegActionBounds {
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

/// Fixed execution mode is authored and cannot be selected by an invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegActionMode {
    Immediate,
    Proposal,
}

/// Declared document requirement on one caller-visible Proposal Action.
/// This summary grants no access to a Proposal or its bytes.
#[derive(Clone, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegActionAttachmentDescriptor {
    id: String,
    required: bool,
    content_types: Vec<String>,
    maximum_bytes: u64,
}

impl BRegActionAttachmentDescriptor {
    pub fn identifier(&self) -> &str {
        &self.id
    }
    pub const fn required(&self) -> bool {
        self.required
    }
    pub fn content_types(&self) -> &[String] {
        &self.content_types
    }
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
}

impl fmt::Debug for BRegActionAttachmentDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionAttachmentDescriptor")
            .field("required", &self.required)
            .finish_non_exhaustive()
    }
}

/// Read-only Proposal capability inventory for one exact Action/profile pair.
/// Operations are descriptive; runtime Proposal links govern execution.
#[derive(Clone, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegProposalActionDescriptor {
    action_id: String,
    access_profile: String,
    operations: Vec<String>,
    readable_inputs: Vec<String>,
}

impl BRegProposalActionDescriptor {
    pub fn action_identifier(&self) -> &str {
        &self.action_id
    }
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }
    pub fn operations(&self) -> &[String] {
        &self.operations
    }
    pub fn readable_inputs(&self) -> &[String] {
        &self.readable_inputs
    }
}

impl fmt::Debug for BRegProposalActionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegProposalActionDescriptor")
            .field("operation_count", &self.operations.len())
            .finish_non_exhaustive()
    }
}

/// Complete descriptive metadata for one caller-visible Action.
#[derive(Clone, PartialEq)]
pub struct BRegActionDescriptor {
    id: String,
    mode: BRegActionMode,
    api_name: String,
    definition_revision: String,
    display: Value,
    required_capabilities: Vec<String>,
    route: Option<String>,
    condition_route: Option<String>,
    input_mode: Option<String>,
    maximum_input_string_bytes: Option<u64>,
    inputs: Vec<BRegActionInputDescriptor>,
    attachments: Vec<BRegActionAttachmentDescriptor>,
    reference_inputs: Vec<BRegActionReferenceInputDescriptor>,
    required_condition_keys: Vec<String>,
    result_effects: Vec<BRegActionResultEffectDescriptor>,
    access_profile: String,
    invoke_path: Option<String>,
    target_conditions_path: Option<String>,
    availability_path: Option<String>,
    bounds: BRegActionBounds,
}

impl BRegActionDescriptor {
    pub fn api_name(&self) -> &str {
        &self.api_name
    }
    pub fn definition_revision(&self) -> &str {
        &self.definition_revision
    }
    pub fn display(&self) -> &Value {
        &self.display
    }
    #[must_use]
    pub const fn mode(&self) -> BRegActionMode {
        self.mode
    }
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
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
    pub fn inputs(&self) -> &[BRegActionInputDescriptor] {
        &self.inputs
    }
    #[must_use]
    pub fn attachments(&self) -> &[BRegActionAttachmentDescriptor] {
        &self.attachments
    }
    #[must_use]
    pub fn reference_inputs(&self) -> &[BRegActionReferenceInputDescriptor] {
        &self.reference_inputs
    }
    #[must_use]
    pub fn required_condition_keys(&self) -> &[String] {
        &self.required_condition_keys
    }
    #[must_use]
    pub fn result_effects(&self) -> &[BRegActionResultEffectDescriptor] {
        &self.result_effects
    }
    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }
    #[must_use]
    pub fn invoke_path(&self) -> Option<&str> {
        self.invoke_path.as_deref()
    }
    #[must_use]
    pub fn target_conditions_path(&self) -> Option<&str> {
        self.target_conditions_path.as_deref()
    }
    #[must_use]
    pub fn availability_path(&self) -> Option<&str> {
        self.availability_path.as_deref()
    }
    #[must_use]
    pub const fn bounds(&self) -> BRegActionBounds {
        self.bounds
    }
}

impl fmt::Debug for BRegActionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionDescriptor")
            .field("input_count", &self.inputs.len())
            .field("result_effect_count", &self.result_effects.len())
            .finish_non_exhaustive()
    }
}

/// Validated Base Registry Engine runtime metadata v2 for one caller projection.
#[derive(Clone, PartialEq)]
pub struct BRegMetadata {
    id: String,
    version: String,
    revision: String,
    entities: Vec<BRegMetadataEntity>,
    operations: Vec<BRegMetadataOperation>,
    action_metadata: Option<Value>,
    statistical_datasets: Option<Value>,
    proposals: Option<Value>,
    proposal_actions: Vec<BRegProposalActionDescriptor>,
    actions: Vec<BRegActionDescriptor>,
    source_binding: Option<String>,
}

impl BRegMetadata {
    /// Select only a caller-visible, action-specific review-context read.
    pub fn select_proposal_review_context(
        &self,
        expected_profile: &str,
        action: &str,
    ) -> Result<crate::BRegProposalReviewBinding, BRegMetadataSelectionError> {
        self.select_proposal_review(expected_profile, action, false)
    }

    /// Select only a caller-visible, action-specific review-status read.
    pub fn select_proposal_review_status(
        &self,
        expected_profile: &str,
        action: &str,
    ) -> Result<crate::BRegProposalReviewBinding, BRegMetadataSelectionError> {
        self.select_proposal_review(expected_profile, action, true)
    }

    fn select_proposal_review(
        &self,
        expected_profile: &str,
        action: &str,
        status: bool,
    ) -> Result<crate::BRegProposalReviewBinding, BRegMetadataSelectionError> {
        if self.proposals.is_none() {
            return Err(selection_error(BRegMetadataSelectionErrorKind::NotFound));
        }
        crate::BRegProposalReviewBinding::from_metadata(
            &serde_json::to_value(&self.proposal_actions).expect("validated Proposal inventory"),
            self.source_binding
                .as_ref()
                .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?,
            expected_profile,
            action,
            status,
        )
        .map_err(|_| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))
    }

    /// Promote an explicit UUID lookup grant independently of collection listing.
    pub fn select_proposal_get(
        &self,
        expected_profile: &str,
    ) -> Result<crate::BRegProposalGetBinding, BRegMetadataSelectionError> {
        crate::BRegProposalGetBinding::from_metadata(
            self.proposals
                .as_ref()
                .and_then(|value| value.get("get"))
                .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?,
            self.source_binding
                .as_ref()
                .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?,
            expected_profile,
        )
        .map_err(|_| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))
    }
    /// Promote only an explicitly advertised Proposal collection grant.
    pub fn select_proposals(
        &self,
        expected_profile: &str,
    ) -> Result<crate::BRegProposalCollection, BRegMetadataSelectionError> {
        crate::BRegProposalCollection::from_metadata(
            self.proposals
                .as_ref()
                .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?,
            self.source_binding
                .as_ref()
                .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?,
            &self.revision,
            expected_profile,
        )
        .map_err(|_| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))
    }
    /// Parse runtime metadata v2 bytes using duplicate-key detection and
    /// resource bounds before interpreting known members. Unknown object
    /// members are ignored; required capabilities still gate execution.
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

    /// Returns caller-filtered immediate-action metadata as a bounded inert
    /// JSON value. A separate action contract validator must promote it before
    /// invocation.
    #[must_use]
    pub fn action_metadata(&self) -> Option<&Value> {
        self.action_metadata.as_ref()
    }

    /// Returns validated caller-filtered statistical dataset descriptions as
    /// bounded inert JSON. These descriptions never grant entity authority.
    #[must_use]
    pub fn statistical_datasets(&self) -> Option<&Value> {
        self.statistical_datasets.as_ref()
    }

    /// Exact caller-visible Action/profile Proposal inventory, without execution authority.
    #[must_use]
    pub fn proposal_actions(&self) -> &[BRegProposalActionDescriptor] {
        &self.proposal_actions
    }

    /// Returns complete typed caller-filtered Action descriptors.
    #[must_use]
    pub fn actions(&self) -> &[BRegActionDescriptor] {
        &self.actions
    }

    /// Promote one complete caller-visible Invoke or Start contract.
    pub fn select_action(
        &self,
        action_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegActionBinding, BRegMetadataSelectionError> {
        let source_binding = self
            .source_binding
            .as_ref()
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::UnboundSource))?;
        let action = self
            .actions
            .iter()
            .find(|action| action.id == action_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        if action.access_profile != expected_profile {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ProfileMismatch,
            ));
        }
        if !action.required_capabilities.is_empty() {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::RequiredCapability,
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
        if !semantics_are_exact || !action_contract_is_exact(action) {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::ContractMismatch,
            ));
        }
        Ok(BRegActionBinding::from_descriptor(
            self.revision.clone(),
            source_binding.clone(),
            action,
        ))
    }

    /// Promote one exact direct Tombstone contract.
    pub fn select_tombstone(
        &self,
        record_type_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegTombstoneBinding, BRegMetadataSelectionError> {
        let (entity, operation, source_binding) = self.select_mutation_operation(
            record_type_identifier,
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
        record_type_identifier: &str,
        expected_profile: &str,
    ) -> Result<BRegBatchBinding, BRegMetadataSelectionError> {
        let (entity, operation, source_binding) = self.select_mutation_operation(
            record_type_identifier,
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
        record_type_identifier: &str,
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
            .find(|entity| entity.id == record_type_identifier)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::NotFound))?;
        let mut operations = self.operations.iter().filter(|operation| {
            operation.source_record_type == entity.id && operation.kind == expected_kind
        });
        let operation = operations
            .find(|operation| operation.access_profile == expected_profile)
            .ok_or_else(|| {
                if self.operations.iter().any(|operation| {
                    operation.source_record_type == entity.id && operation.kind == expected_kind
                }) {
                    selection_error(BRegMetadataSelectionErrorKind::ProfileMismatch)
                } else {
                    selection_error(BRegMetadataSelectionErrorKind::NotFound)
                }
            })?;
        if !operation_capabilities_are_understood(operation) {
            return Err(selection_error(
                BRegMetadataSelectionErrorKind::RequiredCapability,
            ));
        }
        if operation.response_record_type != entity.id {
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
            .find(|entity| entity.id == operation.source_record_type)
            .ok_or_else(|| selection_error(BRegMetadataSelectionErrorKind::ContractMismatch))?;
        if operation.response_record_type != entity.id {
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
            record_type_identifier: entity.id.clone(),
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
}

fn operation_capabilities_are_understood(operation: &BRegMetadataOperation) -> bool {
    operation.required_capabilities.is_empty()
}

fn action_contract_is_exact(action: &BRegActionDescriptor) -> bool {
    let Some(invoke_path) = action.invoke_path.as_deref() else {
        return false;
    };
    if !invoke_path.starts_with("/v1/")
        || invoke_path.contains(['?', '#', '%', '\\'])
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
        Some(path) if !path.starts_with("/v1/") || path.contains(['?', '#', '%', '\\']) => {
            return false;
        }
        None if !action.required_condition_keys.is_empty() => return false,
        _ => {}
    }
    match &action.availability_path {
        Some(path)
            if action.mode != BRegActionMode::Immediate
                || action.reference_inputs.is_empty()
                || !path.starts_with("/v1/")
                || path.contains(['?', '#', '%', '\\']) =>
        {
            return false;
        }
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
                != Some(reference.target_record_type.as_str())
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
            let minimum = required(&mut field_type, "minimumLength")?
                .as_u64()
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
            let maximum = positive_integer(required(&mut field_type, "maximumLength")?)?;
            if maximum > 1_000_000 || minimum > maximum {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
        "text" => {
            if positive_integer(required(&mut field_type, "maximumLength")?)? > 10_000_000 {
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
            bounded_string(required(&mut field_type, "vocabulary")?)?;
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
            let max_bytes = positive_integer(required(&mut field_type, "maximumBytes")?)?;
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
            .field("has_actions", &self.action_metadata.is_some())
            .field(
                "has_statistical_datasets",
                &self.statistical_datasets.is_some(),
            )
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
pub struct BRegActionInputBinding {
    api_name: String,
    required: bool,
    nullable: bool,
    field_type: Value,
}

impl BRegActionInputBinding {
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
pub struct BRegActionBinding {
    action_identifier: String,
    mode: BRegActionMode,
    registry_revision: String,
    access_profile: String,
    invoke_path: String,
    target_conditions_path: Option<String>,
    availability_path: Option<String>,
    definition_revision: String,
    required_condition_keys: BTreeSet<String>,
    result_effects: BTreeMap<String, String>,
    inputs: Vec<BRegActionInputBinding>,
    reference_inputs: Vec<BRegActionReferenceInputDescriptor>,
    bounds: BRegActionBounds,
    handler: bool,
    maximum_input_string_bytes: Option<u64>,
    source_binding: String,
}

impl BRegActionBinding {
    fn from_descriptor(
        registry_revision: String,
        source_binding: String,
        action: &BRegActionDescriptor,
    ) -> Self {
        Self {
            action_identifier: action.id.clone(),
            mode: action.mode,
            registry_revision,
            access_profile: action.access_profile.clone(),
            invoke_path: action
                .invoke_path
                .clone()
                .expect("selected Action has a promoted invocation route"),
            target_conditions_path: action.target_conditions_path.clone(),
            availability_path: action.availability_path.clone(),
            definition_revision: action.definition_revision.clone(),
            required_condition_keys: action.required_condition_keys.iter().cloned().collect(),
            result_effects: action
                .result_effects
                .iter()
                .map(|effect| (effect.effect.clone(), effect.entity.clone()))
                .collect(),
            inputs: action
                .inputs
                .iter()
                .map(|input| BRegActionInputBinding {
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
    pub const fn mode(&self) -> BRegActionMode {
        self.mode
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
    pub fn availability_path(&self) -> Option<&str> {
        self.availability_path.as_deref()
    }
    #[must_use]
    pub fn definition_revision(&self) -> &str {
        &self.definition_revision
    }
    #[must_use]
    pub const fn bounds(&self) -> BRegActionBounds {
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
    pub fn required_condition_keys(&self) -> &BTreeSet<String> {
        &self.required_condition_keys
    }
    #[must_use]
    pub fn result_effects(&self) -> &BTreeMap<String, String> {
        &self.result_effects
    }
    #[must_use]
    pub(crate) fn inputs(&self) -> &[BRegActionInputBinding] {
        &self.inputs
    }
    #[must_use]
    pub fn reference_inputs(&self) -> &[BRegActionReferenceInputDescriptor] {
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

impl fmt::Debug for BRegActionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegActionBinding(<bound>)")
    }
}

#[derive(Clone, PartialEq)]
struct BRegMutationBinding {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    operation_identifier: String,
    access_profile: String,
    record_type_identifier: String,
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
            record_type_identifier: entity.id.clone(),
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
            pub fn record_type_identifier(&self) -> &str {
                &self.common.record_type_identifier
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
    record_type_identifier: String,
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
            pub fn record_type_identifier(&self) -> &str {
                &self.common.record_type_identifier
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

fn parse_metadata(value: Value) -> Result<BRegMetadata, BRegMetadataError> {
    let mut root = object(value)?;
    let metadata_version = string(required(&mut root, "metadataVersion")?)?;
    if metadata_version != "2" {
        return Err(metadata_error(BRegMetadataErrorKind::Version));
    }
    let id = identifier(required(&mut root, "id")?)?;
    let version = bounded_short_text(required(&mut root, "version")?)?;
    let revision = string(required(&mut root, "revision")?)?;
    if !valid_revision(&revision) {
        return Err(metadata_error(BRegMetadataErrorKind::Revision));
    }
    let entities = array(required(&mut root, "recordTypes")?)?
        .into_iter()
        .map(parse_entity)
        .collect::<Result<Vec<_>, _>>()?;
    let operations = array(required(&mut root, "operations")?)?
        .into_iter()
        .map(parse_operation)
        .collect::<Result<Vec<_>, _>>()?;
    let action_metadata = root.remove("actions");
    let mut proposals = root.remove("proposals");
    let proposal_actions = match proposals.as_mut() {
        None => Vec::new(),
        Some(value) => {
            let object = value
                .as_object_mut()
                .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
            parse_proposal_actions(required(object, "actions")?)?
        }
    };
    let statistical_datasets = root
        .remove("statisticalDatasets")
        .map(parse_statistical_datasets)
        .transpose()?;
    let actions = action_metadata
        .as_ref()
        .map(|value| parse_actions(value.clone()))
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
        action_metadata,
        statistical_datasets,
        proposals,
        proposal_actions,
        actions,
        source_binding: None,
    })
}

fn parse_statistical_datasets(value: Value) -> Result<Value, BRegMetadataError> {
    let mut ids = BTreeSet::new();
    let mut supported = Vec::new();
    for value in array(value)? {
        let original = value.clone();
        let mut dataset = object(value)?;
        let mut vocabulary_is_supported = true;
        let id = identifier(required(&mut dataset, "id")?)?;
        if !ids.insert(id) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        identifier(required(&mut dataset, "unit")?)?;
        let kind = string(required(&mut dataset, "periodKind")?)?;
        if !matches!(kind.as_str(), "flow" | "stock") {
            vocabulary_is_supported = false;
        }
        let granularity = string(required(&mut dataset, "granularity")?)?;
        let first_period = string(required(&mut dataset, "firstPeriod")?)?;
        if matches!(granularity.as_str(), "day" | "month" | "quarter" | "year") {
            if !valid_statistical_period(&first_period, &granularity) {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        } else {
            vocabulary_is_supported = false;
        }
        let digest = string(required(&mut dataset, "definitionDigest")?)?;
        if !valid_revision(&digest) {
            return Err(metadata_error(BRegMetadataErrorKind::Revision));
        }
        let mut fields = BTreeSet::new();
        for value in array(required(&mut dataset, "dimensions")?)? {
            let mut dimension = object(value)?;
            let field = identifier(required(&mut dimension, "field")?)?;
            if !fields.insert(field) {
                return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
            }
            bounded_string(required(&mut dimension, "vocabulary")?)?;
            let codes = text_array(required(&mut dimension, "codes")?)?;
            ensure_unique(codes.iter().map(String::as_str))?;
            if !codes.iter().any(|code| code == "_T") {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            if codes
                .iter()
                .any(|code| code.starts_with('_') && !matches!(code.as_str(), "_T" | "_U"))
            {
                vocabulary_is_supported = false;
            }
            finish(dimension)?;
        }
        let operations = identifier_array(required(&mut dataset, "operations")?)?;
        ensure_unique(operations.iter().map(String::as_str))?;
        if operations.is_empty() {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        if operations.iter().any(|operation| {
            !matches!(
                operation.as_str(),
                "read-live"
                    | "list-releases"
                    | "read-released-series"
                    | "read-latest-release"
                    | "read-release-version"
                    | "publish-release"
                    | "withdraw-release"
            )
        }) {
            vocabulary_is_supported = false;
        }
        finish(dataset)?;
        if vocabulary_is_supported {
            supported.push(original);
        }
    }
    Ok(Value::Array(supported))
}

fn valid_statistical_period(period: &str, granularity: &str) -> bool {
    let bytes = period.as_bytes();
    let decimal = |bytes: &[u8]| -> Option<u16> {
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            bytes
                .iter()
                .fold(0_u16, |value, byte| value * 10 + u16::from(byte - b'0')),
        )
    };
    let Some(year) = bytes.get(..4).and_then(decimal).filter(|year| *year > 0) else {
        return false;
    };
    match granularity {
        "year" => bytes.len() == 4 && year < 9999,
        "quarter" if bytes.len() == 7 && bytes[4] == b'-' && bytes[5] == b'Q' => {
            decimal(&bytes[6..])
                .is_some_and(|quarter| (1..=4).contains(&quarter) && (year < 9999 || quarter < 4))
        }
        "month" if bytes.len() == 7 && bytes[4] == b'-' => decimal(&bytes[5..])
            .is_some_and(|month| (1..=12).contains(&month) && (year < 9999 || month < 12)),
        "day" if bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-' => {
            let month = decimal(&bytes[5..7])
                .and_then(|month| u8::try_from(month).ok())
                .and_then(|month| Month::try_from(month).ok());
            let day = decimal(&bytes[8..]).and_then(|day| u8::try_from(day).ok());
            match (month, day) {
                (Some(month), Some(day)) => {
                    Date::from_calendar_date(i32::from(year), month, day).is_ok()
                        && !(year == 9999 && month == Month::December && day == 31)
                }
                _ => false,
            }
        }
        _ => false,
    }
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
    let mutation_policy = entity.remove("mutationPolicy");
    if let Some(value) = &mutation_policy {
        validate_mutation_policy(value)?;
    }
    finish(entity)?;
    Ok(BRegMetadataEntity {
        id,
        dataset_identifier,
        route,
        schema_path,
        operations,
        readable_fields,
        mutation_policy,
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
    let source_record_type = identifier(required(&mut operation, "sourceRecordType")?)?;
    let response_record_type = identifier(required(&mut operation, "responseRecordType")?)?;
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
    let request = parse_request(required(&mut operation, "request")?)?;
    let record_type_label = bounded_text(required(&mut operation, "recordTypeLabel")?)?;
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
    let mut query_value = required(&mut operation, "query")?;
    let spatial_is_supported = validate_query(query_value.clone())?;
    if !spatial_is_supported {
        query_value
            .as_object_mut()
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?
            .remove("spatialQueries");
    }
    let query = serde_json::from_value(query_value)
        .map_err(|_| metadata_error(BRegMetadataErrorKind::Shape))?;
    let read_path = operation
        .remove("readPath")
        .map(parse_read_path)
        .transpose()?;
    finish(operation)?;
    Ok(BRegMetadataOperation {
        id,
        method,
        path,
        kind,
        source_record_type,
        response_record_type,
        access_profile,
        required_capabilities,
        fields,
        readable_fields,
        create_writable_fields,
        patch_writable_fields,
        request,
        record_type_label,
        title_fields,
        query,
        selectors,
        read_path,
    })
}

fn parse_field(value: Value) -> Result<BRegMetadataField, BRegMetadataError> {
    let mut field = object(value)?;
    let id = identifier(required(&mut field, "id")?)?;
    let api_name_value = required(&mut field, "apiName")?;
    let schema = required(&mut field, "schema")?;
    let api_name = api_name(api_name_value)?;
    let required_value = boolean(required(&mut field, "required")?)?;
    let nullable = boolean(required(&mut field, "nullable")?)?;
    let read_only = boolean(required(&mut field, "readOnly")?)?;
    let removable = boolean(required(&mut field, "removable")?)?;
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
    let name = reference.remove("name").map(api_name).transpose()?;
    let inverse_name = reference.remove("inverseName").map(api_name).transpose()?;
    let cardinality = reference.remove("cardinality").map(string).transpose()?;
    if cardinality
        .as_deref()
        .is_some_and(|value| !matches!(value, "one" | "optional-one" | "many"))
    {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let manual_entry = boolean(required(&mut reference, "manualEntry")?)?;
    let target_record_type = reference
        .remove("targetRecordType")
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
        name,
        cardinality,
        inverse_name,
        target_record_type,
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
        let value_origin_is_supported =
            matches!(value_origin.as_str(), "request" | "verified-claim");
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
        if value_origin_is_supported {
            if (value_origin == "request" && request_fields.len() != fields.len())
                || (value_origin == "verified-claim" && !request_fields.is_empty())
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
    }
    Ok(parsed)
}

fn validate_query(value: Value) -> Result<bool, BRegMetadataError> {
    if value.is_null() {
        return Ok(true);
    }
    let mut query = object(value)?;
    identifier(required(&mut query, "kind")?)?;
    validate_field_identities(required(&mut query, "selectableFields")?, None)?;
    validate_field_identities(required(&mut query, "filterableFields")?, Some("operators"))?;
    validate_field_identities(required(&mut query, "sortableFields")?, Some("directions"))?;
    boolean(required(&mut query, "allowCount")?)?;
    positive_integer(required(&mut query, "defaultPageSize")?)?;
    positive_integer(required(&mut query, "maximumPageSize")?)?;
    positive_integer(required(&mut query, "maximumFilterClauses")?)?;
    positive_integer(required(&mut query, "maximumInValues")?)?;
    validate_pagination(required(&mut query, "pagination")?)?;
    validate_temporal(required(&mut query, "temporal")?)?;
    let spatial_is_supported = query
        .remove("spatialQueries")
        .map(validate_spatial_queries)
        .transpose()?
        .unwrap_or(true);
    finish(query)?;
    Ok(spatial_is_supported)
}

fn validate_spatial_queries(value: Value) -> Result<bool, BRegMetadataError> {
    let mut spatial = object(value)?;
    let mut bbox = object(required(&mut spatial, "bbox")?)?;
    api_name(required(&mut bbox, "geometryProperty")?)?;
    positive_number_with_maximum(required(&mut bbox, "maximumLongitudeSpanDegrees")?, 360.0)?;
    positive_number_with_maximum(required(&mut bbox, "maximumLatitudeSpanDegrees")?, 180.0)?;
    let coordinate_reference_system = string(required(&mut bbox, "coordinateReferenceSystem")?)?;
    let semantics = string(required(&mut bbox, "semantics")?)?;
    finish(bbox)?;
    finish(spatial)?;
    Ok(coordinate_reference_system == "CRS84" && semantics == "inclusive_2d_non_crossing")
}

fn validate_field_identities(
    value: Value,
    extra_member: Option<&str>,
) -> Result<(), BRegMetadataError> {
    let mut ids = BTreeSet::new();
    let mut api_names = BTreeSet::new();
    for field in array(value)? {
        let mut field = object(field)?;
        let id = identifier(required(&mut field, "id")?)?;
        let api = api_name(required(&mut field, "apiName")?)?;
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
        "as-of" => {
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
        // A mode this client does not understand has no members it can
        // check. The descriptor stays as served: null already means the
        // collection is not temporal.
        _ => {}
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

fn validate_mutation_policy(value: &Value) -> Result<(), BRegMetadataError> {
    let mut policy = object(value.clone())?;
    for operation in ["create", "patch", "tombstone"] {
        if let Some(mode) = policy.remove(operation) {
            if !matches!(mode.as_str(), Some("direct" | "proposal-required")) {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
        }
    }
    if policy.is_empty() {
        Ok(())
    } else {
        Err(metadata_error(BRegMetadataErrorKind::Shape))
    }
}

fn parse_actions(value: Value) -> Result<Vec<BRegActionDescriptor>, BRegMetadataError> {
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
            "revision",
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
        let api_name = api_name(required(&mut action, "apiName")?)?;
        let definition_revision = string(required(&mut action, "revision")?)?;
        if !valid_revision(&definition_revision) {
            return Err(metadata_error(BRegMetadataErrorKind::Revision));
        }
        let display = required(&mut action, "display")?;
        if !display.is_object() {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        let mut execution = object(required(&mut action, "execution")?)?;
        let mode = match string(required(&mut execution, "mode")?)?.as_str() {
            "immediate" => BRegActionMode::Immediate,
            "proposal" => BRegActionMode::Proposal,
            _ => return Err(metadata_error(BRegMetadataErrorKind::Shape)),
        };
        let required_capabilities =
            optional_identifier_array(&mut action, "requiredCapabilities")?.unwrap_or_default();
        ensure_unique(required_capabilities.iter().map(String::as_str))?;
        let route = action
            .remove("route")
            .map(nullable_path)
            .transpose()?
            .flatten();
        let condition_route = action
            .remove("conditionRoute")
            .map(nullable_path)
            .transpose()?
            .flatten();
        let input_mode = action.remove("inputMode").map(identifier).transpose()?;
        let maximum_input_string_bytes = match action.remove("maximumInputStringBytes") {
            None | Some(Value::Null) => None,
            Some(value) => Some(positive_integer(value)?),
        };
        let attachments = action
            .remove("attachments")
            .map(parse_action_attachments)
            .transpose()?
            .unwrap_or_default();
        if mode == BRegActionMode::Immediate && !attachments.is_empty() {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        let inputs = array(required(&mut action, "inputs")?)?
            .into_iter()
            .map(parse_action_input)
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(inputs.iter().map(|input| input.id.as_str()))?;
        ensure_unique(inputs.iter().map(|input| input.api_name.as_str()))?;
        let reference_inputs = array(required(&mut action, "referenceInputs")?)?
            .into_iter()
            .map(parse_action_reference_input)
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
            .map(parse_action_result_effect)
            .collect::<Result<Vec<_>, _>>()?;
        ensure_unique(result_effects.iter().map(|effect| effect.effect.as_str()))?;

        let mut access = object(required(&mut action, "access")?)?;
        let access_profile = identifier(required(&mut access, "selectedProfile")?)?;
        finish(access)?;
        let mut routes = object(required(&mut action, "routes")?)?;
        let invocation = if mode == BRegActionMode::Immediate {
            "invoke"
        } else {
            "start"
        };
        let invoke_path = routes
            .remove(invocation)
            .map(|value| {
                parse_action_route(
                    value,
                    &format!("actions.{id}.{invocation}"),
                    true,
                    &format!("action-{id}-invoke-input"),
                    &format!("action-{id}-invoke-response"),
                )
            })
            .transpose()?;
        if mode == BRegActionMode::Immediate && invoke_path.is_none() {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        if invoke_path != route {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        let target_conditions_path = match routes.remove("targetConditions").unwrap_or(Value::Null)
        {
            Value::Null => None,
            value => Some(parse_action_route(
                value,
                &format!("actions.{id}.target-conditions"),
                false,
                &format!("action-{id}-target-conditions-input"),
                &format!("action-{id}-target-conditions-response"),
            )?),
        };
        if target_conditions_path != condition_route {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        let availability_path = match routes.remove("availability").unwrap_or(Value::Null) {
            Value::Null => None,
            value => Some(parse_action_route(
                value,
                &format!("actions.{id}.availability"),
                false,
                &format!("action-{id}-availability-input"),
                &format!("action-{id}-availability-response"),
            )?),
        };
        let expected_availability_path = route
            .as_ref()
            .filter(|_| mode == BRegActionMode::Immediate && !reference_inputs.is_empty())
            .map(|path| format!("{path}/availability"));
        if availability_path.is_some() && availability_path != expected_availability_path {
            return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
        }
        if mode == BRegActionMode::Proposal
            && (condition_route.is_some() || !required_condition_keys.is_empty())
        {
            return Err(metadata_error(BRegMetadataErrorKind::Shape));
        }
        finish(routes)?;
        let mut bounds_value = object(required(&mut action, "bounds")?)?;
        let bounds = BRegActionBounds {
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
        parsed.push(BRegActionDescriptor {
            id,
            mode,
            api_name,
            definition_revision,
            display,
            required_capabilities,
            route,
            condition_route,
            input_mode,
            maximum_input_string_bytes,
            inputs,
            attachments,
            reference_inputs,
            required_condition_keys,
            result_effects,
            access_profile,
            invoke_path,
            target_conditions_path,
            availability_path,
            bounds,
        });
    }
    Ok(parsed)
}

fn parse_proposal_actions(
    value: Value,
) -> Result<Vec<BRegProposalActionDescriptor>, BRegMetadataError> {
    let mut identities = BTreeSet::new();
    array(value)?
        .into_iter()
        .map(|value| {
            let mut entry = object(value)?;
            let action_id = identifier(required(&mut entry, "actionId")?)?;
            let access_profile = identifier(required(&mut entry, "accessProfile")?)?;
            if !identities.insert((action_id.clone(), access_profile.clone())) {
                return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
            }
            let operations = identifier_array(required(&mut entry, "operations")?)?;
            ensure_unique(operations.iter().map(String::as_str))?;
            if operations.is_empty() {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            let readable_inputs = identifier_array(required(&mut entry, "readableInputs")?)?;
            ensure_unique(readable_inputs.iter().map(String::as_str))?;
            if !readable_inputs.is_empty() && !operations.iter().any(|operation| operation == "get")
            {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            finish(entry)?;
            Ok(BRegProposalActionDescriptor {
                action_id,
                access_profile,
                operations,
                readable_inputs,
            })
        })
        .collect()
}

fn parse_action_attachments(
    value: Value,
) -> Result<Vec<BRegActionAttachmentDescriptor>, BRegMetadataError> {
    let slots = array(value)?
        .into_iter()
        .map(|value| {
            let mut slot = object(value)?;
            let id = identifier(required(&mut slot, "id")?)?;
            let required_slot = boolean(required(&mut slot, "required")?)?;
            let maximum_bytes = positive_integer(required(&mut slot, "maximumBytes")?)?;
            if maximum_bytes > crate::MAX_BREG_ATTACHMENT_BYTES {
                return Err(metadata_error(BRegMetadataErrorKind::Bound));
            }
            let content_types = array(required(&mut slot, "contentTypes")?)?
                .into_iter()
                .map(bounded_text)
                .collect::<Result<Vec<_>, _>>()?;
            ensure_unique(content_types.iter().map(String::as_str))?;
            if content_types.is_empty()
                || content_types.len() > crate::MAX_BREG_ATTACHMENT_CONTENT_TYPES
                || content_types
                    .iter()
                    .any(|value| !crate::valid_attachment_content_type(value))
            {
                return Err(metadata_error(BRegMetadataErrorKind::Shape));
            }
            finish(slot)?;
            Ok(BRegActionAttachmentDescriptor {
                id,
                required: required_slot,
                content_types,
                maximum_bytes,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure_unique(slots.iter().map(|slot| slot.id.as_str()))?;
    if slots.len() > crate::MAX_BREG_ATTACHMENT_SLOTS {
        return Err(metadata_error(BRegMetadataErrorKind::Bound));
    }
    Ok(slots)
}

fn parse_action_input(value: Value) -> Result<BRegActionInputDescriptor, BRegMetadataError> {
    let mut input = object(value)?;
    let schema = required(&mut input, "schema")?;
    if !schema.is_object() && !schema.is_boolean() {
        return Err(metadata_error(BRegMetadataErrorKind::Shape));
    }
    let parsed = BRegActionInputDescriptor {
        id: identifier(required(&mut input, "id")?)?,
        api_name: api_name(required(&mut input, "apiName")?)?,
        label: input.remove("label").map(string).transpose()?,
        description: input.remove("description").map(string).transpose()?,
        schema,
        field_type: required(&mut input, "fieldType")?,
        required: boolean(required(&mut input, "required")?)?,
        nullable: optional_bool(&mut input, "nullable")?,
        classification: identifier(required(&mut input, "classification")?)?,
    };
    finish(input)?;
    Ok(parsed)
}

fn parse_action_reference_input(
    value: Value,
) -> Result<BRegActionReferenceInputDescriptor, BRegMetadataError> {
    let mut input = object(value)?;
    let parsed = BRegActionReferenceInputDescriptor {
        input: identifier(required(&mut input, "input")?)?,
        api_name: api_name(required(&mut input, "apiName")?)?,
        target_record_type: identifier(required(&mut input, "targetRecordType")?)?,
    };
    finish(input)?;
    Ok(parsed)
}

fn parse_action_result_effect(
    value: Value,
) -> Result<BRegActionResultEffectDescriptor, BRegMetadataError> {
    let mut effect = object(value)?;
    let parsed = BRegActionResultEffectDescriptor {
        effect: identifier(required(&mut effect, "effect")?)?,
        entity: identifier(required(&mut effect, "recordType")?)?,
        operation: BRegOperationKind::parse(identifier(required(&mut effect, "operation")?)?),
    };
    finish(effect)?;
    Ok(parsed)
}

fn parse_action_route(
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
            .any(|entity| entity.id == operation.response_record_type)
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
            .filter_map(|field| field.reference.as_ref()?.target_record_type.as_ref())
        {
            if !entities.iter().any(|entity| entity.id == *target) {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
    }
    for entity in entities {
        if entity.readable_fields.iter().any(|field| {
            !operations.iter().any(|operation| {
                operation.response_record_type == entity.id
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
                operation.response_record_type == entity.id
                    && operation.kind.as_str() == kind.as_str()
                    && operation.access_profile == *profile
            }) {
                return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
            }
        }
        let _ = (&entity.schema_path, &entity.mutation_policy);
    }
    Ok(())
}

fn decode_unique_json(bytes: &[u8]) -> Result<Value, BRegMetadataError> {
    parse_json_preserving_integers(bytes).map_err(|error| {
        if error.to_string().contains("duplicate JSON object member") {
            metadata_error(BRegMetadataErrorKind::DuplicateMember)
        } else {
            metadata_error(BRegMetadataErrorKind::Json)
        }
    })
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

fn finish(_unknown_members: Map<String, Value>) -> Result<(), BRegMetadataError> {
    // The duplicate-key decoder and whole-document bound walk run before
    // parsing, so ignored extension members remain unique and resource-bounded.
    Ok(())
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

fn bounded_string(value: Value) -> Result<String, BRegMetadataError> {
    let value = string(value)?;
    if value.len() > MAX_STRING_BYTES {
        return Err(metadata_error(BRegMetadataErrorKind::Bound));
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

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "metadata_vocabulary_tests.rs"]
mod vocabulary_tests;
