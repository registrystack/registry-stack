//! Bounded, caller-bound Base Registry Engine runtime metadata.
//!
//! Only the served `GET /v1/registry` metadata v1 document can produce an
//! executable operation binding. Generated entity summaries and older
//! metadata artifacts are deliberately insufficient authority.

use std::collections::BTreeSet;
use std::fmt;

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
    application: BRegChangeRequestApplicationCapability,
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
    schema: Value,
    required: bool,
    nullable: bool,
    read_only: bool,
    removable: bool,
    reference_target_entity: Option<String>,
    references: Vec<BRegMetadataReference>,
}

#[derive(Clone, PartialEq)]
struct BRegMetadataReference {
    operation_id: String,
    access_profile: String,
    label_fields: Vec<String>,
}

impl BRegMetadataField {
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn api_name(&self) -> &str {
        &self.api_name
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
    create_writable_fields: Vec<String>,
    patch_writable_fields: Vec<String>,
    request: BRegOperationRequest,
}

impl BRegMetadataOperation {
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

/// Validated Base Registry Engine runtime metadata v1 for one caller projection.
#[derive(Clone, PartialEq)]
pub struct BRegMetadata {
    id: String,
    version: String,
    revision: String,
    entities: Vec<BRegMetadataEntity>,
    operations: Vec<BRegMetadataOperation>,
    actions: Option<Value>,
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
        && request.schema.as_ref() == Some(&expected_lifecycle_schema(kind))
}

fn expected_lifecycle_schema(kind: crate::BRegLifecycleOperation) -> Value {
    use crate::BRegLifecycleOperation as Lifecycle;
    match kind {
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
    }
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
    if let Some(value) = &actions {
        validate_inert_actions(value)?;
    }
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
    let application = parse_change_request_application(required(&mut capability, "application")?)?;
    finish(capability)?;
    Ok(BRegChangeRequestCapability {
        planner,
        review_mode,
        application,
    })
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
    let request = parse_request(required(&mut operation, "request")?)?;
    bounded_text(required(&mut operation, "entityLabel")?)?;
    validate_envelope_identifier(required(&mut operation, "identifier")?)?;
    let title_fields = identifier_array(required(&mut operation, "titleFields")?)?;
    ensure_unique(title_fields.iter().map(String::as_str))?;
    if title_fields
        .iter()
        .any(|title| !fields.iter().any(|field| field.id == *title))
    {
        return Err(metadata_error(BRegMetadataErrorKind::DanglingReference));
    }
    validate_selectors(required(&mut operation, "selectors")?)?;
    validate_query(required(&mut operation, "query")?)?;
    if let Some(read_path) = operation.remove("readPath") {
        validate_read_path(read_path)?;
    }
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
        create_writable_fields,
        patch_writable_fields,
        request,
    })
}

fn parse_field(value: Value) -> Result<BRegMetadataField, BRegMetadataError> {
    let mut field = object(value)?;
    let id = identifier(required(&mut field, "id")?)?;
    let api_name = api_name(required(&mut field, "apiName")?)?;
    let schema = required(&mut field, "schema")?;
    let required_value = boolean(required(&mut field, "required")?)?;
    let nullable = boolean(required(&mut field, "nullable")?)?;
    let read_only = boolean(required(&mut field, "readOnly")?)?;
    let removable = boolean(required(&mut field, "removable")?)?;
    bounded_text(required(&mut field, "label")?)?;
    let (reference_target_entity, references) = field
        .remove("reference")
        .map(parse_references)
        .transpose()?
        .unwrap_or_default();
    if let Some(code_labels) = field.remove("codeLabels") {
        let labels = object(code_labels)?;
        for (code, label) in labels {
            bounded_text(Value::String(code))?;
            bounded_text(label)?;
        }
    }
    finish(field)?;
    Ok(BRegMetadataField {
        id,
        api_name,
        schema,
        required: required_value,
        nullable,
        read_only,
        removable,
        reference_target_entity,
        references,
    })
}

fn parse_references(
    value: Value,
) -> Result<(Option<String>, Vec<BRegMetadataReference>), BRegMetadataError> {
    let mut reference = object(value)?;
    boolean(required(&mut reference, "manualEntry")?)?;
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
            Ok(BRegMetadataReference {
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
    Ok((target_entity, references))
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

fn validate_read_path(value: Value) -> Result<(), BRegMetadataError> {
    let mut read_path = object(value)?;
    identifier(required(&mut read_path, "id")?)?;
    bounded_text(required(&mut read_path, "label")?)?;
    finish(read_path)
}

fn validate_selectors(value: Value) -> Result<(), BRegMetadataError> {
    let selectors = array(value)?;
    let mut selector_ids = BTreeSet::new();
    for selector in selectors {
        let mut selector = object(selector)?;
        let id = identifier(required(&mut selector, "id")?)?;
        if !selector_ids.insert(id) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
        bounded_text(required(&mut selector, "label")?)?;
        identifier(required(&mut selector, "valueOrigin")?)?;
        let mut api_names = BTreeSet::new();
        let mut field_ids = BTreeSet::new();
        for field in array(required(&mut selector, "fields")?)? {
            let mut field = object(field)?;
            if !field_ids.insert(identifier(required(&mut field, "id")?)?)
                || !api_names.insert(api_name(required(&mut field, "apiName")?)?)
            {
                return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
            }
            bounded_text(required(&mut field, "label")?)?;
            required(&mut field, "schema")?;
            boolean(required(&mut field, "required")?)?;
            finish(field)?;
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
    }
    Ok(())
}

fn validate_query(value: Value) -> Result<(), BRegMetadataError> {
    if value.is_null() {
        return Ok(());
    }
    let mut query = object(value)?;
    identifier(required(&mut query, "kind")?)?;
    validate_field_identities(required(&mut query, "selectableFields")?, None)?;
    validate_field_identities(required(&mut query, "filterableFields")?, Some("operators"))?;
    validate_field_identities(required(&mut query, "sortableFields")?, Some("directions"))?;
    boolean(required(&mut query, "allowCount")?)?;
    positive_integer(required(&mut query, "defaultPageSize")?)?;
    positive_integer(required(&mut query, "maxPageSize")?)?;
    positive_integer(required(&mut query, "maxFilterClauses")?)?;
    positive_integer(required(&mut query, "maxInValues")?)?;
    validate_pagination(required(&mut query, "pagination")?)?;
    validate_temporal(required(&mut query, "temporal")?)?;
    finish(query)
}

fn validate_field_identities(
    value: Value,
    extra_member: Option<&str>,
) -> Result<(), BRegMetadataError> {
    let mut ids = BTreeSet::new();
    let mut api_names = BTreeSet::new();
    for field in array(value)? {
        let mut field = object(field)?;
        if !ids.insert(identifier(required(&mut field, "id")?)?)
            || !api_names.insert(api_name(required(&mut field, "apiName")?)?)
        {
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

fn validate_inert_actions(value: &Value) -> Result<(), BRegMetadataError> {
    let actions = value
        .as_array()
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
    let mut identifiers = BTreeSet::new();
    for action in actions {
        let action = action
            .as_object()
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
        let identifier_value = action
            .get("id")
            .cloned()
            .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))?;
        if !identifiers.insert(identifier(identifier_value)?) {
            return Err(metadata_error(BRegMetadataErrorKind::DuplicateIdentifier));
        }
    }
    Ok(())
}

fn positive_integer(value: Value) -> Result<u64, BRegMetadataError> {
    value
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| metadata_error(BRegMetadataErrorKind::Shape))
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
        for reference in operation.fields.iter().flat_map(|field| &field.references) {
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
            .filter_map(|field| field.reference_target_entity.as_ref())
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
