// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::context::{
    AuthorizedActionContext, AuthorizedRequestContext, VerifiedRequestTargetAuthority,
    VerifiedRowBoundary,
};
use crate::contract::FieldTypeSource;
use crate::correlation::RequestCorrelation;
use crate::cursor::{
    CursorAdapter, CursorBinding, CursorCodec, CursorContinuation, CursorQuery,
    CursorRepresentation,
};
use crate::model::{
    CompiledQueryFilterOperator, CompiledQueryKind, CompiledQuerySortDirection, CompiledRegistry,
    HttpMethod,
};
use crate::mutation::BatchMutationItem;
use crate::postgres::{PostgresRecordMutationService, PostgresRevisionReadService};
use crate::record_profile::RecordRepresentation;

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldReadResponse {
    body: Vec<u8>,
    content_type: ReadResponseContentType,
    strong_etag: Option<Vec<u8>>,
}

impl HeldReadResponse {
    pub fn from_json(value: &Value) -> Result<Self, ReadServiceError> {
        Self::from_value(value, ReadResponseContentType::Json)
    }

    pub fn from_json_ld(value: &Value) -> Result<Self, ReadServiceError> {
        Self::from_value(value, ReadResponseContentType::JsonLd)
    }

    pub(crate) fn from_registry_record(
        value: &Value,
        representation: RecordRepresentation,
    ) -> Result<Self, ReadServiceError> {
        match representation {
            RecordRepresentation::Json => Self::from_json(value),
            RecordRepresentation::JsonLd => Self::from_json_ld(value),
        }
    }

    pub fn from_geojson(value: &Value) -> Result<Self, ReadServiceError> {
        Self::from_value(value, ReadResponseContentType::GeoJson)
    }

    fn from_value(
        value: &Value,
        content_type: ReadResponseContentType,
    ) -> Result<Self, ReadServiceError> {
        let body = registry_platform_canonical_json::canonicalize_json(value)
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(Self {
            body,
            content_type,
            strong_etag: None,
        })
    }

    pub(crate) fn with_strong_etag(mut self, strong_etag: String) -> Self {
        self.strong_etag = Some(strong_etag.into_bytes());
        self
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn content_type(&self) -> &'static str {
        self.content_type.as_str()
    }

    #[must_use]
    pub fn strong_etag(&self) -> Option<&[u8]> {
        self.strong_etag.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadResponseContentType {
    Json,
    JsonLd,
    GeoJson,
}

impl ReadResponseContentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
            Self::GeoJson => "application/geo+json",
        }
    }
}

/// Compiler-authorized input for record creation.
pub struct CreateMutationInput<'a> {
    pub route_id: &'a str,
    pub idempotency_key: &'a str,
    pub context: &'a AuthorizedRequestContext,
    pub entity_id: &'a str,
    pub data: serde_json::Map<String, Value>,
    pub response_fields: BTreeSet<String>,
    pub representation: RecordRepresentation,
    pub correlation: &'a RequestCorrelation,
}

/// Compiler-authorized input shared by conditional record mutations.
pub struct ConditionalMutationInput<'a> {
    pub route_id: &'a str,
    pub idempotency_key: &'a str,
    pub if_match: &'a str,
    pub context: &'a AuthorizedRequestContext,
    pub entity_id: &'a str,
    pub record_id: &'a str,
    pub response_fields: BTreeSet<String>,
    pub representation: RecordRepresentation,
    pub correlation: &'a RequestCorrelation,
}

/// Compiler-authorized input for one bounded entity-local batch transaction.
pub struct BatchMutationInput<'a> {
    pub route_id: &'a str,
    pub idempotency_key: &'a str,
    pub context: &'a AuthorizedRequestContext,
    pub entity_id: &'a str,
    pub items: Vec<BatchMutationItem>,
    pub change_context: Option<crate::history_context::ChangeContext>,
    pub response_fields: BTreeSet<String>,
    pub body_bytes: usize,
    pub correlation: &'a RequestCorrelation,
}

/// Strictly parsed HTTP body for one compiled change-request action route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestActionBody {
    Submit,
    Approve {
        proposal_version: u32,
        effect_digest: String,
    },
    Reject {
        proposal_version: u32,
        effect_digest: String,
    },
    RequestRevision {
        proposal_version: u32,
        effect_digest: String,
    },
    Revise {
        rebase: bool,
    },
    Cancel,
    Apply {
        proposal_version: u32,
        effect_digest: String,
    },
}

/// Target authority derived from the selected review/apply grant row
/// boundaries. It contains only values copied from verified token claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestActionTargetAuthority {
    pub target_entity_id: String,
    pub readable_fields: BTreeSet<String>,
    pub row_boundaries: Vec<VerifiedRowBoundary>,
}

impl From<&VerifiedRequestTargetAuthority> for RequestActionTargetAuthority {
    fn from(authority: &VerifiedRequestTargetAuthority) -> Self {
        Self {
            target_entity_id: authority.target_entity_id().to_owned(),
            readable_fields: authority.readable_fields().clone(),
            row_boundaries: authority.row_boundaries().to_vec(),
        }
    }
}

/// Compiler-authorized input for one finite change-request action.
pub struct RequestActionInput<'a> {
    pub route_id: &'a str,
    pub idempotency_key: &'a str,
    pub if_match: &'a str,
    pub context: &'a AuthorizedRequestContext,
    pub entity_id: &'a str,
    pub record_id: &'a str,
    pub action: RequestActionBody,
    pub response_fields: BTreeSet<String>,
    pub target_authority: Vec<RequestActionTargetAuthority>,
    pub correlation: &'a RequestCorrelation,
}

/// One invocation whose input and condition keys have been resolved to logical
/// action input IDs. The runtime still validates values, targets and authority.
pub struct ImmediateActionInput<'a> {
    pub route_id: &'a str,
    pub action_id: &'a str,
    pub idempotency_key: &'a str,
    pub context: &'a AuthorizedActionContext,
    pub input: serde_json::Map<String, Value>,
    pub preconditions: BTreeMap<String, String>,
    pub body_bytes: usize,
    pub correlation: &'a RequestCorrelation,
}

/// Exact-ID condition acquisition under an action's selected authority.
pub struct ActionTargetConditionsInput<'a> {
    pub route_id: &'a str,
    pub action_id: &'a str,
    pub context: &'a AuthorizedActionContext,
    pub input: serde_json::Map<String, Value>,
    pub correlation: &'a RequestCorrelation,
}

#[derive(Clone)]
pub struct RecordReadRequest {
    pub entity_id: String,
    pub operation_id: String,
    pub method: HttpMethod,
    pub context: AuthorizedRequestContext,
    /// Exact response fields authorized for this operation. Source plans must
    /// select and process only this set, plus compiler-owned row-boundary
    /// fields from `context`; they must never fetch the profile's wider field
    /// set and rely on response filtering.
    pub selected_fields: BTreeSet<String>,
    pub representation: CursorRepresentation,
    pub adapter: crate::cursor::CursorAdapter,
    pub adapter_origin: Option<String>,
    pub geojson_next_link_prefix: Option<String>,
    pub kind: RecordReadKind,
    /// Hard source-execution result bound. Implementations must apply it in
    /// the database plan before rows are materialized.
    pub maximum_records: usize,
    /// Bounded request-proposal history continuation for a single request GET.
    /// This is never accepted on list/cursor or canonical entity reads.
    pub request_history_after_proposal_version: Option<i64>,
    pub correlation: RequestCorrelation,
}

impl fmt::Debug for RecordReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordReadRequest")
            .field("entity_id", &self.entity_id)
            .field("operation_id", &self.operation_id)
            .field("method", &self.method)
            .field("context", &"<redacted>")
            .field("selected_fields", &self.selected_fields)
            .field("representation", &self.representation)
            .field("adapter", &self.adapter)
            .field(
                "adapter_origin",
                &self.adapter_origin.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "geojson_next_link_prefix",
                &self.geojson_next_link_prefix.as_ref().map(|_| "<redacted>"),
            )
            .field("kind", &self.kind)
            .field("maximum_records", &self.maximum_records)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RecordReadKind {
    Get {
        id: String,
    },
    List {
        plan: CompiledReadQuery,
    },
    Lookup {
        selector: CompiledLookupSelector,
    },
    Relationship {
        root_id: String,
        path_id: String,
        plan: CompiledReadQuery,
    },
}

impl fmt::Debug for RecordReadKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get { id: _ } => formatter
                .debug_struct("Get")
                .field("id", &"<redacted>")
                .finish(),
            Self::List { plan } => formatter.debug_struct("List").field("plan", plan).finish(),
            Self::Lookup { selector } => formatter
                .debug_struct("Lookup")
                .field("selector", selector)
                .finish(),
            Self::Relationship {
                root_id: _,
                path_id,
                plan,
            } => formatter
                .debug_struct("Relationship")
                .field("root_id", &"<redacted>")
                .field("path_id", path_id)
                .field("plan", plan)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompiledLookupSelector {
    pub route_id: String,
    pub query_operation_id: String,
    pub selector_id: String,
    pub value_origin: crate::contract::LookupValueOrigin,
    pub values: Vec<LookupSelectorValue>,
}

impl fmt::Debug for CompiledLookupSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledLookupSelector")
            .field("route_id", &self.route_id)
            .field("query_operation_id", &self.query_operation_id)
            .field("selector_id", &self.selector_id)
            .field("value_origin", &self.value_origin)
            .field(
                "values",
                &self.values.iter().map(|_| "<redacted>").collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LookupSelectorValue {
    pub field_id: String,
    pub field_type: FieldTypeSource,
    pub value: String,
}

impl fmt::Debug for LookupSelectorValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupSelectorValue")
            .field("field_id", &self.field_id)
            .field("field_type", &self.field_type)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CompiledReadQuery {
    pub route_id: String,
    pub query_operation_id: String,
    pub kind: CompiledQueryKind,
    pub cursor_binding: CursorBinding,
    pub cursor_query: CursorQuery,
    pub projection: Vec<ReadProjectionField>,
    pub filter: Option<ReadFilterExpr>,
    pub spatial: Option<ReadSpatialQuery>,
    pub order: Option<ReadOrderClause>,
    pub include_count: bool,
    pub page_size: u16,
    pub temporal_instant: Option<String>,
    pub adapter: crate::cursor::CursorAdapter,
    pub adapter_origin: Option<String>,
    pub continuation: Option<CursorContinuation>,
}

pub(crate) struct CursorQueryReferenceInput<'a> {
    pub route_id: &'a str,
    pub query_operation_id: &'a str,
    pub query_kind: CompiledQueryKind,
    pub selected_profile: &'a str,
    pub projection: Vec<Value>,
    pub filter: Option<Value>,
    pub spatial: Option<Value>,
    pub order: Option<Value>,
    pub page_size: u16,
    pub include_count: bool,
    pub temporal_instant: Option<&'a str>,
    pub scope: Value,
    pub representation: CursorRepresentation,
    pub adapter: CursorAdapter,
    pub adapter_origin: Option<&'a str>,
}

pub(crate) fn cursor_query_reference_value(input: CursorQueryReferenceInput<'_>) -> Value {
    let mut value = Map::new();
    value.insert("routeId".to_owned(), json!(input.route_id));
    value.insert(
        "queryOperationId".to_owned(),
        json!(input.query_operation_id),
    );
    value.insert("queryKind".to_owned(), json!(input.query_kind));
    value.insert("selectedProfile".to_owned(), json!(input.selected_profile));
    value.insert("projection".to_owned(), json!(input.projection));
    value.insert("filter".to_owned(), json!(input.filter));
    value.insert("spatial".to_owned(), json!(input.spatial));
    value.insert("order".to_owned(), json!(input.order));
    value.insert("pageSize".to_owned(), json!(input.page_size));
    value.insert("includeCount".to_owned(), json!(input.include_count));
    value.insert("temporalInstant".to_owned(), json!(input.temporal_instant));
    value.insert("scope".to_owned(), input.scope);
    value.insert("representation".to_owned(), json!(input.representation));
    value.insert("adapter".to_owned(), json!(input.adapter));
    if let Some(origin) = input.adapter_origin {
        value.insert("adapterOrigin".to_owned(), json!(origin));
    }
    Value::Object(value)
}

impl fmt::Debug for CompiledReadQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledReadQuery")
            .field("route_id", &self.route_id)
            .field("query_operation_id", &self.query_operation_id)
            .field("kind", &self.kind)
            .field("cursor_binding", &self.cursor_binding)
            .field("cursor_query", &"<redacted>")
            .field("projection", &self.projection)
            .field("filter", &self.filter)
            .field("spatial", &self.spatial)
            .field("order", &self.order)
            .field("include_count", &self.include_count)
            .field("page_size", &self.page_size)
            .field(
                "temporal_instant",
                &self.temporal_instant.as_ref().map(|_| "<redacted>"),
            )
            .field("adapter", &self.adapter)
            .field(
                "continuation",
                &self.continuation.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReadSpatialQuery {
    pub bbox: ReadBboxQuery,
}

impl fmt::Debug for ReadSpatialQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadSpatialQuery(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReadBboxQuery {
    pub geometry_field: String,
    pub west: String,
    pub south: String,
    pub east: String,
    pub north: String,
    pub maximum_longitude_span_degrees: String,
    pub maximum_latitude_span_degrees: String,
}

impl fmt::Debug for ReadBboxQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadBboxQuery")
            .field("geometry_field", &self.geometry_field)
            .field("coordinates", &"<redacted>")
            .field("maximum_longitude_span_degrees", &"<redacted>")
            .field("maximum_latitude_span_degrees", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReadProjectionField {
    pub field_id: String,
    pub field_type: FieldTypeSource,
}

impl fmt::Debug for ReadProjectionField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadProjectionField")
            .field("field_id", &self.field_id)
            .field("field_type", &self.field_type)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ReadFilterExpr {
    Binary {
        op: ReadLogicalOp,
        left: Box<ReadFilterExpr>,
        right: Box<ReadFilterExpr>,
    },
    Not(Box<ReadFilterExpr>),
    Group(Box<ReadFilterExpr>),
    Predicate(ReadFilterPredicate),
}

impl fmt::Debug for ReadFilterExpr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadFilterExpr::Binary { op, left, right } => formatter
                .debug_struct("Binary")
                .field("op", op)
                .field("left", left)
                .field("right", right)
                .finish(),
            ReadFilterExpr::Not(expr) => formatter.debug_tuple("Not").field(expr).finish(),
            ReadFilterExpr::Group(expr) => formatter.debug_tuple("Group").field(expr).finish(),
            ReadFilterExpr::Predicate(predicate) => {
                formatter.debug_tuple("Predicate").field(predicate).finish()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadLogicalOp {
    And,
    Or,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReadFilterPredicate {
    pub field_id: String,
    pub field_type: FieldTypeSource,
    pub operator: ReadFilterOperator,
    pub values: Vec<String>,
}

impl fmt::Debug for ReadFilterPredicate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadFilterPredicate")
            .field("field_id", &self.field_id)
            .field("field_type", &self.field_type)
            .field("operator", &self.operator)
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReadOrderClause {
    pub field_id: String,
    pub field_type: FieldTypeSource,
    pub direction: CompiledQuerySortDirection,
}

impl fmt::Debug for ReadOrderClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOrderClause")
            .field("field_id", &self.field_id)
            .field("field_type", &self.field_type)
            .field("direction", &self.direction)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadFilterOperator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    IsNull,
    IsNotNull,
    StartsWith,
    Contains,
}

impl ReadFilterOperator {
    #[must_use]
    pub fn compiled_capability(self) -> CompiledQueryFilterOperator {
        match self {
            Self::Eq | Self::Ne => CompiledQueryFilterOperator::Equals,
            Self::Lt | Self::Le | Self::Gt | Self::Ge => CompiledQueryFilterOperator::Range,
            Self::In => CompiledQueryFilterOperator::In,
            Self::IsNull => CompiledQueryFilterOperator::IsNull,
            Self::IsNotNull => CompiledQueryFilterOperator::IsNotNull,
            Self::StartsWith => CompiledQueryFilterOperator::Prefix,
            Self::Contains => CompiledQueryFilterOperator::Contains,
        }
    }
}

#[derive(Clone)]
pub struct RecordReadRefusal {
    pub method: HttpMethod,
    pub operation_id: String,
    pub target_record: Option<String>,
    pub principal: Option<String>,
    pub selected_access_profile: Option<String>,
    pub purpose_present: bool,
    pub correlation: RequestCorrelation,
}

#[derive(Clone)]
pub struct RevisionReadRequest {
    pub entity_id: String,
    pub operation_id: String,
    pub method: HttpMethod,
    pub record_id: String,
    pub revision: Option<i64>,
    pub context: AuthorizedRequestContext,
    pub selected_fields: BTreeSet<String>,
    pub representation: CursorRepresentation,
    pub maximum_records: usize,
    pub correlation: RequestCorrelation,
}

/// Authorized stored-record history query. The plan's snapshot scope carries
/// an exact reference, or requests one capture on the first page. It must never
/// be executed against live record relations.
#[derive(Clone)]
pub struct SnapshotReadRequest {
    pub entity_id: String,
    pub operation_id: String,
    pub method: HttpMethod,
    pub context: AuthorizedRequestContext,
    pub selected_fields: BTreeSet<String>,
    pub plan: CompiledReadQuery,
    pub maximum_records: usize,
    pub correlation: RequestCorrelation,
}

impl fmt::Debug for SnapshotReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotReadRequest")
            .field("entity_id", &self.entity_id)
            .field("operation_id", &self.operation_id)
            .field("context", &"<redacted>")
            .field("plan", &self.plan)
            .field("maximum_records", &self.maximum_records)
            .finish()
    }
}

impl fmt::Debug for RevisionReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevisionReadRequest")
            .field("entity_id", &self.entity_id)
            .field("operation_id", &self.operation_id)
            .field("method", &self.method)
            .field("record_id", &"<redacted>")
            .field("revision", &self.revision.map(|_| "<redacted>"))
            .field("context", &"<redacted>")
            .field("selected_fields", &self.selected_fields)
            .field("maximum_records", &self.maximum_records)
            .finish()
    }
}

#[derive(Clone)]
pub struct RevisionReadRefusal {
    pub method: HttpMethod,
    pub operation_id: String,
    pub target_record: Option<String>,
    pub principal: Option<String>,
    pub selected_access_profile: Option<String>,
    pub purpose_present: bool,
    pub correlation: RequestCorrelation,
}

impl fmt::Debug for RevisionReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevisionReadRefusal")
            .field("method", &self.method)
            .field("operation_id", &self.operation_id)
            .field(
                "target_record",
                &self.target_record.as_ref().map(|_| "<redacted>"),
            )
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("selected_access_profile", &self.selected_access_profile)
            .field("purpose_present", &self.purpose_present)
            .finish()
    }
}

impl fmt::Debug for RecordReadRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordReadRefusal")
            .field("method", &self.method)
            .field("operation_id", &self.operation_id)
            .field(
                "target_record",
                &self.target_record.as_ref().map(|_| "<redacted>"),
            )
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("selected_access_profile", &self.selected_access_profile)
            .field("purpose_present", &self.purpose_present)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRuntimeIdentity {
    pub package_revision: String,
    pub schema_fingerprint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadServiceError {
    Unavailable,
    CursorInvalid,
}

/// Record reads execute only after the HTTP layer has selected and authorized
/// one finite compiled access profile. Implementations must apply the supplied
/// projection, result bound, and row boundaries in the database transaction;
/// the HTTP response projection is only defense in depth.
pub trait RecordReadService: Send + Sync {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>>;

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>>;

    fn lookup(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>>;

    fn refusal(
        &self,
        _request: RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Revision reads operate only on the canonical internal revision journal.
/// The HTTP layer must select and authorize one non-anonymous compiled profile
/// before invoking this boundary.
pub trait RevisionReadService: Send + Sync {
    fn detail(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>>;

    fn list(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>>;

    fn refusal(
        &self,
        _request: RevisionReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async { Ok(()) })
    }
}

pub trait ReadinessProbe: Send + Sync {
    fn is_ready(&self) -> ServiceFuture<'_, bool>;
}

/// A distinct execution boundary for historical rows and retained schemas.
pub trait SnapshotReadService: Send + Sync {
    fn list(
        &self,
        request: SnapshotReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>>;

    fn refusal(
        &self,
        request: RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>>;
}

#[derive(Clone)]
pub struct HttpService {
    pub(crate) registry: Arc<CompiledRegistry>,
    pub(crate) identity: ReadRuntimeIdentity,
    pub(crate) records: Arc<dyn RecordReadService>,
    pub(crate) revisions: Option<Arc<dyn RevisionReadService>>,
    pub(crate) snapshots: Option<Arc<dyn SnapshotReadService>>,
    pub(crate) cursors: Arc<CursorCodec>,
    pub(crate) mutations: Option<Arc<PostgresRecordMutationService>>,
    pub(crate) readiness: Arc<dyn ReadinessProbe>,
    pub(crate) public_origin: Option<crate::runtime_config::PublicOrigin>,
}

impl HttpService {
    pub(crate) fn read_refusal(
        &self,
        operation: crate::contract::Operation,
        request: RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        if operation == crate::contract::Operation::Snapshot {
            match &self.snapshots {
                Some(snapshots) => snapshots.refusal(request),
                None => Box::pin(async { Err(ReadServiceError::Unavailable) }),
            }
        } else {
            self.records.refusal(request)
        }
    }

    #[must_use]
    pub fn new(
        registry: Arc<CompiledRegistry>,
        identity: ReadRuntimeIdentity,
        records: Arc<dyn RecordReadService>,
        readiness: Arc<dyn ReadinessProbe>,
        cursors: Arc<CursorCodec>,
    ) -> Self {
        Self {
            registry,
            identity,
            records,
            revisions: None,
            snapshots: None,
            cursors,
            mutations: None,
            readiness,
            public_origin: None,
        }
    }

    #[must_use]
    pub fn with_public_origin(mut self, origin: crate::runtime_config::PublicOrigin) -> Self {
        self.public_origin = Some(origin);
        self
    }

    #[must_use]
    pub fn with_postgres_mutations(
        mut self,
        mutations: Arc<PostgresRecordMutationService>,
    ) -> Self {
        self.mutations = Some(mutations);
        self
    }

    #[must_use]
    pub fn with_postgres_revisions(mut self, revisions: Arc<PostgresRevisionReadService>) -> Self {
        self.revisions = Some(revisions);
        self
    }

    #[must_use]
    pub fn with_revisions(mut self, revisions: Arc<dyn RevisionReadService>) -> Self {
        self.revisions = Some(revisions);
        self
    }

    #[must_use]
    pub fn with_snapshots(mut self, snapshots: Arc<dyn SnapshotReadService>) -> Self {
        self.snapshots = Some(snapshots);
        self
    }
}
