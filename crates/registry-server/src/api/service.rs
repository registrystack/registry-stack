// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use super::context::AuthorizedRequestContext;
use crate::contract::FieldTypeSource;
use crate::cursor::{CursorBinding, CursorCodec, CursorContinuation, CursorQuery};
use crate::model::{
    CompiledQueryFilterOperator, CompiledQueryKind, CompiledQuerySortDirection, CompiledRegistry,
    HttpMethod,
};
use crate::mutation::BatchMutationItem;
use crate::postgres::{PostgresRecordMutationService, PostgresRevisionReadService};

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldReadResponse {
    body: Vec<u8>,
    strong_etag: Option<Vec<u8>>,
}

impl HeldReadResponse {
    pub fn from_json(value: &Value) -> Result<Self, ReadServiceError> {
        let body = registry_platform_canonical_json::canonicalize_json(value)
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(Self {
            body,
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
    pub fn strong_etag(&self) -> Option<&[u8]> {
        self.strong_etag.as_deref()
    }
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
}

/// Compiler-authorized input for one bounded entity-local batch transaction.
pub struct BatchMutationInput<'a> {
    pub route_id: &'a str,
    pub idempotency_key: &'a str,
    pub context: &'a AuthorizedRequestContext,
    pub entity_id: &'a str,
    pub items: Vec<BatchMutationItem>,
    pub response_fields: BTreeSet<String>,
    pub body_bytes: usize,
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
    pub kind: RecordReadKind,
    /// Hard source-execution result bound. Implementations must apply it in
    /// the database plan before rows are materialized.
    pub maximum_records: usize,
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
    pub order: Option<ReadOrderClause>,
    pub include_count: bool,
    pub page_size: u16,
    pub temporal_instant: Option<String>,
    pub continuation: Option<CursorContinuation>,
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
            .field("order", &self.order)
            .field("include_count", &self.include_count)
            .field("page_size", &self.page_size)
            .field(
                "temporal_instant",
                &self.temporal_instant.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "continuation",
                &self.continuation.as_ref().map(|_| "<redacted>"),
            )
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
    pub maximum_records: usize,
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

#[derive(Clone)]
pub struct HttpService {
    pub(crate) registry: Arc<CompiledRegistry>,
    pub(crate) identity: ReadRuntimeIdentity,
    pub(crate) records: Arc<dyn RecordReadService>,
    pub(crate) revisions: Option<Arc<dyn RevisionReadService>>,
    pub(crate) cursors: Arc<CursorCodec>,
    pub(crate) mutations: Option<Arc<PostgresRecordMutationService>>,
    pub(crate) readiness: Arc<dyn ReadinessProbe>,
}

impl HttpService {
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
            cursors,
            mutations: None,
            readiness,
        }
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
}
