// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use super::context::AuthorizedRequestContext;
use crate::cursor::{CursorBinding, CursorCodec, CursorContinuation, CursorQuery};
use crate::model::{CompiledQueryFilterOperator, CompiledQueryKind, CompiledRegistry, HttpMethod};
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
    pub record_id: Option<String>,
    pub context: AuthorizedRequestContext,
    /// Exact response fields authorized for this operation. Source plans must
    /// select and process only this set, plus compiler-owned row-boundary
    /// fields from `context`; they must never fetch the profile's wider field
    /// set and rely on response filtering.
    pub selected_fields: BTreeSet<String>,
    pub query: Option<CompiledReadQuery>,
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
            .field("record_id", &self.record_id.as_ref().map(|_| "<redacted>"))
            .field("context", &"<redacted>")
            .field("selected_fields", &self.selected_fields)
            .field("query", &self.query.as_ref().map(|_| "<redacted>"))
            .field("maximum_records", &self.maximum_records)
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
    pub filters: Vec<ReadFilterClause>,
    pub sort: Option<String>,
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
            .field(
                "filters",
                &self
                    .filters
                    .iter()
                    .map(|_| "<redacted>")
                    .collect::<Vec<_>>(),
            )
            .field("sort", &self.sort)
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
pub struct ReadFilterClause {
    pub field: String,
    pub operator: CompiledQueryFilterOperator,
    pub values: Vec<String>,
}

impl fmt::Debug for ReadFilterClause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadFilterClause")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .field("values", &"<redacted>")
            .finish()
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
