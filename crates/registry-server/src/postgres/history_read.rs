// SPDX-License-Identifier: Apache-2.0

//! Bounded PostgreSQL snapshot reads over retained stored-record history.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::api::{
    AuthorizedRequestContext, HeldReadResponse, ReadFilterExpr, ReadFilterOperator,
    ReadFilterPredicate, ReadLogicalOp, ReadOrderClause, ReadProjectionField, ReadServiceError,
    RecordReadRefusal, RowBoundaryOperator as ApiRowBoundaryOperator, ServiceFuture,
    SnapshotReadRequest, SnapshotReadService,
};
use crate::audit::{
    append_read_terminal_audit, profile_is_keyed, record_pre_io_audit, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::contract::{FieldTypeSource, Operation};
use crate::cursor::{
    now_unix_seconds, CursorBinding, CursorCodec, CursorContinuation, CursorFilterExpr,
    CursorFilterOperator, CursorLogicalOp, CursorOrderClause, CursorProjectionField,
    CursorQueryScope,
};
use crate::history_commit::{
    capture_latest_snapshot_reference, resolve_snapshot_reference, ResolvedSnapshot,
};
use crate::history_reference::SnapshotReference;
use crate::history_schema::{
    DecodedHistorySnapshot, HistoryFieldCompatibility, HistoryFieldSource,
    HistorySchemaCompatibility, HistorySchemaDescriptor,
};
use crate::history_store::load_descriptor;
use crate::model::{
    CompiledEntity, CompiledQueryKind, CompiledQueryOperation, CompiledQuerySortDirection,
    CompiledRegistry, HttpMethod,
};
use crate::query_binding::{CursorBindingQuery, CursorBindingReferences};

use super::{
    begin_record_transaction, validate_field_value, ClaimContext, ExpectedRegistryIdentity,
    RegistryLockKey, RowBoundaryContext, RuntimePool,
};

const MAX_SQL_LIMIT: usize = 1000;
const MAX_HISTORY_PACKAGE_DESCRIPTORS: usize = 64;
// LIMIT bounds output, not latest-revision selection or historical filtering.
// Bound every database statement as well as the outer HTTP request lifetime.
const HISTORY_STATEMENT_TIMEOUT: &str = "2000ms";

/// Runtime implementation of the stored-record snapshot query surface.
#[derive(Clone)]
pub struct PostgresSnapshotReadService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
    cursors: Arc<CursorCodec>,
    fault: SnapshotReadFaultControl,
}

impl PostgresSnapshotReadService {
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
        cursors: Arc<CursorCodec>,
    ) -> Self {
        Self {
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
            cursors,
            fault: SnapshotReadFaultControl::Disabled,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: SnapshotReadFaultPoint) -> Self {
        self.fault = SnapshotReadFaultControl::At(fault);
        self
    }

    async fn execute(
        &self,
        request: SnapshotReadRequest,
    ) -> Result<SnapshotReadResult, ReadServiceError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(ReadServiceError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, &request.context, &request.entity_id)?;
        let plan = match SnapshotReadPlan::from_request(
            &self.registry,
            &self.expected,
            self.cursors.as_ref(),
            &request,
        ) {
            Ok(plan) => plan,
            Err(()) => {
                record_pre_io_audit(
                    &mut client,
                    self.lock_key,
                    self.lock_timeout,
                    &self.expected,
                    &claims,
                    &self.audit_profile,
                    PreIoAudit {
                        kind: PreIoAuditKind::Refusal,
                        method: request.method,
                        operation_id: &request.operation_id,
                        target_record: None,
                        correlation: &request.correlation,
                    },
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
                return Err(ReadServiceError::Unavailable);
            }
        };

        record_pre_io_audit(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &claims,
            &self.audit_profile,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: request.method,
                operation_id: &request.operation_id,
                target_record: None,
                correlation: &request.correlation,
            },
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;

        let materialized = self.read_rows(&mut client, &request, &claims, &plan).await;
        let materialized = match materialized {
            Ok(materialized) => materialized,
            Err(error) => {
                let _ = self
                    .record_terminal(
                        &mut client,
                        &claims,
                        &request,
                        &plan,
                        None,
                        TerminalAuditOutcome::Refused,
                        0,
                    )
                    .await;
                return Err(error);
            }
        };
        let held = SnapshotReadResult::from_materialized(materialized)?;
        self.fault
            .fail_at(SnapshotReadFaultPoint::BeforeTerminalAudit)?;
        let outcome = if held.result_count == 0 {
            TerminalAuditOutcome::Empty
        } else {
            TerminalAuditOutcome::Returned
        };
        self.record_terminal(
            &mut client,
            &claims,
            &request,
            &plan,
            Some(&held.effective_binding),
            outcome,
            held.result_count,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(held)
    }

    async fn read_rows(
        &self,
        client: &mut deadpool_postgres::Client,
        request: &SnapshotReadRequest,
        claims: &ClaimContext,
        plan: &SnapshotReadPlan,
    ) -> Result<MaterializedSnapshotRead, ReadServiceError> {
        let guarded = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let transaction = guarded.transaction();
        transaction
            .execute(
                "SELECT set_config('statement_timeout', $1::text, true)",
                &[&HISTORY_STATEMENT_TIMEOUT],
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            SnapshotReadFaultControl::At(SnapshotReadFaultPoint::HistoricalStatementTimeout)
        ) {
            transaction
                .execute("SELECT set_config('statement_timeout', '5ms', true)", &[])
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
            transaction
                .execute("SELECT pg_sleep(0.05)", &[])
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
        }
        // The committed prefix is immutable, and the shared registry lock
        // excludes migration/erasure maintenance until this read commits.
        // Counts, descriptor checks and rows therefore use the same retained
        // state even while ordinary writers append later commits.
        let snapshot = snapshot_from_scope(transaction, &request.plan.cursor_query.scope).await?;
        let snapshot_reference = snapshot.reference.to_string();
        let effective_scope = CursorQueryScope::Snapshot {
            reference: Some(snapshot_reference.clone()),
        };
        let effective_binding = cursor_binding(
            self.cursors.as_ref(),
            &self.expected,
            &self.registry,
            request,
            plan,
            &effective_scope,
        )?;
        let effective_query = cursor_query_with_scope(&request.plan, effective_scope);
        let package_revisions = load_latest_active_package_revisions(
            transaction,
            &request.entity_id,
            snapshot.position,
        )
        .await?;
        if package_revisions.is_empty() {
            guarded
                .commit()
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
            return Ok(MaterializedSnapshotRead {
                rows: Vec::new(),
                next_cursor: None,
                total_count: request.plan.include_count.then_some(0),
                snapshot: snapshot_reference,
                valid_at: request.plan.temporal_instant.clone(),
                effective_binding,
            });
        }
        let descriptors = load_compatible_descriptors(
            transaction,
            &plan.entity,
            &plan.required_fields,
            package_revisions,
        )
        .await?;
        let fields = HistoryFieldSet::new(&plan.entity, &plan.required_fields, &descriptors)?;
        ensure_required_snapshot_keys_present(
            transaction,
            &request.entity_id,
            snapshot.position,
            &fields,
        )
        .await?;

        let selected_fields = request
            .plan
            .projection
            .iter()
            .map(|field| field.field_id.clone())
            .collect::<Vec<_>>();
        let mut total_count = None;
        let (count_sql, count_parameters) = snapshot_count_sql(
            &request.entity_id,
            snapshot.position,
            &request.plan,
            claims,
            &plan.entity,
            &fields,
        )?;
        if request.plan.include_count {
            let refs = count_parameters
                .iter()
                .map(|value| &**value as &(dyn ToSql + Sync))
                .collect::<Vec<_>>();
            total_count = Some(
                transaction
                    .query_one(&count_sql, &refs)
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
                    .get::<_, i64>(0),
            );
        }
        let (page_sql, page_parameters) = snapshot_page_sql(
            &request.entity_id,
            snapshot.position,
            &request.plan,
            claims,
            &plan.entity,
            &fields,
            request.maximum_records,
        )?;
        let refs = page_parameters
            .iter()
            .map(|value| &**value as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = transaction
            .query(&page_sql, &refs)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let page_size = usize::from(request.plan.page_size);
        let has_more = rows.len() > page_size;
        let rows = if has_more {
            &rows[..page_size]
        } else {
            rows.as_slice()
        };
        let next_cursor = if has_more {
            rows.last()
                .map(|row| self.next_cursor(row, &effective_binding, &effective_query, request))
                .transpose()?
        } else {
            None
        };
        let rows = rows
            .iter()
            .map(|row| row_to_record(row, &selected_fields, &descriptors))
            .collect::<Result<Vec<_>, _>>()?;
        guarded
            .commit()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(MaterializedSnapshotRead {
            rows,
            next_cursor,
            total_count,
            snapshot: snapshot_reference,
            valid_at: request.plan.temporal_instant.clone(),
            effective_binding,
        })
    }

    fn next_cursor(
        &self,
        row: &tokio_postgres::Row,
        binding: &CursorBinding,
        query: &crate::cursor::CursorQuery,
        request: &SnapshotReadRequest,
    ) -> Result<String, ReadServiceError> {
        let last_record_id = row
            .try_get::<_, String>(0)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let sort_value = if request.plan.order.is_some() {
            row.try_get::<_, Option<Value>>(4)
                .map_err(|_| ReadServiceError::Unavailable)?
                .and_then(cursor_sort_value)
        } else {
            None
        };
        let payload = self
            .cursors
            .new_payload(
                now_unix_seconds(),
                binding.clone(),
                query.clone(),
                CursorContinuation {
                    last_record_id,
                    sort_value,
                },
            )
            .map_err(|_| ReadServiceError::Unavailable)?;
        self.cursors
            .encode(&payload)
            .map_err(|_| ReadServiceError::Unavailable)
    }

    #[allow(clippy::too_many_arguments)] // Keep request authority and audit outcome explicit.
    async fn record_terminal(
        &self,
        client: &mut deadpool_postgres::Client,
        claims: &ClaimContext,
        request: &SnapshotReadRequest,
        plan: &SnapshotReadPlan,
        binding: Option<&CursorBinding>,
        outcome: TerminalAuditOutcome,
        result_count: usize,
    ) -> Result<(), crate::audit::RegistryAuditError> {
        let key_hasher = self.audit_profile.key_hasher();
        let principal_reference = claims
            .principal()
            .map(|principal| {
                key_hasher.audit_reference_hash(
                    "registry-server-principal-v1",
                    &self.expected.package_revision,
                    principal,
                )
            })
            .transpose()
            .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
        let field_set_reference = field_set_reference(
            &self.audit_profile,
            &self.expected.package_revision,
            &request.selected_fields,
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| crate::audit::RegistryAuditError::Unavailable)?;
        append_read_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            ReadTerminalAudit {
                terminal: TerminalAudit {
                    outcome,
                    method: request.method,
                    operation_id: request.operation_id.clone(),
                    entity_id: plan.entity.id.clone(),
                    package_revision: self.expected.package_revision.clone(),
                    selected_access_profile: claims.access_profile().to_owned(),
                    purpose_present: claims.purpose().is_some(),
                    principal_reference,
                    record_reference: None,
                    record_revision: None,
                    result_count: Some(result_count),
                    field_set_reference: Some(field_set_reference),
                    correlation: request.correlation.clone(),
                },
                query_reference: binding.map(|binding| binding.query_reference.clone()),
                row_boundary_reference: binding
                    .map(|binding| binding.row_boundary_reference.clone()),
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::audit::RegistryAuditError::Unavailable)
    }
}

impl SnapshotReadService for PostgresSnapshotReadService {
    fn list(
        &self,
        request: SnapshotReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async move { Ok(self.execute(request).await?.response) })
    }

    fn refusal(
        &self,
        request: RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async move {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
            crate::audit::record_http_refusal_audit(
                &mut client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                &self.audit_profile,
                crate::audit::HttpRefusalAudit {
                    method: request.method,
                    operation_id: &request.operation_id,
                    target_record: request.target_record.as_deref(),
                    principal: request.principal.as_deref(),
                    selected_access_profile: request.selected_access_profile.as_deref(),
                    purpose_present: request.purpose_present,
                    correlation: &request.correlation,
                },
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)
        })
    }
}

struct SnapshotReadPlan {
    entity: CompiledEntity,
    query_operation: CompiledQueryOperation,
    required_fields: BTreeSet<String>,
}

impl SnapshotReadPlan {
    fn from_request(
        registry: &CompiledRegistry,
        expected: &ExpectedRegistryIdentity,
        cursors: &CursorCodec,
        request: &SnapshotReadRequest,
    ) -> Result<Self, ()> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == request.operation_id)
            .ok_or(())?;
        let entity = registry.entities().get(&request.entity_id).ok_or(())?;
        let profile = entity
            .access_profiles
            .get(request.context.selected_profile())
            .ok_or(())?;
        let operation = registry
            .queries()
            .operations
            .iter()
            .find(|operation| {
                operation.id == request.plan.query_operation_id
                    && operation.route_id == route.id
                    && operation.entity_id == entity.id
                    && operation.profile_id == request.context.selected_profile()
                    && operation.kind == CompiledQueryKind::Snapshot
                    && operation.read_path.is_none()
                    && operation.selector_fields.is_empty()
            })
            .ok_or(())?;
        let selected_fields = request
            .plan
            .projection
            .iter()
            .map(|field| field.field_id.clone())
            .collect::<BTreeSet<_>>();
        if route.operation != Operation::Snapshot
            || route.method != HttpMethod::Get
            || request.method != HttpMethod::Get
            || route.entity_id != request.entity_id
            || route.query_kind != Some(CompiledQueryKind::Snapshot)
            || request.plan.kind != CompiledQueryKind::Snapshot
            || request.plan.route_id != route.id
            || profile.anonymous
            || !profile.operations.contains(&Operation::Snapshot)
            || !route
                .access_profiles
                .iter()
                .any(|profile| profile == request.context.selected_profile())
            || selected_fields.is_empty()
            || selected_fields != request.selected_fields
            || !selected_fields.is_subset(&profile.readable_fields)
            || !selected_fields
                .iter()
                .all(|field| operation.projection_fields.contains(field))
            || request.maximum_records
                != usize::from(request.plan.page_size)
                    .checked_add(1)
                    .ok_or(())?
            || request.maximum_records == 0
            || request.maximum_records > MAX_SQL_LIMIT
            || request.plan.page_size == 0
            || request.plan.page_size > operation.max_page_size
            || request.plan.include_count && !operation.allow_count
            || request.plan.cursor_binding.package_revision != expected.package_revision
            || request.plan.cursor_binding.schema_fingerprint != expected.schema_fingerprint
            || request.plan.cursor_binding.registry_revision != registry.revision()
            || request.plan.cursor_binding.route_id != request.plan.route_id
            || request.plan.cursor_binding.query_operation_id != request.plan.query_operation_id
            || request.plan.cursor_binding.query_kind != request.plan.kind
            || request.plan.cursor_binding.selected_profile != request.context.selected_profile()
            || request.plan.cursor_binding.page_size != request.plan.page_size
            || request.plan.cursor_binding.include_count != request.plan.include_count
            || request.plan.cursor_binding.temporal_instant != request.plan.temporal_instant
            || request.plan.cursor_binding.selected_fields
                != selected_fields.iter().cloned().collect::<Vec<_>>()
            || !valid_optional_cursor_reference(
                request.plan.cursor_binding.principal_reference.as_deref(),
            )
            || !valid_optional_cursor_reference(
                request.plan.cursor_binding.purpose_reference.as_deref(),
            )
            || !valid_cursor_reference(&request.plan.cursor_binding.row_boundary_reference)
            || !valid_cursor_reference(&request.plan.cursor_binding.projection_reference)
            || !valid_cursor_reference(&request.plan.cursor_binding.query_reference)
            || !valid_cursor_reference(&request.plan.cursor_binding.sort_reference)
            || !valid_cursor_reference(&request.plan.cursor_binding.scope_reference)
            || operation.stable_tie_breaker != "record_id"
        {
            return Err(());
        }
        validate_snapshot_scope(
            &request.plan.cursor_query.scope,
            request.plan.continuation.is_some(),
        )?;
        validate_projection(entity, operation, &request.plan.projection)?;
        if let Some(filter) = &request.plan.filter {
            let mut stats = FilterStats::default();
            validate_filter_expr(entity, operation, filter, &mut stats)?;
            if stats.predicates > 32 || stats.in_values > 100 {
                return Err(());
            }
        }
        if let Some(order) = &request.plan.order {
            validate_order(entity, operation, order)?;
        }
        validate_temporal(entity, operation, request.plan.temporal_instant.as_deref())?;
        if let Some(continuation) = &request.plan.continuation {
            if !valid_canonical_uuid(&continuation.last_record_id) {
                return Err(());
            }
            match (&request.plan.order, &continuation.sort_value) {
                (Some(order), Some(value)) => {
                    validate_field_value(value, &order.field_type).map_err(|_| ())?;
                }
                (Some(_), None) | (None, None) => {}
                (None, Some(_)) => return Err(()),
            }
        }
        if !cursor_query_matches_request(&request.plan)? {
            return Err(());
        }
        let references = cursor_binding_references(
            cursors,
            request,
            operation,
            &request.plan.cursor_query.scope,
        )?;
        if request.plan.cursor_binding.principal_reference != references.principal
            || request.plan.cursor_binding.purpose_reference != references.purpose
            || request.plan.cursor_binding.row_boundary_reference != references.row_boundary
            || request.plan.cursor_binding.projection_reference != references.projection
            || request.plan.cursor_binding.query_reference != references.query
            || request.plan.cursor_binding.sort_reference != references.sort
            || request.plan.cursor_binding.scope_reference != references.scope
        {
            return Err(());
        }
        let required_fields = required_history_fields(request, operation)?;
        Ok(Self {
            entity: entity.clone(),
            query_operation: operation.clone(),
            required_fields,
        })
    }
}

async fn snapshot_from_scope(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: &CursorQueryScope,
) -> Result<ResolvedSnapshot, ReadServiceError> {
    match scope {
        CursorQueryScope::Snapshot { reference: None } => {
            capture_latest_snapshot_reference(transaction)
                .await
                .map_err(|_| ReadServiceError::Unavailable)
        }
        CursorQueryScope::Snapshot {
            reference: Some(reference),
        } => {
            let reference =
                SnapshotReference::parse(reference).map_err(|_| ReadServiceError::Unavailable)?;
            resolve_snapshot_reference(transaction, reference)
                .await
                .map_err(|_| ReadServiceError::Unavailable)
        }
        CursorQueryScope::Collection {} | CursorQueryScope::Relationship { .. } => {
            Err(ReadServiceError::Unavailable)
        }
    }
}

async fn load_latest_active_package_revisions(
    transaction: &tokio_postgres::Transaction<'_>,
    entity_id: &str,
    position: i64,
) -> Result<Vec<String>, ReadServiceError> {
    let rows = transaction
        .query(
            "WITH latest AS (
                 SELECT DISTINCT ON (member.record_id)
                        member.record_id, member.record_revision, member.commit_position
                   FROM registry_internal.registry_revision_commit_members AS member
                  WHERE member.entity_id = $1::text
                    AND member.commit_position <= $2::bigint
                  ORDER BY member.record_id, member.commit_position DESC,
                           member.record_revision DESC
             )
             SELECT DISTINCT revision.package_revision
               FROM latest
               JOIN registry_internal.registry_revisions AS revision
                 ON revision.entity_id = $1::text
                AND revision.record_id = latest.record_id
                AND revision.record_revision = latest.record_revision
              WHERE revision.record_lifecycle = 'active'
              ORDER BY revision.package_revision
              LIMIT $3::bigint",
            &[
                &entity_id,
                &position,
                &(i64::try_from(MAX_HISTORY_PACKAGE_DESCRIPTORS + 1)
                    .map_err(|_| ReadServiceError::Unavailable)?),
            ],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    if rows.len() > MAX_HISTORY_PACKAGE_DESCRIPTORS {
        return Err(ReadServiceError::Unavailable);
    }
    rows.into_iter()
        .map(|row| bounded_package_revision(&row, 0))
        .collect()
}

async fn load_compatible_descriptors(
    transaction: &tokio_postgres::Transaction<'_>,
    entity: &CompiledEntity,
    required_fields: &BTreeSet<String>,
    package_revisions: Vec<String>,
) -> Result<BTreeMap<String, CompatibleDescriptor>, ReadServiceError> {
    let mut descriptors = BTreeMap::new();
    for package_revision in package_revisions {
        let descriptor = load_descriptor(transaction, &package_revision)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let compatibility = descriptor
            .compatibility_for_fields(entity, required_fields)
            .map_err(|_| ReadServiceError::Unavailable)?;
        descriptors.insert(
            package_revision,
            CompatibleDescriptor {
                descriptor,
                compatibility,
            },
        );
    }
    Ok(descriptors)
}

struct CompatibleDescriptor {
    descriptor: HistorySchemaDescriptor,
    compatibility: HistorySchemaCompatibility,
}

struct HistoryFieldSet {
    by_field: BTreeMap<String, HistorySqlField>,
}

impl HistoryFieldSet {
    fn new(
        entity: &CompiledEntity,
        required_fields: &BTreeSet<String>,
        descriptors: &BTreeMap<String, CompatibleDescriptor>,
    ) -> Result<Self, ReadServiceError> {
        let mut by_field = BTreeMap::new();
        let mut aliases = BTreeSet::new();
        for (index, field_id) in required_fields.iter().enumerate() {
            let field_type = compiled_stored_field_type(entity, field_id)
                .ok_or(ReadServiceError::Unavailable)?
                .clone();
            let alias = format!("history_field_{index}");
            if !aliases.insert(alias.clone()) {
                return Err(ReadServiceError::Unavailable);
            }
            let mut package_sources = BTreeMap::new();
            for (package_revision, descriptor) in descriptors {
                let field = descriptor
                    .compatibility
                    .fields
                    .get(field_id)
                    .ok_or(ReadServiceError::Unavailable)?;
                package_sources.insert(package_revision.clone(), field.clone());
            }
            by_field.insert(
                field_id.clone(),
                HistorySqlField {
                    field_id: field_id.clone(),
                    alias,
                    field_type,
                    package_sources,
                },
            );
        }
        Ok(Self { by_field })
    }

    fn field(&self, field_id: &str) -> Result<&HistorySqlField, ReadServiceError> {
        self.by_field
            .get(field_id)
            .ok_or(ReadServiceError::Unavailable)
    }
}

#[derive(Clone)]
struct HistorySqlField {
    field_id: String,
    alias: String,
    field_type: FieldTypeSource,
    package_sources: BTreeMap<String, HistoryFieldCompatibility>,
}

impl HistorySqlField {
    fn cte_json_expression(&self) -> Result<String, ReadServiceError> {
        if self.field_id == "id" {
            return Ok("to_jsonb(revision.record_id::text)".to_owned());
        }
        let mut arms = Vec::new();
        for (package_revision, field) in &self.package_sources {
            let source = match &field.source {
                HistoryFieldSource::SnapshotKey { key } => format!(
                    "(convert_from(revision.snapshot, 'UTF8')::jsonb -> {})",
                    sql_quote_literal(key)
                ),
                HistoryFieldSource::JournalRecordId => {
                    "to_jsonb(revision.record_id::text)".to_owned()
                }
            };
            arms.push(format!(
                "WHEN {} THEN {source}",
                sql_quote_literal(package_revision)
            ));
        }
        if arms.is_empty() {
            return Err(ReadServiceError::Unavailable);
        }
        Ok(format!(
            "(CASE revision.package_revision {} ELSE NULL::jsonb END)",
            arms.join(" ")
        ))
    }
}

async fn ensure_required_snapshot_keys_present(
    transaction: &tokio_postgres::Transaction<'_>,
    entity_id: &str,
    position: i64,
    fields: &HistoryFieldSet,
) -> Result<(), ReadServiceError> {
    let predicates = fields
        .by_field
        .values()
        .filter(|field| field.field_id != "id")
        .flat_map(|field| {
            field.package_sources.iter().filter_map(|(package, source)| {
                let HistoryFieldSource::SnapshotKey { key } = &source.source else {
                    return None;
                };
                Some(format!(
                    "(revision.package_revision = {} AND NOT (convert_from(revision.snapshot, 'UTF8')::jsonb ? {}))",
                    sql_quote_literal(package),
                    sql_quote_literal(key),
                ))
            })
        })
        .collect::<Vec<_>>();
    if predicates.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "WITH latest AS (
             SELECT DISTINCT ON (member.record_id)
                    member.record_id, member.record_revision, member.commit_position
               FROM registry_internal.registry_revision_commit_members AS member
              WHERE member.entity_id = $1::text
                AND member.commit_position <= $2::bigint
              ORDER BY member.record_id, member.commit_position DESC,
                       member.record_revision DESC
         )
         SELECT EXISTS (
             SELECT 1
               FROM latest
               JOIN registry_internal.registry_revisions AS revision
                 ON revision.entity_id = $1::text
                AND revision.record_id = latest.record_id
                AND revision.record_revision = latest.record_revision
              WHERE revision.record_lifecycle = 'active'
                AND ({})
              LIMIT 1
         )",
        predicates.join(" OR "),
    );
    let missing: bool = transaction
        .query_one(&sql, &[&entity_id, &position])
        .await
        .map_err(|_| ReadServiceError::Unavailable)?
        .get(0);
    if missing {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(())
}

fn snapshot_count_sql(
    entity_id: &str,
    position: i64,
    query: &crate::api::CompiledReadQuery,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    fields: &HistoryFieldSet,
) -> Result<(String, Vec<Box<dyn ToSql + Sync + Send>>), ReadServiceError> {
    let mut builder = SnapshotSqlBuilder::new(entity_id, position);
    // Count the full authorized result at the pinned commit, not just rows
    // remaining after the continuation boundary.
    let where_sql = snapshot_where_sql(&mut builder, query, claims, entity, fields, None)?;
    Ok((
        format!(
            "{} SELECT count(*)::bigint FROM historical WHERE {where_sql}",
            historical_cte(fields)?
        ),
        builder.parameters,
    ))
}

fn snapshot_page_sql(
    entity_id: &str,
    position: i64,
    query: &crate::api::CompiledReadQuery,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    fields: &HistoryFieldSet,
    limit: usize,
) -> Result<(String, Vec<Box<dyn ToSql + Sync + Send>>), ReadServiceError> {
    let mut builder = SnapshotSqlBuilder::new(entity_id, position);
    let where_sql = snapshot_where_sql(
        &mut builder,
        query,
        claims,
        entity,
        fields,
        query.continuation.as_ref(),
    )?;
    let order_sql = snapshot_order_sql(query, fields)?;
    let sort_projection = query
        .order
        .as_ref()
        .map(|order| {
            let field = fields.field(&order.field_id)?;
            Ok(format!(", {} AS sort_value", field_json_sql(field)?))
        })
        .transpose()?
        .unwrap_or_default();
    let limit_parameter =
        builder.push_i64(i64::try_from(limit).map_err(|_| ReadServiceError::Unavailable)?);
    Ok((
        format!(
            "{} SELECT record_id, record_revision, package_revision, snapshot{sort_projection}
                 FROM historical
                WHERE {where_sql}
                ORDER BY {order_sql}
                LIMIT ${limit_parameter}::bigint",
            historical_cte(fields)?
        ),
        builder.parameters,
    ))
}

fn historical_cte(fields: &HistoryFieldSet) -> Result<String, ReadServiceError> {
    let field_projection = fields
        .by_field
        .values()
        .map(|field| {
            Ok(format!(
                ", {} AS {}",
                field.cte_json_expression()?,
                field.alias
            ))
        })
        .collect::<Result<Vec<_>, ReadServiceError>>()?
        .join("");
    Ok(format!(
        "WITH latest AS (
             SELECT DISTINCT ON (member.record_id)
                    member.record_id, member.record_revision, member.commit_position
               FROM registry_internal.registry_revision_commit_members AS member
              WHERE member.entity_id = $1::text
                AND member.commit_position <= $2::bigint
              ORDER BY member.record_id, member.commit_position DESC,
                       member.record_revision DESC
         ),
         historical AS (
             SELECT revision.record_id::text AS record_id,
                    revision.record_revision,
                    revision.package_revision,
                    revision.snapshot
                    {field_projection}
               FROM latest
               JOIN registry_internal.registry_revisions AS revision
                 ON revision.entity_id = $1::text
                AND revision.record_id = latest.record_id
                AND revision.record_revision = latest.record_revision
              WHERE revision.record_lifecycle = 'active'
         )"
    ))
}

fn snapshot_where_sql(
    builder: &mut SnapshotSqlBuilder,
    query: &crate::api::CompiledReadQuery,
    claims: &ClaimContext,
    entity: &CompiledEntity,
    fields: &HistoryFieldSet,
    continuation: Option<&CursorContinuation>,
) -> Result<String, ReadServiceError> {
    let mut predicates = Vec::new();
    for boundary in claims.row_boundaries() {
        let field = fields.field(boundary.field())?;
        let typed = field_typed_sql(field)?;
        let values = boundary.values();
        match boundary.operator() {
            super::RowBoundaryOperator::Equals => {
                if values.len() != 1 {
                    return Err(ReadServiceError::Unavailable);
                }
                let value = values.first().ok_or(ReadServiceError::Unavailable)?;
                validate_field_value(value, &field.field_type)
                    .map_err(|_| ReadServiceError::Unavailable)?;
                let parameter = builder.push_string((*value).to_owned());
                predicates.push(format!(
                    "{typed} = ${parameter}::text::{}",
                    postgres_cast(&field.field_type)
                ));
            }
            super::RowBoundaryOperator::In => {
                if values.is_empty() {
                    return Err(ReadServiceError::Unavailable);
                }
                let mut placeholders = Vec::new();
                for value in values {
                    validate_field_value(value, &field.field_type)
                        .map_err(|_| ReadServiceError::Unavailable)?;
                    let parameter = builder.push_string(value.to_owned());
                    placeholders.push(format!(
                        "${parameter}::text::{}",
                        postgres_cast(&field.field_type)
                    ));
                }
                predicates.push(format!("{typed} IN ({})", placeholders.join(", ")));
            }
        }
    }
    if let Some(instant) = &query.temporal_instant {
        let temporal = entity
            .temporal
            .as_ref()
            .ok_or(ReadServiceError::Unavailable)?;
        let start = fields.field(&temporal.start_field)?;
        let end = fields.field(&temporal.end_field)?;
        let parameter = builder.push_string(instant.clone());
        let instant_sql = temporal_parameter_sql(&start.field_type, &end.field_type, parameter)?;
        predicates.push(format!(
            "{} <= {instant_sql} AND ({} IS NULL OR {instant_sql} < {})",
            field_typed_sql(start)?,
            field_typed_sql(end)?,
            field_typed_sql(end)?,
        ));
    }
    if let Some(filter) = &query.filter {
        predicates.push(filter_sql(filter, fields, builder)?);
    }
    if let Some(continuation) = continuation {
        if !valid_canonical_uuid(&continuation.last_record_id) {
            return Err(ReadServiceError::CursorInvalid);
        }
        let record_parameter = builder.push_string(continuation.last_record_id.clone());
        if let Some(order) = &query.order {
            let field = fields.field(&order.field_id)?;
            let typed = field_typed_sql(field)?;
            match &continuation.sort_value {
                Some(value) => {
                    validate_field_value(value, &field.field_type)
                        .map_err(|_| ReadServiceError::CursorInvalid)?;
                    let sort_parameter = builder.push_string(value.clone());
                    predicates.push(format!(
                        "({typed} > ${sort_parameter}::text::{cast}
                          OR {typed} IS NULL
                          OR ({typed} = ${sort_parameter}::text::{cast}
                              AND record_id > ${record_parameter}::text))",
                        cast = postgres_cast(&field.field_type),
                    ));
                }
                None => {
                    predicates.push(format!(
                        "({typed} IS NULL AND record_id > ${record_parameter}::text)"
                    ));
                }
            }
        } else {
            predicates.push(format!("record_id > ${record_parameter}::text"));
        }
    }
    if predicates.is_empty() {
        Ok("TRUE".to_owned())
    } else {
        Ok(predicates.join(" AND "))
    }
}

fn snapshot_order_sql(
    query: &crate::api::CompiledReadQuery,
    fields: &HistoryFieldSet,
) -> Result<String, ReadServiceError> {
    if let Some(order) = &query.order {
        let field = fields.field(&order.field_id)?;
        Ok(format!(
            "{} ASC NULLS LAST, record_id ASC",
            field_typed_sql(field)?
        ))
    } else {
        Ok("record_id ASC".to_owned())
    }
}

fn filter_sql(
    filter: &ReadFilterExpr,
    fields: &HistoryFieldSet,
    builder: &mut SnapshotSqlBuilder,
) -> Result<String, ReadServiceError> {
    match filter {
        ReadFilterExpr::Binary { op, left, right } => {
            let operator = match op {
                ReadLogicalOp::And => "AND",
                ReadLogicalOp::Or => "OR",
            };
            Ok(format!(
                "({} {operator} {})",
                filter_sql(left, fields, builder)?,
                filter_sql(right, fields, builder)?
            ))
        }
        ReadFilterExpr::Not(expr) => Ok(format!("(NOT {})", filter_sql(expr, fields, builder)?)),
        ReadFilterExpr::Group(expr) => Ok(format!("({})", filter_sql(expr, fields, builder)?)),
        ReadFilterExpr::Predicate(predicate) => predicate_sql(predicate, fields, builder),
    }
}

fn predicate_sql(
    predicate: &ReadFilterPredicate,
    fields: &HistoryFieldSet,
    builder: &mut SnapshotSqlBuilder,
) -> Result<String, ReadServiceError> {
    let field = fields.field(&predicate.field_id)?;
    if field.field_type != predicate.field_type {
        return Err(ReadServiceError::Unavailable);
    }
    let typed = field_typed_sql(field)?;
    let cast = postgres_cast(&field.field_type);
    match predicate.operator {
        ReadFilterOperator::Eq => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} = ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::Ne => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} <> ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::Lt => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} < ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::Le => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} <= ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::Gt => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} > ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::Ge => {
            let parameter = builder.push_string(predicate.values[0].clone());
            Ok(format!("{typed} >= ${parameter}::text::{cast}"))
        }
        ReadFilterOperator::In => {
            let placeholders = predicate
                .values
                .iter()
                .map(|value| {
                    let parameter = builder.push_string(value.clone());
                    format!("${parameter}::text::{cast}")
                })
                .collect::<Vec<_>>();
            if placeholders.is_empty() {
                return Err(ReadServiceError::Unavailable);
            }
            Ok(format!("{typed} IN ({})", placeholders.join(", ")))
        }
        ReadFilterOperator::IsNull => Ok(format!("{typed} IS NULL")),
        ReadFilterOperator::IsNotNull => Ok(format!("{typed} IS NOT NULL")),
        ReadFilterOperator::StartsWith => {
            let parameter = builder.push_string(format!("{}%", escape_like(&predicate.values[0])));
            Ok(format!("{typed} LIKE ${parameter}::text ESCAPE '\\'"))
        }
        ReadFilterOperator::Contains => {
            let parameter = builder.push_string(format!("%{}%", escape_like(&predicate.values[0])));
            Ok(format!("{typed} LIKE ${parameter}::text ESCAPE '\\'"))
        }
    }
}

fn field_json_sql(field: &HistorySqlField) -> Result<String, ReadServiceError> {
    if field.field_id == "id" {
        return Ok("to_jsonb(record_id)".to_owned());
    }
    Ok(field.alias.clone())
}

fn field_typed_sql(field: &HistorySqlField) -> Result<String, ReadServiceError> {
    if field.field_id == "id" {
        return Ok("record_id::uuid".to_owned());
    }
    let alias = field.alias.clone();
    match &field.field_type {
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. }
        | FieldTypeSource::VocabularyCode { .. }
        | FieldTypeSource::Boolean
        | FieldTypeSource::Int64 => Ok(format!(
            "({alias} #>> '{{}}')::{}",
            postgres_cast(&field.field_type)
        )),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            Err(ReadServiceError::Unavailable)
        }
    }
}

struct SnapshotSqlBuilder {
    parameters: Vec<Box<dyn ToSql + Sync + Send>>,
}

impl SnapshotSqlBuilder {
    fn new(entity_id: &str, position: i64) -> Self {
        Self {
            parameters: vec![Box::new(entity_id.to_owned()), Box::new(position)],
        }
    }

    fn push_string(&mut self, value: String) -> usize {
        self.parameters.push(Box::new(value));
        self.parameters.len()
    }

    fn push_i64(&mut self, value: i64) -> usize {
        self.parameters.push(Box::new(value));
        self.parameters.len()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordEnvelope {
    id: String,
    revision: u64,
    data: Map<String, Value>,
}

fn row_to_record(
    row: &tokio_postgres::Row,
    selected_fields: &[String],
    descriptors: &BTreeMap<String, CompatibleDescriptor>,
) -> Result<RecordEnvelope, ReadServiceError> {
    let id = row
        .try_get::<_, String>(0)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let revision = row
        .try_get::<_, i64>(1)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let package_revision = row
        .try_get::<_, String>(2)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let snapshot = row
        .try_get::<_, Vec<u8>>(3)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if !valid_canonical_uuid(&id) || revision <= 0 {
        return Err(ReadServiceError::Unavailable);
    }
    let descriptor = descriptors
        .get(&package_revision)
        .ok_or(ReadServiceError::Unavailable)?;
    let decoded = descriptor
        .descriptor
        .decode_snapshot_for_fields(&descriptor.compatibility, &snapshot, Some(&id))
        .map_err(|_| ReadServiceError::Unavailable)?;
    let data = projected_data(&decoded, &descriptor.compatibility, selected_fields)?;
    Ok(RecordEnvelope {
        id,
        revision: u64::try_from(revision).map_err(|_| ReadServiceError::Unavailable)?,
        data,
    })
}

fn projected_data(
    decoded: &DecodedHistorySnapshot,
    compatibility: &HistorySchemaCompatibility,
    selected_fields: &[String],
) -> Result<Map<String, Value>, ReadServiceError> {
    let mut data = Map::new();
    for field_id in selected_fields {
        let field = compatibility
            .fields
            .get(field_id)
            .ok_or(ReadServiceError::Unavailable)?;
        let value = decoded
            .by_field_id
            .get(field_id)
            .ok_or(ReadServiceError::Unavailable)?;
        if data
            .insert(field.active_api_name.clone(), value.clone())
            .is_some()
        {
            return Err(ReadServiceError::Unavailable);
        }
    }
    Ok(data)
}

struct MaterializedSnapshotRead {
    rows: Vec<RecordEnvelope>,
    next_cursor: Option<String>,
    total_count: Option<i64>,
    snapshot: String,
    valid_at: Option<String>,
    effective_binding: CursorBinding,
}

struct SnapshotReadResult {
    response: HeldReadResponse,
    result_count: usize,
    effective_binding: CursorBinding,
}

impl SnapshotReadResult {
    fn from_materialized(materialized: MaterializedSnapshotRead) -> Result<Self, ReadServiceError> {
        let result_count = materialized.rows.len();
        let mut body = json!({
            "items": materialized.rows,
            "pageInfo": {"nextCursor": materialized.next_cursor},
            "snapshot": materialized.snapshot,
        });
        if let Some(valid_at) = materialized.valid_at {
            body["validAt"] = json!(valid_at);
        }
        if let Some(count) = materialized.total_count {
            body["count"] = json!(count);
        }
        Ok(Self {
            response: HeldReadResponse::from_json(&body)?,
            result_count,
            effective_binding: materialized.effective_binding,
        })
    }
}

fn strict_claim_context(
    registry: &CompiledRegistry,
    context: &AuthorizedRequestContext,
    entity_id: &str,
) -> Result<ClaimContext, ReadServiceError> {
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(|boundary| match boundary.operator() {
            ApiRowBoundaryOperator::Equals => {
                let values = boundary.values();
                if values.len() != 1 {
                    return Err(ReadServiceError::Unavailable);
                }
                Ok(RowBoundaryContext::Equals {
                    field: boundary.field().to_owned(),
                    value: values.first().ok_or(ReadServiceError::Unavailable)?.clone(),
                })
            }
            ApiRowBoundaryOperator::In => Ok(RowBoundaryContext::In {
                field: boundary.field().to_owned(),
                values: boundary.values().clone(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    ClaimContext::for_compiled(
        registry,
        entity_id,
        context.principal().map(str::to_owned),
        context.selected_profile(),
        context.purpose().map(str::to_owned),
        row_boundaries,
    )
    .map_err(|_| ReadServiceError::Unavailable)
}

fn required_history_fields(
    request: &SnapshotReadRequest,
    operation: &CompiledQueryOperation,
) -> Result<BTreeSet<String>, ()> {
    let mut fields = BTreeSet::new();
    fields.extend(
        request
            .plan
            .projection
            .iter()
            .map(|field| field.field_id.clone()),
    );
    fields.extend(
        request
            .context
            .row_boundaries()
            .iter()
            .map(|field| field.field().to_owned()),
    );
    collect_filter_fields(request.plan.filter.as_ref(), &mut fields);
    if let Some(order) = &request.plan.order {
        fields.insert(order.field_id.clone());
    }
    if request.plan.temporal_instant.is_some() {
        let temporal = operation.temporal.as_ref().ok_or(())?;
        fields.insert(temporal.start_field.clone());
        fields.insert(temporal.end_field.clone());
    }
    Ok(fields)
}

fn collect_filter_fields(filter: Option<&ReadFilterExpr>, fields: &mut BTreeSet<String>) {
    let Some(filter) = filter else {
        return;
    };
    match filter {
        ReadFilterExpr::Binary { left, right, .. } => {
            collect_filter_fields(Some(left), fields);
            collect_filter_fields(Some(right), fields);
        }
        ReadFilterExpr::Not(expr) | ReadFilterExpr::Group(expr) => {
            collect_filter_fields(Some(expr), fields);
        }
        ReadFilterExpr::Predicate(predicate) => {
            fields.insert(predicate.field_id.clone());
        }
    }
}

fn validate_snapshot_scope(scope: &CursorQueryScope, continuation: bool) -> Result<(), ()> {
    match scope {
        CursorQueryScope::Snapshot { reference } => {
            if let Some(reference) = reference {
                SnapshotReference::parse(reference).map_err(|_| ())?;
            } else if continuation {
                return Err(());
            }
            Ok(())
        }
        CursorQueryScope::Collection {} | CursorQueryScope::Relationship { .. } => Err(()),
    }
}

fn validate_projection(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    projection: &[ReadProjectionField],
) -> Result<(), ()> {
    if projection.is_empty() || projection.len() > operation.projection_fields.len() {
        return Err(());
    }
    let mut seen = BTreeSet::new();
    for field in projection {
        if !seen.insert(field.field_id.as_str())
            || !operation.projection_fields.contains(&field.field_id)
            || compiled_stored_field_type(entity, &field.field_id) != Some(&field.field_type)
        {
            return Err(());
        }
    }
    Ok(())
}

#[derive(Default)]
struct FilterStats {
    predicates: usize,
    in_values: usize,
}

fn validate_filter_expr(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    filter: &ReadFilterExpr,
    stats: &mut FilterStats,
) -> Result<(), ()> {
    match filter {
        ReadFilterExpr::Binary { left, right, .. } => {
            validate_filter_expr(entity, operation, left, stats)?;
            validate_filter_expr(entity, operation, right, stats)
        }
        ReadFilterExpr::Not(expr) | ReadFilterExpr::Group(expr) => {
            validate_filter_expr(entity, operation, expr, stats)
        }
        ReadFilterExpr::Predicate(predicate) => {
            validate_filter_predicate(entity, operation, predicate, stats)
        }
    }
}

fn validate_filter_predicate(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    predicate: &ReadFilterPredicate,
    stats: &mut FilterStats,
) -> Result<(), ()> {
    stats.predicates = stats.predicates.checked_add(1).ok_or(())?;
    let Some(field_type) = compiled_stored_field_type(entity, &predicate.field_id) else {
        return Err(());
    };
    let Some(compiled_filter) = operation
        .filter_fields
        .iter()
        .find(|candidate| candidate.field == predicate.field_id)
    else {
        return Err(());
    };
    if !compiled_filter
        .operators
        .contains(&predicate.operator.compiled_capability())
        || field_type != &predicate.field_type
    {
        return Err(());
    }
    match predicate.operator {
        ReadFilterOperator::Eq
        | ReadFilterOperator::Ne
        | ReadFilterOperator::Lt
        | ReadFilterOperator::Le
        | ReadFilterOperator::Gt
        | ReadFilterOperator::Ge
        | ReadFilterOperator::StartsWith
        | ReadFilterOperator::Contains => {
            if predicate.values.len() != 1
                || validate_field_value(&predicate.values[0], field_type).is_err()
            {
                return Err(());
            }
        }
        ReadFilterOperator::In => {
            if predicate.values.is_empty() {
                return Err(());
            }
            stats.in_values = stats
                .in_values
                .checked_add(predicate.values.len())
                .ok_or(())?;
            if predicate
                .values
                .windows(2)
                .any(|window| window[0] >= window[1])
                || predicate
                    .values
                    .iter()
                    .any(|value| validate_field_value(value, field_type).is_err())
            {
                return Err(());
            }
        }
        ReadFilterOperator::IsNull | ReadFilterOperator::IsNotNull => {
            if predicate.values.as_slice() != ["true"] {
                return Err(());
            }
        }
    }
    Ok(())
}

fn validate_order(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    order: &ReadOrderClause,
) -> Result<(), ()> {
    let Some(compiled_sort) = operation
        .sort_fields
        .iter()
        .find(|candidate| candidate.field == order.field_id)
    else {
        return Err(());
    };
    if !compiled_sort
        .directions
        .contains(&CompiledQuerySortDirection::Asc)
        || compiled_stored_field_type(entity, &order.field_id) != Some(&order.field_type)
        || order.direction != CompiledQuerySortDirection::Asc
    {
        return Err(());
    }
    Ok(())
}

fn validate_temporal(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    temporal_instant: Option<&str>,
) -> Result<(), ()> {
    let Some(instant) = temporal_instant else {
        return Ok(());
    };
    let temporal = operation.temporal.as_ref().ok_or(())?;
    let entity_temporal = entity.temporal.as_ref().ok_or(())?;
    if temporal.start_field != entity_temporal.start_field
        || temporal.end_field != entity_temporal.end_field
    {
        return Err(());
    }
    crate::api::normalize_history_valid_at(entity, instant).map(|_| ())
}

fn cursor_query_matches_request(query: &crate::api::CompiledReadQuery) -> Result<bool, ()> {
    Ok(
        query.cursor_query.projection == cursor_projection_from_read(&query.projection)
            && query.cursor_query.filter == query.filter.as_ref().map(cursor_filter_expr_from_read)
            && query.cursor_query.order == query.order.as_ref().map(cursor_order_from_read)
            && query.cursor_query.include_count == query.include_count
            && query.cursor_query.page_size == query.page_size
            && query.cursor_query.temporal_instant == query.temporal_instant
            && matches!(query.cursor_query.scope, CursorQueryScope::Snapshot { .. }),
    )
}

fn cursor_query_with_scope(
    query: &crate::api::CompiledReadQuery,
    scope: CursorQueryScope,
) -> crate::cursor::CursorQuery {
    let mut cursor_query = query.cursor_query.clone();
    cursor_query.scope = scope;
    cursor_query
}

fn cursor_binding(
    cursors: &CursorCodec,
    expected: &ExpectedRegistryIdentity,
    registry: &CompiledRegistry,
    request: &SnapshotReadRequest,
    plan: &SnapshotReadPlan,
    scope: &CursorQueryScope,
) -> Result<CursorBinding, ReadServiceError> {
    let references = cursor_binding_references(cursors, request, &plan.query_operation, scope)
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(CursorBinding {
        package_revision: expected.package_revision.clone(),
        schema_fingerprint: expected.schema_fingerprint.clone(),
        registry_revision: registry.revision().to_owned(),
        route_id: request.plan.route_id.clone(),
        query_operation_id: plan.query_operation.id.clone(),
        query_kind: request.plan.kind,
        selected_profile: request.context.selected_profile().to_owned(),
        principal_reference: references.principal,
        purpose_reference: references.purpose,
        row_boundary_reference: references.row_boundary,
        projection_reference: references.projection,
        query_reference: references.query,
        sort_reference: references.sort,
        scope_reference: references.scope,
        page_size: request.plan.page_size,
        include_count: request.plan.include_count,
        temporal_instant: request.plan.temporal_instant.clone(),
        selected_fields: request.selected_fields.iter().cloned().collect(),
    })
}

fn cursor_binding_references(
    cursors: &CursorCodec,
    request: &SnapshotReadRequest,
    operation: &CompiledQueryOperation,
    scope: &CursorQueryScope,
) -> Result<CursorBindingReferences, ()> {
    crate::query_binding::references(
        cursors,
        &request.plan.route_id,
        operation,
        &request.context,
        CursorBindingQuery {
            selected_fields: &request.selected_fields,
            projection: &request.plan.projection,
            filter: request.plan.filter.as_ref(),
            order: request.plan.order.as_ref(),
            include_count: request.plan.include_count,
            page_size: request.plan.page_size,
            temporal_instant: request.plan.temporal_instant.as_deref(),
            scope,
        },
    )
    .map_err(|_| ())
}

fn cursor_projection_from_read(projection: &[ReadProjectionField]) -> Vec<CursorProjectionField> {
    projection
        .iter()
        .map(|field| CursorProjectionField {
            field_id: field.field_id.clone(),
            field_type: field.field_type.clone(),
        })
        .collect()
}

fn cursor_order_from_read(order: &ReadOrderClause) -> CursorOrderClause {
    CursorOrderClause {
        field_id: order.field_id.clone(),
        field_type: order.field_type.clone(),
        direction: order.direction,
    }
}

fn cursor_filter_expr_from_read(filter: &ReadFilterExpr) -> CursorFilterExpr {
    match filter {
        ReadFilterExpr::Binary { op, left, right } => CursorFilterExpr::Binary {
            op: match op {
                ReadLogicalOp::And => CursorLogicalOp::And,
                ReadLogicalOp::Or => CursorLogicalOp::Or,
            },
            left: Box::new(cursor_filter_expr_from_read(left)),
            right: Box::new(cursor_filter_expr_from_read(right)),
        },
        ReadFilterExpr::Not(expr) => CursorFilterExpr::Not {
            expr: Box::new(cursor_filter_expr_from_read(expr)),
        },
        ReadFilterExpr::Group(expr) => CursorFilterExpr::Group {
            expr: Box::new(cursor_filter_expr_from_read(expr)),
        },
        ReadFilterExpr::Predicate(predicate) => CursorFilterExpr::Predicate {
            predicate: crate::cursor::CursorFilterPredicate {
                field_id: predicate.field_id.clone(),
                field_type: predicate.field_type.clone(),
                operator: match predicate.operator {
                    ReadFilterOperator::Eq => CursorFilterOperator::Eq,
                    ReadFilterOperator::Ne => CursorFilterOperator::Ne,
                    ReadFilterOperator::Lt => CursorFilterOperator::Lt,
                    ReadFilterOperator::Le => CursorFilterOperator::Le,
                    ReadFilterOperator::Gt => CursorFilterOperator::Gt,
                    ReadFilterOperator::Ge => CursorFilterOperator::Ge,
                    ReadFilterOperator::In => CursorFilterOperator::In,
                    ReadFilterOperator::IsNull => CursorFilterOperator::IsNull,
                    ReadFilterOperator::IsNotNull => CursorFilterOperator::IsNotNull,
                    ReadFilterOperator::StartsWith => CursorFilterOperator::StartsWith,
                    ReadFilterOperator::Contains => CursorFilterOperator::Contains,
                },
                values: predicate.values.clone(),
            },
        },
    }
}

fn field_set_reference(
    profile: &AuditProfile,
    package_revision: &str,
    selected_fields: &BTreeSet<String>,
) -> Result<String, crate::audit::RegistryAuditError> {
    let canonical = canonicalize_json(&json!({"selectedFields": selected_fields}))
        .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
    let canonical = std::str::from_utf8(&canonical)
        .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
    profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-read-field-set-v1",
            package_revision,
            canonical,
        )
        .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)
}

fn compiled_stored_field_type<'a>(
    entity: &'a CompiledEntity,
    field_id: &str,
) -> Option<&'a FieldTypeSource> {
    if field_id == entity.canonical_id.id {
        return Some(&entity.canonical_id.field_type);
    }
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| &field.logical.field_type)
}

fn temporal_parameter_sql(
    start_type: &FieldTypeSource,
    end_type: &FieldTypeSource,
    parameter: usize,
) -> Result<String, ReadServiceError> {
    match (start_type, end_type) {
        (FieldTypeSource::Date, FieldTypeSource::Date) => Ok(format!("${parameter}::text::date")),
        (FieldTypeSource::Timestamp, FieldTypeSource::Timestamp) => {
            Ok(format!("${parameter}::text::timestamptz"))
        }
        _ => Err(ReadServiceError::Unavailable),
    }
}

fn postgres_cast(field_type: &FieldTypeSource) -> &'static str {
    match field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. } => "text",
        FieldTypeSource::Int64 => "bigint",
        FieldTypeSource::Decimal { .. } => "numeric",
        FieldTypeSource::Date => "date",
        FieldTypeSource::Timestamp => "timestamptz",
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => "uuid",
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => "jsonb",
    }
}

fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn cursor_sort_value(value: Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn bounded_package_revision(
    row: &tokio_postgres::Row,
    index: usize,
) -> Result<String, ReadServiceError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(value)
}

fn valid_optional_cursor_reference(value: Option<&str>) -> bool {
    value.is_none_or(valid_cursor_reference)
}

fn valid_cursor_reference(value: &str) -> bool {
    const PREFIX: &str = "hmac-sha256:";
    value.strip_prefix(PREFIX).is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn valid_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

fn sql_quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotReadFaultPoint {
    BeforeTerminalAudit,
    HistoricalStatementTimeout,
}

#[cfg(not(feature = "postgres-test"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotReadFaultPoint {
    BeforeTerminalAudit,
}

#[derive(Clone, Copy)]
enum SnapshotReadFaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(SnapshotReadFaultPoint),
}

impl SnapshotReadFaultControl {
    fn fail_at(self, point: SnapshotReadFaultPoint) -> Result<(), ReadServiceError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self, Self::At(configured) if configured == point) {
            return Err(ReadServiceError::Unavailable);
        }
        let _ = (self, point);
        Ok(())
    }
}
