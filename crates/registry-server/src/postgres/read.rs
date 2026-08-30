// SPDX-License-Identifier: Apache-2.0

//! Concrete PostgreSQL record read service with durable audit release gates.

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
    AuthorizedRequestContext, HeldReadResponse, ReadServiceError, RecordReadRequest,
    RecordReadService, RowBoundaryOperator as ApiRowBoundaryOperator, ServiceFuture,
};
use crate::audit::{
    append_read_terminal_audit, profile_is_keyed, record_pre_io_audit, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::contract::{FieldTypeSource, Operation};
use crate::cursor::{now_unix_seconds, CursorCodec, CursorContinuation};
use crate::model::{
    CompiledEntity, CompiledQueryFilterOperator, CompiledQueryKind, CompiledQueryOperation,
    CompiledQuerySortDirection, CompiledRegistry,
};
use crate::mutation::strong_record_etag;

use super::{
    begin_record_transaction, validate_field_value, ClaimContext, ExpectedRegistryIdentity,
    RegistryLockKey, RowBoundaryContext, RuntimePool,
};

const MAX_SQL_LIMIT: usize = 1000;

/// Runtime PostgreSQL implementation of the read-only record surface.
#[derive(Clone)]
pub struct PostgresRecordReadService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
    cursors: Arc<CursorCodec>,
    fault: ReadFaultControl,
}

impl PostgresRecordReadService {
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
            fault: ReadFaultControl::Disabled,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: ReadFaultPoint) -> Self {
        self.fault = ReadFaultControl::At(fault);
        self
    }

    async fn execute(
        &self,
        request: RecordReadRequest,
        operation: Operation,
    ) -> Result<ReadResult, ReadServiceError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(ReadServiceError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, &request.context, &request.entity_id)?;
        let plan = match ReadPlan::from_request(
            &self.registry,
            &self.expected,
            self.cursors.as_ref(),
            &request,
            operation,
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
                        target_record: request.record_id.as_deref(),
                    },
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
                return Ok(ReadResult::empty_get());
            }
        };
        if operation == Operation::Get
            && !request
                .record_id
                .as_deref()
                .is_some_and(valid_canonical_uuid)
        {
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
                    target_record: request.record_id.as_deref(),
                },
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
            return Ok(ReadResult::empty_get());
        }

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
                target_record: request.record_id.as_deref(),
            },
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;

        let materialized = self.read_rows(&mut client, &request, &claims, &plan).await;
        let materialized = match materialized {
            Ok(materialized) => materialized,
            Err(error) => {
                let _ = self
                    .record_read_terminal_audit(
                        &mut client,
                        &claims,
                        &request,
                        self.terminal(
                            &request,
                            &claims,
                            &plan,
                            TerminalAuditOutcome::Refused,
                            0,
                            None,
                        )?,
                    )
                    .await;
                return Err(error);
            }
        };
        let mut held = ReadResult::from_materialized(plan.operation, materialized)?;
        if plan.operation == Operation::Get && held.response.is_some() {
            let response = held.response.take().ok_or(ReadServiceError::Unavailable)?;
            let record_id = request
                .record_id
                .as_deref()
                .ok_or(ReadServiceError::Unavailable)?;
            let record_revision = held.record_revision.ok_or(ReadServiceError::Unavailable)?;
            let etag = strong_record_etag(
                &self.audit_profile,
                &claims,
                &self.expected.package_revision,
                record_id,
                record_revision,
                &request.selected_fields,
            )
            .map_err(|_| ReadServiceError::Unavailable)?;
            held.response = Some(response.with_strong_etag(etag));
        }
        self.fault.fail_at(ReadFaultPoint::BeforeTerminalAudit)?;
        let outcome = if held.result_count == 0 {
            TerminalAuditOutcome::Empty
        } else {
            TerminalAuditOutcome::Returned
        };
        self.record_read_terminal_audit(
            &mut client,
            &claims,
            &request,
            self.terminal(
                &request,
                &claims,
                &plan,
                outcome,
                held.result_count,
                held.record_revision,
            )?,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(held)
    }

    async fn record_read_terminal_audit(
        &self,
        client: &mut deadpool_postgres::Client,
        claims: &ClaimContext,
        request: &RecordReadRequest,
        terminal: TerminalAudit,
    ) -> Result<(), crate::audit::RegistryAuditError> {
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
                terminal,
                query_reference: request
                    .query
                    .as_ref()
                    .map(|query| query.cursor_binding.query_reference.clone()),
                row_boundary_reference: request
                    .query
                    .as_ref()
                    .map(|query| query.cursor_binding.row_boundary_reference.clone()),
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::audit::RegistryAuditError::Unavailable)
    }

    async fn read_rows(
        &self,
        client: &mut deadpool_postgres::Client,
        request: &RecordReadRequest,
        claims: &ClaimContext,
        plan: &ReadPlan,
    ) -> Result<MaterializedRead, ReadServiceError> {
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let selected_fields = request.selected_fields.iter().cloned().collect::<Vec<_>>();
        let projection = projection(
            &plan.entity,
            &selected_fields,
            request
                .query
                .as_ref()
                .and_then(|query| query.sort.as_deref()),
        )?;
        let table = quote_identifier(&plan.entity.physical_table);
        let limit =
            i64::try_from(request.maximum_records).map_err(|_| ReadServiceError::Unavailable)?;
        let rows = match plan.operation {
            Operation::Get => {
                let sql = format!(
                    "SELECT {projection}
                     FROM registry_data.{table}
                     WHERE record_id = $1::text::uuid
                       AND record_lifecycle = 'active'
                     LIMIT 1"
                );
                let record_id = request
                    .record_id
                    .as_deref()
                    .ok_or(ReadServiceError::Unavailable)?;
                transaction
                    .transaction()
                    .query(&sql, &[&record_id])
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
            }
            Operation::List => {
                let query = request
                    .query
                    .as_ref()
                    .ok_or(ReadServiceError::Unavailable)?;
                let _compiled_query = plan
                    .query_operation
                    .as_ref()
                    .ok_or(ReadServiceError::Unavailable)?;
                let (sql, values) = list_sql(&plan.entity, query, &projection, &table)?;
                let mut params = values
                    .into_iter()
                    .map(|value| Box::new(value) as Box<dyn ToSql + Sync + Send>)
                    .collect::<Vec<_>>();
                params.push(Box::new(limit));
                let refs = params
                    .iter()
                    .map(|value| &**value as &(dyn ToSql + Sync))
                    .collect::<Vec<_>>();
                transaction
                    .transaction()
                    .query(&sql, &refs)
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
            }
            _ => return Err(ReadServiceError::Unavailable),
        };
        let page_size = request
            .query
            .as_ref()
            .map_or(request.maximum_records, |query| {
                usize::from(query.page_size)
            });
        let has_more = plan.operation == Operation::List && rows.len() > page_size;
        let rows = if has_more {
            &rows[..page_size]
        } else {
            rows.as_slice()
        };
        let next_cursor = if has_more {
            let query = request
                .query
                .as_ref()
                .ok_or(ReadServiceError::Unavailable)?;
            rows.last()
                .map(|row| self.next_cursor(row, &selected_fields, query))
                .transpose()?
        } else {
            None
        };
        let rows = rows
            .iter()
            .map(|row| row_to_record(row, &plan.entity, &selected_fields))
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(MaterializedRead { rows, next_cursor })
    }

    fn next_cursor(
        &self,
        row: &tokio_postgres::Row,
        selected_fields: &[String],
        query: &crate::api::CompiledReadQuery,
    ) -> Result<String, ReadServiceError> {
        let last_record_id = row
            .try_get::<_, String>(0)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let sort_value = if query.sort.is_some() {
            row.try_get::<_, Option<Value>>(selected_fields.len() + 2)
                .map_err(|_| ReadServiceError::Unavailable)?
                .and_then(cursor_sort_value)
        } else {
            None
        };
        let payload = self
            .cursors
            .new_payload(
                now_unix_seconds(),
                query.cursor_binding.clone(),
                query.cursor_query.clone(),
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

    fn terminal(
        &self,
        request: &RecordReadRequest,
        claims: &ClaimContext,
        plan: &ReadPlan,
        outcome: TerminalAuditOutcome,
        result_count: usize,
        record_revision: Option<i64>,
    ) -> Result<TerminalAudit, ReadServiceError> {
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
            .map_err(|_| ReadServiceError::Unavailable)?;
        let record_reference = request
            .record_id
            .as_deref()
            .map(|record_id| {
                key_hasher.audit_reference_hash(
                    "registry-server-record-v1",
                    &self.expected.package_revision,
                    record_id,
                )
            })
            .transpose()
            .map_err(|_| ReadServiceError::Unavailable)?;
        let field_set_reference = field_set_reference(
            &self.audit_profile,
            &self.expected.package_revision,
            &request.selected_fields,
        )?;
        Ok(TerminalAudit {
            outcome,
            method: request.method,
            operation_id: request.operation_id.clone(),
            entity_id: plan.entity.id.clone(),
            package_revision: self.expected.package_revision.clone(),
            selected_access_profile: claims.access_profile().to_owned(),
            purpose_present: claims.purpose().is_some(),
            principal_reference,
            record_reference,
            record_revision,
            result_count: Some(result_count),
            field_set_reference: Some(field_set_reference),
        })
    }
}

impl RecordReadService for PostgresRecordReadService {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async move {
            let result = self.execute(request, Operation::Get).await?;
            Ok(result.response)
        })
    }

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async move {
            self.execute(request, Operation::List)
                .await?
                .response
                .ok_or(ReadServiceError::Unavailable)
        })
    }

    fn refusal(
        &self,
        request: crate::api::RecordReadRefusal,
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
                },
            )
            .await
            .map_err(|_| ReadServiceError::Unavailable)
        })
    }
}

struct ReadResult {
    response: Option<HeldReadResponse>,
    result_count: usize,
    record_revision: Option<i64>,
}

impl ReadResult {
    fn empty_get() -> Self {
        Self {
            response: None,
            result_count: 0,
            record_revision: None,
        }
    }

    fn from_materialized(
        operation: Operation,
        materialized: MaterializedRead,
    ) -> Result<Self, ReadServiceError> {
        match operation {
            Operation::Get => {
                let Some(record) = materialized.rows.into_iter().next() else {
                    return Ok(Self::empty_get());
                };
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json(&json!(record))?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            Operation::List => {
                let result_count = materialized.rows.len();
                let response = HeldReadResponse::from_json(&json!({
                    "items": materialized.rows,
                    "pageInfo": {"nextCursor": materialized.next_cursor},
                }))?;
                Ok(Self {
                    response: Some(response),
                    result_count,
                    record_revision: None,
                })
            }
            _ => Err(ReadServiceError::Unavailable),
        }
    }
}

struct MaterializedRead {
    rows: Vec<RecordEnvelope>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordEnvelope {
    id: String,
    revision: u64,
    data: Map<String, Value>,
}

struct ReadPlan {
    operation: Operation,
    entity: CompiledEntity,
    query_operation: Option<CompiledQueryOperation>,
}

impl ReadPlan {
    fn from_request(
        registry: &CompiledRegistry,
        expected: &ExpectedRegistryIdentity,
        cursors: &CursorCodec,
        request: &RecordReadRequest,
        operation: Operation,
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
        let inventory = registry
            .physical_names()
            .entities
            .get(&request.entity_id)
            .ok_or(())?;
        let query_operation = if operation == Operation::List {
            let Some(query) = request.query.as_ref() else {
                return Err(());
            };
            if route.query_kind != Some(query.kind) || query.route_id != route.id {
                return Err(());
            }
            let Some(operation) = registry.queries().operations.iter().find(|operation| {
                operation.id == query.query_operation_id
                    && operation.route_id == route.id
                    && operation.entity_id == request.entity_id
                    && operation.profile_id == request.context.selected_profile()
                    && operation.kind == query.kind
            }) else {
                return Err(());
            };
            validate_compiled_query_request(
                registry, expected, cursors, entity, operation, request, query,
            )?;
            Some(operation.clone())
        } else {
            if request.query.is_some() {
                return Err(());
            }
            None
        };
        if route.operation != operation
            || route.method != request.method
            || route.entity_id != request.entity_id
            || !route
                .access_profiles
                .iter()
                .any(|profile| profile == request.context.selected_profile())
            || !profile.operations.contains(&operation)
            || request.maximum_records == 0
            || request.maximum_records > MAX_SQL_LIMIT
            || operation == Operation::Get && request.maximum_records != 1
            || inventory.table != entity.physical_table
            || !valid_physical_identifier(&entity.physical_table)
            || entity.fields.iter().any(|(id, field)| {
                inventory.fields.get(id) != Some(&field.physical_name)
                    || !valid_physical_identifier(&field.physical_name)
            })
            || !request.selected_fields.is_subset(&profile.readable_fields)
            || request
                .selected_fields
                .iter()
                .any(|field| !entity.fields.contains_key(field))
        {
            return Err(());
        }
        Ok(Self {
            operation,
            entity: entity.clone(),
            query_operation,
        })
    }
}

fn validate_compiled_query_request(
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    cursors: &CursorCodec,
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    request: &RecordReadRequest,
    query: &crate::api::CompiledReadQuery,
) -> Result<(), ()> {
    let selected_fields = request.selected_fields.iter().cloned().collect::<Vec<_>>();
    let expected_maximum = usize::from(query.page_size).checked_add(1).ok_or(())?;
    if query.page_size == 0
        || query.page_size > operation.max_page_size
        || request.maximum_records != expected_maximum
        || request.maximum_records > MAX_SQL_LIMIT
        || query.cursor_binding.package_revision != expected.package_revision
        || query.cursor_binding.schema_fingerprint != expected.schema_fingerprint
        || query.cursor_binding.registry_revision != registry.revision()
        || query.cursor_binding.route_id != query.route_id
        || query.cursor_binding.query_operation_id != query.query_operation_id
        || query.cursor_binding.query_kind != query.kind
        || query.cursor_binding.selected_profile != request.context.selected_profile()
        || query.cursor_binding.page_size != query.page_size
        || query.cursor_binding.temporal_instant != query.temporal_instant
        || query.cursor_binding.selected_fields != selected_fields
        || !valid_optional_cursor_reference(query.cursor_binding.principal_reference.as_deref())
        || !valid_optional_cursor_reference(query.cursor_binding.purpose_reference.as_deref())
        || !valid_cursor_reference(&query.cursor_binding.row_boundary_reference)
        || !valid_cursor_reference(&query.cursor_binding.projection_reference)
        || !valid_cursor_reference(&query.cursor_binding.query_reference)
        || !valid_cursor_reference(&query.cursor_binding.sort_reference)
        || !request
            .selected_fields
            .iter()
            .all(|field| operation.projection_fields.contains(field))
        || !operation
            .projection_fields
            .iter()
            .all(|field| entity.fields.contains_key(field))
    {
        return Err(());
    }
    match query.kind {
        CompiledQueryKind::List => {
            if query.temporal_instant.is_some() || operation.temporal.is_some() {
                return Err(());
            }
        }
        CompiledQueryKind::Current | CompiledQueryKind::AsOf => {
            let Some(binding) = operation.temporal.as_ref() else {
                return Err(());
            };
            if query.temporal_instant.is_none()
                || !entity.fields.contains_key(&binding.start_field)
                || !entity.fields.contains_key(&binding.end_field)
            {
                return Err(());
            }
        }
    }
    if query.filters.len() > 32 {
        return Err(());
    }
    let mut total_in_values = 0_usize;
    for filter in &query.filters {
        let Some(compiled_filter) = operation
            .filter_fields
            .iter()
            .find(|candidate| candidate.field == filter.field)
        else {
            return Err(());
        };
        if !compiled_filter.operators.contains(&filter.operator)
            || !entity.fields.contains_key(&filter.field)
        {
            return Err(());
        }
        let field_type = &entity.fields[&filter.field].field_type;
        match filter.operator {
            CompiledQueryFilterOperator::Equals | CompiledQueryFilterOperator::Prefix => {
                if filter.values.len() != 1
                    || validate_field_value(&filter.values[0], field_type).is_err()
                {
                    return Err(());
                }
            }
            CompiledQueryFilterOperator::In => {
                if filter.values.is_empty() {
                    return Err(());
                }
                total_in_values = total_in_values.checked_add(filter.values.len()).ok_or(())?;
                if total_in_values > 100
                    || filter
                        .values
                        .windows(2)
                        .any(|window| window[0] >= window[1])
                    || filter
                        .values
                        .iter()
                        .any(|value| validate_field_value(value, field_type).is_err())
                {
                    return Err(());
                }
            }
            CompiledQueryFilterOperator::Range => {
                if filter.values.len() != 2
                    || filter
                        .values
                        .iter()
                        .any(|value| validate_field_value(value, field_type).is_err())
                {
                    return Err(());
                }
            }
            CompiledQueryFilterOperator::IsNull | CompiledQueryFilterOperator::IsNotNull => {
                if filter.values.len() != 1 || filter.values[0] != "true" {
                    return Err(());
                }
            }
        }
    }
    if let Some(sort) = &query.sort {
        let Some(compiled_sort) = operation
            .sort_fields
            .iter()
            .find(|candidate| candidate.field == *sort)
        else {
            return Err(());
        };
        if !compiled_sort
            .directions
            .contains(&CompiledQuerySortDirection::Asc)
            || !entity.fields.contains_key(sort)
        {
            return Err(());
        }
    }
    if let Some(continuation) = &query.continuation {
        if !valid_canonical_uuid(&continuation.last_record_id) {
            return Err(());
        }
        match (&query.sort, &continuation.sort_value) {
            (Some(sort), Some(value)) => {
                let Some(field) = entity.fields.get(sort) else {
                    return Err(());
                };
                if validate_field_value(value, &field.field_type).is_err() {
                    return Err(());
                }
            }
            (Some(_), None) | (None, None) => {}
            (None, Some(_)) => return Err(()),
        }
    }
    let expected_filters = query
        .filters
        .iter()
        .map(|filter| crate::cursor::CursorFilter {
            field: filter.field.clone(),
            operator: query_filter_operator_name(filter.operator).to_owned(),
            values: filter.values.clone(),
        })
        .collect::<Vec<_>>();
    if query.cursor_query.filters != expected_filters || query.cursor_query.sort != query.sort {
        return Err(());
    }
    let references = cursor_binding_references(cursors, request, operation, query)?;
    if query.cursor_binding.principal_reference != references.principal
        || query.cursor_binding.purpose_reference != references.purpose
        || query.cursor_binding.row_boundary_reference != references.row_boundary
        || query.cursor_binding.projection_reference != references.projection
        || query.cursor_binding.query_reference != references.query
        || query.cursor_binding.sort_reference != references.sort
    {
        return Err(());
    }
    Ok(())
}

struct CursorBindingReferences {
    principal: Option<String>,
    purpose: Option<String>,
    row_boundary: String,
    projection: String,
    query: String,
    sort: String,
}

fn cursor_binding_references(
    cursors: &CursorCodec,
    request: &RecordReadRequest,
    operation: &CompiledQueryOperation,
    query: &crate::api::CompiledReadQuery,
) -> Result<CursorBindingReferences, ()> {
    let principal = request
        .context
        .principal()
        .map(|value| {
            cursors.binding_digest_bytes(b"registry-server-cursor-principal-v1", value.as_bytes())
        })
        .transpose()
        .map_err(|_| ())?;
    let purpose = request
        .context
        .purpose()
        .map(|value| {
            cursors.binding_digest_bytes(b"registry-server-cursor-purpose-v1", value.as_bytes())
        })
        .transpose()
        .map_err(|_| ())?;
    let row_boundary = cursors
        .binding_digest(
            b"registry-server-cursor-row-boundary-v1",
            &json!(request
                .context
                .row_boundaries()
                .iter()
                .map(|boundary| {
                    json!({
                        "field": boundary.field(),
                        "operator": match boundary.operator() {
                            ApiRowBoundaryOperator::Equals => "equals",
                            ApiRowBoundaryOperator::In => "in",
                        },
                        "values": boundary.values(),
                    })
                })
                .collect::<Vec<_>>()),
        )
        .map_err(|_| ())?;
    let selected_fields = request.selected_fields.iter().cloned().collect::<Vec<_>>();
    let projection = cursors
        .binding_digest(
            b"registry-server-cursor-projection-v1",
            &json!({"selectedFields": selected_fields}),
        )
        .map_err(|_| ())?;
    let query_reference = cursors
        .binding_digest(
            b"registry-server-cursor-query-v1",
            &json!({
                "filters": query.cursor_query.filters,
                "temporalInstant": query.temporal_instant,
            }),
        )
        .map_err(|_| ())?;
    let sort = cursors
        .binding_digest(
            b"registry-server-cursor-sort-v1",
            &json!({
                "sort": query.sort,
                "tieBreaker": operation.stable_tie_breaker,
            }),
        )
        .map_err(|_| ())?;
    Ok(CursorBindingReferences {
        principal,
        purpose,
        row_boundary,
        projection,
        query: query_reference,
        sort,
    })
}

fn query_filter_operator_name(operator: CompiledQueryFilterOperator) -> &'static str {
    match operator {
        CompiledQueryFilterOperator::Equals => "equals",
        CompiledQueryFilterOperator::In => "in",
        CompiledQueryFilterOperator::Range => "range",
        CompiledQueryFilterOperator::IsNull => "is_null",
        CompiledQueryFilterOperator::IsNotNull => "is_not_null",
        CompiledQueryFilterOperator::Prefix => "prefix",
    }
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
                let value = boundary
                    .values()
                    .iter()
                    .next()
                    .ok_or(ReadServiceError::Unavailable)?;
                if boundary.values().len() != 1 {
                    return Err(ReadServiceError::Unavailable);
                }
                Ok(RowBoundaryContext::Equals {
                    field: boundary.field().to_owned(),
                    value: value.clone(),
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

fn projection(
    entity: &CompiledEntity,
    selected_fields: &[String],
    sort: Option<&str>,
) -> Result<String, ReadServiceError> {
    let mut expressions = vec!["record_id::text".to_owned(), "record_revision".to_owned()];
    for field in selected_fields {
        let Some(compiled_field) = entity.fields.get(field) else {
            return Err(ReadServiceError::Unavailable);
        };
        let column = quote_identifier(&compiled_field.physical_name);
        if matches!(compiled_field.field_type, FieldTypeSource::Decimal { .. }) {
            expressions.push(format!("to_jsonb({column}::text)"));
        } else {
            expressions.push(format!("to_jsonb({column})"));
        }
    }
    if let Some(sort) = sort {
        let Some(compiled_field) = entity.fields.get(sort) else {
            return Err(ReadServiceError::Unavailable);
        };
        let column = quote_identifier(&compiled_field.physical_name);
        if matches!(compiled_field.field_type, FieldTypeSource::Decimal { .. }) {
            expressions.push(format!("to_jsonb({column}::text)"));
        } else {
            expressions.push(format!("to_jsonb({column})"));
        }
    }
    Ok(expressions.join(", "))
}

fn list_sql(
    entity: &CompiledEntity,
    query: &crate::api::CompiledReadQuery,
    projection: &str,
    table: &str,
) -> Result<(String, Vec<String>), ReadServiceError> {
    let mut values = Vec::new();
    let mut predicates = vec!["record_lifecycle = 'active'".to_owned()];
    let mut grouped_in: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for filter in &query.filters {
        let Some(compiled_field) = entity.fields.get(&filter.field) else {
            return Err(ReadServiceError::Unavailable);
        };
        let column = quote_identifier(&compiled_field.physical_name);
        let cast = postgres_cast(&compiled_field.field_type);
        match filter.operator {
            CompiledQueryFilterOperator::Equals => {
                let parameter = push_value(&mut values, &filter.values[0]);
                predicates.push(format!("{column} = ${parameter}::text::{cast}"));
            }
            CompiledQueryFilterOperator::In => {
                if filter.values.is_empty() {
                    return Err(ReadServiceError::Unavailable);
                }
                grouped_in
                    .entry(&filter.field)
                    .or_default()
                    .extend(filter.values.iter().map(String::as_str));
            }
            CompiledQueryFilterOperator::Range => {
                let lower = push_value(&mut values, &filter.values[0]);
                let upper = push_value(&mut values, &filter.values[1]);
                predicates.push(format!(
                    "{column} >= ${lower}::text::{cast} AND {column} <= ${upper}::text::{cast}"
                ));
            }
            CompiledQueryFilterOperator::IsNull => predicates.push(format!("{column} IS NULL")),
            CompiledQueryFilterOperator::IsNotNull => {
                predicates.push(format!("{column} IS NOT NULL"));
            }
            CompiledQueryFilterOperator::Prefix => {
                let parameter =
                    push_value(&mut values, &format!("{}%", escape_like(&filter.values[0])));
                predicates.push(format!("{column} LIKE ${parameter}::text ESCAPE '\\'"));
            }
        }
    }
    for (field, finite_values) in grouped_in {
        if finite_values.is_empty() {
            return Err(ReadServiceError::Unavailable);
        }
        let Some(compiled_field) = entity.fields.get(field) else {
            return Err(ReadServiceError::Unavailable);
        };
        let column = quote_identifier(&compiled_field.physical_name);
        let cast = postgres_cast(&compiled_field.field_type);
        let placeholders = finite_values
            .iter()
            .map(|value| {
                let parameter = push_value(&mut values, value);
                format!("${parameter}::text::{cast}")
            })
            .collect::<Vec<_>>();
        predicates.push(format!("{column} IN ({})", placeholders.join(", ")));
    }
    if let Some(instant) = &query.temporal_instant {
        let temporal = entity
            .temporal
            .as_ref()
            .ok_or(ReadServiceError::Unavailable)?;
        let start_field = entity
            .fields
            .get(&temporal.start_field)
            .ok_or(ReadServiceError::Unavailable)?;
        let end_field = entity
            .fields
            .get(&temporal.end_field)
            .ok_or(ReadServiceError::Unavailable)?;
        let start = quote_identifier(&start_field.physical_name);
        let end = quote_identifier(&end_field.physical_name);
        let parameter = push_value(&mut values, instant);
        let instant_expression =
            temporal_instant_expression(&start_field.field_type, &end_field.field_type, parameter)?;
        predicates.push(format!(
            "{start} <= {instant_expression} AND ({end} IS NULL OR {instant_expression} < {end})"
        ));
    } else if matches!(
        query.kind,
        CompiledQueryKind::Current | CompiledQueryKind::AsOf
    ) {
        return Err(ReadServiceError::Unavailable);
    }
    if let Some(continuation) = &query.continuation {
        if !valid_canonical_uuid(&continuation.last_record_id) {
            return Err(ReadServiceError::CursorInvalid);
        }
        let record_parameter = push_value(&mut values, &continuation.last_record_id);
        if let Some(sort) = &query.sort {
            let Some(compiled_field) = entity.fields.get(sort) else {
                return Err(ReadServiceError::Unavailable);
            };
            let column = quote_identifier(&compiled_field.physical_name);
            let cast = postgres_cast(&compiled_field.field_type);
            match &continuation.sort_value {
                Some(value) => {
                    validate_field_value(value, &compiled_field.field_type)
                        .map_err(|_| ReadServiceError::CursorInvalid)?;
                    let sort_parameter = push_value(&mut values, value);
                    predicates.push(format!(
                        "({column} > ${sort_parameter}::text::{cast} OR {column} IS NULL OR ({column} = ${sort_parameter}::text::{cast} AND record_id > ${record_parameter}::text::uuid))"
                    ));
                }
                None => predicates.push(format!(
                    "({column} IS NULL AND record_id > ${record_parameter}::text::uuid)"
                )),
            }
        } else {
            predicates.push(format!("record_id > ${record_parameter}::text::uuid"));
        }
    }
    let order = if let Some(sort) = &query.sort {
        let column = quote_identifier(
            &entity
                .fields
                .get(sort)
                .ok_or(ReadServiceError::Unavailable)?
                .physical_name,
        );
        format!("{column} ASC NULLS LAST, record_id ASC")
    } else {
        "record_id ASC".to_owned()
    };
    let limit_parameter = values.len() + 1;
    Ok((
        format!(
            "SELECT {projection}
             FROM registry_data.{table}
             WHERE {}
             ORDER BY {order}
             LIMIT ${limit_parameter}::bigint",
            predicates.join(" AND ")
        ),
        values,
    ))
}

fn temporal_instant_expression(
    start_type: &FieldTypeSource,
    end_type: &FieldTypeSource,
    parameter: usize,
) -> Result<String, ReadServiceError> {
    match (start_type, end_type) {
        (FieldTypeSource::Date, FieldTypeSource::Date) => Ok(format!(
            "((${parameter}::text::timestamptz AT TIME ZONE 'UTC')::date)"
        )),
        (FieldTypeSource::Timestamp, FieldTypeSource::Timestamp) => {
            Ok(format!("${parameter}::text::timestamptz"))
        }
        _ => Err(ReadServiceError::Unavailable),
    }
}

fn push_value(values: &mut Vec<String>, value: &str) -> usize {
    values.push(value.to_owned());
    values.len()
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

fn row_to_record(
    row: &tokio_postgres::Row,
    entity: &CompiledEntity,
    selected_fields: &[String],
) -> Result<RecordEnvelope, ReadServiceError> {
    let id = row
        .try_get::<_, String>(0)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let revision = row
        .try_get::<_, i64>(1)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if !valid_canonical_uuid(&id) || revision <= 0 || row.len() < selected_fields.len() + 2 {
        return Err(ReadServiceError::Unavailable);
    }
    let revision = u64::try_from(revision).map_err(|_| ReadServiceError::Unavailable)?;
    let mut data = Map::new();
    for (index, field) in selected_fields.iter().enumerate() {
        if !entity.fields.contains_key(field) {
            return Err(ReadServiceError::Unavailable);
        }
        let value = row
            .try_get::<_, Option<Value>>(index + 2)
            .map_err(|_| ReadServiceError::Unavailable)?
            .unwrap_or(Value::Null);
        data.insert(field.clone(), value);
    }
    Ok(RecordEnvelope { id, revision, data })
}

fn field_set_reference(
    profile: &AuditProfile,
    package_revision: &str,
    selected_fields: &BTreeSet<String>,
) -> Result<String, ReadServiceError> {
    let canonical = canonicalize_json(&json!({
        "selectedFields": selected_fields,
    }))
    .map_err(|_| ReadServiceError::Unavailable)?;
    let canonical = std::str::from_utf8(&canonical).map_err(|_| ReadServiceError::Unavailable)?;
    profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-read-field-set-v1",
            package_revision,
            canonical,
        )
        .map_err(|_| ReadServiceError::Unavailable)
}

fn valid_physical_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.len() <= 63
}

fn quote_identifier(value: &str) -> String {
    debug_assert!(valid_physical_identifier(value));
    format!("\"{value}\"")
}

fn valid_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use crate::api::{
        AuthorizedRequestContext, CompiledReadQuery, ReadFilterClause, RecordReadRequest,
    };
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{parse_project_json, FieldTypeSource, Operation};
    use crate::cursor::{CursorBinding, CursorCodec, CursorContinuation, CursorQuery};
    use crate::model::{CompiledQueryFilterOperator, CompiledQueryKind, HttpMethod};
    use zeroize::Zeroizing;

    use super::{
        cursor_binding_references, temporal_instant_expression, ExpectedRegistryIdentity, ReadPlan,
        ReadServiceError,
    };

    #[test]
    fn temporal_query_instant_uses_utc_calendar_dates_without_session_timezone_dependence() {
        assert_eq!(
            temporal_instant_expression(&FieldTypeSource::Date, &FieldTypeSource::Date, 7)
                .expect("date temporal fields are valid"),
            "(($7::text::timestamptz AT TIME ZONE 'UTC')::date)"
        );
        assert_eq!(
            temporal_instant_expression(
                &FieldTypeSource::Timestamp,
                &FieldTypeSource::Timestamp,
                3,
            )
            .expect("timestamp temporal fields are valid"),
            "$3::text::timestamptz"
        );
        assert!(matches!(
            temporal_instant_expression(&FieldTypeSource::Date, &FieldTypeSource::Timestamp, 1,),
            Err(ReadServiceError::Unavailable)
        ));
    }

    #[test]
    fn forged_compiled_query_shapes_fail_before_sql_construction() {
        let registry = compile_project(
            &parse_project_json(
                br#"{
                  "apiVersion":"registry.registrystack.org/v1alpha1",
                  "kind":"RegistryProject",
                  "registry":{"id":"plan-guard","version":"1","defaultLanguage":"en"},
                  "entities":[{
                    "id":"case","route":"cases","mutationMode":"mutable","classification":"public",
                    "fields":[
                      {"id":"label","type":"string","required":true,"maxLength":32,"classification":"public"},
                      {"id":"secret","type":"string","required":true,"maxLength":32,"classification":"restricted"}
                    ],
                    "accessProfiles":[{
                      "id":"public","default":true,"anonymous":true,"operations":["list"],
                      "readableFields":["label"],"filterableFields":["label"],"sortableFields":["label"]
                    }]
                  }]
                }"#,
            )
            .expect("fixture parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("fixture compiles");
        let expected = ExpectedRegistryIdentity {
            package_id: "package".to_owned(),
            environment: "local".to_owned(),
            instance_id: "instance".to_owned(),
            database_id: "database".to_owned(),
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
            package_sequence: 1,
        };
        let operation = registry
            .queries()
            .operations
            .iter()
            .find(|operation| operation.kind == CompiledQueryKind::List)
            .expect("list query operation exists");
        let cursors = CursorCodec::new(Zeroizing::new(vec![0x19; 32]), Duration::from_secs(300))
            .expect("test cursor codec is valid");

        let mut request = RecordReadRequest {
            entity_id: "case".to_owned(),
            operation_id: "records.case.list".to_owned(),
            method: HttpMethod::Get,
            record_id: None,
            context: AuthorizedRequestContext::new(None, None, "public".to_owned(), Vec::new()),
            selected_fields: BTreeSet::from(["label".to_owned()]),
            query: Some(CompiledReadQuery {
                route_id: operation.route_id.clone(),
                query_operation_id: operation.id.clone(),
                kind: CompiledQueryKind::List,
                cursor_binding: CursorBinding {
                    package_revision: expected.package_revision.clone(),
                    schema_fingerprint: expected.schema_fingerprint.clone(),
                    registry_revision: registry.revision().to_owned(),
                    route_id: operation.route_id.clone(),
                    query_operation_id: operation.id.clone(),
                    query_kind: CompiledQueryKind::List,
                    selected_profile: "public".to_owned(),
                    principal_reference: None,
                    purpose_reference: None,
                    row_boundary_reference: digest(),
                    projection_reference: digest(),
                    query_reference: digest(),
                    sort_reference: digest(),
                    page_size: 10,
                    temporal_instant: None,
                    selected_fields: vec!["label".to_owned()],
                },
                cursor_query: CursorQuery {
                    filters: Vec::new(),
                    sort: None,
                },
                filters: vec![ReadFilterClause {
                    field: "secret".to_owned(),
                    operator: CompiledQueryFilterOperator::Equals,
                    values: vec!["hidden".to_owned()],
                }],
                sort: None,
                page_size: 10,
                temporal_instant: None,
                continuation: None,
            }),
            maximum_records: 11,
        };
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_err()
        );

        let query = request.query.as_mut().expect("query present");
        query.filters.clear();
        query.sort = Some("secret".to_owned());
        query.cursor_query.sort = Some("secret".to_owned());
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_err()
        );

        let query = request.query.as_mut().expect("query present");
        query.sort = None;
        query.cursor_query.sort = None;
        query.cursor_binding.query_reference = "hidden-raw-query-value".to_owned();
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_err()
        );

        let query = request.query.as_mut().expect("query present");
        query.cursor_binding.query_reference = digest();
        query.continuation = Some(CursorContinuation {
            last_record_id: "not-a-canonical-uuid".to_owned(),
            sort_value: None,
        });
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_err()
        );

        let query = request.query.as_mut().expect("query present");
        query.continuation = None;
        let references = cursor_binding_references(
            &cursors,
            &request,
            operation,
            request.query.as_ref().expect("query present"),
        )
        .expect("bounded request context has cursor references");
        let query = request.query.as_mut().expect("query present");
        query.cursor_binding.principal_reference = references.principal;
        query.cursor_binding.purpose_reference = references.purpose;
        query.cursor_binding.row_boundary_reference = references.row_boundary;
        query.cursor_binding.projection_reference = references.projection;
        query.cursor_binding.query_reference = references.query;
        query.cursor_binding.sort_reference = references.sort;
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_ok()
        );

        request
            .query
            .as_mut()
            .expect("query present")
            .cursor_binding
            .query_reference = digest();
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request, Operation::List)
                .is_err(),
            "a well-shaped forged binding digest fails before SQL construction"
        );
    }

    fn digest() -> String {
        format!("hmac-sha256:{}", "0".repeat(64))
    }
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFaultPoint {
    BeforeTerminalAudit,
}

#[cfg(not(feature = "postgres-test"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadFaultPoint {
    BeforeTerminalAudit,
}

#[derive(Clone, Copy)]
enum ReadFaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(ReadFaultPoint),
}

impl ReadFaultControl {
    fn fail_at(self, point: ReadFaultPoint) -> Result<(), ReadServiceError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self, Self::At(configured) if configured == point) {
            return Err(ReadServiceError::Unavailable);
        }
        let _ = (self, point);
        Ok(())
    }
}
