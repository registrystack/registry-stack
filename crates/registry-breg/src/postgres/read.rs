// SPDX-License-Identifier: Apache-2.0

//! Concrete PostgreSQL record read service with durable audit release gates.

#[path = "request_read.rs"]
mod request_read;

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
    AuthorizedRequestContext, HeldReadResponse, LookupSelectorValue, ReadFilterExpr,
    ReadFilterOperator, ReadFilterPredicate, ReadLogicalOp, ReadOrderClause, ReadProjectionField,
    ReadServiceError, ReadSpatialQuery, RecordReadKind, RecordReadRequest, RecordReadService,
    RowBoundaryOperator as ApiRowBoundaryOperator, ServiceFuture,
};
use crate::audit::{
    append_read_terminal_audit, profile_is_keyed, record_pre_io_audit, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::contract::{FieldTypeSource, Operation};
use crate::cursor::{
    now_unix_seconds, CursorAdapter, CursorBboxQuery, CursorCodec, CursorContinuation,
    CursorFilterExpr, CursorFilterOperator, CursorLogicalOp, CursorOrderClause,
    CursorProjectionField, CursorQueryScope, CursorRepresentation, CursorSpatialQuery,
};
use crate::model::{
    request_query_field_api_name, request_query_field_type, CompiledEntity, CompiledQueryKind,
    CompiledQueryOperation, CompiledQuerySortDirection, CompiledReadPath, CompiledRegistry,
    REQUEST_BREG_STATE_QUERY_FIELD, REQUEST_EFFECT_DIGEST_QUERY_FIELD,
    REQUEST_PROPOSAL_VERSION_QUERY_FIELD,
};
use crate::mutation::strong_record_etag_for_representation;
use crate::query_binding::{CursorBindingQuery, CursorBindingReferences};
use crate::record_profile::{self, RecordRepresentation};

use super::{
    begin_record_transaction, install_spatial_bbox_context, validate_field_value, ClaimContext,
    ExpectedRegistryIdentity, RegistryLockKey, RowBoundaryContext, RuntimePool, SpatialBboxContext,
};

const MAX_SQL_LIMIT: usize = 1000;
const MAX_SPATIAL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

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
    #[cfg(feature = "postgres-test")]
    query_plan: Option<Arc<std::sync::Mutex<Vec<Value>>>>,
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
            #[cfg(feature = "postgres-test")]
            query_plan: None,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: ReadFaultPoint) -> Self {
        self.fault = ReadFaultControl::At(fault);
        self
    }

    /// Observe the actual list plan under its runtime role and transaction
    /// context. Only node/index names and spatial-index use leave the probe.
    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_query_plan_for_test(
        mut self,
        query_plan: Arc<std::sync::Mutex<Vec<Value>>>,
    ) -> Self {
        self.query_plan = Some(query_plan);
        self
    }

    async fn execute(&self, request: RecordReadRequest) -> Result<ReadResult, ReadServiceError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(ReadServiceError::Unavailable);
        }
        let operation = request_operation(&request.kind);
        let target_record = target_record(&request.kind);
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
                        target_record,
                        refusal_reason: None,
                        correlation: &request.correlation,
                    },
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
                return Ok(ReadResult::empty_get());
            }
        };
        if operation == Operation::Get && !target_record.is_some_and(valid_canonical_uuid) {
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
                    target_record,
                    refusal_reason: None,
                    correlation: &request.correlation,
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
                target_record,
                refusal_reason: None,
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
        let mut held =
            match ReadResult::from_materialized(&self.registry, &request, &plan, materialized)
                .and_then(|result| result.enforce_spatial_response_budget(&request))
            {
                Ok(held) => held,
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
        if plan.operation == Operation::Get
            && request.representation != CursorRepresentation::GeoJson
            && held.response.is_some()
        {
            let response = held.response.take().ok_or(ReadServiceError::Unavailable)?;
            let record_id = target_record.ok_or(ReadServiceError::Unavailable)?;
            let record_revision = held.record_revision.ok_or(ReadServiceError::Unavailable)?;
            let representation = match request.representation {
                CursorRepresentation::Json => RecordRepresentation::Json,
                CursorRepresentation::JsonLd => RecordRepresentation::JsonLd,
                CursorRepresentation::GeoJson => return Err(ReadServiceError::Unavailable),
            };
            let etag = strong_record_etag_for_representation(
                &self.audit_profile,
                &claims,
                &self.expected.package_revision,
                record_id,
                record_revision,
                &request.selected_fields,
                representation,
            )
            .map_err(|_| ReadServiceError::Unavailable)?;
            held.response = Some(response.with_strong_etag(etag));
        }
        self.fault.fail_at(ReadFaultPoint::BeforeTerminalAudit)?;
        let outcome = match (plan.operation, held.result_count) {
            (Operation::Lookup, 0) => TerminalAuditOutcome::Unresolved,
            (_, 0) => TerminalAuditOutcome::Empty,
            _ => TerminalAuditOutcome::Returned,
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
                query_reference: request_query(&request.kind)
                    .map(|query| query.cursor_binding.query_reference.clone()),
                row_boundary_reference: request_query(&request.kind)
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
        crate::mutation::install_request_visibility_context(
            transaction.transaction(),
            &plan.entity,
            claims,
            &self.audit_profile,
            &self.expected.database_id,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let query = request_query(&request.kind);
        install_evaluation_date(transaction.transaction(), query).await?;
        install_spatial_query_context(transaction.transaction(), query).await?;
        if let RecordReadKind::Relationship {
            root_id, path_id, ..
        } = &request.kind
        {
            install_read_path_context(transaction.transaction(), path_id, root_id).await?;
        }
        let selected_fields = if let Some(query) = query {
            query
                .projection
                .iter()
                .map(|field| field.field_id.clone())
                .collect::<Vec<_>>()
        } else {
            request.selected_fields.iter().cloned().collect::<Vec<_>>()
        };
        let relations = if let Some(path) = &plan.read_path {
            let root_id = match &request.kind {
                RecordReadKind::Relationship {
                    root_id, path_id, ..
                } if path_id == &path.id => root_id.as_str(),
                _ => return Err(ReadServiceError::Unavailable),
            };
            let through = plan
                .through_entity
                .as_ref()
                .ok_or(ReadServiceError::Unavailable)?;
            ReadRelations::relationship(&plan.source_entity, through, &plan.entity, path, root_id)?
        } else {
            ReadRelations::collection(&plan.entity, query, &selected_fields)?
        };
        let projection = projection(&plan.entity, &relations, &selected_fields, query)?;
        let limit =
            i64::try_from(request.maximum_records).map_err(|_| ReadServiceError::Unavailable)?;
        let mut total_count = None;
        let rows = match plan.operation {
            Operation::Get => {
                let sql = format!(
                    "SELECT {projection}
                     FROM {}
                     WHERE {} = $1::text::uuid
                     LIMIT 1",
                    relations.from_sql, relations.id_expression
                );
                let record_id =
                    target_record(&request.kind).ok_or(ReadServiceError::Unavailable)?;
                transaction
                    .transaction()
                    .query(&sql, &[&record_id])
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
            }
            Operation::List => {
                let query = query.ok_or(ReadServiceError::Unavailable)?;
                let _compiled_query = plan
                    .query_operation
                    .as_ref()
                    .ok_or(ReadServiceError::Unavailable)?;
                let ListStatements {
                    page_sql: sql,
                    count_sql,
                    count_parameters,
                    values,
                } = list_sql(&plan.entity, &relations, query, &projection)?;
                if query.include_count {
                    let refs = values
                        .get(..count_parameters)
                        .ok_or(ReadServiceError::Unavailable)?
                        .iter()
                        .map(|value| value as &(dyn ToSql + Sync))
                        .collect::<Vec<_>>();
                    total_count = Some(
                        transaction
                            .transaction()
                            .query_one(&count_sql, &refs)
                            .await
                            .map_err(|_| ReadServiceError::Unavailable)?
                            .get::<_, i64>(0),
                    );
                }
                let mut params = values
                    .into_iter()
                    .map(|value| Box::new(value) as Box<dyn ToSql + Sync + Send>)
                    .collect::<Vec<_>>();
                params.push(Box::new(limit));
                let refs = params
                    .iter()
                    .map(|value| &**value as &(dyn ToSql + Sync))
                    .collect::<Vec<_>>();
                #[cfg(feature = "postgres-test")]
                if let Some(probe) = &self.query_plan {
                    let explained: Value = transaction
                        .transaction()
                        .query_one(&format!("EXPLAIN (FORMAT JSON, COSTS OFF) {sql}"), &refs)
                        .await
                        .map_err(|_| ReadServiceError::Unavailable)?
                        .get(0);
                    let mut nodes = probe.lock().map_err(|_| ReadServiceError::Unavailable)?;
                    if let Some(plan) = explained.get(0).and_then(|entry| entry.get("Plan")) {
                        summarize_query_plan_for_test(plan, &mut nodes);
                    }
                }
                transaction
                    .transaction()
                    .query(&sql, &refs)
                    .await
                    .map_err(|_| ReadServiceError::Unavailable)?
            }
            Operation::Lookup => {
                let values = match &request.kind {
                    RecordReadKind::Lookup { selector } => &selector.values,
                    _ => return Err(ReadServiceError::Unavailable),
                };
                let (sql, values) = lookup_sql(&plan.entity, &relations, values, &projection)?;
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
        let page_size = query.map_or(request.maximum_records, |query| {
            usize::from(query.page_size)
        });
        let has_more = plan.operation == Operation::List && rows.len() > page_size;
        let rows = if has_more {
            &rows[..page_size]
        } else {
            rows.as_slice()
        };
        let next_cursor = if has_more {
            let query = query.ok_or(ReadServiceError::Unavailable)?;
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
        let mut rows = rows;
        request_read::annotate_records(
            transaction.transaction(),
            &self.registry,
            &self.audit_profile,
            &self.expected,
            request,
            claims,
            &plan.entity,
            &mut rows,
        )
        .await?;
        if rows.is_empty()
            && plan.operation == Operation::Get
            && plan.entity.change_request.is_some()
        {
            // Source views intentionally exclude tombstones. Before consulting
            // retained request provenance, reauthorize this exact erased row
            // through the generated typed-table GET policy and its row bounds.
            let record_id = target_record(&request.kind).ok_or(ReadServiceError::Unavailable)?;
            let sql = format!(
                "SELECT record_revision FROM registry_data.{}
                 WHERE record_id = $1::text::uuid
                   AND record_lifecycle = 'tombstoned'",
                quote_identifier(&plan.entity.physical_table),
            );
            if let Some(row) = transaction
                .transaction()
                .query_opt(&sql, &[&record_id])
                .await
                .map_err(|_| ReadServiceError::Unavailable)?
            {
                let revision: i64 = row.try_get(0).map_err(|_| ReadServiceError::Unavailable)?;
                if revision <= 0 {
                    return Err(ReadServiceError::Unavailable);
                }
                if let Some(record) = request_read::erased_terminal_request_record(
                    transaction.transaction(),
                    &self.registry,
                    &self.expected,
                    request,
                    claims,
                    &plan.entity,
                    record_id,
                    revision,
                )
                .await?
                {
                    rows.push(record);
                }
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(MaterializedRead {
            rows,
            next_cursor,
            total_count,
        })
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
        let sort_value = if query.order.is_some() {
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
                    "breg-principal-v1",
                    &self.expected.package_revision,
                    principal,
                )
            })
            .transpose()
            .map_err(|_| ReadServiceError::Unavailable)?;
        let record_reference = target_record(&request.kind)
            .map(|record_id| {
                key_hasher.audit_reference_hash(
                    "breg-record-v1",
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
            entity_id: Some(plan.entity.id.clone()),
            action_id: None,
            package_revision: self.expected.package_revision.clone(),
            selected_access_profile: claims.access_profile().to_owned(),
            purpose_present: claims.purpose().is_some(),
            principal_reference,
            record_reference,
            record_revision,
            result_count: (outcome != TerminalAuditOutcome::Unresolved).then_some(result_count),
            field_set_reference: Some(field_set_reference),
            correlation: request.correlation.clone(),
        })
    }
}

#[cfg(feature = "postgres-test")]
fn summarize_query_plan_for_test(plan: &Value, nodes: &mut Vec<Value>) {
    let spatial_index_condition = plan
        .get("Index Cond")
        .and_then(Value::as_str)
        .is_some_and(|condition| condition.contains("breg_spgeom_") && condition.contains("&&"));
    nodes.push(json!({
        "nodeType": plan.get("Node Type"),
        "indexName": plan.get("Index Name"),
        "spatialIndexCondition": spatial_index_condition,
    }));
    if let Some(children) = plan.get("Plans").and_then(Value::as_array) {
        for child in children {
            summarize_query_plan_for_test(child, nodes);
        }
    }
}

impl RecordReadService for PostgresRecordReadService {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async move {
            let result = self.execute(request).await?;
            Ok(result.response)
        })
    }

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async move {
            self.execute(request)
                .await?
                .response
                .ok_or(ReadServiceError::Unavailable)
        })
    }

    fn lookup(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async move {
            let result = self.execute(request).await?;
            Ok(result.response)
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
                    action_id: None,
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

struct ReadResult {
    response: Option<HeldReadResponse>,
    result_count: usize,
    record_revision: Option<i64>,
}

impl ReadResult {
    fn enforce_spatial_response_budget(
        self,
        request: &RecordReadRequest,
    ) -> Result<Self, ReadServiceError> {
        let bounded = request.representation == CursorRepresentation::GeoJson
            || request_query(&request.kind).is_some_and(|query| query.spatial.is_some());
        if bounded
            && self
                .response
                .as_ref()
                .is_some_and(|response| response.body().len() > MAX_SPATIAL_RESPONSE_BYTES)
        {
            return Err(ReadServiceError::Unavailable);
        }
        Ok(self)
    }

    fn empty_get() -> Self {
        Self {
            response: None,
            result_count: 0,
            record_revision: None,
        }
    }

    fn from_materialized(
        registry: &CompiledRegistry,
        request: &RecordReadRequest,
        plan: &ReadPlan,
        materialized: MaterializedRead,
    ) -> Result<Self, ReadServiceError> {
        match (plan.operation, request.representation) {
            (Operation::Get, CursorRepresentation::Json) => {
                let Some(record) = materialized.rows.into_iter().next() else {
                    return Ok(Self::empty_get());
                };
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let member = record.into_record_member()?;
                let body = record_profile::single_response(
                    registry.registry_id(),
                    &plan.entity,
                    member,
                    RecordRepresentation::Json,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            (Operation::Get, CursorRepresentation::JsonLd) => {
                let Some(record) = materialized.rows.into_iter().next() else {
                    return Ok(Self::empty_get());
                };
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let member = record.into_record_member()?;
                let body = record_profile::single_response(
                    registry.registry_id(),
                    &plan.entity,
                    member,
                    RecordRepresentation::JsonLd,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json_ld(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            (Operation::Get, CursorRepresentation::GeoJson) => {
                let Some(record) = materialized.rows.into_iter().next() else {
                    return Ok(Self::empty_get());
                };
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let response =
                    HeldReadResponse::from_geojson(&feature_value(&plan.entity, record)?)?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            (Operation::List, CursorRepresentation::Json) => {
                let result_count = materialized.rows.len();
                let items = materialized
                    .rows
                    .into_iter()
                    .map(RecordEnvelope::into_record_member)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut extensions = Map::new();
                if let Some(count) = materialized.total_count {
                    extensions.insert("count".to_owned(), json!(count));
                }
                let body = record_profile::collection_response(
                    registry.registry_id(),
                    &plan.entity,
                    items,
                    materialized.next_cursor,
                    extensions,
                    RecordRepresentation::Json,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count,
                    record_revision: None,
                })
            }
            (Operation::List, CursorRepresentation::JsonLd) => {
                let result_count = materialized.rows.len();
                let items = materialized
                    .rows
                    .into_iter()
                    .map(RecordEnvelope::into_record_member)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut extensions = Map::new();
                if let Some(count) = materialized.total_count {
                    extensions.insert("count".to_owned(), json!(count));
                }
                let body = record_profile::collection_response(
                    registry.registry_id(),
                    &plan.entity,
                    items,
                    materialized.next_cursor,
                    extensions,
                    RecordRepresentation::JsonLd,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json_ld(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count,
                    record_revision: None,
                })
            }
            (Operation::List, CursorRepresentation::GeoJson) => {
                let result_count = materialized.rows.len();
                let next_cursor = materialized.next_cursor;
                let mut registry = json!({
                    "pageInfo": {"nextCursor": next_cursor},
                });
                if let Some(count) = materialized.total_count {
                    registry["count"] = json!(count);
                }
                let links = geojson_links(request, next_cursor.as_deref())?;
                let features = materialized
                    .rows
                    .into_iter()
                    .map(|record| feature_value(&plan.entity, record))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut body = json!({
                    "type": "FeatureCollection",
                    "features": features,
                    "numberReturned": result_count,
                    "registry": registry,
                });
                if let Some(links) = links {
                    body["links"] = links;
                }
                let response = HeldReadResponse::from_geojson(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count,
                    record_revision: None,
                })
            }
            (Operation::Lookup, CursorRepresentation::Json) => {
                let mut rows = materialized.rows.into_iter();
                let Some(record) = rows.next() else {
                    return Ok(Self::empty_get());
                };
                if rows.next().is_some() {
                    return Ok(Self::empty_get());
                }
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let member = record.into_record_member()?;
                let body = record_profile::single_response(
                    registry.registry_id(),
                    &plan.entity,
                    member,
                    RecordRepresentation::Json,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            (Operation::Lookup, CursorRepresentation::JsonLd) => {
                let mut rows = materialized.rows.into_iter();
                let Some(record) = rows.next() else {
                    return Ok(Self::empty_get());
                };
                if rows.next().is_some() {
                    return Ok(Self::empty_get());
                }
                let revision =
                    i64::try_from(record.revision).map_err(|_| ReadServiceError::Unavailable)?;
                let member = record.into_record_member()?;
                let body = record_profile::single_response(
                    registry.registry_id(),
                    &plan.entity,
                    member,
                    RecordRepresentation::JsonLd,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                let response = HeldReadResponse::from_json_ld(&body)?;
                Ok(Self {
                    response: Some(response),
                    result_count: 1,
                    record_revision: Some(revision),
                })
            }
            _ => Err(ReadServiceError::Unavailable),
        }
    }
}

struct MaterializedRead {
    rows: Vec<RecordEnvelope>,
    next_cursor: Option<String>,
    total_count: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RecordEnvelope {
    pub(super) id: String,
    pub(super) revision: u64,
    pub(super) data: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request_presence: Option<Value>,
}

impl RecordEnvelope {
    fn into_record_member(self) -> Result<Value, ReadServiceError> {
        let mut extensions = Map::new();
        if let Some(request) = self.request {
            extensions.insert("request".to_owned(), request);
        }
        if let Some(request_presence) = self.request_presence {
            extensions.insert("requestPresence".to_owned(), request_presence);
        }
        record_profile::record_member(self.id, self.revision.to_string(), self.data, extensions)
            .map_err(|_| ReadServiceError::Unavailable)
    }
}

fn feature_value(
    entity: &CompiledEntity,
    record: RecordEnvelope,
) -> Result<Value, ReadServiceError> {
    let geometry_field = entity
        .geojson
        .as_ref()
        .ok_or(ReadServiceError::Unavailable)?
        .geometry_field
        .clone();
    let geometry_api_name =
        compiled_api_name(entity, &geometry_field).ok_or(ReadServiceError::Unavailable)?;
    let mut properties = record.data;
    let geometry = match properties.remove(geometry_api_name) {
        Some(Value::Null) | None => Value::Null,
        Some(value) => {
            let field = entity
                .fields
                .get(&geometry_field)
                .ok_or(ReadServiceError::Unavailable)?;
            let FieldTypeSource::Crs84Point { precision, bbox } = &field.field_type else {
                return Err(ReadServiceError::Unavailable);
            };
            if !crate::contract::valid_crs84_point(&value, *precision, bbox.as_ref()) {
                return Err(ReadServiceError::Unavailable);
            }
            value
        }
    };
    Ok(json!({
        "type": "Feature",
        "id": record.id,
        "geometry": geometry,
        "properties": properties,
        "registry": {"revision": record.revision},
    }))
}

fn geojson_links(
    request: &RecordReadRequest,
    next_cursor: Option<&str>,
) -> Result<Option<Value>, ReadServiceError> {
    let Some(next_cursor) = next_cursor else {
        return Ok(None);
    };
    let Some(prefix) = request.geojson_next_link_prefix.as_deref() else {
        return Ok(None);
    };
    if request.adapter != CursorAdapter::Gis
        || prefix.is_empty()
        || prefix.len() > 2048
        || prefix.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(Some(json!([{
        "rel": "next",
        "type": "application/geo+json",
        "href": format!("{prefix}{next_cursor}"),
    }])))
}

fn request_operation(kind: &RecordReadKind) -> Operation {
    match kind {
        RecordReadKind::Get { .. } => Operation::Get,
        RecordReadKind::List { .. } | RecordReadKind::Relationship { .. } => Operation::List,
        RecordReadKind::Lookup { .. } => Operation::Lookup,
    }
}

fn request_query(kind: &RecordReadKind) -> Option<&crate::api::CompiledReadQuery> {
    match kind {
        RecordReadKind::List { plan } | RecordReadKind::Relationship { plan, .. } => Some(plan),
        RecordReadKind::Get { .. } | RecordReadKind::Lookup { .. } => None,
    }
}

fn target_record(kind: &RecordReadKind) -> Option<&str> {
    match kind {
        RecordReadKind::Get { id } | RecordReadKind::Relationship { root_id: id, .. } => {
            Some(id.as_str())
        }
        RecordReadKind::List { .. } | RecordReadKind::Lookup { .. } => None,
    }
}

struct ReadPlan {
    operation: Operation,
    source_entity: CompiledEntity,
    entity: CompiledEntity,
    query_operation: Option<CompiledQueryOperation>,
    read_path: Option<CompiledReadPath>,
    through_entity: Option<CompiledEntity>,
}

fn validate_lookup_values(
    entity: &CompiledEntity,
    selector: &crate::model::CompiledSelectorProfile,
    values: &[LookupSelectorValue],
) -> Result<(), ()> {
    if selector.fields.len() != values.len() {
        return Err(());
    }
    for (expected_field, value) in selector.fields.iter().zip(values) {
        if expected_field != &value.field_id
            || compiled_field_type(entity, &value.field_id) != Some(&value.field_type)
            || validate_field_value(&value.value, &value.field_type).is_err()
        {
            return Err(());
        }
    }
    Ok(())
}

impl ReadPlan {
    fn from_request(
        registry: &CompiledRegistry,
        expected: &ExpectedRegistryIdentity,
        cursors: &CursorCodec,
        request: &RecordReadRequest,
    ) -> Result<Self, ()> {
        let operation = request_operation(&request.kind);
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == request.operation_id)
            .ok_or(())?;
        let source_entity = registry.entities().get(&request.entity_id).ok_or(())?;
        if request
            .request_history_after_proposal_version
            .is_some_and(|version| {
                version <= 0
                    || version > i64::from(u32::MAX)
                    || operation != Operation::Get
                    || source_entity.change_request.is_none()
            })
        {
            return Err(());
        }
        let profile = source_entity
            .access_profiles
            .get(request.context.selected_profile())
            .ok_or(())?;
        let mut entity = source_entity;
        let mut read_path = None;
        let mut through_entity = None;
        let query_operation = match &request.kind {
            RecordReadKind::Get { id } => {
                if operation != Operation::Get || !valid_canonical_uuid(id) {
                    return Err(());
                }
                None
            }
            RecordReadKind::List { plan } => {
                if operation != Operation::List
                    || route.query_kind != Some(plan.kind)
                    || plan.route_id != route.id
                {
                    return Err(());
                }
                let compiled_query = registry
                    .queries()
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.id == plan.query_operation_id
                            && operation.route_id == route.id
                            && operation.entity_id == source_entity.id
                            && operation.profile_id == request.context.selected_profile()
                            && operation.kind == plan.kind
                            && operation.read_path.is_none()
                            && operation.selector_fields.is_empty()
                    })
                    .ok_or(())?;
                validate_compiled_query_request(
                    registry,
                    expected,
                    cursors,
                    source_entity,
                    compiled_query,
                    request,
                    plan,
                )?;
                Some(compiled_query.clone())
            }
            RecordReadKind::Lookup { selector } => {
                if operation != Operation::Lookup || route.id != selector.route_id {
                    return Err(());
                }
                let selector_profile = source_entity
                    .selector_profiles
                    .get(&selector.selector_id)
                    .ok_or(())?;
                let grant = profile
                    .lookups
                    .iter()
                    .find(|lookup| lookup.selector == selector.selector_id)
                    .ok_or(())?;
                if grant.value_origin != selector.value_origin {
                    return Err(());
                }
                validate_lookup_values(source_entity, selector_profile, &selector.values)?;
                let compiled_query = registry
                    .queries()
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.id == selector.query_operation_id
                            && operation.route_id == route.id
                            && operation.entity_id == source_entity.id
                            && operation.profile_id == request.context.selected_profile()
                            && operation.kind == CompiledQueryKind::List
                            && operation.read_path.is_none()
                            && operation.selector_fields == selector_profile.fields
                    })
                    .ok_or(())?;
                Some(compiled_query.clone())
            }
            RecordReadKind::Relationship {
                root_id,
                path_id,
                plan,
            } => {
                if operation != Operation::List
                    || !valid_canonical_uuid(root_id)
                    || route.query_kind != Some(plan.kind)
                    || plan.route_id != route.id
                {
                    return Err(());
                }
                let path = source_entity.read_paths.get(path_id).ok_or(())?;
                if route.id != format!("records.{}.path.{}", source_entity.id, path.id) {
                    return Err(());
                }
                let through = registry.entities().get(&path.through).ok_or(())?;
                let target_entity = registry.entities().get(&path.to).ok_or(())?;
                let grant = profile
                    .read_paths
                    .iter()
                    .find(|grant| grant.path == path.id)
                    .ok_or(())?;
                if !request.selected_fields.is_subset(&grant.readable_fields) {
                    return Err(());
                }
                let compiled_query = registry
                    .queries()
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.id == plan.query_operation_id
                            && operation.route_id == route.id
                            && operation.entity_id == target_entity.id
                            && operation.profile_id == request.context.selected_profile()
                            && operation.kind == plan.kind
                            && operation.read_path.as_deref() == Some(path.id.as_str())
                            && operation.selector_fields.is_empty()
                    })
                    .ok_or(())?;
                validate_compiled_query_request(
                    registry,
                    expected,
                    cursors,
                    target_entity,
                    compiled_query,
                    request,
                    plan,
                )?;
                entity = target_entity;
                read_path = Some(path.clone());
                through_entity = Some(through.clone());
                Some(compiled_query.clone())
            }
        };
        if route.operation != operation
            || route.method != request.method
            || route.entity_id != request.entity_id
            || !route
                .access_profiles
                .iter()
                .any(|profile| profile == request.context.selected_profile())
            || (read_path.is_none() && !profile.operations.contains(&operation))
            || request.maximum_records == 0
            || request.maximum_records > MAX_SQL_LIMIT
            || operation == Operation::Get && request.maximum_records != 1
            || operation == Operation::Lookup && request.maximum_records != 2
            || operation == Operation::List
                && request_query(&request.kind)
                    .and_then(|query| usize::from(query.page_size).checked_add(1))
                    != Some(request.maximum_records)
            || !valid_read_representation_request(request)
            || !valid_entity_inventory(registry, source_entity)
            || !valid_entity_inventory(registry, entity)
            || (read_path.is_none() && !request.selected_fields.is_subset(&profile.readable_fields))
            || request
                .selected_fields
                .iter()
                .any(|field| compiled_field_type(entity, field).is_none())
        {
            return Err(());
        }
        Ok(Self {
            operation,
            source_entity: source_entity.clone(),
            entity: entity.clone(),
            query_operation,
            read_path,
            through_entity,
        })
    }
}

fn valid_read_representation_request(request: &RecordReadRequest) -> bool {
    match (
        request_operation(&request.kind),
        request.representation,
        request.adapter,
        request.adapter_origin.as_ref(),
        request.geojson_next_link_prefix.as_ref(),
    ) {
        (
            Operation::Get | Operation::List | Operation::Lookup,
            CursorRepresentation::Json | CursorRepresentation::JsonLd,
            CursorAdapter::Native,
            None,
            None,
        ) => true,
        (
            Operation::Get | Operation::List,
            CursorRepresentation::GeoJson,
            CursorAdapter::Native,
            None,
            None,
        ) => true,
        (
            Operation::Get | Operation::List,
            CursorRepresentation::GeoJson,
            CursorAdapter::Gis,
            Some(origin),
            Some(prefix),
        ) => valid_next_link_prefix(origin) && valid_next_link_prefix(prefix),
        _ => false,
    }
}

fn valid_next_link_prefix(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_entity_inventory(registry: &CompiledRegistry, entity: &CompiledEntity) -> bool {
    let Some(inventory) = registry.physical_names().entities.get(&entity.id) else {
        return false;
    };
    inventory.table == entity.physical_table
        && valid_physical_identifier(&entity.physical_table)
        && entity.fields.iter().all(|(id, field)| {
            inventory.fields.get(id) == Some(&field.physical_name)
                && valid_physical_identifier(&field.physical_name)
        })
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
        || query.cursor_binding.include_count != query.include_count
        || query.cursor_binding.temporal_instant != query.temporal_instant
        || query.cursor_binding.representation != request.representation
        || query.cursor_binding.adapter != request.adapter
        || query.adapter != request.adapter
        || query.cursor_binding.selected_fields != selected_fields
        || !valid_optional_cursor_reference(query.cursor_binding.principal_reference.as_deref())
        || !valid_optional_cursor_reference(query.cursor_binding.purpose_reference.as_deref())
        || !valid_cursor_reference(&query.cursor_binding.row_boundary_reference)
        || !valid_cursor_reference(&query.cursor_binding.projection_reference)
        || !valid_cursor_reference(&query.cursor_binding.query_reference)
        || !valid_cursor_reference(&query.cursor_binding.sort_reference)
        || !valid_cursor_reference(&query.cursor_binding.scope_reference)
        || !valid_optional_cursor_reference(query.cursor_binding.spatial_reference.as_deref())
        || !request
            .selected_fields
            .iter()
            .all(|field| operation.projection_fields.contains(field))
        || !operation
            .projection_fields
            .iter()
            .all(|field| compiled_field_type(entity, field).is_some())
    {
        return Err(());
    }
    match query.kind {
        CompiledQueryKind::Snapshot => return Err(()),
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
    validate_projection(entity, operation, &query.projection)?;
    if let Some(filter) = &query.filter {
        let mut stats = FilterStats::default();
        validate_filter_expr(entity, operation, filter, &mut stats)?;
        if stats.predicates > 32 || stats.in_values > 100 {
            return Err(());
        }
    }
    if let Some(spatial) = &query.spatial {
        validate_spatial_query(entity, operation, spatial)?;
    }
    if let Some(order) = &query.order {
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
            || query_field_type(entity, operation, &order.field_id)
                != Some(order.field_type.clone())
            || order.direction != CompiledQuerySortDirection::Asc
        {
            return Err(());
        }
    }
    if let Some(continuation) = &query.continuation {
        if !valid_canonical_uuid(&continuation.last_record_id) {
            return Err(());
        }
        match (&query.order, &continuation.sort_value) {
            (Some(order), Some(value)) => {
                if validate_field_value(value, &order.field_type).is_err() {
                    return Err(());
                }
            }
            (Some(_), None) | (None, None) => {}
            (None, Some(_)) => return Err(()),
        }
    }
    if !cursor_query_matches_request(query, request)? {
        return Err(());
    }
    let references = cursor_binding_references(cursors, request, operation, query)?;
    if query.cursor_binding.principal_reference != references.principal
        || query.cursor_binding.purpose_reference != references.purpose
        || query.cursor_binding.row_boundary_reference != references.row_boundary
        || query.cursor_binding.projection_reference != references.projection
        || query.cursor_binding.query_reference != references.query
        || query.cursor_binding.sort_reference != references.sort
        || query.cursor_binding.scope_reference != references.scope
        || query.cursor_binding.spatial_reference != references.spatial
    {
        return Err(());
    }
    Ok(())
}

fn cursor_binding_references(
    cursors: &CursorCodec,
    request: &RecordReadRequest,
    operation: &CompiledQueryOperation,
    query: &crate::api::CompiledReadQuery,
) -> Result<CursorBindingReferences, ()> {
    crate::query_binding::references(
        cursors,
        &query.route_id,
        operation,
        &request.context,
        CursorBindingQuery {
            selected_fields: &request.selected_fields,
            projection: &query.projection,
            filter: query.filter.as_ref(),
            spatial: query.spatial.as_ref(),
            order: query.order.as_ref(),
            include_count: query.include_count,
            page_size: query.page_size,
            temporal_instant: query.temporal_instant.as_deref(),
            scope: &query.cursor_query.scope,
            representation: request.representation,
            adapter: request.adapter,
            adapter_origin: request.adapter_origin.as_deref(),
        },
    )
    .map_err(|_| ())
}

fn cursor_query_matches_request(
    query: &crate::api::CompiledReadQuery,
    request: &RecordReadRequest,
) -> Result<bool, ()> {
    let expected_scope = match &request.kind {
        RecordReadKind::List { .. } => CursorQueryScope::Collection {},
        RecordReadKind::Relationship {
            root_id, path_id, ..
        } => CursorQueryScope::Relationship {
            path_id: path_id.clone(),
            root_id: root_id.clone(),
        },
        RecordReadKind::Get { .. } | RecordReadKind::Lookup { .. } => return Ok(false),
    };
    Ok(
        query.cursor_query.projection == cursor_projection_from_read(&query.projection)
            && query.cursor_query.filter == query.filter.as_ref().map(cursor_filter_expr_from_read)
            && query.cursor_query.spatial == query.spatial.as_ref().map(cursor_spatial_from_read)
            && query.cursor_query.order == query.order.as_ref().map(cursor_order_from_read)
            && query.cursor_query.include_count == query.include_count
            && query.cursor_query.page_size == query.page_size
            && query.cursor_query.temporal_instant == query.temporal_instant
            && query.cursor_query.scope == expected_scope,
    )
}

fn validate_spatial_query(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    spatial: &ReadSpatialQuery,
) -> Result<(), ()> {
    if operation.kind != CompiledQueryKind::List || operation.read_path.is_some() {
        return Err(());
    }
    let capability = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
        .ok_or(())?;
    let maximum_longitude_span = crate::query::canonical_positive_decimal_within(
        &capability.maximum_longitude_span_degrees.to_string(),
        "360",
    )
    .map_err(|_| ())?;
    let maximum_latitude_span = crate::query::canonical_positive_decimal_within(
        &capability.maximum_latitude_span_degrees.to_string(),
        "180",
    )
    .map_err(|_| ())?;
    if spatial.bbox.geometry_field != capability.geometry_field
        || spatial.bbox.maximum_longitude_span_degrees != maximum_longitude_span
        || spatial.bbox.maximum_latitude_span_degrees != maximum_latitude_span
        || !matches!(
            compiled_field_type(entity, &spatial.bbox.geometry_field),
            Some(FieldTypeSource::Crs84Point { .. })
        )
    {
        return Err(());
    }
    let parsed = crate::query::parse_read_query([(
        "bbox",
        format!(
            "{},{},{},{}",
            spatial.bbox.west, spatial.bbox.south, spatial.bbox.east, spatial.bbox.north
        ),
    )])
    .map_err(|_| ())?;
    let crate::query::ParsedReadQueryMode::Query(options) = parsed.mode else {
        return Err(());
    };
    let bbox = options.bbox.ok_or(())?;
    if !crate::query::decimal_difference_within(bbox.east(), bbox.west(), &maximum_longitude_span)
        .map_err(|_| ())?
        || !crate::query::decimal_difference_within(
            bbox.north(),
            bbox.south(),
            &maximum_latitude_span,
        )
        .map_err(|_| ())?
    {
        return Err(());
    }
    Ok(())
}

fn cursor_spatial_from_read(spatial: &ReadSpatialQuery) -> CursorSpatialQuery {
    CursorSpatialQuery {
        bbox: CursorBboxQuery {
            geometry_field: spatial.bbox.geometry_field.clone(),
            west: spatial.bbox.west.clone(),
            south: spatial.bbox.south.clone(),
            east: spatial.bbox.east.clone(),
            north: spatial.bbox.north.clone(),
            maximum_longitude_span_degrees: spatial.bbox.maximum_longitude_span_degrees.clone(),
            maximum_latitude_span_degrees: spatial.bbox.maximum_latitude_span_degrees.clone(),
        },
    }
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

async fn install_evaluation_date(
    transaction: &tokio_postgres::Transaction<'_>,
    query: Option<&crate::api::CompiledReadQuery>,
) -> Result<(), ReadServiceError> {
    let instant = query
        .and_then(|query| query.temporal_instant.as_deref())
        .map(parse_rfc3339_utc)
        .transpose()?
        .unwrap_or_else(time::OffsetDateTime::now_utc);
    let evaluation_date = instant.date().to_string();
    transaction
        .execute(
            "SELECT set_config('registry.evaluation_date', $1, true)",
            &[&evaluation_date],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(())
}

async fn install_spatial_query_context(
    transaction: &tokio_postgres::Transaction<'_>,
    query: Option<&crate::api::CompiledReadQuery>,
) -> Result<(), ReadServiceError> {
    let Some(spatial) = query.and_then(|query| query.spatial.as_ref()) else {
        return Ok(());
    };
    let context = SpatialBboxContext::new(
        spatial.bbox.west.clone(),
        spatial.bbox.south.clone(),
        spatial.bbox.east.clone(),
        spatial.bbox.north.clone(),
    )
    .map_err(|_| ReadServiceError::Unavailable)?;
    install_spatial_bbox_context(transaction, &context)
        .await
        .map_err(|_| ReadServiceError::Unavailable)
}

async fn install_read_path_context(
    transaction: &tokio_postgres::Transaction<'_>,
    path_id: &str,
    root_id: &str,
) -> Result<(), ReadServiceError> {
    if path_id.is_empty() || path_id.len() > 256 || !valid_canonical_uuid(root_id) {
        return Err(ReadServiceError::Unavailable);
    }
    transaction
        .execute(
            "SELECT set_config('registry.read_path_id', $1, true),
                    set_config('registry.read_path_root_id', $2, true)",
            &[&path_id, &root_id],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(())
}

fn parse_rfc3339_utc(value: &str) -> Result<time::OffsetDateTime, ReadServiceError> {
    let parsed = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(parsed)
}

struct ReadRelations {
    base_alias: &'static str,
    source_alias: &'static str,
    id_expression: String,
    from_sql: String,
    base_predicates: Vec<String>,
    derived_aliases: BTreeMap<String, String>,
}

impl ReadRelations {
    fn collection(
        entity: &CompiledEntity,
        query: Option<&crate::api::CompiledReadQuery>,
        _selected_fields: &[String],
    ) -> Result<Self, ReadServiceError> {
        let spatial_query = query.is_some_and(|query| query.spatial.is_some());
        let base_alias = "base_record";
        let source_alias = "source_record";
        if !valid_physical_identifier(&entity.physical_table)
            || !valid_physical_identifier(&entity.source_relation.sql_name)
        {
            return Err(ReadServiceError::Unavailable);
        }
        let mut derived_aliases = BTreeMap::new();
        let id_expression = format!(
            "{source_alias}.{}",
            quote_identifier(&entity.canonical_id.sql_name)
        );
        let mut from_sql = format!(
            "registry_source.{} AS {source_alias}
             JOIN registry_data.{} AS {base_alias}
               ON {base_alias}.record_id = {source_alias}.id",
            quote_identifier(&entity.source_relation.sql_name),
            quote_identifier(&entity.physical_table),
        );
        if entity.change_request.is_some() {
            from_sql.push_str(
                " LEFT JOIN registry_internal.registry_request_state AS request_state
                    ON request_state.request_entity_id = ",
            );
            from_sql.push_str(&sql_quote_literal(&entity.id));
            from_sql.push_str(
                "
                   AND request_state.request_id = source_record.id
                  LEFT JOIN registry_internal.registry_request_proposals AS request_proposal
                    ON request_proposal.request_entity_id = request_state.request_entity_id
                   AND request_proposal.request_id = request_state.request_id
                   AND request_proposal.proposal_version = request_state.proposal_version",
            );
        }
        if spatial_query {
            let candidate_view = crate::physical_names::spatial_candidate_view_name(&entity.id);
            if !valid_physical_identifier(&candidate_view) {
                return Err(ReadServiceError::Unavailable);
            }
            from_sql.push_str(&format!(
                " JOIN registry_context.{} AS candidate_record
                    ON candidate_record.id = {id_expression}",
                quote_identifier(&candidate_view),
            ));
        }
        for (index, relation) in entity.derived_relations.values().enumerate() {
            let alias = format!("derived_{index}");
            let view_name = crate::generated_ddl::derived_view_name(
                &entity.source_relation.sql_name,
                &relation.id,
            );
            if !valid_physical_identifier(&view_name) {
                return Err(ReadServiceError::Unavailable);
            }
            from_sql.push_str(&format!(
                " LEFT JOIN registry_derived.{} AS {alias}
                    ON {alias}.{} = {id_expression}",
                quote_identifier(&view_name),
                quote_identifier(&entity.canonical_id.sql_name),
            ));
            derived_aliases.insert(relation.id.clone(), alias);
        }
        Ok(Self {
            base_alias,
            source_alias,
            id_expression,
            from_sql,
            base_predicates: Vec::new(),
            derived_aliases,
        })
    }

    fn relationship(
        source: &CompiledEntity,
        through: &CompiledEntity,
        target: &CompiledEntity,
        path: &CompiledReadPath,
        root_id: &str,
    ) -> Result<Self, ReadServiceError> {
        if !valid_canonical_uuid(root_id) {
            return Err(ReadServiceError::Unavailable);
        }
        for entity in [source, through, target] {
            if !valid_physical_identifier(&entity.physical_table)
                || !valid_physical_identifier(&entity.source_relation.sql_name)
            {
                return Err(ReadServiceError::Unavailable);
            }
        }
        let base_alias = "base_record";
        let source_alias = "target_source_record";
        let path_source_alias = "path_source_record";
        let path_through_alias = "path_through_record";
        let source_id = format!(
            "{path_source_alias}.{}",
            quote_identifier(&source.canonical_id.sql_name)
        );
        let target_id = format!(
            "{source_alias}.{}",
            quote_identifier(&target.canonical_id.sql_name)
        );
        let through_source_ref =
            source_view_field_expression(through, path_through_alias, &path.source_ref)?;
        let through_target_ref =
            source_view_field_expression(through, path_through_alias, &path.target_ref)?;
        let mut from_sql = format!(
            "registry_source.{} AS {path_source_alias}
             JOIN registry_source.{} AS {path_through_alias}
               ON {through_source_ref} = {source_id}
             JOIN registry_source.{} AS {source_alias}
               ON {target_id} = {through_target_ref}
             JOIN registry_data.{} AS {base_alias}
               ON {base_alias}.record_id = {target_id}",
            quote_identifier(&source.source_relation.sql_name),
            quote_identifier(&through.source_relation.sql_name),
            quote_identifier(&target.source_relation.sql_name),
            quote_identifier(&target.physical_table),
        );
        let mut derived_aliases = BTreeMap::new();
        for (index, relation) in target.derived_relations.values().enumerate() {
            let alias = format!("derived_{index}");
            let view_name = crate::generated_ddl::derived_view_name(
                &target.source_relation.sql_name,
                &relation.id,
            );
            if !valid_physical_identifier(&view_name) {
                return Err(ReadServiceError::Unavailable);
            }
            from_sql.push_str(&format!(
                " LEFT JOIN registry_derived.{} AS {alias}
                    ON {alias}.{} = {target_id}",
                quote_identifier(&view_name),
                quote_identifier(&target.canonical_id.sql_name),
            ));
            derived_aliases.insert(relation.id.clone(), alias);
        }
        Ok(Self {
            base_alias,
            source_alias,
            id_expression: target_id,
            from_sql,
            base_predicates: vec![
                format!("{source_id} = NULLIF(current_setting('registry.read_path_root_id', true), '')::uuid"),
                format!(
                    "NULLIF(current_setting('registry.read_path_id', true), '') = {}",
                    sql_quote_literal(&path.id)
                ),
            ],
            derived_aliases,
        })
    }

    fn field_expression(
        &self,
        entity: &CompiledEntity,
        field_id: &str,
    ) -> Result<FieldExpression, ReadServiceError> {
        if entity.change_request.is_some() {
            if let Some(field_type) = request_query_field_type(field_id) {
                let sql = match field_id {
                    REQUEST_BREG_STATE_QUERY_FIELD => "request_state.state",
                    REQUEST_PROPOSAL_VERSION_QUERY_FIELD => "request_state.proposal_version",
                    REQUEST_EFFECT_DIGEST_QUERY_FIELD => "request_proposal.effect_digest",
                    _ => return Err(ReadServiceError::Unavailable),
                };
                return Ok(FieldExpression {
                    sql: sql.to_owned(),
                    field_type,
                });
            }
        }
        if field_id == "id" {
            return Ok(FieldExpression {
                sql: self.id_expression.clone(),
                field_type: entity.canonical_id.field_type.clone(),
            });
        }
        if let Some(field) = entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == field_id)
        {
            if !valid_physical_identifier(&field.logical.sql_name) {
                return Err(ReadServiceError::Unavailable);
            }
            return Ok(FieldExpression {
                sql: format!(
                    "{}.{}",
                    self.source_alias,
                    quote_identifier(&field.logical.sql_name)
                ),
                field_type: field.logical.field_type.clone(),
            });
        }
        if let Some(field) = entity.derived_fields.get(field_id) {
            let alias = self
                .derived_aliases
                .get(&field.derivation_id)
                .ok_or(ReadServiceError::Unavailable)?;
            return Ok(FieldExpression {
                sql: format!("{alias}.{}", quote_identifier(&field.logical.sql_name)),
                field_type: field.logical.field_type.clone(),
            });
        }
        Err(ReadServiceError::Unavailable)
    }
}

fn source_view_field_expression(
    entity: &CompiledEntity,
    alias: &str,
    field_id: &str,
) -> Result<String, ReadServiceError> {
    let field = entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .ok_or(ReadServiceError::Unavailable)?;
    if !valid_physical_identifier(&field.logical.sql_name) {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(format!(
        "{alias}.{}",
        quote_identifier(&field.logical.sql_name)
    ))
}

struct FieldExpression {
    sql: String,
    field_type: FieldTypeSource,
}

fn compiled_field_type<'a>(
    entity: &'a CompiledEntity,
    field_id: &str,
) -> Option<&'a FieldTypeSource> {
    if field_id == "id" {
        return Some(&entity.canonical_id.field_type);
    }
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| &field.logical.field_type)
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| &field.logical.field_type)
        })
}

fn query_field_type(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    field_id: &str,
) -> Option<FieldTypeSource> {
    if operation
        .projection_fields
        .iter()
        .any(|field| field == field_id)
        || operation
            .filter_fields
            .iter()
            .any(|field| field.field == field_id)
        || operation
            .sort_fields
            .iter()
            .any(|field| field.field == field_id)
    {
        compiled_field_type(entity, field_id).cloned().or_else(|| {
            entity
                .change_request
                .as_ref()
                .and_then(|_| request_query_field_type(field_id))
        })
    } else {
        None
    }
}

pub(super) fn compiled_api_name<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<&'a str> {
    if entity.change_request.is_some() {
        if let Some(api_name) = request_query_field_api_name(field_id) {
            return Some(api_name);
        }
    }
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| field.logical.api_name.as_str())
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .filter(|field| field.logical.id == field_id)
                .map(|field| field.logical.api_name.as_str())
        })
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
            || compiled_field_type(entity, &field.field_id) != Some(&field.field_type)
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
    let Some(field_type) = query_field_type(entity, operation, &predicate.field_id) else {
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
        || field_type != predicate.field_type
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
                || validate_field_value(&predicate.values[0], &field_type).is_err()
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
                    .any(|value| validate_field_value(value, &field_type).is_err())
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

fn projection(
    entity: &CompiledEntity,
    relations: &ReadRelations,
    selected_fields: &[String],
    query: Option<&crate::api::CompiledReadQuery>,
) -> Result<String, ReadServiceError> {
    let mut expressions = vec![
        format!("{}::text", relations.id_expression),
        format!("{}.record_revision", relations.base_alias),
    ];
    for field in selected_fields {
        let expression = relations.field_expression(entity, field)?;
        expressions.push(json_expression(&expression.sql, &expression.field_type));
    }
    if let Some(order) = query.and_then(|query| query.order.as_ref()) {
        let expression = relations.field_expression(entity, &order.field_id)?;
        expressions.push(json_expression(&expression.sql, &expression.field_type));
    }
    Ok(expressions.join(", "))
}

/// The page statement and the `$count` statement of one list query.
///
/// The count answers the whole authorized result at this query's predicates, so
/// it stays the same on every page. Only the page statement carries the
/// continuation boundary, and `count_parameters` names the leading values the
/// count statement binds.
struct ListStatements {
    page_sql: String,
    count_sql: String,
    count_parameters: usize,
    values: Vec<String>,
}

fn list_sql(
    entity: &CompiledEntity,
    relations: &ReadRelations,
    query: &crate::api::CompiledReadQuery,
    projection: &str,
) -> Result<ListStatements, ReadServiceError> {
    let mut values = Vec::new();
    let mut predicates = relations.base_predicates.clone();
    if let Some(filter) = &query.filter {
        predicates.push(filter_sql(entity, relations, filter, &mut values)?);
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
        let start = relations
            .field_expression(entity, &temporal.start_field)?
            .sql;
        let end = relations.field_expression(entity, &temporal.end_field)?.sql;
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
    let count_where_sql = where_clause(&predicates);
    let count_parameters = values.len();
    if let Some(continuation) = &query.continuation {
        if !valid_canonical_uuid(&continuation.last_record_id) {
            return Err(ReadServiceError::CursorInvalid);
        }
        let record_parameter = push_value(&mut values, &continuation.last_record_id);
        if let Some(order) = &query.order {
            let field = relations.field_expression(entity, &order.field_id)?;
            let cast = postgres_cast(&field.field_type);
            match &continuation.sort_value {
                Some(value) => {
                    validate_field_value(value, &field.field_type)
                        .map_err(|_| ReadServiceError::CursorInvalid)?;
                    let sort_parameter = push_value(&mut values, value);
                    predicates.push(format!(
                        "({column} > ${sort_parameter}::text::{cast} OR {column} IS NULL OR ({column} = ${sort_parameter}::text::{cast} AND {id} > ${record_parameter}::text::uuid))",
                        column = field.sql,
                        id = relations.id_expression
                    ));
                }
                None => predicates.push(format!(
                    "({column} IS NULL AND {id} > ${record_parameter}::text::uuid)",
                    column = field.sql,
                    id = relations.id_expression
                )),
            }
        } else {
            predicates.push(format!(
                "{} > ${record_parameter}::text::uuid",
                relations.id_expression
            ));
        }
    }
    let where_sql = where_clause(&predicates);
    let order = if let Some(order) = &query.order {
        let field = relations.field_expression(entity, &order.field_id)?;
        format!(
            "{} ASC NULLS LAST, {} ASC",
            field.sql, relations.id_expression
        )
    } else {
        format!("{} ASC", relations.id_expression)
    };
    let limit_parameter = values.len() + 1;
    Ok(ListStatements {
        page_sql: format!(
            "SELECT {projection}
             FROM {}
             WHERE {where_sql}
             ORDER BY {order}
             LIMIT ${limit_parameter}::bigint",
            relations.from_sql
        ),
        count_sql: format!(
            "SELECT count(*)::bigint
             FROM {}
             WHERE {count_where_sql}",
            relations.from_sql
        ),
        count_parameters,
        values,
    })
}

fn where_clause(predicates: &[String]) -> String {
    if predicates.is_empty() {
        "TRUE".to_owned()
    } else {
        predicates.join(" AND ")
    }
}

fn lookup_sql(
    entity: &CompiledEntity,
    relations: &ReadRelations,
    selector_values: &[LookupSelectorValue],
    projection: &str,
) -> Result<(String, Vec<String>), ReadServiceError> {
    if selector_values.is_empty() {
        return Err(ReadServiceError::Unavailable);
    }
    let mut values = Vec::new();
    let mut predicates = relations.base_predicates.clone();
    for selector in selector_values {
        let field = relations.field_expression(entity, &selector.field_id)?;
        if field.field_type != selector.field_type {
            return Err(ReadServiceError::Unavailable);
        }
        validate_field_value(&selector.value, &field.field_type)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let parameter = push_value(&mut values, &selector.value);
        predicates.push(format!(
            "{} = ${parameter}::text::{}",
            field.sql,
            postgres_cast(&field.field_type)
        ));
    }
    let where_sql = predicates.join(" AND ");
    let limit_parameter = values.len() + 1;
    Ok((
        format!(
            "SELECT {projection}
             FROM {}
             WHERE {where_sql}
             ORDER BY {}
             LIMIT ${limit_parameter}::bigint",
            relations.from_sql, relations.id_expression,
        ),
        values,
    ))
}

fn json_expression(expression: &str, field_type: &FieldTypeSource) -> String {
    if matches!(field_type, FieldTypeSource::Decimal { .. }) {
        format!("to_jsonb({expression}::text)")
    } else {
        format!("to_jsonb({expression})")
    }
}

fn filter_sql(
    entity: &CompiledEntity,
    relations: &ReadRelations,
    filter: &ReadFilterExpr,
    values: &mut Vec<String>,
) -> Result<String, ReadServiceError> {
    match filter {
        ReadFilterExpr::Binary { op, left, right } => {
            let operator = match op {
                ReadLogicalOp::And => "AND",
                ReadLogicalOp::Or => "OR",
            };
            Ok(format!(
                "({} {operator} {})",
                filter_sql(entity, relations, left, values)?,
                filter_sql(entity, relations, right, values)?
            ))
        }
        ReadFilterExpr::Not(expr) => Ok(format!(
            "(NOT {})",
            filter_sql(entity, relations, expr, values)?
        )),
        ReadFilterExpr::Group(expr) => Ok(format!(
            "({})",
            filter_sql(entity, relations, expr, values)?
        )),
        ReadFilterExpr::Predicate(predicate) => predicate_sql(entity, relations, predicate, values),
    }
}

fn predicate_sql(
    entity: &CompiledEntity,
    relations: &ReadRelations,
    predicate: &ReadFilterPredicate,
    values: &mut Vec<String>,
) -> Result<String, ReadServiceError> {
    let field = relations.field_expression(entity, &predicate.field_id)?;
    if field.field_type != predicate.field_type {
        return Err(ReadServiceError::Unavailable);
    }
    let cast = postgres_cast(&field.field_type);
    match predicate.operator {
        ReadFilterOperator::Eq => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} = ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::Ne => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} <> ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::Lt => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} < ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::Le => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} <= ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::Gt => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} > ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::Ge => {
            let parameter = push_value(values, &predicate.values[0]);
            Ok(format!("{} >= ${parameter}::text::{cast}", field.sql))
        }
        ReadFilterOperator::In => {
            if predicate.values.is_empty() {
                return Err(ReadServiceError::Unavailable);
            }
            let placeholders = predicate
                .values
                .iter()
                .map(|value| {
                    let parameter = push_value(values, value);
                    format!("${parameter}::text::{cast}")
                })
                .collect::<Vec<_>>();
            Ok(format!("{} IN ({})", field.sql, placeholders.join(", ")))
        }
        ReadFilterOperator::IsNull => Ok(format!("{} IS NULL", field.sql)),
        ReadFilterOperator::IsNotNull => Ok(format!("{} IS NOT NULL", field.sql)),
        ReadFilterOperator::StartsWith => {
            let parameter = push_value(values, &format!("{}%", escape_like(&predicate.values[0])));
            Ok(format!("{} LIKE ${parameter}::text ESCAPE '\\'", field.sql))
        }
        ReadFilterOperator::Contains => {
            let parameter = push_value(values, &format!("%{}%", escape_like(&predicate.values[0])));
            Ok(format!("{} LIKE ${parameter}::text ESCAPE '\\'", field.sql))
        }
    }
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
    for (index, field_id) in selected_fields.iter().enumerate() {
        let api_name = compiled_api_name(entity, field_id).ok_or(ReadServiceError::Unavailable)?;
        if compiled_field_type(entity, field_id).is_none() {
            return Err(ReadServiceError::Unavailable);
        }
        let value = row
            .try_get::<_, Option<Value>>(index + 2)
            .map_err(|_| ReadServiceError::Unavailable)?
            .unwrap_or(Value::Null);
        if data.insert(api_name.to_owned(), value).is_some() {
            return Err(ReadServiceError::Unavailable);
        }
    }
    Ok(RecordEnvelope {
        id,
        revision,
        data,
        request: None,
        request_presence: None,
    })
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
        .audit_reference_hash("breg-read-field-set-v1", package_revision, canonical)
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

fn sql_quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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

    use serde_json::{json, Map};

    use crate::api::{
        AuthorizedRequestContext, CompiledReadQuery, ReadBboxQuery, ReadFilterExpr,
        ReadFilterOperator, ReadFilterPredicate, ReadOrderClause, ReadProjectionField,
        ReadSpatialQuery, RecordReadKind, RecordReadRequest,
    };
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{parse_project_json, FieldTypeSource};
    use crate::cursor::{
        CursorAdapter, CursorBboxQuery, CursorBinding, CursorCodec, CursorContinuation,
        CursorFilterExpr, CursorFilterOperator, CursorFilterPredicate, CursorOrderClause,
        CursorProjectionField, CursorQuery, CursorQueryScope, CursorRepresentation,
        CursorSpatialQuery,
    };
    use crate::model::{CompiledQueryKind, CompiledQuerySortDirection, HttpMethod};
    use zeroize::Zeroizing;

    use super::{
        cursor_binding_references, feature_value, list_sql, projection, quote_identifier,
        temporal_instant_expression, ExpectedRegistryIdentity, ReadPlan, ReadRelations,
        ReadServiceError, RecordEnvelope,
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
    fn invalid_stored_point_geojson_fails_before_response_materialization() {
        let registry = compile_project(
            &parse_project_json(
                br#"{
                  "apiVersion":"registry.registrystack.org/v1alpha1",
                  "kind":"RegistryProject",
                  "registry":{"id":"geojson-guard","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
                  "entities":[{
                    "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"public",
                    "fields":[
                      {"id":"code","type":"string","required":true,"maxLength":32,"classification":"public"},
                      {"id":"location","type":"crs84-point","precision":6,"required":false,"classification":"public"}
                    ],
                    "geojson":{"geometryField":"location"}
                  }],
                  "accessProfiles":[{
                    "id":"public","default":true,"anonymous":true,
                    "grants":[{"entity":"site","operations":["get","list"],"readableFields":["code","location"]}]
                  }]
                }"#,
            )
            .expect("fixture parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("fixture compiles");
        let entity = registry
            .entities()
            .get("site")
            .expect("compiled entity exists");
        let mut data = Map::new();
        data.insert("code".to_owned(), json!("SITE-A"));
        data.insert(
            "location".to_owned(),
            json!({"type": "Point", "coordinates": [181, 0]}),
        );
        let record = RecordEnvelope {
            id: "00000000-0000-4000-8000-000000000001".to_owned(),
            revision: 1,
            data,
            request: None,
            request_presence: None,
        };
        assert!(matches!(
            feature_value(entity, record),
            Err(ReadServiceError::Unavailable)
        ));
    }

    #[test]
    fn spatial_backend_validates_span_with_exact_decimal_query_semantics() {
        let registry = compile_project(
            &parse_project_json(
                br#"{
                  "apiVersion":"registry.registrystack.org/v1alpha1",
                  "kind":"RegistryProject",
                  "registry":{"id":"spatial-span-guard","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
                  "entities":[{
                    "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"public",
                    "fields":[
                      {"id":"code","type":"string","required":true,"maxLength":32,"classification":"public"},
                      {"id":"location","type":"crs84-point","precision":6,"required":false,"classification":"public"}
                    ],
                    "geojson":{"geometryField":"location"}
                  }],
                  "accessProfiles":[{
                    "id":"public","default":true,"anonymous":true,
                    "grants":[{
                      "entity":"site",
                      "operations":["list"],
                      "readableFields":["code","location"],
                      "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.3,"maximumLatitudeSpanDegrees":0.2}}
                    }]
                  }]
                }"#,
            )
            .expect("fixture parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("fixture compiles");
        let entity = registry
            .entities()
            .get("site")
            .expect("compiled entity exists");
        let operation = registry
            .queries()
            .operations
            .iter()
            .find(|operation| operation.kind == CompiledQueryKind::List)
            .expect("list query operation exists");
        let parsed = crate::query::parse_read_query([("bbox", "1e-1,0,4e-1,2e-1")])
            .expect("bbox query parses");
        let crate::query::ParsedReadQueryMode::Query(options) = parsed.mode else {
            panic!("bbox is a first-page query option")
        };
        let bbox = options.bbox.expect("bbox option is present");
        let spatial = ReadSpatialQuery {
            bbox: ReadBboxQuery {
                geometry_field: "location".to_owned(),
                west: bbox.west().to_owned(),
                south: bbox.south().to_owned(),
                east: bbox.east().to_owned(),
                north: bbox.north().to_owned(),
                maximum_longitude_span_degrees: "0.3".to_owned(),
                maximum_latitude_span_degrees: "0.2".to_owned(),
            },
        };
        assert_eq!(spatial.bbox.west, "0.1");
        assert_eq!(spatial.bbox.east, "0.4");
        assert!(
            super::validate_spatial_query(entity, operation, &spatial).is_ok(),
            "backend accepts mathematically exact .1 to .4 span under max .3"
        );

        let just_over = ReadSpatialQuery {
            bbox: ReadBboxQuery {
                geometry_field: "location".to_owned(),
                west: "0.1".to_owned(),
                south: "0".to_owned(),
                east: "0.40000000000000000000000000000000000001".to_owned(),
                north: "0.2".to_owned(),
                maximum_longitude_span_degrees: "0.3".to_owned(),
                maximum_latitude_span_degrees: "0.2".to_owned(),
            },
        };
        assert!(
            super::validate_spatial_query(entity, operation, &just_over).is_err(),
            "backend rejects a span that f64 subtraction would round down"
        );
    }

    #[test]
    fn forged_compiled_query_shapes_fail_before_sql_construction() {
        let registry = compile_project(
            &parse_project_json(
                br#"{
                  "apiVersion":"registry.registrystack.org/v1alpha1",
                  "kind":"RegistryProject",
                  "registry":{"id":"plan-guard","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
                  "entities":[{
                    "id":"case","primaryDataset":"test-dataset","route":"cases","mutationMode":"mutable","classification":"public",
                    "fields":[
                      {"id":"label","type":"string","required":true,"maxLength":32,"classification":"public"},
                      {"id":"secret","type":"string","required":true,"maxLength":32,"classification":"restricted"}
                    ]
                  }],
                  "accessProfiles":[{
                    "id":"public","default":true,"anonymous":true,
                    "grants":[{
                      "entity":"case","operations":["list"],
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
            context: AuthorizedRequestContext::new(None, None, "public".to_owned(), Vec::new()),
            selected_fields: BTreeSet::from(["label".to_owned()]),
            kind: RecordReadKind::List {
                plan: CompiledReadQuery {
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
                        scope_reference: digest(),
                        page_size: 10,
                        include_count: false,
                        temporal_instant: None,
                        selected_fields: vec!["label".to_owned()],
                        spatial_reference: None,
                        representation: CursorRepresentation::Json,
                        adapter: CursorAdapter::Native,
                    },
                    cursor_query: CursorQuery {
                        projection: vec![CursorProjectionField {
                            field_id: "label".to_owned(),
                            field_type: FieldTypeSource::String {
                                min_length: 0,
                                max_length: 32,
                            },
                        }],
                        filter: Some(CursorFilterExpr::Predicate {
                            predicate: CursorFilterPredicate {
                                field_id: "secret".to_owned(),
                                field_type: FieldTypeSource::String {
                                    min_length: 0,
                                    max_length: 32,
                                },
                                operator: CursorFilterOperator::Eq,
                                values: vec!["hidden".to_owned()],
                            },
                        }),
                        spatial: None,
                        order: None,
                        include_count: false,
                        page_size: 10,
                        temporal_instant: None,
                        scope: CursorQueryScope::Collection {},
                    },
                    projection: vec![ReadProjectionField {
                        field_id: "label".to_owned(),
                        field_type: FieldTypeSource::String {
                            min_length: 0,
                            max_length: 32,
                        },
                    }],
                    filter: Some(ReadFilterExpr::Predicate(ReadFilterPredicate {
                        field_id: "secret".to_owned(),
                        field_type: FieldTypeSource::String {
                            min_length: 0,
                            max_length: 32,
                        },
                        operator: ReadFilterOperator::Eq,
                        values: vec!["hidden".to_owned()],
                    })),
                    spatial: None,
                    order: None,
                    include_count: false,
                    page_size: 10,
                    temporal_instant: None,
                    adapter: CursorAdapter::Native,
                    adapter_origin: None,
                    continuation: None,
                },
            },
            maximum_records: 11,
            request_history_after_proposal_version: None,
            representation: CursorRepresentation::Json,
            adapter: CursorAdapter::Native,
            adapter_origin: None,
            geojson_next_link_prefix: None,
            correlation: crate::correlation::RequestCorrelation::breg_created(),
        };
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err());

        let query = query_mut(&mut request);
        query.filter = None;
        query.cursor_query.filter = None;
        query.order = Some(ReadOrderClause {
            field_id: "secret".to_owned(),
            field_type: FieldTypeSource::String {
                min_length: 0,
                max_length: 32,
            },
            direction: CompiledQuerySortDirection::Asc,
        });
        query.cursor_query.order = Some(CursorOrderClause {
            field_id: "secret".to_owned(),
            field_type: FieldTypeSource::String {
                min_length: 0,
                max_length: 32,
            },
            direction: CompiledQuerySortDirection::Asc,
        });
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err());

        let query = query_mut(&mut request);
        query.order = None;
        query.cursor_query.order = None;
        query.cursor_binding.query_reference = "hidden-raw-query-value".to_owned();
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err());

        let query = query_mut(&mut request);
        query.cursor_binding.query_reference = digest();
        query.continuation = Some(CursorContinuation {
            last_record_id: "not-a-canonical-uuid".to_owned(),
            sort_value: None,
        });
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err());

        let query = query_mut(&mut request);
        query.continuation = None;
        let references =
            cursor_binding_references(&cursors, &request, operation, query_ref(&request))
                .expect("bounded request context has cursor references");
        let query = query_mut(&mut request);
        query.cursor_binding.principal_reference = references.principal;
        query.cursor_binding.purpose_reference = references.purpose;
        query.cursor_binding.row_boundary_reference = references.row_boundary;
        query.cursor_binding.projection_reference = references.projection;
        query.cursor_binding.query_reference = references.query;
        query.cursor_binding.sort_reference = references.sort;
        query.cursor_binding.scope_reference = references.scope;
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_ok());
        let native_query_reference = query_ref(&request).cursor_binding.query_reference.clone();

        request.representation = CursorRepresentation::GeoJson;
        request.adapter = CursorAdapter::Gis;
        request.adapter_origin = Some("https://registry.example".to_owned());
        request.geojson_next_link_prefix =
            Some("https://registry.example/v1/gis/collections/cases/items?cursor=".to_owned());
        {
            let query = query_mut(&mut request);
            query.adapter = CursorAdapter::Gis;
            query.adapter_origin = Some("https://registry.example".to_owned());
            query.cursor_binding.representation = CursorRepresentation::GeoJson;
            query.cursor_binding.adapter = CursorAdapter::Gis;
        }
        let references =
            cursor_binding_references(&cursors, &request, operation, query_ref(&request))
                .expect("GIS request context has cursor references");
        assert_ne!(references.query, native_query_reference);
        {
            let query = query_mut(&mut request);
            query.cursor_binding.query_reference = references.query;
        }
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_ok());
        request.adapter_origin = Some("https://other.example".to_owned());
        assert!(ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err());
        request.representation = CursorRepresentation::Json;
        request.adapter = CursorAdapter::Native;
        request.adapter_origin = None;
        request.geojson_next_link_prefix = None;
        {
            let query = query_mut(&mut request);
            query.adapter = CursorAdapter::Native;
            query.adapter_origin = None;
            query.cursor_binding.representation = CursorRepresentation::Json;
            query.cursor_binding.adapter = CursorAdapter::Native;
            query.cursor_binding.query_reference = native_query_reference;
        }

        query_mut(&mut request).cursor_binding.query_reference = digest();
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err(),
            "a well-shaped forged binding digest fails before SQL construction"
        );

        let query = query_mut(&mut request);
        query.cursor_binding.query_reference = digest();
        query.spatial = Some(ReadSpatialQuery {
            bbox: ReadBboxQuery {
                geometry_field: "label".to_owned(),
                west: "0".to_owned(),
                south: "0".to_owned(),
                east: "1".to_owned(),
                north: "1".to_owned(),
                maximum_longitude_span_degrees: "1".to_owned(),
                maximum_latitude_span_degrees: "1".to_owned(),
            },
        });
        query.cursor_query.spatial = Some(CursorSpatialQuery {
            bbox: CursorBboxQuery {
                geometry_field: "label".to_owned(),
                west: "0".to_owned(),
                south: "0".to_owned(),
                east: "1".to_owned(),
                north: "1".to_owned(),
                maximum_longitude_span_degrees: "1".to_owned(),
                maximum_latitude_span_degrees: "1".to_owned(),
            },
        });
        assert!(
            ReadPlan::from_request(&registry, &expected, &cursors, &request).is_err(),
            "spatial predicates require the compiled bbox capability"
        );
    }

    #[test]
    fn spatial_collection_relations_use_candidate_view_with_ordinary_read_surface() {
        let registry = compile_project(
            &parse_project_json(
                br#"{
                  "apiVersion":"registry.registrystack.org/v1alpha1",
                  "kind":"RegistryProject",
                  "registry":{"id":"spatial-relation-guard","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
                  "entities":[{
                    "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"public",
                    "fields":[
                      {"id":"code","type":"string","required":true,"maxLength":32,"classification":"public"},
                      {"id":"location","type":"crs84-point","precision":6,"required":false,"classification":"public"}
                    ],
                    "geojson":{"geometryField":"location"}
                  }],
                  "accessProfiles":[{
                    "id":"public","default":true,"anonymous":true,
                    "grants":[{
                      "entity":"site",
                      "operations":["list"],
                      "readableFields":["code","location"],
                      "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1,"maximumLatitudeSpanDegrees":1}}
                    }]
                  }]
                }"#,
            )
            .expect("fixture parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("fixture compiles");
        let entity = registry
            .entities()
            .get("site")
            .expect("compiled entity exists");
        let selected_fields = ["code".to_owned(), "location".to_owned()];
        let relations =
            ReadRelations::collection(entity, None, &selected_fields).expect("collection builds");
        assert!(relations.from_sql.contains("registry_source."));
        assert!(!relations.from_sql.contains("registry_context."));

        let relations = ReadRelations::collection(
            entity,
            Some(&CompiledReadQuery {
                route_id: "unused".to_owned(),
                query_operation_id: "unused".to_owned(),
                kind: CompiledQueryKind::List,
                cursor_binding: CursorBinding {
                    package_revision: "unused".to_owned(),
                    schema_fingerprint: "unused".to_owned(),
                    registry_revision: "unused".to_owned(),
                    route_id: "unused".to_owned(),
                    query_operation_id: "unused".to_owned(),
                    query_kind: CompiledQueryKind::List,
                    selected_profile: "public".to_owned(),
                    principal_reference: None,
                    purpose_reference: None,
                    row_boundary_reference: digest(),
                    projection_reference: digest(),
                    query_reference: digest(),
                    sort_reference: digest(),
                    scope_reference: digest(),
                    page_size: 10,
                    include_count: false,
                    temporal_instant: None,
                    selected_fields: selected_fields.to_vec(),
                    spatial_reference: Some(digest()),
                    representation: CursorRepresentation::Json,
                    adapter: CursorAdapter::Native,
                },
                cursor_query: CursorQuery {
                    projection: Vec::new(),
                    filter: None,
                    spatial: Some(CursorSpatialQuery {
                        bbox: CursorBboxQuery {
                            geometry_field: "location".to_owned(),
                            west: "100".to_owned(),
                            south: "13".to_owned(),
                            east: "101".to_owned(),
                            north: "14".to_owned(),
                            maximum_longitude_span_degrees: "1".to_owned(),
                            maximum_latitude_span_degrees: "1".to_owned(),
                        },
                    }),
                    order: None,
                    include_count: false,
                    page_size: 10,
                    temporal_instant: None,
                    scope: CursorQueryScope::Collection {},
                },
                projection: Vec::new(),
                filter: None,
                spatial: Some(ReadSpatialQuery {
                    bbox: ReadBboxQuery {
                        geometry_field: "location".to_owned(),
                        west: "100".to_owned(),
                        south: "13".to_owned(),
                        east: "101".to_owned(),
                        north: "14".to_owned(),
                        maximum_longitude_span_degrees: "1".to_owned(),
                        maximum_latitude_span_degrees: "1".to_owned(),
                    },
                }),
                order: None,
                include_count: false,
                page_size: 10,
                temporal_instant: None,
                adapter: CursorAdapter::Native,
                adapter_origin: None,
                continuation: None,
            }),
            &selected_fields,
        )
        .expect("spatial collection builds");
        let candidate_view = crate::physical_names::spatial_candidate_view_name("site");
        assert!(relations.from_sql.contains("registry_source."));
        assert!(relations.from_sql.contains("registry_data."));
        assert!(relations.from_sql.contains(&format!(
            "JOIN registry_context.{} AS candidate_record",
            quote_identifier(&candidate_view)
        )));
        assert!(relations
            .from_sql
            .contains("ON candidate_record.id = source_record.\"id\""));
        assert!(relations.base_predicates.is_empty());

        let code = entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == "code")
            .expect("code field exists");
        let projection = projection(entity, &relations, &selected_fields, None)
            .expect("spatial projection builds from logical source fields");
        assert!(projection.contains(&format!(
            "source_record.{}",
            quote_identifier(&code.logical.sql_name)
        )));
        assert!(!projection.contains(&format!(
            "base_record.{}",
            quote_identifier(&code.physical_name)
        )));
        let query = CompiledReadQuery {
            route_id: "unused".to_owned(),
            query_operation_id: "unused".to_owned(),
            kind: CompiledQueryKind::List,
            cursor_binding: CursorBinding {
                package_revision: "unused".to_owned(),
                schema_fingerprint: "unused".to_owned(),
                registry_revision: "unused".to_owned(),
                route_id: "unused".to_owned(),
                query_operation_id: "unused".to_owned(),
                query_kind: CompiledQueryKind::List,
                selected_profile: "public".to_owned(),
                principal_reference: None,
                purpose_reference: None,
                row_boundary_reference: digest(),
                projection_reference: digest(),
                query_reference: digest(),
                sort_reference: digest(),
                scope_reference: digest(),
                page_size: 10,
                include_count: false,
                temporal_instant: None,
                selected_fields: selected_fields.to_vec(),
                spatial_reference: Some(digest()),
                representation: CursorRepresentation::Json,
                adapter: CursorAdapter::Native,
            },
            cursor_query: CursorQuery {
                projection: Vec::new(),
                filter: None,
                spatial: Some(CursorSpatialQuery {
                    bbox: CursorBboxQuery {
                        geometry_field: "location".to_owned(),
                        west: "100".to_owned(),
                        south: "13".to_owned(),
                        east: "101".to_owned(),
                        north: "14".to_owned(),
                        maximum_longitude_span_degrees: "1".to_owned(),
                        maximum_latitude_span_degrees: "1".to_owned(),
                    },
                }),
                order: None,
                include_count: false,
                page_size: 10,
                temporal_instant: None,
                scope: CursorQueryScope::Collection {},
            },
            projection: Vec::new(),
            filter: None,
            spatial: Some(ReadSpatialQuery {
                bbox: ReadBboxQuery {
                    geometry_field: "location".to_owned(),
                    west: "100".to_owned(),
                    south: "13".to_owned(),
                    east: "101".to_owned(),
                    north: "14".to_owned(),
                    maximum_longitude_span_degrees: "1".to_owned(),
                    maximum_latitude_span_degrees: "1".to_owned(),
                },
            }),
            order: None,
            include_count: false,
            page_size: 10,
            temporal_instant: None,
            adapter: CursorAdapter::Native,
            adapter_origin: None,
            continuation: None,
        };
        let statements =
            list_sql(entity, &relations, &query, &projection).expect("spatial SQL builds");
        assert!(statements.values.is_empty());
        assert!(!statements.page_sql.contains("ST_Intersects"));
        assert!(!statements.page_sql.contains("registry_spatial_ext"));
        assert!(!statements.count_sql.contains("ST_Intersects"));
        assert!(!statements.count_sql.contains("registry_spatial_ext"));
    }

    fn query_ref(request: &RecordReadRequest) -> &CompiledReadQuery {
        match &request.kind {
            RecordReadKind::List { plan } => plan,
            _ => unreachable!("test request is a list"),
        }
    }

    fn query_mut(request: &mut RecordReadRequest) -> &mut CompiledReadQuery {
        match &mut request.kind {
            RecordReadKind::List { plan } => plan,
            _ => unreachable!("test request is a list"),
        }
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
