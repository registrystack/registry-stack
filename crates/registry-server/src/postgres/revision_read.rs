// SPDX-License-Identifier: Apache-2.0

//! Bounded PostgreSQL reads over the canonical internal revision journal.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::Serialize;
use serde_json::{json, Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::api::{
    AuthorizedRequestContext, HeldReadResponse, ReadServiceError, RevisionReadRequest,
    RevisionReadService, RowBoundaryOperator as ApiRowBoundaryOperator, ServiceFuture,
};
use crate::audit::{
    append_read_terminal_audit, profile_is_keyed, record_pre_io_audit, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::contract::{FieldTypeSource, Operation, ProvenanceFieldSource};
use crate::cursor::CursorRepresentation;
use crate::history_context::ChangeContext;
use crate::history_migration::HISTORY_MIGRATION_SYSTEM_ORIGIN;
use crate::history_schema::{
    DecodedHistorySnapshot, HistorySchemaDescriptor, HistorySchemaError, MAX_HISTORY_SNAPSHOT_BYTES,
};
use crate::history_store::{self, HistoryStoreError};
use crate::model::{
    CompiledEntity, CompiledRegistry, CompiledRevisionKind, HttpMethod,
    MAX_REVISION_HISTORY_RECORDS,
};
use crate::record_profile::{self, RecordRepresentation};

use super::{
    begin_record_transaction, validate_field_value, ClaimContext, ExpectedRegistryIdentity,
    RegistryLockKey, RowBoundaryContext, RuntimePool,
};

const MAX_JOURNAL_TEXT_BYTES: usize = 512;

/// Runtime revision-history implementation. Every list is the newest 100
/// authorized journal entries and detail reads exactly one positive revision.
#[derive(Clone)]
pub struct PostgresRevisionReadService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
    fault: RevisionReadFaultControl,
}

impl PostgresRevisionReadService {
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
    ) -> Self {
        Self {
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
            fault: RevisionReadFaultControl::Disabled,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: RevisionReadFaultPoint) -> Self {
        self.fault = RevisionReadFaultControl::At(fault);
        self
    }

    async fn execute(
        &self,
        request: RevisionReadRequest,
    ) -> Result<RevisionReadResult, ReadServiceError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(ReadServiceError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, &request.context, &request.entity_id)?;
        let plan = match RevisionReadPlan::from_request(&self.registry, &request) {
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
                        target_record: Some(&request.record_id),
                        correlation: &request.correlation,
                    },
                )
                .await
                .map_err(|_| ReadServiceError::Unavailable)?;
                return Ok(RevisionReadResult::missing());
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
                target_record: Some(&request.record_id),
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
                        TerminalAuditOutcome::Refused,
                        0,
                        &[],
                    )
                    .await;
                return Err(error);
            }
        };
        let held = RevisionReadResult::from_rows(
            &self.registry,
            &plan.entity,
            request.representation,
            plan.kind,
            materialized,
        )?;
        self.fault
            .fail_at(RevisionReadFaultPoint::BeforeTerminalAudit)?;
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
            outcome,
            held.result_count,
            held.response.as_ref().map_or(&[], HeldReadResponse::body),
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(held)
    }

    async fn read_rows(
        &self,
        client: &mut deadpool_postgres::Client,
        request: &RevisionReadRequest,
        claims: &ClaimContext,
        plan: &RevisionReadPlan,
    ) -> Result<Vec<RevisionEnvelope>, ReadServiceError> {
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
        let record_id =
            Uuid::parse_str(&request.record_id).map_err(|_| ReadServiceError::Unavailable)?;
        if record_id.to_string() != request.record_id {
            return Err(ReadServiceError::Unavailable);
        }
        let (sql, parameters) = revision_sql(
            request,
            &plan.entity,
            record_id,
            !plan.provenance_fields.is_empty(),
        )?;
        let parameter_refs = parameters
            .iter()
            .map(|value| &**value as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = transaction
            .transaction()
            .query(&sql, &parameter_refs)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let mut descriptors = BTreeMap::new();
        let mut context_visibility = BTreeMap::new();
        let rows = revision_rows_from_rows(
            transaction.transaction(),
            &rows,
            &plan.entity,
            &request.context,
            &request.selected_fields,
            plan.provenance_fields.as_slice(),
            &mut descriptors,
            &mut context_visibility,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_terminal(
        &self,
        client: &mut deadpool_postgres::Client,
        claims: &ClaimContext,
        request: &RevisionReadRequest,
        plan: &RevisionReadPlan,
        outcome: TerminalAuditOutcome,
        result_count: usize,
        _exact_response_bytes: &[u8],
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
        let record_reference = key_hasher
            .audit_reference_hash(
                "registry-server-record-v1",
                &self.expected.package_revision,
                &request.record_id,
            )
            .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
        let field_set_reference = field_set_reference(
            &self.audit_profile,
            &self.expected.package_revision,
            &request.selected_fields,
        )?;
        let row_boundary_reference =
            row_boundary_reference(&self.audit_profile, &self.expected.package_revision, claims)?;
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
                    entity_id: Some(plan.entity.id.clone()),
                    action_id: None,
                    package_revision: self.expected.package_revision.clone(),
                    selected_access_profile: claims.access_profile().to_owned(),
                    purpose_present: claims.purpose().is_some(),
                    principal_reference,
                    record_reference: Some(record_reference),
                    // Revision values are intentionally absent from revision-read audit.
                    record_revision: None,
                    result_count: Some(result_count),
                    field_set_reference: Some(field_set_reference),
                    correlation: request.correlation.clone(),
                },
                query_reference: None,
                row_boundary_reference: Some(row_boundary_reference),
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::audit::RegistryAuditError::Unavailable)
    }
}

impl RevisionReadService for PostgresRevisionReadService {
    fn detail(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async move { Ok(self.execute(request).await?.response) })
    }

    fn list(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async move { Ok(self.execute(request).await?.response) })
    }

    fn refusal(
        &self,
        request: crate::api::RevisionReadRefusal,
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

struct RevisionReadPlan {
    kind: CompiledRevisionKind,
    entity: CompiledEntity,
    provenance_fields: Vec<ProvenanceFieldSource>,
}

impl RevisionReadPlan {
    fn from_request(
        registry: &CompiledRegistry,
        request: &RevisionReadRequest,
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
        let kind = route.revision_kind.ok_or(())?;
        let expected_maximum = match kind {
            CompiledRevisionKind::List => usize::from(MAX_REVISION_HISTORY_RECORDS),
            CompiledRevisionKind::Detail => 1,
        };
        if route.operation != Operation::Revisions
            || route.method != HttpMethod::Get
            || route.entity_id != request.entity_id
            || route.maximum_records.map(usize::from) != Some(expected_maximum)
            || request.maximum_records != expected_maximum
            || matches!(kind, CompiledRevisionKind::List) != request.revision.is_none()
            || request.revision.is_some_and(|revision| revision <= 0)
            || profile.anonymous
            || !profile.revision_access
            || !profile.operations.contains(&Operation::Revisions)
            || !route
                .access_profiles
                .iter()
                .any(|candidate| candidate == request.context.selected_profile())
            || !request.selected_fields.is_subset(&profile.readable_fields)
            || request
                .selected_fields
                .iter()
                .any(|field| !entity.fields.contains_key(field))
        {
            return Err(());
        }
        Ok(Self {
            kind,
            entity: entity.clone(),
            provenance_fields: profile.provenance_fields.clone(),
        })
    }
}

fn revision_sql(
    request: &RevisionReadRequest,
    entity: &CompiledEntity,
    record_id: Uuid,
    include_commit_context: bool,
) -> Result<(String, Vec<Box<dyn ToSql + Sync + Send>>), ReadServiceError> {
    let mut parameters: Vec<Box<dyn ToSql + Sync + Send>> =
        vec![Box::new(request.entity_id.clone()), Box::new(record_id)];
    let mut predicates = vec![
        "entity_id = $1::text".to_owned(),
        "record_id = $2::uuid".to_owned(),
        // Erased payloads remain represented by protected request provenance,
        // never by a fabricated canonical snapshot in the revision API.
        "snapshot IS NOT NULL".to_owned(),
        "erased_at IS NULL".to_owned(),
    ];
    if let Some(revision) = request.revision {
        parameters.push(Box::new(revision));
        predicates.push(format!("record_revision = ${}::bigint", parameters.len()));
    }
    for boundary in request.context.row_boundaries() {
        let field_type = if boundary.field() == entity.canonical_id.id {
            &entity.canonical_id.field_type
        } else {
            &entity
                .fields
                .get(boundary.field())
                .ok_or(ReadServiceError::Unavailable)?
                .field_type
        };
        let snapshot_value = if boundary.field() == entity.canonical_id.id {
            "to_jsonb(record_id::text)".to_owned()
        } else {
            parameters.push(Box::new(boundary.field().to_owned()));
            let key_parameter = parameters.len();
            format!("(convert_from(snapshot, 'UTF8')::jsonb -> ${key_parameter}::text)")
        };
        let mut values = Vec::new();
        for value in boundary.values() {
            let canonical = canonical_boundary_value(value, field_type)?;
            parameters.push(Box::new(canonical));
            values.push(format!("${}::text::jsonb", parameters.len()));
        }
        if values.is_empty() {
            return Err(ReadServiceError::Unavailable);
        }
        match boundary.operator() {
            ApiRowBoundaryOperator::Equals if values.len() == 1 => {
                predicates.push(format!("{snapshot_value} = {}", values[0]));
            }
            ApiRowBoundaryOperator::In => {
                predicates.push(format!("{snapshot_value} IN ({})", values.join(", ")));
            }
            ApiRowBoundaryOperator::Equals => return Err(ReadServiceError::Unavailable),
        }
    }
    let limit =
        i64::try_from(request.maximum_records).map_err(|_| ReadServiceError::Unavailable)?;
    parameters.push(Box::new(limit));
    let limit_parameter = parameters.len();
    let context_select = if include_commit_context {
        ", member.commit_position, commit.change_context"
    } else {
        ""
    };
    let context_join = if include_commit_context {
        "LEFT JOIN registry_internal.registry_revision_commit_members AS member
             USING (entity_id, record_id, record_revision)
         LEFT JOIN registry_internal.registry_revision_commits AS commit
             USING (commit_position)"
    } else {
        ""
    };
    Ok((
        format!(
            "SELECT revision.record_id, revision.record_revision, revision.predecessor_revision,
                    revision.record_lifecycle, revision.package_revision, revision.operation_id,
                    revision.mutation_kind, revision.principal_reference,
                    revision.request_reference, revision.snapshot, revision.created_at,
                    EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_request_revision_links l
                         WHERE l.entity_id = revision.entity_id
                           AND l.record_id = revision.record_id
                           AND l.record_revision = revision.record_revision
                           AND l.request_entity_id = revision.entity_id
                           AND l.request_id = revision.record_id
                           AND l.link_kind = 'request_lifecycle'
                    ) AS request_lifecycle_revision{context_select}
               FROM registry_internal.registry_revisions AS revision
               {context_join}
              WHERE {}
              ORDER BY record_revision DESC
              LIMIT ${limit_parameter}::bigint",
            predicates.join(" AND ")
        ),
        parameters,
    ))
}

async fn descriptor_for_package<'a>(
    transaction: &tokio_postgres::Transaction<'_>,
    descriptors: &'a mut BTreeMap<String, HistorySchemaDescriptor>,
    package_revision: &str,
) -> Result<&'a HistorySchemaDescriptor, ReadServiceError> {
    if !descriptors.contains_key(package_revision) {
        let descriptor = load_history_schema_descriptor(transaction, package_revision).await?;
        descriptors.insert(package_revision.to_owned(), descriptor);
    }
    descriptors
        .get(package_revision)
        .ok_or(ReadServiceError::Unavailable)
}

async fn load_history_schema_descriptor(
    transaction: &tokio_postgres::Transaction<'_>,
    package_revision: &str,
) -> Result<HistorySchemaDescriptor, ReadServiceError> {
    history_store::load_descriptor(transaction, package_revision)
        .await
        .map_err(history_store_error)
}

fn history_store_error(_: HistoryStoreError) -> ReadServiceError {
    ReadServiceError::Unavailable
}

fn history_schema_error(_: HistorySchemaError) -> ReadServiceError {
    ReadServiceError::Unavailable
}

fn canonical_boundary_value(
    value: &str,
    field_type: &FieldTypeSource,
) -> Result<String, ReadServiceError> {
    validate_field_value(value, field_type).map_err(|_| ReadServiceError::Unavailable)?;
    let value = match field_type {
        FieldTypeSource::Boolean => Value::Bool(value == "true"),
        FieldTypeSource::Int64 => json!(value
            .parse::<i64>()
            .map_err(|_| ReadServiceError::Unavailable)?),
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Decimal { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. }
        | FieldTypeSource::VocabularyCode { .. } => Value::String(value.to_owned()),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            return Err(ReadServiceError::Unavailable);
        }
    };
    let bytes = canonicalize_json(&value).map_err(|_| ReadServiceError::Unavailable)?;
    String::from_utf8(bytes).map_err(|_| ReadServiceError::Unavailable)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevisionEnvelope {
    id: String,
    revision: u64,
    predecessor_revision: Option<u64>,
    lifecycle: String,
    package_revision: String,
    operation_id: String,
    mutation_kind: String,
    created_at: String,
    actor_reference: String,
    request_reference: String,
    data: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_context: Option<Map<String, Value>>,
}

impl RevisionEnvelope {
    fn into_record_member(self) -> Result<Value, ReadServiceError> {
        let mut extensions = Map::from_iter([
            (
                "predecessorRevision".to_owned(),
                self.predecessor_revision
                    .map_or(Value::Null, |value| json!(value)),
            ),
            ("lifecycle".to_owned(), Value::String(self.lifecycle)),
            (
                "packageRevision".to_owned(),
                Value::String(self.package_revision),
            ),
            (
                "operationIdentifier".to_owned(),
                Value::String(self.operation_id),
            ),
            ("mutationKind".to_owned(), Value::String(self.mutation_kind)),
            ("createdAt".to_owned(), Value::String(self.created_at)),
            (
                "actorReference".to_owned(),
                Value::String(self.actor_reference),
            ),
            (
                "requestReference".to_owned(),
                Value::String(self.request_reference),
            ),
        ]);
        if let Some(change_context) = self.change_context {
            extensions.insert("changeContext".to_owned(), Value::Object(change_context));
        }
        record_profile::record_member(self.id, self.revision.to_string(), self.data, extensions)
            .map_err(|_| ReadServiceError::Unavailable)
    }
}

#[allow(clippy::too_many_arguments)] // Authority, projection and retained-schema caches stay separate.
async fn revision_rows_from_rows(
    transaction: &tokio_postgres::Transaction<'_>,
    rows: &[tokio_postgres::Row],
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    selected_fields: &BTreeSet<String>,
    provenance_fields: &[ProvenanceFieldSource],
    descriptors: &mut BTreeMap<String, HistorySchemaDescriptor>,
    context_visibility: &mut BTreeMap<i64, bool>,
) -> Result<Vec<RevisionEnvelope>, ReadServiceError> {
    let mut materialized = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(revision) = revision_from_row(
            transaction,
            row,
            entity,
            context,
            selected_fields,
            provenance_fields,
            descriptors,
            context_visibility,
        )
        .await?
        {
            materialized.push(revision);
        }
    }
    Ok(materialized)
}

#[allow(clippy::too_many_arguments)]
async fn revision_from_row(
    transaction: &tokio_postgres::Transaction<'_>,
    row: &tokio_postgres::Row,
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    selected_fields: &BTreeSet<String>,
    provenance_fields: &[ProvenanceFieldSource],
    descriptors: &mut BTreeMap<String, HistorySchemaDescriptor>,
    context_visibility: &mut BTreeMap<i64, bool>,
) -> Result<Option<RevisionEnvelope>, ReadServiceError> {
    let record_id = row
        .try_get::<_, Uuid>(0)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let revision = row
        .try_get::<_, i64>(1)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let predecessor = row
        .try_get::<_, Option<i64>>(2)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let lifecycle = bounded_text(row, 3)?;
    let package_revision = bounded_text(row, 4)?;
    let operation_id = bounded_text(row, 5)?;
    let mutation_kind = bounded_text(row, 6)?;
    let actor_reference = bounded_text(row, 7)?;
    let request_reference = bounded_text(row, 8)?;
    let snapshot = row
        .try_get::<_, Vec<u8>>(9)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let created_at = row
        .try_get::<_, SystemTime>(10)
        .map_err(|_| ReadServiceError::Unavailable)?;
    let request_lifecycle_revision = row
        .try_get::<_, bool>(11)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if revision <= 0
        || predecessor.is_some_and(|value| value <= 0 || value >= revision)
        || !matches!(lifecycle.as_str(), "active" | "tombstoned")
        || snapshot.is_empty()
        || snapshot.len() > MAX_HISTORY_SNAPSHOT_BYTES
        || !valid_revision_provenance(
            entity,
            &operation_id,
            &mutation_kind,
            &actor_reference,
            &request_reference,
            request_lifecycle_revision,
        )
    {
        return Err(ReadServiceError::Unavailable);
    }
    let descriptor = descriptor_for_package(transaction, descriptors, &package_revision)
        .await?
        .clone();
    let row_authorization_fields = context
        .row_boundaries()
        .iter()
        .map(|boundary| boundary.field().to_owned())
        .collect::<Vec<_>>();
    let required_fields = HistorySchemaDescriptor::required_history_fields(
        selected_fields,
        row_authorization_fields.iter(),
        std::iter::empty::<&String>(),
    );
    let compatibility = descriptor
        .compatibility_for_fields(entity, &required_fields)
        .map_err(history_schema_error)?;
    let decoded = descriptor
        .decode_snapshot_for_fields(&compatibility, &snapshot, Some(&record_id.to_string()))
        .map_err(history_schema_error)?;
    if !row_authorized(&decoded, context, entity)? {
        return Ok(None);
    }
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
        data.insert(field.active_api_name.clone(), value.clone());
    }
    let change_context = revision_change_context(
        transaction,
        row,
        entity,
        context,
        provenance_fields,
        descriptors,
        context_visibility,
    )
    .await?;
    let revision = u64::try_from(revision).map_err(|_| ReadServiceError::Unavailable)?;
    let predecessor_revision = predecessor
        .map(u64::try_from)
        .transpose()
        .map_err(|_| ReadServiceError::Unavailable)?;
    let created_at = OffsetDateTime::from(created_at)
        .format(&Rfc3339)
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(Some(RevisionEnvelope {
        id: record_id.to_string(),
        revision,
        predecessor_revision,
        lifecycle,
        package_revision,
        operation_id,
        mutation_kind,
        created_at,
        actor_reference,
        request_reference,
        data,
        change_context,
    }))
}

fn row_authorized(
    decoded: &DecodedHistorySnapshot,
    context: &AuthorizedRequestContext,
    entity: &CompiledEntity,
) -> Result<bool, ReadServiceError> {
    for boundary in context.row_boundaries() {
        let field_type = if boundary.field() == entity.canonical_id.id {
            &entity.canonical_id.field_type
        } else {
            &entity
                .fields
                .get(boundary.field())
                .ok_or(ReadServiceError::Unavailable)?
                .field_type
        };
        let value = decoded
            .by_field_id
            .get(boundary.field())
            .ok_or(ReadServiceError::Unavailable)?;
        let actual = canonicalize_json(value).map_err(|_| ReadServiceError::Unavailable)?;
        let actual = String::from_utf8(actual).map_err(|_| ReadServiceError::Unavailable)?;
        let expected = boundary
            .values()
            .iter()
            .map(|value| canonical_boundary_value(value, field_type))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if expected.is_empty() {
            return Err(ReadServiceError::Unavailable);
        }
        let matched = match boundary.operator() {
            ApiRowBoundaryOperator::Equals if expected.len() == 1 => expected.contains(&actual),
            ApiRowBoundaryOperator::In => expected.contains(&actual),
            ApiRowBoundaryOperator::Equals => return Err(ReadServiceError::Unavailable),
        };
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn revision_change_context(
    transaction: &tokio_postgres::Transaction<'_>,
    row: &tokio_postgres::Row,
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    provenance_fields: &[ProvenanceFieldSource],
    descriptors: &mut BTreeMap<String, HistorySchemaDescriptor>,
    context_visibility: &mut BTreeMap<i64, bool>,
) -> Result<Option<Map<String, Value>>, ReadServiceError> {
    if provenance_fields.is_empty() {
        return Ok(None);
    }
    if row.len() < 14 {
        return Err(ReadServiceError::Unavailable);
    }
    let Some(commit_position) = row
        .try_get::<_, Option<i64>>(12)
        .map_err(|_| ReadServiceError::Unavailable)?
    else {
        return Ok(None);
    };
    if commit_position < 0 {
        return Err(ReadServiceError::Unavailable);
    }
    let Some(change_context) = row
        .try_get::<_, Option<Vec<u8>>>(13)
        .map_err(|_| ReadServiceError::Unavailable)?
    else {
        return Ok(None);
    };
    let visible = if let Some(visible) = context_visibility.get(&commit_position) {
        *visible
    } else {
        let visible =
            commit_context_visible(transaction, entity, context, commit_position, descriptors)
                .await?;
        context_visibility.insert(commit_position, visible);
        visible
    };
    if !visible {
        return Ok(None);
    }
    project_change_context(&change_context, provenance_fields)
}

async fn commit_context_visible(
    transaction: &tokio_postgres::Transaction<'_>,
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    commit_position: i64,
    descriptors: &mut BTreeMap<String, HistorySchemaDescriptor>,
) -> Result<bool, ReadServiceError> {
    let rows = transaction
        .query(
            "SELECT revisions.entity_id, revisions.record_id, revisions.package_revision,
                    revisions.snapshot
               FROM registry_internal.registry_revision_commit_members AS member
               JOIN registry_internal.registry_revisions AS revisions
                 USING (entity_id, record_id, record_revision)
              WHERE member.commit_position = $1::bigint
              ORDER BY member.member_index ASC",
            &[&commit_position],
        )
        .await
        .map_err(|_| ReadServiceError::Unavailable)?;
    if rows.is_empty() {
        return Ok(false);
    }
    for row in rows {
        let member_entity_id = row
            .try_get::<_, String>(0)
            .map_err(|_| ReadServiceError::Unavailable)?;
        if member_entity_id != entity.id {
            return Ok(false);
        }
        let member_record_id = row
            .try_get::<_, Uuid>(1)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let package_revision = row
            .try_get::<_, String>(2)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let snapshot = row
            .try_get::<_, Vec<u8>>(3)
            .map_err(|_| ReadServiceError::Unavailable)?;
        let descriptor =
            match descriptor_for_package(transaction, descriptors, &package_revision).await {
                Ok(descriptor) => descriptor.clone(),
                Err(_) => return Ok(false),
            };
        let row_authorization_fields = context
            .row_boundaries()
            .iter()
            .map(|boundary| boundary.field().to_owned())
            .collect::<Vec<_>>();
        let required_fields = HistorySchemaDescriptor::required_history_fields(
            std::iter::empty::<&String>(),
            row_authorization_fields.iter(),
            std::iter::empty::<&String>(),
        );
        let compatibility = match descriptor.compatibility_for_fields(entity, &required_fields) {
            Ok(compatibility) => compatibility,
            Err(_) => return Ok(false),
        };
        let decoded = match descriptor.decode_snapshot_for_fields(
            &compatibility,
            &snapshot,
            Some(&member_record_id.to_string()),
        ) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(false),
        };
        if !row_authorized(&decoded, context, entity)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn project_change_context(
    bytes: &[u8],
    provenance_fields: &[ProvenanceFieldSource],
) -> Result<Option<Map<String, Value>>, ReadServiceError> {
    let value = parse_json_strict(bytes).map_err(|_| ReadServiceError::Unavailable)?;
    let canonical = canonicalize_json(&value).map_err(|_| ReadServiceError::Unavailable)?;
    if canonical != bytes {
        return Err(ReadServiceError::Unavailable);
    }
    ChangeContext::parse_json(&value).map_err(|_| ReadServiceError::Unavailable)?;
    let source = value.as_object().ok_or(ReadServiceError::Unavailable)?;
    let mut projected = Map::new();
    for field in provenance_fields {
        let key = match field {
            ProvenanceFieldSource::Kind => "kind",
            ProvenanceFieldSource::ReasonCode => "reasonCode",
            ProvenanceFieldSource::ReasonText => "reasonText",
            ProvenanceFieldSource::SourceReferences => "sourceReferences",
        };
        let Some(value) = source.get(key) else {
            continue;
        };
        match (field, value) {
            (
                ProvenanceFieldSource::Kind
                | ProvenanceFieldSource::ReasonCode
                | ProvenanceFieldSource::ReasonText,
                Value::String(_),
            )
            | (ProvenanceFieldSource::SourceReferences, Value::Array(_)) => {
                projected.insert(key.to_owned(), value.clone());
            }
            _ => return Err(ReadServiceError::Unavailable),
        }
    }
    Ok((!projected.is_empty()).then_some(projected))
}

fn valid_request_journal_operation(entity_id: &str, operation_id: &str) -> bool {
    let prefix = format!("records.{entity_id}.request.");
    let Some(action) = operation_id.strip_prefix(&prefix) else {
        return false;
    };
    if matches!(action, "submit" | "revise" | "cancel" | "apply") {
        return true;
    }
    let parts = action.split('.').collect::<Vec<_>>();
    matches!(parts.as_slice(), ["stages", stage, "approve" | "reject" | "request_revision"] if !stage.is_empty())
}

fn bounded_text(row: &tokio_postgres::Row, index: usize) -> Result<String, ReadServiceError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ReadServiceError::Unavailable)?;
    if value.is_empty()
        || value.len() > MAX_JOURNAL_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ReadServiceError::Unavailable);
    }
    Ok(value)
}

fn valid_revision_provenance(
    entity: &CompiledEntity,
    operation_id: &str,
    mutation_kind: &str,
    actor_reference: &str,
    request_reference: &str,
    request_lifecycle_revision: bool,
) -> bool {
    match mutation_kind {
        "create" | "patch" | "tombstone" => {
            (operation_id == format!("records.{}.{}", entity.id, mutation_kind)
                || (request_lifecycle_revision
                    && entity.change_request.is_some()
                    && mutation_kind == "patch"
                    && valid_request_journal_operation(&entity.id, operation_id)))
                && valid_hmac_reference(actor_reference)
                && valid_hmac_reference(request_reference)
        }
        "migration" => {
            actor_reference == HISTORY_MIGRATION_SYSTEM_ORIGIN
                && operation_id == request_reference
                && valid_migration_reference(request_reference)
        }
        _ => false,
    }
}

fn valid_migration_reference(value: &str) -> bool {
    let Some((descriptor_path, step_id)) = value.split_once('#') else {
        return false;
    };
    !descriptor_path.is_empty()
        && !step_id.is_empty()
        && descriptor_path.starts_with("modules/")
        && descriptor_path.ends_with("/descriptor.json")
        && !descriptor_path.contains("//")
        && !descriptor_path.contains("/../")
        && step_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_hmac_reference(value: &str) -> bool {
    value.len() == 76
        && value.starts_with("hmac-sha256:")
        && value[12..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct RevisionReadResult {
    response: Option<HeldReadResponse>,
    result_count: usize,
}

impl RevisionReadResult {
    fn missing() -> Self {
        Self {
            response: None,
            result_count: 0,
        }
    }

    fn from_rows(
        registry: &CompiledRegistry,
        entity: &CompiledEntity,
        representation: CursorRepresentation,
        kind: CompiledRevisionKind,
        rows: Vec<RevisionEnvelope>,
    ) -> Result<Self, ReadServiceError> {
        let result_count = rows.len();
        let representation = match representation {
            CursorRepresentation::Json => RecordRepresentation::Json,
            CursorRepresentation::JsonLd => RecordRepresentation::JsonLd,
            CursorRepresentation::GeoJson => return Err(ReadServiceError::Unavailable),
        };
        let response = match kind {
            CompiledRevisionKind::List if rows.is_empty() => return Ok(Self::missing()),
            CompiledRevisionKind::List => {
                let items = rows
                    .into_iter()
                    .map(RevisionEnvelope::into_record_member)
                    .collect::<Result<Vec<_>, _>>()?;
                let body = record_profile::collection_response(
                    registry.registry_id(),
                    entity,
                    items,
                    None,
                    Map::new(),
                    representation,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                HeldReadResponse::from_registry_record(&body, representation)?
            }
            CompiledRevisionKind::Detail => {
                let Some(row) = rows.into_iter().next() else {
                    return Ok(Self::missing());
                };
                let member = row.into_record_member()?;
                let body = record_profile::single_response(
                    registry.registry_id(),
                    entity,
                    member,
                    representation,
                )
                .map_err(|_| ReadServiceError::Unavailable)?;
                HeldReadResponse::from_registry_record(&body, representation)?
            }
        };
        Ok(Self {
            response: Some(response),
            result_count,
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

fn row_boundary_reference(
    profile: &AuditProfile,
    package_revision: &str,
    claims: &ClaimContext,
) -> Result<String, crate::audit::RegistryAuditError> {
    let canonical = canonicalize_json(&json!(claims
        .row_boundaries()
        .iter()
        .map(|boundary| json!({
            "field": boundary.field(),
            "operator": boundary.operator().as_str(),
            "values": boundary.values(),
        }))
        .collect::<Vec<_>>()))
    .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
    let canonical = std::str::from_utf8(&canonical)
        .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)?;
    profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-revision-row-boundary-v1",
            package_revision,
            canonical,
        )
        .map_err(|_| crate::audit::RegistryAuditError::InvalidContext)
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionReadFaultPoint {
    BeforeTerminalAudit,
}

#[cfg(not(feature = "postgres-test"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevisionReadFaultPoint {
    BeforeTerminalAudit,
}

#[derive(Clone, Copy)]
enum RevisionReadFaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(RevisionReadFaultPoint),
}

impl RevisionReadFaultControl {
    fn fail_at(self, point: RevisionReadFaultPoint) -> Result<(), ReadServiceError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self, Self::At(configured) if configured == point) {
            return Err(ReadServiceError::Unavailable);
        }
        let _ = (self, point);
        Ok(())
    }
}
