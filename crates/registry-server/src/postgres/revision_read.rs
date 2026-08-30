// SPDX-License-Identifier: Apache-2.0

//! Bounded PostgreSQL reads over the canonical internal revision journal.

use std::collections::BTreeSet;
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
use crate::contract::{FieldTypeSource, Operation};
use crate::model::{
    CompiledEntity, CompiledRegistry, CompiledRevisionKind, HttpMethod,
    MAX_REVISION_HISTORY_RECORDS,
};

use super::{
    begin_record_transaction, validate_field_value, ClaimContext, ExpectedRegistryIdentity,
    RegistryLockKey, RowBoundaryContext, RuntimePool,
};

const MAX_JOURNAL_TEXT_BYTES: usize = 512;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

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
        let held = RevisionReadResult::from_rows(plan.kind, materialized)?;
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
        let (sql, parameters) = revision_sql(request, &plan.entity, record_id)?;
        let parameter_refs = parameters
            .iter()
            .map(|value| &**value as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = transaction
            .transaction()
            .query(&sql, &parameter_refs)
            .await
            .map_err(|_| ReadServiceError::Unavailable)?;
        let rows = rows
            .iter()
            .map(|row| {
                revision_from_row(
                    row,
                    &plan.entity,
                    &request.context,
                    &request.selected_fields,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
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
                    entity_id: plan.entity.id.clone(),
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
        })
    }
}

fn revision_sql(
    request: &RevisionReadRequest,
    entity: &CompiledEntity,
    record_id: Uuid,
) -> Result<(String, Vec<Box<dyn ToSql + Sync + Send>>), ReadServiceError> {
    let mut parameters: Vec<Box<dyn ToSql + Sync + Send>> =
        vec![Box::new(request.entity_id.clone()), Box::new(record_id)];
    let mut predicates = vec![
        "entity_id = $1::text".to_owned(),
        "record_id = $2::uuid".to_owned(),
    ];
    if let Some(revision) = request.revision {
        parameters.push(Box::new(revision));
        predicates.push(format!("record_revision = ${}::bigint", parameters.len()));
    }
    for boundary in request.context.row_boundaries() {
        let field = entity
            .fields
            .get(boundary.field())
            .ok_or(ReadServiceError::Unavailable)?;
        parameters.push(Box::new(boundary.field().to_owned()));
        let key_parameter = parameters.len();
        let mut values = Vec::new();
        for value in boundary.values() {
            let canonical = canonical_boundary_value(value, &field.field_type)?;
            parameters.push(Box::new(canonical));
            values.push(format!("${}::text::jsonb", parameters.len()));
        }
        if values.is_empty() {
            return Err(ReadServiceError::Unavailable);
        }
        let snapshot_value =
            format!("(convert_from(snapshot, 'UTF8')::jsonb -> ${key_parameter}::text)");
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
    Ok((
        format!(
            "SELECT record_id, record_revision, predecessor_revision, record_lifecycle,
                    package_revision, operation_id, mutation_kind, principal_reference,
                    request_reference, snapshot, created_at
             FROM registry_internal.registry_revisions
             WHERE {}
             ORDER BY record_revision DESC
             LIMIT ${limit_parameter}::bigint",
            predicates.join(" AND ")
        ),
        parameters,
    ))
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
}

fn revision_from_row(
    row: &tokio_postgres::Row,
    entity: &CompiledEntity,
    context: &AuthorizedRequestContext,
    selected_fields: &BTreeSet<String>,
) -> Result<RevisionEnvelope, ReadServiceError> {
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
    if revision <= 0
        || predecessor.is_some_and(|value| value <= 0 || value >= revision)
        || !matches!(lifecycle.as_str(), "active" | "tombstoned")
        || !matches!(mutation_kind.as_str(), "create" | "patch" | "tombstone")
        || operation_id != format!("records.{}.{}", entity.id, mutation_kind)
        || !valid_hmac_reference(&actor_reference)
        || !valid_hmac_reference(&request_reference)
        || snapshot.is_empty()
        || snapshot.len() > MAX_SNAPSHOT_BYTES
    {
        return Err(ReadServiceError::Unavailable);
    }
    let parsed = parse_json_strict(&snapshot).map_err(|_| ReadServiceError::Unavailable)?;
    let canonical = canonicalize_json(&parsed).map_err(|_| ReadServiceError::Unavailable)?;
    if canonical != snapshot {
        return Err(ReadServiceError::Unavailable);
    }
    let snapshot = parsed.as_object().ok_or(ReadServiceError::Unavailable)?;
    let mut data = Map::new();
    for field_id in selected_fields {
        let field = entity
            .fields
            .get(field_id)
            .ok_or(ReadServiceError::Unavailable)?;
        let value = snapshot
            .get(field_id)
            .ok_or(ReadServiceError::Unavailable)?;
        validate_snapshot_value(value, &field.field_type, field.required)?;
        data.insert(field_id.clone(), value.clone());
    }
    for boundary in context.row_boundaries() {
        let field = entity
            .fields
            .get(boundary.field())
            .ok_or(ReadServiceError::Unavailable)?;
        let value = snapshot
            .get(boundary.field())
            .ok_or(ReadServiceError::Unavailable)?;
        validate_snapshot_value(value, &field.field_type, field.required)?;
    }
    let revision = u64::try_from(revision).map_err(|_| ReadServiceError::Unavailable)?;
    let predecessor_revision = predecessor
        .map(u64::try_from)
        .transpose()
        .map_err(|_| ReadServiceError::Unavailable)?;
    let created_at = OffsetDateTime::from(created_at)
        .format(&Rfc3339)
        .map_err(|_| ReadServiceError::Unavailable)?;
    Ok(RevisionEnvelope {
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
    })
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

fn valid_hmac_reference(value: &str) -> bool {
    value.len() == 76
        && value.starts_with("hmac-sha256:")
        && value[12..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_snapshot_value(
    value: &Value,
    field_type: &FieldTypeSource,
    required: bool,
) -> Result<(), ReadServiceError> {
    if value.is_null() {
        return (!required)
            .then_some(())
            .ok_or(ReadServiceError::Unavailable);
    }
    let text = match (field_type, value) {
        (FieldTypeSource::Boolean, Value::Bool(value)) => value.to_string(),
        (FieldTypeSource::Int64, Value::Number(value)) if value.as_i64().is_some() => {
            value.to_string()
        }
        (
            FieldTypeSource::String { .. }
            | FieldTypeSource::Text { .. }
            | FieldTypeSource::Decimal { .. }
            | FieldTypeSource::Date
            | FieldTypeSource::Timestamp
            | FieldTypeSource::Uuid
            | FieldTypeSource::Reference { .. }
            | FieldTypeSource::VocabularyCode { .. },
            Value::String(value),
        ) => value.clone(),
        (FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. }, value) => {
            let bytes = canonicalize_json(value).map_err(|_| ReadServiceError::Unavailable)?;
            String::from_utf8(bytes).map_err(|_| ReadServiceError::Unavailable)?
        }
        _ => return Err(ReadServiceError::Unavailable),
    };
    validate_field_value(&text, field_type).map_err(|_| ReadServiceError::Unavailable)
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
        kind: CompiledRevisionKind,
        rows: Vec<RevisionEnvelope>,
    ) -> Result<Self, ReadServiceError> {
        let result_count = rows.len();
        let response = match kind {
            CompiledRevisionKind::List if rows.is_empty() => return Ok(Self::missing()),
            CompiledRevisionKind::List => HeldReadResponse::from_json(&json!({"items": rows}))?,
            CompiledRevisionKind::Detail => {
                let Some(row) = rows.into_iter().next() else {
                    return Ok(Self::missing());
                };
                HeldReadResponse::from_json(&json!(row))?
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
