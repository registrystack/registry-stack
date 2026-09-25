// SPDX-License-Identifier: Apache-2.0

//! Operator lifecycle around a reviewed field-encryption backfill.
//!
//! Two bounded paths live here, one on each side of the apply that runs the
//! backfill steps:
//!
//! - The preflight is read-only. Before any apply runs, it resolves the same
//!   covered fields the backfill would seal, echoes the descriptor's explicit
//!   history choice, counts every stored copy the flip touches, and names the
//!   records whose normalized values would collide on a unique blind index.
//!   The apply-side preflight refuses those collisions authoritatively; this
//!   surface lets an operator see them first, value-free.
//! - The erase-history lifecycle runs only after the flip's package is active.
//!   For every flip that declared erase-and-rebaseline it enumerates the
//!   records that still hold plaintext pre-flip revisions, erases each
//!   record's retained history through the established erasure path, and
//!   restores snapshot coverage with one rebaseline. It is operator tooling,
//!   never an engine step, and every audit envelope it writes carries counts
//!   and references only.

use std::collections::BTreeSet;

use registry_platform_audit::AuditEntry;
use serde::Serialize;
use serde_json::json;
use tokio_postgres::Client;
use zeroize::Zeroizing;

use crate::audit::RegistryAudit;
use crate::history_commit::lock_history_head;
use crate::history_erasure::{
    erase_record_history_for_lifecycle, HistoryErasureError, HistoryErasureRequest,
    RecordHistoryErasureTarget, MAX_ERASURE_REVISIONS,
};
use crate::history_maintenance::{
    append_maintenance_entries, profile_is_keyed, set_local_timeouts, verify_ready_identity,
    HistoryMaintenanceTimeouts,
};
use crate::history_rebaseline::{
    history_rebaseline_entry, rebaseline_history_coverage_in_transaction, HistoryRebaselineError,
    HistoryRebaselineOutcome, HistoryRebaselineRequest,
};
use crate::migration_plan::{
    ReviewedFieldEncryptionHistory, ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationPlan,
};
use crate::model::CompiledRegistry;
use crate::package::CompiledRegistryMigrationBaseline;
use crate::postgres::{
    covered_field_encryption_fields, field_plaintext_string, prepare_unique_blind_index_preflight,
    prior_plaintext_projection, record_unique_blind_index_page, recursive_member_path,
    set_force_row_security, verify_migration_role, ConnectionConfig, ExpectedRegistryIdentity,
    FieldEncryptionCoveredField, RegistryLockKey, SqlIdentifier,
};

pub use crate::history_maintenance::HistoryMaintenanceTimeouts as FieldEncryptionBackfillTimeouts;

/// The audit schema every field-encryption lifecycle entry carries. The shape
/// follows the history maintenance entries: actor reference, package revision,
/// step, and counts; field values never cross this boundary.
pub const FIELD_ENCRYPTION_AUDIT_SCHEMA: &str = "breg-field-encryption-audit/v2";

const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;
/// Bound the records one collision report names so a bulk collision cannot
/// flood an operator surface. The apply-side preflight applies the same cap.
const MAX_NAMED_DUPLICATE_RECORDS: usize = 64;
/// Plaintext values are bounded near 64 KiB, keeping one exact-normalization
/// page near 32 MiB while the database owns cross-page collision state.
const PREFLIGHT_VALUE_PAGE_SIZE: i64 = 512;
/// Keep both target discovery and each established erasure transaction bounded.
const MAX_ERASURE_TARGETS_PER_PAGE: i64 = 128;
const AUDIT_OPERATION_ID: &str = "field-encryption-erase-history";

/// Read-only preflight over the database a reviewed backfill would target.
pub struct FieldEncryptionBackfillPreflightRequest<'a> {
    /// The identity the database must already hold: the backfill's predecessor.
    /// The preflight refuses when the active revision is anything else, so its
    /// counts always describe the state the apply would start from.
    pub expected: &'a ExpectedRegistryIdentity,
    pub migration_role: &'a SqlIdentifier,
    pub timeouts: FieldEncryptionBackfillTimeouts,
    /// The successor package's compiled registry.
    pub registry: &'a CompiledRegistry,
    /// The successor package's validated reviewed migration plan.
    pub plan: &'a ValidatedReviewedMigrationPlan,
    /// The predecessor baseline the apply would bind.
    pub predecessor_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    /// The successor package revision the backfill journals under.
    pub target_package_revision: &'a str,
}

/// The value-free counts and duplicate names one backfill step's preflight
/// produced. Every count names rows; the duplicate list names authored record
/// identifiers a unique blind index would refuse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldEncryptionBackfillPreflightReport {
    pub steps: Vec<FieldEncryptionBackfillStepPreflight>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldEncryptionBackfillStepPreflight {
    pub entity_id: String,
    pub history_choice: ReviewedFieldEncryptionHistory,
    pub fields: Vec<FieldEncryptionBackfillFieldPreflight>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldEncryptionBackfillFieldPreflight {
    pub field_id: String,
    pub api_name: String,
    pub unique_blind_index: bool,
    /// Live rows that still carry a plaintext value in the prior column.
    pub plaintext_row_count: u64,
    /// Retained journal revisions, recorded before the boundary, that carry
    /// the field member: the rows the chosen history path erases or accepts.
    pub journal_row_count: u64,
    pub request_target_row_count: u64,
    pub request_proposal_row_count: u64,
    pub idempotency_row_count: u64,
    pub outbox_row_count: u64,
    /// Authored record identifiers whose normalized values would collide on
    /// the field's unique blind index. Empty unless `unique_blind_index`.
    pub duplicate_record_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FieldEncryptionBackfillPreflightError {
    #[error("field-encryption preflight input is invalid")]
    InvalidInput,
    #[error("field-encryption preflight requires the configured migration authority")]
    MigrationAuthority,
    #[error("field-encryption preflight storage is unavailable")]
    Unavailable,
}

impl From<crate::postgres::PostgresKernelError> for FieldEncryptionBackfillPreflightError {
    fn from(error: crate::postgres::PostgresKernelError) -> Self {
        Self::from(crate::history_maintenance::HistoryMaintenanceError::from(
            error,
        ))
    }
}

impl From<crate::history_maintenance::HistoryMaintenanceError>
    for FieldEncryptionBackfillPreflightError
{
    fn from(error: crate::history_maintenance::HistoryMaintenanceError) -> Self {
        match error {
            crate::history_maintenance::HistoryMaintenanceError::InvalidInput => Self::InvalidInput,
            crate::history_maintenance::HistoryMaintenanceError::MigrationAuthority => {
                Self::MigrationAuthority
            }
            crate::history_maintenance::HistoryMaintenanceError::Unavailable => Self::Unavailable,
        }
    }
}

/// Open the configured migration connection and run the read-only preflight.
pub async fn preflight_field_encryption_backfill_with_connection(
    connection: &ConnectionConfig,
    request: FieldEncryptionBackfillPreflightRequest<'_>,
) -> Result<FieldEncryptionBackfillPreflightReport, FieldEncryptionBackfillPreflightError> {
    let pool = connection
        .build_pool()
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    preflight_field_encryption_backfill(&mut client, request).await
}

/// Run the read-only preflight over an already opened migration connection.
/// Everything it reads happens in one transaction pinned to UTC, so the counts
/// describe one consistent state and render exactly the projections the apply
/// would seal.
pub async fn preflight_field_encryption_backfill(
    client: &mut Client,
    request: FieldEncryptionBackfillPreflightRequest<'_>,
) -> Result<FieldEncryptionBackfillPreflightReport, FieldEncryptionBackfillPreflightError> {
    request.expected.validate()?;
    if !request
        .plan
        .migrations()
        .iter()
        .any(|migration| migration.descriptor.history.is_some())
    {
        return Err(FieldEncryptionBackfillPreflightError::InvalidInput);
    }
    verify_migration_role(client, request.migration_role).await?;

    let transaction = client
        .transaction()
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    // Plaintext projections render typed columns through the session time
    // zone; pin the same UTC the apply's chunk transactions pin.
    transaction
        .execute("SELECT set_config('TimeZone', 'UTC', true)", &[])
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;

    let mut steps = Vec::new();
    for migration in request.plan.migrations() {
        for step in &migration.steps {
            let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { entity_id, .. } =
                &step.descriptor
            else {
                continue;
            };
            // The plan validation already refused a missing or unmatched
            // history choice for this backfill. Unrelated descriptors in the
            // same reviewed plan do not need a field-encryption choice.
            let history_choice = migration
                .descriptor
                .history
                .ok_or(FieldEncryptionBackfillPreflightError::InvalidInput)?;
            let covered = covered_field_encryption_fields(
                request.registry,
                request.predecessor_baseline,
                entity_id,
                step,
            )
            .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?;
            let table = &request
                .registry
                .entities()
                .get(entity_id.as_str())
                .ok_or(FieldEncryptionBackfillPreflightError::InvalidInput)?
                .physical_table;
            // Entity tables normally FORCE RLS. The migration role owns them
            // but deliberately has no BYPASSRLS authority, so the value-free
            // operator preflight must use the same bounded maintenance bracket
            // as the authoritative apply scan or it would report zero rows.
            set_force_row_security(&transaction, std::slice::from_ref(table), false)
                .await
                .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
            let mut fields = Vec::new();
            for field in &covered {
                fields.push(
                    field_preflight(&transaction, field, table, request.target_package_revision)
                        .await?,
                );
            }
            set_force_row_security(&transaction, std::slice::from_ref(table), true)
                .await
                .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
            steps.push(FieldEncryptionBackfillStepPreflight {
                entity_id: entity_id.clone(),
                history_choice,
                fields,
            });
        }
    }
    transaction
        .commit()
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    Ok(FieldEncryptionBackfillPreflightReport { steps })
}

#[allow(clippy::too_many_lines)] // One bounded query set per covered field, kept together.
async fn field_preflight(
    transaction: &tokio_postgres::Transaction<'_>,
    field: &FieldEncryptionCoveredField<'_>,
    table: &str,
    target_package_revision: &str,
) -> Result<FieldEncryptionBackfillFieldPreflight, FieldEncryptionBackfillPreflightError> {
    let entity_id = field.entity_id;
    let field_id = field.logical_field_id;
    let table = SqlIdentifier::parse(table)
        .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?;
    let plaintext_projection = prior_plaintext_projection(field.prior);

    let rows_sql = format!(
        "SELECT record_id, {plaintext_projection}
           FROM registry_data.{}
          WHERE ($1::uuid IS NULL OR record_id > $1::uuid)
          ORDER BY record_id
          LIMIT $2",
        table.quoted()
    );

    let mut plaintext_row_count = 0_u64;
    // Normalized-duplicate detection needs no service key material: an
    // ephemeral keyed digest preserves equality for this run. Keep the exact
    // Rust normalization semantics, but place only keyed digests and record
    // ids in transaction-local PostgreSQL state instead of raw normalized
    // plaintext or an unbounded process map.
    let unique_blind = field.blind.filter(|blind| blind.unique);
    let ephemeral_index_key = unique_blind.map(|_| {
        let mut key = [0_u8; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Zeroizing::new(key)
    });
    if unique_blind.is_some() {
        prepare_unique_blind_index_preflight(transaction)
            .await
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    }
    let mut after_record_id: Option<uuid::Uuid> = None;
    let mut duplicate_record_ids = BTreeSet::new();
    loop {
        let rows = transaction
            .query(&rows_sql, &[&after_record_id, &PREFLIGHT_VALUE_PAGE_SIZE])
            .await
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
        if rows.is_empty() {
            break;
        }
        let mut blind_index_digests = Vec::with_capacity(rows.len());
        let mut normalized_record_ids = Vec::with_capacity(rows.len());
        for row in &rows {
            let record_id: uuid::Uuid = row
                .try_get(0)
                .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
            let value = row
                .try_get::<_, Option<serde_json::Value>>(1)
                .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?
                .unwrap_or(serde_json::Value::Null);
            if let Some(plaintext) = field_plaintext_string(field.prior, &value)
                .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?
            {
                plaintext_row_count = plaintext_row_count
                    .checked_add(1)
                    .ok_or(FieldEncryptionBackfillPreflightError::Unavailable)?;
                if let Some(blind) = unique_blind {
                    let normalized = crate::field_encryption::FieldEncryptionService::normalize(
                        &blind.normalization,
                        &plaintext,
                    );
                    let key = ephemeral_index_key
                        .as_ref()
                        .ok_or(FieldEncryptionBackfillPreflightError::Unavailable)?;
                    blind_index_digests.push(
                        registry_platform_crypto::field_encryption::blind_index_hmac(
                            key,
                            &normalized,
                        )
                        .to_vec(),
                    );
                    normalized_record_ids.push(record_id);
                }
            }
            after_record_id = Some(record_id);
        }
        if !blind_index_digests.is_empty() {
            let page_duplicates = record_unique_blind_index_page(
                transaction,
                0,
                &blind_index_digests,
                &normalized_record_ids,
                i64::try_from(MAX_NAMED_DUPLICATE_RECORDS)
                    .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?,
            )
            .await
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
            for record_id in page_duplicates {
                if duplicate_record_ids.len() < MAX_NAMED_DUPLICATE_RECORDS {
                    duplicate_record_ids.insert(record_id);
                }
            }
        }
    }

    let journal = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND package_revision <> $2
                AND convert_from(snapshot, 'UTF8')::jsonb ? $3",
            &[&entity_id, &target_package_revision, &field_id],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let journal_row_count = u64::try_from(journal.get::<_, i64>(0))
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;

    // Pre-seal, every stored copy that mentions the member is a plaintext
    // copy the chosen history path will erase or explicitly accept.
    let request_targets = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_request_targets
              WHERE target_entity_id = $1
                AND (base_snapshot ? $2 OR after_snapshot ? $2)",
            &[&entity_id, &field_id],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let request_proposals = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_request_proposals AS proposal
              WHERE snapshot IS NOT NULL
                AND (
                    EXISTS (
                        SELECT 1
                          FROM jsonb_array_elements(
                                   COALESCE(proposal.snapshot -> 'effects', '[]'::jsonb)
                               ) AS effect
                          CROSS JOIN LATERAL jsonb_array_elements(
                              COALESCE(effect -> 'fieldChanges', '[]'::jsonb)
                          ) AS field_change
                         WHERE effect -> 'target' ->> 'entityId' = $1
                           AND field_change ->> 'field' = $2
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM jsonb_array_elements(
                              COALESCE(
                                  proposal.snapshot #> '{applicationPreconditions,targets}',
                                  '[]'::jsonb
                              )
                          ) AS guard
                         WHERE guard ->> 'entityId' = $1
                           AND guard -> 'values' ? $2
                    )
                )",
            &[&entity_id, &field_id],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let idempotency = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_idempotency
              WHERE convert_from(response_body, 'UTF8')::jsonb @? ($1::text)::jsonpath",
            &[&recursive_member_path(field.predecessor_api_name)
                .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let outbox = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_outbox
              WHERE payload IS NOT NULL
                AND convert_from(payload, 'UTF8')::jsonb @? ($1::text)::jsonpath",
            &[&recursive_member_path(field.logical_field_id)
                .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;

    let duplicate_record_ids = duplicate_record_ids.into_iter().collect();

    Ok(FieldEncryptionBackfillFieldPreflight {
        field_id: field_id.to_owned(),
        api_name: field.api_name.to_owned(),
        unique_blind_index: field.blind.is_some_and(|blind| blind.unique),
        plaintext_row_count,
        journal_row_count,
        request_target_row_count: u64::try_from(request_targets.get::<_, i64>(0))
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?,
        request_proposal_row_count: u64::try_from(request_proposals.get::<_, i64>(0))
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?,
        idempotency_row_count: u64::try_from(idempotency.get::<_, i64>(0))
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?,
        outbox_row_count: u64::try_from(outbox.get::<_, i64>(0))
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?,
        duplicate_record_ids,
    })
}

/// One record whose retained pre-flip history the erase lifecycle still has to
/// erase: the record, the entity, and the newest pre-flip revision holding the
/// plaintext member.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingEraseTarget {
    entity_id: String,
    record_id: uuid::Uuid,
    erase_through_revision: i64,
}

/// The erase-and-rebaseline lifecycle request. The scope is not named by the
/// operator: it is the recorded erase-and-rebaseline flips themselves, so the
/// lifecycle can never erase history a descriptor did not declare.
pub struct FieldEncryptionHistoryErasureRequest<'a> {
    /// The identity the database must already hold. Because flips are recorded
    /// only by the apply that activates their package, a matching identity
    /// proves the successor package is active before any erasure runs.
    pub expected: &'a ExpectedRegistryIdentity,
    pub migration_role: &'a SqlIdentifier,
    pub lock_key: RegistryLockKey,
    pub timeouts: HistoryMaintenanceTimeouts,
    pub audit: &'a RegistryAudit,
    pub operator_reference: &'a str,
    pub reason: &'a str,
    /// The active package's compiled registry, used by the closing rebaseline.
    pub registry: &'a CompiledRegistry,
}

/// The value-free outcome of one completed erase-history lifecycle. Counts
/// aggregate the per-record erasures; the rebaseline outcome is carried whole.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldEncryptionHistoryErasureOutcome {
    pub erased_record_count: u64,
    pub erased_revision_count: u64,
    pub erased_commit_member_count: u64,
    pub scrubbed_change_context_count: u64,
    pub scrubbed_outbox_payload_count: u64,
    pub scrubbed_cached_response_count: u64,
    pub scrubbed_request_target_count: u64,
    pub scrubbed_request_proposal_count: u64,
    pub removed_descriptor_count: u64,
    pub rebaseline: HistoryRebaselineOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FieldEncryptionHistoryErasureError {
    #[error("field-encryption history erasure input is invalid")]
    InvalidInput,
    #[error("field-encryption history erasure requires the configured migration authority")]
    MigrationAuthority,
    #[error("field-encryption history erasure found no retained plaintext history to erase")]
    NoPendingPlaintextHistory,
    #[error("field-encryption history erasure failed in the per-record erasure path")]
    Erasure(HistoryErasureError),
    #[error("field-encryption history erasure failed in the closing rebaseline")]
    Rebaseline(HistoryRebaselineError),
    #[error("field-encryption history erasure storage is unavailable")]
    Unavailable,
}

impl From<crate::postgres::PostgresKernelError> for FieldEncryptionHistoryErasureError {
    fn from(error: crate::postgres::PostgresKernelError) -> Self {
        Self::from(crate::history_maintenance::HistoryMaintenanceError::from(
            error,
        ))
    }
}

impl From<crate::history_maintenance::HistoryMaintenanceError>
    for FieldEncryptionHistoryErasureError
{
    fn from(error: crate::history_maintenance::HistoryMaintenanceError) -> Self {
        match error {
            crate::history_maintenance::HistoryMaintenanceError::InvalidInput => Self::InvalidInput,
            crate::history_maintenance::HistoryMaintenanceError::MigrationAuthority => {
                Self::MigrationAuthority
            }
            crate::history_maintenance::HistoryMaintenanceError::Unavailable => Self::Unavailable,
        }
    }
}

/// Open the configured migration connection and run the erase-history
/// lifecycle under the Registry maintenance lock.
pub async fn erase_field_encryption_history_with_connection(
    connection: &ConnectionConfig,
    request: FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<FieldEncryptionHistoryErasureOutcome, FieldEncryptionHistoryErasureError> {
    let pool = connection
        .build_pool()
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    erase_field_encryption_history(&mut client, request).await
}

/// Run the erase-history lifecycle over an already opened migration
/// connection: enumerate the pending targets, erase each record's retained
/// history through the established erasure path, rebaseline coverage once,
/// then append the rebaseline and lifecycle entries after that commit. Each per-record erasure and the
/// rebaseline take the Registry advisory transaction lock in turn, so the
/// lifecycle never runs concurrent with an apply that holds the session lock.
pub async fn erase_field_encryption_history(
    client: &mut Client,
    request: FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<FieldEncryptionHistoryErasureOutcome, FieldEncryptionHistoryErasureError> {
    validate_request(&request)?;
    verify_migration_role(client, request.migration_role).await?;

    // Change-request snapshots are not generic record history. Scrub only the
    // copies that still carry plaintext for a recorded erase-and-rebaseline
    // flip. The transaction also marks coverage incomplete, which is the
    // existing durable retry signal if this lifecycle stops before rebaseline.
    let (_, _, needs_rebaseline, lifecycle_reference) =
        scrub_plaintext_request_snapshots(client, &request).await?;
    let mut erased_any = false;
    loop {
        let targets = pending_erase_targets(client, &request).await?;
        if targets.is_empty() {
            break;
        }
        erased_any = true;
        for target in &targets {
            // Discovery caps each target at the next 10,000 retained revisions,
            // preserving the established transaction bound. Re-querying after
            // the page commits resumes the same record when it has more history.
            erase_record_history_for_lifecycle(
                client,
                HistoryErasureRequest {
                    expected: request.expected,
                    migration_role: request.migration_role,
                    lock_key: request.lock_key,
                    timeouts: request.timeouts,
                    audit: request.audit,
                    operator_reference: request.operator_reference,
                    reason: request.reason,
                    target: RecordHistoryErasureTarget::new(
                        &target.entity_id,
                        target.record_id,
                        target.erase_through_revision,
                    ),
                },
                &lifecycle_reference,
            )
            .await
            .map_err(FieldEncryptionHistoryErasureError::Erasure)?;
        }
    }
    if !erased_any && !needs_rebaseline {
        return Err(FieldEncryptionHistoryErasureError::NoPendingPlaintextHistory);
    }

    // Coverage and the lifecycle's terminal progress row form one closing
    // commit; the rebaseline and terminal entries are appended after it. A
    // failure before that commit leaves coverage incomplete and the existing
    // retry path remains available.
    let transaction = client
        .transaction()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&request.lock_key.get()],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;
    let rebaseline_request = HistoryRebaselineRequest {
        expected: request.expected,
        migration_role: request.migration_role,
        lock_key: request.lock_key,
        timeouts: request.timeouts,
        audit: request.audit,
        operator_reference: request.operator_reference,
        registry: request.registry,
    };
    let rebaseline = rebaseline_history_coverage_in_transaction(&transaction, &rebaseline_request)
        .await
        .map_err(FieldEncryptionHistoryErasureError::Rebaseline)?;
    let counts = aggregate_lifecycle_counts(&transaction, &lifecycle_reference).await?;

    let outcome = FieldEncryptionHistoryErasureOutcome {
        erased_record_count: counts.erased_record_count,
        erased_revision_count: counts.erased_revision_count,
        erased_commit_member_count: counts.erased_commit_member_count,
        scrubbed_change_context_count: counts.scrubbed_change_context_count,
        scrubbed_outbox_payload_count: counts.scrubbed_outbox_payload_count,
        scrubbed_cached_response_count: counts.scrubbed_cached_response_count,
        scrubbed_request_target_count: counts.scrubbed_request_target_count,
        scrubbed_request_proposal_count: counts.scrubbed_request_proposal_count,
        removed_descriptor_count: counts.removed_descriptor_count,
        rebaseline,
    };
    let rebaseline_entry = history_rebaseline_entry(
        &rebaseline_request,
        &outcome.rebaseline,
        lifecycle_reference.clone(),
    )
    .map_err(FieldEncryptionHistoryErasureError::Rebaseline)?;
    let terminal_entry = erase_history_entry(&request, &lifecycle_reference, &outcome)?;
    record_lifecycle_progress(
        &transaction,
        &lifecycle_reference,
        LifecycleProgressKind::Terminal,
        0,
        0,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    append_maintenance_entries(request.audit, vec![rebaseline_entry, terminal_entry]).await?;
    Ok(outcome)
}

/// Clear whole request snapshots when their frozen originating package
/// predates a recorded erase-and-rebaseline flip and they mention its field.
/// Package order comes from the migration ledger, not request revision timing:
/// a draft can predate the flip while its frozen proposal and target snapshots
/// are created afterward. This also reaches canceled and rejected creates
/// whose target never produced a retained record revision.
async fn scrub_plaintext_request_snapshots(
    client: &mut Client,
    request: &FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<(u64, u64, bool, String), FieldEncryptionHistoryErasureError> {
    let transaction = client
        .transaction()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&request.lock_key.get()],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;
    let head = lock_history_head(&transaction)
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    let flip_state = transaction
        .query_one(
            "SELECT
                 EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_field_encryption_flips
                      WHERE history_choice = 'erase-and-rebaseline'
                 ),
                 EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_field_encryption_flips
                      WHERE history_choice = 'erase-and-rebaseline'
                        AND history_commit_position IS NULL
                 )",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    let has_erase_choice_flip: bool = flip_state.get(0);
    let missing_history_cutoff: bool = flip_state.get(1);
    if missing_history_cutoff {
        return Err(FieldEncryptionHistoryErasureError::Unavailable);
    }
    let lifecycle_reference =
        field_encryption_lifecycle_reference_in_transaction(&transaction, request).await?;
    if !has_erase_choice_flip {
        transaction
            .commit()
            .await
            .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
        return Ok((0, 0, false, lifecycle_reference));
    }
    let (terminal_exists, correlated_progress_exists) =
        lifecycle_progress_state(&transaction, &lifecycle_reference).await?;
    let unresolved_provenance: bool = transaction
        .query_one(
            "WITH target_positions AS (
                 SELECT target_package_revision AS package_revision, package_sequence
                   FROM registry_internal.registry_migrations
             ),
             source_positions AS (
                 SELECT source.source_package_revision AS package_revision,
                        min(source.package_sequence - 1)::bigint AS package_sequence,
                        1::bigint AS inferred_count
                   FROM registry_internal.registry_migrations AS source
                  WHERE source.source_package_revision IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM target_positions AS target
                         WHERE target.package_revision = source.source_package_revision
                    )
                  GROUP BY source.source_package_revision
             ),
             package_positions AS (
                 SELECT package_revision, package_sequence, 1::bigint AS inferred_count
                   FROM target_positions
                 UNION ALL
                 SELECT package_revision, package_sequence, inferred_count
                   FROM source_positions
             )
             SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_request_proposals AS proposal
                   JOIN registry_internal.registry_field_encryption_flips AS flip
                     ON flip.history_choice = 'erase-and-rebaseline'
                   LEFT JOIN package_positions AS boundary
                     ON boundary.package_revision = flip.boundary_package_revision
                   LEFT JOIN package_positions AS origin
                     ON origin.package_revision = proposal.snapshot ->> 'originatingPackage'
                  WHERE proposal.snapshot IS NOT NULL
                    AND proposal.erased_at IS NULL
                    AND (
                        EXISTS (
                            SELECT 1
                              FROM jsonb_array_elements(
                                  COALESCE(proposal.snapshot -> 'effects', '[]'::jsonb)
                              ) AS effect
                              CROSS JOIN LATERAL jsonb_array_elements(
                                  COALESCE(effect -> 'fieldChanges', '[]'::jsonb)
                              ) AS field_change
                             WHERE effect -> 'target' ->> 'entityId' = flip.entity_id
                               AND field_change ->> 'field' = flip.field_id
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM jsonb_array_elements(
                                  COALESCE(
                                      proposal.snapshot #> '{applicationPreconditions,targets}',
                                      '[]'::jsonb
                                  )
                              ) AS guard
                             WHERE guard ->> 'entityId' = flip.entity_id
                               AND guard -> 'values' ? flip.field_id
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_request_targets AS target
                             WHERE target.request_entity_id = proposal.request_entity_id
                               AND target.request_id = proposal.request_id
                               AND target.proposal_version = proposal.proposal_version
                               AND target.erased_at IS NULL
                               AND target.target_entity_id = flip.entity_id
                               AND (
                                   target.base_snapshot ? flip.field_id
                                   OR target.after_snapshot ? flip.field_id
                               )
                        )
                    )
                    AND (
                        proposal.snapshot ->> 'originatingPackage' IS NULL
                        OR boundary.package_revision IS NULL
                        OR boundary.inferred_count <> 1
                        OR origin.package_revision IS NULL
                        OR origin.inferred_count <> 1
                    )
             )",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?
        .get(0);
    if unresolved_provenance {
        return Err(FieldEncryptionHistoryErasureError::Unavailable);
    }

    // Targets must be scrubbed while their parent proposal still carries the
    // frozen originating package used to classify the snapshot as pre-flip.
    let scrubbed_request_target_count = transaction
        .execute(
            "WITH target_positions AS (
                 SELECT target_package_revision AS package_revision, package_sequence
                   FROM registry_internal.registry_migrations
             ),
             source_positions AS (
                 SELECT source.source_package_revision AS package_revision,
                        min(source.package_sequence - 1)::bigint AS package_sequence,
                        1::bigint AS inferred_count
                   FROM registry_internal.registry_migrations AS source
                  WHERE source.source_package_revision IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM target_positions AS target
                         WHERE target.package_revision = source.source_package_revision
                    )
                  GROUP BY source.source_package_revision
             ),
             package_positions AS (
                 SELECT package_revision, package_sequence, 1::bigint AS inferred_count
                   FROM target_positions
                 UNION ALL
                 SELECT package_revision, package_sequence, inferred_count
                   FROM source_positions
             )
             UPDATE registry_internal.registry_request_targets AS target
                SET base_snapshot = NULL,
                    after_snapshot = NULL,
                    erased_at = transaction_timestamp()
              WHERE target.erased_at IS NULL
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_field_encryption_flips AS flip
                      JOIN package_positions AS boundary
                        ON boundary.package_revision = flip.boundary_package_revision
                       AND boundary.inferred_count = 1
                      JOIN registry_internal.registry_request_proposals AS proposal
                        ON proposal.request_entity_id = target.request_entity_id
                       AND proposal.request_id = target.request_id
                       AND proposal.proposal_version = target.proposal_version
                      JOIN package_positions AS origin
                        ON origin.package_revision =
                           proposal.snapshot ->> 'originatingPackage'
                       AND origin.inferred_count = 1
                     WHERE flip.history_choice = 'erase-and-rebaseline'
                       AND target.target_entity_id = flip.entity_id
                       AND (
                           target.base_snapshot ? flip.field_id
                           OR target.after_snapshot ? flip.field_id
                       )
                       AND origin.package_sequence < boundary.package_sequence
                )",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;

    let scrubbed_request_proposal_count = transaction
        .execute(
            "WITH target_positions AS (
                 SELECT target_package_revision AS package_revision, package_sequence
                   FROM registry_internal.registry_migrations
             ),
             source_positions AS (
                 SELECT source.source_package_revision AS package_revision,
                        min(source.package_sequence - 1)::bigint AS package_sequence,
                        1::bigint AS inferred_count
                   FROM registry_internal.registry_migrations AS source
                  WHERE source.source_package_revision IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM target_positions AS target
                         WHERE target.package_revision = source.source_package_revision
                    )
                  GROUP BY source.source_package_revision
             ),
             package_positions AS (
                 SELECT package_revision, package_sequence, 1::bigint AS inferred_count
                   FROM target_positions
                 UNION ALL
                 SELECT package_revision, package_sequence, inferred_count
                   FROM source_positions
             )
             UPDATE registry_internal.registry_request_proposals AS proposal
                SET snapshot = NULL,
                    erased_at = transaction_timestamp()
              WHERE proposal.snapshot IS NOT NULL
                AND proposal.erased_at IS NULL
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_field_encryption_flips AS flip
                      JOIN package_positions AS boundary
                        ON boundary.package_revision = flip.boundary_package_revision
                       AND boundary.inferred_count = 1
                      JOIN package_positions AS origin
                        ON origin.package_revision =
                           proposal.snapshot ->> 'originatingPackage'
                       AND origin.inferred_count = 1
                     WHERE flip.history_choice = 'erase-and-rebaseline'
                       AND origin.package_sequence < boundary.package_sequence
                       AND (
                           EXISTS (
                               SELECT 1
                                 FROM jsonb_array_elements(
                                     COALESCE(proposal.snapshot -> 'effects', '[]'::jsonb)
                                 ) AS effect
                                 CROSS JOIN LATERAL jsonb_array_elements(
                                     COALESCE(effect -> 'fieldChanges', '[]'::jsonb)
                                 ) AS field_change
                                WHERE effect -> 'target' ->> 'entityId' = flip.entity_id
                                  AND field_change ->> 'field' = flip.field_id
                           )
                           OR EXISTS (
                               SELECT 1
                                 FROM jsonb_array_elements(
                                     COALESCE(
                                         proposal.snapshot #> '{applicationPreconditions,targets}',
                                         '[]'::jsonb
                                     )
                                 ) AS guard
                                WHERE guard ->> 'entityId' = flip.entity_id
                                  AND guard -> 'values' ? flip.field_id
                           )
                       )
                )",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;

    let scrubbed_any = scrubbed_request_target_count != 0 || scrubbed_request_proposal_count != 0;
    let has_pending_revisions: bool = transaction
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_field_encryption_flips AS flip
                   JOIN registry_internal.registry_revisions AS revision
                     ON revision.entity_id = flip.entity_id
                   LEFT JOIN registry_internal.registry_revision_commit_members AS member
                     ON member.entity_id = revision.entity_id
                    AND member.record_id = revision.record_id
                    AND member.record_revision = revision.record_revision
                  WHERE flip.history_choice = 'erase-and-rebaseline'
                    AND revision.snapshot IS NOT NULL
                    AND revision.erased_at IS NULL
                    AND revision.package_revision <> flip.boundary_package_revision
                    AND convert_from(revision.snapshot, 'UTF8')::jsonb ? flip.field_id
                    AND (
                        member.commit_position < flip.history_commit_position
                        OR member.commit_position IS NULL
                    )
             )",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?
        .get(0);
    let lifecycle_started = scrubbed_any || has_pending_revisions;
    let mut scrub_entry = None;
    if terminal_exists && lifecycle_started {
        // A completed flip manifest must never acquire fresh pre-flip work.
        // Returning before commit rolls back any request scrubs above.
        return Err(FieldEncryptionHistoryErasureError::Unavailable);
    }
    if lifecycle_started {
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_commit_head
                    SET coverage_ready = false,
                        updated_at = transaction_timestamp()
                  WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
        if changed != 1 {
            return Err(FieldEncryptionHistoryErasureError::Unavailable);
        }
        if scrubbed_any {
            record_lifecycle_progress(
                &transaction,
                &lifecycle_reference,
                LifecycleProgressKind::RequestScrub,
                scrubbed_request_target_count,
                scrubbed_request_proposal_count,
            )
            .await?;
            scrub_entry = Some(request_scrub_entry(
                request,
                &lifecycle_reference,
                scrubbed_request_target_count,
                scrubbed_request_proposal_count,
            ));
        }
    }
    let head_incomplete = !head.coverage_ready || head.unavailable_after_position.is_some();
    let needs_rebaseline =
        lifecycle_started || (!terminal_exists && correlated_progress_exists && head_incomplete);
    transaction
        .commit()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    append_maintenance_entries(request.audit, scrub_entry.into_iter().collect()).await?;
    Ok((
        scrubbed_request_target_count,
        scrubbed_request_proposal_count,
        needs_rebaseline,
        lifecycle_reference,
    ))
}

/// Enumerate the records whose retained history still carries a plaintext
/// member a flip declared erase-and-rebaseline for.
///
/// A revision qualifies from durable flip provenance, never from value shape.
/// Indexed revisions precede the flip's exclusive history position. Unindexed
/// revisions are legacy pre-commit-index rows because post-install writes add
/// their commit member atomically. The boundary package itself is excluded, as
/// are later indexed encrypted revisions from subsequent packages.
async fn pending_erase_targets(
    client: &mut Client,
    request: &FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<Vec<PendingEraseTarget>, FieldEncryptionHistoryErasureError> {
    let transaction = client
        .transaction()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&request.lock_key.get()],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;
    let rows = transaction
        .query(
            "WITH pending_boundaries AS (
                 SELECT flip.entity_id, revision.record_id,
                        max(revision.record_revision)::bigint AS pending_boundary
                   FROM registry_internal.registry_field_encryption_flips AS flip
                   JOIN registry_internal.registry_revisions AS revision
                     ON revision.entity_id = flip.entity_id
                   LEFT JOIN registry_internal.registry_revision_commit_members AS member
                     ON member.entity_id = revision.entity_id
                    AND member.record_id = revision.record_id
                    AND member.record_revision = revision.record_revision
                  WHERE flip.history_choice = 'erase-and-rebaseline'
                    AND revision.snapshot IS NOT NULL
                    AND revision.erased_at IS NULL
                    AND revision.package_revision <> flip.boundary_package_revision
                    AND convert_from(revision.snapshot, 'UTF8')::jsonb ? flip.field_id
                    AND (
                        member.commit_position < flip.history_commit_position
                        OR member.commit_position IS NULL
                    )
                  GROUP BY flip.entity_id, revision.record_id
             ), ranked AS (
                 SELECT boundary.entity_id, boundary.record_id,
                        revision.record_revision,
                        row_number() OVER (
                            PARTITION BY boundary.entity_id, boundary.record_id
                            ORDER BY revision.record_revision
                        ) AS revision_ordinal
                   FROM pending_boundaries AS boundary
                   JOIN registry_internal.registry_revisions AS revision
                     ON revision.entity_id = boundary.entity_id
                    AND revision.record_id = boundary.record_id
                    AND revision.record_revision <= boundary.pending_boundary
             )
             SELECT entity_id, record_id, max(record_revision)::bigint
               FROM ranked
              WHERE revision_ordinal <= $1
              GROUP BY entity_id, record_id
              ORDER BY entity_id, record_id
              LIMIT $2",
            &[&MAX_ERASURE_REVISIONS, &MAX_ERASURE_TARGETS_PER_PAGE],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    rows.into_iter()
        .map(|row| {
            Ok(PendingEraseTarget {
                entity_id: row
                    .try_get(0)
                    .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?,
                record_id: row
                    .try_get(1)
                    .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?,
                erase_through_revision: row
                    .try_get(2)
                    .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?,
            })
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FieldEncryptionLifecycleCounts {
    erased_record_count: u64,
    erased_revision_count: u64,
    erased_commit_member_count: u64,
    scrubbed_change_context_count: u64,
    scrubbed_outbox_payload_count: u64,
    scrubbed_cached_response_count: u64,
    scrubbed_request_target_count: u64,
    scrubbed_request_proposal_count: u64,
    removed_descriptor_count: u64,
}

async fn field_encryption_lifecycle_reference_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<String, FieldEncryptionHistoryErasureError> {
    let rows = transaction
        .query(
            "SELECT entity_id, field_id, boundary_package_revision,
                    history_commit_position
               FROM registry_internal.registry_field_encryption_flips
              WHERE history_choice = 'erase-and-rebaseline'
              ORDER BY entity_id, field_id",
            &[],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    let manifest = rows
        .iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, Option<i64>>(3),
            )
        })
        .collect::<Vec<_>>();
    let manifest = serde_json::to_string(&manifest)
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    request
        .audit
        .profile()
        .key_hasher()
        .audit_reference_hash(
            "breg-field-encryption-lifecycle-v1",
            &request.expected.package_id,
            &manifest,
        )
        .map_err(|_| FieldEncryptionHistoryErasureError::InvalidInput)
}

/// Report whether the lifecycle already recorded its terminal step, and
/// whether it recorded any other progress: a per-record erasure or a request
/// scrub. Both facts are durable state written in the commit of the step they
/// describe, never read back from audit output.
async fn lifecycle_progress_state(
    transaction: &tokio_postgres::Transaction<'_>,
    lifecycle_reference: &str,
) -> Result<(bool, bool), FieldEncryptionHistoryErasureError> {
    let row = transaction
        .query_one(
            "SELECT
                 EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_field_encryption_lifecycle_progress
                      WHERE lifecycle_reference = $1
                        AND progress_kind = 'terminal'
                 ),
                 EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_field_encryption_lifecycle_progress
                      WHERE lifecycle_reference = $1
                        AND progress_kind <> 'terminal'
                 )",
            &[&lifecycle_reference],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    Ok((row.get(0), row.get(1)))
}

#[derive(Clone, Copy)]
enum LifecycleProgressKind {
    RequestScrub,
    Terminal,
}

impl LifecycleProgressKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestScrub => "request-scrub",
            Self::Terminal => "terminal",
        }
    }
}

/// Record one lifecycle step in the commit that performs it. Per-record
/// erasures record their own rows through the erasure path.
async fn record_lifecycle_progress(
    transaction: &tokio_postgres::Transaction<'_>,
    lifecycle_reference: &str,
    kind: LifecycleProgressKind,
    scrubbed_request_target_count: u64,
    scrubbed_request_proposal_count: u64,
) -> Result<(), FieldEncryptionHistoryErasureError> {
    let count = |value: u64| {
        i64::try_from(value).map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)
    };
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_lifecycle_progress
                    (lifecycle_reference, progress_kind,
                     scrubbed_request_target_count, scrubbed_request_proposal_count)
             VALUES ($1, $2, $3, $4)",
            &[
                &lifecycle_reference,
                &kind.as_str(),
                &count(scrubbed_request_target_count)?,
                &count(scrubbed_request_proposal_count)?,
            ],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    Ok(())
}

fn request_scrub_entry(
    request: &FieldEncryptionHistoryErasureRequest<'_>,
    lifecycle_reference: &str,
    scrubbed_request_target_count: u64,
    scrubbed_request_proposal_count: u64,
) -> AuditEntry {
    AuditEntry::response(
        FIELD_ENCRYPTION_AUDIT_SCHEMA,
        lifecycle_reference,
        json!({
            "phase": "request-scrub",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
            "lifecycleReference": lifecycle_reference,
            "scrubbedRequestTargetCount": scrubbed_request_target_count,
            "scrubbedRequestProposalCount": scrubbed_request_proposal_count,
        }),
    )
}

async fn aggregate_lifecycle_counts(
    transaction: &tokio_postgres::Transaction<'_>,
    lifecycle_reference: &str,
) -> Result<FieldEncryptionLifecycleCounts, FieldEncryptionHistoryErasureError> {
    let row = transaction
        .query_one(
            "SELECT
                 count(DISTINCT target_record_reference) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 )::bigint,
                 COALESCE(sum(erased_revision_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(erased_commit_member_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_change_context_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_outbox_payload_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_cached_response_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_request_target_count) FILTER (
                     WHERE progress_kind = 'request-scrub'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_request_proposal_count) FILTER (
                     WHERE progress_kind = 'request-scrub'
                 ), 0)::bigint,
                 COALESCE(sum(removed_descriptor_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint
               FROM registry_internal.registry_field_encryption_lifecycle_progress
              WHERE lifecycle_reference = $1",
            &[&lifecycle_reference],
        )
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    let count = |index| {
        u64::try_from(row.get::<_, i64>(index))
            .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)
    };
    Ok(FieldEncryptionLifecycleCounts {
        erased_record_count: count(0)?,
        erased_revision_count: count(1)?,
        erased_commit_member_count: count(2)?,
        scrubbed_change_context_count: count(3)?,
        scrubbed_outbox_payload_count: count(4)?,
        scrubbed_cached_response_count: count(5)?,
        scrubbed_request_target_count: count(6)?,
        scrubbed_request_proposal_count: count(7)?,
        removed_descriptor_count: count(8)?,
    })
}

/// Build the lifecycle's one summary entry. It names counts and hashed
/// references only: which records were erased stays in the per-record erasure
/// entries, and no field value ever reaches the audit log.
fn erase_history_entry(
    request: &FieldEncryptionHistoryErasureRequest<'_>,
    lifecycle_reference: &str,
    outcome: &FieldEncryptionHistoryErasureOutcome,
) -> Result<AuditEntry, FieldEncryptionHistoryErasureError> {
    if !profile_is_keyed(request.audit.profile()) {
        return Err(FieldEncryptionHistoryErasureError::InvalidInput);
    }
    let key_hasher = request.audit.profile().key_hasher();
    let operator_reference = key_hasher
        .audit_reference_hash(
            "breg-field-encryption-operator-v1",
            &request.expected.package_revision,
            request.operator_reference,
        )
        .map_err(|_| FieldEncryptionHistoryErasureError::InvalidInput)?;
    let reason_reference = key_hasher
        .audit_reference_hash(
            "breg-field-encryption-reason-v1",
            &request.expected.package_revision,
            request.reason,
        )
        .map_err(|_| FieldEncryptionHistoryErasureError::InvalidInput)?;
    Ok(AuditEntry::response(
        FIELD_ENCRYPTION_AUDIT_SCHEMA,
        lifecycle_reference,
        json!({
            "phase": "terminal",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
            "lifecycleReference": lifecycle_reference,
            "operatorReference": operator_reference,
            "reasonReference": reason_reference,
            "historyChoice": "erase-and-rebaseline",
            "erasedRecordCount": outcome.erased_record_count,
            "erasedRevisionCount": outcome.erased_revision_count,
            "erasedCommitMemberCount": outcome.erased_commit_member_count,
            "scrubbedChangeContextCount": outcome.scrubbed_change_context_count,
            "scrubbedOutboxPayloadCount": outcome.scrubbed_outbox_payload_count,
            "scrubbedCachedResponseCount": outcome.scrubbed_cached_response_count,
            "scrubbedRequestTargetCount": outcome.scrubbed_request_target_count,
            "scrubbedRequestProposalCount": outcome.scrubbed_request_proposal_count,
            "removedDescriptorCount": outcome.removed_descriptor_count,
            "baselinePosition": outcome.rebaseline.baseline_position,
            "coveragePolicy": "per_record_erasure_then_single_rebaseline",
        }),
    ))
}

fn validate_request(
    request: &FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<(), FieldEncryptionHistoryErasureError> {
    request.expected.validate()?;
    if request.operator_reference.is_empty()
        || request.operator_reference.len() > MAX_OPERATOR_REFERENCE_BYTES
        || request.operator_reference.chars().any(char::is_control)
        || request.reason.is_empty()
        || request.reason.len() > MAX_REASON_BYTES
        || request.reason.chars().any(char::is_control)
        || request.registry.entities().is_empty()
        || !profile_is_keyed(request.audit.profile())
    {
        return Err(FieldEncryptionHistoryErasureError::InvalidInput);
    }
    Ok(())
}
