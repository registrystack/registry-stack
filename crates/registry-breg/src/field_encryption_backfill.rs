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

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_audit::AuditProfile;
use serde::Serialize;
use serde_json::json;
use tokio_postgres::Client;

use crate::history_erasure::{
    erase_record_history, HistoryErasureError, HistoryErasureRequest, RecordHistoryErasureTarget,
};
use crate::history_maintenance::{
    append_audit_envelope, profile_is_keyed, set_local_timeouts, verify_ready_identity,
    HistoryMaintenanceTimeouts,
};
use crate::history_rebaseline::{
    rebaseline_history_coverage, HistoryRebaselineError, HistoryRebaselineOutcome,
    HistoryRebaselineRequest,
};
use crate::migration_plan::{
    ReviewedFieldEncryptionHistory, ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationPlan,
};
use crate::model::CompiledRegistry;
use crate::package::CompiledRegistryMigrationBaseline;
use crate::postgres::{
    covered_field_encryption_fields, field_plaintext_string, prior_plaintext_projection,
    recursive_member_path, verify_migration_role, ConnectionConfig, ExpectedRegistryIdentity,
    FieldEncryptionCoveredField, RegistryLockKey, SqlIdentifier,
};

pub use crate::history_maintenance::HistoryMaintenanceTimeouts as FieldEncryptionBackfillTimeouts;

/// The audit schema every field-encryption lifecycle envelope carries. The
/// shape follows the history maintenance envelopes: actor reference, package
/// revision, step, and counts; field values never cross this boundary.
pub const FIELD_ENCRYPTION_AUDIT_SCHEMA: &str = "breg-field-encryption-audit/v1";

const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;
/// Bound the records one collision report names so a bulk collision cannot
/// flood an operator surface. The apply-side preflight applies the same cap.
const MAX_NAMED_DUPLICATE_RECORDS: usize = 64;
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
        // The plan validation already refused a missing or unmatched history
        // choice, so the apply arm's expectation and this echo agree.
        let history_choice = migration
            .descriptor
            .history
            .ok_or(FieldEncryptionBackfillPreflightError::InvalidInput)?;
        for step in &migration.steps {
            let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { entity_id, .. } =
                &step.descriptor
            else {
                continue;
            };
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
            let mut fields = Vec::new();
            for field in &covered {
                fields.push(
                    field_preflight(&transaction, field, table, request.target_package_revision)
                        .await?,
                );
            }
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
    let field_id = field.candidate.id.as_str();
    let table = SqlIdentifier::parse(table)
        .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?;
    let plaintext_projection = prior_plaintext_projection(field.prior);

    let rows_sql = format!(
        "SELECT record_id::text, {plaintext_projection}
           FROM registry_data.{}
          ORDER BY record_id",
        table.quoted()
    );
    let rows = transaction
        .query(&rows_sql, &[])
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;

    let mut plaintext_row_count = 0_u64;
    // Normalized-duplicate detection needs no key material: the blind index
    // is a deterministic function of the normalized value, so two records
    // collide exactly when their normalized plaintexts are equal.
    let mut normalized_seen = NormalizedSeen::default();
    for row in &rows {
        let record_id: String = row
            .try_get(0)
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
        let value = row
            .try_get::<_, Option<serde_json::Value>>(1)
            .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?
            .unwrap_or(serde_json::Value::Null);
        let Some(plaintext) = field_plaintext_string(field.prior, &value)
            .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?
        else {
            continue;
        };
        plaintext_row_count = plaintext_row_count
            .checked_add(1)
            .ok_or(FieldEncryptionBackfillPreflightError::Unavailable)?;
        if let Some(blind) = field.blind.filter(|blind| blind.unique) {
            let normalized = crate::field_encryption::FieldEncryptionService::normalize(
                &blind.normalization,
                &plaintext,
            );
            normalized_seen.record(normalized, record_id);
        }
    }

    let journal = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND package_revision <> $2
                AND snapshot ? $3",
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
                AND snapshot ? $2
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_request_targets AS target
                     WHERE target.request_entity_id = proposal.request_entity_id
                       AND target.request_id = proposal.request_id
                       AND target.proposal_version = proposal.proposal_version
                       AND target.target_entity_id = $1
                )",
            &[&entity_id, &field_id],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let idempotency = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_idempotency
              WHERE convert_from(response_body, 'UTF8')::jsonb @? $1::jsonpath",
            &[&recursive_member_path(field.api_name)
                .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;
    let outbox = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_outbox
              WHERE payload IS NOT NULL
                AND convert_from(payload, 'UTF8')::jsonb @? $1::jsonpath",
            &[&recursive_member_path(field.api_name)
                .map_err(|_| FieldEncryptionBackfillPreflightError::InvalidInput)?],
        )
        .await
        .map_err(|_| FieldEncryptionBackfillPreflightError::Unavailable)?;

    let duplicate_record_ids = normalized_seen.duplicates();
    let duplicate_record_ids = if duplicate_record_ids.len() > MAX_NAMED_DUPLICATE_RECORDS {
        duplicate_record_ids[..MAX_NAMED_DUPLICATE_RECORDS].to_vec()
    } else {
        duplicate_record_ids
    };

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

/// Normalized plaintext to the first authored record id that carried it. The
/// duplicate list holds record ids only; normalized values are keys and never
/// leave this map.
#[derive(Default)]
struct NormalizedSeen {
    first: BTreeMap<String, String>,
    duplicates: BTreeSet<String>,
}

impl NormalizedSeen {
    fn record(&mut self, normalized: String, record_id: String) {
        match self.first.entry(normalized) {
            std::collections::btree_map::Entry::Occupied(first) => {
                // A value colliding three times names three records, so a
                // collision is counted per record, not per pair.
                self.duplicates.insert(first.get().clone());
                self.duplicates.insert(record_id);
            }
            std::collections::btree_map::Entry::Vacant(first) => {
                first.insert(record_id);
            }
        }
    }

    fn duplicates(&self) -> Vec<String> {
        self.duplicates.iter().cloned().collect()
    }
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
    pub audit_profile: &'a AuditProfile,
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
/// then append the lifecycle's audit envelope. Each per-record erasure and the
/// rebaseline take the Registry advisory transaction lock in turn, so the
/// lifecycle never runs concurrent with an apply that holds the session lock.
pub async fn erase_field_encryption_history(
    client: &mut Client,
    request: FieldEncryptionHistoryErasureRequest<'_>,
) -> Result<FieldEncryptionHistoryErasureOutcome, FieldEncryptionHistoryErasureError> {
    validate_request(&request)?;
    verify_migration_role(client, request.migration_role).await?;

    let targets = pending_erase_targets(client, &request).await?;
    if targets.is_empty() {
        return Err(FieldEncryptionHistoryErasureError::NoPendingPlaintextHistory);
    }

    let mut erased_record_count = 0_u64;
    let mut erased_revision_count = 0_u64;
    let mut erased_commit_member_count = 0_u64;
    let mut scrubbed_change_context_count = 0_u64;
    let mut scrubbed_outbox_payload_count = 0_u64;
    let mut scrubbed_cached_response_count = 0_u64;
    let mut scrubbed_request_target_count = 0_u64;
    let mut scrubbed_request_proposal_count = 0_u64;
    let mut removed_descriptor_count = 0_u64;
    for target in &targets {
        // The erasure path enforces the per-record revision cap and appends
        // its own per-record audit envelope; a refusal stops the lifecycle
        // with the record already erased staying erased, so a re-run resumes.
        let outcome = erase_record_history(
            client,
            HistoryErasureRequest {
                expected: request.expected,
                migration_role: request.migration_role,
                lock_key: request.lock_key,
                timeouts: request.timeouts,
                audit_profile: request.audit_profile,
                operator_reference: request.operator_reference,
                reason: request.reason,
                target: RecordHistoryErasureTarget::new(
                    &target.entity_id,
                    target.record_id,
                    target.erase_through_revision,
                ),
            },
        )
        .await
        .map_err(FieldEncryptionHistoryErasureError::Erasure)?;
        erased_record_count = erased_record_count
            .checked_add(1)
            .ok_or(FieldEncryptionHistoryErasureError::Unavailable)?;
        for (total, part) in [
            (&mut erased_revision_count, outcome.erased_revision_count),
            (
                &mut erased_commit_member_count,
                outcome.erased_commit_member_count,
            ),
            (
                &mut scrubbed_change_context_count,
                outcome.scrubbed_change_context_count,
            ),
            (
                &mut scrubbed_outbox_payload_count,
                outcome.scrubbed_outbox_payload_count,
            ),
            (
                &mut scrubbed_cached_response_count,
                outcome.scrubbed_cached_response_count,
            ),
            (
                &mut scrubbed_request_target_count,
                outcome.scrubbed_request_target_count,
            ),
            (
                &mut scrubbed_request_proposal_count,
                outcome.scrubbed_request_proposal_count,
            ),
            (
                &mut removed_descriptor_count,
                outcome.removed_descriptor_count,
            ),
        ] {
            *total = total
                .checked_add(part)
                .ok_or(FieldEncryptionHistoryErasureError::Unavailable)?;
        }
    }

    let rebaseline = rebaseline_history_coverage(
        client,
        HistoryRebaselineRequest {
            expected: request.expected,
            migration_role: request.migration_role,
            lock_key: request.lock_key,
            timeouts: request.timeouts,
            audit_profile: request.audit_profile,
            operator_reference: request.operator_reference,
            registry: request.registry,
        },
    )
    .await
    .map_err(FieldEncryptionHistoryErasureError::Rebaseline)?;

    let outcome = FieldEncryptionHistoryErasureOutcome {
        erased_record_count,
        erased_revision_count,
        erased_commit_member_count,
        scrubbed_change_context_count,
        scrubbed_outbox_payload_count,
        scrubbed_cached_response_count,
        scrubbed_request_target_count,
        scrubbed_request_proposal_count,
        removed_descriptor_count,
        rebaseline,
    };
    append_erase_history_audit(client, &request, &outcome).await?;
    Ok(outcome)
}

/// Enumerate the records whose retained history still carries a plaintext
/// member a flip declared erase-and-rebaseline for.
///
/// A revision qualifies when its snapshot holds the field member and that
/// member is not a tagged envelope: every post-flip recording, by the runtime
/// or by the backfill itself, is a tagged envelope, so what remains is
/// exactly the pre-flip plaintext the choice declared destroyed. The test
/// reads member shape only; erasure itself stays whole-row and
/// format-agnostic.
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
            "SELECT flip.entity_id, revision.record_id, max(revision.record_revision)::bigint
               FROM registry_internal.registry_field_encryption_flips AS flip
               JOIN registry_internal.registry_revisions AS revision
                 ON revision.entity_id = flip.entity_id
              WHERE flip.history_choice = 'erase-and-rebaseline'
                AND revision.snapshot IS NOT NULL
                AND revision.erased_at IS NULL
                AND convert_from(revision.snapshot, 'UTF8')::jsonb ? flip.field_id
                AND NOT COALESCE(
                    convert_from(revision.snapshot, 'UTF8')::jsonb -> flip.field_id ? $1::text,
                    false)
              GROUP BY flip.entity_id, revision.record_id
              ORDER BY flip.entity_id, revision.record_id",
            &[&registry_platform_crypto::field_encryption::ENVELOPE_MEMBER_TAG],
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

/// Append the lifecycle's one summary envelope. It names counts and hashed
/// references only: which records were erased stays in the per-record erasure
/// envelopes, and no field value ever reaches the audit journal.
async fn append_erase_history_audit(
    client: &mut Client,
    request: &FieldEncryptionHistoryErasureRequest<'_>,
    outcome: &FieldEncryptionHistoryErasureOutcome,
) -> Result<(), FieldEncryptionHistoryErasureError> {
    if !profile_is_keyed(request.audit_profile) {
        return Err(FieldEncryptionHistoryErasureError::InvalidInput);
    }
    let key_hasher = request.audit_profile.key_hasher();
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
    append_audit_envelope(
        &transaction,
        request.audit_profile,
        json!({
            "schema": FIELD_ENCRYPTION_AUDIT_SCHEMA,
            "phase": "terminal",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
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
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| FieldEncryptionHistoryErasureError::Unavailable)?;
    Ok(())
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
        || !profile_is_keyed(request.audit_profile)
    {
        return Err(FieldEncryptionHistoryErasureError::InvalidInput);
    }
    Ok(())
}
