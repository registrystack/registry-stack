// SPDX-License-Identifier: Apache-2.0
//! History readiness checks for reviewed package migrations.
//!
//! A reviewed migration can update stored records only when history can record
//! the same change as first-class internal revisions. The package verifier and
//! migration ledger already prove SQL closure and affected-row bounds. This
//! module adds the narrower history contract: supported data-changing steps
//! must identify one retained entity table, carry explicit row bounds, and run
//! through a bounded pre/post row capture before the step is committed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::contract::FieldTypeSource;
use crate::history_commit::{
    allocate_revision_commit, install_history_commit_schema, load_history_head, CommitAllocation,
    HistoryCommitError, RevisionCommitMember,
};
use crate::history_context::CommitOrigin;
use crate::history_schema::HistorySchemaDescriptor;
use crate::history_store::{
    install_history_schema_store, load_descriptor, retain_verified_descriptor,
};
use crate::migration_plan::{
    AffectedRowBounds, ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationStep,
};
use crate::model::{CompiledEntity, CompiledField, CompiledRegistry};
use crate::package::CompiledRegistryMigrationBaseline;
use crate::postgres::{ExpectedRegistryIdentity, SqlIdentifier};
use crate::revision::{
    canonical_snapshot, insert_internal_migration_revision, InternalMigrationRevisionInsert,
};

#[cfg(feature = "runtime")]
use tokio_postgres::Transaction;

pub(crate) const HISTORY_MIGRATION_SYSTEM_ORIGIN: &str = "breg-reviewed-migration-v1";
pub const MAX_HISTORY_MIGRATION_COMMIT_MEMBERS: u64 = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SupportedHistoryMigrationStep {
    pub(crate) descriptor_path: String,
    pub(crate) step_id: String,
    pub(crate) entity_id: String,
    pub(crate) physical_table: String,
    pub(crate) affected_rows: AffectedRowBounds,
}

impl SupportedHistoryMigrationStep {
    #[must_use]
    pub(crate) fn migration_reference(&self) -> String {
        format!("{}#{}", self.descriptor_path, self.step_id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum HistoryMigrationError {
    #[error("reviewed transactional SQL must declare affected-row bounds for history")]
    UnboundedTransactionalSql,
    #[error("reviewed transactional SQL must name at least one data object")]
    EmptyObjectSet,
    #[error("history migration can only update registry_data entity tables")]
    UnsupportedObject,
    #[error("history migration supports one retained entity per transactional step")]
    CrossEntityStep,
    #[error("history migration supports one physical table per transactional step")]
    CrossTableStep,
    #[error("history migration affected-row bounds are invalid")]
    InvalidAffectedRows,
    #[error("history migration supports only direct reviewed UPDATE statements")]
    UnsupportedSqlShape,
    #[error("history migration table exceeds the declared affected-row budget")]
    TableBudgetExceeded,
    #[error("history migration baseline exceeds the supported row budget")]
    BaselineBudgetExceeded,
    #[error("history migration changed record identity or lifecycle metadata")]
    UnexpectedRowShape,
    #[error("history migration could not append internal revisions")]
    RevisionUnavailable,
}

pub(crate) type Result<T> = std::result::Result<T, HistoryMigrationError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedHistoryUpdateCapture {
    step: SupportedHistoryMigrationStep,
    rows: BTreeMap<Uuid, CapturedEntityRow>,
}

/// The page-scoped capture one reviewed chunk journals: exactly the rows the
/// chunk selected, locked, and rewrote in this transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReviewedPageCapture {
    step: SupportedHistoryMigrationStep,
    rows: BTreeMap<Uuid, CapturedEntityRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedEntityRow {
    record_revision: i64,
    record_lifecycle: String,
    active_package_revision: String,
    data: Map<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LatestRevisionBinding {
    record_reference: String,
    record_revision: i64,
    record_lifecycle: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LatestRevisionSnapshot {
    record_revision: i64,
    record_lifecycle: String,
    package_revision: String,
    snapshot: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BaselineMember {
    pub(crate) entity_id: String,
    pub(crate) record_id: Uuid,
    pub(crate) record_revision: i64,
}

#[cfg(feature = "runtime")]
pub(crate) async fn prepare_bounded_history_update(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    descriptor_path: &str,
    step: &ValidatedReviewedMigrationStep,
) -> Result<BoundedHistoryUpdateCapture> {
    let supported = classify_reviewed_history_step(descriptor_path, step)?;
    validate_reviewed_update_sql(&step.sql)?;
    let entity = entity_for_step(registry, &supported)?;
    let row_count = count_entity_rows(transaction, entity).await?;
    if row_count > supported.affected_rows.max {
        return Err(HistoryMigrationError::TableBudgetExceeded);
    }
    let rows = capture_entity_rows(transaction, entity, true).await?;
    Ok(BoundedHistoryUpdateCapture {
        step: supported,
        rows,
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn ensure_successor_history_ready(
    transaction: &Transaction<'_>,
    current: &ExpectedRegistryIdentity,
    predecessor_baseline: Option<&CompiledRegistryMigrationBaseline>,
    predecessor_descriptor: Option<&HistorySchemaDescriptor>,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_history_schema_store(transaction, runtime_role)
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    install_history_commit_schema(transaction, runtime_role)
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;

    match load_history_head(transaction).await {
        Ok(_head) => {
            let retained = load_descriptor(transaction, &current.package_revision)
                .await
                .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
            if predecessor_descriptor.is_some_and(|expected| expected != &retained) {
                return Err(HistoryMigrationError::RevisionUnavailable);
            }
            Ok(())
        }
        Err(HistoryCommitError::NotReady) => {
            establish_existing_history_baseline(
                transaction,
                current,
                predecessor_baseline.ok_or(HistoryMigrationError::RevisionUnavailable)?,
                predecessor_descriptor.ok_or(HistoryMigrationError::RevisionUnavailable)?,
            )
            .await
        }
        Err(_) => Err(HistoryMigrationError::RevisionUnavailable),
    }
}

#[cfg(feature = "runtime")]
pub(crate) async fn finish_bounded_history_update(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    package_revision: &str,
    capture: BoundedHistoryUpdateCapture,
) -> Result<u64> {
    if package_revision.is_empty() {
        return Err(HistoryMigrationError::RevisionUnavailable);
    }
    let entity = entity_for_step(registry, &capture.step)?;
    let post_rows = capture_entity_rows(transaction, entity, false).await?;
    journal_captured_changes(
        transaction,
        &capture.step,
        capture.rows,
        post_rows,
        package_revision,
    )
    .await
}

/// Capture the pre-change rows of one chunk page of a reviewed chunked
/// backfill or a field-encryption backfill. The step's classified entity is
/// the successor registry's entity, so encrypted fields project their envelope
/// column and the capture is already in journal shape.
#[cfg(feature = "runtime")]
pub(crate) async fn prepare_reviewed_page_capture(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    descriptor_path: &str,
    step: &ValidatedReviewedMigrationStep,
    page: &[Uuid],
) -> Result<ReviewedPageCapture> {
    let supported = check_reviewed_history_step(descriptor_path, step)?;
    let page_len =
        u64::try_from(page.len()).map_err(|_| HistoryMigrationError::InvalidAffectedRows)?;
    if page_len > supported.affected_rows.max {
        return Err(HistoryMigrationError::InvalidAffectedRows);
    }
    let entity = entity_for_step(registry, &supported)?;
    let rows = capture_entity_rows_page(transaction, entity, page).await?;
    Ok(ReviewedPageCapture {
        step: supported,
        rows,
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn finish_reviewed_page_update(
    transaction: &Transaction<'_>,
    registry: &CompiledRegistry,
    package_revision: &str,
    capture: ReviewedPageCapture,
) -> Result<u64> {
    if package_revision.is_empty() {
        return Err(HistoryMigrationError::RevisionUnavailable);
    }
    let entity = entity_for_step(registry, &capture.step)?;
    let post_rows = capture_entity_rows_page(
        transaction,
        entity,
        &capture.rows.keys().copied().collect::<Vec<_>>(),
    )
    .await?;
    journal_captured_changes(
        transaction,
        &capture.step,
        capture.rows,
        post_rows,
        package_revision,
    )
    .await
}

/// Diff captured before rows against their post-change rows and record the
/// change as first-class internal revisions: one revision per changed row,
/// metadata bump per changed row, then one migration commit for the whole set.
#[cfg(feature = "runtime")]
async fn journal_captured_changes(
    transaction: &Transaction<'_>,
    step: &SupportedHistoryMigrationStep,
    before_rows: BTreeMap<Uuid, CapturedEntityRow>,
    post_rows: BTreeMap<Uuid, CapturedEntityRow>,
    package_revision: &str,
) -> Result<u64> {
    if before_rows.keys().ne(post_rows.keys()) {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }

    let migration_reference = step.migration_reference();
    let mut changed = Vec::new();
    for (record_id, before) in &before_rows {
        let after = post_rows
            .get(record_id)
            .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
        if before.record_revision != after.record_revision
            || before.record_lifecycle != after.record_lifecycle
            || before.active_package_revision != after.active_package_revision
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        if before.data == after.data {
            continue;
        }
        let next_revision = before
            .record_revision
            .checked_add(1)
            .ok_or(HistoryMigrationError::RevisionUnavailable)?;
        let latest = load_latest_revision_binding(transaction, &step.entity_id, *record_id).await?;
        if latest.record_revision != before.record_revision
            || latest.record_lifecycle != before.record_lifecycle
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        update_history_migrated_row_metadata(
            transaction,
            &step.physical_table,
            *record_id,
            before.record_revision,
            &before.record_lifecycle,
            &before.active_package_revision,
            next_revision,
            package_revision,
        )
        .await?;
        let snapshot = canonical_snapshot(&after.data)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        insert_internal_migration_revision(
            transaction,
            InternalMigrationRevisionInsert {
                entity_id: &step.entity_id,
                record_id: *record_id,
                record_reference: &latest.record_reference,
                record_revision: next_revision,
                predecessor_revision: before.record_revision,
                lifecycle: &before.record_lifecycle,
                package_revision,
                system_origin: HISTORY_MIGRATION_SYSTEM_ORIGIN,
                migration_reference: &migration_reference,
                snapshot: &snapshot,
            },
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        changed.push((*record_id, next_revision));
    }

    if changed.is_empty() {
        return Ok(0);
    }
    let members = changed
        .iter()
        .map(|(record_id, record_revision)| RevisionCommitMember {
            entity_id: step.entity_id.as_str(),
            record_id: *record_id,
            record_revision: *record_revision,
        })
        .collect::<Vec<_>>();
    allocate_revision_commit(
        transaction,
        CommitAllocation {
            package_revision,
            origin: CommitOrigin::Migration {
                system_origin: HISTORY_MIGRATION_SYSTEM_ORIGIN,
                migration_reference: Some(&migration_reference),
            },
            change_context: None,
            members: &members,
        },
    )
    .await
    .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    u64::try_from(changed.len()).map_err(|_| HistoryMigrationError::RevisionUnavailable)
}

#[cfg(feature = "runtime")]
async fn establish_existing_history_baseline(
    transaction: &Transaction<'_>,
    current: &ExpectedRegistryIdentity,
    predecessor_baseline: &CompiledRegistryMigrationBaseline,
    predecessor_descriptor: &HistorySchemaDescriptor,
) -> Result<()> {
    if predecessor_baseline.package_revision != current.package_revision
        || predecessor_descriptor.package_revision != current.package_revision
    {
        return Err(HistoryMigrationError::RevisionUnavailable);
    }
    retain_verified_descriptor(transaction, predecessor_descriptor)
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    verify_revision_journal_uses_active_descriptor(transaction, predecessor_baseline).await?;
    let members = verify_live_rows_match_journal_heads(
        transaction,
        &predecessor_baseline.entities,
        Some(&predecessor_baseline.package_revision),
    )
    .await?;
    insert_existing_history_baseline(transaction, &current.package_revision, &members).await
}

/// Prove the retained journal head of every live row reproduces that row, and
/// return the members a baseline commit would index.
///
/// `required_package_revision` pins every journal head to one package revision,
/// as an existing-data migration baseline requires. A live registry whose
/// journal legitimately spans several package revisions passes `None`; each
/// head keeps its own retained descriptor either way.
#[cfg(feature = "runtime")]
pub(crate) async fn verify_live_rows_match_journal_heads(
    transaction: &Transaction<'_>,
    entities: &BTreeMap<String, CompiledEntity>,
    required_package_revision: Option<&str>,
) -> Result<Vec<BaselineMember>> {
    let expected_members = count_baseline_members(transaction, entities).await?;
    let mut members = Vec::with_capacity(
        usize::try_from(expected_members)
            .map_err(|_| HistoryMigrationError::BaselineBudgetExceeded)?,
    );
    for entity in entities.values() {
        let live_rows = capture_entity_rows(transaction, entity, true).await?;
        let latest_revisions =
            load_latest_revision_snapshots(transaction, &entity.id, None).await?;
        if live_rows.keys().ne(latest_revisions.keys()) {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        for (record_id, live) in live_rows {
            let latest = latest_revisions
                .get(&record_id)
                .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
            verify_journal_head_reproduces_live_row(&live, latest, required_package_revision)?;
            members.push(BaselineMember {
                entity_id: entity.id.clone(),
                record_id,
                record_revision: live.record_revision,
            });
        }
    }
    Ok(members)
}

/// The live rows one page of [`verify_every_live_row_matches_its_journal_head`]
/// reads, and the journal heads it loads beside them.
#[cfg(feature = "runtime")]
const LIVE_ROW_VERIFICATION_PAGE_ROWS: i64 = 1_000;

/// Prove the retained journal head of every live row reproduces that row, and
/// that every retained journal head still has its live row, page by page.
/// Returns how many live rows were verified.
///
/// Each entity table is locked against writes before its first page, so every
/// page reads one stable state for the rest of the caller's transaction. A
/// caller that has already lifted forced row security on the entity tables
/// holds them exclusively, reads included, and this lock adds nothing to that.
/// Every statement reads one page: at most [`LIVE_ROW_VERIFICATION_PAGE_ROWS`]
/// live rows, their journal heads, and the retained heads whose record
/// identifiers fall in the page's key range, so the number of live rows is not
/// bounded here and no statement scans an entity's whole history. Nothing is
/// collected for a commit: a caller that must index the live rows as members
/// uses [`verify_live_rows_match_journal_heads`], which the commit-member budget
/// bounds.
#[cfg(feature = "runtime")]
pub(crate) async fn verify_every_live_row_matches_its_journal_head(
    transaction: &Transaction<'_>,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<u64> {
    let mut verified = 0_u64;
    for entity in entities.values() {
        let table_name = SqlIdentifier::parse(&entity.physical_table)
            .map_err(|_| HistoryMigrationError::UnsupportedObject)?;
        transaction
            .batch_execute(&format!(
                "LOCK TABLE registry_data.{} IN SHARE ROW EXCLUSIVE MODE",
                table_name.quoted()
            ))
            .await
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let projection = history_returning_projection(entity);
        let mut after: Option<Uuid> = None;
        loop {
            let rows = transaction
                .query(
                    &format!(
                        "SELECT {projection}
                           FROM registry_data.{}
                          WHERE $1::uuid IS NULL OR record_id > $1::uuid
                          ORDER BY record_id
                          LIMIT $2",
                        table_name.quoted()
                    ),
                    &[&after, &LIVE_ROW_VERIFICATION_PAGE_ROWS],
                )
                .await
                .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
            let fetched = rows.len();
            let live_rows = decode_captured_rows(rows, entity)?;
            let Some(last) = live_rows.keys().next_back().copied() else {
                break;
            };
            let page = live_rows.keys().copied().collect::<Vec<_>>();
            let latest_revisions =
                load_latest_revision_snapshots(transaction, &entity.id, Some(&page)).await?;
            if live_rows.keys().ne(latest_revisions.keys()) {
                return Err(HistoryMigrationError::UnexpectedRowShape);
            }
            for (record_id, live) in &live_rows {
                let latest = latest_revisions
                    .get(record_id)
                    .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
                verify_journal_head_reproduces_live_row(live, latest, None)?;
            }
            let page_rows = u64::try_from(live_rows.len())
                .map_err(|_| HistoryMigrationError::UnexpectedRowShape)?;
            // Every live row of the page has a journal head, proved above, so
            // an equal count of retained heads across the page's key range
            // leaves no head there without its live row.
            if count_retained_journal_heads_in_range(transaction, &entity.id, after, Some(last))
                .await?
                != page_rows
            {
                return Err(HistoryMigrationError::UnexpectedRowShape);
            }
            verified = verified
                .checked_add(page_rows)
                .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
            after = Some(last);
            if i64::try_from(fetched).map_or(true, |count| count < LIVE_ROW_VERIFICATION_PAGE_ROWS)
            {
                break;
            }
        }
        // No live row lies past the last page, so no retained head may either.
        if count_retained_journal_heads_in_range(transaction, &entity.id, after, None).await? != 0 {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
    }
    Ok(verified)
}

/// Count the distinct records holding a retained journal head for one entity
/// whose identifiers lie after `after` and up to `through`, either bound open
/// when absent. The primary key leads with the entity and record identifiers,
/// so the count reads only that key range.
#[cfg(feature = "runtime")]
async fn count_retained_journal_heads_in_range(
    transaction: &Transaction<'_>,
    entity_id: &str,
    after: Option<Uuid>,
    through: Option<Uuid>,
) -> Result<u64> {
    let count = transaction
        .query_one(
            "SELECT count(DISTINCT record_id)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND ($2::uuid IS NULL OR record_id > $2::uuid)
                AND ($3::uuid IS NULL OR record_id <= $3::uuid)",
            &[&entity_id, &after, &through],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?
        .try_get::<_, i64>(0)
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    u64::try_from(count).map_err(|_| HistoryMigrationError::UnexpectedRowShape)
}

#[cfg(feature = "runtime")]
fn verify_journal_head_reproduces_live_row(
    live: &CapturedEntityRow,
    latest: &LatestRevisionSnapshot,
    required_package_revision: Option<&str>,
) -> Result<()> {
    let snapshot =
        canonical_snapshot(&live.data).map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    if live.record_revision != latest.record_revision
        || live.record_lifecycle != latest.record_lifecycle
        || required_package_revision.is_some_and(|required| latest.package_revision != required)
        || snapshot != latest.snapshot
    {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
async fn verify_revision_journal_uses_active_descriptor(
    transaction: &Transaction<'_>,
    predecessor_baseline: &CompiledRegistryMigrationBaseline,
) -> Result<()> {
    let rows = transaction
        .query(
            "SELECT DISTINCT entity_id, package_revision
               FROM registry_internal.registry_revisions
              ORDER BY entity_id, package_revision",
            &[],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    for row in rows {
        let entity_id = row
            .try_get::<_, String>(0)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let package_revision = row
            .try_get::<_, String>(1)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        if entity_id.is_empty()
            || package_revision.is_empty()
            || !predecessor_baseline.entities.contains_key(&entity_id)
            || package_revision != predecessor_baseline.package_revision
        {
            return Err(HistoryMigrationError::RevisionUnavailable);
        }
    }
    Ok(())
}

#[cfg(feature = "runtime")]
async fn count_baseline_members(
    transaction: &Transaction<'_>,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<u64> {
    let mut total = 0_u64;
    for entity in entities.values() {
        let count = count_entity_rows(transaction, entity).await?;
        total = total
            .checked_add(count)
            .ok_or(HistoryMigrationError::BaselineBudgetExceeded)?;
        if total > MAX_HISTORY_MIGRATION_COMMIT_MEMBERS {
            return Err(HistoryMigrationError::BaselineBudgetExceeded);
        }
    }
    Ok(total)
}

#[cfg(feature = "runtime")]
async fn count_entity_rows(transaction: &Transaction<'_>, entity: &CompiledEntity) -> Result<u64> {
    let table_name = SqlIdentifier::parse(&entity.physical_table)
        .map_err(|_| HistoryMigrationError::UnsupportedObject)?;
    let row_count = transaction
        .query_one(
            &format!(
                "SELECT count(*)::bigint FROM registry_data.{}",
                table_name.quoted()
            ),
            &[],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?
        .get::<_, i64>(0);
    if row_count < 0 {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }
    u64::try_from(row_count).map_err(|_| HistoryMigrationError::UnexpectedRowShape)
}

#[cfg(feature = "runtime")]
async fn load_latest_revision_snapshots(
    transaction: &Transaction<'_>,
    entity_id: &str,
    records: Option<&[Uuid]>,
) -> Result<BTreeMap<Uuid, LatestRevisionSnapshot>> {
    let rows = transaction
        .query(
            "SELECT DISTINCT ON (record_id)
                    record_id, record_revision, record_lifecycle, package_revision, snapshot
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND ($2::uuid[] IS NULL OR record_id = ANY($2::uuid[]))
              ORDER BY record_id, record_revision DESC",
            &[&entity_id, &records],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    let mut revisions = BTreeMap::new();
    for row in rows {
        let record_id = row
            .try_get::<_, Uuid>(0)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let record_revision = row
            .try_get::<_, i64>(1)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let record_lifecycle = row
            .try_get::<_, String>(2)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let package_revision = row
            .try_get::<_, String>(3)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let snapshot = row
            .try_get::<_, Vec<u8>>(4)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        if record_revision <= 0
            || !matches!(record_lifecycle.as_str(), "active" | "tombstoned")
            || package_revision.is_empty()
            || snapshot.is_empty()
            || revisions
                .insert(
                    record_id,
                    LatestRevisionSnapshot {
                        record_revision,
                        record_lifecycle,
                        package_revision,
                        snapshot,
                    },
                )
                .is_some()
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
    }
    Ok(revisions)
}

#[cfg(feature = "runtime")]
async fn insert_existing_history_baseline(
    transaction: &Transaction<'_>,
    package_revision: &str,
    members: &[BaselineMember],
) -> Result<()> {
    let history_lineage = Uuid::new_v4();
    let change_id = Uuid::new_v4();
    let snapshot_reference = Uuid::new_v4();
    let system_origin = "breg-existing-history-baseline-v1";
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_commit_head
                 (singleton, history_lineage, latest_position,
                  coverage_baseline_position, coverage_ready)
             VALUES (true, $1, 0, 0, true)",
            &[&history_lineage],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commits
                 (commit_position, change_id, snapshot_reference, history_lineage,
                  originating_package_revision, origin_kind, system_origin,
                  baseline_reference, establishes_baseline)
             VALUES (0, $1, $2, $3, $4, 'baseline', $5, $5, true)",
            &[
                &change_id,
                &snapshot_reference,
                &history_lineage,
                &package_revision,
                &system_origin,
            ],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    for (index, member) in members.iter().enumerate() {
        let member_index =
            i32::try_from(index).map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revision_commit_members
                     (entity_id, record_id, record_revision, commit_position, member_index)
                 VALUES ($1, $2, $3, 0, $4)",
                &[
                    &member.entity_id,
                    &member.record_id,
                    &member.record_revision,
                    &member_index,
                ],
            )
            .await
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    }
    Ok(())
}

fn classify_reviewed_history_step(
    descriptor_path: &str,
    step: &ValidatedReviewedMigrationStep,
) -> Result<SupportedHistoryMigrationStep> {
    match &step.descriptor {
        ReviewedMigrationStepDescriptor::TransactionalSql {
            id,
            objects,
            affected_rows,
            ..
        } => {
            let affected_rows =
                affected_rows.ok_or(HistoryMigrationError::UnboundedTransactionalSql)?;
            if affected_rows.min > affected_rows.max
                || affected_rows.max == 0
                || affected_rows.max > MAX_HISTORY_MIGRATION_COMMIT_MEMBERS
            {
                return Err(HistoryMigrationError::InvalidAffectedRows);
            }
            let (entity_id, physical_table) = classify_step_objects(objects)?;
            Ok(SupportedHistoryMigrationStep {
                descriptor_path: descriptor_path.to_owned(),
                step_id: id.clone(),
                entity_id,
                physical_table,
                affected_rows,
            })
        }
        ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id,
            entity_id,
            objects,
            chunk_size,
            ..
        } => {
            let chunk_size = u64::from(*chunk_size);
            // One chunk's changed rows are one commit's member set, so the
            // commit-member budget bounds the chunk size.
            if chunk_size == 0 || chunk_size > MAX_HISTORY_MIGRATION_COMMIT_MEMBERS {
                return Err(HistoryMigrationError::InvalidAffectedRows);
            }
            let (object_entity_id, physical_table) = classify_step_objects(objects)?;
            if &object_entity_id != entity_id {
                return Err(HistoryMigrationError::CrossEntityStep);
            }
            Ok(SupportedHistoryMigrationStep {
                descriptor_path: descriptor_path.to_owned(),
                step_id: id.clone(),
                entity_id: object_entity_id,
                physical_table,
                affected_rows: AffectedRowBounds {
                    min: 0,
                    max: chunk_size,
                },
            })
        }
        ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
            id,
            objects,
            chunk_size,
            ..
        } => {
            let chunk_size = u64::from(*chunk_size);
            // One chunk's page is one commit's member set, so the page bound is
            // the chunk size and the commit-member budget bounds it again.
            if chunk_size == 0 || chunk_size > MAX_HISTORY_MIGRATION_COMMIT_MEMBERS {
                return Err(HistoryMigrationError::InvalidAffectedRows);
            }
            let (entity_id, physical_table) = classify_step_objects(objects)?;
            Ok(SupportedHistoryMigrationStep {
                descriptor_path: descriptor_path.to_owned(),
                step_id: id.clone(),
                entity_id,
                physical_table,
                affected_rows: AffectedRowBounds {
                    min: 0,
                    max: chunk_size,
                },
            })
        }
    }
}

fn classify_step_objects(
    objects: &[crate::migration_plan::ReviewedMigrationObject],
) -> Result<(String, String)> {
    if objects.is_empty() {
        return Err(HistoryMigrationError::EmptyObjectSet);
    }

    let mut entity_ids = BTreeSet::new();
    let mut tables = BTreeSet::new();
    for object in objects {
        if object.schema != "registry_data"
            || object.entity_id.is_empty()
            || object.table.is_empty()
        {
            return Err(HistoryMigrationError::UnsupportedObject);
        }
        entity_ids.insert(object.entity_id.clone());
        tables.insert(object.table.clone());
    }
    if entity_ids.len() != 1 {
        return Err(HistoryMigrationError::CrossEntityStep);
    }
    if tables.len() != 1 {
        return Err(HistoryMigrationError::CrossTableStep);
    }

    let entity_id = entity_ids
        .into_iter()
        .next()
        .ok_or(HistoryMigrationError::UnsupportedObject)?;
    let physical_table = tables
        .into_iter()
        .next()
        .ok_or(HistoryMigrationError::UnsupportedObject)?;
    Ok((entity_id, physical_table))
}

/// Classify a reviewed step apply journals and check its authored SQL has the
/// shape the journal accepts, without touching the database. Activation runs
/// this before a journaled step changes a row, and `bregctl test` runs it
/// during the rehearsal, so both refuse the same steps.
pub(crate) fn check_reviewed_history_step(
    descriptor_path: &str,
    step: &ValidatedReviewedMigrationStep,
) -> Result<SupportedHistoryMigrationStep> {
    let supported = classify_reviewed_history_step(descriptor_path, step)?;
    match &step.descriptor {
        ReviewedMigrationStepDescriptor::TransactionalSql { .. } => {
            validate_reviewed_update_sql(&step.sql)?;
        }
        ReviewedMigrationStepDescriptor::ChunkedBackfill { .. } => {
            validate_reviewed_chunk_sql(&step.sql)?;
        }
        // The engine writes the field-encryption statement; no authored SQL.
        ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. } => {}
    }
    Ok(supported)
}

/// Statements a reviewed update may not contain, and the record metadata only
/// the journal may write, each matched as a whole word.
const REFUSED_REVIEWED_UPDATE_WORDS: [&str; 12] = [
    "insert",
    "delete",
    "truncate",
    "alter",
    "drop",
    "create",
    "merge",
    "record_revision",
    "record_lifecycle",
    "active_package_revision",
    "created_at",
    "updated_at",
];

fn validate_reviewed_update_sql(sql: &str) -> Result<()> {
    let words = reviewed_update_words(sql)?;
    if words.iter().any(|word| word == "record_id") {
        return Err(HistoryMigrationError::UnsupportedSqlShape);
    }
    Ok(())
}

/// A chunked backfill binds its page of record identifiers as `$1`, so it may
/// name `record_id`; every other refusal of a reviewed update still applies.
fn validate_reviewed_chunk_sql(sql: &str) -> Result<()> {
    reviewed_update_words(sql).map(|_| ())
}

/// The lowercased words of one reviewed update statement, refused unless the
/// statement starts with `UPDATE`, holds no second statement, and names no
/// refused word. This is a lexical first check only: activation parses the
/// statement and pins its shape, and the journal refuses a step that changes
/// record metadata.
fn reviewed_update_words(sql: &str) -> Result<Vec<String>> {
    // A statement the scan cannot delimit with certainty is read as written,
    // so a leading comment then refuses it and every word inside its literals
    // counts.
    let text = mask_comments_and_literals(sql).unwrap_or_else(|| sql.to_owned());
    let statement = text.trim().trim_end_matches(';').trim();
    if statement.contains(';') {
        return Err(HistoryMigrationError::UnsupportedSqlShape);
    }
    let words = statement
        // `$` splits words here, so a dollar-quoted body read as written
        // still exposes the words inside it.
        .split(|character: char| character == '$' || !is_sql_word_character(character))
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let starts_with_update = statement
        .get(..6)
        .is_some_and(|first| first.eq_ignore_ascii_case("update"))
        && words.first().is_some_and(|word| word == "update");
    if !starts_with_update
        || words
            .iter()
            .any(|word| REFUSED_REVIEWED_UPDATE_WORDS.contains(&word.as_str()))
    {
        return Err(HistoryMigrationError::UnsupportedSqlShape);
    }
    Ok(words)
}

fn is_sql_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || character == '_'
        || character == '$'
        || !character.is_ascii()
}

/// Replace comments and the contents of plain string literals with a space and
/// keep a quoted identifier's name as a word. Returns `None` when the statement
/// holds a construct whose extent depends on server settings or on a tag this
/// scan would have to trust: a dollar-quoted body, a backslash inside a quoted
/// literal, or an unterminated comment, literal, or identifier.
fn mask_comments_and_literals(sql: &str) -> Option<String> {
    let characters = sql.chars().collect::<Vec<_>>();
    let mut masked = String::with_capacity(sql.len());
    let mut index = 0;
    while let Some(&character) = characters.get(index) {
        let next = characters.get(index + 1).copied();
        match character {
            '-' if next == Some('-') => {
                while characters.get(index).is_some_and(|&c| c != '\n') {
                    index += 1;
                }
                masked.push(' ');
            }
            '/' if next == Some('*') => {
                let mut depth = 0_usize;
                loop {
                    match (characters.get(index), characters.get(index + 1)) {
                        (Some('/'), Some('*')) => {
                            depth += 1;
                            index += 2;
                        }
                        (Some('*'), Some('/')) => {
                            depth -= 1;
                            index += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        (Some(_), _) => index += 1,
                        (None, _) => return None,
                    }
                }
                masked.push(' ');
            }
            '\'' | '"' => {
                let mut name = String::new();
                index += 1;
                loop {
                    match (characters.get(index), characters.get(index + 1)) {
                        (Some('\\'), _) => return None,
                        (Some(&c), Some(&following))
                            if c == character && following == character =>
                        {
                            name.push(c);
                            index += 2;
                        }
                        (Some(&c), _) if c == character => {
                            index += 1;
                            break;
                        }
                        (Some(&c), _) => {
                            name.push(c);
                            index += 1;
                        }
                        (None, _) => return None,
                    }
                }
                masked.push(' ');
                if character == '"' {
                    masked.push_str(&name);
                    masked.push(' ');
                }
            }
            '$' => {
                let follows_word = index > 0 && is_sql_word_character(characters[index - 1]);
                if !follows_word && !next.is_some_and(|c| c.is_ascii_digit()) {
                    return None;
                }
                masked.push(character);
                index += 1;
            }
            _ => {
                masked.push(character);
                index += 1;
            }
        }
    }
    Some(masked)
}

fn entity_for_step<'a>(
    registry: &'a CompiledRegistry,
    step: &SupportedHistoryMigrationStep,
) -> Result<&'a CompiledEntity> {
    let entity = registry
        .entities()
        .get(&step.entity_id)
        .ok_or(HistoryMigrationError::UnsupportedObject)?;
    if entity.physical_table != step.physical_table {
        return Err(HistoryMigrationError::UnsupportedObject);
    }
    Ok(entity)
}

#[cfg(feature = "runtime")]
async fn capture_entity_rows(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    lock_rows: bool,
) -> Result<BTreeMap<Uuid, CapturedEntityRow>> {
    let table_name = SqlIdentifier::parse(&entity.physical_table)
        .map_err(|_| HistoryMigrationError::UnsupportedObject)?;
    let projection = history_returning_projection(entity);
    if lock_rows {
        transaction
            .batch_execute(&format!(
                "LOCK TABLE registry_data.{} IN SHARE ROW EXCLUSIVE MODE",
                table_name.quoted()
            ))
            .await
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    }
    let lock_clause = if lock_rows { " FOR UPDATE" } else { "" };
    let rows = transaction
        .query(
            &format!(
                "SELECT {projection}
                   FROM registry_data.{}
                  ORDER BY record_id{lock_clause}",
                table_name.quoted()
            ),
            &[],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    decode_captured_rows(rows, entity)
}

/// Capture exactly the rows one reviewed chunk selected and locked in this
/// transaction. The caller holds the page's row locks, so no table lock
/// or re-lock is needed here.
#[cfg(feature = "runtime")]
async fn capture_entity_rows_page(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    page: &[Uuid],
) -> Result<BTreeMap<Uuid, CapturedEntityRow>> {
    let table_name = SqlIdentifier::parse(&entity.physical_table)
        .map_err(|_| HistoryMigrationError::UnsupportedObject)?;
    let projection = history_returning_projection(entity);
    let rows = transaction
        .query(
            &format!(
                "SELECT {projection}
                   FROM registry_data.{}
                  WHERE record_id = ANY($1)
                  ORDER BY record_id",
                table_name.quoted()
            ),
            &[&page],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    let captured = decode_captured_rows(rows, entity)?;
    if captured.len() != page.len() {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }
    Ok(captured)
}

#[cfg(feature = "runtime")]
fn decode_captured_rows(
    rows: Vec<tokio_postgres::Row>,
    entity: &CompiledEntity,
) -> Result<BTreeMap<Uuid, CapturedEntityRow>> {
    let mut captured = BTreeMap::new();
    for row in rows {
        let record_id = row
            .try_get::<_, String>(0)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let record_revision = row
            .try_get::<_, i64>(1)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let record_lifecycle = row
            .try_get::<_, String>(2)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let active_package_revision = row
            .try_get::<_, String>(3)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        let record_uuid =
            Uuid::parse_str(&record_id).map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
        if record_uuid.to_string() != record_id
            || record_revision <= 0
            || !matches!(record_lifecycle.as_str(), "active" | "tombstoned")
            || active_package_revision.is_empty()
            || row.len() != entity.fields.len() + 4
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        let mut data = Map::new();
        for (index, field) in entity.fields.values().enumerate() {
            let value = row
                .try_get::<_, Option<Value>>(index + 4)
                .map_err(|_| HistoryMigrationError::RevisionUnavailable)?
                .unwrap_or(Value::Null);
            // Encrypted columns project base64; the captured row keeps the
            // tagged member, unopened, so journal snapshots canonicalize
            // byte-identically with the mutation row path.
            let value = if field.encryption.is_some() {
                crate::mutation::envelope_member_from_projection(value)
                    .map_err(|_| HistoryMigrationError::RevisionUnavailable)?
            } else {
                value
            };
            data.insert(field.id.clone(), value);
        }
        if captured
            .insert(
                record_uuid,
                CapturedEntityRow {
                    record_revision,
                    record_lifecycle,
                    active_package_revision,
                    data,
                },
            )
            .is_some()
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
    }
    Ok(captured)
}

fn history_returning_projection(entity: &CompiledEntity) -> String {
    let mut expressions = vec![
        "record_id::text".to_owned(),
        "record_revision".to_owned(),
        "record_lifecycle".to_owned(),
        "active_package_revision".to_owned(),
    ];
    expressions.extend(entity.fields.values().map(field_json_projection));
    expressions.join(", ")
}

fn field_json_projection(field: &CompiledField) -> String {
    let column = quote_identifier(&field.physical_name);
    if field.encryption.is_some() {
        // The envelope column projects as base64 text; row decode turns it into
        // the tagged JSON member, byte-identically with the mutation row path.
        return format!("to_jsonb(encode({column}, 'base64'))");
    }
    match &field.field_type {
        FieldTypeSource::Decimal { .. } => format!("to_jsonb({column}::text)"),
        _ => format!("to_jsonb({column})"),
    }
}

#[cfg(feature = "runtime")]
async fn load_latest_revision_binding(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
) -> Result<LatestRevisionBinding> {
    let row = transaction
        .query_opt(
            "SELECT record_reference, record_revision, record_lifecycle
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1 AND record_id = $2
              ORDER BY record_revision DESC
              LIMIT 1",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?
        .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
    Ok(LatestRevisionBinding {
        record_reference: row
            .try_get(0)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?,
        record_revision: row
            .try_get(1)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?,
        record_lifecycle: row
            .try_get(2)
            .map_err(|_| HistoryMigrationError::RevisionUnavailable)?,
    })
}

#[cfg(feature = "runtime")]
#[allow(clippy::too_many_arguments)] // Keep prior and target row bindings explicit.
async fn update_history_migrated_row_metadata(
    transaction: &Transaction<'_>,
    table: &str,
    record_id: Uuid,
    expected_revision: i64,
    expected_lifecycle: &str,
    expected_active_package_revision: &str,
    next_revision: i64,
    package_revision: &str,
) -> Result<()> {
    let table_name =
        SqlIdentifier::parse(table).map_err(|_| HistoryMigrationError::UnsupportedObject)?;
    let changed = transaction
        .execute(
            &format!(
                "UPDATE registry_data.{}
                    SET record_revision = $2::bigint,
                        active_package_revision = $3,
                        updated_at = transaction_timestamp()
                  WHERE record_id = $1
                    AND record_revision = $4::bigint
                    AND record_lifecycle = $5
                    AND active_package_revision = $6",
                table_name.quoted()
            ),
            &[
                &record_id,
                &next_revision,
                &package_revision,
                &expected_revision,
                &expected_lifecycle,
                &expected_active_package_revision,
            ],
        )
        .await
        .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
    if changed != 1 {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }
    Ok(())
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_plan::{
        ChunkCursorProtocol, ReviewedMigrationObject, ReviewedMigrationObjectKind,
    };

    fn object(entity_id: &str, table: &str) -> ReviewedMigrationObject {
        ReviewedMigrationObject {
            schema: "registry_data".to_owned(),
            table: table.to_owned(),
            entity_id: entity_id.to_owned(),
            kind: ReviewedMigrationObjectKind::Entity,
            member_id: None,
            physical_name: table.to_owned(),
        }
    }

    fn step(descriptor: ReviewedMigrationStepDescriptor) -> ValidatedReviewedMigrationStep {
        ValidatedReviewedMigrationStep {
            descriptor,
            sql: "UPDATE registry_data.households SET name = name".to_owned(),
            sha256: "abc".to_owned(),
        }
    }

    #[test]
    fn bounded_single_entity_transactional_step_is_classified() {
        let classified = classify_reviewed_history_step(
            "migrations/descriptor.json",
            &step(ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "normalize-household".to_owned(),
                sql_path: "migrations/normalize.sql".to_owned(),
                objects: vec![object("household", "households")],
                affected_rows: Some(AffectedRowBounds { min: 1, max: 10 }),
            }),
        )
        .expect("bounded single-entity transactional SQL is the supported lane");

        assert_eq!(classified.entity_id, "household");
        assert_eq!(classified.physical_table, "households");
        assert_eq!(
            classified.migration_reference(),
            "migrations/descriptor.json#normalize-household"
        );
        assert_eq!(
            classified.affected_rows,
            AffectedRowBounds { min: 1, max: 10 }
        );
    }

    #[test]
    fn unbounded_transactional_step_is_refused() {
        let error = classify_reviewed_history_step(
            "migrations/descriptor.json",
            &step(ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "normalize-household".to_owned(),
                sql_path: "migrations/normalize.sql".to_owned(),
                objects: vec![object("household", "households")],
                affected_rows: None,
            }),
        )
        .expect_err("affected-row bounds are required before history migration can run");

        assert_eq!(error, HistoryMigrationError::UnboundedTransactionalSql);
    }

    #[test]
    fn affected_row_bound_above_commit_limit_is_refused() {
        let error = classify_reviewed_history_step(
            "migrations/descriptor.json",
            &step(ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "normalize-household".to_owned(),
                sql_path: "migrations/normalize.sql".to_owned(),
                objects: vec![object("household", "households")],
                affected_rows: Some(AffectedRowBounds {
                    min: 1,
                    max: MAX_HISTORY_MIGRATION_COMMIT_MEMBERS + 1,
                }),
            }),
        )
        .expect_err("a single history migration commit cannot exceed the commit-member cap");

        assert_eq!(error, HistoryMigrationError::InvalidAffectedRows);
    }

    fn chunked_step(entity_id: &str, chunk_size: u32) -> ValidatedReviewedMigrationStep {
        let mut step = step(ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "backfill-household".to_owned(),
            entity_id: entity_id.to_owned(),
            sql_path: "migrations/backfill.sql".to_owned(),
            objects: vec![object("household", "households")],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size,
            max_total_rows: 10_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
        });
        step.sql = "UPDATE registry_data.households SET status = 'active' \
                    WHERE record_id = ANY($1::pg_catalog.uuid[])"
            .to_owned();
        step
    }

    #[test]
    fn chunked_backfill_journals_each_chunk_as_one_commit() {
        let classified = check_reviewed_history_step(
            "migrations/descriptor.json",
            &chunked_step("household", 100),
        )
        .expect("a chunked backfill over one entity is journaled");

        assert_eq!(classified.entity_id, "household");
        assert_eq!(classified.physical_table, "households");
        assert_eq!(
            classified.affected_rows,
            AffectedRowBounds { min: 0, max: 100 },
            "one chunk commits at most its chunk size, and may change nothing"
        );
    }

    #[test]
    fn chunked_backfill_above_the_commit_limit_is_refused() {
        let chunk_size = u32::try_from(MAX_HISTORY_MIGRATION_COMMIT_MEMBERS + 1).unwrap();
        let error = check_reviewed_history_step(
            "migrations/descriptor.json",
            &chunked_step("household", chunk_size),
        )
        .expect_err("one chunk is one commit, so it cannot exceed the commit-member cap");

        assert_eq!(error, HistoryMigrationError::InvalidAffectedRows);
    }

    #[test]
    fn chunked_backfill_over_another_entity_than_its_objects_is_refused() {
        let error =
            check_reviewed_history_step("migrations/descriptor.json", &chunked_step("member", 100))
                .expect_err("the chunked entity and the step's objects must agree");

        assert_eq!(error, HistoryMigrationError::CrossEntityStep);
    }

    #[test]
    fn chunked_backfill_may_bind_its_page_but_not_write_record_metadata() {
        let mut forged = chunked_step("household", 100);
        forged.sql = "UPDATE registry_data.households SET record_revision = 9 \
                      WHERE record_id = ANY($1::pg_catalog.uuid[])"
            .to_owned();
        assert_eq!(
            check_reviewed_history_step("migrations/descriptor.json", &forged),
            Err(HistoryMigrationError::UnsupportedSqlShape),
            "record metadata belongs to the journal"
        );

        let mut transactional = step(ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "normalize-household".to_owned(),
            sql_path: "migrations/normalize.sql".to_owned(),
            objects: vec![object("household", "households")],
            affected_rows: Some(AffectedRowBounds { min: 0, max: 10 }),
        });
        transactional.sql = "UPDATE registry_data.households SET status = 'active' \
                             WHERE record_id = ANY('{}'::pg_catalog.uuid[])"
            .to_owned();
        assert_eq!(
            check_reviewed_history_step("migrations/descriptor.json", &transactional),
            Err(HistoryMigrationError::UnsupportedSqlShape),
            "a transactional update binds no page, so it still may not name record_id"
        );
    }

    fn chunked_sql_check(sql: &str) -> Result<SupportedHistoryMigrationStep> {
        let mut step = chunked_step("household", 100);
        step.sql = sql.to_owned();
        check_reviewed_history_step("migrations/descriptor.json", &step)
    }

    #[test]
    fn chunked_backfill_accepts_comments_line_breaks_and_words_inside_literals() {
        for sql in [
            "-- SPDX-License-Identifier: Apache-2.0\n\
             /* Normalise the status, /* nested */ once. */\n\
             UPDATE registry_data.households SET status = 'active' \
             WHERE record_id = ANY($1::pg_catalog.uuid[]);",
            "UPDATE\n  registry_data.households\n   SET status = 'active'\n\t WHERE \
             record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET created_at_source = 'form', \
             updated_at_source = 'form' WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET note = 'delete me; then insert it''s drop' \
             WHERE record_id = ANY($1::pg_catalog.uuid[]) -- create nothing else",
        ] {
            assert!(
                chunked_sql_check(sql).is_ok(),
                "a valid chunked update is accepted: {sql}"
            );
        }
    }

    #[test]
    fn chunked_backfill_refuses_the_statement_shapes_the_journal_cannot_hold() {
        for sql in [
            // Record metadata, however it is spelled.
            "UPDATE registry_data.households SET created_at = now() \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households AS h SET status = h.updated_at::text \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET \"record_revision\" = 9 \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET RECORD_LIFECYCLE = 'active' \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            // A second statement, or a statement that is not an update.
            "UPDATE registry_data.households SET status = 'a' \
             WHERE record_id = ANY($1::pg_catalog.uuid[]); DELETE FROM registry_data.households",
            "UPDATE registry_data.households SET status = 'a' \
             WHERE record_id = ANY($1::pg_catalog.uuid[]);\nSELECT 1",
            "-- UPDATE registry_data.households\nSELECT 1",
            "/* UPDATE */ DELETE FROM registry_data.households WHERE record_id = ANY($1)",
            "WITH moved AS (DELETE FROM registry_data.households RETURNING record_id) \
             UPDATE registry_data.households SET status = 'a' WHERE record_id = ANY($1)",
            "UPDATE registry_data.households SET status = (SELECT 1 FROM (INSERT INTO x VALUES (1)) i) \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            // Constructs whose extent the scan will not guess are read as
            // written, so a refused word inside them still refuses.
            "UPDATE registry_data.households SET status = $$delete$$ \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET status = E'\\' delete ' \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "UPDATE registry_data.households SET status = 'unterminated delete \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "$$ $$ UPDATE registry_data.households SET status = 'a' \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "-- a comment the scan cannot end\n UPDATE registry_data.households \
             SET status = $x$a$x$ WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "/* unterminated UPDATE registry_data.households SET status = 'a' \
             WHERE record_id = ANY($1::pg_catalog.uuid[])",
            "",
            ";",
        ] {
            assert_eq!(
                chunked_sql_check(sql),
                Err(HistoryMigrationError::UnsupportedSqlShape),
                "the statement is refused: {sql}"
            );
        }
    }

    #[test]
    fn cross_entity_transactional_step_is_refused() {
        let error = classify_reviewed_history_step(
            "migrations/descriptor.json",
            &step(ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "normalize-household".to_owned(),
                sql_path: "migrations/normalize.sql".to_owned(),
                objects: vec![
                    object("household", "households"),
                    object("member", "members"),
                ],
                affected_rows: Some(AffectedRowBounds { min: 1, max: 10 }),
            }),
        )
        .expect_err("one transactional step cannot be mapped to two history entities");

        assert_eq!(error, HistoryMigrationError::CrossEntityStep);
    }

    #[test]
    fn sql_shape_refuses_system_column_update() {
        let error = validate_reviewed_update_sql(
            "UPDATE registry_data.households SET record_revision = record_revision + 1",
        )
        .expect_err("reviewed migration SQL cannot change system columns directly");

        assert_eq!(error, HistoryMigrationError::UnsupportedSqlShape);
    }
}
