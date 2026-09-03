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

pub(crate) const HISTORY_MIGRATION_SYSTEM_ORIGIN: &str = "registry-server-reviewed-migration-v1";
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
    #[error("reviewed chunked backfills are not history-safe yet")]
    ChunkedBackfillUnsupported,
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
    if capture.rows.keys().ne(post_rows.keys()) {
        return Err(HistoryMigrationError::UnexpectedRowShape);
    }

    let migration_reference = capture.step.migration_reference();
    let mut changed = Vec::new();
    for (record_id, before) in &capture.rows {
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
        let latest =
            load_latest_revision_binding(transaction, &capture.step.entity_id, *record_id).await?;
        if latest.record_revision != before.record_revision
            || latest.record_lifecycle != before.record_lifecycle
        {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        update_history_migrated_row_metadata(
            transaction,
            &capture.step.physical_table,
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
                entity_id: &capture.step.entity_id,
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
            entity_id: capture.step.entity_id.as_str(),
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
        let latest_revisions = load_latest_revision_snapshots(transaction, &entity.id).await?;
        if live_rows.keys().ne(latest_revisions.keys()) {
            return Err(HistoryMigrationError::UnexpectedRowShape);
        }
        for (record_id, live) in live_rows {
            let latest = latest_revisions
                .get(&record_id)
                .ok_or(HistoryMigrationError::UnexpectedRowShape)?;
            let snapshot = canonical_snapshot(&live.data)
                .map_err(|_| HistoryMigrationError::RevisionUnavailable)?;
            if live.record_revision != latest.record_revision
                || live.record_lifecycle != latest.record_lifecycle
                || required_package_revision
                    .is_some_and(|required| latest.package_revision != required)
                || snapshot != latest.snapshot
            {
                return Err(HistoryMigrationError::UnexpectedRowShape);
            }
            members.push(BaselineMember {
                entity_id: entity.id.clone(),
                record_id,
                record_revision: live.record_revision,
            });
        }
    }
    Ok(members)
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
) -> Result<BTreeMap<Uuid, LatestRevisionSnapshot>> {
    let rows = transaction
        .query(
            "SELECT DISTINCT ON (record_id)
                    record_id, record_revision, record_lifecycle, package_revision, snapshot
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
              ORDER BY record_id, record_revision DESC",
            &[&entity_id],
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
    let system_origin = "registry-server-existing-history-baseline-v1";
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
        ReviewedMigrationStepDescriptor::ChunkedBackfill { .. } => {
            Err(HistoryMigrationError::ChunkedBackfillUnsupported)
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

fn validate_reviewed_update_sql(sql: &str) -> Result<()> {
    let normalized = sql.trim().trim_end_matches(';').trim();
    let lowercase = normalized.to_ascii_lowercase();
    if !lowercase.starts_with("update ") || lowercase.contains(';') {
        return Err(HistoryMigrationError::UnsupportedSqlShape);
    }
    for refused in [
        " insert ",
        " delete ",
        " truncate ",
        " alter ",
        " drop ",
        " create ",
        " merge ",
        " record_id",
        " record_revision",
        " record_lifecycle",
        " active_package_revision",
        " created_at",
        " updated_at",
    ] {
        if lowercase.contains(refused) {
            return Err(HistoryMigrationError::UnsupportedSqlShape);
        }
    }
    Ok(())
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

    #[test]
    fn chunked_backfill_is_refused_for_history_migration() {
        let error = classify_reviewed_history_step(
            "migrations/descriptor.json",
            &step(ReviewedMigrationStepDescriptor::ChunkedBackfill {
                id: "backfill-household".to_owned(),
                entity_id: "household".to_owned(),
                sql_path: "migrations/backfill.sql".to_owned(),
                objects: vec![object("household", "households")],
                cursor: ChunkCursorProtocol::RecordIdUuidArray,
                chunk_size: 100,
                max_total_rows: 1_000,
                lock_timeout_ms: 1_000,
                statement_timeout_ms: 10_000,
                exact_affected_rows: true,
            }),
        )
        .expect_err("chunked backfills need a fuller history engine");

        assert_eq!(error, HistoryMigrationError::ChunkedBackfillUnsupported);
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
