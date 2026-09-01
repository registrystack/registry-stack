// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL commit index helpers for retained Registry Server history.

use uuid::Uuid;

use crate::history_context::{ChangeContext, ChangeContextError, CommitOrigin};
use crate::history_reference::SnapshotReference;

#[cfg(feature = "runtime")]
use crate::postgres::SqlIdentifier;
#[cfg(feature = "runtime")]
use tokio_postgres::{GenericClient, Transaction};

const MAX_PACKAGE_REVISION_BYTES: usize = 256;
const MAX_COMMIT_MEMBERS: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevisionCommitMember<'a> {
    pub(crate) entity_id: &'a str,
    pub(crate) record_id: Uuid,
    pub(crate) record_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct CommitAllocation<'a> {
    pub(crate) package_revision: &'a str,
    pub(crate) origin: CommitOrigin<'a>,
    pub(crate) change_context: Option<&'a ChangeContext>,
    pub(crate) members: &'a [RevisionCommitMember<'a>],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommittedPosition {
    pub(crate) position: i64,
    pub(crate) change_id: Uuid,
    pub(crate) reference: SnapshotReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryHead {
    pub(crate) history_lineage: Uuid,
    pub(crate) latest_position: i64,
    pub(crate) coverage_baseline_position: i64,
    pub(crate) coverage_ready: bool,
    pub(crate) unavailable_after_position: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedSnapshot {
    pub(crate) position: i64,
    pub(crate) history_lineage: Uuid,
    pub(crate) package_revision: String,
    pub(crate) reference: SnapshotReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HistoryCommitError {
    #[error("history commit input is invalid")]
    InvalidInput,
    #[error("history commit state is not ready")]
    NotReady,
    #[error("snapshot reference is unknown")]
    UnknownReference,
    #[error("snapshot reference is from another history lineage")]
    WrongLineage,
    #[error("snapshot reference is in the future")]
    FutureReference,
    #[error("snapshot history is unavailable")]
    Unavailable,
}

impl From<ChangeContextError> for HistoryCommitError {
    fn from(_: ChangeContextError) -> Self {
        Self::InvalidInput
    }
}

#[cfg(feature = "runtime")]
pub(crate) async fn install_history_commit_schema(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), HistoryCommitError> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_commit_head (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 history_lineage uuid NOT NULL UNIQUE,
                 latest_position bigint NOT NULL CHECK (latest_position >= 0),
                 coverage_baseline_position bigint NOT NULL
                     CHECK (coverage_baseline_position >= 0),
                 coverage_ready boolean NOT NULL DEFAULT false,
                 unavailable_after_position bigint
                     CHECK (unavailable_after_position IS NULL OR unavailable_after_position >= 0),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 CHECK (coverage_baseline_position <= latest_position),
                 CHECK (
                     unavailable_after_position IS NULL
                     OR unavailable_after_position >= coverage_baseline_position
                 )
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_revision_commits (
                 commit_position bigint PRIMARY KEY CHECK (commit_position >= 0),
                 change_id uuid NOT NULL UNIQUE,
                 snapshot_reference uuid NOT NULL UNIQUE,
                 history_lineage uuid NOT NULL,
                 originating_package_revision text NOT NULL
                     CHECK (
                         originating_package_revision <> ''
                         AND octet_length(originating_package_revision) <= 256
                     ),
                 origin_kind text NOT NULL
                     CHECK (origin_kind IN ('mutation', 'migration', 'baseline')),
                 actor_reference text CHECK (
                     actor_reference IS NULL
                     OR (actor_reference <> '' AND octet_length(actor_reference) <= 512)
                 ),
                 request_reference text CHECK (
                     request_reference IS NULL
                     OR (request_reference <> '' AND octet_length(request_reference) <= 512)
                 ),
                 system_origin text CHECK (
                     system_origin IS NULL
                     OR (system_origin <> '' AND octet_length(system_origin) <= 512)
                 ),
                 migration_reference text CHECK (
                     migration_reference IS NULL
                     OR (migration_reference <> '' AND octet_length(migration_reference) <= 512)
                 ),
                 baseline_reference text CHECK (
                     baseline_reference IS NULL
                     OR (baseline_reference <> '' AND octet_length(baseline_reference) <= 512)
                 ),
                 establishes_baseline boolean NOT NULL DEFAULT false,
                 change_context bytea CHECK (
                     change_context IS NULL
                     OR (octet_length(change_context) > 0 AND octet_length(change_context) <= 16384)
                 ),
                 change_context_digest bytea CHECK (
                     change_context_digest IS NULL OR octet_length(change_context_digest) = 32
                 ),
                 recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 FOREIGN KEY (history_lineage)
                     REFERENCES registry_internal.registry_commit_head (history_lineage)
                     ON DELETE RESTRICT,
                 CHECK (
                     (change_context IS NULL AND change_context_digest IS NULL)
                     OR (change_context IS NOT NULL AND change_context_digest IS NOT NULL)
                 ),
                 CHECK (
                     (origin_kind = 'mutation'
                         AND actor_reference IS NOT NULL
                         AND request_reference IS NOT NULL
                         AND system_origin IS NULL
                         AND migration_reference IS NULL
                         AND baseline_reference IS NULL
                         AND establishes_baseline = false)
                     OR
                     (origin_kind = 'migration'
                         AND actor_reference IS NULL
                         AND request_reference IS NULL
                         AND system_origin IS NOT NULL
                         AND baseline_reference IS NULL)
                     OR
                     (origin_kind = 'baseline'
                         AND actor_reference IS NULL
                         AND request_reference IS NULL
                         AND system_origin IS NOT NULL
                         AND migration_reference IS NULL
                         AND establishes_baseline = true)
                 )
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_revision_commit_members (
                 entity_id text NOT NULL CHECK (entity_id <> ''),
                 record_id uuid NOT NULL,
                 record_revision bigint NOT NULL CHECK (record_revision > 0),
                 commit_position bigint NOT NULL CHECK (commit_position >= 0),
                 member_index integer NOT NULL CHECK (member_index >= 0),
                 PRIMARY KEY (entity_id, record_id, record_revision),
                 UNIQUE (commit_position, member_index),
                 FOREIGN KEY (entity_id, record_id, record_revision)
                     REFERENCES registry_internal.registry_revisions
                         (entity_id, record_id, record_revision)
                     ON DELETE RESTRICT,
                 FOREIGN KEY (commit_position)
                     REFERENCES registry_internal.registry_revision_commits (commit_position)
                     ON DELETE RESTRICT
             );
             CREATE INDEX IF NOT EXISTS registry_revision_commit_members_lookup_idx
                 ON registry_internal.registry_revision_commit_members
                     (entity_id, record_id, commit_position DESC, record_revision DESC);
             CREATE INDEX IF NOT EXISTS registry_revision_commit_members_position_idx
                 ON registry_internal.registry_revision_commit_members
                     (commit_position, entity_id, record_id);
             REVOKE ALL ON registry_internal.registry_commit_head,
                 registry_internal.registry_revision_commits,
                 registry_internal.registry_revision_commit_members FROM PUBLIC;",
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    let role = quoted_identifier(runtime_role.as_str());
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON registry_internal.registry_commit_head,
                 registry_internal.registry_revision_commits,
                 registry_internal.registry_revision_commit_members FROM {role};
             GRANT SELECT ON registry_internal.registry_commit_head TO {role};
             GRANT UPDATE (latest_position, updated_at)
                 ON registry_internal.registry_commit_head TO {role};
             GRANT SELECT, INSERT ON registry_internal.registry_revision_commits,
                 registry_internal.registry_revision_commit_members TO {role};",
        ))
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    Ok(())
}

#[cfg(feature = "runtime")]
pub(crate) async fn install_empty_history_baseline(
    client: &impl GenericClient,
    package_revision: &str,
) -> Result<CommittedPosition, HistoryCommitError> {
    validate_package_revision(package_revision)?;
    let revision_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?
        .get(0);
    if revision_count != 0 {
        return Err(HistoryCommitError::NotReady);
    }
    let existing_head = client
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    if existing_head.is_some() {
        return Err(HistoryCommitError::InvalidInput);
    }

    let history_lineage = Uuid::new_v4();
    let change_id = Uuid::new_v4();
    let reference = SnapshotReference::new_random();
    let origin = CommitOrigin::Baseline {
        system_origin: "registry-server-empty-history-baseline-v1",
        baseline_reference: None,
    }
    .validate()?;
    client
        .execute(
            "INSERT INTO registry_internal.registry_commit_head
                 (singleton, history_lineage, latest_position,
                  coverage_baseline_position, coverage_ready)
             VALUES (true, $1, 0, 0, true)",
            &[&history_lineage],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    client
        .execute(
            "INSERT INTO registry_internal.registry_revision_commits
                 (commit_position, change_id, snapshot_reference, history_lineage,
                  originating_package_revision, origin_kind, system_origin,
                  establishes_baseline)
             VALUES (0, $1, $2, $3, $4, $5, $6, $7)",
            &[
                &change_id,
                &reference.uuid(),
                &history_lineage,
                &package_revision,
                &origin.kind,
                &origin.system_origin,
                &origin.establishes_baseline,
            ],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    Ok(CommittedPosition {
        position: 0,
        change_id,
        reference,
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn lock_history_head(
    transaction: &Transaction<'_>,
) -> Result<HistoryHead, HistoryCommitError> {
    let row = transaction
        .query_opt(
            "SELECT history_lineage, latest_position, coverage_baseline_position,
                    coverage_ready, unavailable_after_position
               FROM registry_internal.registry_commit_head
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?
        .ok_or(HistoryCommitError::NotReady)?;
    Ok(HistoryHead {
        history_lineage: row.get(0),
        latest_position: row.get(1),
        coverage_baseline_position: row.get(2),
        coverage_ready: row.get(3),
        unavailable_after_position: row.get(4),
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn load_history_head(
    transaction: &Transaction<'_>,
) -> Result<HistoryHead, HistoryCommitError> {
    let row = transaction
        .query_opt(
            "SELECT history_lineage, latest_position, coverage_baseline_position,
                    coverage_ready, unavailable_after_position
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?
        .ok_or(HistoryCommitError::NotReady)?;
    Ok(HistoryHead {
        history_lineage: row.get(0),
        latest_position: row.get(1),
        coverage_baseline_position: row.get(2),
        coverage_ready: row.get(3),
        unavailable_after_position: row.get(4),
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn allocate_revision_commit(
    transaction: &Transaction<'_>,
    allocation: CommitAllocation<'_>,
) -> Result<CommittedPosition, HistoryCommitError> {
    validate_allocation(&allocation)?;
    let origin = allocation.origin.validate()?;
    let head = lock_history_head(transaction).await?;
    let next_position = head
        .latest_position
        .checked_add(1)
        .ok_or(HistoryCommitError::InvalidInput)?;
    let change_id = Uuid::new_v4();
    let reference = SnapshotReference::new_random();
    let context_bytes = allocation
        .change_context
        .map(ChangeContext::canonical_bytes);
    let context_digest = allocation
        .change_context
        .map(|context| context.digest().to_vec());
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commits
                 (commit_position, change_id, snapshot_reference, history_lineage,
                  originating_package_revision, origin_kind, actor_reference,
                  request_reference, system_origin, migration_reference,
                  baseline_reference, establishes_baseline, change_context,
                  change_context_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            &[
                &next_position,
                &change_id,
                &reference.uuid(),
                &head.history_lineage,
                &allocation.package_revision,
                &origin.kind,
                &origin.actor_reference,
                &origin.request_reference,
                &origin.system_origin,
                &origin.migration_reference,
                &origin.baseline_reference,
                &origin.establishes_baseline,
                &context_bytes,
                &context_digest,
            ],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    for (index, member) in allocation.members.iter().enumerate() {
        let member_index = i32::try_from(index).map_err(|_| HistoryCommitError::InvalidInput)?;
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revision_commit_members
                     (entity_id, record_id, record_revision, commit_position, member_index)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &member.entity_id,
                    &member.record_id,
                    &member.record_revision,
                    &next_position,
                    &member_index,
                ],
            )
            .await
            .map_err(|_| HistoryCommitError::Unavailable)?;
    }
    let updated = transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET latest_position = $1, updated_at = transaction_timestamp()
              WHERE singleton AND latest_position = $2",
            &[&next_position, &head.latest_position],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    if updated != 1 {
        return Err(HistoryCommitError::Unavailable);
    }
    Ok(CommittedPosition {
        position: next_position,
        change_id,
        reference,
    })
}

#[cfg(feature = "runtime")]
pub(crate) async fn resolve_snapshot_reference(
    transaction: &Transaction<'_>,
    reference: SnapshotReference,
) -> Result<ResolvedSnapshot, HistoryCommitError> {
    let head = load_history_head(transaction).await?;
    resolve_snapshot_with_head(transaction, &head, reference).await
}

#[cfg(feature = "runtime")]
pub(crate) async fn capture_latest_snapshot_reference(
    transaction: &Transaction<'_>,
) -> Result<ResolvedSnapshot, HistoryCommitError> {
    let head = load_history_head(transaction).await?;
    if !head.coverage_ready
        || head
            .unavailable_after_position
            .is_some_and(|unavailable_after| head.latest_position > unavailable_after)
    {
        return Err(HistoryCommitError::Unavailable);
    }
    let row = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = $1",
            &[&head.latest_position],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?;
    let snapshot_id: Uuid = row.get(0);
    resolve_snapshot_with_head(transaction, &head, SnapshotReference::for_uuid(snapshot_id)).await
}

#[cfg(feature = "runtime")]
async fn resolve_snapshot_with_head(
    transaction: &Transaction<'_>,
    head: &HistoryHead,
    reference: SnapshotReference,
) -> Result<ResolvedSnapshot, HistoryCommitError> {
    let row = transaction
        .query_opt(
            "SELECT commit_position, history_lineage, originating_package_revision
               FROM registry_internal.registry_revision_commits
              WHERE snapshot_reference = $1",
            &[&reference.uuid()],
        )
        .await
        .map_err(|_| HistoryCommitError::Unavailable)?
        .ok_or(HistoryCommitError::UnknownReference)?;
    let position: i64 = row.get(0);
    let history_lineage: Uuid = row.get(1);
    let package_revision: String = row.get(2);
    validate_snapshot_position(head, history_lineage, position)?;
    Ok(ResolvedSnapshot {
        position,
        history_lineage,
        package_revision,
        reference,
    })
}

fn validate_allocation(allocation: &CommitAllocation<'_>) -> Result<(), HistoryCommitError> {
    validate_package_revision(allocation.package_revision)?;
    if allocation.members.is_empty() || allocation.members.len() > MAX_COMMIT_MEMBERS {
        return Err(HistoryCommitError::InvalidInput);
    }
    for member in allocation.members {
        if member.entity_id.is_empty() || member.record_revision <= 0 {
            return Err(HistoryCommitError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_package_revision(package_revision: &str) -> Result<(), HistoryCommitError> {
    if package_revision.is_empty() || package_revision.len() > MAX_PACKAGE_REVISION_BYTES {
        return Err(HistoryCommitError::InvalidInput);
    }
    Ok(())
}

fn validate_snapshot_position(
    head: &HistoryHead,
    history_lineage: Uuid,
    position: i64,
) -> Result<(), HistoryCommitError> {
    if history_lineage != head.history_lineage {
        return Err(HistoryCommitError::WrongLineage);
    }
    if position > head.latest_position {
        return Err(HistoryCommitError::FutureReference);
    }
    if !head.coverage_ready
        || position < head.coverage_baseline_position
        || head
            .unavailable_after_position
            .is_some_and(|unavailable_after| position > unavailable_after)
    {
        return Err(HistoryCommitError::Unavailable);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
fn quoted_identifier(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_requires_members_and_package_identity() {
        let allocation = CommitAllocation {
            package_revision: "pkg-1",
            origin: CommitOrigin::Mutation {
                actor_reference: "actor",
                request_reference: "request",
            },
            change_context: None,
            members: &[],
        };
        assert_eq!(
            validate_allocation(&allocation),
            Err(HistoryCommitError::InvalidInput)
        );
    }

    #[test]
    fn snapshot_position_validation_refuses_wrong_future_and_unavailable_lineages() {
        let current = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af7").unwrap();
        let other = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af8").unwrap();
        let head = HistoryHead {
            history_lineage: current,
            latest_position: 2,
            coverage_baseline_position: 0,
            coverage_ready: true,
            unavailable_after_position: Some(1),
        };

        assert_eq!(
            validate_snapshot_position(&head, other, 1),
            Err(HistoryCommitError::WrongLineage)
        );
        assert_eq!(
            validate_snapshot_position(&head, current, 3),
            Err(HistoryCommitError::FutureReference)
        );
        assert_eq!(
            validate_snapshot_position(&head, current, 2),
            Err(HistoryCommitError::Unavailable)
        );
        assert_eq!(validate_snapshot_position(&head, current, 1), Ok(()));
    }
}
