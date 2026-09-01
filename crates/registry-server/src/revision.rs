// SPDX-License-Identifier: Apache-2.0

//! Complete canonical revision snapshots for Registry Server mutations.

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use tokio_postgres::Transaction;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RevisionError {
    #[error("revision snapshot is invalid")]
    InvalidSnapshot,
    #[error("revision journal is unavailable")]
    Unavailable,
}

pub(crate) fn canonical_snapshot(data: &Map<String, Value>) -> Result<Vec<u8>, RevisionError> {
    canonicalize_json(&Value::Object(data.clone())).map_err(|_| RevisionError::InvalidSnapshot)
}

pub(crate) struct RevisionInsert<'a> {
    pub entity_id: &'a str,
    pub record_id: Uuid,
    pub record_reference: &'a str,
    pub record_revision: i64,
    pub predecessor_revision: Option<i64>,
    pub lifecycle: &'a str,
    pub package_revision: &'a str,
    pub operation_id: &'a str,
    pub mutation_kind: &'a str,
    pub principal_reference: &'a str,
    pub request_reference: &'a str,
    pub snapshot: &'a [u8],
}

pub(crate) struct InternalMigrationRevisionInsert<'a> {
    pub entity_id: &'a str,
    pub record_id: Uuid,
    pub record_reference: &'a str,
    pub record_revision: i64,
    pub predecessor_revision: i64,
    pub lifecycle: &'a str,
    pub package_revision: &'a str,
    pub system_origin: &'a str,
    pub migration_reference: &'a str,
    pub snapshot: &'a [u8],
}

pub(crate) async fn insert_revision(
    transaction: &Transaction<'_>,
    revision: RevisionInsert<'_>,
) -> Result<(), RevisionError> {
    if revision.entity_id.is_empty()
        || revision.record_reference.is_empty()
        || revision.record_revision <= 0
        || revision
            .predecessor_revision
            .is_some_and(|predecessor| predecessor <= 0 || predecessor >= revision.record_revision)
        || !matches!(revision.lifecycle, "active" | "tombstoned")
        || revision.package_revision.is_empty()
        || revision.operation_id.is_empty()
        || !matches!(revision.mutation_kind, "create" | "patch" | "tombstone")
        || revision.principal_reference.is_empty()
        || revision.request_reference.is_empty()
        || revision.snapshot.is_empty()
        || revision.snapshot.len() > 2 * 1024 * 1024
    {
        return Err(RevisionError::InvalidSnapshot);
    }
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &revision.entity_id,
                &revision.record_id,
                &revision.record_reference,
                &revision.record_revision,
                &revision.predecessor_revision,
                &revision.lifecycle,
                &revision.package_revision,
                &revision.operation_id,
                &revision.mutation_kind,
                &revision.principal_reference,
                &revision.request_reference,
                &revision.snapshot,
            ],
        )
        .await
        .map_err(|_| RevisionError::Unavailable)?;
    if changed != 1 {
        return Err(RevisionError::Unavailable);
    }
    Ok(())
}

pub(crate) async fn insert_internal_migration_revision(
    transaction: &Transaction<'_>,
    revision: InternalMigrationRevisionInsert<'_>,
) -> Result<(), RevisionError> {
    if revision.entity_id.is_empty()
        || revision.record_reference.is_empty()
        || revision.record_revision <= 1
        || revision.predecessor_revision <= 0
        || revision.predecessor_revision >= revision.record_revision
        || !matches!(revision.lifecycle, "active" | "tombstoned")
        || revision.package_revision.is_empty()
        || revision.system_origin.is_empty()
        || revision.migration_reference.is_empty()
        || revision.snapshot.is_empty()
        || revision.snapshot.len() > 2 * 1024 * 1024
    {
        return Err(RevisionError::InvalidSnapshot);
    }
    let predecessor_revision = Some(revision.predecessor_revision);
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'migration', $9, $10, $11)",
            &[
                &revision.entity_id,
                &revision.record_id,
                &revision.record_reference,
                &revision.record_revision,
                &predecessor_revision,
                &revision.lifecycle,
                &revision.package_revision,
                &revision.migration_reference,
                &revision.system_origin,
                &revision.migration_reference,
                &revision.snapshot,
            ],
        )
        .await
        .map_err(|_| RevisionError::Unavailable)?;
    if changed != 1 {
        return Err(RevisionError::Unavailable);
    }
    Ok(())
}
