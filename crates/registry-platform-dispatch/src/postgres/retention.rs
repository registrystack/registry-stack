// SPDX-License-Identifier: Apache-2.0

//! Bounded terminal metadata deletion within the consumer's transaction.
use std::time::SystemTime;

use tokio_postgres::Transaction;

use super::{JobKey, JobTable};
use crate::DispatchError;

/// Maximum candidate count per retention transaction.
pub const MAX_PRUNE_BATCH: usize = 256;

/// Delete eligible terminal candidates at or before a product-owned cutoff.
///
/// The consumer selects candidates under its retention/replay policy and owns
/// dependent cleanup in this same transaction. This final predicate preserves
/// pending, leased and unknown jobs, and dead letters without completed expiry.
/// It also rechecks the horizon if a candidate changed before deletion. A
/// consumer with additional replay or receipt requirements must enforce them
/// before calling this function; metadata deletion does not erase audit logs.
///
/// Returns only deleted keys. No rows are committed here. The caller must roll
/// back on any error, including a dependent cleanup error.
///
/// # Errors
/// Returns `Unavailable` for more than [`MAX_PRUNE_BATCH`] candidates or a
/// database failure.
pub async fn prune_terminal(
    transaction: &Transaction<'_>,
    table: &JobTable,
    candidates: &[JobKey],
    before: SystemTime,
) -> Result<Vec<JobKey>, DispatchError> {
    if candidates.len() > MAX_PRUNE_BATCH {
        return Err(DispatchError::Unavailable);
    }
    let statement = transaction
        .prepare(&format!(
            "DELETE FROM {table} WHERE {id}=$1 AND {part}=$2 AND updated_at <= $3
         AND ((state='delivered' AND delivered_at <= $3)
           OR (state='expired' AND expired_at <= $3)
           OR (state='dead-lettered' AND dead_lettered_at <= $3 AND expired_at <= $3)
           OR state='cancelled')",
            table = table.qualified(),
            id = table.id_column(),
            part = table.part_column(),
        ))
        .await?;
    let mut deleted = Vec::new();
    for key in candidates {
        if transaction
            .execute(&statement, &[&key.id(), &key.part(), &before])
            .await?
            == 1
        {
            deleted.push(key.clone());
        }
    }
    Ok(deleted)
}
