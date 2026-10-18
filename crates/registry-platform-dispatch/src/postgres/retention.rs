// SPDX-License-Identifier: Apache-2.0

//! Bounded terminal metadata deletion within the consumer's transaction.
use std::time::SystemTime;

use tokio_postgres::Transaction;

use super::{JobKey, JobTable};

/// Maximum candidate count per retention transaction.
pub const MAX_PRUNE_BATCH: usize = 256;

/// Why a terminal-metadata retention batch could not complete.
///
/// Unlike the lease machine's single [`crate::DispatchError`], a retention
/// failure is reported to the operator, who must be able to tell a pass that
/// fails on every tick apart from a transient one. The cause is value-free:
/// a refused bound, or the SQLSTATE the server reported. It never carries a
/// row value, statement text, server message, or connection detail.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetentionError {
    #[error("more than {MAX_PRUNE_BATCH} retention candidates were supplied")]
    BatchBound,
    #[error("a retention table or job key identifier is outside its bound")]
    Identifier,
    #[error("the database refused a retention statement with SQLSTATE {0}")]
    Database(String),
    #[error(
        "a retention statement failed without a SQLSTATE (connection, protocol, or row decoding)"
    )]
    Client,
}

impl RetentionError {
    /// The SQLSTATE the server reported, when the failure carried one.
    #[must_use]
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Database(code) => Some(code),
            Self::BatchBound | Self::Identifier | Self::Client => None,
        }
    }
}

impl From<tokio_postgres::Error> for RetentionError {
    fn from(error: tokio_postgres::Error) -> Self {
        error
            .code()
            .map_or(Self::Client, |code| Self::Database(code.code().to_owned()))
    }
}

/// Delete eligible terminal candidates at or before a product-owned cutoff.
///
/// The consumer selects candidates under its retention/replay policy and owns
/// dependent cleanup in this same transaction. This final predicate preserves
/// pending, leased and unknown jobs, and dead letters without completed expiry.
/// It also rechecks the horizon if a candidate changed before deletion.
/// Dead letters age from `dead_lettered_at`; subsequent completed expiry may
/// update `expired_at` and `updated_at` without restarting the horizon. A
/// consumer with additional replay or receipt requirements must enforce them
/// before calling this function; metadata deletion does not erase audit logs.
///
/// Returns only deleted keys. No rows are committed here. The caller must roll
/// back on any error, including a dependent cleanup error.
///
/// # Errors
/// Returns [`RetentionError::BatchBound`] for more than [`MAX_PRUNE_BATCH`]
/// candidates, and the value-free database cause for a failed statement.
pub async fn prune_terminal(
    transaction: &Transaction<'_>,
    table: &JobTable,
    candidates: &[JobKey],
    before: SystemTime,
) -> Result<Vec<JobKey>, RetentionError> {
    if candidates.len() > MAX_PRUNE_BATCH {
        return Err(RetentionError::BatchBound);
    }
    let statement = transaction
        .prepare(&format!(
            "DELETE FROM {table} WHERE {id}=$1 AND {part}=$2
         AND ((updated_at <= $3
               AND ((state='delivered' AND delivered_at <= $3)
                 OR (state='expired' AND expired_at <= $3)
                 OR state='cancelled'))
           OR (state='dead-lettered' AND dead_lettered_at <= $3 AND expired_at IS NOT NULL))",
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

#[cfg(test)]
mod tests {
    use super::RetentionError;

    #[test]
    fn a_retention_failure_names_its_cause_and_only_its_sqlstate() {
        let refused = RetentionError::Database("23503".to_owned());
        assert_eq!(refused.sqlstate(), Some("23503"));
        assert_eq!(
            refused.to_string(),
            "the database refused a retention statement with SQLSTATE 23503"
        );
        assert_eq!(RetentionError::Client.sqlstate(), None);
        assert!(RetentionError::BatchBound.to_string().contains("256"));
    }
}
