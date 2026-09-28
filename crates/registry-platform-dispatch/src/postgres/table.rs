// SPDX-License-Identifier: Apache-2.0

//! The product-owned job table: its validated names, its key, its states,
//! the DDL a consumer may install, and the enqueue INSERT.

use std::time::SystemTime;

use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::identifier::is_plain_identifier;
use crate::outcome::{ConfigError, DispatchError};

/// The longest job table name, in bytes. It leaves room for the constraint
/// and index names the DDL derives from it inside PostgreSQL's 63-byte
/// identifier limit.
pub const MAX_TABLE_NAME_BYTES: usize = 50;

/// The longest job key part, in bytes.
pub const MAX_JOB_PART_BYTES: usize = 256;

/// The columns the core owns in every job table. A consumer's key columns
/// and extra columns must not reuse these names.
pub(crate) const CORE_COLUMNS: [&str; 11] = [
    "generation",
    "state",
    "attempt",
    "next_attempt_at",
    "attempt_started_at",
    "lease_expires_at",
    "lease_token",
    "delivered_at",
    "dead_lettered_at",
    "expired_at",
    "updated_at",
];

/// The validated names of one product's job table.
///
/// Every name is a plain lowercase SQL identifier, checked once here, so the
/// core can interpolate them into its statements without quoting and no
/// name ever comes from request input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobTable {
    schema: String,
    table: String,
    id_column: String,
    part_column: String,
}

impl JobTable {
    /// Name a job table `schema.table` keyed by a `uuid` column and a
    /// bounded text column.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Identifier`] when a name is not a plain lowercase SQL
    /// identifier (the table at most [`MAX_TABLE_NAME_BYTES`] bytes, every
    /// other name at most 63), when the two key columns share a name, or
    /// when a key column reuses a core column name.
    pub fn new(
        schema: &str,
        table: &str,
        id_column: &str,
        part_column: &str,
    ) -> Result<Self, ConfigError> {
        let valid = is_plain_identifier(schema, 63)
            && is_plain_identifier(table, MAX_TABLE_NAME_BYTES)
            && is_plain_identifier(id_column, 63)
            && is_plain_identifier(part_column, 63)
            && id_column != part_column
            && !CORE_COLUMNS.contains(&id_column)
            && !CORE_COLUMNS.contains(&part_column);
        if !valid {
            return Err(ConfigError::Identifier);
        }
        Ok(Self {
            schema: schema.to_owned(),
            table: table.to_owned(),
            id_column: id_column.to_owned(),
            part_column: part_column.to_owned(),
        })
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    #[must_use]
    pub fn id_column(&self) -> &str {
        &self.id_column
    }

    #[must_use]
    pub fn part_column(&self) -> &str {
        &self.part_column
    }

    pub(crate) fn qualified(&self) -> String {
        format!("{}.{}", self.schema, self.table)
    }

    /// The DDL for a job table with every column, check, and index the core
    /// relies on, for a consumer that does not already own an equivalent
    /// table. The consumer runs the statements in its own migration and may
    /// add its own columns and foreign keys beside them.
    #[must_use]
    pub fn create_statements(&self) -> Vec<String> {
        let Self {
            schema,
            table,
            id_column: id,
            part_column: part,
        } = self;
        vec![
            format!(
                "CREATE TABLE IF NOT EXISTS {schema}.{table} (
                 {id} uuid NOT NULL,
                 {part} text NOT NULL
                     CHECK ({part} <> '' AND octet_length({part}) <= {MAX_JOB_PART_BYTES}),
                 generation bigint NOT NULL CHECK (generation > 0),
                 state text NOT NULL
                     CONSTRAINT {table}_state_values CHECK (
                         state IN ('pending', 'leased', 'delivered', 'dead_lettered',
                                   'expired', 'unknown', 'cancelled')
                     ),
                 attempt smallint NOT NULL CHECK (attempt >= 0),
                 next_attempt_at timestamptz,
                 attempt_started_at timestamptz,
                 lease_expires_at timestamptz,
                 lease_token uuid,
                 delivered_at timestamptz,
                 dead_lettered_at timestamptz,
                 expired_at timestamptz,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY ({id}, {part}),
                 CONSTRAINT {table}_shape CHECK (
                     (state = 'pending'
                         AND next_attempt_at IS NOT NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'leased'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NOT NULL
                         AND lease_expires_at > attempt_started_at
                         AND lease_token IS NOT NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'delivered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NOT NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'dead_lettered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NOT NULL)
                     OR (state = 'expired'
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NOT NULL)
                     OR (state = 'unknown'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'cancelled'
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                 )
             );"
            ),
            format!(
                "CREATE INDEX IF NOT EXISTS {table}_due_idx
                 ON {schema}.{table} (next_attempt_at, {id}, {part})
                 WHERE state = 'pending';"
            ),
            format!(
                "CREATE INDEX IF NOT EXISTS {table}_lease_idx
                 ON {schema}.{table} (lease_expires_at, {id}, {part})
                 WHERE state = 'leased';"
            ),
        ]
    }
}

/// The key of one job: a `uuid` naming the product's work item and a
/// bounded part naming one dispatch of it (a destination, for instance).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct JobKey {
    id: Uuid,
    part: String,
}

impl JobKey {
    /// # Errors
    ///
    /// [`ConfigError::OutOfBounds`] when `part` is empty or longer than
    /// [`MAX_JOB_PART_BYTES`].
    pub fn new(id: Uuid, part: impl Into<String>) -> Result<Self, ConfigError> {
        let part = part.into();
        if part.is_empty() || part.len() > MAX_JOB_PART_BYTES {
            return Err(ConfigError::OutOfBounds);
        }
        Ok(Self { id, part })
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub fn part(&self) -> &str {
        &self.part
    }
}

/// The stored state of one job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JobState {
    /// Waiting for its next attempt, which is due at `next_attempt_at`.
    Pending,
    /// Held by exactly one worker until `lease_expires_at`.
    Leased,
    Delivered,
    /// Stopped by a permanent failure or an exhausted attempt budget.
    DeadLettered,
    /// Stopped before it could be sent, or by a retry that would have landed
    /// after its expiry.
    Expired,
    /// Stopped because an attempt's fate is unknown and its policy holds
    /// uncertain attempts rather than sending them again.
    Unknown,
    /// Withdrawn before it was dispatched.
    Cancelled,
}

impl JobState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Delivered => "delivered",
            Self::DeadLettered => "dead_lettered",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "leased" => Self::Leased,
            "delivered" => Self::Delivered,
            "dead_lettered" => Self::DeadLettered,
            "expired" => Self::Expired,
            "unknown" => Self::Unknown,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

/// Insert one pending job inside the caller's transaction.
///
/// The job is due at the later of the transaction timestamp and
/// `not_before`, so a job enqueued without a not-before instant is due at
/// once and one enqueued with an instant in the past is due at once too.
/// This function performs no transaction management of its own.
///
/// # Errors
///
/// [`DispatchError::Unavailable`] when the INSERT fails or writes other than
/// one row.
pub async fn enqueue(
    transaction: &Transaction<'_>,
    table: &JobTable,
    key: &JobKey,
    not_before: Option<SystemTime>,
) -> Result<(), DispatchError> {
    let changed = transaction
        .execute(
            &format!(
                "INSERT INTO {qualified}
                 ({id}, {part}, generation, state, attempt, next_attempt_at)
             VALUES ($1, $2, 1, 'pending', 0,
                     GREATEST(transaction_timestamp(), $3::timestamptz))",
                qualified = table.qualified(),
                id = table.id_column,
                part = table.part_column,
            ),
            &[&key.id, &key.part, &not_before],
        )
        .await?;
    if changed != 1 {
        return Err(DispatchError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_table_accepts_only_plain_distinct_names() {
        let table =
            JobTable::new("product", "work_jobs", "work_id", "destination").expect("plain names");
        assert_eq!(table.qualified(), "product.work_jobs");
        for (schema, name, id, part) in [
            ("Product", "jobs", "id", "part"),
            ("product", "jobs; drop table x", "id", "part"),
            ("product", "jobs", "id", "id"),
            ("product", "jobs", "state", "part"),
            ("product", "jobs", "id", "generation"),
            (
                "product",
                &"j".repeat(MAX_TABLE_NAME_BYTES + 1),
                "id",
                "part",
            ),
            ("", "jobs", "id", "part"),
        ] {
            assert_eq!(
                JobTable::new(schema, name, id, part),
                Err(ConfigError::Identifier),
                "{schema}.{name} ({id}, {part})"
            );
        }
    }

    #[test]
    fn the_derived_names_fit_postgres_identifiers() {
        let table = JobTable::new("s", &"j".repeat(MAX_TABLE_NAME_BYTES), "id", "part")
            .expect("the longest table name");
        for statement in table.create_statements() {
            for suffix in ["_state_values", "_shape", "_due_idx", "_lease_idx"] {
                if let Some(start) = statement.find(&format!("{}{suffix}", table.table())) {
                    let name = &statement[start..start + table.table().len() + suffix.len()];
                    assert!(name.len() <= 63, "{name}");
                }
            }
        }
    }

    #[test]
    fn a_job_key_part_is_bounded() {
        let id = Uuid::nil();
        assert!(JobKey::new(id, "p").is_ok());
        assert!(JobKey::new(id, "p".repeat(MAX_JOB_PART_BYTES)).is_ok());
        assert_eq!(JobKey::new(id, ""), Err(ConfigError::OutOfBounds));
        assert_eq!(
            JobKey::new(id, "p".repeat(MAX_JOB_PART_BYTES + 1)),
            Err(ConfigError::OutOfBounds)
        );
    }

    #[test]
    fn every_state_round_trips_through_its_stored_spelling() {
        for state in [
            JobState::Pending,
            JobState::Leased,
            JobState::Delivered,
            JobState::DeadLettered,
            JobState::Expired,
            JobState::Unknown,
            JobState::Cancelled,
        ] {
            assert_eq!(JobState::parse(state.as_str()), Some(state));
        }
        assert_eq!(JobState::parse("Pending"), None);
    }
}
