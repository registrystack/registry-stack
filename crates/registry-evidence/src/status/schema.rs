//! The ledger's PostgreSQL schema and its migrations.
//!
//! Migrations are applied in one transaction under an advisory lock, in the
//! order of [`MIGRATIONS`], and recorded in the schema's own
//! `schema_migrations` table. A database that records a migration this build
//! does not know is refused rather than written to.

use std::fmt;

use super::error::StatusError;
use super::pools::ReservedPool;

/// The schema the ledger uses unless the deployment names another.
pub const DEFAULT_SCHEMA: &str = "evidence_status";

/// Ordered migrations: a version and the SQL that creates it. The SQL names
/// tables unqualified; it runs with the ledger schema first on the search
/// path.
const MIGRATIONS: [(i64, &str); 2] = [
    (1, include_str!("migrations/0001_lists_and_allocations.sql")),
    (
        2,
        include_str!("migrations/0002_transitions_observations.sql"),
    ),
];

/// Advisory lock class for migrations; the second key is the schema name's
/// hash, so ledgers in different schemas migrate independently.
const MIGRATION_LOCK_CLASS: i32 = 0x6576_6d31;

/// A validated PostgreSQL schema name: lower-case ASCII letters, digits and
/// underscores, starting with a letter or underscore, at most 63 bytes, and
/// not in the reserved `pg_` namespace. Validation makes it safe to quote into
/// statements.
#[derive(Clone, PartialEq, Eq)]
pub struct SchemaName(String);

impl SchemaName {
    pub fn new(name: &str) -> Result<Self, StatusError> {
        let valid = (1..=63).contains(&name.len())
            && name
                .bytes()
                .next()
                .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            && !name.starts_with("pg_");
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(StatusError::Configuration(
                "the status schema name is not a plain lower-case PostgreSQL identifier",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The schema name as a quoted identifier.
    pub(crate) fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

impl Default for SchemaName {
    fn default() -> Self {
        Self(DEFAULT_SCHEMA.to_owned())
    }
}

impl fmt::Debug for SchemaName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SchemaName").field(&self.0).finish()
    }
}

/// Create the schema if needed and apply every migration it lacks.
pub(crate) async fn migrate(schema: &SchemaName, pool: &ReservedPool) -> Result<(), StatusError> {
    let mut client = pool.client().await?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| StatusError::database(&error))?;
    let quoted = schema.quoted();
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&MIGRATION_LOCK_CLASS, &schema.as_str()],
        )
        .await
        .map_err(|error| StatusError::database(&error))?;
    transaction
        .batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS {quoted};
             SET LOCAL search_path TO {quoted};
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version bigint PRIMARY KEY CHECK (version > 0),
                 applied_at timestamptz NOT NULL
             );"
        ))
        .await
        .map_err(|error| StatusError::database(&error))?;
    let applied: Vec<i64> = transaction
        .query(
            "SELECT version FROM schema_migrations ORDER BY version",
            &[],
        )
        .await
        .map_err(|error| StatusError::database(&error))?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let known: Vec<i64> = MIGRATIONS.iter().map(|(version, _)| *version).collect();
    if applied.len() > known.len() || applied[..] != known[..applied.len()] {
        return Err(StatusError::SchemaVersion);
    }
    for (version, sql) in &MIGRATIONS[applied.len()..] {
        transaction
            .batch_execute(sql)
            .await
            .map_err(|error| StatusError::database(&error))?;
        transaction
            .execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, now())",
                &[version],
            )
            .await
            .map_err(|error| StatusError::database(&error))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| StatusError::database(&error))
}

#[cfg(test)]
mod tests {
    use super::{SchemaName, DEFAULT_SCHEMA};

    #[test]
    fn schema_names_are_plain_lower_case_identifiers() {
        assert_eq!(SchemaName::default().as_str(), DEFAULT_SCHEMA);
        assert_eq!(SchemaName::default().quoted(), "\"evidence_status\"");
        for valid in ["evidence_status", "_ledger", "status_2", &"a".repeat(63)] {
            assert!(SchemaName::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "Evidence",
            "2status",
            "evidence-status",
            "evidence\"status",
            "pg_status",
            "status; DROP",
            &"a".repeat(64),
        ] {
            assert!(SchemaName::new(invalid).is_err(), "{invalid}");
        }
    }
}
