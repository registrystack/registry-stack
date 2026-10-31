// SPDX-License-Identifier: Apache-2.0

//! The audit journal's PostgreSQL store: the schema migration and the
//! append path for its value-free event rows
//! (`products/adapter/CONCEPT.md` section 11).
//!
//! Rows are append-only: writers only insert, retention deletes whole rows
//! by `occurred_at`, and a trigger refuses anything else. `occurred_at` is
//! stamped from the runtime clock at the event, never from a database
//! default, and retention deletes serve from
//! `adapter_journal_events_occurrence_idx`. The journal records no bodies:
//! no request payloads, no response payloads, no field values, no filled
//! query strings.

use std::fmt;
use std::time::SystemTime;

use deadpool_postgres::GenericClient;
use tokio_postgres::Error as PgError;

/// Every schema version, in the order it is applied. Each later migration
/// takes the next number.
pub(crate) const MIGRATIONS: [(i64, &str); 3] = [
    (100, include_str!("journal/migrations/0100_journal.sql")),
    (
        200,
        include_str!("journal/migrations/0200_call_refused.sql"),
    ),
    (
        300,
        include_str!("journal/migrations/0300_breaker_fallback.sql"),
    ),
];

/// The newest schema version this release applies.
pub(crate) const SUPPORTED_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// Shared advisory-lock key for schema migration. Its ASCII bytes spell
/// "adapter_".
pub(crate) const MIGRATION_LOCK_KEY: i64 = 0x6164_6170_7465_725f;

/// Most rows one retention delete removes, so a backlog drains in bounded
/// statements instead of one long-held lock.
pub const MAX_RETENTION_BATCH: u32 = 1_000;

/// The table privileges the runtime role needs on `adapter_journal_events`:
/// INSERT to append events, and SELECT and DELETE for retention to find and
/// remove expired ones.
pub const RUNTIME_PRIVILEGES: [&str; 3] = ["INSERT", "SELECT", "DELETE"];

/// Why a journal write or migration failed. Neither the pool nor the
/// driver repeats the connection string in its message, so naming the
/// cause costs no credential.
#[derive(Debug)]
pub enum JournalError {
    /// The database holds a journal schema newer than this release
    /// applies.
    SchemaNewer {
        /// The newest version the database applied.
        found: i64,
        /// The newest version this release supports.
        supported: i64,
    },
    /// The journal migration lock was not held when it was released.
    MigrationLock,
    /// The driver's own account of what went wrong.
    Query(PgError),
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalError::SchemaNewer { found, supported } => write!(
                formatter,
                "the Adapter journal database holds schema version {found}, newer than the version {supported} this release applies; this release cannot serve it"
            ),
            JournalError::MigrationLock => write!(
                formatter,
                "the Adapter journal migration lock was not held when it was released"
            ),
            JournalError::Query(error) => {
                write!(formatter, "the Adapter journal query failed: {error}")
            }
        }
    }
}

impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JournalError::SchemaNewer { .. } | JournalError::MigrationLock => None,
            JournalError::Query(error) => Some(error),
        }
    }
}

impl From<PgError> for JournalError {
    fn from(error: PgError) -> Self {
        JournalError::Query(error)
    }
}

/// Apply every pending journal migration under the shared advisory lock,
/// refusing a database this release cannot serve. Running it again, or
/// twice at once, applies nothing twice. Each migration commits together
/// with its ledger row, so an interrupted startup leaves both or neither.
/// The caller supplies the pooled client, whose session holds the advisory
/// lock.
pub async fn migrate(client: &mut impl GenericClient) -> Result<(), JournalError> {
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await?;
    let applied = apply_migrations(client).await;
    let released = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await;
    applied?;
    if released?.get::<_, bool>(0) {
        Ok(())
    } else {
        Err(JournalError::MigrationLock)
    }
}

/// Check journal readiness without reading records or appending an event.
/// The exact migration set must match this binary, and the active role must
/// hold every [`RUNTIME_PRIVILEGES`] on the journal table in the configured
/// search path: append to it, and run retention over it.
pub async fn ready(client: &impl GenericClient) -> Result<bool, JournalError> {
    let applied = client
        .query(
            "SELECT version FROM adapter_schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect::<Vec<_>>();
    if applied
        != MIGRATIONS
            .iter()
            .map(|(version, _)| *version)
            .collect::<Vec<_>>()
    {
        return Ok(false);
    }
    Ok(missing_runtime_privileges(client).await?.is_empty())
}

/// The [`RUNTIME_PRIVILEGES`] the active role lacks on
/// `adapter_journal_events`, in that order; all of them when the table is
/// not in the search path.
pub async fn missing_runtime_privileges(
    client: &impl GenericClient,
) -> Result<Vec<&'static str>, JournalError> {
    let row = client
        .query_one(
            "SELECT has_table_privilege(current_user, to_regclass('adapter_journal_events'), 'INSERT'),
                    has_table_privilege(current_user, to_regclass('adapter_journal_events'), 'SELECT'),
                    has_table_privilege(current_user, to_regclass('adapter_journal_events'), 'DELETE')",
            &[],
        )
        .await?;
    Ok(RUNTIME_PRIVILEGES
        .iter()
        .enumerate()
        .filter(|(column, _)| !row.get::<_, Option<bool>>(*column).unwrap_or(false))
        .map(|(_, privilege)| *privilege)
        .collect())
}

async fn apply_migrations(client: &mut impl GenericClient) -> Result<(), JournalError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS adapter_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await?;
    let applied = client
        .query("SELECT version FROM adapter_schema_migrations", &[])
        .await?
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect::<Vec<_>>();
    if let Some(found) = applied.iter().copied().max() {
        if found > SUPPORTED_SCHEMA_VERSION {
            return Err(JournalError::SchemaNewer {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
    }
    for (version, migration) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        let transaction = client.transaction().await?;
        transaction.batch_execute(migration).await?;
        transaction
            .execute(
                "INSERT INTO adapter_schema_migrations(version,applied_at) VALUES($1,now())",
                &[&version],
            )
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}

/// Deletes at most [`MAX_RETENTION_BATCH`] journal events that occurred
/// before `cutoff`, oldest first through
/// `adapter_journal_events_occurrence_idx`, and returns how many it
/// removed. It needs only SELECT and DELETE: no row lock clause, which
/// would also demand UPDATE on the append-only journal. Replicas sweeping
/// at once may pick the same rows; one deletes them and the other counts
/// them as already gone.
pub async fn delete_expired(
    client: &impl GenericClient,
    cutoff: SystemTime,
) -> Result<u64, JournalError> {
    Ok(client
        .execute(
            "DELETE FROM adapter_journal_events
             WHERE event_id IN (
                 SELECT event_id FROM adapter_journal_events
                 WHERE occurred_at < $1
                 ORDER BY occurred_at, event_id
                 LIMIT $2
             )",
            &[&cutoff, &i64::from(MAX_RETENTION_BATCH)],
        )
        .await?)
}

/// One journal event. It carries identifiers, classes, and codes only:
/// never a request payload, a response payload, a field value, or a filled
/// query string.
#[derive(Clone, Debug)]
pub struct JournalEvent {
    /// The closed Camel kind (`CONCEPT.md` section 11), for example
    /// `exchangeCreated`.
    pub event_kind: &'static str,
    /// The exchange the event belongs to.
    pub exchange_id: String,
    /// The concrete operation the exchange serves.
    pub operation: String,
    /// The verified caller identity the facade authenticated.
    pub caller_ref: String,
    /// The route serving the exchange.
    pub route_id: String,
    /// Value-free per-kind facts (endpoint id, method, status, duration,
    /// response size and digest, error class, problem code, a send's
    /// delivery certainty: `maybe-sent` or `not-sent`) as a bounded
    /// JSON object, or none.
    pub detail: Option<String>,
}

/// Append one event row, stamped `occurred_at` from the runtime clock at
/// the event. The caller journals before answering, so the stamp is the
/// event's instant, not the response's.
pub async fn append(
    client: &impl GenericClient,
    event: JournalEvent,
    occurred_at: SystemTime,
) -> Result<(), JournalError> {
    client
        .execute(
            "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, detail, occurred_at) \
             VALUES ($1, $2, $3, $4, $5, COALESCE($6::text::jsonb, '{}'::jsonb), $7)",
            &[
                &event.event_kind,
                &event.exchange_id,
                &event.operation,
                &event.caller_ref,
                &event.route_id,
                &event.detail,
                &occurred_at,
            ],
        )
        .await?;
    Ok(())
}
