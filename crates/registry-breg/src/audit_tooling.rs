// SPDX-License-Identifier: Apache-2.0

//! Operator verification, export, and retention for the chained audit journal.
//!
//! The journal is a hash chain: every record carries the previous record's hash
//! and one head row names the newest hash. Chain order is recovered from those
//! links alone. `created_at` is a transaction start timestamp, so a transaction
//! that started earlier can append later and the column is not chain order.
//!
//! Verification proves the retained set: every reachable record hashes to what
//! it claims under the deployment audit key, the head names the newest of them,
//! and the table holds no record the head cannot reach. It cannot prove that no
//! record was ever removed, which is why an operator records the reported head
//! hash outside the database and exports the journal off-host before pruning.
//!
//! Pruning removes a prefix of the chain and only records created before the
//! boundary, so what remains is a suffix that still verifies and whose first
//! record names the boundary. It runs under the migration authority with the
//! head row locked, so runtime appends wait instead of racing the delete.
//!
//! Every path here reads envelope bytes, references, and hashes. None of them
//! reads a record value, and none of them writes to the journal except the one
//! retention record a committed prune appends.

use std::io::Write;
use std::path::Path;

use registry_platform_audit::{
    verify_chain, AuditChainHasher, AuditEnvelope, AuditProfile, ChainVerificationError,
};
use serde::Serialize;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_postgres::IsolationLevel;

use crate::history_maintenance::{
    append_audit_envelope, profile_is_keyed, set_local_timeouts, HistoryMaintenanceError,
    HistoryMaintenanceTimeouts,
};
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::load_runtime_config;

const PRUNE_OPERATION_ID: &str = "audit.retention.prune";
const CHAIN_CURSOR: &str = "registry_audit_chain";
const CHAIN_FETCH_BATCH: usize = 1000;

/// Recover chain order from the links. The walk starts at the head hash and
/// steps to the row whose `record_hash` is the current envelope's `prev_hash`,
/// which a genesis record leaves null so the recursion stops there.
const CHAIN_CTE: &str = "WITH RECURSIVE chain AS (
         SELECT record.envelope_id,
                record.record_hash,
                record.envelope,
                record.created_at,
                1::bigint AS depth
           FROM registry_internal.registry_audit AS record
           JOIN registry_internal.registry_audit_head AS head
             ON head.singleton
            AND head.last_hash = record.record_hash
          UNION ALL
         SELECT previous.envelope_id,
                previous.record_hash,
                previous.envelope,
                previous.created_at,
                step.depth + 1
           FROM chain AS step
           JOIN registry_internal.registry_audit AS previous
             ON previous.record_hash = decode(
                    convert_from(step.envelope, 'UTF8')::jsonb ->> 'prev_hash', 'hex')
     )";

/// Number every chain position from the oldest reachable record, then name the
/// first position the boundary retains. A boundary no record reaches keeps the
/// position one past the end, so the whole chain qualifies for removal.
const CHAIN_PRUNE_PLAN_CTE: &str = "ordered AS (
         SELECT envelope_id,
                record_hash,
                created_at,
                row_number() OVER (ORDER BY depth DESC) AS position
           FROM chain
     ),
     boundary AS (
         SELECT COALESCE(min(position), (SELECT count(*) FROM ordered) + 1) AS first_retained
           FROM ordered
          WHERE created_at >= $1::text::timestamptz
     )";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuditToolingError {
    #[error("the audit chain is broken at position {position}")]
    ChainBroken { position: u64 },
    #[error("the audit journal holds an unreadable envelope at position {position}")]
    InvalidEnvelope { position: u64 },
    #[error("the audit head does not name the newest reachable record")]
    HeadMismatch,
    #[error("the audit journal holds records the head cannot reach")]
    Unreachable { records: u64 },
    #[error("the audit retention boundary is later than the current transaction time")]
    BoundaryInFuture,
    #[error("the audit journal is unavailable")]
    Unavailable,
}

pub type Result<T> = std::result::Result<T, AuditToolingError>;

impl From<HistoryMaintenanceError> for AuditToolingError {
    fn from(_error: HistoryMaintenanceError) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerification {
    pub records: u64,
    pub start_prev_hash: Option<String>,
    pub last_hash: Option<String>,
    pub head_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExport {
    pub records: u64,
    pub last_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPrune {
    pub dry_run: bool,
    pub removed_records: u64,
    pub retained_records: u64,
    pub boundary_hash: Option<String>,
    pub first_retained_envelope_id: Option<String>,
}

/// The instant a prune keeps from: a record created at or after it stays, and
/// so does every record after it in chain order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPruneBoundary {
    pub before: OffsetDateTime,
}

impl AuditPruneBoundary {
    /// Parse one RFC 3339 instant. Adopter tooling reaches a boundary through
    /// this, so a command line does not have to carry the date library the
    /// runtime parses with.
    pub fn parse_rfc3339(value: &str) -> Result<Self> {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(|before| Self { before })
            .map_err(|_| AuditToolingError::Unavailable)
    }

    fn rendered(&self) -> Result<String> {
        self.before
            .format(&Rfc3339)
            .map_err(|_| AuditToolingError::Unavailable)
    }
}

/// One walk over the reachable chain, oldest record first.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChainWalk {
    records: u64,
    start_prev_hash: Option<[u8; 32]>,
    last_hash: Option<[u8; 32]>,
}

/// Package-bound operator boundary used by `bregctl`.
///
/// Construction closes the runtime configuration, package, active database
/// identity, managed catalog, both database roles, the Registry lock, and the
/// audit profile before any journal operation can run. SQL remains
/// product-owned here.
pub struct AuditOperatorService {
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    runtime_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    timeouts: HistoryMaintenanceTimeouts,
    audit_profile: AuditProfile,
}

impl AuditOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(AuditToolingError::Unavailable);
        }
        let config = load_runtime_config(path).map_err(|_| AuditToolingError::Unavailable)?;
        let package_root = config.package().root().to_path_buf();
        let runtime_connection = config
            .runtime_database_connection_config()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let pool = runtime_connection
            .build_pool()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let context = config.package_load_context();
        let startup = crate::startup::prepare_startup(
            &package_root,
            &context,
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;
        drop(client);
        let migration_connection = config
            .migration_database_connection_config()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let audit_profile = config
            .audit_profile()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let timeouts = HistoryMaintenanceTimeouts::new(
            config.operational_timeouts().migration_lock,
            config.operational_timeouts().migration_statement,
        )?;
        Ok(Self {
            expected: startup.expected_identity().clone(),
            expected_catalog: startup.expected_catalog().clone(),
            lock_key: startup.lock_key(),
            migration_connection,
            runtime_connection,
            migration_role: config.database().roles().migration().clone(),
            runtime_role: config.database().roles().runtime().clone(),
            timeouts,
            audit_profile,
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)] // Keep distinct migration and runtime identities explicit.
    pub fn new_for_test(
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        runtime_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit_profile: AuditProfile,
    ) -> Self {
        Self {
            expected,
            expected_catalog,
            lock_key,
            migration_connection,
            runtime_connection,
            migration_role,
            runtime_role,
            timeouts: HistoryMaintenanceTimeouts::new(
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(30),
            )
            .expect("bounded test timeouts are valid"),
            audit_profile,
        }
    }

    /// Verify the reachable chain against the head and the table.
    pub async fn verify(&self) -> Result<AuditVerification> {
        let (walk, head_hash) = self.read_chain(None).await?;
        Ok(AuditVerification {
            records: walk.records,
            start_prev_hash: walk.start_prev_hash.map(hex::encode),
            last_hash: walk.last_hash.map(hex::encode),
            head_hash: head_hash.map(hex::encode),
        })
    }

    /// Write the verified chain as JSON lines in chain order.
    ///
    /// Verification and writing share one snapshot, so the first inconsistency
    /// fails the export instead of shipping a journal nothing vouches for. The
    /// caller owns the sink; this never opens a file.
    pub async fn export(&self, sink: &mut dyn Write) -> Result<AuditExport> {
        let (walk, _) = self.read_chain(Some(sink)).await?;
        sink.flush().map_err(|_| AuditToolingError::Unavailable)?;
        Ok(AuditExport {
            records: walk.records,
            last_hash: walk.last_hash.map(hex::encode),
        })
    }

    /// Remove the longest prefix of the chain whose records were all created
    /// before the boundary, and record what went.
    ///
    /// The prefix rule is what keeps the journal verifiable: the walk stops at
    /// the first record in chain order created at or after the boundary, even
    /// when a later record carries an earlier timestamp, so what remains is a
    /// suffix whose first record still links to the last removed one.
    pub async fn prune(&self, boundary: AuditPruneBoundary, dry_run: bool) -> Result<AuditPrune> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(AuditToolingError::Unavailable);
        }
        let before = boundary.rendered()?;
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let pg_client: &mut tokio_postgres::Client = &mut client;
        verify_migration_role(pg_client, &self.migration_role)
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let transaction = pg_client
            .transaction()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        set_local_timeouts(&transaction, self.timeouts).await?;
        transaction
            .execute(
                "SELECT pg_catalog.pg_advisory_xact_lock($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;

        // Take the head row before reading the chain, so a runtime append waits
        // for this transaction instead of extending a chain the plan below has
        // already measured.
        transaction
            .query_opt(
                "SELECT last_hash
                   FROM registry_internal.registry_audit_head
                  WHERE singleton
                  FOR UPDATE",
                &[],
            )
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;

        let future = transaction
            .query_one(
                "SELECT $1::text::timestamptz > transaction_timestamp()",
                &[&before],
            )
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        if future.get::<_, bool>(0) {
            return Err(AuditToolingError::BoundaryInFuture);
        }

        let plan = transaction
            .query_one(
                &format!(
                    "{CHAIN_CTE},
                     {CHAIN_PRUNE_PLAN_CTE}
                     SELECT boundary.first_retained - 1 AS removed_records,
                            (SELECT count(*) FROM ordered)
                                - (boundary.first_retained - 1) AS retained_records,
                            (SELECT ordered.record_hash
                               FROM ordered
                              WHERE ordered.position = boundary.first_retained - 1)
                                AS boundary_hash,
                            (SELECT ordered.envelope_id
                               FROM ordered
                              WHERE ordered.position = boundary.first_retained)
                                AS first_retained_envelope_id
                       FROM boundary"
                ),
                &[&before],
            )
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let removed_records = count_from(&plan, 0)?;
        let retained_records = count_from(&plan, 1)?;
        let boundary_hash = plan
            .get::<_, Option<Vec<u8>>>(2)
            .map(|bytes| hash_from(&bytes))
            .transpose()?
            .map(hex::encode);
        let first_retained_envelope_id = plan.get::<_, Option<String>>(3);

        if !dry_run && removed_records > 0 {
            let deleted = transaction
                .execute(
                    &format!(
                        "{CHAIN_CTE},
                         {CHAIN_PRUNE_PLAN_CTE}
                         DELETE FROM registry_internal.registry_audit AS target
                          USING ordered, boundary
                          WHERE target.envelope_id = ordered.envelope_id
                            AND ordered.position < boundary.first_retained"
                    ),
                    &[&before],
                )
                .await
                .map_err(|_| AuditToolingError::Unavailable)?;
            if deleted != removed_records {
                return Err(AuditToolingError::Unavailable);
            }
            append_audit_envelope(
                &transaction,
                &self.audit_profile,
                json!({
                    "schema": "breg-audit-retention-audit/v1",
                    "phase": "terminal",
                    "outcome": "committed",
                    "operationId": PRUNE_OPERATION_ID,
                    "packageRevision": self.expected.package_revision,
                    "removedRecords": removed_records,
                    "retainedRecords": retained_records,
                    "boundaryHash": &boundary_hash,
                    "before": before,
                }),
            )
            .await?;
        }

        if dry_run {
            transaction
                .rollback()
                .await
                .map_err(|_| AuditToolingError::Unavailable)?;
        } else {
            transaction
                .commit()
                .await
                .map_err(|_| AuditToolingError::Unavailable)?;
        }
        Ok(AuditPrune {
            dry_run,
            removed_records,
            retained_records,
            boundary_hash,
            first_retained_envelope_id,
        })
    }

    /// Append one record to the journal over the runtime connection, so a test
    /// can seed the chain the runtime role writes.
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn append_record_for_test(&self, record: serde_json::Value) -> Result<()> {
        let pool = self
            .runtime_connection
            .build_pool()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let pg_client: &mut tokio_postgres::Client = &mut client;
        let transaction = pg_client
            .transaction()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        append_audit_envelope(&transaction, &self.audit_profile, record).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AuditToolingError::Unavailable)
    }

    /// Read the reachable chain in one repeatable-read, read-only snapshot on
    /// the runtime connection, which holds SELECT and INSERT and no more.
    ///
    /// The snapshot is what makes the head, the chain, and the row count agree
    /// without holding the Registry lock, so a scheduled verification never
    /// blocks maintenance.
    async fn read_chain(
        &self,
        sink: Option<&mut dyn Write>,
    ) -> Result<(ChainWalk, Option<[u8; 32]>)> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(AuditToolingError::Unavailable);
        }
        let pool = self
            .runtime_connection
            .build_pool()
            .map_err(|_| AuditToolingError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        let pg_client: &mut tokio_postgres::Client = &mut client;
        let transaction = pg_client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        set_local_timeouts(&transaction, self.timeouts).await?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;

        let head_hash = read_head_hash(&transaction).await?;
        let walk = walk_chain(&transaction, &self.audit_profile.chain_hasher(), sink).await?;
        if walk.last_hash != head_hash {
            return Err(AuditToolingError::HeadMismatch);
        }
        let total = transaction
            .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        if walk.records != count_from(&total, 0)? {
            return Err(AuditToolingError::Unreachable {
                records: walk.records,
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        Ok((walk, head_hash))
    }
}

async fn read_head_hash(transaction: &tokio_postgres::Transaction<'_>) -> Result<Option<[u8; 32]>> {
    let row = transaction
        .query_opt(
            "SELECT last_hash
               FROM registry_internal.registry_audit_head
              WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;
    row.and_then(|row| row.get::<_, Option<Vec<u8>>>(0))
        .map(|bytes| hash_from(&bytes))
        .transpose()
}

/// Stream the reachable chain oldest first through a server-side cursor, so a
/// journal larger than memory still verifies.
async fn walk_chain(
    transaction: &tokio_postgres::Transaction<'_>,
    hasher: &AuditChainHasher,
    mut sink: Option<&mut dyn Write>,
) -> Result<ChainWalk> {
    transaction
        .execute(
            &format!(
                "DECLARE {CHAIN_CURSOR} NO SCROLL CURSOR FOR
                 {CHAIN_CTE}
                 SELECT envelope_id, record_hash, envelope
                   FROM chain
                  ORDER BY depth DESC"
            ),
            &[],
        )
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;
    let fetch = format!("FETCH FORWARD {CHAIN_FETCH_BATCH} FROM {CHAIN_CURSOR}");
    let mut walk = ChainWalk::default();
    loop {
        let rows = transaction
            .query(fetch.as_str(), &[])
            .await
            .map_err(|_| AuditToolingError::Unavailable)?;
        if rows.is_empty() {
            break;
        }
        let mut envelopes = Vec::with_capacity(rows.len());
        for (index, row) in rows.iter().enumerate() {
            let offset = u64::try_from(index).map_err(|_| AuditToolingError::Unavailable)?;
            let position = walk
                .records
                .checked_add(offset)
                .and_then(|position| position.checked_add(1))
                .ok_or(AuditToolingError::Unavailable)?;
            let envelope_id: String = row.get(0);
            let record_hash: Vec<u8> = row.get(1);
            let stored: Vec<u8> = row.get(2);
            let envelope: AuditEnvelope = serde_json::from_slice(&stored)
                .map_err(|_| AuditToolingError::InvalidEnvelope { position })?;
            if envelope.envelope_id != envelope_id || envelope.record_hash.as_slice() != record_hash
            {
                return Err(AuditToolingError::InvalidEnvelope { position });
            }
            envelopes.push(envelope);
        }
        let verified = verify_chain(&envelopes, hasher)
            .map_err(|error| chain_position_error(walk.records, &error))?;
        if walk.records == 0 {
            walk.start_prev_hash = verified.start_prev_hash;
        } else if verified.start_prev_hash != walk.last_hash {
            // `verify_chain` starts each batch from its own first `prev_hash`,
            // so linking the batches is this walk's responsibility.
            return Err(AuditToolingError::ChainBroken {
                position: walk.records + 1,
            });
        }
        if let Some(sink) = sink.as_deref_mut() {
            for envelope in &envelopes {
                let line = envelope
                    .to_jsonl()
                    .map_err(|_| AuditToolingError::Unavailable)?;
                sink.write_all(line.as_bytes())
                    .map_err(|_| AuditToolingError::Unavailable)?;
            }
        }
        let batch = u64::try_from(envelopes.len()).map_err(|_| AuditToolingError::Unavailable)?;
        walk.records = walk
            .records
            .checked_add(batch)
            .ok_or(AuditToolingError::Unavailable)?;
        walk.last_hash = verified.last_hash;
    }
    transaction
        .execute(&format!("CLOSE {CHAIN_CURSOR}"), &[])
        .await
        .map_err(|_| AuditToolingError::Unavailable)?;
    Ok(walk)
}

fn chain_position_error(base: u64, error: &ChainVerificationError) -> AuditToolingError {
    let (line, invalid) = match error {
        ChainVerificationError::InvalidJson { line, .. } => (*line, true),
        ChainVerificationError::PrevHashMismatch { line, .. }
        | ChainVerificationError::RecordHashMismatch { line } => (*line, false),
        _ => return AuditToolingError::Unavailable,
    };
    let Ok(line) = u64::try_from(line) else {
        return AuditToolingError::Unavailable;
    };
    let Some(position) = base.checked_add(line) else {
        return AuditToolingError::Unavailable;
    };
    if invalid {
        AuditToolingError::InvalidEnvelope { position }
    } else {
        AuditToolingError::ChainBroken { position }
    }
}

fn count_from(row: &tokio_postgres::Row, index: usize) -> Result<u64> {
    u64::try_from(row.get::<_, i64>(index)).map_err(|_| AuditToolingError::Unavailable)
}

fn hash_from(bytes: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| AuditToolingError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_parses_and_renders_one_rfc_3339_instant() {
        let boundary =
            AuditPruneBoundary::parse_rfc3339("2026-01-02T03:04:05Z").expect("boundary parses");
        assert_eq!(
            boundary.rendered().expect("boundary renders"),
            "2026-01-02T03:04:05Z"
        );
        assert_eq!(
            AuditPruneBoundary::parse_rfc3339("2026-01-02"),
            Err(AuditToolingError::Unavailable)
        );
        assert_eq!(
            AuditPruneBoundary::parse_rfc3339(""),
            Err(AuditToolingError::Unavailable)
        );
    }

    #[test]
    fn chain_positions_are_reported_from_the_batch_base() {
        assert_eq!(
            chain_position_error(
                1000,
                &ChainVerificationError::RecordHashMismatch { line: 7 }
            ),
            AuditToolingError::ChainBroken { position: 1007 }
        );
        assert_eq!(
            chain_position_error(
                0,
                &ChainVerificationError::PrevHashMismatch {
                    line: 2,
                    expected: None,
                    actual: None,
                }
            ),
            AuditToolingError::ChainBroken { position: 2 }
        );
        assert_eq!(
            chain_position_error(
                4,
                &ChainVerificationError::InvalidJson {
                    line: 1,
                    message: String::new(),
                }
            ),
            AuditToolingError::InvalidEnvelope { position: 5 }
        );
    }
}
