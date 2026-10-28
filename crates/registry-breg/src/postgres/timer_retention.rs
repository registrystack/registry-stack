// SPDX-License-Identifier: Apache-2.0

//! Bounded expiry of retained Record-timer diagnostic history.

use tokio_postgres::GenericClient;

use super::{GuardedTransaction, PostgresKernelError, Result, RuntimeRevoke, SqlIdentifier};

pub(super) const TIMER_RETENTION_FUNCTION: &str =
    "registry_internal.prune_record_timer_retention(integer)";
pub(super) const TIMER_TERMINAL_RETENTION_INDEX: &str =
    "registry_internal.registry_record_timer_generations_retention_idx";
pub(super) const TIMER_ATTEMPT_RETENTION_INDEX: &str =
    "registry_internal.registry_record_timer_attempts_retention_idx";
pub(super) const TIMER_RETENTION_BATCH_MAXIMUM: u32 = 1_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TimerRetentionBatchResult {
    /// Sum of independently bounded terminal and unfinished attempt lanes.
    pub(super) attempts_pruned: u64,
    pub(super) generations_pruned: u64,
}

/// Installs the narrow deletion authority used by the timer worker.
///
/// The runtime role never receives `DELETE` on either ledger table. The fixed
/// function accepts only a bounded row budget and derives eligibility from
/// stored expiry timestamps and the database clock.
pub(super) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_with_clock(migration, runtime_role, "clock_timestamp()").await
}

async fn install_with_clock(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    database_clock: &str,
) -> Result<()> {
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await?
        .with_public();
    migration
        .batch_execute(&format!(
            "CREATE INDEX IF NOT EXISTS registry_record_timer_generations_retention_idx
                 ON registry_internal.registry_record_timer_generations
                    (detail_expires_at,occurrence_id)
                 WHERE detail_expires_at IS NOT NULL
                   AND state IN ('completed','refused','cancelled','superseded','missed');
             CREATE INDEX IF NOT EXISTS registry_record_timer_attempts_retention_idx
                 ON registry_internal.registry_record_timer_attempts
                    (detail_expires_at,occurrence_id,attempt_number)
                 WHERE detail_expires_at IS NOT NULL;
             CREATE OR REPLACE FUNCTION {function_name}
                 RETURNS TABLE (attempts_pruned bigint,generations_pruned bigint)
                 LANGUAGE plpgsql SECURITY DEFINER
                 SET search_path = pg_catalog, registry_internal AS $body$
             DECLARE
                 database_now timestamptz;
                 terminal_attempts_pruned bigint;
                 unfinished_attempts_pruned bigint;
             BEGIN
                 IF $1 IS NULL OR $1 < 1 OR $1 > {maximum} THEN
                     RAISE EXCEPTION USING
                         ERRCODE = '22023',
                         MESSAGE = 'record-timer retention batch limit is invalid';
                 END IF;
                 database_now := {database_clock};

                 WITH expired AS MATERIALIZED (
                     SELECT attempt.occurrence_id,attempt.attempt_number
                       FROM registry_internal.registry_record_timer_generations AS generation
                       JOIN registry_internal.registry_record_timer_attempts AS attempt
                         ON attempt.occurrence_id=generation.occurrence_id
                      WHERE generation.detail_expires_at IS NOT NULL
                        AND generation.detail_expires_at <= database_now
                        AND generation.state IN
                            ('completed','refused','cancelled','superseded','missed')
                        AND attempt.finished_at IS NOT NULL
                      ORDER BY generation.detail_expires_at,
                               generation.occurrence_id,attempt.attempt_number
                      LIMIT $1
                      FOR UPDATE OF attempt SKIP LOCKED
                 ), removed AS (
                     DELETE FROM registry_internal.registry_record_timer_attempts AS attempt
                      USING expired
                      WHERE attempt.occurrence_id=expired.occurrence_id
                        AND attempt.attempt_number=expired.attempt_number
                  RETURNING 1
                 )
                 SELECT count(*) INTO terminal_attempts_pruned FROM removed;

                 WITH expired AS MATERIALIZED (
                     SELECT attempt.occurrence_id,attempt.attempt_number
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                       JOIN registry_internal.registry_record_timer_generations AS generation
                         ON generation.occurrence_id=attempt.occurrence_id
                      WHERE attempt.finished_at IS NOT NULL
                        AND attempt.detail_expires_at IS NOT NULL
                        AND attempt.detail_expires_at <= database_now
                        AND generation.state IN ('pending','leased','blocked')
                      ORDER BY attempt.detail_expires_at,
                               attempt.occurrence_id,attempt.attempt_number
                      LIMIT $1
                      FOR UPDATE OF attempt SKIP LOCKED
                 ), removed AS (
                     DELETE FROM registry_internal.registry_record_timer_attempts AS attempt
                      USING expired
                      WHERE attempt.occurrence_id=expired.occurrence_id
                        AND attempt.attempt_number=expired.attempt_number
                  RETURNING 1
                 )
                 SELECT count(*) INTO unfinished_attempts_pruned FROM removed;

                 attempts_pruned := terminal_attempts_pruned + unfinished_attempts_pruned;

                 WITH expired AS MATERIALIZED (
                     SELECT generation.occurrence_id
                       FROM registry_internal.registry_record_timer_generations AS generation
                      WHERE generation.detail_expires_at IS NOT NULL
                        AND generation.detail_expires_at <= database_now
                        AND generation.state IN
                            ('completed','refused','cancelled','superseded','missed')
                        AND NOT EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_current AS current
                             WHERE current.occurrence_id=generation.occurrence_id
                        )
                        AND NOT EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_attempts AS attempt
                             WHERE attempt.occurrence_id=generation.occurrence_id
                        )
                      ORDER BY generation.detail_expires_at,generation.occurrence_id
                      LIMIT $1
                      FOR UPDATE OF generation SKIP LOCKED
                 ), removed AS (
                     DELETE FROM registry_internal.registry_record_timer_generations AS generation
                      USING expired
                      WHERE generation.occurrence_id=expired.occurrence_id
                        AND NOT EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_current AS current
                             WHERE current.occurrence_id=generation.occurrence_id
                        )
                        AND NOT EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_attempts AS attempt
                             WHERE attempt.occurrence_id=generation.occurrence_id
                        )
                  RETURNING 1
                 )
                 SELECT count(*) INTO generations_pruned FROM removed;
                 RETURN NEXT;
             END
             $body$;
             REVOKE ALL ON FUNCTION {function_name} FROM {revoke};
             GRANT EXECUTE ON FUNCTION {function_name} TO {role};",
            function_name = TIMER_RETENTION_FUNCTION,
            maximum = TIMER_RETENTION_BATCH_MAXIMUM,
            role = runtime_role.quoted(),
            database_clock = database_clock,
        ))
        .await?;
    Ok(())
}

#[cfg(feature = "postgres-test")]
pub(super) async fn install_with_clock_for_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    database_clock: &str,
) -> Result<()> {
    install_with_clock(migration, runtime_role, database_clock).await
}

/// Prunes at most `limit` rows from each of three independently bounded lanes
/// inside an already admitted Registry transaction. This prevents a continuous
/// attempt backlog from starving terminal-generation cleanup while bounding a
/// call to `3 * limit` rows. Callers own transaction admission, statement
/// budget and commit.
pub(super) async fn prune_timer_retention_batch(
    transaction: &GuardedTransaction<'_>,
    limit: u32,
) -> Result<TimerRetentionBatchResult> {
    if limit == 0 || limit > TIMER_RETENTION_BATCH_MAXIMUM {
        return Err(PostgresKernelError::Configuration(
            "record-timer retention batch limit is invalid",
        ));
    }
    let limit = i32::try_from(limit).map_err(|_| {
        PostgresKernelError::Configuration("record-timer retention batch limit is invalid")
    })?;
    let row = transaction
        .transaction()
        .query_one(
            "SELECT attempts_pruned,generations_pruned
               FROM registry_internal.prune_record_timer_retention($1)",
            &[&limit],
        )
        .await?;
    Ok(TimerRetentionBatchResult {
        attempts_pruned: u64::try_from(row.get::<_, i64>(0))
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
        generations_pruned: u64::try_from(row.get::<_, i64>(1))
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
    })
}
